import Fastify from 'fastify';
import cors from '@fastify/cors';
import path from 'node:path';
import fs from 'node:fs';
import { KustoClient, loadTableSchemas } from '@huntbook/core';
import { loadScenarioFromFile, generateScenarioDataset } from '@huntbook/datagen';

const PORT = parseInt(process.env.PORT || '3001', 10);
const KUSTO_ENDPOINT = process.env.KUSTO_ENDPOINT || 'http://127.0.0.1:8080';

const fastify = Fastify({ logger: true });

// Register CORS for localhost UI
await fastify.register(cors, {
  origin: [
    'http://localhost:5173',
    'http://127.0.0.1:5173',
    'http://localhost:3000',
    'http://127.0.0.1:3000'
  ],
  methods: ['GET', 'POST']
});

const kusto = new KustoClient(KUSTO_ENDPOINT);

const rootDir = path.resolve(process.cwd(), '../../');
const tablesDir = path.resolve(rootDir, 'schemas/tables');
const scenariosDir = path.resolve(rootDir, 'scenarios');

// 1. GET /health
fastify.get('/health', async () => {
  const emulatorConnected = await kusto.isHealthy();
  return {
    status: 'ok',
    emulatorConnected,
    endpoint: KUSTO_ENDPOINT
  };
});

// 2. GET /datasets
fastify.get('/datasets', async () => {
  const datasets = [
    { id: 'scenario-01', title: 'Scenario 01: Password spray to inbox rule exfiltration' },
    { id: 'scenario-02', title: 'Scenario 02: Phishing document to persistence' },
    { id: 'scenario-03', title: 'Scenario 03: Ransomware precursors' },
    { id: 'baseline', title: 'Benign Enterprise Baseline Noise' }
  ];
  return { datasets };
});

// 3. POST /datasets/:id/load
fastify.post<{ Params: { id: string } }>('/datasets/:id/load', async (request, reply) => {
  const { id } = request.params;
  const isHealthy = await kusto.isHealthy();

  if (!isHealthy) {
    return reply.status(503).send({
      error: 'Kusto emulator is offline or unreachable at ' + KUSTO_ENDPOINT
    });
  }

  const tableSchemas = loadTableSchemas(tablesDir);

  // Initialize tables in emulator
  for (const [name, schema] of tableSchemas.entries()) {
    try {
      await kusto.createTable(name, schema.columns);
    } catch (err) {
      fastify.log.warn(`Table creation notice for ${name}: ${err}`);
    }
  }

  // Load dataset
  const scMap: Record<string, string> = {
    'scenario-01': '01-password-spray-to-mailbox-rule.yml',
    'scenario-02': '02-phish-to-powershell-to-persistence.yml',
    'scenario-03': '03-ransomware-precursors.yml'
  };

  if (!scMap[id]) {
    return reply.status(404).send({ error: `Dataset ${id} not found` });
  }

  const scPath = path.join(scenariosDir, scMap[id]);
  const scenario = loadScenarioFromFile(scPath);
  const dataset = generateScenarioDataset(scenario);

  const loadedSummary: Record<string, number> = {};

  for (const [table, rows] of dataset.entries()) {
    const schema = tableSchemas.get(table);
    if (!schema) continue;
    const colNames = schema.columns.map(c => c.name);

    await kusto.ingestRows(table, colNames, rows);
    loadedSummary[table] = rows.length;
  }

  return {
    status: 'loaded',
    dataset: id,
    summary: loadedSummary
  };
});

// 4. POST /run (Safety restricted read-only query execution)
interface RunBody {
  query: string;
  datasetId?: string;
  params?: Record<string, any>;
}

fastify.post<{ Body: RunBody }>('/run', async (request, reply) => {
  const { query } = request.body;

  if (!query || typeof query !== 'string') {
    return reply.status(400).send({ error: 'Missing required field: query' });
  }

  // Security guardrail: no management dot-commands permitted
  const sanitized = query.trim();
  if (sanitized.startsWith('.')) {
    return reply.status(403).send({
      error: 'Security restriction: Kusto management dot-commands are not allowed in Lab execution mode.'
    });
  }

  const isHealthy = await kusto.isHealthy();
  if (!isHealthy) {
    return reply.status(503).send({
      error: 'Kusto emulator is offline. Start the container via "docker compose up -d kusto-emulator".'
    });
  }

  const startMs = Date.now();
  try {
    // Append safe row limit if not specified
    const limitedQuery = sanitized.includes('take') || sanitized.includes('limit')
      ? sanitized
      : `${sanitized}\n| take 1000`;

    const rows = await kusto.executeQuery(limitedQuery);
    const executionTimeMs = Date.now() - startMs;

    return {
      rows,
      count: rows.length,
      executionTimeMs
    };
  } catch (err) {
    return reply.status(500).send({
      error: `Query execution failed: ${err instanceof Error ? err.message : String(err)}`
    });
  }
});

// Start Server
try {
  await fastify.listen({ port: PORT, host: '127.0.0.1' });
  console.log(`\n🚀 HuntBook Lab API running on http://127.0.0.1:${PORT}`);
} catch (err) {
  fastify.log.error(err);
  process.exit(1);
}

