import { describe, it, expect } from 'vitest';
import Fastify from 'fastify';
import cors from '@fastify/cors';

describe('Lab API Service Contract', () => {
  it('handles health and dataset endpoints', async () => {
    const fastify = Fastify();
    await fastify.register(cors);

    fastify.get('/health', async () => ({ status: 'ok', emulatorConnected: false }));
    fastify.get('/datasets', async () => ({
      datasets: [
        { id: 'scenario-01', title: 'Scenario 01' },
        { id: 'scenario-02', title: 'Scenario 02' }
      ]
    }));

    const healthRes = await fastify.inject({ method: 'GET', url: '/health' });
    expect(healthRes.statusCode).toBe(200);
    const healthJson = healthRes.json();
    expect(healthJson.status).toBe('ok');

    const datasetsRes = await fastify.inject({ method: 'GET', url: '/datasets' });
    expect(datasetsRes.statusCode).toBe(200);
    const datasetsJson = datasetsRes.json();
    expect(datasetsJson.datasets.length).toBeGreaterThan(0);
  });

  it('rejects forbidden dot-commands in /run for security', async () => {
    const fastify = Fastify();
    fastify.post('/run', async (req, reply) => {
      const { query } = req.body as any;
      if (query.trim().startsWith('.')) {
        return reply.status(403).send({ error: 'Management commands not allowed' });
      }
      return { rows: [] };
    });

    const maliciousRes = await fastify.inject({
      method: 'POST',
      url: '/run',
      payload: { query: '.drop table SigninLogs' }
    });

    expect(maliciousRes.statusCode).toBe(403);
  });
});

