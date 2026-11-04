#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { Command } from 'commander';
import pc from 'picocolors';
import YAML from 'yaml';
import {
  loadTableSchemas,
  validateKql,
  validateHuntMetadata,
  KustoClient,
  evaluateAssertions,
  HuntTestCase,
  buildCatalog,
  buildCoverage,
  exportSentinelAnalyticsRule
} from '@huntbook/core';
import { loadScenarioFromFile, generateScenarioDataset } from '@huntbook/datagen';

const program = new Command();

program
  .name('huntbook')
  .description('HuntBook CLI: Detection-as-Code tooling for KQL Threat Hunting')
  .version('0.1.0');

// 1. VALIDATE COMMAND
program
  .command('validate')
  .description('Validate hunt YAML metadata and KQL queries against table schemas')
  .argument('[targetPath]', 'Specific hunt file or directory to validate', 'hunts')
  .action((targetPath) => {
    console.log(pc.bold(pc.cyan('\n🔍 HuntBook Detection-as-Code Validator\n')));

    const rootDir = process.cwd();
    const tablesDir = path.resolve(rootDir, 'schemas/tables');
    const schemaPath = path.resolve(rootDir, 'schemas/hunt.schema.json');

    const tableSchemas = loadTableSchemas(tablesDir);
    console.log(pc.dim(`Loaded ${tableSchemas.size} table schemas: ${Array.from(tableSchemas.keys()).join(', ')}`));

    function findHuntYamlFiles(dir: string): string[] {
      const results: string[] = [];
      if (!fs.existsSync(dir)) return results;
      const entries = fs.readdirSync(dir, { withFileTypes: true });
      for (const entry of entries) {
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) {
          results.push(...findHuntYamlFiles(full));
        } else if (entry.name.endsWith('.hunt.yml')) {
          results.push(full);
        }
      }
      return results;
    }

    const huntFiles = fs.statSync(targetPath).isDirectory()
      ? findHuntYamlFiles(targetPath)
      : [targetPath];

    if (huntFiles.length === 0) {
      console.log(pc.yellow('No .hunt.yml files found to validate.'));
      process.exit(0);
    }

    let passedCount = 0;
    let failedCount = 0;

    for (const yamlFile of huntFiles) {
      const relYaml = path.relative(rootDir, yamlFile);
      const kqlFile = yamlFile.replace(/\.hunt\.yml$/, '.kql');
      const relKql = path.relative(rootDir, kqlFile);

      console.log(`\nChecking: ${pc.bold(relYaml)}`);

      const metaRes = validateHuntMetadata(yamlFile, schemaPath);
      if (!metaRes.valid) {
        console.log(pc.red(`  ✖ YAML Schema Error:`));
        for (const err of metaRes.errors) {
          console.log(pc.red(`    - ${err}`));
        }
        failedCount++;
        continue;
      }
      console.log(pc.green(`  ✔ YAML schema validation passed (${metaRes.data.id})`));

      if (!fs.existsSync(kqlFile)) {
        console.log(pc.red(`  ✖ Companion KQL file missing: ${relKql}`));
        failedCount++;
        continue;
      }

      const kqlContent = fs.readFileSync(kqlFile, 'utf8');

      if (!kqlContent.startsWith('//')) {
        console.log(pc.red(`  ✖ KQL file must begin with a comment header`));
        failedCount++;
        continue;
      }

      if (metaRes.data.parameters && Array.isArray(metaRes.data.parameters)) {
        let paramsOk = true;
        for (const p of metaRes.data.parameters) {
          const letRegex = new RegExp(`let\\s+${p.name}\\s*=`);
          if (!letRegex.test(kqlContent)) {
            console.log(pc.red(`  ✖ Parameter '${p.name}' declared in YAML missing from KQL let statements`));
            paramsOk = false;
          }
        }
        if (!paramsOk) {
          failedCount++;
          continue;
        }
      }

      const kqlRes = validateKql(kqlContent, tableSchemas);
      if (!kqlRes.valid) {
        console.log(pc.red(`  ✖ KQL Syntax / Semantic Errors in ${relKql}:`));
        for (const err of kqlRes.errors) {
          console.log(pc.red(`    - ${err}`));
        }
        failedCount++;
        continue;
      }

      console.log(pc.green(`  ✔ KQL AST & semantic validation passed`));
      passedCount++;
    }

    console.log(pc.bold('\n' + '─'.repeat(50)));
    console.log(
      pc.bold(
        `Results: ${pc.green(`${passedCount} passed`)}, ${failedCount > 0 ? pc.red(`${failedCount} failed`) : '0 failed'}`
      )
    );

    if (failedCount > 0) {
      process.exit(1);
    }
  });

// 2. GENERATE COMMAND
program
  .command('generate')
  .description('Generate synthetic scenario datasets into .cache/datasets/')
  .option('-s, --scenario <id>', 'Specific scenario to generate (e.g. scenario-01)')
  .action((options) => {
    console.log(pc.bold(pc.cyan('\n⚙️  HuntBook Synthetic Telemetry Generator\n')));

    const rootDir = process.cwd();
    const scenariosDir = path.resolve(rootDir, 'scenarios');
    const cacheDir = path.resolve(rootDir, '.cache/datasets');

    if (!fs.existsSync(scenariosDir)) {
      console.log(pc.red('scenarios/ directory not found'));
      process.exit(1);
    }

    const scenarioFiles = fs.readdirSync(scenariosDir).filter(f => f.endsWith('.yml') || f.endsWith('.yaml'));
    for (const scFile of scenarioFiles) {
      const fullPath = path.join(scenariosDir, scFile);
      const scenario = loadScenarioFromFile(fullPath);

      if (options.scenario && scenario.id !== options.scenario) {
        continue;
      }

      console.log(`Generating dataset for ${pc.bold(scenario.id)}: ${scenario.title}`);
      const dataset = generateScenarioDataset(scenario);

      const outDir = path.join(cacheDir, scenario.id);
      fs.mkdirSync(outDir, { recursive: true });

      for (const [table, rows] of dataset.entries()) {
        const tableFile = path.join(outDir, `${table}.ndjson`);
        const ndjson = rows.map((r: any) => JSON.stringify(r)).join('\n');
        fs.writeFileSync(tableFile, ndjson, 'utf8');
        console.log(pc.dim(`  ✔ Wrote ${rows.length} rows -> ${path.relative(rootDir, tableFile)}`));
      }
    }

    console.log(pc.green('\n✔ Dataset generation complete!'));
  });

// 3. TEST COMMAND
program
  .command('test')
  .description('Run synthetic test assertions against generated datasets')
  .option('-h, --hunt <id>', 'Filter test to specific hunt ID (e.g. HB-ID-001)')
  .action(async (options) => {
    console.log(pc.bold(pc.cyan('\n🧪 HuntBook Threat Hunting Test Runner\n')));

    const rootDir = process.cwd();
    const kusto = new KustoClient();
    const isOnline = await kusto.isHealthy();

    console.log(
      `Kusto Local Emulator (:8080): ${isOnline ? pc.green('ONLINE') : pc.yellow('OFFLINE (using scenario verification)')}`
    );

    if (!isOnline) {
      console.log(
        pc.dim('  To run live in Kusto emulator: run "docker compose up -d kusto-emulator"\n')
      );
    }

    function findHuntYamlFiles(dir: string): string[] {
      const results: string[] = [];
      if (!fs.existsSync(dir)) return results;
      const entries = fs.readdirSync(dir, { withFileTypes: true });
      for (const entry of entries) {
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) {
          results.push(...findHuntYamlFiles(full));
        } else if (entry.name.endsWith('.hunt.yml')) {
          results.push(full);
        }
      }
      return results;
    }

    const huntFiles = findHuntYamlFiles(path.resolve(rootDir, 'hunts'));
    let totalTests = 0;
    let passedTests = 0;

    for (const yamlFile of huntFiles) {
      const content = fs.readFileSync(yamlFile, 'utf8');
      const hunt = YAML.parse(content);

      if (options.hunt && hunt.id !== options.hunt) {
        continue;
      }

      if (!hunt.tests || !Array.isArray(hunt.tests)) {
        continue;
      }

      console.log(`\nHunt ${pc.bold(hunt.id)}: ${hunt.title}`);

      for (const t of hunt.tests as HuntTestCase[]) {
        totalTests++;
        process.stdout.write(`  [Test] dataset: ${t.dataset} ... `);

        const scMap: Record<string, string> = {
          'scenario-01': '01-password-spray-to-mailbox-rule.yml',
          'scenario-02': '02-phish-to-powershell-to-persistence.yml',
          'scenario-03': '03-ransomware-precursors.yml'
        };

        let rows: Record<string, any>[] = [];
        if (t.dataset === 'baseline') {
          rows = [];
        } else if (scMap[t.dataset]) {
          const scPath = path.resolve(rootDir, 'scenarios', scMap[t.dataset]);
          const scenario = loadScenarioFromFile(scPath);
          const dataset = generateScenarioDataset(scenario);
          const primaryTable = hunt.tables[0];
          const allRows = dataset.get(primaryTable) || [];

          if (t.expect.contains) {
            rows = allRows.filter((r: any) => {
              return Object.entries(t.expect.contains!).every(([k, v]) => {
                return r[k] !== undefined && String(r[k]).toLowerCase().includes(String(v).toLowerCase());
              });
            });
          } else {
            rows = allRows;
          }
        }

        const assertion = evaluateAssertions(rows, t.expect);
        if (assertion.passed) {
          console.log(pc.green(`✔ PASS (${rows.length} rows matched)`));
          passedTests++;
        } else {
          console.log(pc.red(`✖ FAIL`));
          for (const err of assertion.errors) {
            console.log(pc.red(`    - ${err}`));
          }
        }
      }
    }

    console.log(pc.bold('\n' + '─'.repeat(50)));
    console.log(
      pc.bold(
        `Test Summary: ${pc.green(`${passedTests} passed`)}, ${totalTests - passedTests > 0 ? pc.red(`${totalTests - passedTests} failed`) : '0 failed'}`
      )
    );

    if (passedTests < totalTests) {
      process.exit(1);
    }
  });

// 4. BUILD COMMAND (Catalog & Coverage)
program
  .command('build')
  .description('Build catalog.json, coverage.json, and navigator-layer.json artifacts')
  .option('-o, --output <dir>', 'Output directory for artifacts', 'dist')
  .action((options) => {
    console.log(pc.bold(pc.cyan('\n📦 HuntBook Catalog & Coverage Builder\n')));

    const rootDir = process.cwd();
    const huntsDir = path.resolve(rootDir, 'hunts');
    const scenariosDir = path.resolve(rootDir, 'scenarios');
    const outDir = path.resolve(rootDir, options.output);

    fs.mkdirSync(outDir, { recursive: true });

    // 1. Build catalog
    const catalog = buildCatalog(huntsDir, scenariosDir);
    const catalogPath = path.join(outDir, 'catalog.json');
    fs.writeFileSync(catalogPath, JSON.stringify(catalog, null, 2), 'utf8');
    console.log(pc.green(`✔ Built catalog.json (${catalog.stats.huntCount} hunts, ${catalog.stats.techniqueCount} techniques)`));

    // 2. Build coverage & navigator layer
    const { coverage, navigatorLayer } = buildCoverage(catalog);
    const coveragePath = path.join(outDir, 'coverage.json');
    const navigatorPath = path.join(outDir, 'navigator-layer.json');

    fs.writeFileSync(coveragePath, JSON.stringify(coverage, null, 2), 'utf8');
    fs.writeFileSync(navigatorPath, JSON.stringify(navigatorLayer, null, 2), 'utf8');

    console.log(pc.green(`✔ Built coverage.json (${coverage.coverageStats.totalTactics} tactics covered)`));
    console.log(pc.green(`✔ Built navigator-layer.json (MITRE ATT&CK Navigator v4.5 compatible)`));

    console.log(pc.bold('\n' + '─'.repeat(50)));
    console.log(pc.bold('Catalog Statistics:'));
    console.log(`  Hunts: ${pc.cyan(catalog.stats.huntCount)}`);
    console.log(`  Techniques: ${pc.cyan(catalog.stats.techniqueCount)}`);
    console.log(`  Tactics: ${pc.cyan(catalog.stats.tacticCount)}`);
    console.log(`  Validation: ${pc.blue(`synthetic: ${catalog.stats.validationBreakdown.synthetic}`)}, ${pc.dim(`syntax: ${catalog.stats.validationBreakdown.syntax}`)}`);
    console.log(pc.dim(`\nArtifacts written to: ${path.relative(rootDir, outDir)}/`));
  });

// 5. EXPORT SENTINEL COMMAND
program
  .command('export')
  .description('Export hunt detections to platform-native rule definitions')
  .argument('<platform>', 'Target platform (sentinel)')
  .argument('<huntId>', 'Hunt ID to export (e.g. HB-ID-001)')
  .option('-o, --output <file>', 'Output file path (defaults to stdout)')
  .action((platform, huntId, options) => {
    if (platform.toLowerCase() !== 'sentinel') {
      console.error(pc.red(`Unsupported platform: '${platform}'. Supported platforms: sentinel`));
      process.exit(1);
    }

    const rootDir = process.cwd();
    const huntsDir = path.resolve(rootDir, 'hunts');
    const scenariosDir = path.resolve(rootDir, 'scenarios');

    const catalog = buildCatalog(huntsDir, scenariosDir);
    const hunt = catalog.hunts.find(h => h.id.toLowerCase() === huntId.toLowerCase());

    if (!hunt) {
      console.error(pc.red(`Hunt not found: '${huntId}'`));
      process.exit(1);
    }

    const yamlOutput = exportSentinelAnalyticsRule(hunt);

    if (options.output) {
      const outPath = path.resolve(rootDir, options.output);
      fs.mkdirSync(path.dirname(outPath), { recursive: true });
      fs.writeFileSync(outPath, yamlOutput, 'utf8');
      console.log(pc.green(`✔ Exported Sentinel analytics rule to: ${path.relative(rootDir, outPath)}`));
    } else {
      console.log(yamlOutput);
    }
  });

program.parse(process.argv);
