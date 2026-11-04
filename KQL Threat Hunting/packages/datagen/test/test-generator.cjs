const path = require('path');
const { loadScenarioFromFile, generateScenarioDataset } = require('../dist/index.js');

const scenarios = [
  '01-password-spray-to-mailbox-rule.yml',
  '02-phish-to-powershell-to-persistence.yml',
  '03-ransomware-precursors.yml'
];

for (const scName of scenarios) {
  const scPath = path.resolve(__dirname, '../../../scenarios', scName);
  const scenario = loadScenarioFromFile(scPath);
  console.log(`\nScenario: ${scenario.id} - ${scenario.title}`);
  const dataset = generateScenarioDataset(scenario);

  for (const [table, rows] of dataset.entries()) {
    console.log(`  Table: ${table} -> ${rows.length} rows generated`);
  }
}

