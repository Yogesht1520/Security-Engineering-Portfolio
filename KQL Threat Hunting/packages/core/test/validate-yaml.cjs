const fs = require('fs');
const path = require('path');
const YAML = require('yaml');
const Ajv = require('ajv');
const addFormats = require('ajv-formats');

const ajv = new Ajv({ allErrors: true, allowUnionTypes: true });
addFormats(ajv);

const schemaJson = JSON.parse(fs.readFileSync(path.resolve(__dirname, '../../../schemas/hunt.schema.json'), 'utf8'));
const validate = ajv.compile(schemaJson);

const yamlContent = fs.readFileSync(path.resolve(__dirname, '../../../hunts/identity/T1110.003-password-spray.hunt.yml'), 'utf8');
const data = YAML.parse(yamlContent);

const valid = validate(data);
console.log('YAML schema validation valid?', valid);
if (!valid) {
  console.error('Validation errors:', validate.errors);
} else {
  console.log('SUCCESS: HB-ID-001 metadata passed JSON schema validation with full format checking!');
}
