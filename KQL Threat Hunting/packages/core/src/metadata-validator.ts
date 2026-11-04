import fs from 'node:fs';
import YAML from 'yaml';
import Ajv from 'ajv';
import addFormats from 'ajv-formats';

export interface ValidationResult {
  valid: boolean;
  errors: string[];
  data?: any;
}

let ajvInstance: any = null;
let validateFn: any = null;

export function getAjvValidator(schemaPath: string) {
  if (validateFn) return validateFn;

  const schemaContent = fs.readFileSync(schemaPath, 'utf8');
  const schema = JSON.parse(schemaContent);

  const ajv = new (Ajv as any)({ allErrors: true, allowUnionTypes: true });
  (addFormats as any)(ajv);
  validateFn = ajv.compile(schema);
  ajvInstance = ajv;
  return validateFn;
}

export function validateHuntMetadata(yamlPath: string, schemaPath: string): ValidationResult {
  if (!fs.existsSync(yamlPath)) {
    return { valid: false, errors: [`File not found: ${yamlPath}`] };
  }

  const content = fs.readFileSync(yamlPath, 'utf8');
  let data: any;
  try {
    data = YAML.parse(content);
  } catch (err) {
    return { valid: false, errors: [`YAML parsing error: ${err instanceof Error ? err.message : String(err)}`] };
  }

  const validate = getAjvValidator(schemaPath);
  const valid = validate(data);

  if (!valid) {
    const errors = (validate.errors || []).map((e: any) => `${e.instancePath || 'root'}: ${e.message}`);
    return { valid: false, errors, data };
  }

  return { valid: true, errors: [], data };
}

