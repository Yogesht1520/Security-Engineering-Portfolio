import fs from 'node:fs';
import path from 'node:path';
import YAML from 'yaml';
import { KustoClient } from './kusto-client.js';
import type { TableSchema } from './schema-loader.js';

export interface TestExpectation {
  min_rows?: number;
  max_rows?: number;
  contains?: Record<string, any>;
}

export interface HuntTestCase {
  dataset: string;
  expect: TestExpectation;
}

export interface TestResult {
  huntId: string;
  dataset: string;
  passed: boolean;
  actualRows: number;
  errors: string[];
}

export function evaluateAssertions(
  rows: Record<string, any>[],
  expect: TestExpectation
): { passed: boolean; errors: string[] } {
  const errors: string[] = [];

  if (expect.min_rows !== undefined && rows.length < expect.min_rows) {
    errors.push(`Expected at least ${expect.min_rows} rows, but got ${rows.length}`);
  }

  if (expect.max_rows !== undefined && rows.length > expect.max_rows) {
    errors.push(`Expected at most ${expect.max_rows} rows, but got ${rows.length}`);
  }

  if (expect.contains) {
    for (const [key, expectedVal] of Object.entries(expect.contains)) {
      const match = rows.some(r => {
        const val = r[key];
        if (val === undefined) return false;
        return String(val).toLowerCase().includes(String(expectedVal).toLowerCase());
      });
      if (!match) {
        errors.push(`No row contained field '${key}' with value '${expectedVal}'`);
      }
    }
  }

  return {
    passed: errors.length === 0,
    errors
  };
}

