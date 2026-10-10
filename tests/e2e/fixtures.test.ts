import { describe, expect, it } from 'vitest';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { scan } from '../../src/scanner.js';
import { FIXTURES } from '../helpers.js';

// De momento se comprueba que las apps de prueba están bien formadas y que la ingesta las parsea.
// Cuando estén los detectores (H2), este test pasará a comparar los hallazgos con expected.json.
const APPS = ['vulnerable-app', 'safe-app', 'prebuild-app'];

describe('fixtures: apps Expo de prueba', () => {
  it.each(APPS)('%s es un proyecto Expo', (name) => {
    const pkg = JSON.parse(readFileSync(join(FIXTURES, name, 'package.json'), 'utf8')) as {
      dependencies?: Record<string, string>;
    };
    expect(pkg.dependencies?.expo).toBeDefined();
  });

  it.each(['vulnerable-app', 'prebuild-app'])('%s documenta sus vulnerabilidades en expected.json', (name) => {
    const expected = JSON.parse(readFileSync(join(FIXTURES, name, 'expected.json'), 'utf8')) as {
      findings: Array<{ ruleId: string; file: string; line: number }>;
    };
    expect(expected.findings.length).toBeGreaterThan(0);
    for (const f of expected.findings) {
      expect(existsSync(join(FIXTURES, name, f.file))).toBe(true);
    }
  });

  it.each(APPS)('%s se parsea entero sin errores', async (name) => {
    const result = await scan(join(FIXTURES, name));
    expect(result.stats.sourceFiles).toBeGreaterThan(0);
    expect(result.stats.parsedFiles).toBe(result.stats.sourceFiles);
    expect(result.warnings.filter((w) => w.message.startsWith('Error de parseo'))).toEqual([]);
  });
});
