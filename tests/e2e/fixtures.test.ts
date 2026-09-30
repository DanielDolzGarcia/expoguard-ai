import { describe, expect, it } from 'vitest';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

// De momento solo se comprueba que las apps de prueba están bien formadas.
// Cuando estén los detectores (H2), este test pasará a comparar los hallazgos con expected.json.
const FIXTURES = join(import.meta.dirname, '..', 'fixtures');

describe('fixtures: apps Expo de prueba', () => {
  it.each(['vulnerable-app', 'safe-app', 'prebuild-app'])('%s es un proyecto Expo', (name) => {
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
});
