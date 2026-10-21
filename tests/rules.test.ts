import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { FAMILY_PREFIX, getRule, RULES } from '../src/rules.js';
import { FIXTURES } from './helpers.js';

const catalog = JSON.parse(readFileSync(join(FIXTURES, '..', '..', 'data', 'masvs.json'), 'utf8')) as {
  masvs: Record<string, string>;
  owasp: Record<string, string>;
};

describe('catálogo de reglas', () => {
  it.each(RULES.map((r) => [r.id, r]))('%s apunta a un control MASVS y una categoría OWASP existentes', (_id, rule) => {
    expect(Object.keys(catalog.masvs)).toContain(rule.masvs);
    expect(Object.keys(catalog.owasp)).toContain(rule.owasp);
    expect(FAMILY_PREFIX[rule.family]).toBeDefined();
    expect(rule.remediation.length).toBeGreaterThan(10);
  });

  it('los ids son únicos', () => {
    expect(new Set(RULES.map((r) => r.id)).size).toBe(RULES.length);
  });

  it('getRule falla con una regla desconocida', () => {
    expect(() => getRule('no/existe')).toThrow(/Regla desconocida/);
  });
});
