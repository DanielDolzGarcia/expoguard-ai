import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { scan, severityAtLeast } from '../../src/scanner.js';
import type { ScanResult } from '../../src/types.js';
import { FIXTURES } from '../helpers.js';

interface Expected {
  findings: Array<{ ruleId: string; file: string; line: number }>;
}

const RECORDED = readFileSync(join(FIXTURES, '..', 'data', 'npm-audit-vulnerable-app.json'), 'utf8');

function expectedOf(name: string): Expected {
  return JSON.parse(readFileSync(join(FIXTURES, name, 'expected.json'), 'utf8')) as Expected;
}

function key(f: { ruleId: string; file: string; line: number }) {
  return `${f.ruleId} @ ${f.file}:${f.line}`;
}

function compare(result: ScanResult, expected: Expected) {
  const got = new Set(result.findings.map((f) => key({ ruleId: f.ruleId, file: f.location.file, line: f.location.line })));
  const want = expected.findings.map(key);
  return { missing: want.filter((k) => !got.has(k)), extra: [...got].filter((k) => !want.includes(k)) };
}

describe('e2e: fixtures con vulnerabilidades conocidas', () => {
  it('vulnerable-app: detecta TODAS las vulnerabilidades insertadas', async () => {
    const result = await scan(join(FIXTURES, 'vulnerable-app'), { auditRunner: async () => RECORDED });
    const { missing, extra } = compare(result, expectedOf('vulnerable-app'));
    expect(missing).toEqual([]);
    // Lo que sobra son dependencias transitivas reales del árbol de Expo (no insertadas a mano).
    expect(extra.every((k) => k.startsWith('deps/known-vulnerability @ package.json'))).toBe(true);
    expect(result.warnings).toEqual([]);
  });

  it('prebuild-app: app.config.ts dinámico, AndroidManifest e Info.plist', async () => {
    const result = await scan(join(FIXTURES, 'prebuild-app'), { skipDependencies: true });
    const { missing, extra } = compare(result, expectedOf('prebuild-app'));
    expect(missing).toEqual([]);
    expect(extra).toEqual([]);
  });

  it('safe-app: ningún hallazgo de severidad media o superior', async () => {
    const result = await scan(join(FIXTURES, 'safe-app'));
    const serious = result.findings.filter((f) => severityAtLeast(f.severity, 'medium'));
    expect(serious).toEqual([]);
  });

  it('ningún hallazgo contiene un secreto completo de las fixtures', async () => {
    const result = await scan(join(FIXTURES, 'vulnerable-app'), { auditRunner: async () => RECORDED });
    const json = JSON.stringify(result);
    for (const secret of ['FAKE00EXPOGUARD00000000000', 'AKIAIOSFODNN7EXAMPLE', 'FAKEexpoguard0000000000000000', 'Zx9fQ2LmP8vR4tW7yB1nK6hJ3sD5gA0c']) {
      expect(json).not.toContain(secret);
    }
  });

  it('asigna ids por familia y ordena por severidad', async () => {
    const result = await scan(join(FIXTURES, 'vulnerable-app'), { skipDependencies: true });
    expect(result.findings[0]!.severity).toBe('critical');
    expect(result.findings.find((f) => f.family === 'storage')!.id).toBe('STORAGE-001');
    const total = Object.values(result.stats.bySeverity).reduce((a, b) => a + b, 0);
    expect(total).toBe(result.findings.length);
  });

  it('un detector que falla no tumba el análisis: queda como aviso', async () => {
    const result = await scan(join(FIXTURES, 'vulnerable-app'), {
      auditRunner: async () => {
        throw new Error('ENOTFOUND registry.npmjs.org');
      },
    });
    expect(result.warnings.map((w) => w.message)).toEqual(['Falló el detector dependencies: Error: ENOTFOUND registry.npmjs.org']);
    expect(result.findings.length).toBeGreaterThan(20);
  });

  it('un fichero con error de sintaxis se registra y el resto se analiza', async () => {
    const { makeProject, MIN_PKG } = await import('../helpers.js');
    const dir = makeProject({
      'package.json': MIN_PKG,
      'roto.ts': 'const = ;',
      'ok.ts': "import AsyncStorage from '@react-native-async-storage/async-storage';\nAsyncStorage.setItem('token', t);",
    });
    const result = await scan(dir, { skipDependencies: true });
    expect(result.warnings[0]!.message).toMatch(/Error de parseo/);
    expect(result.findings.map((f) => f.ruleId)).toContain('storage/async-storage-sensitive');
  });
});
