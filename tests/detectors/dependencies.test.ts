import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { dependenciesDetector, introducedBy, resolveNpm, reverseDependencies } from '../../src/detectors/dependencies.js';
import { buildContext } from '../../src/scanner.js';
import { FIXTURES, MIN_PKG, runDetector } from '../helpers.js';

const RECORDED = readFileSync(join(FIXTURES, '..', 'data', 'npm-audit-vulnerable-app.json'), 'utf8');

describe('dependenciesDetector', () => {
  it('convierte la salida real de npm audit en un hallazgo por paquete', async () => {
    const { ctx } = buildContext(join(FIXTURES, 'vulnerable-app'), { auditRunner: async () => RECORDED });
    const f = await dependenciesDetector.run(ctx);
    const byPkg = Object.fromEntries(f.map((x) => [x.evidence!['package'], x]));

    expect(Object.keys(byPkg).sort()).toEqual(['axios', 'decode-uri-component', 'image-size', 'lodash', 'node-forge', 'postcss']);
    expect(byPkg['axios']).toMatchObject({ severity: 'high', location: { file: 'package.json', line: 8 } });
    expect(byPkg['axios']!.evidence).toMatchObject({ direct: true, usedInSource: true, fix: 'axios@0.21.4' });
    expect(byPkg['lodash']!.evidence).toMatchObject({ direct: true, usedInSource: false });
    expect(byPkg['decode-uri-component']).toMatchObject({ severity: 'medium', location: { line: 12 } });
    // Transitiva que no está enlazada en effects: se atribuye usando package-lock.json
    expect(byPkg['image-size']!.evidence!['introducedBy']).toEqual(['expo', 'react-native']);
    expect(byPkg['node-forge']!.evidence!['fix']).toBe('expo@44.0.6 (cambio de versión mayor)');
  });

  it('sin lockfile de npm devuelve un aviso informativo y no ejecuta npm audit', async () => {
    let called = false;
    const runner = async () => {
      called = true;
      return '{}';
    };
    const none = await runDetector(dependenciesDetector, {}, { auditRunner: runner });
    expect(none[0]).toMatchObject({ ruleId: 'deps/no-lockfile' });
    const yarn = await runDetector(dependenciesDetector, { 'yarn.lock': '' }, { auditRunner: runner });
    expect(yarn[0]!.message).toMatch(/yarn/);
    expect(called).toBe(false);
  });

  it('--skip-deps no hace nada', async () => {
    const f = await runDetector(dependenciesDetector, { 'package-lock.json': '{}' }, { skipDependencies: true });
    expect(f).toEqual([]);
  });

  it('propaga el error de npm audit (sin red, registro caído...)', async () => {
    const files = { 'package.json': MIN_PKG, 'package-lock.json': '{}' };
    await expect(
      runDetector(dependenciesDetector, files, { auditRunner: async () => JSON.stringify({ error: { code: 'ENOTFOUND', summary: 'sin red' } }) }),
    ).rejects.toThrow(/sin red/);
  });

  it('localiza npm-cli.js para no depender de shell en Windows', () => {
    const { cmd, prefix } = resolveNpm();
    expect(cmd).toBe(process.execPath);
    expect(prefix[0]).toMatch(/npm-cli\.js$/);
  });
});

describe('reverseDependencies / introducedBy', () => {
  const lock = {
    packages: {
      '': { dependencies: { app: '1' } },
      'node_modules/app': { dependencies: { mid: '1' } },
      'node_modules/mid': { dependencies: { bad: '1' } },
      'node_modules/mid/node_modules/bad': {},
    },
  };

  it('construye el grafo inverso desde el lockfile', () => {
    const g = reverseDependencies(lock);
    expect([...g.direct]).toEqual(['app']);
    expect([...g.dependents.get('bad')!]).toEqual(['mid']);
  });

  it('sube hasta la dependencia directa aunque los intermedios no sean vulnerables', () => {
    const report = { bad: { name: 'bad', severity: 'high', isDirect: false, via: [], effects: [], range: '*', fixAvailable: false } };
    expect(introducedBy(report, 'bad')).toEqual([]);
    expect(introducedBy(report, 'bad', lock)).toEqual(['app']);
  });
});
