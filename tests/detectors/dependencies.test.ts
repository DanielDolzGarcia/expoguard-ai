import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { dependenciesDetector, introducedBy, lockMetadataFindings, resolveNpm, reverseDependencies } from '../../src/detectors/dependencies.js';
import { buildContext } from '../../src/scanner.js';
import { FIXTURES, makeProject, recordedOsvClient, runDetector } from '../helpers.js';

const RECORDED = readFileSync(join(FIXTURES, '..', 'data', 'npm-audit-vulnerable-app.json'), 'utf8');

describe('dependenciesDetector', () => {
  it('convierte la salida real de npm audit en un hallazgo por paquete', async () => {
    const { ctx } = buildContext(join(FIXTURES, 'vulnerable-app'), { auditRunner: async () => RECORDED });
    const f = (await dependenciesDetector.run(ctx)).filter((x) => x.ruleId === 'deps/known-vulnerability');
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

  it('sin lockfile, o con uno de bun, devuelve un aviso informativo y no ejecuta npm audit', async () => {
    let called = false;
    const runner = async () => {
      called = true;
      return '{}';
    };
    const none = await runDetector(dependenciesDetector, {}, { auditRunner: runner });
    expect(none[0]).toMatchObject({ ruleId: 'deps/no-lockfile', message: 'No hay lockfile versionado.' });
    const bun = await runDetector(dependenciesDetector, { 'bun.lock': '{}' }, { auditRunner: runner });
    expect(bun[0]!.message).toMatch(/bun/);
    expect(called).toBe(false);
  });

  it('--skip-deps no hace nada (ni npm audit ni OSV)', async () => {
    const osv = recordedOsvClient();
    expect(await runDetector(dependenciesDetector, { 'package-lock.json': '{}' }, { skipDependencies: true })).toEqual([]);
    expect(await runDetector(dependenciesDetector, { 'yarn.lock': 'axios@0.21.1:\n  version "0.21.1"\n' }, { skipDependencies: true, osvClient: osv })).toEqual([]);
    expect(osv.calls.batch).toBe(0);
  });

  it('si npm audit falla, avisa y conserva lo que no necesita red', async () => {
    const lock = JSON.stringify({
      packages: { '': { dependencies: { viejo: '1.0.0' } }, 'node_modules/viejo': { version: '1.0.0', license: 'MIT', deprecated: 'Ya no se mantiene' } },
    });
    const dir = makeProject({ 'package.json': JSON.stringify({ dependencies: { expo: '~54.0.0', viejo: '1.0.0' } }), 'package-lock.json': lock });
    const { ctx, warnings } = buildContext(dir, { auditRunner: async () => JSON.stringify({ error: { code: 'ENOTFOUND', summary: 'sin red' } }) });
    const f = await dependenciesDetector.run(ctx);
    expect(f.map((x) => x.ruleId)).toEqual(['deps/deprecated-package']);
    expect(warnings.map((w) => w.message)).toEqual([
      'npm audit no se pudo completar (sin red): no se han comprobado vulnerabilidades conocidas.',
    ]);
  });

  it('localiza npm-cli.js para no depender de shell en Windows', () => {
    const { cmd, prefix } = resolveNpm();
    expect(cmd).toBe(process.execPath);
    expect(prefix[0]).toMatch(/npm-cli\.js$/);
  });
});

describe('lockMetadataFindings: obsoletos y licencias (package-lock.json real de vulnerable-app)', () => {
  const lock = JSON.parse(readFileSync(join(FIXTURES, 'vulnerable-app', 'package-lock.json'), 'utf8')) as Parameters<typeof lockMetadataFindings>[1];

  it('agrupa los obsoletos por nombre@versión y los atribuye a la dependencia directa', () => {
    const { ctx } = buildContext(join(FIXTURES, 'vulnerable-app'), { skipDependencies: true });
    const dep = lockMetadataFindings(ctx, lock).filter((f) => f.ruleId === 'deps/deprecated-package');
    const byPkg = Object.fromEntries(dep.map((f) => [`${f.evidence!['package']}@${f.evidence!['version']}`, f]));

    expect(Object.keys(byPkg).sort()).toEqual(['glob@7.2.3', 'inflight@1.0.6', 'rimraf@3.0.2']);
    // glob@7.2.3 aparece 5 veces en el árbol: un solo hallazgo
    expect(byPkg['glob@7.2.3']!.message).toMatch(/aparece 5 veces/);
    for (const f of dep) {
      expect(f.severity).toBe('low'); // todas son transitivas
      expect(f.evidence!['direct']).toBe(false);
      expect((f.evidence!['introducedBy'] as string[]).length).toBeGreaterThan(0);
    }
  });

  it('los paquetes sin licencia en el lockfile se agrupan en un único aviso informativo', () => {
    const { ctx } = buildContext(join(FIXTURES, 'vulnerable-app'), { skipDependencies: true });
    const lic = lockMetadataFindings(ctx, lock).filter((f) => f.ruleId === 'deps/license-issue');
    expect(lic).toHaveLength(1);
    expect(lic[0]!.severity).toBeUndefined(); // usa la de la regla: info
    // Los dos declaran licencia con el campo antiguo "licenses", que npm no copia al lockfile
    expect(lic[0]!.evidence!['packages']).toEqual(['qrcode-terminal@0.11.0', 'requireg@0.2.2']);
  });

  it('obsoleto directo = media; licencia propietaria = baja; ignora enlaces locales', () => {
    const dir = makeProject({ 'package.json': JSON.stringify({ dependencies: { expo: '~54.0.0', viejo: '1.0.0', priv: '2.0.0' } }) });
    const { ctx } = buildContext(dir, { skipDependencies: true });
    const f = lockMetadataFindings(ctx, {
      packages: {
        '': { dependencies: { viejo: '1.0.0', priv: '2.0.0', local: 'file:../local' } },
        'node_modules/viejo': { version: '1.0.0', license: 'MIT', deprecated: 'Usa "nuevo"' },
        'node_modules/priv': { version: '2.0.0', license: 'UNLICENSED' },
        'node_modules/local': { link: true },
      },
    });
    expect(f.find((x) => x.ruleId === 'deps/deprecated-package')).toMatchObject({ severity: 'medium', location: { line: 1 } });
    expect(f.find((x) => x.ruleId === 'deps/license-issue')).toMatchObject({ severity: 'low', evidence: { package: 'priv', license: 'UNLICENSED' } });
    expect(f).toHaveLength(2);
  });
});

describe('respaldo con OSV (yarn y pnpm)', () => {
  it('yarn-app: un hallazgo por paquete vulnerable, con la versión que lo corrige', async () => {
    const osv = recordedOsvClient();
    const { ctx } = buildContext(join(FIXTURES, 'yarn-app'), { osvClient: osv, auditRunner: async () => Promise.reject(new Error('no debe llamarse')) });
    const f = await dependenciesDetector.run(ctx);
    const byPkg = Object.fromEntries(f.map((x) => [x.evidence!['package'], x]));

    expect(Object.keys(byPkg).sort()).toEqual(['axios', 'follow-redirects', 'lodash', 'minimist']);
    expect(osv.calls.batch).toBe(1);
    expect(byPkg['axios']).toMatchObject({ location: { file: 'package.json', line: 8 }, evidence: { direct: true, usedInSource: true, source: 'osv.dev' } });
    expect((byPkg['axios']!.evidence!['advisories'] as string[]).length).toBe(24);
    expect(byPkg['lodash']!.evidence).toMatchObject({ direct: true, usedInSource: false });
    // Transitivas: se señalan en su entrada del lockfile
    expect(byPkg['follow-redirects']).toMatchObject({ location: { file: 'yarn.lock', line: 22 }, evidence: { direct: false } });
    expect(byPkg['minimist']!.evidence!['fix']).toBe('1.2.6');
  });

  it('pnpm: lee pnpm-lock.yaml y consulta OSV', async () => {
    const osv = recordedOsvClient();
    const pnpm = ['lockfileVersion: "9.0"', 'packages:', '  lodash@4.17.15:', '    resolution: {integrity: x}', '  react@19.1.0:', '    resolution: {integrity: y}'].join('\n');
    const f = await runDetector(dependenciesDetector, { 'pnpm-lock.yaml': pnpm }, { osvClient: osv });
    expect(f.map((x) => `${x.evidence!['package']} @ ${x.location.file}:${x.location.line}`)).toEqual(['lodash @ pnpm-lock.yaml:3']);
  });

  it('un lockfile vacío o ilegible no llama a OSV', async () => {
    const osv = recordedOsvClient();
    expect(await runDetector(dependenciesDetector, { 'yarn.lock': '# vacío\n' }, { osvClient: osv })).toEqual([]);
    expect(osv.calls.batch).toBe(0);
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
