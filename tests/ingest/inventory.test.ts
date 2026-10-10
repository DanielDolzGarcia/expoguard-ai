import { describe, expect, it } from 'vitest';
import { mkdirSync, symlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { buildInventory, classify, MAX_FILE_SIZE } from '../../src/ingest/inventory.js';
import { MIN_PKG, makeProject } from '../helpers.js';

describe('classify', () => {
  it.each([
    ['src/App.tsx', 'source'],
    ['index.js', 'source'],
    ['metro.config.cjs', 'source'],
    ['types/global.d.ts', 'other'],
    ['app.json', 'config'],
    ['app.config.ts', 'config'],
    ['eas.json', 'config'],
    ['packages/x/package.json', 'other'],
    ['.env', 'env'],
    ['.env.production', 'env'],
    ['android/app/src/main/AndroidManifest.xml', 'native'],
    ['ios/App/Info.plist', 'native'],
    ['assets/logo.png', 'other'],
  ])('%s -> %s', (path, kind) => {
    expect(classify(path)).toBe(kind);
  });
});

describe('buildInventory', () => {
  it('ignora node_modules, .git, build y Pods, y no incluye lockfiles', () => {
    const dir = makeProject({
      'package.json': MIN_PKG,
      'package-lock.json': '{}',
      'App.tsx': 'export default 1',
      'node_modules/lib/index.js': 'x',
      '.git/config': 'x',
      'android/app/build/gen.js': 'x',
      'ios/Pods/a.js': 'x',
      'src/a.ts': 'export const a = 1',
    });
    const paths = buildInventory(dir).files.map((f) => f.path);
    expect(paths).toEqual(['App.tsx', 'package.json', 'src/a.ts']);
  });

  it('omite ficheros de más de 1 MB y lo registra', () => {
    const dir = makeProject({ 'package.json': MIN_PKG });
    writeFileSync(join(dir, 'big.js'), 'a'.repeat(MAX_FILE_SIZE + 1));
    const inv = buildInventory(dir);
    expect(inv.files.map((f) => f.path)).not.toContain('big.js');
    expect(inv.skipped).toContainEqual({ path: 'big.js', reason: 'más de 1024 KB' });
  });

  it('no sigue enlaces simbólicos que salen del proyecto', () => {
    const outside = makeProject({ 'secret.ts': 'export const k = "fuera"' });
    const dir = makeProject({ 'package.json': MIN_PKG });
    mkdirSync(join(dir, 'src'));
    // 'junction' funciona en Windows sin permisos de administrador
    symlinkSync(outside, join(dir, 'src', 'link'), 'junction');
    const inv = buildInventory(dir);
    expect(inv.files.map((f) => f.path)).not.toContain('src/link/secret.ts');
    expect(inv.skipped.map((s) => s.reason)).toContain('enlace simbólico');
  });
});
