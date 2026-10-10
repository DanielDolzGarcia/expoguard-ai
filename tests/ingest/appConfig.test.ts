import { describe, expect, it } from 'vitest';
import { join } from 'node:path';
import { getPath, loadAppConfig, UNKNOWN } from '../../src/ingest/appConfig.js';
import { loadExpoProject } from '../../src/ingest/project.js';
import { FIXTURES, MIN_PKG, makeProject } from '../helpers.js';

function configOf(files: Record<string, string>) {
  return loadAppConfig(loadExpoProject(makeProject({ 'package.json': MIN_PKG, ...files })));
}

describe('loadAppConfig', () => {
  it('lee app.json, entra en "expo" y conserva las líneas', () => {
    const { config } = loadAppConfig(loadExpoProject(join(FIXTURES, 'vulnerable-app')));
    expect(config.file).toBe('app.json');
    expect(config.data['scheme']).toBe('myapp');
    expect(config.lineOf(['scheme'])).toBe(6);
    expect(config.lineOf(['android', 'allowBackup'])).toBe(9);
    expect(getPath(config.data, ['ios', 'infoPlist', 'NSAppTransportSecurity', 'NSAllowsArbitraryLoads'])).toBe(true);
    expect(config.lineOf(['plugins', '1', '1', 'android', 'usesCleartextTraffic'])).toBe(32);
  });

  it('evalúa app.config.ts con función flecha sin ejecutarlo', () => {
    const { config, warning } = loadAppConfig(loadExpoProject(join(FIXTURES, 'prebuild-app')));
    expect(warning).toBeUndefined();
    expect(config.data['scheme']).toBe('app');
    expect(config.data['name']).toBe(UNKNOWN); // depende de process.env
    expect(getPath(config.data, ['extra', 'sentryDsn'])).toBe(UNKNOWN);
    expect(config.lineOf(['android'])).toBe(10);
  });

  it('soporta module.exports con una constante y satisfies', () => {
    const { config } = configOf({
      'app.config.js': [
        "const IOS = { bundleIdentifier: 'com.a.b' };",
        'const config = { expo: { slug: `s`, ios: IOS, version: 1, x: null } };',
        'module.exports = config;',
      ].join('\n'),
    });
    expect(config.data).toMatchObject({ slug: 's', ios: { bundleIdentifier: 'com.a.b' }, version: 1, x: null });
  });

  it('soporta export default de un objeto con satisfies y función con return', () => {
    const a = configOf({ 'app.config.ts': "export default { slug: 'a' } satisfies ExpoConfig;" });
    expect(a.config.data['slug']).toBe('a');
    const b = configOf({ 'app.config.ts': "export default function () { const x = 1; return { slug: 'b' }; }" });
    expect(b.config.data['slug']).toBe('b');
  });

  it('avisa si no encuentra el objeto exportado o el fichero no parsea', () => {
    expect(configOf({ 'app.config.js': 'const a = 1;' }).warning).toMatch(/No se encontró/);
    expect(configOf({ 'app.config.ts': 'export default {' }).warning).toMatch(/No se pudo parsear/);
    expect(configOf({ 'app.json': '{ "expo": ' }).warning).toMatch(/Error leyendo/);
  });

  it('una clave __proto__ en app.json no altera el prototipo (regresión del aviso de ESLint)', () => {
    const { config } = configOf({
      'app.json': '{ "expo": { "__proto__": { "android": { "allowBackup": false } }, "slug": "p" } }',
    });
    expect(config.data['slug']).toBe('p');
    // Si el prototipo se hubiera contaminado, android.allowBackup "aparecería" heredado.
    expect(getPath(config.data, ['android', 'allowBackup'])).toBeUndefined();
    expect(Object.getPrototypeOf(config.data)).toBeNull();
  });

  it('sin fichero de configuración devuelve un objeto vacío', () => {
    const { config } = configOf({});
    expect(config.data).toEqual({});
    expect(config.lineOf(['x'])).toBeNull();
  });
});
