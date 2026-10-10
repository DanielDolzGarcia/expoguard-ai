import { describe, expect, it } from 'vitest';
import { join } from 'node:path';
import { ExpoProjectError, loadExpoProject } from '../../src/ingest/project.js';
import { FIXTURES, MIN_PKG, makeProject } from '../helpers.js';

describe('loadExpoProject', () => {
  it('rechaza una ruta que no existe', () => {
    expect(() => loadExpoProject(join(FIXTURES, 'no-existe'))).toThrow(ExpoProjectError);
  });

  it('rechaza un directorio sin package.json', () => {
    const dir = makeProject({ 'README.md': 'hola' });
    expect(() => loadExpoProject(dir)).toThrow(/package.json/);
  });

  it('rechaza un package.json inválido', () => {
    const dir = makeProject({ 'package.json': '{ esto no es json' });
    expect(() => loadExpoProject(dir)).toThrow(/JSON válido/);
  });

  it('rechaza un proyecto que no depende de expo', () => {
    const dir = makeProject({ 'package.json': JSON.stringify({ dependencies: { react: '19.0.0' } }) });
    expect(() => loadExpoProject(dir)).toThrow(/no es un proyecto Expo/);
  });

  it('reconoce la fixture vulnerable como managed con app.json y lockfile npm', () => {
    const p = loadExpoProject(join(FIXTURES, 'vulnerable-app'));
    expect(p).toMatchObject({ name: 'vulnshop', configFile: 'app.json', workflow: 'managed', lockfile: 'npm' });
    expect(p.expoVersion).toBe('~54.0.0');
  });

  it('reconoce prebuild y da prioridad a app.config.ts', () => {
    const p = loadExpoProject(join(FIXTURES, 'prebuild-app'));
    expect(p.workflow).toBe('prebuild');
    expect(p.configFile).toBe('app.config.ts');
    expect(p.lockfile).toBeNull();
  });

  it('acepta expo en devDependencies y detecta yarn', () => {
    const dir = makeProject({
      'package.json': JSON.stringify({ devDependencies: { expo: '54.0.1' } }),
      'yarn.lock': '',
      'app.json': '{}',
      'app.config.js': 'module.exports = {}',
    });
    const p = loadExpoProject(dir);
    expect(p.lockfile).toBe('yarn');
    expect(p.configFile).toBe('app.config.js');
    expect(p.name).toBe('sin-nombre');
  });

  it('funciona sin fichero de configuración', () => {
    const p = loadExpoProject(makeProject({ 'package.json': MIN_PKG }));
    expect(p.configFile).toBeNull();
  });
});
