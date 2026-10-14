/* eslint-disable security/detect-non-literal-fs-filename -- todas las rutas son join(root, <nombre fijo>) */
import { existsSync, readFileSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';
import type { ExpoProject } from '../types.js';

export class ExpoProjectError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ExpoProjectError';
  }
}

const CONFIG_FILES = ['app.config.ts', 'app.config.js', 'app.config.mjs', 'app.config.cjs', 'app.json'];

const LOCKFILES: Array<[string, NonNullable<ExpoProject['lockfile']>]> = [
  ['package-lock.json', 'npm'],
  ['yarn.lock', 'yarn'],
  ['pnpm-lock.yaml', 'pnpm'],
  ['bun.lockb', 'bun'],
  ['bun.lock', 'bun'],
];

interface PackageJson {
  name?: string;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
}

/** Comprueba que `dir` es un proyecto Expo y recoge sus datos básicos. No ejecuta nada del proyecto. */
export function loadExpoProject(dir: string): ExpoProject {
  const root = resolve(dir);
  if (!existsSync(root) || !statSync(root).isDirectory()) {
    throw new ExpoProjectError(`La ruta no existe o no es un directorio: ${root}`);
  }

  const pkgPath = join(root, 'package.json');
  if (!existsSync(pkgPath)) {
    throw new ExpoProjectError('No se encuentra package.json: no parece un proyecto Node/Expo.');
  }

  let pkg: PackageJson;
  try {
    pkg = JSON.parse(readFileSync(pkgPath, 'utf8')) as PackageJson;
  } catch (err) {
    throw new ExpoProjectError(`package.json no es JSON válido: ${(err as Error).message}`);
  }

  const dependencies = { ...pkg.devDependencies, ...pkg.dependencies };
  const expoVersion = dependencies['expo'];
  if (!expoVersion) {
    throw new ExpoProjectError('package.json no declara la dependencia "expo": no es un proyecto Expo.');
  }

  // app.config.* tiene prioridad sobre app.json, igual que en Expo CLI.
  const configFile = CONFIG_FILES.find((f) => existsSync(join(root, f))) ?? null;

  const hasNative = existsSync(join(root, 'android')) || existsSync(join(root, 'ios'));

  const lockfile = LOCKFILES.find(([f]) => existsSync(join(root, f)))?.[1] ?? null;

  return {
    root,
    name: pkg.name ?? 'sin-nombre',
    expoVersion,
    configFile,
    workflow: hasNative ? 'prebuild' : 'managed',
    lockfile,
    dependencies,
  };
}
