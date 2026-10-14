import { readdirSync, lstatSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import type { FileKind, InventoryFile } from '../types.js';

export const MAX_FILE_SIZE = 1024 * 1024;

const IGNORED_DIRS = new Set([
  'node_modules',
  '.git',
  '.expo',
  '.expo-shared',
  'dist',
  'web-build',
  'build',
  'coverage',
  'Pods',
  '.gradle',
  '.idea',
  '.vscode',
]);

const IGNORED_FILES = new Set(['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lockb', 'bun.lock']);

const SOURCE_EXT = /\.(?:[cm]?[jt]sx?)$/i;
const CONFIG_NAMES = /^(?:app\.json|app\.config\.[cm]?[jt]s|eas\.json|package\.json)$/;
const NATIVE_NAMES = /^(?:AndroidManifest\.xml|Info\.plist|network_security_config\.xml)$/;

export function classify(relPath: string): FileKind {
  const name = relPath.split('/').pop() ?? relPath;
  if (name === '.env' || name.startsWith('.env.')) return 'env';
  if (CONFIG_NAMES.test(name) && !relPath.includes('/')) return 'config';
  if (NATIVE_NAMES.test(name)) return 'native';
  if (SOURCE_EXT.test(name) && !name.endsWith('.d.ts')) return 'source';
  return 'other';
}

export interface Inventory {
  files: InventoryFile[];
  skipped: Array<{ path: string; reason: string }>;
}

/**
 * Recorre el proyecto y devuelve los ficheros a analizar.
 * No sigue enlaces simbólicos: un enlace podría apuntar fuera del proyecto (p. ej. a ~/.ssh).
 */
export function buildInventory(root: string): Inventory {
  const files: InventoryFile[] = [];
  const skipped: Inventory['skipped'] = [];

  // Las rutas salen del propio recorrido de `root` (elegido por el usuario) y nunca de enlaces simbólicos.
  const walk = (dir: string): void => {
    // eslint-disable-next-line security/detect-non-literal-fs-filename -- ver comentario anterior
    const entries = readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      const abs = join(dir, entry.name);
      const rel = relative(root, abs).split(sep).join('/');

      if (entry.isSymbolicLink()) {
        skipped.push({ path: rel, reason: 'enlace simbólico' });
        continue;
      }
      if (entry.isDirectory()) {
        if (IGNORED_DIRS.has(entry.name)) continue;
        walk(abs);
        continue;
      }
      if (!entry.isFile() || IGNORED_FILES.has(entry.name)) continue;

      const kind = classify(rel);
      if (kind === 'other') continue;

      // eslint-disable-next-line security/detect-non-literal-fs-filename -- ruta del recorrido de root
      const size = lstatSync(abs).size;
      if (size > MAX_FILE_SIZE) {
        skipped.push({ path: rel, reason: `más de ${MAX_FILE_SIZE / 1024} KB` });
        continue;
      }
      files.push({ path: rel, absPath: abs, kind, size });
    }
  };

  walk(root);
  files.sort((a, b) => a.path.localeCompare(b.path));
  return { files, skipped };
}
