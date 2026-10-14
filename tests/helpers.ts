import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach } from 'vitest';
import { buildContext } from '../src/scanner.js';
import type { Detector, RawFinding, ScanOptions } from '../src/types.js';

export const FIXTURES = resolve(dirname(fileURLToPath(import.meta.url)), 'fixtures');

const created: string[] = [];
afterEach(() => {
  while (created.length) rmSync(created.pop()!, { recursive: true, force: true });
});

export const MIN_PKG = JSON.stringify({ name: 'tmp-app', dependencies: { expo: '~54.0.0' } });

/** Crea un proyecto temporal con los ficheros indicados. Se borra al acabar cada test. */
export function makeProject(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), 'expoguard-'));
  created.push(dir);
  for (const [rel, content] of Object.entries(files)) {
    const abs = join(dir, rel);
    mkdirSync(dirname(abs), { recursive: true });
    writeFileSync(abs, content, 'utf8');
  }
  return dir;
}

/** Ejecuta un único detector sobre un proyecto temporal. */
export async function runDetector(
  detector: Detector,
  files: Record<string, string>,
  options: ScanOptions = {},
): Promise<RawFinding[]> {
  const dir = makeProject({ 'package.json': MIN_PKG, ...files });
  const { ctx } = buildContext(dir, options);
  return detector.run(ctx);
}

export function rules(findings: RawFinding[]): string[] {
  return findings.map((f) => f.ruleId);
}
