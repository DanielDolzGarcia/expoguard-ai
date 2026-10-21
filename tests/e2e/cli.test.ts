import { describe, expect, it } from 'vitest';
import { spawnSync } from 'node:child_process';
import { join, resolve } from 'node:path';
import { FIXTURES } from '../helpers.js';

const CLI = resolve(FIXTURES, '..', '..', 'src', 'cli.ts');

function run(...args: string[]) {
  const res = spawnSync(process.execPath, ['--import', 'tsx', CLI, ...args], { encoding: 'utf8', timeout: 30_000 });
  return { code: res.status, stdout: res.stdout, stderr: res.stderr };
}

describe('CLI expoguard', () => {
  it('scan --json devuelve JSON válido y código 1 con hallazgos altos', () => {
    const { code, stdout } = run('scan', join(FIXTURES, 'vulnerable-app'), '--json', '--skip-deps');
    expect(code).toBe(1);
    const result = JSON.parse(stdout);
    expect(result.tool.name).toBe('expoguard-ai');
    expect(result.findings.length).toBeGreaterThan(20);
  });

  it('--fail-on critical en safe-app devuelve 0', () => {
    const { code, stdout } = run('scan', join(FIXTURES, 'safe-app'), '--fail-on', 'critical', '--skip-deps');
    expect(code).toBe(0);
    expect(stdout).toContain('Total:');
  });

  it('un directorio que no es Expo devuelve código 2', () => {
    const { code, stderr } = run('scan', FIXTURES);
    expect(code).toBe(2);
    expect(stderr).toMatch(/package.json/);
  });

  it('rules lista el catálogo', () => {
    const { code, stdout } = run('rules');
    expect(code).toBe(0);
    expect(stdout).toContain('storage/async-storage-sensitive');
  });
});
