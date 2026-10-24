import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { parsePnpmLock, parseYarnLock, splitDescriptor } from '../../src/ingest/lockfiles.js';
import { FIXTURES } from '../helpers.js';

describe('splitDescriptor', () => {
  it('separa nombre y rango, también con scope', () => {
    expect(splitDescriptor('axios@^0.21.1')).toEqual({ name: 'axios', range: '^0.21.1' });
    expect(splitDescriptor('@babel/core@npm:7.0.0')).toEqual({ name: '@babel/core', range: 'npm:7.0.0' });
    expect(splitDescriptor('sin-rango')).toBeNull();
  });
});

describe('parseYarnLock', () => {
  it('yarn v1: versión exacta y línea de cada entrada (fixture yarn-app)', () => {
    const pkgs = parseYarnLock(readFileSync(join(FIXTURES, 'yarn-app', 'yarn.lock'), 'utf8'));
    const byName = Object.fromEntries(pkgs.map((p) => [p.name, p]));
    expect(pkgs).toHaveLength(11);
    expect(byName['axios']).toEqual({ name: 'axios', version: '0.21.1', line: 12 });
    expect(byName['@react-native-async-storage/async-storage']!.version).toBe('2.1.2');
    // Entrada con varios descriptores: cuenta una sola vez
    expect(byName['minimist']).toEqual({ name: 'minimist', version: '1.2.5', line: 40 });
    expect(byName['expo']!.version).toBe('54.0.38');
  });

  it('yarn berry: ignora workspaces, enlaces y parches; acepta CRLF', () => {
    const text = [
      '__metadata:',
      '  version: 8',
      '',
      '"axios@npm:0.21.1, axios@npm:^0.21.0":',
      '  version: 0.21.1',
      '  resolution: "axios@npm:0.21.1"',
      '',
      '"@scope/lib@npm:^2.0.0":',
      '  version: 2.3.0',
      '',
      '"mi-app@workspace:.":',
      '  version: 0.0.0-use.local',
      '',
      '"local@link:../local":',
      '  version: 0.0.0-use.local',
    ].join('\r\n');
    expect(parseYarnLock(text)).toEqual([
      { name: 'axios', version: '0.21.1', line: 4 },
      { name: '@scope/lib', version: '2.3.0', line: 8 },
    ]);
  });
});

describe('parsePnpmLock', () => {
  it('v9: claves sin barra, con peers y con scope; solo la sección packages', () => {
    const text = [
      "lockfileVersion: '9.0'",
      'importers:',
      '  .:',
      '    dependencies:',
      '      axios:',
      '        specifier: 0.21.1',
      '        version: 0.21.1',
      'packages:',
      '',
      '  axios@0.21.1:',
      '    resolution: {integrity: sha512-x}',
      '',
      "  '@babel/core@7.24.0':",
      '    resolution: {integrity: sha512-y}',
      '',
      '  react-dom@19.1.0(react@19.1.0):',
      '    resolution: {integrity: sha512-z}',
      'snapshots:',
      '  axios@0.21.1:',
      '    dependencies: {}',
    ].join('\n');
    expect(parsePnpmLock(text)).toEqual([
      { name: 'axios', version: '0.21.1', line: 10 },
      { name: '@babel/core', version: '7.24.0', line: 13 },
      { name: 'react-dom', version: '19.1.0', line: 16 },
    ]);
  });

  it('v6 (/nombre@versión) y v5 (/nombre/versión, peers con _)', () => {
    const v6 = ['packages:', '  /lodash@4.17.15:', '    dev: false', '  /@scope/a@1.0.0(react@18.2.0):', '    dev: false'].join('\n');
    expect(parsePnpmLock(v6).map((p) => `${p.name}@${p.version}`)).toEqual(['lodash@4.17.15', '@scope/a@1.0.0']);
    const v5 = ['packages:', '  /lodash/4.17.15:', '    dev: false', '  /@scope/a/1.0.0_react@18.2.0:', '    dev: false', '  /raro:', '    dev: false'].join('\n');
    expect(parsePnpmLock(v5).map((p) => `${p.name}@${p.version}`)).toEqual(['lodash@4.17.15', '@scope/a@1.0.0']);
  });
});
