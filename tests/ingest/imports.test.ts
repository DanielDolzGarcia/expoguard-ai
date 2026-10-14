import { describe, expect, it } from 'vitest';
import { collectImportedPackages, packageRoot } from '../../src/ingest/imports.js';
import { parseSource } from '../../src/ingest/parser.js';

describe('packageRoot', () => {
  it.each([
    ['lodash', 'lodash'],
    ['lodash/merge', 'lodash'],
    ['@expo/vector-icons/Feather', '@expo/vector-icons'],
    ['./local', null],
    ['../x', null],
    ['node:fs', null],
    ['@solo', null],
  ])('%s -> %s', (spec, root) => {
    expect(packageRoot(spec)).toBe(root);
  });
});

describe('collectImportedPackages', () => {
  it('recoge import, require, import() y export from', () => {
    const code = [
      "import axios from 'axios';",
      "import './side-effect';",
      "const _ = require('lodash/fp');",
      "export { x } from '@scope/pkg/sub';",
      "export * from 'zod';",
      "const m = await import('dayjs');",
    ].join('\n');
    const res = parseSource(code, 'a.ts');
    if (!res.ok) throw new Error(res.error);
    const pkgs = collectImportedPackages([{ path: 'a.ts', code, ast: res.ast }]);
    expect([...pkgs].sort()).toEqual(['@scope/pkg', 'axios', 'dayjs', 'lodash', 'zod']);
  });
});
