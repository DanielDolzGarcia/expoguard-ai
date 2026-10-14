import { describe, expect, it } from 'vitest';
import { parseSource } from '../../src/ingest/parser.js';

describe('parseSource', () => {
  it('parsea TSX con tipos y JSX', () => {
    const res = parseSource('const A = ({ n }: { n: number }) => <Text>{n}</Text>;', 'A.tsx');
    expect(res.ok).toBe(true);
  });

  it('parsea TS con genéricos que en TSX serían ambiguos', () => {
    const res = parseSource('const id = <T,>(x: T) => x; const y = <string>"a";', 'a.ts');
    expect(res.ok).toBe(true);
  });

  it('parsea JS con JSX (habitual en React Native)', () => {
    expect(parseSource('export default () => <View />;', 'App.js').ok).toBe(true);
  });

  it('parsea CommonJS', () => {
    expect(parseSource('const x = require("x"); module.exports = x;', 'metro.config.js').ok).toBe(true);
  });

  it('devuelve el error sin lanzar excepción', () => {
    const res = parseSource('const = ;', 'roto.ts');
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.error).toMatch(/Unexpected token/);
  });
});
