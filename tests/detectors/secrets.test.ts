import { describe, expect, it } from 'vitest';
import { globMatch, looksLikeSecret, maskSecret, secretsDetector, shannonEntropy } from '../../src/detectors/secrets.js';
import { rules, runDetector } from '../helpers.js';

describe('utilidades de secretos', () => {
  it('calcula la entropía de Shannon', () => {
    expect(shannonEntropy('')).toBe(0);
    expect(shannonEntropy('aaaa')).toBe(0);
    expect(shannonEntropy('abcd')).toBe(2);
  });

  it('enmascara sin revelar el valor', () => {
    const masked = maskSecret('sk_live_ABCDEFGHIJKLMNOP');
    expect(masked).toBe('sk_l…[24 caracteres]');
    expect(masked).not.toContain('ABCDEF');
  });

  it('descarta marcadores y cadenas de baja entropía', () => {
    expect(looksLikeSecret('Zx9fQ2LmP8vR4tW7yB1nK6hJ3sD5gA0c')).toBe(true);
    expect(looksLikeSecret('your-api-key-here-please')).toBe(false);
    expect(looksLikeSecret('aaaaaaaaaaaaaaaaaaaa')).toBe(false);
    expect(looksLikeSecret('corto1A')).toBe(false);
  });

  it.each([
    ['.env', '.env', true],
    ['.env*', '.env.local', true],
    ['*.local', '.env.local', true],
    ['.env', '.env.local', false],
    ['src/*.ts', 'src/a.ts', true],
    ['src/*.ts', 'src/sub/a.ts', false],
    ['?.js', 'a.js', true],
  ])('globMatch(%s, %s) = %s', (p, s, expected) => {
    expect(globMatch(p, s)).toBe(expected);
  });
});

describe('secretsDetector', () => {
  it('detecta claves conocidas en código y enmascara el snippet', async () => {
    const f = await runDetector(secretsDetector, {
      'src/keys.ts': [
        "const a = 'AKIAIOSFODNN7EXAMPLE';",
        "const b = 'sk_live_FAKE00EXPOGUARD00000000000';",
        "const c = 'sk_test_FAKE00EXPOGUARD00000000000';",
        "const d = 'ghp_FAKEexpoguard000000000000000000000000';",
        "const e = 'xoxb-FAKE-expoguard-0000';",
        "const g = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.FAKEsignatureFAKEsig';",
        "const h = 'sk-ant-FAKEexpoguard000000000000';",
      ].join('\n'),
    });
    expect(rules(f)).toEqual([
      'secrets/aws-access-key',
      'secrets/stripe-secret-key',
      'secrets/stripe-secret-key',
      'secrets/github-token',
      'secrets/slack-token',
      'secrets/jwt',
      'secrets/llm-api-key',
    ]);
    expect(f[2]!.severity).toBe('medium'); // sk_test
    for (const finding of f) {
      expect(finding.snippet).not.toMatch(/FAKE00EXPOGUARD00000000000|FAKEexpoguard0000/);
    }
  });

  it('una clave de Google de longitud incorrecta no se detecta como tal', async () => {
    const f = await runDetector(secretsDetector, { 'a.ts': "const k = 'AIzaSyTooShort';" });
    expect(rules(f)).not.toContain('secrets/google-api-key');
  });

  it('no duplica: la regla específica gana a la genérica en la misma línea', async () => {
    const f = await runDetector(secretsDetector, { 'a.ts': "const AWS_ACCESS_KEY = 'AKIAIOSFODNN7EXAMPLE';" });
    expect(rules(f)).toEqual(['secrets/aws-access-key']);
  });

  it('no marca nombres de claves, marcadores ni process.env', async () => {
    const f = await runDetector(secretsDetector, {
      'a.ts': [
        "const TOKEN_KEY = 'accessToken';",
        "const apiKey = 'your-api-key-here-please';",
        'const secret = process.env.SECRET;',
        "const password = '';",
      ].join('\n'),
    });
    expect(f).toEqual([]);
  });

  it('EXPO_PUBLIC_ con nombre sensible es un secreto incrustado; una URL no', async () => {
    const f = await runDetector(secretsDetector, {
      '.gitignore': '.env',
      '.env': ['# comentario', 'EXPO_PUBLIC_API_URL=https://x.example', 'EXPO_PUBLIC_STRIPE_SECRET="abc123XYZ987secret"'].join('\n'),
    });
    expect(rules(f)).toEqual(['secrets/expo-public-secret']);
    expect(f[0]!.location.line).toBe(3);
    expect(f[0]!.snippet).toBe('EXPO_PUBLIC_STRIPE_SECRET=abc1…[18 caracteres]');
  });

  it('una clave de Firebase en EXPO_PUBLIC_ baja a severidad media', async () => {
    const f = await runDetector(secretsDetector, {
      '.gitignore': '.env*',
      '.env.production': 'EXPO_PUBLIC_FIREBASE_API_KEY=AIzaSyFAKE_expoguard_000000000000000000',
    });
    expect(f).toHaveLength(1);
    expect(f[0]!.severity).toBe('medium');
  });

  it('.env sin .gitignore se marca; con negación (!) también', async () => {
    const a = await runDetector(secretsDetector, { '.env': 'A=1' });
    expect(rules(a)).toEqual(['secrets/env-file-versioned']);
    const b = await runDetector(secretsDetector, { '.gitignore': '.env*\n!.env', '.env': 'A=1' });
    expect(rules(b)).toEqual(['secrets/env-file-versioned']);
    const c = await runDetector(secretsDetector, { '.env.example': 'API_KEY=changeme' });
    expect(c).toEqual([]);
  });

  it('secreto no público en .env versionado se informa con su regla', async () => {
    const f = await runDetector(secretsDetector, {
      '.gitignore': '.env',
      '.env': 'export AWS_KEY=AKIAIOSFODNN7EXAMPLE',
    });
    expect(rules(f)).toEqual(['secrets/aws-access-key']);
  });

  it('no se cuelga con líneas minificadas enormes (ReDoS)', async () => {
    const huge = `const token = "${'a1'.repeat(200_000)}`;
    const start = performance.now();
    await runDetector(secretsDetector, { 'bundle.js': huge });
    expect(performance.now() - start).toBeLessThan(2000);
  });
});
