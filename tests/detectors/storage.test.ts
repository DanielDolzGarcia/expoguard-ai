import { describe, expect, it } from 'vitest';
import { storageDetector } from '../../src/detectors/storage.js';
import { rules, runDetector } from '../helpers.js';

const IMPORT = "import AsyncStorage from '@react-native-async-storage/async-storage';\n";

describe('storageDetector', () => {
  it('distingue un token de una preferencia', async () => {
    const f = await runDetector(storageDetector, {
      'a.ts': IMPORT + "AsyncStorage.setItem('jwt', t);\nAsyncStorage.setItem('language', 'es');",
    });
    expect(rules(f)).toEqual(['storage/async-storage-sensitive', 'storage/async-storage-write']);
    expect(f[0]!.evidence).toMatchObject({ key: 'jwt', method: 'setItem' });
  });

  it('resuelve la clave desde constantes y objetos constantes', async () => {
    const f = await runDetector(storageDetector, {
      'a.ts':
        IMPORT +
        "const KEYS = { SESSION: 'session_v2' } as const;\nconst K = 'refresh';\n" +
        'AsyncStorage.setItem(KEYS.SESSION, x);\nAsyncStorage.mergeItem(K, x);',
    });
    expect(rules(f)).toEqual(['storage/async-storage-sensitive', 'storage/async-storage-sensitive']);
  });

  it('usa el nombre del valor cuando la clave es dinámica', async () => {
    const f = await runDetector(storageDetector, {
      'a.ts': IMPORT + 'AsyncStorage.setItem(`user_${id}`, password);\nAsyncStorage.setItem(k, v);',
    });
    expect(rules(f)).toEqual(['storage/async-storage-sensitive', 'storage/async-storage-write']);
    expect(f[1]!.message).toContain('<k>');
  });

  it('analiza multiSet par a par', async () => {
    const f = await runDetector(storageDetector, {
      'a.ts': IMPORT + "AsyncStorage.multiSet([['theme', 'dark'], ['authToken', t]]);",
    });
    expect(rules(f)).toEqual(['storage/async-storage-write', 'storage/async-storage-sensitive']);
  });

  it('ignora otros objetos con setItem (localStorage, variables locales)', async () => {
    const f = await runDetector(storageDetector, {
      'a.ts': "localStorage.setItem('token', t);\nfunction f(AsyncStorage) { AsyncStorage.setItem('token', t); }",
      'b.ts': IMPORT + "function g() { const AsyncStorage = fake; AsyncStorage.setItem('token', t); }",
    });
    expect(f).toEqual([]);
  });

  it('soporta la API antigua de react-native y alias', async () => {
    const f = await runDetector(storageDetector, {
      'a.js': "import { AsyncStorage as AS } from 'react-native';\nAS.setItem('password', p);",
    });
    expect(rules(f)).toEqual(['storage/async-storage-sensitive']);
  });

  it('redux-persist: whitelist con auth es alta; sin auth, media; sin whitelist, alta', async () => {
    const mk = (cfg: string) => ({ 'store.ts': IMPORT + `const c = { key: 'root', storage: AsyncStorage${cfg} };` });
    const a = await runDetector(storageDetector, mk(", whitelist: ['auth']"));
    expect(a[0]).toMatchObject({ ruleId: 'storage/redux-persist-async-storage', severity: 'high' });
    const b = await runDetector(storageDetector, mk(", whitelist: ['cart']"));
    expect(b[0]!.severity).toBeUndefined();
    const c = await runDetector(storageDetector, mk(''));
    expect(c[0]!.severity).toBe('high');
    const d = await runDetector(storageDetector, mk(", blacklist: ['auth']"));
    expect(d[0]!.severity).toBeUndefined();
  });

  it('logs con datos sensibles, también dentro de plantillas y objetos', async () => {
    const f = await runDetector(storageDetector, {
      'a.ts': [
        'console.log(`user ${user.password}`);',
        'console.debug({ t: session.token });',
        "console.warn('a' + otp);",
        "console.log('token guardado');",
        'console.log(user.name);',
      ].join('\n'),
    });
    expect(rules(f)).toEqual(['storage/sensitive-log', 'storage/sensitive-log', 'storage/sensitive-log']);
    expect(f.map((x) => x.location.line)).toEqual([1, 2, 3]);
  });
});
