import { describe, expect, it } from 'vitest';
import { nativeDetector } from '../../src/detectors/native.js';
import { rules, runDetector } from '../helpers.js';

const appJson = (expo: object) => ({ 'app.json': JSON.stringify({ expo }, null, 2) });

describe('nativeDetector: app.json', () => {
  it('configuración segura: sin hallazgos', async () => {
    const f = await runDetector(nativeDetector, appJson({ scheme: 'com.acme.app', android: { allowBackup: false } }));
    expect(f).toEqual([]);
  });

  it('allowBackup implícito es severidad baja y apunta a la clave padre', async () => {
    const f = await runDetector(nativeDetector, appJson({ scheme: 'com.acme.app', android: { package: 'x' } }));
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ ruleId: 'native/android-allow-backup', severity: 'low', location: { line: 4 } });
  });

  it('sin bloque android, la línea apunta al inicio', async () => {
    const f = await runDetector(nativeDetector, appJson({ scheme: 'com.acme.app' }));
    expect(f[0]!.location.line).toBe(1);
  });

  it('esquemas genéricos (también en array)', async () => {
    const f = await runDetector(nativeDetector, appJson({ scheme: ['com.acme.app', 'abc', 'MyApp'], android: { allowBackup: false } }));
    expect(f.map((x) => x.evidence?.['scheme'])).toEqual(['abc', 'MyApp']);
  });

  it('permisos: con prefijo android.permission., y severidad según el número', async () => {
    const one = await runDetector(nativeDetector, appJson({ scheme: 'com.a.b', android: { allowBackup: false, permissions: ['android.permission.CAMERA', 'INTERNET'] } }));
    expect(one[0]).toMatchObject({ ruleId: 'native/dangerous-permissions', severity: 'low' });
    const many = await runDetector(nativeDetector, appJson({ scheme: 'com.a.b', android: { allowBackup: false, permissions: ['READ_SMS', 'CAMERA', 'RECORD_AUDIO'] } }));
    expect(many[0]!.severity).toBe('medium');
  });

  it('cleartext en android directo y excepciones ATS por dominio', async () => {
    const f = await runDetector(
      nativeDetector,
      appJson({
        scheme: 'com.a.b',
        android: { allowBackup: false, usesCleartextTraffic: true },
        ios: { infoPlist: { NSAppTransportSecurity: { NSExceptionDomains: { 'api.example': { NSExceptionAllowsInsecureHTTPLoads: true } } } } },
      }),
    );
    expect(rules(f)).toEqual(['native/android-cleartext', 'native/ios-ats-disabled']);
    expect(f[1]!.severity).toBe('medium');
  });

  it('sin fichero de configuración no hay hallazgos de app.json', async () => {
    expect(await runDetector(nativeDetector, {})).toEqual([]);
  });
});

describe('nativeDetector: ficheros nativos', () => {
  it('Info.plist con el valor en la misma línea', async () => {
    const f = await runDetector(nativeDetector, {
      'ios/X/Info.plist': '<dict>\n<key>NSAllowsArbitraryLoads</key><true/>\n</dict>',
    });
    expect(f[0]).toMatchObject({ ruleId: 'native/ios-ats-disabled', location: { line: 2 } });
  });

  it('Info.plist con <false/> no se informa', async () => {
    const f = await runDetector(nativeDetector, {
      'ios/X/Info.plist': '<dict>\n<key>NSAllowsArbitraryLoads</key>\n<false/>\n</dict>',
    });
    expect(f).toEqual([]);
  });
});
