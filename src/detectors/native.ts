import { getPath } from '../ingest/appConfig.js';
import type { AppConfig, Detector, InventoryFile, RawFinding, ScanContext } from '../types.js';

/** Permisos de nivel "dangerous" (o especiales) de Android que conviene justificar. */
export const DANGEROUS_PERMISSIONS = new Set([
  'READ_SMS',
  'RECEIVE_SMS',
  'SEND_SMS',
  'READ_CONTACTS',
  'WRITE_CONTACTS',
  'READ_CALL_LOG',
  'WRITE_CALL_LOG',
  'READ_PHONE_STATE',
  'READ_PHONE_NUMBERS',
  'CALL_PHONE',
  'ACCESS_FINE_LOCATION',
  'ACCESS_BACKGROUND_LOCATION',
  'RECORD_AUDIO',
  'CAMERA',
  'READ_EXTERNAL_STORAGE',
  'WRITE_EXTERNAL_STORAGE',
  'MANAGE_EXTERNAL_STORAGE',
  'READ_MEDIA_IMAGES',
  'READ_MEDIA_VIDEO',
  'BODY_SENSORS',
  'SYSTEM_ALERT_WINDOW',
  'REQUEST_INSTALL_PACKAGES',
  'READ_CALENDAR',
  'WRITE_CALENDAR',
  'QUERY_ALL_PACKAGES',
]);

const GENERIC_SCHEMES = new Set(['myapp', 'app', 'exp', 'expo', 'test', 'demo', 'mobile', 'example', 'application', 'main']);

function cfgFinding(cfg: AppConfig, path: string[], ruleId: string, message: string, extra: Partial<RawFinding> = {}): RawFinding {
  // Si la clave no existe, se señala la clave padre más cercana que sí exista.
  let line: number | null = null;
  for (let i = path.length; i > 0 && line === null; i--) line = cfg.lineOf(path.slice(0, i));
  return { ruleId, message, location: { file: cfg.file ?? 'app.json', line: line ?? 1 }, ...extra };
}

function checkAppConfig(cfg: AppConfig): RawFinding[] {
  if (!cfg.file) return [];
  const data = cfg.data;
  const out: RawFinding[] = [];

  // Esquema de deep link
  const scheme = data['scheme'];
  const schemes = Array.isArray(scheme) ? scheme : [scheme];
  schemes.forEach((s, i) => {
    if (typeof s !== 'string') return;
    if (GENERIC_SCHEMES.has(s.toLowerCase()) || (s.length <= 4 && !s.includes('.'))) {
      out.push(
        cfgFinding(cfg, Array.isArray(scheme) ? ['scheme', String(i)] : ['scheme'], 'native/generic-scheme', `El esquema "${s}://" es genérico: otra app puede registrarlo y recibir los enlaces.`, {
          evidence: { scheme: s },
        }),
      );
    }
  });

  // allowBackup: Expo lo deja a true si no se indica.
  const allowBackup = getPath(data, ['android', 'allowBackup']);
  if (allowBackup === true) {
    out.push(cfgFinding(cfg, ['android', 'allowBackup'], 'native/android-allow-backup', 'android.allowBackup está a true: los datos de la app se incluyen en las copias de seguridad.'));
  } else if (allowBackup === undefined) {
    out.push(
      cfgFinding(cfg, ['android', 'allowBackup'], 'native/android-allow-backup', 'android.allowBackup no está definido y Expo lo pone a true por defecto.', {
        severity: 'low',
        evidence: { implicit: true },
      }),
    );
  }

  // Permisos
  const perms = getPath(data, ['android', 'permissions']);
  if (Array.isArray(perms)) {
    const dangerous = perms
      .filter((p): p is string => typeof p === 'string')
      .map((p) => p.replace(/^android\.permission\./, ''))
      .filter((p) => DANGEROUS_PERMISSIONS.has(p));
    if (dangerous.length > 0) {
      out.push(
        cfgFinding(cfg, ['android', 'permissions'], 'native/dangerous-permissions', dangerous.length === 1 ? `Se solicita 1 permiso peligroso: ${dangerous[0]}.` : `Se solicitan ${dangerous.length} permisos peligrosos: ${dangerous.join(', ')}.`, {
          severity: dangerous.length >= 3 ? 'medium' : 'low',
          evidence: { permissions: dangerous },
        }),
      );
    }
  }

  // Tráfico en claro en Android: clave directa o plugin expo-build-properties
  if (getPath(data, ['android', 'usesCleartextTraffic']) === true) {
    out.push(cfgFinding(cfg, ['android', 'usesCleartextTraffic'], 'native/android-cleartext', 'android.usesCleartextTraffic está a true.'));
  }
  const plugins = data['plugins'];
  if (Array.isArray(plugins)) {
    plugins.forEach((plugin, i) => {
      if (!Array.isArray(plugin) || plugin[0] !== 'expo-build-properties') return;
      if (getPath(plugin[1], ['android', 'usesCleartextTraffic']) === true) {
        out.push(
          cfgFinding(cfg, ['plugins', String(i), '1', 'android', 'usesCleartextTraffic'], 'native/android-cleartext', 'expo-build-properties activa usesCleartextTraffic en Android.'),
        );
      }
    });
  }

  // App Transport Security en iOS
  const ats = ['ios', 'infoPlist', 'NSAppTransportSecurity'];
  if (getPath(data, [...ats, 'NSAllowsArbitraryLoads']) === true) {
    out.push(cfgFinding(cfg, [...ats, 'NSAllowsArbitraryLoads'], 'native/ios-ats-disabled', 'NSAllowsArbitraryLoads está a true: iOS permite conexiones HTTP a cualquier dominio.'));
  }
  const domains = getPath(data, [...ats, 'NSExceptionDomains']);
  if (domains && typeof domains === 'object') {
    for (const [domain, conf] of Object.entries(domains as Record<string, unknown>)) {
      if (getPath(conf, ['NSExceptionAllowsInsecureHTTPLoads']) === true) {
        out.push(
          cfgFinding(cfg, [...ats, 'NSExceptionDomains', domain], 'native/ios-ats-disabled', `ATS permite HTTP sin cifrar para ${domain}.`, {
            severity: 'medium',
            evidence: { domain },
          }),
        );
      }
    }
  }
  return out;
}

function lineMatches(text: string, re: RegExp): number[] {
  const lines: number[] = [];
  text.split(/\r?\n/).forEach((l, i) => {
    if (re.test(l)) lines.push(i + 1);
  });
  return lines;
}

function checkManifest(file: InventoryFile, text: string): RawFinding[] {
  const out: RawFinding[] = [];
  const checks: Array<[RegExp, string, string]> = [
    [/android:usesCleartextTraffic\s*=\s*"true"/, 'native/android-cleartext', 'El manifiesto permite tráfico HTTP sin cifrar.'],
    [/android:allowBackup\s*=\s*"true"/, 'native/android-allow-backup', 'El manifiesto habilita allowBackup.'],
    [/android:debuggable\s*=\s*"true"/, 'native/android-debuggable', 'El manifiesto marca la app como depurable.'],
  ];
  for (const [re, ruleId, message] of checks) {
    for (const line of lineMatches(text, re)) out.push({ ruleId, message, location: { file: file.path, line } });
  }
  return out;
}

function checkInfoPlist(file: InventoryFile, text: string): RawFinding[] {
  const lines = text.split(/\r?\n/);
  const out: RawFinding[] = [];
  lines.forEach((l, i) => {
    if (!l.includes('<key>NSAllowsArbitraryLoads</key>')) return;
    // El valor está en la misma línea o en la siguiente no vacía.
    const rest = l.split('</key>')[1] ?? '';
    const next = rest.trim() ? rest : (lines.slice(i + 1).find((x) => x.trim()) ?? '');
    if (next.includes('<true/>')) {
      out.push({
        ruleId: 'native/ios-ats-disabled',
        message: 'Info.plist activa NSAllowsArbitraryLoads.',
        location: { file: file.path, line: i + 1 },
      });
    }
  });
  return out;
}

export const nativeDetector: Detector = {
  family: 'native',
  async run(ctx: ScanContext) {
    const findings = checkAppConfig(ctx.appConfig);
    for (const file of ctx.files) {
      if (file.kind !== 'native') continue;
      const text = ctx.readText(file);
      if (file.path.endsWith('AndroidManifest.xml')) findings.push(...checkManifest(file, text));
      else if (file.path.endsWith('Info.plist')) findings.push(...checkInfoPlist(file, text));
    }
    return findings;
  },
};
