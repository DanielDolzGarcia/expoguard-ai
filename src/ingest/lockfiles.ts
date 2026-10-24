// Lectura de los lockfiles de yarn y pnpm para saber qué versión exacta de cada paquete se instala.
// Solo hace falta nombre y versión (para consultar OSV), así que se leen línea a línea sin añadir
// un parser de YAML como dependencia.

export interface LockedPackage {
  name: string;
  version: string;
  /** Línea (1-based) de la entrada en el lockfile. */
  line: number;
}

/** Separa "nombre@rango" teniendo en cuenta los paquetes con scope (@scope/nombre@rango). */
export function splitDescriptor(descriptor: string): { name: string; range: string } | null {
  const at = descriptor.indexOf('@', descriptor.startsWith('@') ? 1 : 0);
  if (at <= 0) return null;
  return { name: descriptor.slice(0, at), range: descriptor.slice(at + 1) };
}

function unquote(s: string): string {
  const t = s.trim();
  return (t.startsWith('"') && t.endsWith('"')) || (t.startsWith("'") && t.endsWith("'")) ? t.slice(1, -1) : t;
}

function dedupe(list: LockedPackage[]): LockedPackage[] {
  const seen = new Set<string>();
  return list.filter((p) => {
    const k = `${p.name}@${p.version}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}

/**
 * yarn.lock v1 (yarn classic) y v2+ (berry). Cada entrada empieza en la columna 0 con uno o varios
 * descriptores separados por comas y termina en ":"; debajo, con sangría, va `version "x"` (v1)
 * o `version: x` (berry). En berry se ignoran las resoluciones que no vienen del registro
 * (workspace:, link:, file:, patch:...).
 */
export function parseYarnLock(text: string): LockedPackage[] {
  const out: LockedPackage[] = [];
  let current: { name: string; line: number; npm: boolean } | null = null;

  for (const [i, raw] of text.split(/\r?\n/).entries()) {
    if (raw === '' || raw.startsWith('#')) continue;

    if (!raw.startsWith(' ')) {
      current = null;
      if (!raw.endsWith(':') || raw.startsWith('__metadata')) continue;
      // v1 entrecomilla cada descriptor; berry entrecomilla la lista entera ("a@npm:1, a@npm:^1"):
      // se quitan las comillas de cada trozo después de separar por comas.
      const first = raw.slice(0, -1).split(',')[0]!.trim().replace(/^["']/, '').replace(/["']$/, '');
      const desc = splitDescriptor(first);
      if (!desc) continue;
      // berry: "nombre@npm:rango"; v1: "nombre@rango"
      const protocol = /^([a-z]+):/.exec(desc.range)?.[1];
      current = { name: desc.name, line: i + 1, npm: protocol === undefined || protocol === 'npm' };
      continue;
    }

    if (current && /^ {2}version[ :]/.test(raw)) {
      const version = unquote(raw.trim().replace(/^version:?\s*/, ''));
      if (current.npm && version && !version.includes('use.local')) out.push({ name: current.name, version, line: current.line });
      current = null;
    }
  }
  return dedupe(out);
}

/** Nombre y versión de una clave de pnpm ya sin "/" inicial ni peers v6/v9. */
function pnpmKey(key: string): { name: string; version: string } | null {
  // v5: "nombre/1.0.0" o "@scope/nombre/1.0.0" (con peers "_react@18.2.0")
  const parts = key.split('/');
  const v5Len = key.startsWith('@') ? 3 : 2;
  if (parts.length === v5Len && /^\d/.test(parts.at(-1)!)) {
    return { name: parts.slice(0, -1).join('/'), version: parts.at(-1)!.split('_')[0]! };
  }
  // v6/v9: "nombre@1.0.0" o "@scope/nombre@1.0.0"
  const desc = splitDescriptor(key);
  return desc && /^\d/.test(desc.range) ? { name: desc.name, version: desc.range } : null;
}

/**
 * pnpm-lock.yaml: claves de la sección `packages:` con dos espacios de sangría.
 * Formatos admitidos: v9 (`nombre@1.0.0`), v6 (`/nombre@1.0.0`) y v5 (`/nombre/1.0.0`), con o sin
 * sufijo de peer dependencies (`(react@18.2.0)` en v6/v9, `_react@18.2.0` en v5).
 */
export function parsePnpmLock(text: string): LockedPackage[] {
  const out: LockedPackage[] = [];
  let inPackages = false;

  for (const [i, raw] of text.split(/\r?\n/).entries()) {
    if (/^\S/.test(raw)) {
      inPackages = raw.trimEnd() === 'packages:';
      continue;
    }
    if (!inPackages || !/^ {2}\S/.test(raw) || !raw.trimEnd().endsWith(':')) continue;

    let key = unquote(raw.trim().slice(0, -1));
    key = key.replace(/\(.*$/, ''); // peers v6/v9
    if (key.startsWith('/')) key = key.slice(1);

    const pkg = pnpmKey(key);
    if (pkg) out.push({ ...pkg, line: i + 1 });
  }
  return dedupe(out);
}
