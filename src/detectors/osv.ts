// Cliente mínimo de la API pública de OSV (https://osv.dev), usado como respaldo de npm audit
// cuando el proyecto usa yarn o pnpm. Solo se envían nombres y versiones de paquetes públicos
// de npm: nunca código ni ficheros del proyecto analizado.
import type { Severity } from '../types.js';

const API = 'https://api.osv.dev/v1';
const BATCH_SIZE = 1000; // límite de la API por petición
const MAX_DETAILS = 300; // tope de avisos que se descargan en detalle por análisis
const CONCURRENCY = 8;

export interface OsvEvent {
  introduced?: string;
  fixed?: string;
  last_affected?: string;
}

export interface OsvVuln {
  id: string;
  summary?: string;
  aliases?: string[];
  database_specific?: { severity?: string };
  affected?: Array<{
    package?: { name?: string; ecosystem?: string };
    ranges?: Array<{ type?: string; events?: OsvEvent[] }>;
  }>;
}

export interface OsvClient {
  /** Para cada paquete, los ids de los avisos que le afectan (mismo orden que la entrada). */
  queryBatch(packages: Array<{ name: string; version: string }>): Promise<string[][]>;
  getVuln(id: string): Promise<OsvVuln>;
}

async function postJson(url: string, body: unknown): Promise<unknown> {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(30_000),
  });
  if (!res.ok) throw new Error(`OSV respondió ${res.status}`);
  return res.json();
}

export const defaultOsvClient: OsvClient = {
  async queryBatch(packages) {
    const out: string[][] = [];
    for (let i = 0; i < packages.length; i += BATCH_SIZE) {
      const chunk = packages.slice(i, i + BATCH_SIZE);
      const data = (await postJson(`${API}/querybatch`, {
        queries: chunk.map((p) => ({ package: { name: p.name, ecosystem: 'npm' }, version: p.version })),
      })) as { results?: Array<{ vulns?: Array<{ id: string }> }> };
      const results = data.results ?? [];
      chunk.forEach((_, k) => out.push((results.at(k)?.vulns ?? []).map((v) => v.id)));
    }
    return out;
  },
  async getVuln(id) {
    const res = await fetch(`${API}/vulns/${encodeURIComponent(id)}`, { signal: AbortSignal.timeout(30_000) });
    if (!res.ok) throw new Error(`OSV respondió ${res.status} para ${id}`);
    return (await res.json()) as OsvVuln;
  },
};

/** Descarga el detalle de los avisos con concurrencia limitada. */
export async function fetchVulns(client: OsvClient, ids: string[]): Promise<Map<string, OsvVuln>> {
  const unique = [...new Set(ids)].slice(0, MAX_DETAILS);
  const out = new Map<string, OsvVuln>();
  let next = 0;
  const worker = async () => {
    while (next < unique.length) {
      const id = unique[next++]!;
      out.set(id, await client.getVuln(id));
    }
  };
  await Promise.all(Array.from({ length: Math.min(CONCURRENCY, unique.length) }, worker));
  return out;
}

export function osvSeverity(v: OsvVuln): Severity {
  switch (v.database_specific?.severity?.toUpperCase()) {
    case 'CRITICAL':
      return 'critical';
    case 'HIGH':
      return 'high';
    case 'MODERATE':
    case 'MEDIUM':
      return 'medium';
    case 'LOW':
      return 'low';
    default:
      return 'medium'; // sin clasificar: se trata como media hasta que el triaje lo revise
  }
}

/** Compara versiones x.y.z (las prerelease se ordenan antes que la versión final). */
export function compareVersions(a: string, b: string): number {
  const parse = (v: string) => {
    const [core = '', pre] = v.split('-', 2);
    return { nums: core.split('.').map((n) => Number.parseInt(n, 10) || 0), pre };
  };
  const pa = parse(a);
  const pb = parse(b);
  for (let i = 0; i < 3; i++) {
    const d = (pa.nums.at(i) ?? 0) - (pb.nums.at(i) ?? 0);
    if (d !== 0) return Math.sign(d);
  }
  if (pa.pre && !pb.pre) return -1;
  if (!pa.pre && pb.pre) return 1;
  return 0;
}

/** Primera versión que corrige el aviso para la versión instalada, si OSV la indica. */
export function fixedVersionFor(v: OsvVuln, name: string, version: string): string | undefined {
  for (const aff of v.affected ?? []) {
    if (aff.package?.ecosystem !== 'npm' || aff.package.name !== name) continue;
    for (const range of aff.ranges ?? []) {
      if (range.type !== 'SEMVER') continue;
      let introduced: string | undefined;
      for (const ev of range.events ?? []) {
        if (ev.introduced !== undefined) introduced = ev.introduced;
        if (ev.fixed !== undefined && introduced !== undefined) {
          const afterStart = introduced === '0' || compareVersions(version, introduced) >= 0;
          if (afterStart && compareVersions(version, ev.fixed) < 0) return ev.fixed;
          introduced = undefined;
        }
      }
    }
  }
  return undefined;
}
