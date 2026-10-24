import { execFile } from 'node:child_process';
import { existsSync, lstatSync, readFileSync } from 'node:fs';
import { basename, dirname, join } from 'node:path';
import { evaluateJson } from '../ingest/appConfig.js';
import { parsePnpmLock, parseYarnLock } from '../ingest/lockfiles.js';
import { SEVERITIES, type AuditRunner, type Detector, type RawFinding, type ScanContext, type Severity } from '../types.js';
import { compareVersions, defaultOsvClient, fetchVulns, fixedVersionFor, osvSeverity, type OsvClient, type OsvVuln } from './osv.js';

interface Advisory {
  source: number;
  name: string;
  title: string;
  url: string;
  severity: string;
  range: string;
  cvss?: { score: number };
}

interface AuditEntry {
  name: string;
  severity: string;
  isDirect: boolean;
  via: Array<string | Advisory>;
  effects: string[];
  range: string;
  fixAvailable: boolean | { name: string; version: string; isSemVerMajor: boolean };
}

export interface NpmAuditReport {
  auditReportVersion?: number;
  vulnerabilities?: Record<string, AuditEntry>;
  error?: { code?: string; summary?: string };
}

const REGISTRY = 'https://registry.npmjs.org/';

/**
 * Localiza npm-cli.js para ejecutarlo con el propio Node. En Windows `npm` es un .cmd y, desde
 * Node 20.12 (CVE-2024-27980), execFile no puede lanzarlo sin shell: y no queremos shell.
 */
export function resolveNpm(): { cmd: string; prefix: string[] } {
  const fromEnv = process.env['npm_execpath'];
  // eslint-disable-next-line security/detect-non-literal-fs-filename -- variable que define el propio npm
  if (fromEnv && basename(fromEnv) === 'npm-cli.js' && existsSync(fromEnv)) {
    return { cmd: process.execPath, prefix: [fromEnv] };
  }
  const nodeDir = dirname(process.execPath);
  const candidates = [
    join(nodeDir, 'node_modules', 'npm', 'bin', 'npm-cli.js'), // Windows
    join(nodeDir, '..', 'lib', 'node_modules', 'npm', 'bin', 'npm-cli.js'), // Linux/macOS
  ];
  // eslint-disable-next-line security/detect-non-literal-fs-filename -- rutas derivadas de process.execPath
  const cli = candidates.find((c) => existsSync(c));
  return cli ? { cmd: process.execPath, prefix: [cli] } : { cmd: 'npm', prefix: [] };
}

/** Ejecuta `npm audit` sin shell, sin instalar nada (--package-lock-only) y contra el registro oficial. */
export const defaultAuditRunner: AuditRunner = (cwd) =>
  new Promise((resolve, reject) => {
    const { cmd, prefix } = resolveNpm();
    execFile(
      cmd,
      [...prefix, 'audit', '--json', '--package-lock-only', `--registry=${REGISTRY}`],
      { cwd, shell: false, timeout: 120_000, maxBuffer: 64 * 1024 * 1024, windowsHide: true },
      (err, stdout) => {
        // npm audit sale con código 1 cuando encuentra vulnerabilidades: no es un error.
        if (stdout && stdout.trim().startsWith('{')) resolve(stdout);
        else reject(err ?? new Error('npm audit no devolvió JSON'));
      },
    );
  });

function mapSeverity(npmSeverity: string): Severity {
  switch (npmSeverity) {
    case 'critical':
      return 'critical';
    case 'high':
      return 'high';
    case 'moderate':
      return 'medium';
    case 'low':
      return 'low';
    default:
      return 'info';
  }
}

interface LockEntry {
  version?: string;
  license?: string;
  deprecated?: string;
  link?: boolean;
  dependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
}

interface PackageLock {
  packages?: Record<string, LockEntry>;
}

/** "node_modules/a/node_modules/@s/b" -> "@s/b" */
function nameFromLockPath(path: string): string {
  return path.slice(path.lastIndexOf('node_modules/') + 'node_modules/'.length);
}

/**
 * Grafo inverso nombre -> paquetes que dependen de él, a partir de package-lock.json (v2/v3).
 * Hace falta porque `effects` de npm audit solo enlaza dependientes que también son vulnerables.
 */
export function reverseDependencies(lock: PackageLock): { dependents: Map<string, Set<string>>; direct: Set<string> } {
  const dependents = new Map<string, Set<string>>();
  const direct = new Set<string>();
  for (const [path, meta] of Object.entries(lock.packages ?? {})) {
    const from = path === '' ? '' : nameFromLockPath(path);
    for (const dep of Object.keys({ ...meta.dependencies, ...meta.optionalDependencies })) {
      if (from === '') direct.add(dep);
      let set = dependents.get(dep);
      if (!set) dependents.set(dep, (set = new Set()));
      set.add(from);
    }
  }
  return { dependents, direct };
}

/** Sube por el árbol hasta las dependencias directas que introducen el paquete vulnerable. */
export function introducedBy(report: Record<string, AuditEntry>, name: string, lock?: PackageLock): string[] {
  const graph = lock ? reverseDependencies(lock) : null;
  const direct = new Set<string>();
  const seen = new Set<string>();
  const queue = [name];
  while (queue.length) {
    const cur = queue.shift()!;
    if (seen.has(cur)) continue;
    seen.add(cur);
    // eslint-disable-next-line security/detect-object-injection -- protegido con hasOwn (claves del informe de npm)
    const entry = Object.hasOwn(report, cur) ? report[cur] : undefined;
    if (entry?.isDirect || graph?.direct.has(cur)) {
      direct.add(cur);
      continue;
    }
    queue.push(...(entry?.effects ?? []));
    for (const parent of graph?.dependents.get(cur) ?? []) if (parent !== '') queue.push(parent);
  }
  return [...direct].sort();
}

function ghsa(url: string): string {
  return url.split('/').pop() ?? url;
}

/** Línea de una dependencia en package.json (1 si no aparece, p. ej. una transitiva). */
function dependencyLines(ctx: ScanContext): (dep: string) => number {
  const pkgFile = ctx.files.find((f) => f.path === 'package.json');
  const { lines } = pkgFile ? evaluateJson(ctx.readText(pkgFile)) : { lines: new Map<string, number>() };
  return (dep) => lines.get(['dependencies', dep].join('\u0000')) ?? lines.get(['devDependencies', dep].join('\u0000')) ?? 1;
}

export function auditToFindings(ctx: ScanContext, report: NpmAuditReport): RawFinding[] {
  const vulns = report.vulnerabilities ?? {};
  const lock = readLock(ctx.root);
  const lineOfDep = dependencyLines(ctx);

  const findings: RawFinding[] = [];
  for (const entry of Object.values(vulns)) {
    const advisories = entry.via.filter((v): v is Advisory => typeof v === 'object');
    if (advisories.length === 0) continue; // solo afectado de forma transitiva: se informa en el paquete origen

    const parents = introducedBy(vulns, entry.name, lock);
    const anchor = entry.isDirect ? entry.name : (parents[0] ?? entry.name);
    const fix =
      typeof entry.fixAvailable === 'object'
        ? `${entry.fixAvailable.name}@${entry.fixAvailable.version}${entry.fixAvailable.isSemVerMajor ? ' (cambio de versión mayor)' : ''}`
        : entry.fixAvailable
          ? 'npm audit fix'
          : 'sin corrección publicada';
    const worst = [...advisories].sort((a, b) => (b.cvss?.score ?? 0) - (a.cvss?.score ?? 0))[0]!;

    findings.push({
      ruleId: 'deps/known-vulnerability',
      severity: mapSeverity(entry.severity),
      message:
        `${entry.name} (${entry.range}) tiene ${advisories.length} aviso(s); el más grave: "${worst.title}".` +
        (entry.isDirect ? '' : ` Dependencia transitiva introducida por ${parents.join(', ') || '?'}.`),
      location: { file: 'package.json', line: lineOfDep(anchor) },
      evidence: {
        package: entry.name,
        direct: entry.isDirect,
        introducedBy: parents,
        usedInSource: ctx.importedPackages.has(entry.name),
        advisories: advisories.map((a) => ghsa(a.url)),
        maxCvss: worst.cvss?.score ?? 0,
        fix,
      },
    });
  }
  return findings;
}

/**
 * Revisión de package-lock.json sin red: paquetes que su autor ha marcado como obsoletos
 * (`deprecated`) y paquetes sin licencia declarada o con licencia propietaria.
 */
export function lockMetadataFindings(ctx: ScanContext, lock: PackageLock): RawFinding[] {
  const lineOfDep = dependencyLines(ctx);
  const { direct } = reverseDependencies(lock);
  const findings: RawFinding[] = [];

  // Obsoletos: una entrada por nombre@versión aunque aparezca varias veces en el árbol.
  const deprecated = new Map<string, { name: string; version: string; message: string; copies: number }>();
  const unlicensed = new Set<string>();
  for (const [path, meta] of Object.entries(lock.packages ?? {})) {
    if (path === '' || meta.link) continue;
    const name = nameFromLockPath(path);
    const version = meta.version ?? '?';
    if (meta.deprecated) {
      const key = `${name}@${version}`;
      const prev = deprecated.get(key);
      if (prev) prev.copies++;
      else deprecated.set(key, { name, version, message: meta.deprecated, copies: 1 });
    }
    const license = meta.license?.trim();
    if (license && (license.toUpperCase() === 'UNLICENSED' || license.toUpperCase().startsWith('SEE LICENSE IN'))) {
      findings.push({
        ruleId: 'deps/license-issue',
        severity: 'low',
        message: `${name}@${version} tiene una licencia propietaria ("${license}"): comprobar que se puede redistribuir dentro de la app.`,
        location: { file: 'package.json', line: lineOfDep(direct.has(name) ? name : (introducedBy({}, name, lock)[0] ?? name)) },
        evidence: { package: name, license },
      });
    } else if (!license) {
      unlicensed.add(`${name}@${version}`);
    }
  }

  for (const d of deprecated.values()) {
    const isDirect = direct.has(d.name);
    const parents = isDirect ? [d.name] : introducedBy({}, d.name, lock);
    const note = d.message.length > 160 ? `${d.message.slice(0, 157)}...` : d.message;
    findings.push({
      ruleId: 'deps/deprecated-package',
      severity: isDirect ? 'medium' : 'low',
      message:
        `${d.name}@${d.version} está marcado como obsoleto por su autor: "${note}".` +
        (isDirect ? '' : ` Dependencia transitiva introducida por ${parents.join(', ') || '?'}`) +
        (d.copies > 1 ? ` (aparece ${d.copies} veces en el árbol).` : isDirect ? '' : '.'),
      location: { file: 'package.json', line: lineOfDep(parents[0] ?? d.name) },
      evidence: { package: d.name, version: d.version, direct: isDirect, introducedBy: parents, usedInSource: ctx.importedPackages.has(d.name) },
    });
  }

  // Sin licencia: un único aviso informativo. Muchos paquetes antiguos la declaran con el campo
  // "licenses" (array), que npm no copia al lockfile, así que no se puede afirmar que no tengan.
  if (unlicensed.size > 0) {
    const list = [...unlicensed].sort();
    findings.push({
      ruleId: 'deps/license-issue',
      message: `${list.length} paquete(s) no declaran licencia en package-lock.json: ${list.join(', ')}. Puede que usen el campo antiguo "licenses"; revisar a mano.`,
      location: { file: 'package.json', line: 1 },
      evidence: { packages: list },
    });
  }
  return findings;
}

/** Respaldo con OSV cuando el lockfile es de yarn o pnpm (npm audit no los entiende). */
export async function osvFindings(ctx: ScanContext, client: OsvClient): Promise<RawFinding[]> {
  const lockName = ctx.project.lockfile === 'yarn' ? 'yarn.lock' : 'pnpm-lock.yaml';
  // Se lee aparte del inventario: los lockfiles de proyectos reales suelen superar el límite de 1 MB.
  const text = readTextIfSmall(join(ctx.root, lockName));
  if (text === undefined) return [];
  const packages = ctx.project.lockfile === 'yarn' ? parseYarnLock(text) : parsePnpmLock(text);
  if (packages.length === 0) return [];

  const idsPerPackage = await client.queryBatch(packages.map(({ name, version }) => ({ name, version })));
  const details = await fetchVulns(client, idsPerPackage.flat());
  const lineOfDep = dependencyLines(ctx);
  const rank = (v: OsvVuln) => SEVERITIES.indexOf(osvSeverity(v)); // SEVERITIES va de critical a info

  const findings: RawFinding[] = [];
  packages.forEach((pkg, i) => {
    const ids = idsPerPackage.at(i) ?? [];
    if (ids.length === 0) return;
    const vulns = ids.map((id) => details.get(id)).filter((v): v is OsvVuln => v !== undefined);
    const worst = [...vulns].sort((a, b) => rank(a) - rank(b))[0];
    const fixes = vulns.map((v) => fixedVersionFor(v, pkg.name, pkg.version)).filter((f): f is string => f !== undefined);
    const fix = fixes.length ? fixes.sort(compareVersions).at(-1)! : 'sin corrección publicada';
    const isDirect = Object.hasOwn(ctx.project.dependencies, pkg.name);

    findings.push({
      ruleId: 'deps/known-vulnerability',
      severity: worst ? osvSeverity(worst) : 'medium',
      message:
        `${pkg.name}@${pkg.version} tiene ${ids.length} aviso(s) en OSV` +
        (worst?.summary ? `; el más grave: "${worst.summary}".` : '.') +
        (isDirect ? '' : ` Dependencia transitiva (ver ${lockName}).`),
      // Las directas se señalan en package.json; las transitivas, en su entrada del lockfile.
      location: isDirect ? { file: 'package.json', line: lineOfDep(pkg.name) } : { file: lockName, line: pkg.line },
      evidence: {
        package: pkg.name,
        version: pkg.version,
        direct: isDirect,
        usedInSource: ctx.importedPackages.has(pkg.name),
        advisories: ids,
        source: 'osv.dev',
        fix,
      },
    });
  });
  return findings;
}

export const dependenciesDetector: Detector = {
  family: 'dependencies',
  async run(ctx) {
    if (ctx.options.skipDependencies) return [];
    const location = { file: 'package.json', line: 1 };

    if (ctx.project.lockfile === 'yarn' || ctx.project.lockfile === 'pnpm') {
      return osvFindings(ctx, ctx.options.osvClient ?? defaultOsvClient);
    }
    if (ctx.project.lockfile !== 'npm') {
      return [
        {
          ruleId: 'deps/no-lockfile',
          message: ctx.project.lockfile ? `El lockfile de ${ctx.project.lockfile} todavía no se puede auditar.` : 'No hay lockfile versionado.',
          location,
        },
      ];
    }

    // Lo que no necesita red se calcula primero: si npm audit falla, se conserva.
    const lock = readLock(ctx.root);
    const findings = lock ? lockMetadataFindings(ctx, lock) : [];
    try {
      const raw = await (ctx.options.auditRunner ?? defaultAuditRunner)(ctx.root);
      const report = JSON.parse(raw) as NpmAuditReport;
      if (report.error) throw new Error(report.error.summary ?? report.error.code ?? 'error');
      findings.push(...auditToFindings(ctx, report));
    } catch (err) {
      ctx.warn(`npm audit no se pudo completar (${err instanceof Error ? err.message : String(err)}): no se han comprobado vulnerabilidades conocidas.`);
    }
    return findings;
  },
};

const MAX_LOCKFILE_BYTES = 50 * 1024 * 1024;

/** Lee un lockfile de la raíz del proyecto (nombre fijo) con un tope de tamaño generoso. */
function readTextIfSmall(path: string): string | undefined {
  try {
    // eslint-disable-next-line security/detect-non-literal-fs-filename -- lockfile con nombre fijo dentro de la raíz
    const st = lstatSync(path); // lstat: un enlace simbólico no es isFile(), igual que en el inventario
    if (!st.isFile() || st.size > MAX_LOCKFILE_BYTES) return undefined;
    // eslint-disable-next-line security/detect-non-literal-fs-filename -- ídem
    return readFileSync(path, 'utf8');
  } catch {
    return undefined;
  }
}

function readLock(root: string): PackageLock | undefined {
  const text = readTextIfSmall(join(root, 'package-lock.json'));
  if (text === undefined) return undefined;
  try {
    return JSON.parse(text) as PackageLock;
  } catch {
    return undefined;
  }
}
