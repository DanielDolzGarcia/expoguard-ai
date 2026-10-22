import { execFile } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { basename, dirname, join } from 'node:path';
import { evaluateJson } from '../ingest/appConfig.js';
import type { AuditRunner, Detector, RawFinding, ScanContext, Severity } from '../types.js';

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

interface PackageLock {
  packages?: Record<string, { dependencies?: Record<string, string>; optionalDependencies?: Record<string, string> }>;
}

/**
 * Grafo inverso nombre -> paquetes que dependen de él, a partir de package-lock.json (v2/v3).
 * Hace falta porque `effects` de npm audit solo enlaza dependientes que también son vulnerables.
 */
export function reverseDependencies(lock: PackageLock): { dependents: Map<string, Set<string>>; direct: Set<string> } {
  const dependents = new Map<string, Set<string>>();
  const direct = new Set<string>();
  for (const [path, meta] of Object.entries(lock.packages ?? {})) {
    const from = path === '' ? '' : path.slice(path.lastIndexOf('node_modules/') + 'node_modules/'.length);
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

export function auditToFindings(ctx: ScanContext, report: NpmAuditReport): RawFinding[] {
  const vulns = report.vulnerabilities ?? {};
  const pkgFile = ctx.files.find((f) => f.path === 'package.json');
  const { lines } = pkgFile ? evaluateJson(ctx.readText(pkgFile)) : { lines: new Map<string, number>() };
  const lock = readLock(ctx.root);
  const lineOfDep = (dep: string) =>
    lines.get(['dependencies', dep].join('\u0000')) ?? lines.get(['devDependencies', dep].join('\u0000')) ?? 1;

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

export const dependenciesDetector: Detector = {
  family: 'dependencies',
  async run(ctx) {
    if (ctx.options.skipDependencies) return [];
    if (ctx.project.lockfile !== 'npm') {
      return [
        {
          ruleId: 'deps/no-lockfile',
          message: ctx.project.lockfile
            ? `Lockfile de ${ctx.project.lockfile}: por ahora solo se audita package-lock.json.`
            : 'No hay lockfile versionado.',
          location: { file: 'package.json', line: 1 },
        },
      ];
    }
    const runner = ctx.options.auditRunner ?? defaultAuditRunner;
    const raw = await runner(ctx.root);
    const report = JSON.parse(raw) as NpmAuditReport;
    if (report.error) throw new Error(`npm audit: ${report.error.summary ?? report.error.code ?? 'error'}`);
    return auditToFindings(ctx, report);
  },
};

function readLock(root: string): PackageLock | undefined {
  const path = join(root, 'package-lock.json');
  try {
    // eslint-disable-next-line security/detect-non-literal-fs-filename -- package-lock.json dentro de la raíz
    return JSON.parse(readFileSync(path, 'utf8')) as PackageLock;
  } catch {
    return undefined;
  }
}
