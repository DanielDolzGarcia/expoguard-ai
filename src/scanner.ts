import { readFileSync } from 'node:fs';
import { loadExpoProject } from './ingest/project.js';
import { buildInventory } from './ingest/inventory.js';
import { parseSource } from './ingest/parser.js';
import { loadAppConfig } from './ingest/appConfig.js';
import { collectImportedPackages } from './ingest/imports.js';
import { DETECTORS } from './detectors/index.js';
import { FAMILY_PREFIX, getRule } from './rules.js';
import {
  SEVERITIES,
  type Finding,
  type ParsedFile,
  type RawFinding,
  type ScanContext,
  type ScanOptions,
  type ScanResult,
  type ScanWarning,
  type Severity,
} from './types.js';

export const VERSION = '0.2.1';

const SEVERITY_RANK: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

export function severityAtLeast(sev: Severity, threshold: Severity): boolean {
  // eslint-disable-next-line security/detect-object-injection -- claves de tipo Severity
  return SEVERITY_RANK[sev] <= SEVERITY_RANK[threshold];
}

/** Prepara el contexto común: proyecto, inventario, AST y configuración. */
export function buildContext(dir: string, options: ScanOptions = {}): { ctx: ScanContext; warnings: ScanWarning[] } {
  const project = loadExpoProject(dir);
  const warnings: ScanWarning[] = [];

  const inventory = buildInventory(project.root);
  for (const s of inventory.skipped) warnings.push({ file: s.path, message: `Omitido: ${s.reason}` });

  const cache = new Map<string, string>();
  const readText = (f: { absPath: string }) => {
    let text = cache.get(f.absPath);
    if (text === undefined) {
      // eslint-disable-next-line security/detect-non-literal-fs-filename -- ruta del inventario (dentro de root)
      text = readFileSync(f.absPath, 'utf8');
      cache.set(f.absPath, text);
    }
    return text;
  };

  const parsed: ParsedFile[] = [];
  for (const file of inventory.files) {
    if (file.kind !== 'source') continue;
    const code = readText(file);
    const res = parseSource(code, file.path);
    if (res.ok) parsed.push({ path: file.path, code, ast: res.ast });
    else warnings.push({ file: file.path, message: `Error de parseo: ${res.error}` });
  }

  const { config, warning } = loadAppConfig(project);
  if (warning) warnings.push({ file: project.configFile ?? undefined, message: warning });

  const ctx: ScanContext = {
    root: project.root,
    project,
    files: inventory.files,
    parsed,
    appConfig: config,
    importedPackages: collectImportedPackages(parsed),
    options,
    readText,
    warn: (message) => warnings.push({ message }),
  };
  return { ctx, warnings };
}

function complete(raw: RawFinding[]): Finding[] {
  const sorted = raw
    .map((r) => {
      const rule = getRule(r.ruleId);
      return { ...r, family: rule.family, title: rule.title, severity: r.severity ?? rule.severity, masvs: rule.masvs, owasp: rule.owasp };
    })
    .sort(
      (a, b) =>
        SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity] ||
        a.location.file.localeCompare(b.location.file) ||
        a.location.line - b.location.line,
    );

  const counters = new Map<string, number>();
  return sorted.map((f) => {
    const prefix = FAMILY_PREFIX[f.family];
    const n = (counters.get(prefix) ?? 0) + 1;
    counters.set(prefix, n);
    return { id: `${prefix}-${String(n).padStart(3, '0')}`, ...f };
  });
}

export async function scan(dir: string, options: ScanOptions = {}): Promise<ScanResult> {
  const started = performance.now();
  const { ctx, warnings } = buildContext(dir, options);

  // Los detectores son independientes y se ejecutan en paralelo.
  const results = await Promise.allSettled(
    DETECTORS.map((d) => d.run(ctx).catch((err: unknown) => Promise.reject(new Error(`${d.family}: ${String(err)}`)))),
  );
  const raw: RawFinding[] = [];
  for (const res of results) {
    if (res.status === 'fulfilled') raw.push(...res.value);
    else warnings.push({ message: `Falló el detector ${(res.reason as Error).message}` });
  }

  const findings = complete(raw);
  const bySeverity = Object.fromEntries(SEVERITIES.map((s) => [s, 0])) as Record<Severity, number>;
  for (const f of findings) bySeverity[f.severity]++;

  const { root: _root, dependencies: _deps, ...projectInfo } = ctx.project;
  return {
    tool: { name: 'expoguard-ai', version: VERSION },
    project: projectInfo,
    stats: {
      files: ctx.files.length,
      sourceFiles: ctx.files.filter((f) => f.kind === 'source').length,
      parsedFiles: ctx.parsed.length,
      durationMs: Math.round(performance.now() - started),
      bySeverity,
    },
    findings,
    warnings,
  };
}
