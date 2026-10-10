import type { File as BabelFile } from '@babel/types';

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const;
export type Severity = (typeof SEVERITIES)[number];

export type Family = 'secrets' | 'storage' | 'dependencies' | 'webview' | 'native';

export type FileKind = 'source' | 'config' | 'env' | 'native' | 'other';

export interface InventoryFile {
  /** Ruta relativa a la raíz del proyecto, con separador "/". */
  path: string;
  absPath: string;
  kind: FileKind;
  size: number;
}

export interface ParsedFile {
  path: string;
  code: string;
  ast: BabelFile;
}

export interface ExpoProject {
  root: string;
  name: string;
  expoVersion: string;
  configFile: string | null;
  workflow: 'managed' | 'prebuild';
  lockfile: 'npm' | 'yarn' | 'pnpm' | 'bun' | null;
  dependencies: Record<string, string>;
}

export interface AppConfig {
  /** Fichero de donde sale la configuración (app.json, app.config.ts...). */
  file: string | null;
  /** Objeto `expo` evaluado de forma estática. Los valores no literales son UNKNOWN. */
  data: Record<string, unknown>;
  /** Línea (1-based) de una clave, p. ej. ['android', 'allowBackup']. */
  lineOf(path: string[]): number | null;
}

export interface Location {
  file: string;
  line: number;
  column?: number;
}

/** Lo que devuelve un detector. El escáner completa id, título, MASVS y OWASP desde el catálogo. */
export interface RawFinding {
  ruleId: string;
  message: string;
  location: Location;
  /** Severidad concreta cuando la regla admite varias (p. ej. según el aviso de npm). */
  severity?: Severity;
  snippet?: string;
  evidence?: Record<string, string | number | boolean | string[]>;
}

export interface Finding extends RawFinding {
  id: string;
  family: Family;
  title: string;
  severity: Severity;
  masvs: string;
  owasp: string;
}

export interface ScanOptions {
  skipDependencies?: boolean;
  /** Permite sustituir la ejecución de `npm audit` en los tests. */
  auditRunner?: AuditRunner;
}

export type AuditRunner = (cwd: string) => Promise<string>;

export interface ScanContext {
  root: string;
  project: ExpoProject;
  files: InventoryFile[];
  parsed: ParsedFile[];
  appConfig: AppConfig;
  /** Paquetes importados desde el código de la app (import, require, import()). */
  importedPackages: Set<string>;
  options: ScanOptions;
  readText(file: InventoryFile): string;
}

export interface Detector {
  family: Family;
  run(ctx: ScanContext): Promise<RawFinding[]>;
}

export interface ScanWarning {
  file?: string;
  message: string;
}

export interface ScanResult {
  tool: { name: 'expoguard-ai'; version: string };
  project: Omit<ExpoProject, 'dependencies' | 'root'>;
  stats: {
    files: number;
    sourceFiles: number;
    parsedFiles: number;
    durationMs: number;
    bySeverity: Record<Severity, number>;
  };
  findings: Finding[];
  warnings: ScanWarning[];
}
