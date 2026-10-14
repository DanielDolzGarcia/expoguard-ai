#!/usr/bin/env node
import { writeFileSync } from 'node:fs';
import { styleText } from 'node:util';
import { Command, Option } from 'commander';
import { scan, severityAtLeast, VERSION } from './scanner.js';
import { ExpoProjectError } from './ingest/project.js';
import { RULES } from './rules.js';
import { SEVERITIES, type Finding, type ScanResult, type Severity } from './types.js';

type Style = Parameters<typeof styleText>[0];

const SEVERITY_STYLE: Record<Severity, Style> = {
  critical: ['bgRed', 'white', 'bold'],
  high: ['red', 'bold'],
  medium: 'yellow',
  low: 'cyan',
  info: 'gray',
};

function paint(style: Style, text: string): string {
  return process.stdout.isTTY ? styleText(style, text) : text;
}

function printFinding(f: Finding): void {
  const sev = paint(SEVERITY_STYLE[f.severity], `[${f.severity.toUpperCase()}]`.padEnd(10));
  console.log(`${sev} ${f.id}  ${f.title}`);
  console.log(`           ${f.location.file}:${f.location.line}  (${f.ruleId} · ${f.masvs} · ${f.owasp})`);
  console.log(`           ${f.message}`);
  if (f.snippet) console.log(paint('gray', `           > ${f.snippet}`));
  console.log();
}

function printHuman(result: ScanResult, minSeverity: Severity): void {
  const p = result.project;
  console.log(paint('bold', `ExpoGuard AI v${result.tool.version}`) + `  ·  ${p.name} (expo ${p.expoVersion}, ${p.workflow})`);
  console.log(
    `Ficheros: ${result.stats.files} (${result.stats.sourceFiles} de código, ${result.stats.parsedFiles} parseados) · ${result.stats.durationMs} ms\n`,
  );

  const shown = result.findings.filter((f) => severityAtLeast(f.severity, minSeverity));
  for (const f of shown) printFinding(f);

  if (result.warnings.length > 0) {
    console.log(paint('gray', `Avisos (${result.warnings.length}):`));
    for (const w of result.warnings) console.log(paint('gray', `  - ${w.file ? `${w.file}: ` : ''}${w.message}`));
    console.log();
  }

  // eslint-disable-next-line security/detect-object-injection -- s recorre SEVERITIES
  const summary = SEVERITIES.map((s) => `${s}: ${result.stats.bySeverity[s]}`).join('  ');
  console.log(paint('bold', `Total: ${result.findings.length} hallazgos`) + `  (${summary})`);
  if (shown.length < result.findings.length) {
    console.log(paint('gray', `Se ocultan ${result.findings.length - shown.length} por debajo de "${minSeverity}".`));
  }
}

const program = new Command();
program
  .name('expoguard')
  .description('Audita la seguridad del código fuente de apps React Native con Expo')
  .version(VERSION);

program
  .command('scan')
  .description('Analiza un proyecto Expo')
  .argument('[path]', 'ruta del proyecto', '.')
  .option('--json', 'escribe el resultado en JSON por la salida estándar')
  .option('-o, --output <file>', 'guarda el resultado JSON en un fichero')
  .option('--skip-deps', 'no ejecuta npm audit (análisis sin red)')
  .addOption(new Option('--fail-on <severity>', 'código de salida 1 si hay hallazgos de esta severidad o más').choices(SEVERITIES).default('high'))
  .addOption(new Option('--min-severity <severity>', 'oculta en consola los hallazgos por debajo').choices(SEVERITIES).default('info'))
  .action(async (path: string, opts: { json?: boolean; output?: string; skipDeps?: boolean; failOn: Severity; minSeverity: Severity }) => {
    try {
      const result = await scan(path, { skipDependencies: opts.skipDeps ?? false });
      const json = JSON.stringify(result, null, 2);
      // eslint-disable-next-line security/detect-non-literal-fs-filename -- ruta de salida elegida por el usuario
      if (opts.output) writeFileSync(opts.output, json + '\n', 'utf8');
      if (opts.json) console.log(json);
      else printHuman(result, opts.minSeverity);
      process.exitCode = result.findings.some((f) => severityAtLeast(f.severity, opts.failOn)) ? 1 : 0;
    } catch (err) {
      if (err instanceof ExpoProjectError) {
        console.error(`Error: ${err.message}`);
      } else {
        console.error(`Error inesperado: ${(err as Error).stack ?? String(err)}`);
      }
      process.exitCode = 2;
    }
  });

program
  .command('rules')
  .description('Lista las reglas deterministas disponibles')
  .action(() => {
    for (const r of RULES) {
      console.log(`${r.id.padEnd(38)} ${r.severity.padEnd(8)} ${r.masvs.padEnd(19)} ${r.owasp.padEnd(4)} ${r.title}`);
    }
  });

await program.parseAsync();
