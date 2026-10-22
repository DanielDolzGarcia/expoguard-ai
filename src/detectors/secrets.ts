import { existsSync, readFileSync } from 'node:fs';
import { join, posix } from 'node:path';
import type { Detector, InventoryFile, RawFinding, ScanContext, Severity } from '../types.js';

interface SecretPattern {
  ruleId: string;
  label: string;
  re: RegExp;
  severity?: (match: RegExpExecArray) => Severity | undefined;
}

// Todos los cuantificadores están acotados o no se solapan, para evitar ReDoS en líneas minificadas largas.
export const PATTERNS: readonly SecretPattern[] = [
  {
    ruleId: 'secrets/private-key',
    label: 'clave privada PEM',
    re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----/,
  },
  { ruleId: 'secrets/aws-access-key', label: 'AWS access key', re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/ },
  {
    ruleId: 'secrets/stripe-secret-key',
    label: 'Stripe secret key',
    re: /\b[rs]k_(live|test)_[0-9A-Za-z]{16,128}\b/,
    severity: (m) => (m[1] === 'test' ? 'medium' : undefined),
  },
  {
    ruleId: 'secrets/llm-api-key',
    label: 'clave de API de LLM (OpenAI/Anthropic/OpenRouter)',
    re: /\bsk-(?:proj-|ant-|or-v1-)?[A-Za-z0-9_-]{20,200}/,
  },
  {
    ruleId: 'secrets/github-token',
    label: 'token de GitHub',
    re: /\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b/,
  },
  { ruleId: 'secrets/slack-token', label: 'token de Slack', re: /\bxox[abprs]-[A-Za-z0-9-]{10,200}/ },
  { ruleId: 'secrets/google-api-key', label: 'Google API key', re: /\bAIza[0-9A-Za-z_-]{35}(?![0-9A-Za-z_-])/ },
  {
    ruleId: 'secrets/jwt',
    label: 'JWT',
    re: /\beyJ[A-Za-z0-9_-]{10,2000}\.eyJ[A-Za-z0-9_-]{10,4000}\.[A-Za-z0-9_-]{10,2000}/,
  },
];

const GENERIC_ASSIGNMENT =
  /([A-Za-z0-9_$-]{0,40}(?:secret|token|passw(?:or)?d|pwd|api[_-]?key|private[_-]?key|access[_-]?key|signing[_-]?key|auth[_-]?key)[A-Za-z0-9_$-]{0,40})["']?\s{0,5}[:=]\s{0,5}["'`]([^"'`\s]{16,256})["'`]/i;

const PLACEHOLDER = /your|example|placeholder|changeme|dummy|sample|xxxx|<|>|\$\{|process\.env|todo/i;

const SENSITIVE_ENV_NAME = /(SECRET|TOKEN|PASSWORD|PASSWD|PRIVATE|API_?KEY|ACCESS_?KEY|CLIENT_SECRET|AUTH)/i;

export function shannonEntropy(s: string): number {
  if (!s) return 0;
  const freq = new Map<string, number>();
  for (const ch of s) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let h = 0;
  for (const n of freq.values()) {
    const p = n / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

function charClasses(s: string): number {
  return [/[a-z]/, /[A-Z]/, /[0-9]/].filter((re) => re.test(s)).length;
}

export function looksLikeSecret(value: string): boolean {
  return value.length >= 16 && !PLACEHOLDER.test(value) && charClasses(value) >= 2 && shannonEntropy(value) >= 3.5;
}

/** Nunca se guarda el secreto completo: solo los 4 primeros caracteres y la longitud. */
export function maskSecret(value: string): string {
  return `${value.slice(0, 4)}…[${value.length} caracteres]`;
}

function matchPattern(text: string): { pattern: SecretPattern; match: RegExpExecArray } | null {
  for (const pattern of PATTERNS) {
    const match = pattern.re.exec(text);
    if (match) return { pattern, match };
  }
  return null;
}

function scanTextFile(file: InventoryFile, text: string, isAppConfig: boolean): RawFinding[] {
  const findings: RawFinding[] = [];
  const lines = text.split(/\r?\n/);
  lines.forEach((line, i) => {
    const hit = matchPattern(line);
    if (hit) {
      const value = hit.match[0];
      const where = isAppConfig ? ` en ${file.path} (se publica dentro de la app)` : '';
      findings.push({
        ruleId: hit.pattern.ruleId,
        severity: hit.pattern.severity?.(hit.match),
        message: `Encontrado ${hit.pattern.label}${where}: ${maskSecret(value)}`,
        location: { file: file.path, line: i + 1, column: hit.match.index + 1 },
        snippet: line.replace(value, maskSecret(value)).trim().slice(0, 200),
        evidence: { type: hit.pattern.label },
      });
      return;
    }

    const generic = GENERIC_ASSIGNMENT.exec(line);
    if (generic && looksLikeSecret(generic[2]!)) {
      const [, name, value] = generic as unknown as [string, string, string];
      findings.push({
        ruleId: 'secrets/generic-high-entropy',
        message: `"${name}" contiene una cadena de alta entropía (${shannonEntropy(value).toFixed(2)} bits/carácter): ${maskSecret(value)}`,
        location: { file: file.path, line: i + 1, column: generic.index + 1 },
        snippet: line.replace(value, maskSecret(value)).trim().slice(0, 200),
        evidence: { variable: name, entropy: Number(shannonEntropy(value).toFixed(2)) },
      });
    }
  });
  return findings;
}

/* eslint-disable security/detect-object-injection -- índices numéricos sobre cadenas, no claves de objeto */
/** Coincidencia de patrones de .gitignore con * y ? (sin expresiones regulares construidas desde el fichero). */
export function globMatch(pattern: string, text: string): boolean {
  let p = 0;
  let t = 0;
  let star = -1;
  let mark = 0;
  // Algoritmo clásico de comodines con un único punto de retroceso: tiempo lineal en la práctica.
  // Ni * ni ? cruzan una "/".
  while (t < text.length) {
    const pc = pattern[p];
    if (pc !== undefined && pc !== '*' && (pc === text[t] || (pc === '?' && text[t] !== '/'))) {
      p++;
      t++;
    } else if (pc === '*') {
      star = p++;
      mark = t;
    } else if (star !== -1 && text[mark] !== '/') {
      p = star + 1;
      t = ++mark;
    } else {
      return false;
    }
  }
  while (p < pattern.length && pattern[p] === '*') p++;
  return p === pattern.length;
}
/* eslint-enable security/detect-object-injection */

/** ¿Algún .gitignore (raíz o carpeta del fichero) excluye esta ruta? Respeta las negaciones (!). */
export function isGitIgnored(root: string, relPath: string): boolean {
  const dirs = new Set(['', posix.dirname(relPath) === '.' ? '' : posix.dirname(relPath)]);
  let ignored = false;
  for (const dir of dirs) {
    const gi = join(root, dir, '.gitignore');
    // eslint-disable-next-line security/detect-non-literal-fs-filename -- .gitignore dentro del proyecto analizado
    if (!existsSync(gi)) continue;
    // eslint-disable-next-line security/detect-non-literal-fs-filename -- ídem
    const lines = readFileSync(gi, 'utf8').split(/\r?\n/);
    const local = dir ? relPath.slice(dir.length + 1) : relPath;
    const base = posix.basename(relPath);
    for (const raw of lines) {
      const line = raw.trim();
      if (!line || line.startsWith('#')) continue;
      const negate = line.startsWith('!');
      const pat = (negate ? line.slice(1) : line).replace(/^\//, '').replace(/\/$/, '');
      const target = pat.includes('/') ? local : base;
      if (globMatch(pat, target)) ignored = !negate;
    }
  }
  return ignored;
}

function parseEnvLine(line: string): { key: string; value: string } | null {
  const trimmed = line.trim();
  if (!trimmed || trimmed.startsWith('#')) return null;
  const eq = trimmed.indexOf('=');
  if (eq <= 0) return null;
  const key = trimmed.slice(0, eq).replace(/^export\s+/, '').trim();
  let value = trimmed.slice(eq + 1).trim();
  if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
    value = value.slice(1, -1);
  }
  return { key, value };
}

function scanEnvFile(ctx: ScanContext, file: InventoryFile, text: string): RawFinding[] {
  const findings: RawFinding[] = [];
  const name = posix.basename(file.path);
  const isTemplate = /\.(?:example|sample|template|dist)$/.test(name);

  if (!isTemplate && !isGitIgnored(ctx.root, file.path)) {
    findings.push({
      ruleId: 'secrets/env-file-versioned',
      message: `${file.path} no está excluido en .gitignore: sus valores acabarán en el repositorio.`,
      location: { file: file.path, line: 1 },
    });
  }

  text.split(/\r?\n/).forEach((line, i) => {
    const entry = parseEnvLine(line);
    if (!entry || !entry.value) return;
    const hit = matchPattern(entry.value);
    const isPublic = entry.key.startsWith('EXPO_PUBLIC_');
    const sensitiveName = SENSITIVE_ENV_NAME.test(entry.key.replace(/^EXPO_PUBLIC_/, ''));
    const masked = maskSecret(entry.value);
    const location = { file: file.path, line: i + 1 };
    const snippet = `${entry.key}=${masked}`;

    if (isPublic && (hit || (sensitiveName && !PLACEHOLDER.test(entry.value)))) {
      findings.push({
        ruleId: 'secrets/expo-public-secret',
        // Una clave de Google/Firebase en EXPO_PUBLIC_ suele ser pública por diseño: severidad media.
        severity: hit?.pattern.ruleId === 'secrets/google-api-key' ? 'medium' : undefined,
        message: `${entry.key} se incrusta en el bundle JavaScript y parece un secreto${hit ? ` (${hit.pattern.label})` : ''}: ${masked}`,
        location,
        snippet,
        evidence: { variable: entry.key, ...(hit ? { type: hit.pattern.label } : {}) },
      });
    } else if (hit && !isTemplate) {
      findings.push({
        ruleId: hit.pattern.ruleId,
        severity: hit.pattern.severity?.(hit.match),
        message: `Encontrado ${hit.pattern.label} en ${entry.key}: ${masked}`,
        location,
        snippet,
        evidence: { variable: entry.key, type: hit.pattern.label },
      });
    }
  });
  return findings;
}

export const secretsDetector: Detector = {
  family: 'secrets',
  async run(ctx) {
    const findings: RawFinding[] = [];
    for (const file of ctx.files) {
      const text = ctx.readText(file);
      if (file.kind === 'env') findings.push(...scanEnvFile(ctx, file, text));
      else findings.push(...scanTextFile(file, text, file.path === ctx.appConfig.file));
    }
    return findings;
  },
};
