import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { parseExpression } from '@babel/parser';
import type * as t from '@babel/types';
import type { AppConfig, ExpoProject } from '../types.js';
import { parseSource } from './parser.js';

/** Marcador para valores que no se pueden conocer sin ejecutar el código (process.env.X, llamadas...). */
export const UNKNOWN = Symbol('unknown');

type Lines = Map<string, number>;

interface EvalState {
  lines: Lines;
  /** Constantes de nivel superior del fichero, para resolver `export default config`. */
  consts: Map<string, t.Expression>;
  depth: number;
}

function unwrap(node: t.Node): t.Node {
  let n = node;
  while (
    n.type === 'TSAsExpression' ||
    n.type === 'TSSatisfiesExpression' ||
    n.type === 'TSNonNullExpression' ||
    n.type === 'ParenthesizedExpression' ||
    n.type === 'TypeCastExpression'
  ) {
    n = n.expression;
  }
  return n;
}

function keyName(prop: t.ObjectProperty): string | null {
  if (prop.computed) return prop.key.type === 'StringLiteral' ? prop.key.value : null;
  if (prop.key.type === 'Identifier') return prop.key.name;
  if (prop.key.type === 'StringLiteral') return prop.key.value;
  if (prop.key.type === 'NumericLiteral') return String(prop.key.value);
  return null;
}

/** Evalúa de forma estática un nodo literal. Registra la línea de cada clave en `state.lines`. */
function evaluate(node: t.Node, path: string[], state: EvalState): unknown {
  if (state.depth > 50) return UNKNOWN;
  const n = unwrap(node);
  switch (n.type) {
    case 'StringLiteral':
      return n.value;
    case 'NumericLiteral':
      return n.value;
    case 'BooleanLiteral':
      return n.value;
    case 'NullLiteral':
      return null;
    case 'TemplateLiteral':
      return n.expressions.length === 0 ? (n.quasis[0]?.value.cooked ?? '') : UNKNOWN;
    case 'Identifier': {
      if (n.name === 'undefined') return undefined;
      const target = state.consts.get(n.name);
      if (!target) return UNKNOWN;
      state.depth++;
      const value = evaluate(target, path, state);
      state.depth--;
      return value;
    }
    case 'ArrayExpression':
      return n.elements.map((el, i) =>
        el && el.type !== 'SpreadElement' ? evaluate(el, [...path, String(i)], state) : UNKNOWN,
      );
    case 'ObjectExpression': {
      // Sin prototipo: una clave "__proto__" en el app.json analizado no debe alterar el objeto resultante.
      const out = Object.create(null) as Record<string, unknown>;
      for (const prop of n.properties) {
        if (prop.type !== 'ObjectProperty') continue; // spread (...config) y métodos se ignoran
        const name = keyName(prop);
        if (name === null) continue;
        const childPath = [...path, name];
        if (prop.loc) state.lines.set(childPath.join('\u0000'), prop.loc.start.line);
        // eslint-disable-next-line security/detect-object-injection -- `out` no tiene prototipo
        out[name] = evaluate(prop.value, childPath, state);
      }
      return out;
    }
    default:
      return UNKNOWN;
  }
}

/** Busca el objeto que devuelve una función flecha o function: `({ config }) => ({...})`. */
function returnedExpression(fn: t.Node): t.Node | null {
  const f = unwrap(fn);
  if (f.type !== 'ArrowFunctionExpression' && f.type !== 'FunctionExpression' && f.type !== 'FunctionDeclaration') {
    return f;
  }
  if (f.body.type !== 'BlockStatement') return f.body;
  for (const stmt of f.body.body) {
    if (stmt.type === 'ReturnStatement' && stmt.argument) return stmt.argument;
  }
  return null;
}

function findExportedConfig(ast: t.File, consts: Map<string, t.Expression>): t.Node | null {
  for (const stmt of ast.program.body) {
    if (stmt.type === 'ExportDefaultDeclaration') {
      const decl = stmt.declaration;
      if (decl.type === 'Identifier' && consts.has(decl.name)) {
        return returnedExpression(consts.get(decl.name)!);
      }
      return returnedExpression(decl);
    }
    // module.exports = ...
    if (
      stmt.type === 'ExpressionStatement' &&
      stmt.expression.type === 'AssignmentExpression' &&
      stmt.expression.left.type === 'MemberExpression' &&
      stmt.expression.left.object.type === 'Identifier' &&
      stmt.expression.left.object.name === 'module' &&
      stmt.expression.left.property.type === 'Identifier' &&
      stmt.expression.left.property.name === 'exports'
    ) {
      const right = stmt.expression.right;
      if (right.type === 'Identifier' && consts.has(right.name)) {
        return returnedExpression(consts.get(right.name)!);
      }
      return returnedExpression(right);
    }
  }
  return null;
}

function collectTopLevelConsts(ast: t.File): Map<string, t.Expression> {
  const consts = new Map<string, t.Expression>();
  for (const stmt of ast.program.body) {
    const decl =
      stmt.type === 'VariableDeclaration'
        ? stmt
        : stmt.type === 'ExportNamedDeclaration' && stmt.declaration?.type === 'VariableDeclaration'
          ? stmt.declaration
          : null;
    if (!decl || decl.kind !== 'const') continue;
    for (const d of decl.declarations) {
      if (d.id.type === 'Identifier' && d.init) consts.set(d.id.name, d.init);
    }
  }
  return consts;
}

function makeConfig(file: string | null, data: unknown, lines: Lines, prefix: string[]): AppConfig {
  const obj = data && typeof data === 'object' && !Array.isArray(data) ? (data as Record<string, unknown>) : {};
  return {
    file,
    data: obj,
    lineOf(path: string[]) {
      return lines.get([...prefix, ...path].join('\u0000')) ?? null;
    },
  };
}

/** Si la configuración va dentro de { expo: {...} } devuelve esa parte, como hace Expo CLI. */
function selectExpo(data: unknown): { data: unknown; prefix: string[] } {
  if (data && typeof data === 'object' && 'expo' in data) {
    const inner = (data as Record<string, unknown>)['expo'];
    if (inner && typeof inner === 'object') return { data: inner, prefix: ['expo'] };
  }
  return { data, prefix: [] };
}

/** Evalúa un JSON con Babel para conservar las posiciones de cada clave. */
export function evaluateJson(text: string): { data: unknown; lines: Lines } {
  const node = parseExpression(text, { sourceType: 'module' });
  const lines: Lines = new Map();
  const data = evaluate(node, [], { lines, consts: new Map(), depth: 0 });
  return { data, lines };
}

export function loadAppConfig(project: ExpoProject): { config: AppConfig; warning?: string } {
  const file = project.configFile;
  if (!file) return { config: makeConfig(null, {}, new Map(), []) };

  // eslint-disable-next-line security/detect-non-literal-fs-filename -- nombre fijo de CONFIG_FILES dentro de la raíz
  const text = readFileSync(join(project.root, file), 'utf8');
  try {
    if (file.endsWith('.json')) {
      const { data, lines } = evaluateJson(text);
      const sel = selectExpo(data);
      return { config: makeConfig(file, sel.data, lines, sel.prefix) };
    }

    const parsed = parseSource(text, file);
    if (!parsed.ok) {
      return { config: makeConfig(file, {}, new Map(), []), warning: `No se pudo parsear ${file}: ${parsed.error}` };
    }
    const consts = collectTopLevelConsts(parsed.ast);
    const exported = findExportedConfig(parsed.ast, consts);
    if (!exported) {
      return {
        config: makeConfig(file, {}, new Map(), []),
        warning: `No se encontró el objeto exportado en ${file}`,
      };
    }
    const lines: Lines = new Map();
    const data = evaluate(exported, [], { lines, consts, depth: 0 });
    const sel = selectExpo(data);
    return { config: makeConfig(file, sel.data, lines, sel.prefix) };
  } catch (err) {
    return {
      config: makeConfig(file, {}, new Map(), []),
      warning: `Error leyendo ${file}: ${(err as Error).message}`,
    };
  }
}

/** Acceso seguro a una ruta del objeto de configuración. */
export function getPath(obj: unknown, path: string[]): unknown {
  let cur: unknown = obj;
  for (const key of path) {
    if (!cur || typeof cur !== 'object' || !Object.hasOwn(cur, key)) return undefined;
    // eslint-disable-next-line security/detect-object-injection -- solo propiedades propias (hasOwn)
    cur = (cur as Record<string, unknown>)[key];
  }
  return cur;
}
