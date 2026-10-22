import type * as t from '@babel/types';
import {
  columnOf,
  expressionName,
  importLocals,
  lineOf,
  resolveString,
  SENSITIVE_NAME,
  snippetAt,
  traverse,
  type NodePath,
} from '../ast.js';
import type { Detector, ParsedFile, RawFinding } from '../types.js';

const ASYNC_STORAGE_MODULES = ['@react-native-async-storage/async-storage', '@react-native-community/async-storage'];
const WRITE_METHODS = new Set(['setItem', 'mergeItem', 'multiSet', 'multiMerge']);
const LOG_METHODS = new Set(['log', 'info', 'debug', 'warn', 'error', 'trace']);

function asyncStorageNames(ast: t.File): Set<string> {
  const names = new Set<string>();
  for (const mod of ASYNC_STORAGE_MODULES) for (const n of importLocals(ast, mod)) names.add(n);
  // API antigua: import { AsyncStorage } from 'react-native'
  for (const n of importLocals(ast, 'react-native', ['AsyncStorage'])) names.add(n);
  return names;
}

/** ¿El identificador es realmente el AsyncStorage importado (y no una variable local con el mismo nombre)? */
function isImportBinding(path: NodePath, name: string): boolean {
  const binding = path.scope.getBinding(name);
  return binding?.kind === 'module';
}

function describeKey(path: NodePath, node: t.Node | undefined): { key: string | null; text: string } {
  if (!node) return { key: null, text: '<sin clave>' };
  const key = resolveString(path, node);
  if (key !== null) return { key, text: `"${key}"` };
  if (node.type === 'TemplateLiteral') {
    const approx = node.quasis.map((q) => q.value.cooked ?? '').join('*');
    return { key: approx, text: `\`${approx}\`` };
  }
  const name = expressionName(node);
  return { key: name, text: name ? `<${name}>` : '<clave dinámica>' };
}

function writeFinding(file: ParsedFile, path: NodePath, call: t.CallExpression, method: string): RawFinding[] {
  const pairs: Array<{ keyNode?: t.Node; valueNode?: t.Node }> = [];
  if (method === 'multiSet' || method === 'multiMerge') {
    const arg = call.arguments[0];
    if (arg?.type === 'ArrayExpression') {
      for (const el of arg.elements) {
        if (el?.type === 'ArrayExpression') pairs.push({ keyNode: el.elements[0] ?? undefined, valueNode: el.elements[1] ?? undefined });
      }
    }
    if (pairs.length === 0) pairs.push({});
  } else {
    pairs.push({ keyNode: call.arguments[0], valueNode: call.arguments[1] });
  }

  return pairs.map(({ keyNode, valueNode }) => {
    const { key, text } = describeKey(path, keyNode);
    const valueName = valueNode ? expressionName(valueNode) : null;
    const sensitive = (key !== null && SENSITIVE_NAME.test(key)) || (valueName !== null && SENSITIVE_NAME.test(valueName));
    const line = lineOf(call);
    return {
      ruleId: sensitive ? 'storage/async-storage-sensitive' : 'storage/async-storage-write',
      message: sensitive
        ? `AsyncStorage.${method} guarda ${text}${valueName ? ` (valor: ${valueName})` : ''} sin cifrar.`
        : `AsyncStorage.${method} guarda ${text}. Revisar si el dato es sensible.`,
      location: { file: file.path, line, column: columnOf(call) },
      snippet: snippetAt(file.code, line),
      evidence: { method, key: key ?? '<dinámica>', ...(valueName ? { value: valueName } : {}) },
    };
  });
}

function reduxPersistFinding(file: ParsedFile, prop: t.ObjectProperty, obj: t.ObjectExpression): RawFinding {
  const listed: string[] = [];
  let listKind: 'whitelist' | 'blacklist' | null = null;
  for (const p of obj.properties) {
    if (p.type !== 'ObjectProperty' || p.key.type !== 'Identifier') continue;
    if ((p.key.name === 'whitelist' || p.key.name === 'blacklist') && p.value.type === 'ArrayExpression') {
      listKind = p.key.name;
      for (const el of p.value.elements) if (el?.type === 'StringLiteral') listed.push(el.value);
    }
  }
  const sensitiveSlices = listKind === 'whitelist' ? listed.filter((s) => SENSITIVE_NAME.test(s) || /user/i.test(s)) : [];
  // Sin whitelist se persiste TODO el estado, incluido el de autenticación si existe.
  const high = sensitiveSlices.length > 0 || listKind === null;
  const line = lineOf(prop);
  return {
    ruleId: 'storage/redux-persist-async-storage',
    severity: high ? 'high' : undefined,
    message:
      sensitiveSlices.length > 0
        ? `redux-persist guarda en AsyncStorage ramas sensibles del estado: ${sensitiveSlices.join(', ')}.`
        : listKind === null
          ? 'redux-persist guarda todo el estado en AsyncStorage (sin whitelist).'
          : `redux-persist guarda en AsyncStorage: ${listed.join(', ') || '(lista vacía)'}.`,
    location: { file: file.path, line, column: columnOf(prop) },
    snippet: snippetAt(file.code, line),
    evidence: { [listKind ?? 'whitelist']: listed },
  };
}

function sensitiveArgs(args: t.CallExpression['arguments']): string[] {
  const names: string[] = [];
  const visit = (node: t.Node) => {
    const name = expressionName(node);
    if (name) {
      const last = name.split('.').pop()!;
      if (SENSITIVE_NAME.test(last)) names.push(name);
      return;
    }
    if (node.type === 'TemplateLiteral') node.expressions.forEach(visit);
    else if (node.type === 'BinaryExpression') {
      visit(node.left);
      visit(node.right);
    } else if (node.type === 'ObjectExpression') {
      for (const p of node.properties) {
        if (p.type === 'ObjectProperty') visit(p.value);
      }
    }
  };
  args.forEach((a) => visit(a));
  return names;
}

export function analyzeStorage(file: ParsedFile): RawFinding[] {
  const findings: RawFinding[] = [];
  const storageNames = asyncStorageNames(file.ast);

  traverse(file.ast, {
    CallExpression(path) {
      const { callee } = path.node;
      if (callee.type !== 'MemberExpression' || callee.computed || callee.property.type !== 'Identifier') return;
      const method = callee.property.name;

      if (
        callee.object.type === 'Identifier' &&
        storageNames.has(callee.object.name) &&
        WRITE_METHODS.has(method) &&
        isImportBinding(path, callee.object.name)
      ) {
        findings.push(...writeFinding(file, path, path.node, method));
        return;
      }

      if (callee.object.type === 'Identifier' && callee.object.name === 'console' && LOG_METHODS.has(method)) {
        const names = sensitiveArgs(path.node.arguments);
        if (names.length > 0) {
          const line = lineOf(path.node);
          findings.push({
            ruleId: 'storage/sensitive-log',
            message: `console.${method} escribe ${names.join(', ')} en el log del dispositivo.`,
            location: { file: file.path, line, column: columnOf(path.node) },
            snippet: snippetAt(file.code, line),
            evidence: { values: names },
          });
        }
      }
    },
    ObjectProperty(path) {
      // { storage: AsyncStorage } dentro de la configuración de redux-persist
      const { key, value } = path.node;
      if (key.type !== 'Identifier' || key.name !== 'storage') return;
      if (value.type !== 'Identifier' || !storageNames.has(value.name)) return;
      const obj = path.parentPath.node;
      if (obj.type !== 'ObjectExpression') return;
      findings.push(reduxPersistFinding(file, path.node, obj));
    },
  });
  return findings;
}

export const storageDetector: Detector = {
  family: 'storage',
  async run(ctx) {
    return ctx.parsed.flatMap(analyzeStorage);
  },
};
