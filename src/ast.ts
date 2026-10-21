import traverseDefault, { type NodePath } from '@babel/traverse';
import type * as t from '@babel/types';

export const traverse = traverseDefault;
export type { NodePath };

/** Nombres de variable o de clave que suelen contener datos sensibles. */
export const SENSITIVE_NAME =
  /(token|jwt|session|passw|pwd|secret|credential|auth|bearer|cookie|refresh|private|pin(?:code)?$|otp|cvv|card|iban|ssn)/i;

/**
 * Intenta conocer el valor de cadena de una expresión sin ejecutar nada:
 * literales, plantillas sin huecos, constantes locales y propiedades de objetos constantes.
 */
export function resolveString(path: NodePath, node: t.Node | null | undefined, depth = 0): string | null {
  if (!node || depth > 5) return null;
  switch (node.type) {
    case 'StringLiteral':
      return node.value;
    case 'TemplateLiteral':
      return node.expressions.length === 0 ? (node.quasis[0]?.value.cooked ?? null) : null;
    case 'TSAsExpression':
    case 'TSSatisfiesExpression':
    case 'TSNonNullExpression':
      return resolveString(path, node.expression, depth + 1);
    case 'Identifier': {
      const binding = path.scope.getBinding(node.name);
      if (!binding || !binding.constant || !binding.path.isVariableDeclarator()) return null;
      return resolveString(binding.path, binding.path.node.init, depth + 1);
    }
    case 'MemberExpression': {
      // KEYS.TOKEN con const KEYS = { TOKEN: '...' }
      if (node.object.type !== 'Identifier' || node.computed || node.property.type !== 'Identifier') return null;
      const binding = path.scope.getBinding(node.object.name);
      if (!binding || !binding.path.isVariableDeclarator()) return null;
      const init = binding.path.node.init;
      const obj = init?.type === 'TSAsExpression' ? init.expression : init;
      if (obj?.type !== 'ObjectExpression') return null;
      const propName = node.property.name;
      for (const prop of obj.properties) {
        if (
          prop.type === 'ObjectProperty' &&
          ((prop.key.type === 'Identifier' && prop.key.name === propName) ||
            (prop.key.type === 'StringLiteral' && prop.key.value === propName))
        ) {
          return resolveString(binding.path, prop.value, depth + 1);
        }
      }
      return null;
    }
    default:
      return null;
  }
}

/** Nombre "legible" de una expresión: token, user.password, ... */
export function expressionName(node: t.Node): string | null {
  if (node.type === 'Identifier') return node.name;
  if (node.type === 'MemberExpression' && !node.computed && node.property.type === 'Identifier') {
    const obj = expressionName(node.object);
    return obj ? `${obj}.${node.property.name}` : node.property.name;
  }
  if (node.type === 'OptionalMemberExpression' && !node.computed && node.property.type === 'Identifier') {
    const obj = expressionName(node.object);
    return obj ? `${obj}.${node.property.name}` : node.property.name;
  }
  return null;
}

/** Nombres locales con los que se importa un módulo: import X from 'm', import * as X, import { a as X }. */
export function importLocals(ast: t.File, source: string, imported?: string[]): Set<string> {
  const names = new Set<string>();
  for (const stmt of ast.program.body) {
    if (stmt.type !== 'ImportDeclaration' || stmt.source.value !== source) continue;
    for (const spec of stmt.specifiers) {
      if (spec.type === 'ImportDefaultSpecifier' || spec.type === 'ImportNamespaceSpecifier') {
        if (!imported || imported.includes('default')) names.add(spec.local.name);
      } else {
        const name = spec.imported.type === 'Identifier' ? spec.imported.name : spec.imported.value;
        if (!imported || imported.includes(name)) names.add(spec.local.name);
      }
    }
  }
  return names;
}

export function lineOf(node: t.Node): number {
  return node.loc?.start.line ?? 0;
}

export function columnOf(node: t.Node): number {
  return (node.loc?.start.column ?? 0) + 1;
}

/** Línea de código original recortada, para mostrarla como contexto del hallazgo. */
export function snippetAt(code: string, line: number): string {
  const text = code.split(/\r?\n/)[line - 1] ?? '';
  return text.trim().slice(0, 200);
}
