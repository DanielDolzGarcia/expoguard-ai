import type * as t from '@babel/types';
import { traverse } from '../ast.js';
import type { ParsedFile } from '../types.js';

/** 'lodash/merge' -> 'lodash', '@expo/vector-icons/Feather' -> '@expo/vector-icons'. Las rutas relativas se descartan. */
export function packageRoot(spec: string): string | null {
  if (spec.startsWith('.') || spec.startsWith('/') || spec.startsWith('node:')) return null;
  const parts = spec.split('/');
  if (spec.startsWith('@')) return parts.length >= 2 ? `${parts[0]}/${parts[1]}` : null;
  return parts[0] ?? null;
}

/** Paquetes que el código de la app importa de verdad (import, export from, require, import()). */
export function collectImportedPackages(files: ParsedFile[]): Set<string> {
  const found = new Set<string>();
  const add = (node: t.Node | null | undefined) => {
    if (node?.type !== 'StringLiteral') return;
    const root = packageRoot(node.value);
    if (root) found.add(root);
  };

  for (const file of files) {
    traverse(file.ast, {
      ImportDeclaration(p) {
        add(p.node.source);
      },
      ExportNamedDeclaration(p) {
        add(p.node.source);
      },
      ExportAllDeclaration(p) {
        add(p.node.source);
      },
      CallExpression(p) {
        const callee = p.node.callee;
        if ((callee.type === 'Identifier' && callee.name === 'require') || callee.type === 'Import') {
          add(p.node.arguments[0]);
        }
      },
      ImportExpression(p) {
        add(p.node.source);
      },
    });
  }
  return found;
}
