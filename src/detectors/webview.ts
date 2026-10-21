import type * as t from '@babel/types';
import type { Binding } from '@babel/traverse';
import { columnOf, importLocals, lineOf, resolveString, snippetAt, traverse, type NodePath } from '../ast.js';
import type { Detector, ParsedFile, RawFinding } from '../types.js';

const FILE_ACCESS_PROPS = new Set(['allowFileAccess', 'allowFileAccessFromFileURLs', 'allowUniversalAccessFromFileURLs']);

/** Funciones que devuelven datos controlados por quien abre el deep link. */
const SOURCE_HOOKS = new Set(['useLocalSearchParams', 'useGlobalSearchParams', 'useSearchParams', 'useURL']);
const SOURCE_LINKING_METHODS = new Set(['parse', 'useURL', 'getInitialURL', 'parseInitialURLAsync', 'useLinkingURL']);

/** Nombres de funciones que, si reciben el dato, consideramos una validación. */
const VALIDATOR_NAME = /valid|allow|safe|saniti|whitelist|trusted|check|verify|isHttps/i;

function attrName(attr: t.JSXAttribute): string | null {
  return attr.name.type === 'JSXIdentifier' ? attr.name.name : null;
}

/** Valor de un atributo JSX: `prop` sin valor equivale a true. */
function attrExpression(attr: t.JSXAttribute): t.Node | null {
  if (attr.value === null || attr.value === undefined) return { type: 'BooleanLiteral', value: true } as t.BooleanLiteral;
  if (attr.value.type === 'JSXExpressionContainer') {
    return attr.value.expression.type === 'JSXEmptyExpression' ? null : attr.value.expression;
  }
  return attr.value;
}

function isTrue(node: t.Node | null): boolean {
  return node?.type === 'BooleanLiteral' && node.value;
}

function isFalse(node: t.Node | null): boolean {
  return node?.type === 'BooleanLiteral' && !node.value;
}

/** Plantilla con huecos o concatenación: el script se construye con datos en tiempo de ejecución. */
function isDynamicScript(path: NodePath, node: t.Node | null | undefined): boolean {
  if (!node) return false;
  if (node.type === 'TemplateLiteral') return node.expressions.length > 0;
  if (node.type === 'BinaryExpression' && node.operator === '+') return true;
  if (node.type === 'StringLiteral') return false;
  return resolveString(path, node) === null;
}

function uriOfSource(node: t.Node | null): t.Node | null {
  if (node?.type !== 'ObjectExpression') return null;
  for (const p of node.properties) {
    if (p.type === 'ObjectProperty' && p.key.type === 'Identifier' && p.key.name === 'uri') return p.value;
  }
  return null;
}

class TaintTracker {
  private readonly tainted = new Set<Binding>();

  constructor(private readonly linkingNames: Set<string>) {}

  /** ¿La expresión es una fuente de datos de deep link? */
  isSource(node: t.Node | null | undefined): boolean {
    if (!node) return false;
    let n: t.Node = node;
    while (n.type === 'AwaitExpression' || n.type === 'TSAsExpression' || n.type === 'TSNonNullExpression') {
      n = n.type === 'AwaitExpression' ? n.argument : n.expression;
    }
    if (n.type === 'CallExpression') {
      const c = n.callee;
      if (c.type === 'Identifier' && SOURCE_HOOKS.has(c.name)) return true;
      if (
        c.type === 'MemberExpression' &&
        c.object.type === 'Identifier' &&
        this.linkingNames.has(c.object.name) &&
        c.property.type === 'Identifier' &&
        SOURCE_LINKING_METHODS.has(c.property.name)
      ) {
        return true;
      }
    }
    // route.params / props.route.params (React Navigation)
    if (n.type === 'MemberExpression' && n.property.type === 'Identifier' && n.property.name === 'params') {
      const obj = n.object;
      if (obj.type === 'Identifier' && obj.name === 'route') return true;
      if (obj.type === 'MemberExpression' && obj.property.type === 'Identifier' && obj.property.name === 'route') return true;
      if (obj.type === 'CallExpression' && obj.callee.type === 'Identifier' && obj.callee.name === 'useRoute') return true;
    }
    return false;
  }

  /** Marca como contaminadas todas las variables que declara un patrón (const { a, b: c } = ...). */
  taintDeclarator(path: NodePath<t.VariableDeclarator>): void {
    for (const name of Object.keys(path.get('id').getBindingIdentifiers())) {
      const b = path.scope.getBinding(name);
      if (b) this.tainted.add(b);
    }
  }

  taintBinding(b: Binding | undefined): void {
    if (b) this.tainted.add(b);
  }

  /** Variables contaminadas a las que hace referencia una expresión. */
  references(path: NodePath<t.Node>, node: t.Node | null | undefined): Binding[] {
    if (!node) return [];
    const found: Binding[] = [];
    const check = (id: t.Identifier, scopePath: NodePath) => {
      const b = scopePath.scope.getBinding(id.name);
      if (b && this.tainted.has(b)) found.push(b);
    };
    if (node.type === 'Identifier') {
      check(node, path);
      return found;
    }
    path.traverse({
      Identifier(inner) {
        if (inner.findParent((p) => p.node === node)) {
          if (inner.isReferencedIdentifier()) check(inner.node, inner);
        }
      },
    });
    return found;
  }

  /** ¿En la función que contiene el sink se pasa el dato por un validador? */
  isValidated(sinkPath: NodePath, bindings: Binding[]): boolean {
    const fn = sinkPath.getFunctionParent() ?? sinkPath.scope.getProgramParent().path;
    let validated = false;
    fn.traverse({
      CallExpression(call) {
        const callee = call.node.callee;
        const name =
          callee.type === 'Identifier'
            ? callee.name
            : callee.type === 'MemberExpression' && callee.property.type === 'Identifier'
              ? callee.property.name
              : '';
        if (!VALIDATOR_NAME.test(name) && name !== 'startsWith' && name !== 'includes') return;
        const subjects = [...call.node.arguments, ...(callee.type === 'MemberExpression' ? [callee.object] : [])];
        for (const arg of subjects) {
          if (arg.type === 'Identifier') {
            const b = call.scope.getBinding(arg.name);
            if (b && bindings.includes(b)) validated = true;
          }
        }
      },
    });
    return validated;
  }
}

export function analyzeWebView(file: ParsedFile): RawFinding[] {
  const findings: RawFinding[] = [];
  const webViewNames = importLocals(file.ast, 'react-native-webview');
  const linkingNames = new Set([...importLocals(file.ast, 'expo-linking'), ...importLocals(file.ast, 'react-native', ['Linking'])]);
  const browserNames = importLocals(file.ast, 'expo-web-browser');
  const taint = new TaintTracker(linkingNames);

  const push = (ruleId: string, node: t.Node, message: string, evidence?: RawFinding['evidence']) => {
    const line = lineOf(node);
    findings.push({
      ruleId,
      message,
      location: { file: file.path, line, column: columnOf(node) },
      snippet: snippetAt(file.code, line),
      ...(evidence ? { evidence } : {}),
    });
  };

  const sink = (path: NodePath<t.Node>, arg: t.Node | null | undefined, sinkName: string) => {
    const refs = taint.references(path, arg);
    if (refs.length === 0 || taint.isValidated(path, refs)) return;
    const params = [...new Set(refs.map((b) => b.identifier.name))];
    push(
      'deeplink/unvalidated-param-to-sink',
      arg ?? path.node,
      `El parámetro de deep link "${params.join(', ')}" llega sin validar a ${sinkName}.`,
      { params, sink: sinkName },
    );
  };

  // 1.ª pasada: fuentes y propagación (const a = fuente; const b = a.x).
  for (let pass = 0; pass < 2; pass++) {
    traverse(file.ast, {
      VariableDeclarator(path) {
        const init = path.node.init;
        if (taint.isSource(init) || (init && taint.references(path.get('init') as NodePath<t.Node>, init).length > 0)) {
          taint.taintDeclarator(path);
        }
      },
      CallExpression(path) {
        // Linking.addEventListener('url', (event) => ...): event viene del deep link.
        const c = path.node.callee;
        if (
          c.type === 'MemberExpression' &&
          c.object.type === 'Identifier' &&
          linkingNames.has(c.object.name) &&
          c.property.type === 'Identifier' &&
          c.property.name === 'addEventListener'
        ) {
          const handler = path.get('arguments.1') as NodePath<t.Node>;
          if (handler.isFunction()) {
            const first = handler.node.params[0];
            if (first?.type === 'Identifier') taint.taintBinding(handler.scope.getBinding(first.name));
          }
        }
      },
    });
  }

  // 2.ª pasada: props de WebView y sinks.
  traverse(file.ast, {
    JSXOpeningElement(path) {
      const name = path.node.name;
      if (name.type !== 'JSXIdentifier' || !webViewNames.has(name.name)) return;

      const attrs = new Map<string, t.JSXAttribute>();
      for (const a of path.node.attributes) {
        if (a.type === 'JSXAttribute') {
          const n = attrName(a);
          if (n) attrs.set(n, a);
        }
      }

      const origin = attrs.get('originWhitelist');
      const originExpr = origin ? attrExpression(origin) : null;
      if (originExpr?.type === 'ArrayExpression' && originExpr.elements.some((e) => e?.type === 'StringLiteral' && e.value === '*')) {
        push('webview/origin-whitelist-wildcard', origin!, 'originWhitelist incluye "*": la WebView navega a cualquier origen.');
      }

      for (const prop of FILE_ACCESS_PROPS) {
        const a = attrs.get(prop);
        if (a && isTrue(attrExpression(a))) push('webview/file-access', a, `${prop} está activado.`, { prop });
      }

      const mixed = attrs.get('mixedContentMode');
      const mixedExpr = mixed ? attrExpression(mixed) : null;
      if (mixedExpr?.type === 'StringLiteral' && mixedExpr.value === 'always') {
        push('webview/mixed-content', mixed!, 'mixedContentMode="always" permite cargar recursos http en páginas https.');
      }

      const jsAttr = attrs.get('javaScriptEnabled');
      const jsDisabled = jsAttr ? isFalse(attrExpression(jsAttr)) : false; // por defecto está activado
      const source = attrs.get('source');
      const uri = source ? uriOfSource(attrExpression(source)) : null;
      if (uri && !jsDisabled && resolveString(path, uri) === null) {
        push('webview/dynamic-source-js', source!, 'La URL de la WebView se calcula en tiempo de ejecución y JavaScript está activado.');
      }
      if (uri) {
        const sourcePath = path.get('attributes').find((a) => a.node === source) as NodePath<t.Node>;
        sink(sourcePath, uri, 'WebView source.uri');
      }

      const injected = attrs.get('injectedJavaScript');
      const injectedExpr = injected ? attrExpression(injected) : null;
      if (injected && isDynamicScript(path, injectedExpr)) {
        push('webview/inject-javascript-dynamic', injected, 'injectedJavaScript se construye con datos dinámicos.');
      }
    },
    // ref.current?.injectJavaScript(...) es un OptionalCallExpression, no un CallExpression.
    'CallExpression|OptionalCallExpression'(path: NodePath<t.CallExpression | t.OptionalCallExpression>) {
      const c = path.node.callee;
      const arg = path.node.arguments[0];
      const member = c.type === 'MemberExpression' || c.type === 'OptionalMemberExpression' ? c : null;
      const method = member && member.property.type === 'Identifier' ? member.property.name : null;

      if (method === 'injectJavaScript' && isDynamicScript(path, arg)) {
        push('webview/inject-javascript-dynamic', path.node, 'injectJavaScript recibe un script construido con datos dinámicos.');
      }

      if (member?.object.type === 'Identifier') {
        const obj = member.object.name;
        if (linkingNames.has(obj) && method === 'openURL') sink(path, arg, 'Linking.openURL');
        if (browserNames.has(obj) && method === 'openBrowserAsync') sink(path, arg, 'WebBrowser.openBrowserAsync');
      }
      if (c.type === 'Identifier' && c.name === 'fetch') sink(path, arg, 'fetch');
    },
  });

  return findings;
}

export const webviewDetector: Detector = {
  family: 'webview',
  async run(ctx) {
    return ctx.parsed.flatMap(analyzeWebView);
  },
};
