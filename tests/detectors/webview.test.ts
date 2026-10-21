import { describe, expect, it } from 'vitest';
import { webviewDetector } from '../../src/detectors/webview.js';
import { rules, runDetector } from '../helpers.js';

const WV = "import { WebView } from 'react-native-webview';\n";

describe('webviewDetector: props de WebView', () => {
  it('una WebView estática y segura no genera hallazgos', async () => {
    const f = await runDetector(webviewDetector, {
      'a.tsx': WV + "const A = () => <WebView source={{ uri: 'https://ok.example' }} originWhitelist={['https://ok.example']} />;",
    });
    expect(f).toEqual([]);
  });

  it('URL dinámica con JS activado por defecto; con javaScriptEnabled={false} no', async () => {
    const a = await runDetector(webviewDetector, { 'a.tsx': WV + 'const A = ({ u }) => <WebView source={{ uri: u }} />;' });
    expect(rules(a)).toEqual(['webview/dynamic-source-js']);
    const b = await runDetector(webviewDetector, {
      'a.tsx': WV + 'const A = ({ u }) => <WebView source={{ uri: u }} javaScriptEnabled={false} />;',
    });
    expect(b).toEqual([]);
  });

  it('una constante local cuenta como URL estática', async () => {
    const f = await runDetector(webviewDetector, {
      'a.tsx': WV + "const URL_HELP = 'https://help.example';\nconst A = () => <WebView source={{ uri: URL_HELP }} />;",
    });
    expect(f).toEqual([]);
  });

  it('acceso a ficheros, contenido mixto y comodín de orígenes', async () => {
    const f = await runDetector(webviewDetector, {
      'a.tsx':
        WV +
        "const A = () => <WebView source={{ uri: 'https://x' }} allowFileAccessFromFileURLs mixedContentMode=\"always\" originWhitelist={['*']} allowFileAccess={false} />;",
    });
    expect(rules(f).sort()).toEqual(['webview/file-access', 'webview/mixed-content', 'webview/origin-whitelist-wildcard']);
  });

  it('respeta el alias del import y no confunde otros componentes', async () => {
    const a = await runDetector(webviewDetector, {
      'a.tsx': "import WV from 'react-native-webview';\nconst A = () => <WV source={{ uri: 'https://x' }} originWhitelist={['*']} />;",
    });
    expect(rules(a)).toEqual(['webview/origin-whitelist-wildcard']);
    const b = await runDetector(webviewDetector, { 'a.tsx': "const A = () => <WebView originWhitelist={['*']} />;" });
    expect(b).toEqual([]);
  });

  it('injectJavaScript / injectedJavaScript con datos dinámicos (incluida la llamada opcional ?.)', async () => {
    const f = await runDetector(webviewDetector, {
      'a.tsx':
        WV +
        [
          'ref.current?.injectJavaScript(`setUser(${name})`);',
          "ref.current.injectJavaScript('window.scrollTo(0,0); true;');",
          "ref.injectJavaScript('a' + b);",
          'const A = () => <WebView injectedJavaScript={`init(${cfg})`} />;',
          "const B = () => <WebView injectedJavaScript={'init()'} />;",
        ].join('\n'),
    });
    expect(rules(f)).toEqual(['webview/inject-javascript-dynamic', 'webview/inject-javascript-dynamic', 'webview/inject-javascript-dynamic']);
    expect(f.map((x) => x.location.line)).toEqual([2, 4, 5]);
  });
});

describe('webviewDetector: deep links', () => {
  it('parámetro de expo-router hasta Linking.openURL', async () => {
    const f = await runDetector(webviewDetector, {
      'a.tsx': [
        "import { useLocalSearchParams } from 'expo-router';",
        "import { Linking } from 'react-native';",
        'export default function S() {',
        '  const { next } = useLocalSearchParams();',
        '  const target = String(next);',
        '  Linking.openURL(target);',
        '}',
      ].join('\n'),
    });
    expect(rules(f)).toEqual(['deeplink/unvalidated-param-to-sink']);
    expect(f[0]!.evidence).toMatchObject({ sink: 'Linking.openURL', params: ['target'] });
  });

  it('si el parámetro pasa por un validador no se informa', async () => {
    const f = await runDetector(webviewDetector, {
      'a.tsx': [
        "import { useLocalSearchParams } from 'expo-router';",
        "import * as Linking from 'expo-linking';",
        'export default function S() {',
        '  const { next } = useLocalSearchParams();',
        '  if (isAllowedHost(next)) Linking.openURL(next);',
        '}',
      ].join('\n'),
    });
    expect(f).toEqual([]);
  });

  it('route.params de React Navigation hasta fetch y WebBrowser', async () => {
    const f = await runDetector(webviewDetector, {
      'a.tsx': [
        "import * as WebBrowser from 'expo-web-browser';",
        'export function S({ route }) {',
        '  const { url } = route.params;',
        '  fetch(url);',
        '  WebBrowser.openBrowserAsync(url);',
        '}',
      ].join('\n'),
    });
    expect(f.map((x) => x.evidence?.['sink'])).toEqual(['fetch', 'WebBrowser.openBrowserAsync']);
  });

  it('getInitialURL con await y parse', async () => {
    const f = await runDetector(webviewDetector, {
      'a.ts': [
        "import * as Linking from 'expo-linking';",
        'async function boot() {',
        '  const initial = await Linking.getInitialURL();',
        '  fetch(initial);',
        "  fetch('https://static.example');",
        '}',
      ].join('\n'),
    });
    expect(f).toHaveLength(1);
    expect(f[0]!.location.line).toBe(4);
  });
});
