import type { Family, Severity } from './types.js';

export interface Rule {
  id: string;
  family: Family;
  title: string;
  severity: Severity;
  masvs: string;
  owasp: string;
  remediation: string;
}

// Catálogo de reglas deterministas. La severidad es la de partida: el triaje de IA (H3) podrá
// proponer otra, pero nunca eliminar un hallazgo crítico.
export const RULES: readonly Rule[] = [
  // --- Secretos ---
  {
    id: 'secrets/private-key',
    family: 'secrets',
    title: 'Clave privada incrustada en el código',
    severity: 'critical',
    masvs: 'MASVS-CRYPTO-2',
    owasp: 'M1',
    remediation: 'Eliminar la clave del repositorio, rotarla y firmar en el servidor.',
  },
  {
    id: 'secrets/aws-access-key',
    family: 'secrets',
    title: 'Credencial de AWS incrustada',
    severity: 'critical',
    masvs: 'MASVS-STORAGE-1',
    owasp: 'M1',
    remediation: 'Revocar la clave en IAM y usar credenciales temporales (Cognito) o un backend intermedio.',
  },
  {
    id: 'secrets/stripe-secret-key',
    family: 'secrets',
    title: 'Clave secreta de Stripe incrustada',
    severity: 'critical',
    masvs: 'MASVS-STORAGE-1',
    owasp: 'M1',
    remediation: 'Rotar la clave. En la app solo debe ir la clave publicable (pk_...).',
  },
  {
    id: 'secrets/llm-api-key',
    family: 'secrets',
    title: 'Clave de API de un proveedor de LLM incrustada',
    severity: 'high',
    masvs: 'MASVS-STORAGE-1',
    owasp: 'M1',
    remediation: 'Rotar la clave y llamar al modelo desde un backend propio con límites de uso.',
  },
  {
    id: 'secrets/github-token',
    family: 'secrets',
    title: 'Token de GitHub incrustado',
    severity: 'high',
    masvs: 'MASVS-STORAGE-1',
    owasp: 'M1',
    remediation: 'Revocar el token en GitHub.',
  },
  {
    id: 'secrets/slack-token',
    family: 'secrets',
    title: 'Token de Slack incrustado',
    severity: 'high',
    masvs: 'MASVS-STORAGE-1',
    owasp: 'M1',
    remediation: 'Revocar el token en Slack.',
  },
  {
    id: 'secrets/google-api-key',
    family: 'secrets',
    title: 'Clave de API de Google incrustada',
    severity: 'medium',
    masvs: 'MASVS-STORAGE-1',
    owasp: 'M1',
    remediation:
      'Si es una clave de cliente de Firebase es pública por diseño: restringirla por app y API en Google Cloud. Si no, moverla al servidor.',
  },
  {
    id: 'secrets/jwt',
    family: 'secrets',
    title: 'Token JWT incrustado',
    severity: 'medium',
    masvs: 'MASVS-STORAGE-1',
    owasp: 'M1',
    remediation: 'Los tokens se obtienen en tiempo de ejecución; no deben estar en el código.',
  },
  {
    id: 'secrets/generic-high-entropy',
    family: 'secrets',
    title: 'Posible secreto (cadena de alta entropía en variable sensible)',
    severity: 'medium',
    masvs: 'MASVS-CRYPTO-2',
    owasp: 'M1',
    remediation: 'Comprobar si es un secreto real; en ese caso, rotarlo y sacarlo del código.',
  },
  {
    id: 'secrets/expo-public-secret',
    family: 'secrets',
    title: 'Secreto en una variable EXPO_PUBLIC_ (se incrusta en el bundle)',
    severity: 'high',
    masvs: 'MASVS-STORAGE-1',
    owasp: 'M1',
    remediation: 'Las variables EXPO_PUBLIC_* se copian en el JavaScript publicado. Usar un backend o EAS Secrets en el servidor.',
  },
  {
    id: 'secrets/env-file-versioned',
    family: 'secrets',
    title: 'Fichero .env no excluido en .gitignore',
    severity: 'medium',
    masvs: 'MASVS-STORAGE-1',
    owasp: 'M1',
    remediation: 'Añadir .env* a .gitignore y eliminarlo del historial si ya se subió.',
  },

  // --- Almacenamiento ---
  {
    id: 'storage/async-storage-sensitive',
    family: 'storage',
    title: 'Dato sensible guardado en AsyncStorage (sin cifrar)',
    severity: 'high',
    masvs: 'MASVS-STORAGE-1',
    owasp: 'M9',
    remediation: 'Usar expo-secure-store (Keychain/Keystore) para tokens y credenciales.',
  },
  {
    id: 'storage/async-storage-write',
    family: 'storage',
    title: 'Escritura en AsyncStorage (revisar si el dato es sensible)',
    severity: 'low',
    masvs: 'MASVS-STORAGE-1',
    owasp: 'M9',
    remediation: 'Si el valor es sensible, usar expo-secure-store. Si es una preferencia, no requiere acción.',
  },
  {
    id: 'storage/redux-persist-async-storage',
    family: 'storage',
    title: 'redux-persist guarda el estado en AsyncStorage',
    severity: 'medium',
    masvs: 'MASVS-STORAGE-1',
    owasp: 'M9',
    remediation: 'Excluir las ramas sensibles (auth) o usar un storage cifrado como redux-persist-expo-securestore.',
  },
  {
    id: 'storage/sensitive-log',
    family: 'storage',
    title: 'Dato sensible escrito en el log',
    severity: 'medium',
    masvs: 'MASVS-STORAGE-2',
    owasp: 'M9',
    remediation: 'Eliminar el log o quitar el dato. console.* sigue activo en builds de producción.',
  },

  // --- Dependencias ---
  {
    id: 'deps/known-vulnerability',
    family: 'dependencies',
    title: 'Dependencia con vulnerabilidades conocidas',
    severity: 'medium',
    masvs: 'MASVS-CODE-3',
    owasp: 'M2',
    remediation: 'Actualizar a una versión corregida compatible con el SDK de Expo (npx expo install --fix).',
  },
  {
    id: 'deps/no-lockfile',
    family: 'dependencies',
    title: 'No hay package-lock.json: no se pueden auditar las dependencias',
    severity: 'info',
    masvs: 'MASVS-CODE-3',
    owasp: 'M2',
    remediation: 'Versionar el lockfile para tener builds reproducibles y poder auditarlas.',
  },
  {
    id: 'deps/deprecated-package',
    family: 'dependencies',
    title: 'Paquete marcado como obsoleto (abandonado) por su autor',
    severity: 'low',
    masvs: 'MASVS-CODE-3',
    owasp: 'M2',
    remediation: 'Sustituirlo por la alternativa que indica el autor o actualizar la dependencia que lo arrastra: ya no recibe parches de seguridad.',
  },
  {
    id: 'deps/license-issue',
    family: 'dependencies',
    title: 'Dependencia sin licencia declarada o con licencia propietaria',
    severity: 'info',
    masvs: 'MASVS-CODE-3',
    owasp: 'M2',
    remediation: 'Comprobar la licencia en el repositorio del paquete antes de publicar la app; sin licencia no hay permiso para redistribuirlo.',
  },

  // --- WebView y deep links ---
  {
    id: 'webview/origin-whitelist-wildcard',
    family: 'webview',
    title: 'WebView acepta cualquier origen (originWhitelist con *)',
    severity: 'medium',
    masvs: 'MASVS-PLATFORM-2',
    owasp: 'M4',
    remediation: 'Limitar originWhitelist a los dominios propios con https.',
  },
  {
    id: 'webview/file-access',
    family: 'webview',
    title: 'WebView con acceso a ficheros locales',
    severity: 'high',
    masvs: 'MASVS-PLATFORM-2',
    owasp: 'M4',
    remediation: 'Desactivar allowFileAccess y allowUniversalAccessFromFileURLs salvo necesidad justificada.',
  },
  {
    id: 'webview/dynamic-source-js',
    family: 'webview',
    title: 'WebView con URL dinámica y JavaScript activado',
    severity: 'medium',
    masvs: 'MASVS-PLATFORM-2',
    owasp: 'M4',
    remediation: 'Validar la URL contra una lista de dominios o desactivar javaScriptEnabled.',
  },
  {
    id: 'webview/inject-javascript-dynamic',
    family: 'webview',
    title: 'JavaScript inyectado en la WebView construido con datos dinámicos',
    severity: 'medium',
    masvs: 'MASVS-PLATFORM-2',
    owasp: 'M4',
    remediation: 'Pasar los datos con postMessage y JSON.stringify en lugar de concatenarlos en el script.',
  },
  {
    id: 'webview/mixed-content',
    family: 'webview',
    title: 'WebView permite contenido mixto (http dentro de https)',
    severity: 'medium',
    masvs: 'MASVS-NETWORK-1',
    owasp: 'M5',
    remediation: 'Usar mixedContentMode="never" (valor por defecto).',
  },
  {
    id: 'deeplink/unvalidated-param-to-sink',
    family: 'webview',
    title: 'Parámetro de deep link sin validar llega a una operación peligrosa',
    severity: 'high',
    masvs: 'MASVS-PLATFORM-1',
    owasp: 'M4',
    remediation: 'Validar el parámetro (esquema https y lista de hosts permitidos) antes de abrirlo o cargarlo.',
  },

  // --- Configuración nativa ---
  {
    id: 'native/android-cleartext',
    family: 'native',
    title: 'Android permite tráfico HTTP sin cifrar',
    severity: 'high',
    masvs: 'MASVS-NETWORK-1',
    owasp: 'M5',
    remediation: 'Quitar usesCleartextTraffic o limitarlo a dominios de desarrollo con networkSecurityConfig.',
  },
  {
    id: 'native/ios-ats-disabled',
    family: 'native',
    title: 'iOS App Transport Security desactivado',
    severity: 'high',
    masvs: 'MASVS-NETWORK-1',
    owasp: 'M5',
    remediation: 'Eliminar NSAllowsArbitraryLoads y usar excepciones por dominio solo si es imprescindible.',
  },
  {
    id: 'native/android-allow-backup',
    family: 'native',
    title: 'Copias de seguridad de Android habilitadas',
    severity: 'medium',
    masvs: 'MASVS-STORAGE-2',
    owasp: 'M8',
    remediation: 'Poner android.allowBackup a false en app.json (Expo lo deja a true por defecto).',
  },
  {
    id: 'native/dangerous-permissions',
    family: 'native',
    title: 'Permisos Android peligrosos solicitados',
    severity: 'medium',
    masvs: 'MASVS-PRIVACY-1',
    owasp: 'M8',
    remediation: 'Pedir solo los permisos imprescindibles y quitar el resto de android.permissions.',
  },
  {
    id: 'native/generic-scheme',
    family: 'native',
    title: 'Esquema de deep link genérico (fácil de suplantar)',
    severity: 'low',
    masvs: 'MASVS-PLATFORM-1',
    owasp: 'M8',
    remediation: 'Usar un esquema único (p. ej. el bundle id) y App Links/Universal Links verificados.',
  },
  {
    id: 'native/android-debuggable',
    family: 'native',
    title: 'Aplicación Android marcada como depurable',
    severity: 'high',
    masvs: 'MASVS-RESILIENCE-4',
    owasp: 'M7',
    remediation: 'Eliminar android:debuggable del manifiesto; Gradle lo gestiona por tipo de build.',
  },
];

const BY_ID = new Map(RULES.map((r) => [r.id, r]));

export function getRule(id: string): Rule {
  const rule = BY_ID.get(id);
  if (!rule) throw new Error(`Regla desconocida: ${id}`);
  return rule;
}

export const FAMILY_PREFIX: Record<Family, string> = {
  secrets: 'SECRETS',
  storage: 'STORAGE',
  dependencies: 'DEPS',
  webview: 'WEBVIEW',
  native: 'NATIVE',
};
