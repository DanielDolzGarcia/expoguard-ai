# ExpoGuard AI

Herramienta de línea de comandos que audita la seguridad del **código fuente** de aplicaciones
React Native creadas con **Expo**, antes de compilarlas. Combina reglas deterministas con (a partir del hito H3)
un modelo de lenguaje que filtra falsos positivos, prioriza y explica cada hallazgo.

> Proyecto de la asignatura Proyectos de Ciberseguridad (INSO4D) · Daniel Dolz García · Estado: **v0.2.0 (hitos H0–H2)**.

## Qué detecta (v0.2.0)

| Familia | Ejemplos | OWASP / MASVS |
|---|---|---|
| Secretos | Claves de AWS, Stripe, OpenAI/Anthropic/OpenRouter, GitHub, Slack, Google, JWT, claves PEM, cadenas de alta entropía, `EXPO_PUBLIC_*` con secretos, `.env` sin `.gitignore` | M1 · MASVS-STORAGE-1 / CRYPTO-2 |
| Almacenamiento | `AsyncStorage.setItem` con tokens o credenciales (resolviendo constantes), `redux-persist` con AsyncStorage, `console.*` con datos sensibles | M9 · MASVS-STORAGE-1/2 |
| Dependencias | `npm audit --package-lock-only`, agrupado por paquete, con la dependencia directa que lo introduce y si se importa en el código | M2 · MASVS-CODE-3 |
| WebView y deep links | `originWhitelist={['*']}`, acceso a ficheros, contenido mixto, URL dinámica con JS, `injectJavaScript` con datos, parámetros de deep link que llegan sin validar a `openURL`/`fetch`/WebView | M4/M5 · MASVS-PLATFORM-1/2 |
| Configuración nativa | `usesCleartextTraffic`, `NSAllowsArbitraryLoads`, `allowBackup` (también implícito), permisos peligrosos, esquema genérico, `android:debuggable` (app.json, app.config.js/ts, AndroidManifest.xml, Info.plist) | M5/M7/M8 · MASVS-NETWORK-1, PRIVACY-1… |

`expoguard rules` lista las 29 reglas con su severidad, control MASVS y categoría OWASP.

## Requisitos

- Node.js **24** o superior (incluye npm).
- Git (para clonar).
- Conexión a Internet solo para la auditoría de dependencias (se puede omitir con `--skip-deps`).

## Instalación

```bash
git clone https://github.com/DanielDolzGarcia/expoguard-ai.git
cd expoguard-ai
npm ci
npm run build
```

## Uso

```bash
# Analizar un proyecto Expo
node dist/cli.js scan ruta/al/proyecto-expo

# Sin red (no ejecuta npm audit)
node dist/cli.js scan ruta/al/proyecto --skip-deps

# Resultado en JSON (por pantalla o a fichero)
node dist/cli.js scan ruta/al/proyecto --json
node dist/cli.js scan ruta/al/proyecto -o informe.json

# Solo mostrar severidad alta o más, y fallar (código 1) solo con críticos
node dist/cli.js scan ruta/al/proyecto --min-severity high --fail-on critical

# Probarlo con las fixtures incluidas
node dist/cli.js scan tests/fixtures/vulnerable-app
```

Durante el desarrollo se puede ejecutar sin compilar: `npm run dev -- scan tests/fixtures/vulnerable-app`.

También se puede instalar como comando global con `npm link` y usar `expoguard scan .` dentro de un proyecto Expo.

**Códigos de salida:** `0` sin hallazgos por encima de `--fail-on` (por defecto `high`), `1` con hallazgos, `2` error (p. ej. la ruta no es un proyecto Expo).

## Desarrollo

```bash
npm run typecheck      # tsc --strict
npm run lint           # ESLint + eslint-plugin-security
npm test               # Vitest
npm run test:coverage  # con umbral mínimo del 70 %
npm run ci             # todo lo anterior + build (lo mismo que GitHub Actions)
```

Estructura:

```
src/cli.ts            comando "expoguard" (Commander)
src/scanner.ts        orquestación: contexto común y detectores en paralelo
src/ingest/           validación Expo, inventario, parseo AST (Babel), lectura estática de app.json/app.config
src/detectors/        secrets, storage, dependencies, webview (+ deep links), native
src/rules.ts          catálogo de reglas
data/masvs.json       catálogo local de controles MASVS v2.1 y OWASP Mobile Top 10 2024
tests/                tests unitarios y e2e; tests/fixtures con proyectos Expo vulnerables
docs/TAREAS.md        especificación de cada tarea
docs/AI_LOG.md        registro del uso de IA
CLAUDE.md             convenciones que sigue el agente de IA
```

## Seguridad de la propia herramienta

- **Nunca ejecuta** código del proyecto analizado: `app.config.ts` se evalúa de forma estática sobre el AST.
- No sigue enlaces simbólicos ni lee ficheros de más de 1 MB.
- `npm audit` se lanza sin shell, con `--package-lock-only` (no instala nada) y forzando el registro oficial, para que un `.npmrc` malicioso no lo redirija.
- Los secretos se muestran **siempre enmascarados** (4 primeros caracteres y longitud).
- Este repositorio **no contiene credenciales**. Las claves de `tests/` son falsas y contienen `FAKE` o `EXAMPLE`.
- A partir de H3 la clave de OpenRouter se leerá de la variable de entorno `OPENROUTER_API_KEY` (nunca de un fichero versionado).

## Pendiente (H3–H5)

Triaje y redacción con LLM vía OpenRouter (con saneador de secretos y validación Zod), informe Markdown,
pruebas de inyección de prompts, respaldo con la API de OSV y métricas de precisión con y sin IA. Ver `docs/TAREAS.md`.
