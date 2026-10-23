# Especificación de tareas

Cada tarea es la especificación que recibe el agente (Claude Code) junto con `CLAUDE.md`.
Formato: objetivo, criterios de aceptación y casos de prueba. Estado actualizado a 23/10/2026.

---

## T01 · Preparación del repositorio (H0) — ✅ completada

**Objetivo.** Repositorio Git con TypeScript estricto, ESLint con reglas de seguridad, Vitest con cobertura, CI de GitHub Actions, `CLAUDE.md` y `docs/AI_LOG.md`.

**Criterios de aceptación.**
- `npm run ci` termina sin errores.
- El workflow `.github/workflows/ci.yml` ejecuta typecheck, lint, tests con cobertura, build y `npm audit` del propio proyecto.
- `.gitignore` excluye `.env*` (salvo las fixtures) para que no se suban claves.

## T02 · Fixtures Expo vulnerables (H0) — ✅ completada

**Objetivo.** Proyectos Expo de prueba con vulnerabilidades insertadas y conocidas de antemano.

**Criterios de aceptación.**
- `tests/fixtures/vulnerable-app`: al menos una vulnerabilidad por familia, documentadas en `expected.json` (regla, fichero y línea).
- `tests/fixtures/safe-app`: misma funcionalidad hecha de forma segura (sirve para medir falsos positivos).
- `tests/fixtures/prebuild-app`: proyecto con `app.config.ts` dinámico y carpetas `android/` e `ios/` generadas.
- Todas las claves son falsas (contienen `FAKE` o `EXAMPLE`).

## T03 · Validación del proyecto Expo e inventario (H1) — ✅ completada

**Objetivo.** Dado un directorio, comprobar que es un proyecto Expo y listar los ficheros a analizar.

**Criterios de aceptación.**
- Error claro (código de salida 2) si no hay `package.json` o no depende de `expo`.
- Detecta el fichero de configuración (`app.json`, `app.config.js`, `app.config.ts`) y si el proyecto es *managed* o *prebuild*.
- El inventario ignora `node_modules`, `.git`, carpetas de build y `ios/Pods`, **no sigue enlaces simbólicos** y omite ficheros de más de 1 MB.
- Clasifica cada fichero como `source`, `config`, `env`, `native` u `other`.

**Casos de prueba.** Directorio vacío; `package.json` sin expo; proyecto con `node_modules`; enlace simbólico que apunta fuera del proyecto.

## T04 · Parseo AST (H1) — ✅ completada

**Objetivo.** Parsear JS/JSX/TS/TSX con `@babel/parser` sin detener el análisis si un fichero falla.

**Criterios de aceptación.**
- Plugins según extensión (`typescript`, `jsx`).
- Un fichero con error de sintaxis se registra como aviso y el resto se sigue analizando.
- Parsea sin errores la plantilla oficial de `create-expo-app` y las fixtures.

## T05 · Lectura estática de la configuración (H1) — ✅ completada

**Objetivo.** Obtener el objeto `expo` de `app.json` o de `app.config.js/ts` **sin ejecutar** el fichero, con el número de línea de cada clave.

**Criterios de aceptación.**
- Soporta `export default {…}`, `export default ({ config }) => ({…})`, `module.exports = …`, `satisfies`/`as ExpoConfig` y referencias a una constante.
- Los valores no literales (p. ej. `process.env.X`) se marcan como desconocidos, no se evalúan.

## T06 · Modelo de hallazgos y catálogo de reglas (H2) — ✅ completada

**Objetivo.** Tipo `Finding` común, catálogo de reglas con severidad, control MASVS y categoría OWASP Mobile Top 10 2024, y `data/masvs.json`.

**Criterios de aceptación.** Toda regla apunta a un control MASVS y a una categoría OWASP que existen en el catálogo local (test automático).

## T07 · Detectores deterministas (H2) — 🟡 en curso

**Objetivo.** Cinco detectores: secretos, almacenamiento, dependencias, WebView/deep links y configuración nativa.

**Criterios de aceptación.**
- Detecta **todas** las vulnerabilidades de `vulnerable-app/expected.json`.
- `safe-app` no genera hallazgos de severidad media o superior.
- Los secretos aparecen siempre enmascarados.
- `npm audit` se ejecuta sin shell y con `--package-lock-only` (no instala ni ejecuta nada del proyecto).

**Pendiente dentro de T07.** Respaldo con la API de OSV cuando no hay `package-lock.json` (yarn/pnpm); paquetes abandonados o sin licencia; seguimiento de datos entre ficheros en deep links.

## T08 · CLI `expoguard scan` (H2, adelantado de H4) — ✅ completada (versión mínima)

**Objetivo.** Comando que ejecuta el análisis y muestra los hallazgos por consola o en JSON.

**Criterios de aceptación.** Opciones `--json`, `--output`, `--skip-deps`, `--fail-on`; código de salida 0 sin hallazgos por encima del umbral, 1 con hallazgos, 2 si hay error.

---

## Pendientes (H3–H5)

- T09 · Cliente OpenRouter y saneador de secretos (H3).
- T10 · Prompts de triaje y redacción, validación con Zod, caché por hash (H3).
- T11 · Comparación de modelos sobre las fixtures (H3).
- T12 · Informe Markdown + JSON definitivo (H4).
- T13 · Fixtures de inyección de prompts y pruebas de fuga (H4).
- T14 · Métricas de precisión con y sin IA, README final y memoria (H5).
