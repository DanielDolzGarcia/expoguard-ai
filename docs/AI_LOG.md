# Registro de uso de IA (AI_LOG)

Registro de cada uso de IA en el desarrollo: fecha, herramienta/modelo, especificación, ficheros afectados,
grado de automatización y qué se aceptó, se modificó o se descartó.

Escala de automatización usada:

| Nivel | Significado |
|---|---|
| 0 | Sin IA |
| 1 | Asistencia puntual (preguntas, explicaciones, revisión de un fragmento) |
| 2 | Generación de código bajo demanda, integrado a mano |
| 3 | Agente que genera código y tests de una tarea completa; revisión humana del diff |
| 4 | Desarrollo agéntico completo (el agente planifica, implementa, prueba y corrige en bucle) |

Como se planteó en la primera entrega, las tareas de código se hacen con nivel 3: el alumno escribe la issue,
Claude Code genera el código y los tests en la rama `feature/<issue>` y el alumno revisa el diff antes de integrarlo.
Para dudas concretas y textos se usa un nivel menor (1 o 2). Lo que se hizo sin IA está al final del registro.

---

## Entradas

### 2026-09-30 · Preparación del repositorio (issue #1)
- **Herramienta:** Claude Code (CLI), modelo Claude Opus 5.5.
- **Especificación:** issue #1 (T01 y T02 de `docs/TAREAS.md`), con la lista de vulnerabilidades que debía tener cada app de prueba.
- **Ficheros:** `package.json`, `tsconfig*.json`, `eslint.config.js`, `vitest.config.ts`, `.gitignore`, `.github/workflows/ci.yml`, `tests/fixtures/**`.
- **Automatización:** nivel 3.
- **Resultado:** aceptado con cambios.
  - npm instaló versiones mayores más nuevas de lo previsto (Babel 8, TypeScript 6, Vitest 5, ESLint 10). Se eliminó `@types/babel__traverse` porque Babel 8 ya incluye sus tipos.
  - La CI de la pull request fallaba porque todavía no había código ni tests (`tsc` sin ficheros de entrada y Vitest sin tests). Se pidió al agente un `src/cli.ts` mínimo y un test que comprueba que las apps de prueba están bien formadas. En las issues #2 y #3 se sustituyen por las versiones reales.
  - `data/masvs.json`: la lista de controles MASVS y categorías del Mobile Top 10 la preparó el alumno a partir de la web de OWASP; el agente solo la pasó a JSON.

### 2026-10-01 · Error al subir el repositorio a GitHub
- **Herramienta:** Claude Code, Claude Opus 5.5.
- **Automatización:** nivel 1. GitHub rechazó el primer push con «refusing to allow an OAuth App to create or update workflow `.github/workflows/ci.yml` without `workflow` scope». Se preguntó qué significaba; la solución (`gh auth refresh -s workflow`) la aplicó el alumno.

### 2026-10-10 · Ingesta y parseo (issue #2)
- **Herramienta:** Claude Code, Claude Opus 5.5.
- **Especificación:** issue #2 (T03, T04 y T05).
- **Ficheros:** `src/ingest/*`, `src/ast.ts`, `src/scanner.ts`, `src/cli.ts`, `tests/ingest/*`, `tests/helpers.ts`.
- **Automatización:** nivel 3.
- **Validación:** `tsc --strict` (sin errores a la primera), 52 tests (uno de ellos parsea enteras las tres apps de prueba), ESLint y escaneo de la plantilla oficial de `create-expo-app` (Expo SDK 58, 18/18 ficheros parseados).
- **Errores detectados en el código generado y correcciones:**
  - La CI de la pull request falló por cobertura de ramas (58 % frente al 70 % exigido): el agente había adelantado en `src/ast.ts` utilidades que solo usan los detectores y que aún no tenían tests. Se dejaron para la issue de los detectores y la cobertura de ramas subió al 80 %.
  - ESLint (`no-unused-vars`): `_root` y `_deps` en una desestructuración. La configuración solo ignoraba argumentos con `_` → se añadió `ignoreRestSiblings`.
  - ESLint (`security/detect-object-injection`): **prototype pollution real** en el evaluador estático de `app.json`: `out[name] = …` con claves que vienen del proyecto analizado. Un `"__proto__"` cambiaba el prototipo del objeto y podía ocultar o falsear valores de configuración. → Objetos con `Object.create(null)`, `getPath` con `Object.hasOwn` y test de regresión.
  - ESLint (`security/detect-unsafe-regex`): regex `^\.env(?:\..+)?$` → sustituida por comparaciones de cadenas.
  - 25 avisos `detect-non-literal-fs-filename` / `detect-object-injection` revisados uno a uno: falsos positivos (la herramienta tiene que leer rutas elegidas por el usuario). Se justifican en línea o se desactivan solo en `tests/`.

### 2026-10-21 · Detectores deterministas (issue #3)
- **Herramienta:** Claude Code, Claude Opus 5.5.
- **Especificación:** issue #3 (T06, T07 y T08). Los controles MASVS y las categorías OWASP de cada regla los asignó el alumno en la issue.
- **Ficheros:** `src/rules.ts`, `src/detectors/*`, `tests/detectors/*`, `tests/e2e/*`, `tests/rules.test.ts`.
- **Automatización:** nivel 3.
- **Validación:** 139 tests (cobertura 96,4 % de líneas y 83 % de ramas), e2e contra las tres fixtures, `npm audit` real sobre `vulnerable-app` y prueba de mutación hecha a mano por el alumno (7 errores ya corregidos reintroducidos, los 7 detectados).
- **Errores detectados en el código generado y correcciones:**
  - `globMatch` (patrones de `.gitignore`): la primera versión tenía las ramas en mal orden y retrocedía antes de casar una `/` literal. Detectado al revisar el diff → reescrito con el algoritmo estándar.
  - `ref.current?.injectJavaScript(...)` es un `OptionalCallExpression` en Babel y el visitor solo miraba `CallExpression`: el caso de la fixture no se habría detectado. Detectado en revisión → visitor `CallExpression|OptionalCallExpression` y test con `?.`.
  - `tsc` encontró dos comparaciones imposibles (código muerto) en `native.ts` y `webview.ts`.
  - Fixture: la clave falsa de Google tenía 33 caracteres tras `AIza` y el formato real exige 35, así que la regla nunca la habría encontrado. Corregida la fixture, no la regla.
  - `expected.json`: el agente puso axios y lodash en las líneas 7 y 11 de `package.json`, pero están en la 8 y la 13. La herramienta tenía razón y la especificación estaba mal.
  - Dependencias transitivas «introducidas por ?» (`image-size`): `npm audit` solo enlaza en `effects` los dependientes que también son vulnerables. → Grafo inverso desde `package-lock.json`.
  - Dos atajos de tipado poco limpios (`as never` y un cast de `getBindingIdentifiers`) sustituidos por código correcto.
- **Decisiones de seguridad añadidas durante la revisión:** cuantificadores acotados en las regex de secretos (con test de ReDoS sobre una línea de 400 KB) y `--registry` forzado en `npm audit`.

### 2026-10-22 · Borrador del README
- **Herramienta:** Claude Code, Claude Opus 5.5.
- **Ficheros:** `README.md`.
- **Automatización:** nivel 2. Se pidió un borrador de las secciones de instalación y uso a partir de la salida de `expoguard scan --help`. El alumno lo integró a mano: quitó una opción `--fix` que no existe, rehízo el ejemplo de salida con una ejecución real y escribió la parte de seguridad.

### 2026-10-23 · Versión de las actions de la CI (issue #4)
- **Herramienta:** Claude Code, Claude Opus 5.5.
- **Automatización:** nivel 1. La CI avisaba de que `actions/checkout@v4` y `actions/setup-node@v4` usan Node 20, que está obsoleto. Se preguntó qué versión usa Node 24; el cambio a v7 en `ci.yml` lo hizo el alumno.
- **Resultado:** la siguiente ejecución salió en verde sin el aviso.

### 2026-10-23 · Dudas sobre OSV y los lockfiles (antes de la issue #6)
- **Herramienta:** Claude Code, Claude Opus 5.5.
- **Automatización:** nivel 1. Preguntas sobre el endpoint `querybatch` de OSV y las diferencias entre `yarn.lock` v1 y berry y entre las versiones de `pnpm-lock.yaml`. Las respuestas se comprobaron con la documentación oficial y con lockfiles reales generados por el alumno; una de ellas (que pnpm v9 sigue usando `/` delante del nombre) era incorrecta.

### 2026-10-24 · Dependencias: OSV, paquetes obsoletos y licencias (issue #6)
- **Herramienta:** Claude Code, Claude Opus 5.5.
- **Especificación:** issue #6 (pendientes de T07). Incluye lo que investigó antes el alumno: la API de OSV (`querybatch`) y los formatos de `yarn.lock` (v1 y berry) y `pnpm-lock.yaml` (v5, v6 y v9).
- **Ficheros:** `src/ingest/lockfiles.ts`, `src/detectors/osv.ts`, `src/detectors/dependencies.ts`, `src/rules.ts` (31 reglas), `src/types.ts`, `src/scanner.ts`, `tests/ingest/lockfiles.test.ts`, `tests/detectors/osv.test.ts`, `tests/detectors/dependencies.test.ts`, `tests/e2e/fixtures.test.ts`, `tests/fixtures/yarn-app/`, `tests/data/osv-yarn-app.json`.
- **Automatización:** nivel 3.
- **Validación:** 160 tests (cobertura 96,8 % de líneas); respuestas reales de OSV grabadas para `yarn-app`; prueba con la plantilla oficial de Expo SDK 58 usando un `pnpm-lock.yaml` real (539 paquetes, generado con `pnpm install --lockfile-only --ignore-scripts`) y comparación con `npm audit` sobre un `package-lock.json` real de la misma plantilla: **los dos encuentran los mismos paquetes** (node-forge y zod).
- **Errores detectados y correcciones:**
  - **Parser de yarn berry:** la cabecera `"axios@npm:0.21.1, axios@npm:^0.21.0":` va entrecomillada entera; el código separaba por comas antes de quitar las comillas y el nombre quedaba como `"axios`. Lo detectó el test de berry → se quitan las comillas de cada trozo.
  - **Diseño:** la primera versión leía el lockfile desde el inventario, que omite ficheros de más de 1 MB, y un `yarn.lock` real suele superarlo. Detectado al revisar el diff → lectura directa con `lstat` (sin seguir enlaces simbólicos) y tope de 50 MB.
  - **ESLint de seguridad:** una regex con cuantificador anidado (`detect-unsafe-regex`) para las claves de pnpm v5 → sustituida por `split('/')`; 6 accesos por índice → reescritos con `entries()` y `.at()` en lugar de justificarlos.
  - **Licencias:** el lockfile de `vulnerable-app` tiene 2 paquetes sin licencia. El alumno consultó el registro de npm y sí la declaran, con el campo antiguo `licenses` que npm no copia al lockfile. → La regla no trata la ausencia como problema: un único aviso informativo.
  - **Comportamiento ante fallos:** antes, si `npm audit` fallaba se perdía todo el detector. Ahora se avisa con `ctx.warn` y se conservan los hallazgos calculados sin red.
  - Un test tenía mal contada una línea del `yarn.lock` (42 en vez de 40); la herramienta tenía razón.
- **Cambio de alcance:** el seguimiento de deep links entre ficheros pasa a líneas futuras (requiere análisis entre módulos).

### 2026-10-25 · Memoria de la segunda entrega (issue #7)
- **Herramienta:** Claude Code, Claude Opus 5.5.
- **Automatización:** nivel 1. La memoria la redacta el alumno; la IA revisa la redacción y comprueba que las cifras coinciden con la salida de la herramienta y de la CI.

---

## Trabajo sin IA (nivel 0)

- **Especificaciones:** las issues #1 a #7, `docs/TAREAS.md`, `CLAUDE.md` y este registro.
- **Datos de partida:** la lista de vulnerabilidades de cada app de prueba, a partir del catálogo de la primera entrega, y la lista de controles de OWASP MASVS y categorías del Mobile Top 10.
- **GitHub:** creación del repositorio e inicio de sesión con `gh`. También el `git add -f` del `.env` de `safe-app`, que su propio `.gitignore` excluía.
- **Issue #5:** «Se solicitan 1 permisos peligrosos» al analizar `safe-app`. Concordancia corregida y comprobación añadida al test.
- **Investigación:** documentación de OSV y de los lockfiles (con las dudas del 23/10) y licencias en el registro de npm (issue #6).
- **Prueba de mutación:** reintroducir a propósito errores ya corregidos y comprobar que algún test falla. 7/7 con los detectores y 9/9 tras la issue #6.
- **Revisión** del diff de cada pull request antes de integrarla.
