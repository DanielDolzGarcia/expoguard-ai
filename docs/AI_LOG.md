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
Para dudas concretas y textos se usa un nivel menor (1 o 2).

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
