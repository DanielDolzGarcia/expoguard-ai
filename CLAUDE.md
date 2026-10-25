# CLAUDE.md — Convenciones del proyecto ExpoGuard AI

Este fichero lo lee el agente (Claude Code) al empezar cada tarea. Recoge las normas que debe seguir.

## Qué es el proyecto

CLI en TypeScript (Node.js 24) que audita el código fuente de apps React Native con Expo.
Primero detecta con reglas deterministas y después un LLM vía OpenRouter hace el triaje (pendiente).

## Estructura

- `src/cli.ts` — comando `expoguard scan` (Commander). Solo parseo de argumentos y salida.
- `src/ingest/` — validación del proyecto Expo, inventario de ficheros, parseo AST, lectura de app.json/app.config.
- `src/detectors/` — un fichero por familia. Cada detector exporta un objeto `Detector` y **no** escribe en disco ni en consola.
- `src/rules.ts` — catálogo de reglas (id, severidad, MASVS, OWASP Mobile Top 10).
- `src/ai/` — (pendiente) cliente OpenRouter, saneador y prompts.
- `src/report/` — (pendiente) informes Markdown y JSON.
- `data/masvs.json` — catálogo local de controles MASVS y categorías OWASP.
- `tests/` — tests Vitest. `tests/fixtures/` contiene proyectos Expo de prueba con vulnerabilidades conocidas.

## Normas obligatorias

1. **No añadir dependencias** sin aprobación explícita del alumno. Antes, proponer y justificar.
2. **Toda funcionalidad nueva lleva tests** en `tests/`. Cobertura mínima global del 70 %.
3. `npm run ci` (typecheck + lint + tests con cobertura + build) debe pasar antes de dar una tarea por terminada.
4. TypeScript en modo `strict`. Prohibido `any` salvo justificación en comentario.
5. La herramienta **nunca ejecuta** código del proyecto analizado ni lo modifica. Solo lo lee.
6. Los procesos externos (`npm audit`) se lanzan con `execFile` y argumentos en array, nunca con `shell: true`.
7. Los valores de los secretos **nunca** aparecen completos en hallazgos, logs ni informes: siempre enmascarados.
8. Las claves de las fixtures son falsas y deben contener la palabra `FAKE` o `EXAMPLE` cuando el formato lo permita.
9. Nada de credenciales reales en el repositorio. La clave de OpenRouter se leerá de la variable `OPENROUTER_API_KEY`.

## Estilo

- Código y nombres en inglés; mensajes al usuario, comentarios de alto nivel y documentación en español.
- Funciones pequeñas y puras cuando sea posible; los detectores reciben el contexto ya parseado.
- Commits en español, con el trailer `AI-Assisted: Claude Code` cuando el código lo haya generado el agente.

## Flujo de trabajo

1. Cada tarea se abre como **issue** en GitHub, con su especificación de `docs/TAREAS.md` (objetivo, criterios de aceptación y casos de prueba).
2. Se trabaja en una rama `feature/<número de issue>-<nombre>`, por ejemplo `feature/2-ingesta`.
3. Se abre una **pull request** a `main` que cierra la issue (`Closes #n`). Se revisa el diff y se integra cuando la CI está en verde.
4. Después del merge la rama se conserva, para que quede el trabajo de cada issue.
