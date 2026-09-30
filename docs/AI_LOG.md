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
