import { parse, type ParserPlugin } from '@babel/parser';
import type { File as BabelFile } from '@babel/types';

export type ParseOutcome = { ok: true; ast: BabelFile } | { ok: false; error: string };

function pluginsFor(filename: string): ParserPlugin[] {
  if (/\.[cm]?tsx$/i.test(filename)) return ['typescript', 'jsx'];
  if (/\.[cm]?ts$/i.test(filename)) return ['typescript'];
  // En React Native los .js suelen llevar JSX.
  return ['jsx'];
}

/** Parsea un fichero JS/TS. Nunca lanza: devuelve el error para registrarlo como aviso. */
export function parseSource(code: string, filename: string): ParseOutcome {
  try {
    const ast = parse(code, {
      sourceType: 'unambiguous',
      sourceFilename: filename,
      plugins: pluginsFor(filename),
      errorRecovery: true,
    });
    const recovered = (ast as BabelFile & { errors?: Array<{ message: string }> }).errors ?? [];
    if (recovered.length > 0) {
      return { ok: false, error: recovered[0]!.message };
    }
    return { ok: true, ast };
  } catch (err) {
    return { ok: false, error: (err as Error).message };
  }
}
