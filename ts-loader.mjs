// Resolve `.js` source imports to sibling `.ts` files when both are present.
// Used only by `npm test` so that .ts source can run via --experimental-transform-types.
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

export async function resolve(specifier, context, nextResolve) {
  if (specifier.endsWith('.js') && (specifier.startsWith('./') || specifier.startsWith('../'))) {
    try {
      const jsUrl = new URL(specifier, context.parentURL);
      const tsFilePath = fileURLToPath(jsUrl).replace(/\.js$/, '.ts');
      if (existsSync(tsFilePath)) {
        return nextResolve(specifier.replace(/\.js$/, '.ts'), context);
      }
    } catch { /* fall through */ }
  }
  return nextResolve(specifier, context);
}
