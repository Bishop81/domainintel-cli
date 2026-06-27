/**
 * Builds the standalone, self-contained DomainIntel CLI bundle.
 *
 * Bundles cli.mjs and the entire analyzer graph (plus whois) into a single file
 * with no runtime dependencies, so it can be published to npm and run with
 * `npx @domainintel/cli`. The filesystem-writing logger is swapped for a
 * stderr-only stub.
 *
 * Run from the repo root: `node build.mjs` (or `npm run build`).
 */
import { build } from 'esbuild';
import { fileURLToPath } from 'url';
import path from 'path';

const here = path.dirname(fileURLToPath(import.meta.url));
const stub = path.join(here, 'stub-logger.js');

// Redirect any import of lib/utils/errorLogger to the stderr-only stub.
const swapLogger = {
  name: 'swap-logger',
  setup(b) {
    b.onResolve({ filter: /utils[\\/]errorLogger(\.js)?$/ }, () => ({ path: stub }));
  }
};

await build({
  entryPoints: [path.join(here, 'cli.mjs')],
  outfile: path.join(here, 'dist', 'cli.mjs'),
  bundle: true,
  platform: 'node',
  format: 'esm',
  target: 'node18',
  // Shebang + a real `require` so bundled CJS deps (e.g. whois) can load Node
  // built-ins like 'net' at runtime under ESM output.
  banner: {
    js: [
      '#!/usr/bin/env node',
      "import { createRequire as __cr } from 'module';",
      'const require = __cr(import.meta.url);'
    ].join('\n')
  },
  plugins: [swapLogger],
  logLevel: 'info'
});

console.error('Built dist/cli.mjs');
