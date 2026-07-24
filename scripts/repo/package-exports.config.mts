/**
 * @file Exports config for @socketsecurity/bun-security-scanner. The package
 *   keeps a hand-curated single-entry surface (`.` — the Bun security scanner
 *   plugin module), so the generator is not used to synthesize per-leaf
 *   exports. The `ignore` globs cover the per-module `.d.ts` declarations tsc
 *   emits alongside the bundled entry point: they are reachable from
 *   `dist/index.d.ts` via relative type imports (so they must ship) but are
 *   not export entries themselves.
 */

import type { ExportsConfig } from '../fleet/make-package-exports.mts'
import { REPO_ROOT } from '../fleet/paths.mts'

export const packageDir: string = REPO_ROOT

export const config: ExportsConfig = {
  ignore: ['dist/*.d.ts', 'dist/modes/*.d.ts'],
  outDir: 'dist',
}
