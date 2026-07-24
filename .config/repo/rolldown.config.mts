/**
 * @file Rolldown configuration for the Bun security scanner bundle. One ESM
 *   entry (the scanner module has a top-level await in its token bootstrap, so
 *   CJS output is off the table); every runtime dep — socket-lib, the Socket
 *   SDK, and packageurl-js — is vendored into the bundle so the published
 *   plugin carries zero runtime dependencies, the same dist shape
 *   socket-packageurl-js and socket-sdk-js publish. Only the `bun` module and
 *   node builtins stay external.
 */

import Module from 'node:module'
import path from 'node:path'
import process from 'node:process'

import { createLibStubPlugin } from './rolldown/lib-stub.mts'
import { REPO_ROOT } from '../../scripts/fleet/paths.mts'

import type { OutputOptions, Plugin, RolldownOptions } from 'rolldown'

const rootPath = REPO_ROOT
const srcPath = path.join(rootPath, 'src')
const distPath = path.join(rootPath, 'dist')

// `json/parse` eagerly requires `schema/validate`, which eagerly requires
// @sinclair/typebox/value (~335KB rendered) — but `validateSchema` only runs
// when a caller passes a schema to `parseJsonSafe`, and nothing on this
// scanner's import surface (logger/default, secrets/socket-api-token,
// env/xdg, plus the self-contained sdk + packageurl-js bundles) ever does.
// Verified reachable-from-THIS-repo only through that eager require chain;
// the built bundle is smoke-tested in every mode by test/dist.test.ts.
const LIB_STUB_PATTERN = /@socketsecurity\/lib\/dist\/schema\/validate\.js$/

/**
 * Rewrite bare Node builtin imports to the `node:` protocol + externalize
 * them, so a vendored dependency's `require('fs')` doesn't leak into the
 * bundle. Same shape as socket-sdk-js's resolveId hook; `bun` rides along
 * because the scanner entry imports the Bun runtime module, which only exists
 * inside Bun itself.
 */
export function createNodeProtocolPlugin(): Plugin {
  const builtins = new Set(
    Module.builtinModules.filter(m => !m.startsWith('node:')),
  )
  return {
    name: 'node-protocol',
    resolveId(source) {
      if (builtins.has(source)) {
        return { id: `node:${source}`, external: true }
      }
      if (source === 'bun' || source.startsWith('bun:')) {
        return { id: source, external: true }
      }
      return undefined
    },
  }
}

export const buildConfig: RolldownOptions & { output: OutputOptions } = {
  input: {
    index: path.join(srcPath, 'index.ts'),
  },
  output: {
    banner: '/* Socket Security Scanner for Bun - Built with rolldown */',
    codeSplitting: false,
    dir: distPath,
    entryFileNames: '[name].js',
    format: 'esm',
    minify: false,
    sourcemap: false,
  },
  platform: 'node',
  plugins: [
    createLibStubPlugin({ stubPattern: LIB_STUB_PATTERN }),
    createNodeProtocolPlugin(),
  ],
  transform: {
    define: {
      'process.env.NODE_ENV': JSON.stringify(
        process.env['NODE_ENV'] || 'production',
      ),
    },
  },
  treeshake: true,
}

export const configs: ReadonlyArray<
  RolldownOptions & { output: OutputOptions }
> = [buildConfig]
