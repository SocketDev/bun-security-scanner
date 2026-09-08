import crypto from 'node:crypto'
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs'
import path from 'node:path'
import process from 'node:process'
import { spawnSync } from '@socketsecurity/lib-stable/process/spawn/child'
import { getDefaultLogger } from '@socketsecurity/lib-stable/logger/default'
import { scannerFuzzOptions } from './fuzz-options.mts'
import type { ScannerFuzzParameters } from './fuzz-options.mts'
import { REPO_CACHE_DIR, REPO_ROOT } from '../fleet/paths.mts'
import { isMainModule } from '../fleet/process/is-main-module.mts'
import { runMain } from '../fleet/process/run-main.mts'
import type { ScriptMeta } from '../fleet/process/run-main.mts'

const logger = getDefaultLogger()

export function recordFuzzFailure(config: {
  directory: string
  options: ScannerFuzzParameters
  code: number
  stdout: string
  stderr: string
}): string {
  mkdirSync(config.directory, { recursive: true })
  const directory = mkdtempSync(path.join(config.directory, 'run-'))
  writeFileSync(
    path.join(directory, 'result.json'),
    JSON.stringify(
      {
        ...config.options,
        exitCode: config.code,
        harness: 'test/scanner-factory.fuzz.test.mts',
        replay: `SCANNER_FUZZ_SEED=${config.options.seed} SCANNER_FUZZ_RUNS=${config.options.numRuns} pnpm run test:fuzz`,
      },
      undefined,
      2,
    ) + '\n',
  )
  writeFileSync(path.join(directory, 'stdout.log'), config.stdout)
  writeFileSync(path.join(directory, 'stderr.log'), config.stderr)
  return directory
}

export function main(): void {
  const options = scannerFuzzOptions({
    ...process.env,
    SCANNER_FUZZ_SEED:
      process.env['SCANNER_FUZZ_SEED'] ??
      String(crypto.randomInt(2_147_483_648)),
    SCANNER_FUZZ_RUNS: process.env['SCANNER_FUZZ_RUNS'] ?? '1000',
  })
  const env = {
    ...process.env,
    SCANNER_FUZZ_SEED: String(options.seed),
    SCANNER_FUZZ_RUNS: String(options.numRuns),
    DO_NOT_TRACK: '1',
    DISABLE_TELEMETRY: '1',
  }
  logger.log(`Scanner fuzz seed=${options.seed} runs=${options.numRuns}`)
  const result = spawnSync(
    'bun',
    ['test', 'test/scanner-factory.fuzz.test.mts', '--timeout', '60000'],
    {
      cwd: REPO_ROOT,
      env,
      encoding: 'utf8',
      stdio: 'pipe',
      timeout: 65_000,
      killSignal: 'SIGKILL',
    },
  )
  const stderr = [result.stderr, result.error?.message]
    .filter(Boolean)
    .join('\n')
  logger.log(result.stdout ?? '')
  logger.log(stderr)
  const code = result.status ?? 1
  if (code !== 0) {
    const directory = recordFuzzFailure({
      directory: path.join(REPO_CACHE_DIR, 'fuzz'),
      options,
      code,
      stdout: result.stdout ?? '',
      stderr,
    })
    logger.error(
      `Fuzz job failed. Evidence: ${directory}. Replay seed ${options.seed} with SCANNER_FUZZ_SEED and pnpm run test:fuzz.`,
    )
  }
  process.exitCode = code
}

const SCRIPT_META: ScriptMeta = {
  describe:
    'run seeded scanner properties with Bun and save failure logs plus replay settings',
  help: 'Usage: pnpm run test:fuzz\n\nSCANNER_FUZZ_SEED sets a signed 32-bit seed (default: random, printed before execution).\nSCANNER_FUZZ_RUNS sets cases per property (default 1000; maximum 100000).\nFailure evidence is stored in .cache/repo/fuzz/run-*.',
}

if (isMainModule(import.meta.url)) {
  runMain(main, SCRIPT_META)
}
