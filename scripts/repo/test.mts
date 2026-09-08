import { readdirSync } from 'node:fs'
import path from 'node:path'
import process from 'node:process'
import { spawn } from '@socketsecurity/lib-stable/process/spawn/child'
import { normalizePath } from '@socketsecurity/lib-stable/paths/normalize'
import { REPO_ROOT } from '../fleet/paths.mts'
import { coverBudgetMs } from '../fleet/constants/test-budget.mts'
import { isMainModule } from '../fleet/process/is-main-module.mts'
import { runMain } from '../fleet/process/run-main.mts'

export function collectScannerTests(root: string): string[] {
  const files: string[] = []
  function visit(directory: string): void {
    for (const entry of readdirSync(path.join(root, directory), {
      withFileTypes: true,
    })) {
      const relative = path.join(directory, entry.name)
      if (entry.isDirectory()) {
        if (!['fleet', 'fixtures', '_shared'].includes(entry.name)) {
          visit(relative)
        }
      } else if (entry.isFile() && entry.name.endsWith('.test.mts')) {
        files.push(relative)
      }
    }
  }
  visit('test')
  return files.toSorted()
}

function matchesScannerTest(file: string, selector: string): boolean {
  const candidate = normalizePath(file)
  const normalized = normalizePath(selector)
  const scope = normalized.startsWith('./') ? normalized.slice(2) : normalized
  return candidate.includes(scope) || scope.endsWith(`/${candidate}`)
}

export function scannerTestArgs(
  argv: readonly string[],
  files: readonly string[],
  options?: { fuzz?: boolean | undefined } | undefined,
): string[] {
  const opts = { __proto__: null, ...options } as NonNullable<typeof options>
  const args = argv.filter(arg => arg !== '--all')
  const valuedOptions = new Set([
    '--coverage-dir',
    '--coverage-reporter',
    '--max-concurrency',
    '--reporter',
    '--reporter-outfile',
    '--rerun-each',
    '--seed',
    '--shard',
    '--test-name-pattern',
    '--timeout',
    '-t',
  ])
  const flags: string[] = []
  const selectors: string[] = []
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index]!
    if (arg.startsWith('-')) {
      flags.push(arg)
      if (valuedOptions.has(arg)) {
        const value = args[++index]
        if (value === undefined) {
          throw new Error(`Missing value for ${arg}.`)
        }
        flags.push(value)
      }
    } else {
      selectors.push(arg)
    }
  }
  for (let index = 0, { length } = selectors; index < length; index += 1) {
    const selector = selectors[index]!
    if (!files.some(file => matchesScannerTest(file, selector))) {
      throw new Error(`No scanner tests match ${selector}.`)
    }
  }
  const selected = files.filter(file => {
    if (opts.fuzz === true && !file.endsWith('.fuzz.test.mts')) {
      return false
    }
    if (selectors.length === 0) {
      return opts.fuzz === true || !file.endsWith('.fuzz.test.mts')
    }
    return selectors.some(selector => matchesScannerTest(file, selector))
  })
  if (selected.length === 0) {
    throw new Error('No scanner tests match the requested test scope.')
  }
  return ['test', ...flags, ...selected]
}

export async function main(): Promise<number> {
  const args = scannerTestArgs(
    process.argv.slice(2),
    collectScannerTests(REPO_ROOT),
    {
      fuzz: process.env['FLEET_TEST_FUZZ'] === '1',
    },
  )
  const result = await spawn('bun', args, {
    cwd: REPO_ROOT,
    stdio: 'inherit',
    timeout: coverBudgetMs(),
    killSignal: 'SIGKILL',
    throws: false,
  })
  return result.code ?? 1
}

if (isMainModule(import.meta.url)) {
  runMain(main, {
    describe:
      'runs the scanner Bun tests with explicit offline and fuzz scopes',
    help: 'Usage: pnpm test [--all | <test paths and Bun options>]\nSet FLEET_TEST_FUZZ=1 to select the scanner fuzz harness. Live tests require SOCKET_SCANNER_LIVE_TESTS=1.',
  })
}
