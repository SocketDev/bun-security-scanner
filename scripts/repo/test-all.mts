import process from 'node:process'
import { globSync } from 'node:fs'
import path from 'node:path'
import { spawn } from '@socketsecurity/lib-stable/process/spawn/child'
import { normalizePath } from '@socketsecurity/lib-stable/paths/normalize'
import { REPO_ROOT } from '../fleet/paths.mts'
import { coverBudgetMs } from '../fleet/constants/test-budget.mts'
import { isMainModule } from '../fleet/process/is-main-module.mts'
import { runMain } from '../fleet/process/main/run.mts'
import type { ScriptMeta } from '../fleet/process/main/run.mts'
import { getScriptArgs, scriptStdio } from '../fleet/process/script-output.mts'
import { collectScannerTests } from './test.mts'
import { repoNodeTestExcludeGlobs } from '../../.config/repo/vitest.settings.mts'

export interface TestCommand {
  readonly args: readonly string[]
  readonly entry: string
}

export function aggregateExitCode(exitCodes: readonly number[]): number {
  return exitCodes.find(code => code !== 0) ?? 0
}

function modePlan(argv: readonly string[]): TestCommand[] | undefined {
  const modes = argv.filter(
    arg => arg === '--all' || arg === '--ci' || arg === '--staged',
  )
  if (modes.length > 1 || (modes.length === 1 && argv.length !== 1)) {
    throw new Error('Use --ci, --all or --staged without other test arguments.')
  }
  if (modes[0] === '--staged') {
    return [
      { args: ['--staged'], entry: 'scripts/fleet/test.mts' },
      { args: ['--all'], entry: 'scripts/repo/test.mts' },
    ]
  }
  if (modes[0] === '--ci') {
    return [
      { args: ['--ci'], entry: 'scripts/fleet/test.mts' },
      { args: ['--all'], entry: 'scripts/repo/test.mts' },
    ]
  }
  if (modes[0] === '--all' || argv.length === 0) {
    const args = modes.length === 0 ? [] : ['--all']
    return [
      { args, entry: 'scripts/fleet/test.mts' },
      { args, entry: 'scripts/repo/test.mts' },
    ]
  }
  return undefined
}

function matchingFiles(files: readonly string[], selector: string): string[] {
  const candidate = normalizePath(selector)
  return files.filter(file => {
    const normalized = normalizePath(file)
    return (
      normalized === candidate ||
      normalized.startsWith(`${candidate}/`) ||
      normalized.endsWith(`/${candidate}`)
    )
  })
}

function explicitPlan(
  argv: readonly string[],
  scannerFiles: readonly string[],
  vitestFiles: readonly string[],
): TestCommand[] {
  const scannerSelectors: string[] = []
  const vitestSelectors: string[] = []
  const bunOptions: string[] = []
  const valueOptions = new Set([
    '--reporter',
    '--reporter-outfile',
    '--test-name-pattern',
    '--timeout',
  ])
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index]!
    if (arg.startsWith('-')) {
      if (!valueOptions.has(arg)) {
        throw new Error(`Unsupported aggregate test option ${arg}.`)
      }
      const value = argv[++index]
      if (value === undefined) {
        throw new Error(`Missing value for ${arg}.`)
      }
      bunOptions.push(arg, value)
      continue
    }
    const selector = normalizePath(arg)
    const normalized = path.isAbsolute(selector)
      ? normalizePath(path.relative(REPO_ROOT, selector))
      : selector.startsWith('./')
        ? selector.slice(2)
        : selector
    const bun = matchingFiles(scannerFiles, normalized)
    const fleet = matchingFiles(vitestFiles, normalized)
    if (bun.length === 0 && fleet.length === 0) {
      throw new Error(`No test owner matches ${arg}.`)
    }
    scannerSelectors.push(...bun)
    vitestSelectors.push(...fleet)
  }
  if (
    vitestSelectors.length > 0 &&
    scannerSelectors.length === 0 &&
    bunOptions.length > 0
  ) {
    throw new Error('Bun-only options cannot be used with Vitest selectors.')
  }
  const plan: TestCommand[] = []
  if (vitestSelectors.length > 0) {
    plan.push({
      args: [...new Set(vitestSelectors)],
      entry: 'scripts/fleet/test.mts',
    })
  }
  if (scannerSelectors.length > 0) {
    plan.push({
      args: [...bunOptions, ...new Set(scannerSelectors)],
      entry: 'scripts/repo/test.mts',
    })
  }
  return plan
}

export function buildTestPlan(
  argv: readonly string[],
  scannerFiles: readonly string[],
  vitestFiles: readonly string[],
  ownershipGlobs: readonly string[],
): TestCommand[] {
  if (ownershipGlobs.length === 0) {
    throw new Error(
      'Bun test ownership is missing from vitest.nodeTestExclude.',
    )
  }
  const planned = modePlan(argv)
  if (planned !== undefined) {
    return planned
  }
  const plan = explicitPlan(argv, scannerFiles, vitestFiles)
  if (plan.length === 0) {
    throw new Error('No tests selected.')
  }
  return plan
}

export async function main(): Promise<number> {
  const ownership = repoNodeTestExcludeGlobs()
  const vitestFiles = globSync('test/**/*.test.{js,ts,mjs,mts,cjs}', {
    cwd: REPO_ROOT,
  }).filter(file => {
    const normalized = normalizePath(file)
    return (
      !ownership.some(glob => path.matchesGlob(normalized, glob)) &&
      !normalized
        .split('/')
        .some(segment => ['fixtures', '_shared'].includes(segment))
    )
  })
  const plan = buildTestPlan(
    getScriptArgs(),
    collectScannerTests(REPO_ROOT, ownership),
    vitestFiles,
    ownership,
  )
  const exitCodes: number[] = []
  for (const command of plan) {
    const result = await spawn(
      process.execPath,
      [command.entry, ...command.args],
      {
        cwd: REPO_ROOT,
        stdio: scriptStdio('inherit'),
        timeout: coverBudgetMs(),
        killSignal: 'SIGKILL',
        throws: false,
      },
    )
    exitCodes.push(result.code ?? 1)
  }
  return aggregateExitCode(exitCodes)
}

const SCRIPT_META: ScriptMeta = {
  describe: 'runs the fleet Vitest and repository Bun test owners',
  heavyJob: 'test',
  help: 'Usage: pnpm test [--ci | --all | --staged | <test paths> [--timeout <ms> | --reporter <name>]]; --staged runs fleet staged tests plus the owned non-fuzz Bun suite; use test:fast or test:mid for fleet-only lanes and test:fuzz for the separate fuzz runner.',
  json: 'result',
}

if (isMainModule(import.meta.url)) {
  runMain(main, SCRIPT_META)
}
