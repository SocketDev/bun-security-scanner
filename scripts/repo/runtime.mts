import path from 'node:path'
import process from 'node:process'
import { fileURLToPath } from 'node:url'

export const REPO_ROOT = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '../..',
)

export const REPO_CACHE_DIR = path.join(REPO_ROOT, '.cache')

export function isMainModule(url: string): boolean {
  const entry = process.argv[1]
  return entry !== undefined && url === new URL(`file://${path.resolve(entry)}`).href
}

export function getScriptArgs(): string[] {
  return process.argv.slice(2)
}

export function scriptStdio(mode: 'inherit' | 'ignore'): 'inherit' | 'ignore' {
  return mode
}

export function runMain(main: () => Promise<void> | void): void {
  Promise.resolve(main()).catch(error => {
    process.stderr.write(`${error instanceof Error ? error.stack ?? error.message : String(error)}\n`)
    process.exitCode = 1
  })
}

export function getScriptLogger() {
  return {
    done(message: string) {
      process.stdout.write(`${message}\n`)
    },
    error(message: string) {
      process.stderr.write(`${message}\n`)
    },
    fail(error: unknown) {
      process.stderr.write(`${error instanceof Error ? error.stack ?? error.message : String(error)}\n`)
    },
    info(message: string) {
      process.stdout.write(`${message}\n`)
    },
    substep(message: string) {
      process.stdout.write(`${message}\n`)
    },
    success(message: string) {
      process.stdout.write(`${message}\n`)
    },
  }
}

export function coverBudgetMs(): number {
  return process.env['CI'] === 'true' ? 60_000 : 30_000
}
