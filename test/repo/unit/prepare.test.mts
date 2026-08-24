/**
 * @file Unit tests for the bootstrap/prepare.mts dep-0 doctor. Covers the
 *   pure helpers directly. fetchBundle/repairWorkspacePackages/
 *   reconcileInstall/maybeNotifyUpdate/runPrepare are left uncovered here:
 *   they mutate the repo's own tracked pnpm-workspace.yaml or hit the
 *   network, so exercising them for real would either dirty a tracked file
 *   this change doesn't otherwise touch or make the suite network-flaky.
 */
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs'
import os from 'node:os'
import path from 'node:path'

import { afterAll, describe, expect, test } from 'bun:test'

import { safeDeleteSync } from '@socketsecurity/lib-stable/fs/safe'

import {
  ensureWorkspacePackages,
  isAppliedRefCurrentOrNewer,
  isMainModule,
  log,
  resolveRepoRoot,
  tryRun,
} from '../../../scripts/repo/bootstrap/prepare.mts'

const tmpDirs: string[] = []

afterAll(() => {
  for (const dir of tmpDirs) {
    safeDeleteSync(dir, { force: true, recursive: true })
  }
})

function makeTmpDir(prefix: string): string {
  const dir = mkdtempSync(path.join(os.tmpdir(), prefix))
  tmpDirs.push(dir)
  return dir
}

describe('resolveRepoRoot', () => {
  test('walks up to the nearest package.json ancestor', () => {
    const root = makeTmpDir('resolve-root-')
    writeFileSync(path.join(root, 'package.json'), '{}', 'utf8')
    const nested = path.join(root, 'a', 'b', 'c')
    mkdirSync(nested, { recursive: true })

    expect(resolveRepoRoot(nested)).toBe(root)
  })

  test('falls back three levels up when no ancestor has a package.json', () => {
    const base = makeTmpDir('resolve-root-none-')
    const nested = path.join(base, 'a', 'b', 'c')
    mkdirSync(nested, { recursive: true })

    expect(resolveRepoRoot(nested)).toBe(path.resolve(nested, '..', '..', '..'))
  })
})

describe('ensureWorkspacePackages', () => {
  const REQUIRED = ['a/*', 'b/*']

  test('adds a packages: block when none exists', () => {
    expect(ensureWorkspacePackages('foo: bar\n', REQUIRED)).toBe(
      "packages:\n  - 'a/*'\n  - 'b/*'\n\nfoo: bar\n",
    )
  })

  test('appends only the missing globs after the existing bullets', () => {
    const yaml = "packages:\n  - 'a/*'\n  - 'c/*'\n"
    expect(ensureWorkspacePackages(yaml, REQUIRED)).toBe(
      "packages:\n  - 'a/*'\n  - 'c/*'\n  - 'b/*'\n",
    )
  })

  test('is a no-op once every glob is present', () => {
    const yaml = "packages:\n  - 'a/*'\n  - 'b/*'\n"
    expect(ensureWorkspacePackages(yaml, REQUIRED)).toBe(yaml)
  })

  test('stops the block at the first non-indented line', () => {
    const yaml = "packages:\n  - 'a/*'\nother: 1\n"
    expect(ensureWorkspacePackages(yaml, REQUIRED)).toBe(
      "packages:\n  - 'a/*'\n  - 'b/*'\nother: 1\n",
    )
  })
})

describe('isAppliedRefCurrentOrNewer', () => {
  const PINNED = `fleet-pack-${'0'.repeat(40)}`
  const APPLIED = `fleet-pack-${'1'.repeat(40)}`

  test('is false when either ref is missing', () => {
    expect(isAppliedRefCurrentOrNewer(undefined, APPLIED)).toBe(false)
    expect(isAppliedRefCurrentOrNewer(PINNED, undefined)).toBe(false)
  })

  test('is true when the applied ref equals the pin', () => {
    expect(isAppliedRefCurrentOrNewer(PINNED, PINNED)).toBe(true)
  })

  test('is false when a ref does not parse as a fleet-pack sha', () => {
    expect(isAppliedRefCurrentOrNewer(PINNED, 'not-a-pack-ref')).toBe(false)
  })

  test('trusts a divergent applied ref outside CI with no sibling wheelhouse checkout', () => {
    const originalCI = process.env['CI']
    delete process.env['CI']
    try {
      expect(isAppliedRefCurrentOrNewer(PINNED, APPLIED)).toBe(true)
    } finally {
      if (originalCI === undefined) {
        delete process.env['CI']
      } else {
        process.env['CI'] = originalCI
      }
    }
  })

  test('never trusts a divergent applied ref in CI with no sibling wheelhouse checkout', () => {
    const originalCI = process.env['CI']
    process.env['CI'] = '1'
    try {
      expect(isAppliedRefCurrentOrNewer(PINNED, APPLIED)).toBe(false)
    } finally {
      if (originalCI === undefined) {
        delete process.env['CI']
      } else {
        process.env['CI'] = originalCI
      }
    }
  })
})

describe('tryRun', () => {
  test('is true when the command exits zero', () => {
    expect(tryRun('node', ['-e', 'process.exit(0)'])).toBe(true)
  })

  test('is false when the command exits non-zero', () => {
    expect(tryRun('node', ['-e', 'process.exit(1)'])).toBe(false)
  })
})

describe('isMainModule', () => {
  test('is false when the test runner, not this script, is the entry', () => {
    expect(isMainModule()).toBe(false)
  })
})

describe('log', () => {
  test('prefixes the message with fleet-prepare', () => {
    const original = console.log
    const calls: unknown[][] = []
    console.log = (...args: unknown[]) => {
      calls.push(args)
    }
    try {
      log('hello')
    } finally {
      console.log = original
    }
    expect(calls).toEqual([['fleet-prepare: hello']])
  })
})
