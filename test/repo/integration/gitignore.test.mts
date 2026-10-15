import { mkdtempSync, readFileSync } from 'node:fs'
import os from 'node:os'
import path from 'node:path'

import { expect, test } from 'bun:test'

import { spawnSync } from '@socketsecurity/lib-stable/process/spawn/child'
import { safeDeleteSync } from '@socketsecurity/lib-stable/fs/safe'
import { GIT_CONTEXT_VARS } from '../../../.git-hooks/_shared/git-context-vars.mts'
import { isolateGitEnv } from '../../../.git-hooks/_shared/isolate-git-env.mts'
import { REPO_ROOT } from '../../../scripts/fleet/paths.mts'

test('strong git environment isolation strips context and pins config', () => {
  const names = [...GIT_CONTEXT_VARS, 'GIT_CONFIG_GLOBAL', 'GIT_CONFIG_SYSTEM']
  const previous = new Map(
    names.map(name => [name, process.env[name]] as const),
  )
  try {
    for (const name of GIT_CONTEXT_VARS) {
      process.env[name] = `/synthetic/${name.toLowerCase()}`
    }
    process.env['GIT_CONFIG_GLOBAL'] = '/synthetic/global-config'
    process.env['GIT_CONFIG_SYSTEM'] = '/synthetic/system-config'

    isolateGitEnv({ pinConfigToNull: true })

    for (const name of GIT_CONTEXT_VARS) {
      expect(process.env[name]).toBeUndefined()
    }
    expect(process.env['GIT_CONFIG_GLOBAL']).toBe('/dev/null')
    expect(process.env['GIT_CONFIG_SYSTEM']).toBe('/dev/null')
  } finally {
    for (const name of names) {
      const value = previous.get(name)
      if (value === undefined) {
        delete process.env[name]
      } else {
        process.env[name] = value
      }
    }
  }
})

test('ignore policy admits source and rejects runtime files by default', () => {
  const root = mkdtempSync(path.join(os.tmpdir(), 'scanner-ignore-'))
  try {
    const init = spawnSync('git', ['init', '--quiet', root], {
      env: { ...process.env, GIT_CONFIG_NOSYSTEM: '1' },
    })
    expect(init.status).toBe(0)
    const result = spawnSync(
      'git',
      [
        '-c',
        `core.excludesFile=${path.join(REPO_ROOT, '.gitignore')}`,
        'check-ignore',
        '--no-index',
        '--stdin',
      ],
      {
        cwd: root,
        encoding: 'utf8',
        input:
          [
            'package.json',
            'src/new-scanner.mts',
            'test/modes/new-scanner.test.mts',
            'local-note.unknown',
            'src/local-note.txt',
            '.env.local',
            'dist/index.js',
            'node_modules/example/index.mts',
            'scripts/fleet/new-check.mts',
            '.claude/reports/session.md',
          ].join('\n') + '\n',
      },
    )
    expect(result.status).toBe(0)
    expect(String(result.stdout).trim().split('\n')).toEqual([
      'local-note.unknown',
      'src/local-note.txt',
      '.env.local',
      'dist/index.js',
      'node_modules/example/index.mts',
      'scripts/fleet/new-check.mts',
      '.claude/reports/session.md',
    ])
  } finally {
    safeDeleteSync(root)
  }
})

test('ignore file keeps the canonical prologue and owned blocks', () => {
  const content = readFileSync(path.join(REPO_ROOT, '.gitignore'), 'utf8')
  expect(content.split(/\r?\n/u).slice(0, 2)).toEqual(['*', '!*/'])
  expect(
    content.match(/^# <\/?(?:fleet(?:-pack|-allowlist)?|repo)>$/gmu),
  ).toEqual([
    '# <fleet-pack>',
    '# </fleet-pack>',
    '# <repo>',
    '# </repo>',
    '# <fleet-allowlist>',
    '# </fleet-allowlist>',
  ])
})
