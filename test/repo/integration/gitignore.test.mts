import { mkdtempSync, readFileSync } from 'node:fs'
import os from 'node:os'
import path from 'node:path'

import { expect, test } from 'bun:test'

import { spawnSync } from '@socketsecurity/lib-stable/process/spawn/child'
import { safeDeleteSync } from '@socketsecurity/lib-stable/fs/safe'
import { REPO_ROOT } from '../../../scripts/fleet/paths.mts'

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

test('ignore rules have one fleet owner and one repository owner', () => {
  const content = readFileSync(path.join(REPO_ROOT, '.gitignore'), 'utf8')
  expect(content.match(/^# <fleet>$/gm)).toHaveLength(1)
  expect(content.match(/^# <repo>$/gm)).toHaveLength(1)
  expect(content.trim().startsWith('# <fleet>')).toBe(true)
  expect(content.trim().endsWith('# </repo>')).toBe(true)
})
