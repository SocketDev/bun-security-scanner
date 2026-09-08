// socket-lint: mirror-exempt — verifies test process network isolation.
import { expect, test } from 'bun:test'
import { execFileSync } from 'node:child_process'
import https from 'node:https'
import nock from 'nock'
import { SCANNER_NETWORK_PRELOAD } from '../scripts/network-preload.mts'

test('provider HTTP requests fail closed without a fixture', async () => {
  const error = await new Promise<Error>(resolve => {
    https.get('https://example.invalid/provider').on('error', resolve)
  })
  expect(error).toMatchObject({ code: 'ENETUNREACH' })
})

test('provider fetch requests fail closed without a fixture', async () => {
  await expect(fetch('https://example.invalid/provider')).rejects.toMatchObject(
    { code: 'ENETUNREACH' },
  )
})

test('mocked providers remain available', async () => {
  const scope = nock('https://example.invalid')
    .get('/fixture')
    .reply(200, 'fixture response')
  expect(await (await fetch('https://example.invalid/fixture')).text()).toBe(
    'fixture response',
  )
  expect(scope.isDone()).toBe(true)
})

test('literal loopback fixture servers remain available', async () => {
  const server = Bun.serve({
    hostname: '127.0.0.1',
    port: 0,
    fetch: () => new Response('local fixture'),
  })
  try {
    expect(await (await fetch(`http://127.0.0.1:${server.port}`)).text()).toBe(
      'local fixture',
    )
  } finally {
    server.stop(true)
  }
})

test.each(['node', process.execPath])(
  'preloads network isolation into %s subprocesses',
  executable => {
    const output = execFileSync(
      executable,
      [
        ...(executable === process.execPath
          ? ['--preload', SCANNER_NETWORK_PRELOAD]
          : []),
        '--input-type=module',
        '--eval',
        `
    if (!globalThis[Symbol.for('scanner.test-network-guard')]) process.exit(2)
    const https = await import('node:https')
    const code = await new Promise(resolve => https.get('https://example.invalid/provider').on('error', error => resolve(error.code)))
    process.stdout.write(code)
  `,
      ],
      { encoding: 'utf8', timeout: 10000, env: { ...process.env } },
    )
    expect(output).toBe('ENETUNREACH')
  },
)
