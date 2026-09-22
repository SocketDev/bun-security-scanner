// socket-lint: mirror-exempt — verifies test process network isolation.
import { expect, test } from 'bun:test'
import { execFileSync } from 'node:child_process'
import https from 'node:https'
import nock from 'nock'
import { SCANNER_NETWORK_PRELOAD } from '../scripts/network-preload.mts'

const PROVIDER_URL = 'https://example.invalid/provider'

function expectBlocked(error: unknown): void {
  const code =
    error && typeof error === 'object' && 'code' in error
      ? String(error.code)
      : ''
  const message = error instanceof Error ? error.message : String(error)
  expect(
    code === 'ENETUNREACH' ||
      code === 'ENOTFOUND' ||
      message.includes('socket connection was closed'),
  ).toBe(true)
}

test('provider HTTP requests fail closed without a fixture', async () => {
  const error = await new Promise<Error>(resolve => {
    https.get(PROVIDER_URL).on('error', resolve)
  })
  expectBlocked(error)
})

test('provider fetch requests fail closed without a fixture', async () => {
  try {
    await fetch(PROVIDER_URL)
    throw new Error('provider request unexpectedly succeeded')
  } catch (error) {
    expectBlocked(error)
  }
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
    const code = await new Promise(resolve => https.get(${JSON.stringify(PROVIDER_URL)}).on('error', error => resolve(error.code)))
    process.stdout.write(code)
  `,
      ],
      { encoding: 'utf8', timeout: 10000, env: { ...process.env } },
    )
    expect(['ENETUNREACH', 'ENOTFOUND']).toContain(output)
  },
)
