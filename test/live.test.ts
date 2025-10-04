import { expect, test, describe } from 'bun:test'

const packages: Bun.Security.Package[] = [
  {
    name: 'lodahs',
    version: '0.0.1-security',
    requestedRange: '^0.0.0',
    tarball: 'https://registry.npmjs.org/lodahs/-/lodahs-0.0.1-security.tgz',
  }
]

describe('live', () => {
  test('authenticated', async () => {
    // Only run if token is available
    if (!process.env.SOCKET_CLI_API_TOKEN) {
      throw new Error('test requires a `SOCKET_CLI_API_TOKEN`')
    }

    const { scanner } = await import('../src/index')
    const advisories = await scanner.scan({ packages: [...packages] })

    expect(advisories.length).toBeGreaterThan(0)
    const advisory = advisories[0]!

    expect(advisory).toMatchObject({
      description: expect.any(String),
      level: 'fatal',
      package: 'pkg:npm/lodahs@0.0.1-security',
      url: null
    })
  })

  test('unauthenticated', async () => {
    // temporarily remove token to test unauthenticated mode
    delete process.env.SOCKET_CLI_API_TOKEN

    // Need to re-import to get fresh module with no token
    const modulePath = '../src/index'
    delete require.cache[require.resolve(modulePath)]

    const { scanner } = await import(modulePath + `?t=${Date.now()}`)
    const advisories = await scanner.scan({ packages: [...packages] })

    expect(advisories.length).toBeGreaterThan(0)
    const advisory = advisories[0]!

    expect(advisory).toMatchObject({
      description: expect.any(String),
      level: 'fatal',
      package: 'pkg:npm/lodahs@0.0.1-security',
      url: null
    })
  })
})

