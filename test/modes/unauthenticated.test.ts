import {
  afterEach,
  beforeEach,
  describe,
  expect,
  jest,
  spyOn,
  test,
} from 'bun:test'
import type { Mock } from 'bun:test'
import { errorMessage } from '@socketsecurity/lib-stable/errors/message'
import { unauthenticated } from '../../src/modes/unauthenticated'
import type { SocketArtifact } from '../../src/types'

describe('unauthenticated', () => {
  const mockPackages: Bun.Security.Package[] = [
    {
      name: 'lodahs',
      version: '0.0.1-security',
      requestedRange: '^0.0.0',
      tarball: 'https://registry.npmjs.org/lodahs/-/lodahs-0.0.1-security.tgz',
    },
  ]

  const mockArtifact: SocketArtifact = {
    inputPurl: 'pkg:npm/lodahs@0.0.1-security',
    alerts: [
      {
        action: 'error',
        type: 'malware',
        props: {
          description: 'Known malicious package',
        },
      },
    ],
  }

  let fetchSpy: Mock<typeof fetch>

  beforeEach(() => {
    // `typeof fetch` carries the `preconnect` property, so the mock
    // implementation needs the full callable-with-preconnect shape.
    const mockFetch: typeof fetch = Object.assign(
      () => Promise.resolve(new Response(JSON.stringify(mockArtifact))),
      { preconnect: () => undefined },
    )
    fetchSpy = spyOn(global, 'fetch').mockImplementation(mockFetch)
  })

  afterEach(() => {
    fetchSpy.mockRestore()
  })

  test('unauthenticated scanner should call firewall API without auth', async () => {
    const scanner = unauthenticated()

    const results = scanner([...mockPackages])

    for await (const artifacts of results) {
      expect(artifacts).toHaveLength(1)
      expect(artifacts[0]).toEqual(mockArtifact)
    }

    expect(fetchSpy).toHaveBeenCalledTimes(1)
    expect(fetchSpy).toHaveBeenCalledWith(
      'https://firewall-api.socket.dev/purl/pkg%3Anpm%2Flodahs%400.0.1-security',
      {
        headers: {
          'User-Agent': expect.stringContaining('SocketBunSecurityScanner'),
        },
        // Every request is bounded by a timeout AbortSignal so a hung
        // connection can never block `bun install` indefinitely (SURF-1041).
        signal: expect.any(AbortSignal),
      },
    )
  })

  test('unauthenticated scanner should batch requests correctly', async () => {
    const scanner = unauthenticated()

    const multiplePackages: Bun.Security.Package[] = Array.from(
      { length: 100 },
      (_, i) => ({
        name: `package${i}`,
        version: '1.0.0',
        requestedRange: '^1.0.0',
        tarball: `https://registry.npmjs.org/package${i}/-/package${i}-1.0.0.tgz`,
      }),
    )

    // Mock 100 responses for 100 packages
    for (let i = 0; i < 100; i++) {
      fetchSpy.mockResolvedValueOnce(new Response(''))
    }

    const results = scanner([...multiplePackages])

    for await (const artifacts of results) {
      // Process results
    }

    // With maxBatchLength: 50, should make 2 batches (50 + 50 packages)
    // Each batch makes parallel requests, so should be 100 total fetch calls
    expect(fetchSpy).toHaveBeenCalledTimes(100)
  })

  test('unauthenticated scanner should handle API errors', async () => {
    const scanner = unauthenticated()

    fetchSpy.mockResolvedValueOnce(new Response('Error', { status: 404 }))

    const results = scanner([...mockPackages])

    // try/catch instead of `await expect(…).rejects.toThrow(…)` — bun-types
    // declares the rejects matchers as returning void, so awaiting them trips
    // typescript/await-thenable even though Bun's runtime hands back a promise.
    let thrown: unknown
    try {
      for await (const artifacts of results) {
        // Should throw before getting here
      }
    } catch (e) {
      thrown = e
    }
    expect(thrown).toBeInstanceOf(Error)
    expect(errorMessage(thrown)).toContain(
      'Socket Security Scanner: Received 404 from server',
    )
  })

  test('unauthenticated scanner should properly encode PURLs', async () => {
    const scanner = unauthenticated()

    const specialPackage: Bun.Security.Package[] = [
      {
        name: '@scope/package-name',
        version: '1.0.0-beta.1',
        requestedRange: '^1.0.0',
        tarball:
          'https://registry.npmjs.org/@scope/package-name/-/package-name-1.0.0-beta.1.tgz',
      },
    ]

    const results = scanner([...specialPackage])

    for await (const artifacts of results) {
      // Process results
    }

    expect(fetchSpy).toHaveBeenCalledTimes(1)
    // Check that special characters are properly encoded
    expect(fetchSpy).toHaveBeenCalledWith(
      expect.stringContaining(
        'pkg%3Anpm%2F%40scope%2Fpackage-name%401.0.0-beta.1',
      ),
      {
        headers: {
          'User-Agent': expect.stringContaining('SocketBunSecurityScanner'),
        },
        signal: expect.any(AbortSignal),
      },
    )
  })

  test('unauthenticated scanner should parse NDJSON responses', async () => {
    const scanner = unauthenticated()

    const artifact1: SocketArtifact = {
      inputPurl: 'pkg:npm/package1@1.0.0',
      alerts: [{ action: 'warn', type: 'deprecation', props: {} }],
    }

    const artifact2: SocketArtifact = {
      inputPurl: 'pkg:npm/package2@2.0.0',
      alerts: [{ action: 'error', type: 'malware', props: {} }],
    }

    const ndjson = `${JSON.stringify(artifact1)}\n${JSON.stringify(artifact2)}`

    fetchSpy.mockResolvedValueOnce(new Response(ndjson))

    const results = scanner([...mockPackages])

    for await (const artifacts of results) {
      expect(artifacts).toHaveLength(2)
      expect(artifacts[0]).toEqual(artifact1)
      expect(artifacts[1]).toEqual(artifact2)
    }
  })

  // REGRESSION (SURF-1041): a hung firewall-api connection must surface as a
  // scan error, never block the scan (and therefore `bun install`) forever.
  // Before the fix the fetch had no AbortSignal, so a response that never
  // arrived left the scan pending indefinitely. Now every request carries a
  // timeout AbortSignal; when it fires, fetch rejects and the fail-fast
  // Promise.all propagates that rejection out of the async generator.
  //
  // Deterministic: the stub models a hung connection — it settles ONLY when its
  // AbortSignal aborts (rejecting with the signal's reason), never on its own.
  // Fake timers fast-forward past the 30s request budget so the real
  // AbortSignal.timeout fires without waiting in wall-clock time.
  test('unauthenticated scanner surfaces a request timeout as an error', async () => {
    const hungFetch: typeof fetch = Object.assign(
      (_url: string | URL | Request, init?: RequestInit | undefined) =>
        new Promise<Response>((_resolve, reject) => {
          const signal = init?.signal
          if (signal) {
            signal.addEventListener(
              'abort',
              () => {
                reject(signal.reason)
              },
              { once: true },
            )
          }
        }),
      { preconnect: () => undefined },
    )
    fetchSpy.mockImplementation(hungFetch)

    jest.useFakeTimers()
    try {
      const scanner = unauthenticated()
      const results = scanner([...mockPackages])

      let thrown: unknown
      const consume = (async () => {
        try {
          for await (const artifacts of results) {
            void artifacts
          }
        } catch (e) {
          thrown = e
        }
      })()

      // Let the flight dispatch and register its abort listener, then blow past
      // the per-request deadline so AbortSignal.timeout fires.
      await Promise.resolve()
      jest.advanceTimersByTime(30_000)

      await consume

      // A TimeoutError (DOMException) is an Error; the scan rejected instead of
      // hanging. Narrow with instanceof rather than a cast so the name check is
      // type-safe.
      expect(thrown).toBeInstanceOf(Error)
      expect(thrown instanceof Error ? thrown.name : undefined).toBe(
        'TimeoutError',
      )
    } finally {
      jest.useRealTimers()
    }
  })
})
