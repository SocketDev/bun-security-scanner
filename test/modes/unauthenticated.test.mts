import { afterEach, beforeEach, describe, expect, spyOn, test } from 'bun:test'
import type { Mock } from 'bun:test'
import timers from 'node:timers/promises'
import { errorMessage } from '@socketsecurity/lib-stable/errors/message'
import { unauthenticated } from '../../src/modes/unauthenticated.mts'
import type { SocketArtifact } from '../../src/types.mts'
import { tolerantSleep } from '../fleet/_shared/lib/timing.mts'

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
  let retryDelaySpy: Mock<typeof timers.setTimeout>

  beforeEach(() => {
    // `typeof fetch` carries the `preconnect` property, so the mock
    // implementation needs the full callable-with-preconnect shape.
    const mockFetch: typeof fetch = Object.assign(
      () => Promise.resolve(new Response(JSON.stringify(mockArtifact))),
      { preconnect: () => undefined },
    )
    fetchSpy = spyOn(global, 'fetch').mockImplementation(mockFetch)
    retryDelaySpy = spyOn(timers, 'setTimeout').mockResolvedValue(undefined)
  })

  afterEach(() => {
    fetchSpy.mockRestore()
    retryDelaySpy.mockRestore()
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
          'User-Agent': expect.stringContaining('socket-bun-security-scanner'),
        },
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
      void artifacts
    }

    // Every purl costs one request on the free endpoint, whatever the batching.
    expect(fetchSpy).toHaveBeenCalledTimes(100)
  })

  test('unauthenticated scanner caps concurrent requests at the shipped config', async () => {
    // The cap is a REQUEST cap and the free endpoint answers one purl per
    // request, so a flight of N purls is N concurrent requests. This runs the
    // shipped configuration — the one the cap has to hold for.
    let inFlight = 0
    let peak = 0
    let total = 0

    fetchSpy.mockImplementation(
      Object.assign(
        async () => {
          inFlight += 1
          total += 1
          peak = Math.max(peak, inFlight)
          await new Promise<void>(resolve => {
            setTimeout(resolve, tolerantSleep(5))
          })
          inFlight -= 1
          return new Response('')
        },
        { preconnect: () => undefined },
      ) as typeof fetch,
    )

    const manyPackages: Bun.Security.Package[] = Array.from(
      { length: 120 },
      (_, i) => ({
        name: `package${i}`,
        version: '1.0.0',
        requestedRange: '^1.0.0',
        tarball: `https://registry.npmjs.org/package${i}/-/package${i}-1.0.0.tgz`,
      }),
    )

    const scanner = unauthenticated()

    for await (const artifacts of scanner(manyPackages)) {
      void artifacts
    }

    expect(total).toBe(120)
    // 20 is the advertised cap. Counting packages instead of requests let the
    // peak reach the batch width, so 120 packages opened 50 sockets at once.
    expect(peak).toBeLessThanOrEqual(20)
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
        void artifacts
        // Should throw before getting here
      }
    } catch (e) {
      thrown = e
    }
    expect(thrown).toBeInstanceOf(Error)
    expect(errorMessage(thrown)).toContain(
      'Socket Security Scanner: Received 404 from server',
    )
    expect(fetchSpy).toHaveBeenCalledTimes(1)
    expect(retryDelaySpy).not.toHaveBeenCalled()
  })

  test('transient connection failure retries and retains security alerts', async () => {
    const otherArtifact: SocketArtifact = {
      inputPurl: 'pkg:npm/example-dependency@1.0.0',
      alerts: [{ action: 'warn', type: 'deprecation', props: {} }],
    }
    fetchSpy.mockRejectedValueOnce(
      Object.assign(new Error('Connection closed'), { code: 'ECONNRESET' }),
    )
    fetchSpy.mockResolvedValueOnce(new Response(JSON.stringify(otherArtifact)))
    const received: SocketArtifact[] = []
    for await (const artifacts of unauthenticated()([
      ...mockPackages,
      {
        name: 'example-dependency',
        version: '1.0.0',
        requestedRange: '^1.0.0',
        tarball:
          'https://registry.npmjs.org/example-dependency/-/example-dependency-1.0.0.tgz',
      },
    ])) {
      received.push(...artifacts)
    }
    expect(received).toHaveLength(2)
    expect(received).toEqual(
      expect.arrayContaining([mockArtifact, otherArtifact]),
    )
    expect(fetchSpy).toHaveBeenCalledTimes(3)
    expect(retryDelaySpy.mock.calls.map(([delay]) => delay)).toEqual([1000])
  })

  test.each([408, 429, 500, 502, 503, 504])(
    'transient HTTP %i retries and retains security alerts',
    async status => {
      fetchSpy.mockResolvedValueOnce(new Response('Unavailable', { status }))
      const received: SocketArtifact[] = []
      for await (const artifacts of unauthenticated()([...mockPackages])) {
        received.push(...artifacts)
      }
      expect(received).toEqual([mockArtifact])
      expect(fetchSpy).toHaveBeenCalledTimes(2)
      expect(retryDelaySpy.mock.calls.map(([delay]) => delay)).toEqual([1000])
    },
  )

  test('response body disconnect retries the complete request', async () => {
    const response = new Response('')
    spyOn(response, 'text').mockRejectedValueOnce(
      Object.assign(new Error('Connection closed'), { code: 'ECONNRESET' }),
    )
    fetchSpy.mockResolvedValueOnce(response)
    const received: SocketArtifact[] = []
    for await (const artifacts of unauthenticated()([...mockPackages])) {
      received.push(...artifacts)
    }
    expect(received).toEqual([mockArtifact])
    expect(fetchSpy).toHaveBeenCalledTimes(2)
  })

  test('connection failures stop after five attempts and reject', async () => {
    const failure = Object.assign(new Error('Connection closed'), {
      code: 'ECONNRESET',
    })
    fetchSpy.mockRejectedValue(failure)
    const result = await Array.fromAsync(
      unauthenticated()([...mockPackages]),
    ).catch((error: unknown) => error)
    expect(result).toBe(failure)
    expect(fetchSpy).toHaveBeenCalledTimes(5)
    expect(retryDelaySpy.mock.calls.map(([delay]) => delay)).toEqual([
      1000, 2000, 4000, 8000,
    ])
  })

  test('transient HTTP failures stop after five attempts and reject', async () => {
    fetchSpy.mockImplementation(
      Object.assign(
        () => Promise.resolve(new Response('Unavailable', { status: 503 })),
        { preconnect: () => undefined },
      ),
    )
    const result = await Array.fromAsync(
      unauthenticated()([...mockPackages]),
    ).catch((error: unknown) => error)
    expect(result).toBeInstanceOf(Error)
    expect(fetchSpy).toHaveBeenCalledTimes(5)
    expect(retryDelaySpy.mock.calls.map(([delay]) => delay)).toEqual([
      1000, 2000, 4000, 8000,
    ])
  })

  test.each([400, 401, 403])('HTTP %i fails without retry', async status => {
    fetchSpy.mockResolvedValueOnce(new Response('Rejected', { status }))
    const result = await Array.fromAsync(
      unauthenticated()([...mockPackages]),
    ).catch((error: unknown) => error)
    expect(result).toBeInstanceOf(Error)
    expect(fetchSpy).toHaveBeenCalledTimes(1)
    expect(retryDelaySpy).not.toHaveBeenCalled()
  })

  test('interrupted retry delay rejects instead of reporting a clean scan', async () => {
    fetchSpy.mockRejectedValueOnce(new TypeError('Connection closed'))
    retryDelaySpy.mockRejectedValueOnce(
      new DOMException('Aborted', 'AbortError'),
    )
    const result = await Array.fromAsync(
      unauthenticated()([...mockPackages]),
    ).catch((error: unknown) => error)
    expect(result).toBeInstanceOf(Error)
    expect(fetchSpy).toHaveBeenCalledTimes(1)
    expect(retryDelaySpy).toHaveBeenCalledTimes(1)
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
      void artifacts
    }

    expect(fetchSpy).toHaveBeenCalledTimes(1)
    // Check that special characters are properly encoded
    expect(fetchSpy).toHaveBeenCalledWith(
      expect.stringContaining(
        'pkg%3Anpm%2F%40scope%2Fpackage-name%401.0.0-beta.1',
      ),
      {
        headers: {
          'User-Agent': expect.stringContaining('socket-bun-security-scanner'),
        },
      },
    )
  })

  test('malformed NDJSON rejects instead of reporting a clean scan', async () => {
    fetchSpy.mockResolvedValueOnce(new Response('not-json'))
    const scan = unauthenticated()([...mockPackages])
    let failure: unknown
    try {
      for await (const artifacts of scan) {
        void artifacts
      }
    } catch (error) {
      failure = error
    }
    expect(failure).toBeInstanceOf(SyntaxError)
    expect(fetchSpy).toHaveBeenCalledTimes(1)
    expect(retryDelaySpy).not.toHaveBeenCalled()
  })

  test('NDJSON accepts CRLF and skips empty records', async () => {
    fetchSpy.mockResolvedValueOnce(
      new Response(`\r\n${JSON.stringify(mockArtifact)}\r\n\r\n`),
    )
    const received: SocketArtifact[] = []
    for await (const artifacts of unauthenticated()([...mockPackages])) {
      received.push(...artifacts)
    }
    expect(received).toEqual([mockArtifact])
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
})
