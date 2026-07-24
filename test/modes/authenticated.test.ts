import { afterEach, beforeEach, describe, expect, spyOn, test } from 'bun:test'
import type { Mock } from 'bun:test'
import { errorMessage } from '@socketsecurity/lib-stable/errors/message'
import { SocketSdk } from '@socketsecurity/sdk'
import { authenticated } from '../../src/modes/authenticated'
import type { SocketArtifact } from '../../src/types'

describe('authenticated', () => {
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

  // The SDK talks node:http, not global fetch, so the mock seam is the
  // batchPackageStream method itself (prototype spy — restored after each
  // test so the live suite still drives the real transport).
  let streamSpy: Mock<typeof SocketSdk.prototype.batchPackageStream>

  function mockStreamResults(
    results: Array<{
      success: boolean
      status: number
      data?: unknown | undefined
    }>,
  ): void {
    const impl = async function* () {
      yield* results
    }
    streamSpy.mockImplementation(
      // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- the mock yields the success/status/data subset the scanner consumes; the sdk's full generated result type is irrelevant to these behavior tests.
      impl as unknown as typeof SocketSdk.prototype.batchPackageStream,
    )
  }

  beforeEach(() => {
    streamSpy = spyOn(SocketSdk.prototype, 'batchPackageStream')
  })

  afterEach(() => {
    streamSpy.mockRestore()
  })

  test('authenticated scanner should stream purls through the Socket SDK', async () => {
    mockStreamResults([{ success: true, status: 200, data: mockArtifact }])

    const scanner = authenticated('test-api-key-123')
    const results = scanner([...mockPackages])

    for await (const artifacts of results) {
      expect(artifacts).toHaveLength(1)
      expect(artifacts[0]).toEqual(mockArtifact)
    }

    expect(streamSpy).toHaveBeenCalledTimes(1)
    expect(streamSpy).toHaveBeenCalledWith(
      {
        components: [{ purl: 'pkg:npm/lodahs@0.0.1-security' }],
      },
      { queryParams: { actions: 'error,warn' } },
    )
  })

  test('authenticated scanner should batch every package into one stream', async () => {
    mockStreamResults([])

    const scanner = authenticated('test-api-key-123')

    const multiplePackages: Bun.Security.Package[] = [
      {
        name: 'package1',
        version: '1.0.0',
        requestedRange: '^1.0.0',
        tarball: 'https://registry.npmjs.org/package1/-/package1-1.0.0.tgz',
      },
      {
        name: '@scope/package2',
        version: '2.0.0',
        requestedRange: '^2.0.0',
        tarball:
          'https://registry.npmjs.org/@scope/package2/-/package2-2.0.0.tgz',
      },
    ]

    const results = scanner([...multiplePackages])

    for await (const artifacts of results) {
      // Drain the generator; assertions follow.
      void artifacts
    }

    // The SDK owns chunking/concurrency, so all purls go in a single call.
    expect(streamSpy).toHaveBeenCalledTimes(1)
    expect(streamSpy).toHaveBeenCalledWith(
      {
        components: [
          { purl: 'pkg:npm/package1@1.0.0' },
          { purl: 'pkg:npm/@scope/package2@2.0.0' },
        ],
      },
      { queryParams: { actions: 'error,warn' } },
    )
  })

  test('authenticated scanner should drain the packages array it is handed', async () => {
    mockStreamResults([])

    const scanner = authenticated('test-api-key-123')
    const packages = [...mockPackages]
    const results = scanner(packages)

    for await (const artifacts of results) {
      // Drain the generator; assertions follow.
      void artifacts
    }

    // `scan()` loops `while (packages.length)` — a non-consuming
    // implementation would spin forever.
    expect(packages).toHaveLength(0)
  })

  test('authenticated scanner should handle API errors', async () => {
    mockStreamResults([{ success: false, status: 500 }])

    const scanner = authenticated('test-api-key-123')
    const results = scanner([...mockPackages])

    // try/catch instead of `await expect(…).rejects.toThrow(…)` — bun-types
    // declares the rejects matchers as returning void, so awaiting them trips
    // typescript/await-thenable even though Bun's runtime hands back a promise.
    let thrown: unknown
    try {
      for await (const artifacts of results) {
        // The throw is the behavior under test.
        void artifacts
      }
    } catch (e) {
      thrown = e
    }
    expect(thrown).toBeInstanceOf(Error)
    expect(errorMessage(thrown)).toContain(
      'Socket Security Scanner: Received 500 from server',
    )
  })
})
