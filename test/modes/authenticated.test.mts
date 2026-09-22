import { afterEach, beforeEach, describe, expect, spyOn, test } from 'bun:test'
import type { Mock } from 'bun:test'
import { SocketSdk } from '@socketsecurity/sdk'
import nock from 'nock'
import { authenticated } from '../../src/modes/authenticated.mts'
import type { SocketArtifact } from '../../src/types.mts'

function createPackages(count: number): Bun.Security.Package[] {
  const packages: Bun.Security.Package[] = []
  for (let index = 0; index < count; index += 1) {
    packages.push({
      name: `example-package-${index}`,
      version: '1.0.0',
      requestedRange: '^1.0.0',
      tarball: `https://registry.npmjs.org/example-package-${index}/-/example-package-${index}-1.0.0.tgz`,
    })
  }
  return packages
}

const artifact: SocketArtifact = {
  alerts: [
    {
      action: 'error',
      type: 'malware',
      props: { description: 'Fixture alert' },
    },
  ],
  inputPurl: 'pkg:npm/example-package-0@1.0.0',
}
const fetchPackages = SocketSdk.prototype.batchPackageFetch

describe('authenticated', () => {
  let fetchSpy: Mock<typeof SocketSdk.prototype.batchPackageFetch>

  function mockArtifacts(records: unknown[] = [artifact]): void {
    fetchSpy.mockResolvedValue(
      // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- fixtures contain the SDK fields consumed by the scanner, including control records.
      { success: true, status: 200, data: records } as Awaited<
        ReturnType<typeof fetchPackages>
      >,
    )
  }

  beforeEach(() => {
    fetchSpy = spyOn(SocketSdk.prototype, 'batchPackageFetch')
    nock.disableNetConnect()
  })

  afterEach(() => {
    fetchSpy.mockRestore()
    nock.cleanAll()
    nock.enableNetConnect()
  })

  test('yields each artifact with the action filter and full record shape', async () => {
    mockArtifacts([artifact, artifact])
    const packages = createPackages(2)
    const results: SocketArtifact[][] = []
    for await (const artifacts of authenticated('example-api-key')(packages)) {
      results.push(artifacts)
    }
    expect(results).toEqual([[artifact], [artifact]])
    expect(packages).toHaveLength(0)
    expect(fetchSpy).toHaveBeenCalledTimes(1)
    expect(fetchSpy).toHaveBeenCalledWith(
      {
        components: [
          { purl: 'pkg:npm/example-package-0@1.0.0' },
          { purl: 'pkg:npm/example-package-1@1.0.0' },
        ],
      },
      { actions: 'error,warn', compact: false },
    )
  })

  test('does not request an empty package list', async () => {
    const results: SocketArtifact[][] = []
    for await (const artifacts of authenticated('example-api-key')([])) {
      results.push(artifacts)
    }
    expect(results).toEqual([])
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  test('keeps scoped package PURLs intact', async () => {
    mockArtifacts([])
    const packages = createPackages(1)
    packages[0]!.name = '@example/scoped-package'
    for await (const artifacts of authenticated('example-api-key')(packages)) {
      void artifacts
    }
    expect(fetchSpy).toHaveBeenCalledWith(
      { components: [{ purl: 'pkg:npm/@example/scoped-package@1.0.0' }] },
      { actions: 'error,warn', compact: false },
    )
  })

  test('fetches 1025 packages in sequential batches of 1024 and 1', async () => {
    mockArtifacts()
    const packages = createPackages(1025)
    const scan =
      authenticated('example-api-key')(packages)[Symbol.asyncIterator]()
    expect((await scan.next()).value).toEqual([artifact])
    expect(fetchSpy).toHaveBeenCalledTimes(1)
    expect(fetchSpy.mock.calls[0]![0].components).toHaveLength(1024)
    expect(packages).toHaveLength(0)
    expect((await scan.next()).value).toEqual([artifact])
    expect(fetchSpy).toHaveBeenCalledTimes(2)
    expect(fetchSpy.mock.calls[1]![0].components).toEqual([
      { purl: 'pkg:npm/example-package-1024@1.0.0' },
    ])
    expect((await scan.next()).done).toBe(true)
  })

  test('does not start another request after the consumer stops', async () => {
    mockArtifacts()
    const scan = authenticated('example-api-key')(createPackages(1025))[
      Symbol.asyncIterator
    ]()
    await scan.next()
    await scan.return?.()
    expect(fetchSpy).toHaveBeenCalledTimes(1)
  })

  test('skips SDK control records', async () => {
    mockArtifacts([
      { _type: 'purlError', value: { error: 'package_not_found' } },
      artifact,
      { _type: 'summary', value: { purl_input: 1, resolved: 1 } },
    ])
    const results: SocketArtifact[][] = []
    for await (const artifacts of authenticated('example-api-key')(
      createPackages(1),
    )) {
      results.push(artifacts)
    }
    expect(results).toEqual([[artifact]])
  })

  test('preserves an organization monitor action for advisory filtering', async () => {
    const monitored = {
      ...artifact,
      alerts: [
        {
          action: 'monitor' as const,
          type: 'licenseSpdxDisj',
          props: { description: 'Observed license expression' },
        },
      ],
    }
    mockArtifacts([monitored])
    const results: SocketArtifact[][] = []
    for await (const artifacts of authenticated('example-api-key')(
      createPackages(1),
    )) {
      results.push(artifacts)
    }
    expect(results).toEqual([[monitored]])
  })

  test('propagates a later batch failure after yielding earlier artifacts', async () => {
    mockArtifacts()
    const failure = new Error('fixture batch interrupted')
    const scan = authenticated('example-api-key')(createPackages(1025))[
      Symbol.asyncIterator
    ]()
    expect((await scan.next()).value).toEqual([artifact])
    fetchSpy.mockRejectedValueOnce(failure)
    let caught: unknown
    try {
      await scan.next()
    } catch (error) {
      caught = error
    }
    expect(caught).toBe(failure)
  })

  test('rejects API failures without yielding artifacts', async () => {
    fetchSpy.mockResolvedValue({
      success: false,
      status: 500,
      error: 'fixture failure',
    })
    const results: SocketArtifact[][] = []
    let caught: unknown
    try {
      for await (const artifacts of authenticated('example-api-key')(
        createPackages(1),
      )) {
        results.push(artifacts)
      }
    } catch (error) {
      caught = error
    }
    expect(results).toEqual([])
    expect(caught).toBeInstanceOf(Error)
  })

  test('rejects responses beyond the buffered response bound', async () => {
    const paddingBytes = 10 * 1024 * 1024
    const sdk = new SocketSdk('example-api-key', { retries: 0 })
    fetchSpy.mockImplementation((payload, query) =>
      fetchPackages.call(sdk, payload, query),
    )
    nock('https://purl-api.socket.dev')
      .post('/batch')
      .query({ actions: 'error,warn', compact: 'false' })
      .reply(
        200,
        `${JSON.stringify({
          type: 'npm',
          name: 'example-package',
          ...artifact,
          padding: ' '.repeat(paddingBytes),
        })}\n`,
        {
          'content-type': 'application/x-ndjson',
          'content-encoding': 'identity',
        },
      )
    const results: SocketArtifact[][] = []
    let caught: unknown
    try {
      for await (const artifacts of authenticated('example-api-key')(
        createPackages(1),
      )) {
        results.push(artifacts)
      }
    } catch (error) {
      caught = error
    }
    expect(results).toEqual([])
    expect(caught).toBeInstanceOf(Error)
  })
})
