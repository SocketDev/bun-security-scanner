import { expect, test, describe, spyOn, beforeEach, afterEach } from 'bun:test'
import unauthenticated from '../../src/modes/unauthenticated'
import type { SocketArtifact } from '../../src/types'

describe('unauthenticated', () => {
  const mockPackages: Bun.Security.Package[] = [
    {
      name: 'lodahs',
      version: '0.0.1-security',
      requestedRange: '^0.0.0',
      tarball: 'https://registry.npmjs.org/lodahs/-/lodahs-0.0.1-security.tgz',
    }
  ]

  const mockArtifact: SocketArtifact = {
    inputPurl: 'pkg:npm/lodahs@0.0.1-security',
    alerts: [
      {
        action: 'error',
        type: 'malware',
        props: {
          description: 'Known malicious package'
        }
      }
    ]
  }

  let fetchSpy

  beforeEach(() => {
    fetchSpy = spyOn(global, 'fetch').mockImplementation(() => Promise.resolve(
      new Response(JSON.stringify(mockArtifact))
    ))
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
        'headers': {
          'User-Agent': expect.stringContaining('SocketBunSecurityScanner'),
        }
      }
    )
  })

  test('unauthenticated scanner should batch requests correctly', async () => {
    const scanner = unauthenticated()

    const multiplePackages: Bun.Security.Package[] = Array.from({ length: 100 }, (_, i) => ({
      name: `package${i}`,
      version: '1.0.0',
      requestedRange: '^1.0.0',
      tarball: `https://registry.npmjs.org/package${i}/-/package${i}-1.0.0.tgz`,
    }))

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

    fetchSpy.mockResolvedValueOnce(
      new Response('Error', { status: 404 })
    )

    const results = scanner([...mockPackages])

    await expect(async () => {
      for await (const artifacts of results) {
        // Should throw before getting here
      }
    }).toThrow('Socket Security Scanner: Received 404 from server')
  })

  test('unauthenticated scanner should properly encode PURLs', async () => {
    const scanner = unauthenticated()

    const specialPackage: Bun.Security.Package[] = [
      {
        name: '@scope/package-name',
        version: '1.0.0-beta.1',
        requestedRange: '^1.0.0',
        tarball: 'https://registry.npmjs.org/@scope/package-name/-/package-name-1.0.0-beta.1.tgz',
      }
    ]

    const results = scanner([...specialPackage])

    for await (const artifacts of results) {
      // Process results
    }

    expect(fetchSpy).toHaveBeenCalledTimes(1)
    // Check that special characters are properly encoded
    expect(fetchSpy).toHaveBeenCalledWith(
      expect.stringContaining('pkg%3Anpm%2F%40scope%2Fpackage-name%401.0.0-beta.1'), 
        {
          'headers': {
            'User-Agent': expect.stringContaining('SocketBunSecurityScanner'),
          }
        }
      )
  })

  test('unauthenticated scanner should parse NDJSON responses', async () => {
    const scanner = unauthenticated()

    const artifact1: SocketArtifact = {
      inputPurl: 'pkg:npm/package1@1.0.0',
      alerts: [{ action: 'warn', type: 'deprecation', props: {} }]
    }

    const artifact2: SocketArtifact = {
      inputPurl: 'pkg:npm/package2@2.0.0',
      alerts: [{ action: 'error', type: 'malware', props: {} }]
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
