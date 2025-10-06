import { expect, test, describe, spyOn, beforeEach, afterEach } from 'bun:test'
import authenticated from '../../src/modes/authenticated'
import type { SocketArtifact } from '../../src/types'


describe('authenticated', () => {
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

  test('authenticated scanner should call Socket API with Bearer token', async () => {
    const apiKey = 'test-api-key-123'
    const scanner = authenticated(apiKey)

    const results = scanner([...mockPackages])

    for await (const artifacts of results) {
      expect(artifacts).toHaveLength(1)
      expect(artifacts[0]).toEqual(mockArtifact)
    }

    expect(fetchSpy).toHaveBeenCalledTimes(1)
    expect(fetchSpy).toHaveBeenCalledWith(
      'https://api.socket.dev/v0/purl?actions=error,warn',
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${apiKey}`
        },
        body: JSON.stringify({
          components: [{ purl: 'pkg:npm/lodahs@0.0.1-security' }]
        })
      }
    )
  })

  test('authenticated scanner should batch requests correctly', async () => {
    const apiKey = 'test-api-key-123'
    const scanner = authenticated(apiKey)

    const multiplePackages: Bun.Security.Package[] = [
      {
        name: 'package1',
        version: '1.0.0',
        requestedRange: '^1.0.0',
        tarball: 'https://registry.npmjs.org/package1/-/package1-1.0.0.tgz',
      },
      {
        name: 'package2',
        version: '2.0.0',
        requestedRange: '^2.0.0',
        tarball: 'https://registry.npmjs.org/package2/-/package2-2.0.0.tgz',
      }
    ]

    fetchSpy
      .mockResolvedValueOnce(new Response(''))
      .mockResolvedValueOnce(new Response(''))

    const results = scanner([...multiplePackages])

    for await (const artifacts of results) {
      // Process results
    }

    // With maxBatchLength: 1, should make 2 separate calls
    expect(fetchSpy).toHaveBeenCalledTimes(2)
  })

  test('authenticated scanner should handle API errors', async () => {
    const apiKey = 'test-api-key-123'
    const scanner = authenticated(apiKey)

    fetchSpy.mockResolvedValueOnce(
      new Response('Error', { status: 500 })
    )

    const results = scanner([...mockPackages])

    await expect(async () => {
      for await (const artifacts of results) {
        // Should throw before getting here
      }
    }).toThrow('Socket Security Scanner: Received 500 from server')
  })
})
