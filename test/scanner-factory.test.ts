import { expect, test, describe } from 'bun:test'
import { createScanner } from '../src/scanner-factory'
import type { SocketArtifact } from '../src/types'

const mockPackages: Bun.Security.Package[] = [
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
  },
  {
    name: 'package3',
    version: '3.0.0',
    requestedRange: '^3.0.0',
    tarball: 'https://registry.npmjs.org/package3/-/package3-3.0.0.tgz',
  }
]

describe('scanner-factory', () => {
  test('should call fetchStrategy with correct purls', async () => {
    const capturedPurls: string[] = []
    const fetchStrategy = async (purls: string[], artifacts: SocketArtifact[]) => {
      capturedPurls.push(...purls)
    }

    const scanner = createScanner({
      maxSending: 10,
      maxBatchLength: 5,
      fetchStrategy
    })

    const results = scanner([...mockPackages])

    for await (const artifacts of results) {
      // Consume results
    }

    expect(capturedPurls).toEqual([
      'pkg:npm/package1@1.0.0',
      'pkg:npm/package2@2.0.0',
      'pkg:npm/package3@3.0.0'
    ])
  })

  test('should respect maxBatchLength', async () => {
    const batchSizes: number[] = []
    const fetchStrategy = async (purls: string[], artifacts: SocketArtifact[]) => {
      batchSizes.push(purls.length)
    }

    const scanner = createScanner({
      maxSending: 10,
      maxBatchLength: 2,
      fetchStrategy
    })

    const results = scanner([...mockPackages])

    for await (const artifacts of results) {
      // Consume results
    }

    // 3 packages with maxBatchLength of 2 should create batches of [2, 1]
    expect(batchSizes).toEqual([2, 1])
  })

  test('should yield artifacts from fetchStrategy', async () => {
    const mockArtifacts: SocketArtifact[] = [
      {
        inputPurl: 'pkg:npm/package1@1.0.0',
        alerts: [{ action: 'error', type: 'malware', props: {} }]
      },
      {
        inputPurl: 'pkg:npm/package2@2.0.0',
        alerts: [{ action: 'warn', type: 'deprecation', props: {} }]
      }
    ]

    const fetchStrategy = async (purls: string[], artifacts: SocketArtifact[]) => {
      artifacts.push(...mockArtifacts)
    }

    const scanner = createScanner({
      maxSending: 10,
      maxBatchLength: 5,
      fetchStrategy
    })

    const results = scanner([...mockPackages])
    const allArtifacts: SocketArtifact[] = []

    for await (const artifacts of results) {
      allArtifacts.push(...artifacts)
    }

    expect(allArtifacts).toEqual(mockArtifacts)
  })

  test('should not call fetchStrategy with empty batch', async () => {
    let callCount = 0
    const fetchStrategy = async (purls: string[], artifacts: SocketArtifact[]) => {
      callCount++
      expect(purls.length).toBeGreaterThan(0)
    }

    const scanner = createScanner({
      maxSending: 10,
      maxBatchLength: 3,
      fetchStrategy
    })

    const results = scanner([...mockPackages])

    for await (const artifacts of results) {
      // Consume results
    }

    // 3 packages with maxBatchLength of 3 should make exactly 1 call
    expect(callCount).toBe(1)
  })

  test('should handle empty package list', async () => {
    let callCount = 0
    const fetchStrategy = async (purls: string[], artifacts: SocketArtifact[]) => {
      callCount++
    }

    const scanner = createScanner({
      maxSending: 10,
      maxBatchLength: 5,
      fetchStrategy
    })

    const results = scanner([])

    for await (const artifacts of results) {
      // Should not yield anything
    }

    expect(callCount).toBe(0)
  })

  test('should respect maxSending with concurrent requests', async () => {
    let maxConcurrent = 0
    let currentInFlight = 0
    const delays: Promise<void>[] = []

    const fetchStrategy = async (purls: string[], artifacts: SocketArtifact[]) => {
      currentInFlight += purls.length
      maxConcurrent = Math.max(maxConcurrent, currentInFlight)

      // Simulate async work
      const delay = new Promise<void>(resolve => setTimeout(resolve, 10))
      delays.push(delay)
      await delay

      currentInFlight -= purls.length
    }

    const manyPackages = Array.from({ length: 50 }, (_, i) => ({
      name: `package${i}`,
      version: '1.0.0',
      requestedRange: '^1.0.0',
      tarball: `https://registry.npmjs.org/package${i}/-/package${i}-1.0.0.tgz`,
    }))

    const scanner = createScanner({
      maxSending: 10,
      maxBatchLength: 1,
      fetchStrategy
    })

    const results = scanner(manyPackages)

    for await (const artifacts of results) {
      // Consume results
    }

    // Should never exceed maxSending
    expect(maxConcurrent).toBeLessThanOrEqual(10)
  })

  test('should yield artifacts progressively with maxBatchLength', async () => {
    let batchIndex = 0
    const fetchStrategy = async (purls: string[], artifacts: SocketArtifact[]) => {
      artifacts.push({
        inputPurl: `batch-${batchIndex++}`,
        alerts: []
      })
    }

    const scanner = createScanner({
      maxSending: 10,
      maxBatchLength: 1,
      fetchStrategy
    })

    const packages = [mockPackages[0]!, mockPackages[1]!]
    const results = scanner(packages)
    const yielded: number[] = []

    for await (const artifacts of results) {
      yielded.push(artifacts.length)
    }

    // Should yield twice, once per batch
    expect(yielded.length).toEqual(2)
  })
})
