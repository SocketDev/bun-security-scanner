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
    const fetchStrategy = async (purls: string[]) => {
      capturedPurls.push(...purls)
      return []
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
    const fetchStrategy = async (purls: string[]) => {
      batchSizes.push(purls.length)
      return []
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

    const fetchStrategy = async (purls: string[]) => {
      return [...mockArtifacts]
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
    const fetchStrategy = async (purls: string[]) => {
      callCount++
      expect(purls.length).toBeGreaterThan(0)
      return []
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
    const fetchStrategy = async (purls: string[]) => {
      callCount++
      return []
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

    const fetchStrategy = async (purls: string[]) => {
      currentInFlight += purls.length
      maxConcurrent = Math.max(maxConcurrent, currentInFlight)

      // Simulate async work
      const delay = new Promise<void>(resolve => setTimeout(resolve, 10))
      delays.push(delay)
      await delay

      currentInFlight -= purls.length
      return []
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
    const fetchStrategy = async (purls: string[]) => {
      return [{
        inputPurl: `batch-${batchIndex++}`,
        alerts: []
      }]
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

// Helper to create a promise whose resolution is controlled externally
function deferred<T>() {
  let resolve!: (value: T) => void
  const promise = new Promise<T>(r => { resolve = r })
  return { promise, resolve }
}

function makePkg(name: string, version = '1.0.0'): Bun.Security.Package {
  return {
    name,
    version,
    requestedRange: `^${version}`,
    tarball: `https://registry.npmjs.org/${name}/-/${name}-${version}.tgz`,
  }
}

function makeArtifact(purl: string): SocketArtifact {
  return { inputPurl: purl, alerts: [{ action: 'error', type: 'test', props: {} }] }
}

describe('scanner-factory race condition regression', () => {
  test('late-resolving flight delivers artifacts after array swap', async () => {
    // Flight 1 (pkg-a) is launched, doesn't resolve yet.
    // Flight 2 (pkg-b) is launched and resolves immediately, triggering a yield + swap.
    // Flight 1 then resolves. Its artifact must not be lost.
    const gate = deferred<SocketArtifact[]>()
    let call = 0

    const fetchStrategy = async (purls: string[]) => {
      call++
      if (call === 1) {
        // First flight: wait until we release the gate
        return gate.promise
      }
      // Second flight: resolve immediately
      return purls.map(p => makeArtifact(p))
    }

    const scanner = createScanner({ maxSending: 30, maxBatchLength: 1, fetchStrategy })
    const results = scanner([makePkg('pkg-a'), makePkg('pkg-b')])
    const allArtifacts: SocketArtifact[] = []

    // Start consuming the async generator. After pkg-b's flight resolves
    // immediately, the generator yields and swaps artifacts = [].
    // Then release pkg-a's flight so it resolves into the new array.
    const consumer = (async () => {
      for await (const batch of results) {
        allArtifacts.push(...batch)
        // After the first yield, release the slow flight
        if (call >= 2) {
          gate.resolve([makeArtifact('pkg:npm/pkg-a@1.0.0')])
        }
      }
    })()

    await consumer

    const purls = allArtifacts.map(a => a.inputPurl).sort()
    expect(purls).toEqual(['pkg:npm/pkg-a@1.0.0', 'pkg:npm/pkg-b@1.0.0'])
  })

  test('all flights pending until final drain collects every artifact', async () => {
    // All flights stay pending until after the while-loop ends.
    // Everything should be collected at the final `await Promise.all` + yield.
    const gates: { resolve: (v: SocketArtifact[]) => void }[] = []

    const fetchStrategy = async (purls: string[]) => {
      const d = deferred<SocketArtifact[]>()
      gates.push(d)
      return d.promise
    }

    const packages = Array.from({ length: 5 }, (_, i) => makePkg(`pkg${i}`))

    const scanner = createScanner({ maxSending: 30, maxBatchLength: 1, fetchStrategy })
    const results = scanner([...packages])
    const allArtifacts: SocketArtifact[] = []

    // Start consuming — the generator will loop through all packages, launching
    // flights that never resolve, so no intermediate yields happen.
    // After all packages are dispatched, it hits `await Promise.all([...pending])`.
    // We then resolve all gates.
    const consumer = (async () => {
      for await (const batch of results) {
        allArtifacts.push(...batch)
      }
    })()

    // Wait a tick for all flights to be dispatched
    await new Promise(r => setTimeout(r, 10))

    // Now resolve all gates
    for (let i = 0; i < gates.length; i++) {
      gates[i]!.resolve([makeArtifact(`pkg:npm/pkg${i}@1.0.0`)])
    }

    await consumer

    expect(allArtifacts.length).toBe(5)
    const purls = allArtifacts.map(a => a.inputPurl).sort()
    expect(purls).toEqual(
      Array.from({ length: 5 }, (_, i) => `pkg:npm/pkg${i}@1.0.0`).sort()
    )
  })

  test('staggered resolution across multiple yield cycles loses nothing', async () => {
    // Odd-numbered flights resolve slowly, even-numbered resolve instantly.
    // With maxBatchLength=1 this forces multiple yield+swap cycles with
    // in-flight stragglers from previous cycles.
    const gates: { resolve: (v: SocketArtifact[]) => void }[] = []

    const fetchStrategy = async (purls: string[]) => {
      const purl = purls[0]!
      const idx = parseInt(purl.match(/pkg(\d+)/)![1]!)
      if (idx % 2 === 1) {
        // Odd: delay resolution
        const d = deferred<SocketArtifact[]>()
        gates.push({ resolve: (v) => d.resolve(v) })
        return d.promise
      }
      // Even: resolve immediately
      return [makeArtifact(purl)]
    }

    const packages = Array.from({ length: 8 }, (_, i) => makePkg(`pkg${i}`))

    const scanner = createScanner({ maxSending: 30, maxBatchLength: 1, fetchStrategy })
    const results = scanner([...packages])
    const allArtifacts: SocketArtifact[] = []

    const consumer = (async () => {
      for await (const batch of results) {
        allArtifacts.push(...batch)
      }
    })()

    // Wait for all flights to be dispatched, then release the slow ones
    await new Promise(r => setTimeout(r, 20))
    for (let i = 0; i < gates.length; i++) {
      const oddIdx = i * 2 + 1
      gates[i]!.resolve([makeArtifact(`pkg:npm/pkg${oddIdx}@1.0.0`)])
    }

    await consumer

    expect(allArtifacts.length).toBe(8)
    const purls = allArtifacts.map(a => a.inputPurl).sort()
    expect(purls).toEqual(
      Array.from({ length: 8 }, (_, i) => `pkg:npm/pkg${i}@1.0.0`).sort()
    )
  })

  test('authenticated-mode scenario: 50+ packages with maxBatchLength=1 and maxSending=30', async () => {
    // Mirrors the real customer config that triggered the bug report.
    // Variable latency with high concurrency — every artifact must survive.
    const fetchStrategy = async (purls: string[]) => {
      await new Promise<void>(r => setTimeout(r, Math.random() * 30))
      return purls.map(p => makeArtifact(p))
    }

    const packages = Array.from({ length: 60 }, (_, i) => makePkg(`dep${i}`))

    const scanner = createScanner({ maxSending: 30, maxBatchLength: 1, fetchStrategy })
    const results = scanner([...packages])
    const allArtifacts: SocketArtifact[] = []

    for await (const batch of results) {
      allArtifacts.push(...batch)
    }

    expect(allArtifacts.length).toBe(60)
    const purls = allArtifacts.map(a => a.inputPurl).sort()
    const expected = packages.map(p => `pkg:npm/${p.name}@${p.version}`).sort()
    expect(purls).toEqual(expected)
  })

  test('artifacts from a flight that resolves during yield are not lost', async () => {
    // Specifically tests: flight 1 resolves, generator yields and swaps,
    // and flight 2 resolves during that same tick. Flight 2's results
    // must land in the new array, not the old one.
    let flightCount = 0
    const slow = deferred<SocketArtifact[]>()

    const fetchStrategy = async (purls: string[]) => {
      flightCount++
      if (flightCount <= 2) {
        // First two flights resolve immediately
        return purls.map(p => makeArtifact(p))
      }
      // Third flight: delayed
      return slow.promise
    }

    const scanner = createScanner({ maxSending: 30, maxBatchLength: 1, fetchStrategy })
    const results = scanner([makePkg('a'), makePkg('b'), makePkg('c')])
    const allArtifacts: SocketArtifact[] = []
    let yieldCount = 0

    const consumer = (async () => {
      for await (const batch of results) {
        yieldCount++
        allArtifacts.push(...batch)
        // After first yield, resolve the slow flight
        if (yieldCount === 1) {
          slow.resolve([makeArtifact('pkg:npm/c@1.0.0')])
        }
      }
    })()

    await consumer

    const purls = allArtifacts.map(a => a.inputPurl).sort()
    expect(purls).toEqual(['pkg:npm/a@1.0.0', 'pkg:npm/b@1.0.0', 'pkg:npm/c@1.0.0'])
  })
})
