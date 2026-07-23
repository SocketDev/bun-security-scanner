// socket-lint: mirror-exempt — fast-check fuzz suite complementing the unit mirror scanner-factory.test.ts; renaming to the source basename would collide with it
/**
 * @file Property/fuzz tests for src/scanner-factory (Tier-1 fast-check).
 *   `createScanner` returns an async generator that batches an input list of
 *   packages, turns each into a `pkg:npm/<name>@<version>` purl, hands batches
 *   to an injected `fetchStrategy`, throttles concurrency at `maxSending`, and
 *   yields artifacts that `fetchStrategy` pushes into the shared array.
 *   The load-bearing contracts, read from source, are:
 *
 *   - every input package produces exactly one purl, in input order (no drop, no
 *     dup, no reorder);
 *   - batches are non-empty, bounded by `maxBatchLength`, and partition the input
 *     (only the final batch may be short);
 *   - every artifact a synchronous `fetchStrategy` pushes is yielded exactly once
 *     (conservation). Arbitraries are CONSTRUCTED so the expected outcome is
 *     known up front — the expected purls are built from the input packages
 *     with the same template the module documents, never imported from src, so
 *     the oracle is not a reimplementation of the SUT.
 */

import { describe, expect, test } from 'bun:test'
import fc from 'fast-check'

import { createScanner } from '../src/scanner-factory'
import type { SocketArtifact } from '../src/types'

// A minimal Bun.Security.Package. `name`/`version` feed pure string
// interpolation in the SUT, so arbitrary strings (unicode, `@`, `/`, control
// chars) are all valid inputs — nothing parses them.
const packageArb = fc
  .record({ name: fc.string(), version: fc.string() })
  .map(({ name, version }) => ({
    name,
    version,
    requestedRange: '*',
    tarball: '',
  }))

const packagesArb = fc.array(packageArb, { maxLength: 60 })

// maxBatchLength >= 1 (a batch always holds at least one package once it
// flushes) and maxSending >= 1. Ranges span N so the concurrency-throttle
// `await` path (in_flight >= maxSending) is exercised for real.
const configArb = fc.record({
  maxSending: fc.integer({ min: 1, max: 50 }),
  maxBatchLength: fc.integer({ min: 1, max: 20 }),
})

// The purl template the module documents. Kept here as the test's own spec so
// the expected side of every assertion is derived from the input, not the SUT.
function purlOf(pkg: { name: string; version: string }): string {
  return `pkg:npm/${pkg.name}@${pkg.version}`
}

describe('scanner-factory (fuzz)', () => {
  // ROUND-TRIP / derived-from-input + never-throws: the generator drives one
  // purl per package, in input order, and only ever yields arrays.
  test('sends exactly one purl per package, in input order', async () => {
    await fc.assert(
      fc.asyncProperty(packagesArb, configArb, async (pkgs, cfg) => {
        const seen: string[] = []
        const fetchStrategy = async (
          purls: string[],
          _artifacts: SocketArtifact[],
        ) => {
          seen.push(...purls)
        }
        const scan = createScanner({ ...cfg, fetchStrategy })
        for await (const chunk of scan([...pkgs])) {
          expect(Array.isArray(chunk)).toBe(true)
        }
        const expected = pkgs.map(purlOf)
        expect(seen).toEqual(expected)
      }),
    )
  })

  // INVARIANT: batches are non-empty, bounded by maxBatchLength, partition the
  // input, and there are exactly ceil(N / maxBatchLength) of them with only the
  // last one allowed to be short.
  test('batches are bounded, non-empty, and partition the input', async () => {
    await fc.assert(
      fc.asyncProperty(packagesArb, configArb, async (pkgs, cfg) => {
        const sizes: number[] = []
        const fetchStrategy = async (
          purls: string[],
          _artifacts: SocketArtifact[],
        ) => {
          sizes.push(purls.length)
        }
        const scan = createScanner({ ...cfg, fetchStrategy })
        for await (const chunk of scan([...pkgs])) {
          expect(Array.isArray(chunk)).toBe(true)
        }
        const total = sizes.reduce((a, b) => a + b, 0)
        expect(total).toBe(pkgs.length)
        expect(sizes.length).toBe(Math.ceil(pkgs.length / cfg.maxBatchLength))
        for (let i = 0, { length } = sizes; i < length; i += 1) {
          const size = sizes[i]!
          expect(size).toBeGreaterThanOrEqual(1)
          expect(size).toBeLessThanOrEqual(cfg.maxBatchLength)
        }
        // Every batch but the last is a full batch.
        for (let i = 0; i < sizes.length - 1; i += 1) {
          expect(sizes[i]).toBe(cfg.maxBatchLength)
        }
      }),
    )
  })

  // CONSERVATION: a fetchStrategy that synchronously pushes one uniquely-tagged
  // artifact per purl has every artifact yielded exactly once — no loss, no
  // duplication — across the whole concurrency range (including maxSending==1,
  // which forces the throttle + intermediate-yield path).
  test('yields every synchronously-pushed artifact exactly once', async () => {
    await fc.assert(
      fc.asyncProperty(packagesArb, configArb, async (pkgs, cfg) => {
        let counter = 0
        const fetchStrategy = async (
          purls: string[],
          artifacts: SocketArtifact[],
        ) => {
          for (let i = 0, { length } = purls; i < length; i += 1) {
            const purl = purls[i]!
            artifacts.push({ inputPurl: `${purl}#${counter}`, alerts: [] })
            counter += 1
          }
        }
        const scan = createScanner({ ...cfg, fetchStrategy })
        const got: SocketArtifact[] = []
        for await (const chunk of scan([...pkgs])) {
          got.push(...chunk)
        }
        // One artifact per package, all present, all distinct.
        expect(got.length).toBe(pkgs.length)
        const ids = got.map(a => a.inputPurl)
        expect(new Set(ids).size).toBe(ids.length)
      }),
    )
  })

  // INVARIANT: fetchStrategy is never invoked with an empty batch, for any
  // input/config.
  test('never invokes fetchStrategy with an empty batch', async () => {
    await fc.assert(
      fc.asyncProperty(packagesArb, configArb, async (pkgs, cfg) => {
        let sawEmpty = false
        const fetchStrategy = async (
          purls: string[],
          _artifacts: SocketArtifact[],
        ) => {
          if (purls.length === 0) {
            sawEmpty = true
          }
        }
        const scan = createScanner({ ...cfg, fetchStrategy })
        for await (const chunk of scan([...pkgs])) {
          expect(Array.isArray(chunk)).toBe(true)
        }
        expect(sawEmpty).toBe(false)
      }),
    )
  })

  // REGRESSION: createScanner must not drop artifacts pushed by an in-flight
  // fetchStrategy after an intermediate `yield`.
  //
  // The scanner once drained via `const tmp = artifacts; artifacts = []; yield
  // tmp`, rebinding `artifacts` to a fresh array. Flights started earlier still
  // held the OLD reference, and the real modes push their results only after a
  // network await (`const data = await res.text(); artifacts.push(...)`), so a
  // flight still in flight when the reset happened pushed into the orphaned
  // array — whose contents were never yielded again, silently dropping alerts
  // for every flight that resolved after a reset. The fix keeps one stable
  // array and drains with `splice(0)`.
  //
  // Deterministic repro models the real post-`await res.text()` push with a
  // macrotask defer (setTimeout): 2 packages, one batch each, maxSending=1 —
  // package "b"'s flight resolves after the intermediate yield. A single
  // microtask defer (`await Promise.resolve()`) lands before the old reset and
  // hid the bug; real I/O does not.
  test('conservation holds for deferred (post-await) pushes', async () => {
    const pkgs = [
      { name: 'a', version: '1', requestedRange: '*', tarball: '' },
      { name: 'b', version: '1', requestedRange: '*', tarball: '' },
    ]
    const fetchStrategy = async (
      purls: string[],
      artifacts: SocketArtifact[],
    ) => {
      // Model the real modes: results arrive only after a network round-trip,
      // i.e. a macrotask later — after the generator's intermediate yield.
      await new Promise<void>(resolve => {
        setTimeout(resolve, 0)
      })
      for (let i = 0, { length } = purls; i < length; i += 1) {
        const purl = purls[i]!
        artifacts.push({ inputPurl: purl, alerts: [] })
      }
    }
    const scan = createScanner({
      maxSending: 1,
      maxBatchLength: 1,
      fetchStrategy,
    })
    const got: SocketArtifact[] = []
    for await (const chunk of scan([...pkgs])) {
      got.push(...chunk)
    }
    // Every package's artifact survives — no silent drop.
    expect(got.length).toBe(pkgs.length)
  })
})
