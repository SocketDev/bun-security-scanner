import { describe, expect, test } from 'bun:test'
import { createSecurityScanner } from '../src/scanner-bootstrap.mts'

describe('scanner composition', () => {
  test('accumulates batches and preserves fatal advisory mapping', async () => {
    const scanner = createSecurityScanner(async function* (packages) {
      packages.shift()
      yield [
        {
          inputPurl: 'pkg:npm/example-package@1.0.0',
          alerts: [
            {
              action: 'error',
              type: 'malware',
              props: { notes: 'Fixture warning' },
            },
          ],
        },
      ]
    })
    const packageFixture = {
      name: 'example-package',
      version: '1.0.0',
      requestedRange: '1.0.0',
      tarball:
        'https://registry.npmjs.org/example-package/-/example-package-1.0.0.tgz',
    }
    const result = await scanner.scan({
      packages: [packageFixture, packageFixture],
    })
    expect(result).toHaveLength(2)
    expect(result[0]!.level).toBe('fatal')
    expect(result[0]!.description).toContain('Fixture warning')
    expect(await scanner.scan({ packages: [] })).toEqual([])
  })
})
