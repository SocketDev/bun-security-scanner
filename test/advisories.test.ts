import { describe, expect, test } from 'bun:test'
import { artifactsToAdvisories, parseNpmPurl } from '../src/advisories'
import type { SocketArtifact } from '../src/types'

describe('parseNpmPurl', () => {
  test('parses an unscoped npm purl', () => {
    expect(parseNpmPurl('pkg:npm/lodash@4.17.21')).toEqual({
      name: 'lodash',
      version: '4.17.21',
    })
  })

  test('parses a scoped npm purl, rejoining namespace and name', () => {
    expect(parseNpmPurl('pkg:npm/%40scope/pkg@1.2.3')).toEqual({
      name: '@scope/pkg',
      version: '1.2.3',
    })
  })

  test('decodes a percent-encoded scope the API can emit', () => {
    // `%40angular` is the percent-encoded form of `@angular`.
    expect(parseNpmPurl('pkg:npm/%40angular/core@17.0.0')).toEqual({
      name: '@angular/core',
      version: '17.0.0',
    })
  })

  test('returns undefined when the version is missing', () => {
    expect(parseNpmPurl('pkg:npm/lodash')).toBeUndefined()
  })

  test('returns undefined for a malformed purl', () => {
    expect(parseNpmPurl('not-a-purl')).toBeUndefined()
    expect(parseNpmPurl('')).toBeUndefined()
  })
})

describe('artifactsToAdvisories', () => {
  function artifact(
    overrides: Partial<SocketArtifact> & {
      alerts?: SocketArtifact['alerts']
    } = {},
  ): SocketArtifact {
    return {
      inputPurl: 'pkg:npm/lodash@4.17.21',
      alerts: [],
      ...overrides,
    }
  }

  test('returns an empty list for no artifacts', () => {
    expect(artifactsToAdvisories([])).toEqual([])
  })

  test('skips an artifact with no alerts', () => {
    expect(artifactsToAdvisories([artifact({ alerts: [] })])).toEqual([])
  })

  test('maps an error alert to a fatal advisory', () => {
    const advisories = artifactsToAdvisories([
      artifact({
        alerts: [{ action: 'error', type: 'malware', props: {} }],
      }),
    ])

    expect(advisories).toHaveLength(1)
    expect(advisories[0]).toMatchObject({
      level: 'fatal',
      package: 'pkg:npm/lodash@4.17.21',
      url: 'https://socket.dev/npm/package/lodash/overview/4.17.21',
    })
  })

  test('maps a warn alert to a warn advisory', () => {
    const advisories = artifactsToAdvisories([
      artifact({
        alerts: [{ action: 'warn', type: 'deprecation', props: {} }],
      }),
    ])

    expect(advisories[0]!.level).toBe('warn')
  })

  test('builds the scoped socket.dev overview URL', () => {
    const advisories = artifactsToAdvisories([
      artifact({
        inputPurl: 'pkg:npm/%40scope/pkg@1.2.3',
        alerts: [{ action: 'error', type: 'malware', props: {} }],
      }),
    ])

    expect(advisories[0]!.url).toBe(
      'https://socket.dev/npm/package/@scope/pkg/overview/1.2.3',
    )
  })

  test('prepends the typo-squat hint for a didYouMean alert', () => {
    const advisories = artifactsToAdvisories([
      artifact({
        alerts: [
          {
            action: 'warn',
            type: 'didYouMean',
            props: { alternatePackage: 'lodash' },
          },
        ],
      }),
    ])

    expect(advisories[0]!.description).toBe(
      '\n\nThis package could be a typo-squatting attempt of another package (lodash).\n',
    )
  })

  test('omits the typo-squat hint when alternatePackage is absent', () => {
    const advisories = artifactsToAdvisories([
      artifact({
        alerts: [{ action: 'warn', type: 'didYouMean', props: {} }],
      }),
    ])

    // No alternatePackage → no hint → the description is just the trailing
    // newline joined from the seed empty string.
    expect(advisories[0]!.description).toBe('\n')
  })

  test('assembles description, note, and fix joined by blank lines', () => {
    const advisories = artifactsToAdvisories([
      artifact({
        alerts: [
          {
            action: 'error',
            type: 'malware',
            props: { description: 'Malicious code', note: 'Seen in the wild' },
            fix: { description: 'Remove it' },
          },
        ],
      }),
    ])

    expect(advisories[0]!.description).toBe(
      '\n\nMalicious code\n\nSeen in the wild\n\nFix: Remove it\n',
    )
  })

  test('skips an artifact whose purl cannot be parsed, dropping all its alerts', () => {
    const advisories = artifactsToAdvisories([
      artifact({
        inputPurl: 'not-a-purl',
        alerts: [
          { action: 'error', type: 'malware', props: {} },
          { action: 'warn', type: 'deprecation', props: {} },
        ],
      }),
    ])

    expect(advisories).toEqual([])
  })

  test('emits one advisory per alert on an artifact', () => {
    const advisories = artifactsToAdvisories([
      artifact({
        alerts: [
          { action: 'error', type: 'malware', props: {} },
          { action: 'warn', type: 'deprecation', props: {} },
        ],
      }),
    ])

    expect(advisories.map(a => a.level)).toEqual(['fatal', 'warn'])
  })

  test('flattens alerts across multiple artifacts, skipping empty ones', () => {
    const advisories = artifactsToAdvisories([
      artifact({
        inputPurl: 'pkg:npm/a@1.0.0',
        alerts: [{ action: 'error', type: 'malware', props: {} }],
      }),
      artifact({ inputPurl: 'pkg:npm/b@2.0.0', alerts: [] }),
      artifact({
        inputPurl: 'pkg:npm/c@3.0.0',
        alerts: [{ action: 'warn', type: 'deprecation', props: {} }],
      }),
    ])

    expect(advisories.map(a => a.package)).toEqual([
      'pkg:npm/a@1.0.0',
      'pkg:npm/c@3.0.0',
    ])
  })
})
