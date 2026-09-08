import { expect, test } from 'bun:test'
import { rolldown } from 'rolldown'
import { buildConfig } from '../../../.config/repo/rolldown.config.mts'

test('source output retains license notices without dependency documentation examples', async () => {
  const fixture = 'fixture:dependency-comments'
  const bundle = await rolldown({
    input: fixture,
    plugins: [
      {
        name: 'dependency-comment-fixture',
        resolveId(id) {
          return id === fixture ? id : undefined
        },
        load(id) {
          if (id !== fixture) {
            return undefined
          }
          return `/*! @license Example-License */
/** @example documentation-only fixture */
export function fixtureValue() { return 42 }
`
        },
      },
    ],
  })
  try {
    const result = await bundle.generate(buildConfig.output)
    expect(result.output).toHaveLength(1)
    const chunk = result.output[0]!
    expect(chunk.type).toBe('chunk')
    if (chunk.type !== 'chunk') {
      throw new Error('Expected the fixture JavaScript chunk.')
    }
    expect(chunk.code).toContain('@license Example-License')
    expect(chunk.code).not.toContain('documentation-only fixture')
    expect(chunk.code).toContain('return 42')
  } finally {
    await bundle.close()
  }
})
