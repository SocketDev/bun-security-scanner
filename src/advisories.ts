import type Bun from 'bun'
import { PackageURL } from '@socketregistry/packageurl-js'
import type { SocketArtifact } from './types'

/**
 * Map Socket artifacts to Bun security advisories. Pure — no I/O — so the
 * alert→advisory mapping (level, description assembly, overview URL) is unit
 * testable without the module-init token bootstrap that `index.ts` runs.
 *
 * Behavior contract (kept identical to the original inline `scan()` loop):
 * - An artifact with no alerts contributes nothing.
 * - An artifact whose `inputPurl` cannot be parsed is skipped entirely — its
 * socket.dev overview URL can't be built, and every alert on it shares that
 * same unparseable purl.
 * - `action: 'error'` maps to `level: 'fatal'`; anything else maps to `'warn'`
 * (Bun only recognizes `'fatal' | 'warn'`).
 * - The description is assembled from the typo-squat hint, the alert
 * description, the note, and the fix, joined by blank lines with a trailing
 * newline.
 */
export function artifactsToAdvisories(
  artifacts: SocketArtifact[],
): Bun.Security.Advisory[] {
  const advisories: Bun.Security.Advisory[] = []

  for (let i = 0, { length } = artifacts; i < length; i += 1) {
    const artifact = artifacts[i]!

    if (!artifact.alerts || artifact.alerts.length === 0) {
      continue
    }

    const parsed = parseNpmPurl(artifact.inputPurl)

    if (!parsed) {
      continue
    }

    const { name, version } = parsed
    const url = `https://socket.dev/npm/package/${name}/overview/${version}`
    const { alerts } = artifact

    for (let j = 0, alertCount = alerts.length; j < alertCount; j += 1) {
      const alert = alerts[j]!
      const description = ['']

      if (alert.type === 'didYouMean' && alert.props.alternatePackage) {
        description.push(
          `This package could be a typo-squatting attempt of another package (${alert.props.alternatePackage}).`,
        )
      }

      if (alert.props.description) {
        description.push(alert.props.description)
      }

      if (alert.props.note) {
        description.push(alert.props.note)
      }

      const fix = alert.fix?.description

      if (fix) {
        description.push(`Fix: ${fix}`)
      }

      advisories.push({
        level: alert.action === 'error' ? 'fatal' : 'warn',
        package: artifact.inputPurl,
        url,
        description: description.join('\n\n') + '\n',
      })
    }
  }

  return advisories
}

/**
 * Parse an npm purl into the `@scope/name` + version pair the socket.dev
 * overview URL wants. `PackageURL.fromString` decodes percent-encoded scopes
 * the API can legally emit in `inputPurl` (the old hand-rolled regex never
 * did); it throws on malformed purls, so map that to `undefined` to preserve
 * the skip-on-no-match behavior.
 */
export function parseNpmPurl(
  purl: string,
): { name: string; version: string } | undefined {
  try {
    const { name, namespace, version } = PackageURL.fromString(purl)
    if (!name || !version) {
      return undefined
    }
    return { name: namespace ? `${namespace}/${name}` : name, version }
  } catch {
    return undefined
  }
}
