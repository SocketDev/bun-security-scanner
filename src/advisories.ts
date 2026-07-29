import type Bun from 'bun'
import { PackageURL } from '@socketregistry/packageurl-js'
import type { SocketArtifact } from './types'

/**
 * Overview URL for an artifact whose `inputPurl` does not parse into a
 * socket.dev package path. A purl the parser rejects still carries alerts, so
 * the advisory ships with the site root instead of a package deep link.
 */
const FALLBACK_OVERVIEW_URL = 'https://socket.dev/'

/**
 * Map Socket artifacts to Bun security advisories. Pure — no I/O — so the
 * alert→advisory mapping (level, description assembly, overview URL) is unit
 * testable without the module-init token bootstrap that `index.ts` runs.
 *
 * Behavior contract:
 *
 * - An artifact with no alerts contributes nothing.
 * - Every alert becomes an advisory. An `inputPurl` the parser rejects (a
 *   `github:`/`file:` version spec, a non-npm ecosystem) degrades the overview
 *   URL to `FALLBACK_OVERVIEW_URL` and reports the raw `inputPurl` as the
 *   package identifier — a security signal is never gated on URL construction.
 * - `action: 'error'` maps to `level: 'fatal'`; anything else maps to `'warn'`
 *   (Bun only recognizes `'fatal' | 'warn'`).
 * - The description is assembled from the typo-squat hint, the alert description,
 *   the note, and the fix, joined by blank lines with a trailing newline.
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
    const url = parsed
      ? `https://socket.dev/npm/package/${parsed.name}/overview/${parsed.version}`
      : FALLBACK_OVERVIEW_URL
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
 * Parse an **npm** purl into the `@scope/name` + version pair the socket.dev
 * npm overview URL wants. `PackageURL.fromString` decodes percent-encoded
 * scopes the API can legally emit in `inputPurl`, and throws on a malformed
 * purl. A purl from another ecosystem parses cleanly but has no npm overview
 * page, so it is rejected here alongside the malformed and version-less ones —
 * `undefined` means "no npm deep link", never "drop the artifact".
 */
export function parseNpmPurl(
  purl: string,
): { name: string; version: string } | undefined {
  try {
    const { name, namespace, type, version } = PackageURL.fromString(purl)
    if (type !== 'npm' || !name || !version) {
      return undefined
    }
    return { name: namespace ? `${namespace}/${name}` : name, version }
  } catch {
    return undefined
  }
}
