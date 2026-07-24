import Bun from 'bun'
import path from 'node:path'
import os from 'node:os'
import { PackageURL } from '@socketregistry/packageurl-js'
import { authenticated } from './modes/authenticated'
import { unauthenticated } from './modes/unauthenticated'
import { getDefaultLogger } from '@socketsecurity/lib-stable/logger/default'
import { readSocketApiTokenSync } from '@socketsecurity/lib-stable/secrets/socket-api-token'

const logger = getDefaultLogger()

// Bootstrap: env aliases first (SOCKET_API_TOKEN canonical, SOCKET_API_KEY
// legacy — the release workflows export the org secret under the legacy
// name), then the Socket settings file fallback below. Env-only: a keychain
// prompt is unacceptable inside `bun install`.
let socketApiToken = readSocketApiTokenSync({ allowEnvOnly: true })

if (typeof socketApiToken !== 'string') {
  // get OS app data directory
  let dataHome =
    process.platform === 'win32' ? Bun.env.LOCALAPPDATA : Bun.env.XDG_DATA_HOME

  // fallback
  if (!dataHome) {
    if (process.platform === 'win32') {
      throw new Error('missing %LOCALAPPDATA%')
    }

    const home = os.homedir()

    dataHome = path.join(
      home,
      ...(process.platform === 'darwin'
        ? ['Library', 'Application Support']
        : ['.local', 'share']),
    )
  }

  // append `socket/settings`
  const defaultSettingsPath = path.join(dataHome, 'socket', 'settings')
  const file = Bun.file(defaultSettingsPath)

  // attempt to read token from socket settings. This module is a Bun-only
  // ESM plugin entry point and never bundles to CJS.
  // socket-lint: allow top-level-await
  if (await file.exists()) {
    // socket-lint: allow top-level-await
    const rawContent = await file.text()
    // rawContent is base64, must decode

    try {
      socketApiToken = JSON.parse(
        Buffer.from(rawContent, 'base64').toString().trim(),
      ).apiToken
    } catch {
      throw new Error('error reading Socket settings')
    }
  }
}

if (!socketApiToken) {
  logger.warn(
    `Socket Security Scanner free mode. Set SOCKET_API_TOKEN to use your Socket org settings.`,
  )
}

const scannerImplementation = socketApiToken
  ? authenticated(socketApiToken)
  : unauthenticated()

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
    if (!version) {
      return undefined
    }
    return { name: namespace ? `${namespace}/${name}` : name, version }
  } catch {
    return undefined
  }
}

export const scanner: Bun.Security.Scanner = {
  async scan({ packages }: { packages: Bun.Security.Package[] }) {
    const results: Bun.Security.Advisory[] = []

    while (packages.length) {
      const scanResults = scannerImplementation(packages)

      for await (const artifacts of scanResults) {
        for (const artifact of artifacts) {
          if (artifact.alerts && artifact.alerts.length > 0) {
            for (const alert of artifact.alerts) {
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

              const parsed = parseNpmPurl(artifact.inputPurl)

              if (!parsed) {
                continue
              }

              const { name, version } = parsed

              const url = `https://socket.dev/npm/package/${name}/overview/${version}`

              results.push({
                level: alert.action === 'error' ? 'fatal' : 'warn',
                package: artifact.inputPurl,
                url,
                description: description.join('\n\n') + '\n',
              })
            }
          }
        }
      }
    }
    return results
  },
  version: '1',
}
