import Bun from 'bun'
import path from 'node:path'
import os from 'node:os'
import { artifactsToAdvisories, parseNpmPurl } from './advisories'
import { authenticated } from './modes/authenticated'
import { unauthenticated } from './modes/unauthenticated'
import { getDefaultLogger } from '@socketsecurity/lib/logger/default'
import { readSocketApiTokenSync } from '@socketsecurity/lib/secrets/socket-api-token'
import { getXdgDataHome } from '@socketsecurity/lib/env/xdg'

// Re-exported for backwards compatibility: `parseNpmPurl` used to live here.
// The alert→advisory mapping and purl parsing now live in the side-effect-free
// `./advisories` module so they're unit testable without this file's
// module-init token bootstrap.
export { parseNpmPurl }

const logger = getDefaultLogger()

// Bootstrap: env aliases first (SOCKET_API_TOKEN canonical, SOCKET_API_KEY
// legacy — the release workflows export the org secret under the legacy
// name), then the Socket settings file fallback below. Env-only: a keychain
// prompt is unacceptable inside `bun install`.
let socketApiToken = readSocketApiTokenSync({ allowEnvOnly: true })

if (typeof socketApiToken !== 'string') {
  // get OS app data directory (getXdgDataHome only reads $XDG_DATA_HOME; the
  // win32 LOCALAPPDATA + darwin Application Support fallbacks stay hand-rolled)
  let dataHome =
    process.platform === 'win32' ? Bun.env.LOCALAPPDATA : getXdgDataHome()

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

export const scanner: Bun.Security.Scanner = {
  async scan({ packages }: { packages: Bun.Security.Package[] }) {
    const results: Bun.Security.Advisory[] = []

    while (packages.length) {
      const scanResults = scannerImplementation(packages)

      for await (const artifacts of scanResults) {
        results.push(...artifactsToAdvisories(artifacts))
      }
    }
    return results
  },
  version: '1',
}
