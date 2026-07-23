import Bun from 'bun'
import path from 'node:path'
import os from 'node:os'
import { authenticated } from './modes/authenticated'
import { unauthenticated } from './modes/unauthenticated'
import { getDefaultLogger } from '@socketsecurity/lib-stable/logger/default'

const logger = getDefaultLogger()

// Bootstrap: this module resolves the token itself, with a Socket settings
// file fallback below. socket-api-token-getter: allow direct-env
let SOCKET_API_KEY = process.env.SOCKET_API_TOKEN

if (typeof SOCKET_API_KEY !== 'string') {
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
      SOCKET_API_KEY = JSON.parse(
        Buffer.from(rawContent, 'base64').toString().trim(),
      ).apiToken
    } catch {
      throw new Error('error reading Socket settings')
    }
  }
}

if (!SOCKET_API_KEY) {
  logger.warn(
    `Socket Security Scanner free mode. Set SOCKET_API_TOKEN to use your Socket org settings.`,
  )
}

const scannerImplementation = SOCKET_API_KEY
  ? authenticated(SOCKET_API_KEY)
  : unauthenticated()
// npm purl: `pkg:npm/` prefix, capture 1 = package name (optional `@scope/`
// then a name with no `@`), literal `@`, capture 2 = version (rest of string).
const purlRegex = /^pkg:npm\/((?:@[^/]+\/)?(?:[^@]+))@(.+)$/

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

              const match = artifact.inputPurl.match(purlRegex)

              if (!match) {
                continue
              }

              const name = match[1]
              const version = match[2]

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
