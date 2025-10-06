import type Bun from 'bun'
import path from 'node:path'
import os from 'node:os'
import authenticated from './modes/authenticated'
import unauthenticated from './modes/unauthenticated'

let SOCKET_API_KEY = process.env.SOCKET_API_KEY

if (typeof SOCKET_API_KEY !== 'string') {
  // get OS app data directory
  let dataHome = process.platform === 'win32'
      ? Bun.env.LOCALAPPDATA
      : Bun.env.XDG_DATA_HOME

  // fallback
  if (!dataHome) {
    if (process.platform === 'win32') throw new Error('missing %LOCALAPPDATA%')

    const home = os.homedir()

    dataHome = path.join(home, ...(process.platform === 'darwin'
      ? ['Library', 'Application Support']
      : ['.local', 'share']
    ))
  }

  // append `socket/settings`
  const defaultSettingsPath = path.join(dataHome, 'socket', 'settings')
  const file = Bun.file(defaultSettingsPath)

  // attempt to read token from socket settings
  if (await file.exists()) {
    const rawContent = await file.text()
    // rawContent is base64, must decode

    try {
      SOCKET_API_KEY = JSON.parse(Buffer.from(rawContent, 'base64').toString().trim()).apiToken
    } catch {
      throw new Error('error reading Socket settings')
    }
  }
}

if (!SOCKET_API_KEY) {
  console.log(`⚠ Socket Security Scanner free mode. Set SOCKET_API_KEY to use your Socket org settings.`)
}

const scannerImplementation = SOCKET_API_KEY ? authenticated(SOCKET_API_KEY) : unauthenticated()

export const scanner: Bun.Security.Scanner = {
  version: '1',
  async scan({ packages }: { packages: Array<Bun.Security.Package> }) {
    const results: Bun.Security.Advisory[] = []

    while (packages.length) {
      const scanResults = scannerImplementation(packages)

      for await (const artifacts of scanResults) {
        for (const artifact of artifacts) {
          if (artifact.alerts && artifact.alerts.length > 0) {
            for (const alert of artifact.alerts) {
              let description = ''

              if (alert.type === 'didYouMean') {
                description = `This package could be a typo-squatting attempt of another package (${alert.props.alternatePackage}).`
              }
              if (alert.props.description) {
                description = description ? `${description}\n\n${alert.props.description}` : alert.props.description
              }
              if (alert.props.note) {
                description = description ? `${description}\n\n${alert.props.note}` : alert.props.note
              }
              const fix = alert.fix?.description
              if (fix) {
                description = description ? `${description}\n\nFix: ${fix}` : `Fix: ${fix}`
              }

              results.push({
                level: alert.action === 'error' ? 'fatal' : 'warn',
                package: artifact.inputPurl,
                url: null,
                description
              })
            }
          }
        }
      }
    }
    return results
  }
}
