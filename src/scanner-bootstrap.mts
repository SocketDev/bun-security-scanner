import Bun from 'bun'
import { Buffer } from 'node:buffer'
import os from 'node:os'
import path from 'node:path'
import process from 'node:process'
import { getDefaultLogger } from '@socketsecurity/lib/logger/default'
import { readSocketApiTokenSync } from '@socketsecurity/lib/secrets/socket-api-token'
import { getXdgDataHome } from '@socketsecurity/lib/env/xdg'
import { artifactsToAdvisories } from './advisories.mts'
import { authenticated } from './modes/authenticated.mts'
import { unauthenticated } from './modes/unauthenticated.mts'
import type { ScannerImplementation } from './types.mts'

const logger = getDefaultLogger()

export interface ScannerTokenConfig {
  envToken: string | undefined
  platform: NodeJS.Platform
  home: string
  xdgDataHome: string | undefined
  localAppData: string | undefined
  readSettings: (filename: string) => Promise<string | undefined>
  warn: (message: string) => void
}

export async function bootstrapScanner(): Promise<Bun.Security.Scanner> {
  const token = await resolveScannerToken({
    envToken: readSocketApiTokenSync({ allowEnvOnly: true }),
    platform: process.platform,
    home: os.homedir(),
    xdgDataHome: getXdgDataHome(),
    localAppData: Bun.env['LOCALAPPDATA'],
    async readSettings(filename) {
      const file = Bun.file(filename)
      return (await file.exists()) ? await file.text() : undefined
    },
    warn: message => logger.warn(message),
  })
  if (!token) {
    logger.warn(
      'Socket Security Scanner free mode. Set SOCKET_API_TOKEN to use your Socket org settings.',
    )
  }
  return createSecurityScanner(token ? authenticated(token) : unauthenticated())
}

export function createSecurityScanner(
  implementation: ScannerImplementation,
): Bun.Security.Scanner {
  return {
    async scan({ packages }) {
      const results: Bun.Security.Advisory[] = []
      while (packages.length) {
        for await (const artifacts of implementation(packages)) {
          results.push(...artifactsToAdvisories(artifacts))
        }
      }
      return results
    },
    version: '1',
  }
}

export async function resolveScannerToken(
  config: ScannerTokenConfig,
): Promise<string | undefined> {
  if (config.envToken?.trim()) {
    return config.envToken
  }
  let dataHome =
    config.platform === 'win32' ? config.localAppData : config.xdgDataHome
  if (!dataHome) {
    if (config.platform === 'win32') {
      throw new Error('missing %LOCALAPPDATA%')
    }
    dataHome = path.join(
      config.home,
      ...(config.platform === 'darwin'
        ? ['Library', 'Application Support']
        : ['.local', 'share']),
    )
  }
  const settingsPath = path.join(dataHome, 'socket', 'settings')
  for (const filename of [
    settingsPath,
    path.join(settingsPath, 'config.json'),
  ]) {
    try {
      const raw = await config.readSettings(filename)
      if (raw === undefined) {
        continue
      }
      const settings: unknown = JSON.parse(
        Buffer.from(raw, 'base64').toString('utf8').trim(),
      )
      if (
        typeof settings === 'object' &&
        settings !== null &&
        'apiToken' in settings &&
        typeof settings.apiToken === 'string' &&
        settings.apiToken.trim()
      ) {
        return settings.apiToken
      }
      throw new Error('Invalid token shape')
    } catch {
      config.warn(
        `Socket Security Scanner: cannot read the Socket settings file.\n  Where: ${filename}\n  Saw: unreadable or invalid settings.\n  Wanted: base64-encoded JSON with a nonempty string "apiToken" field.\n  Fix: re-run \`socket login\` or set SOCKET_API_TOKEN in the environment.\n  Continuing to the next credential source.`,
      )
    }
  }
  return undefined
}
