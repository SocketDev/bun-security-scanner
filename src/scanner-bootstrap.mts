import Bun from 'bun'
import os from 'node:os'
import process from 'node:process'
import { getDefaultLogger } from '@socketsecurity/lib/logger/default'
import { readSocketApiTokenSync } from '@socketsecurity/lib/secrets/socket-api-token'
import { getXdgDataHome } from '@socketsecurity/lib/env/xdg'
import { artifactsToAdvisories } from './advisories.mts'
import { authenticated } from './modes/authenticated.mts'
import { unauthenticated } from './modes/unauthenticated.mts'
import { resolveScannerCredential } from './scanner/credentials.mts'
import type { ScannerImplementation } from './types.mts'

const logger = getDefaultLogger()

export async function bootstrapScanner(): Promise<Bun.Security.Scanner> {
  const credentials = await resolveScannerCredential(
    readSocketApiTokenSync({ allowEnvOnly: true }),
    {
      platform: process.platform,
      home: os.homedir(),
      xdgDataHome: getXdgDataHome(),
      localAppData: Bun.env['LOCALAPPDATA'],
    },
  )
  if (credentials.kind === 'absent') {
    logger.warn(
      'Socket Security Scanner free mode. Set SOCKET_API_TOKEN to use your Socket org settings.',
    )
  }
  return createSecurityScanner(
    credentials.kind === 'token'
      ? authenticated(credentials.token)
      : unauthenticated(),
  )
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
