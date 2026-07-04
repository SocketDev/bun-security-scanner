import Bun from 'bun'
import authenticated from './modes/authenticated'
import unauthenticated from './modes/unauthenticated'
import { resolveApiKey } from './resolve-api-key'

const SOCKET_API_KEY = await resolveApiKey()

if (!SOCKET_API_KEY) {
  console.log(`⚠ Socket Security Scanner free mode. Set SOCKET_API_KEY to use your Socket org settings.`)
}

const scannerImplementation = SOCKET_API_KEY ? authenticated(SOCKET_API_KEY) : unauthenticated()
const purlRegex = /^pkg:npm\/((?:@[^/]+\/)?(?:[^@]+))@(.+)$/

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
              const description = ['']

              if (alert.type === 'didYouMean') {
                description.push(`This package could be a typo-squatting attempt of another package (${alert.props.alternatePackage}).`)
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

              const match = artifact.inputPurl.match(purlRegex);

              if (!match) continue;

              const name = match[1];
              const version = match[2];

              const url = `https://socket.dev/npm/package/${name}/overview/${version}`

              results.push({
                level: alert.action === 'error' ? 'fatal' : 'warn',
                package: artifact.inputPurl,
                url,
                description: description.join('\n\n') + '\n'
              })
            }
          }
        }
      }
    }
    return results
  }
}
