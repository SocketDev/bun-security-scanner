import Bun from 'bun'
import path from 'node:path'
import os from 'node:os'

export async function resolveApiKey (): Promise<string | undefined> {
  if (typeof process.env.SOCKET_API_KEY === 'string') {
    return process.env.SOCKET_API_KEY
  }

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

  // attempt to read token from socket settings
  // supports both the legacy flat file and the CLI v2 directory layout
  const settingsPath = path.join(dataHome, 'socket', 'settings')
  const candidates = [
    Bun.file(settingsPath),
    Bun.file(path.join(settingsPath, 'config.json'))
  ]

  for (const file of candidates) {
    if (await file.exists()) {
      const rawContent = await file.text()
      // rawContent is base64, must decode

      try {
        return JSON.parse(Buffer.from(rawContent, 'base64').toString().trim()).apiToken
      } catch {
        throw new Error('error reading Socket settings')
      }
    }
  }

  return undefined
}
