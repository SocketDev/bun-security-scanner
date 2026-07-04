import { expect, test, describe, beforeEach, afterEach } from 'bun:test'
import { resolveApiKey } from '../src/resolve-api-key'
import path from 'node:path'
import fs from 'node:fs'
import os from 'node:os'

describe('resolveApiKey', () => {
  let tmpDir: string
  let originalEnv: Record<string, string | undefined>

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'socket-test-'))
    originalEnv = {
      SOCKET_API_KEY: process.env.SOCKET_API_KEY,
      XDG_DATA_HOME: process.env.XDG_DATA_HOME,
    }
  })

  afterEach(() => {
    // restore env
    for (const [key, value] of Object.entries(originalEnv)) {
      if (value === undefined) {
        delete process.env[key]
      } else {
        process.env[key] = value
      }
    }

    fs.rmSync(tmpDir, { recursive: true, force: true })
  })

  test('should return SOCKET_API_KEY from environment variable', async () => {
    process.env.SOCKET_API_KEY = 'env-test-token'

    const result = await resolveApiKey()

    expect(result).toBe('env-test-token')
  })

  test('should read token from legacy flat settings file', async () => {
    delete process.env.SOCKET_API_KEY
    process.env.XDG_DATA_HOME = tmpDir

    const settingsDir = path.join(tmpDir, 'socket')
    fs.mkdirSync(settingsDir, { recursive: true })

    const token = 'legacy-flat-file-token'
    const content = Buffer.from(JSON.stringify({ apiToken: token })).toString('base64')
    fs.writeFileSync(path.join(settingsDir, 'settings'), content)

    const result = await resolveApiKey()

    expect(result).toBe(token)
  })

  test('should read token from CLI v2 settings/config.json', async () => {
    delete process.env.SOCKET_API_KEY
    process.env.XDG_DATA_HOME = tmpDir

    const settingsDir = path.join(tmpDir, 'socket', 'settings')
    fs.mkdirSync(settingsDir, { recursive: true })

    const token = 'cli-v2-directory-token'
    const content = Buffer.from(JSON.stringify({ apiToken: token })).toString('base64')
    fs.writeFileSync(path.join(settingsDir, 'config.json'), content)

    const result = await resolveApiKey()

    expect(result).toBe(token)
  })

  test('should prefer legacy flat file over CLI v2 directory', async () => {
    delete process.env.SOCKET_API_KEY
    process.env.XDG_DATA_HOME = tmpDir

    const socketDir = path.join(tmpDir, 'socket')

    // create legacy flat file
    fs.mkdirSync(socketDir, { recursive: true })
    const legacyToken = 'legacy-token'
    fs.writeFileSync(
      path.join(socketDir, 'settings'),
      Buffer.from(JSON.stringify({ apiToken: legacyToken })).toString('base64')
    )

    // Note: can't have both a file and directory named 'settings',
    // so this test just verifies the flat file is read when it exists

    const result = await resolveApiKey()

    expect(result).toBe(legacyToken)
  })

  test('should return undefined when no settings exist', async () => {
    delete process.env.SOCKET_API_KEY
    process.env.XDG_DATA_HOME = tmpDir

    const result = await resolveApiKey()

    expect(result).toBeUndefined()
  })

  test('should throw on malformed settings file', async () => {
    delete process.env.SOCKET_API_KEY
    process.env.XDG_DATA_HOME = tmpDir

    const settingsDir = path.join(tmpDir, 'socket')
    fs.mkdirSync(settingsDir, { recursive: true })
    fs.writeFileSync(path.join(settingsDir, 'settings'), 'not-valid-base64-json!!!')

    await expect(resolveApiKey()).rejects.toThrow('error reading Socket settings')
  })

  test('should prefer env variable over settings file', async () => {
    process.env.SOCKET_API_KEY = 'env-takes-priority'
    process.env.XDG_DATA_HOME = tmpDir

    const settingsDir = path.join(tmpDir, 'socket', 'settings')
    fs.mkdirSync(settingsDir, { recursive: true })
    fs.writeFileSync(
      path.join(settingsDir, 'config.json'),
      Buffer.from(JSON.stringify({ apiToken: 'file-token' })).toString('base64')
    )

    const result = await resolveApiKey()

    expect(result).toBe('env-takes-priority')
  })
})
