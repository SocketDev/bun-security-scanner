import Bun from 'bun'
import { Buffer } from 'node:buffer'
import { readFile, stat } from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import process from 'node:process'
import { TextDecoder } from 'node:util'
import { getDefaultLogger } from '@socketsecurity/lib/logger/default'
import { getXdgDataHome } from '@socketsecurity/lib/env/xdg'
import { resolveSync } from '@socketsecurity/lib/secrets/find'
import { artifactsToAdvisories } from './advisories.mts'
import { authenticated } from './modes/authenticated.mts'
import { unauthenticated } from './modes/unauthenticated.mts'
import { throwIfRetiredApiToken } from './retired-api-token.mts'
import type { ScannerImplementation } from './types.mts'

const logger = getDefaultLogger()
const scannerCredentialReadError =
  'Socket Security Scanner: Socket credentials could not be read. Run socket login or set SOCKET_API_TOKEN.'
const SOCKET_API_TOKEN_ALIASES = [
  'SOCKET_API_TOKEN',
  // socket-api-token-env: bootstrap -- aliases normalize to this canonical name.
  'SOCKET_API_KEY',
  'SOCKET_CLI_API_TOKEN',
  'SOCKET_CLI_API_KEY',
  // socket-api-token-env: bootstrap -- aliases normalize to this canonical name.
  'SOCKET_SECURITY_API_TOKEN',
  // socket-api-token-env: bootstrap -- aliases normalize to this canonical name.
  'SOCKET_SECURITY_API_KEY',
] as const

export interface ScannerTokenConfig {
  envToken: string | undefined
  platform: NodeJS.Platform
  home: string
  xdgDataHome: string | undefined
  localAppData: string | undefined
}

export type ScannerSettingsResult =
  | { kind: 'absent' }
  | { kind: 'invalid' }
  | { kind: 'token'; token: string }

export interface ScannerTokenResolutionState {
  hadFailure: boolean
  token: string | undefined
}

export function advanceScannerTokenResolution(
  state: ScannerTokenResolutionState,
  result: ScannerSettingsResult,
): ScannerTokenResolutionState {
  if (result.kind === 'token') {
    return { hadFailure: state.hadFailure, token: result.token }
  }
  return {
    hadFailure: state.hadFailure || result.kind === 'invalid',
    token: undefined,
  }
}

export async function bootstrapScanner(): Promise<Bun.Security.Scanner> {
  const token = await resolveScannerToken({
    envToken: readScannerApiTokenSync(),
    platform: process.platform,
    home: os.homedir(),
    xdgDataHome: getXdgDataHome(),
    localAppData: Bun.env['LOCALAPPDATA'],
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

export function decodeScannerSettings(raw: string): ScannerSettingsResult {
  let settings: unknown
  try {
    const decoded = new TextDecoder('utf-8', {
      fatal: true,
      ignoreBOM: true,
    }).decode(Buffer.from(raw, 'base64'))
    settings = JSON.parse(decoded.trim())
  } catch {
    return { kind: 'invalid' }
  }
  if (
    typeof settings !== 'object' ||
    settings === null ||
    Array.isArray(settings)
  ) {
    return { kind: 'invalid' }
  }
  if (!Object.hasOwn(settings, 'apiToken')) {
    return { kind: 'absent' }
  }
  const token: unknown = Reflect.get(settings, 'apiToken')
  return typeof token === 'string' && token.trim()
    ? { kind: 'token', token }
    : { kind: 'invalid' }
}

export function errorCode(error: unknown): string | undefined {
  if (
    typeof error === 'object' &&
    error !== null &&
    'code' in error &&
    typeof error.code === 'string'
  ) {
    return error.code
  }
  return undefined
}

export async function missingScannerSettingsAreAbsent(
  filename: string,
): Promise<boolean> {
  let directory = path.dirname(filename)
  while (true) {
    try {
      const parentStats = await stat(directory)
      return parentStats.isDirectory()
    } catch (error) {
      const parent = nextScannerSettingsAncestor(directory, errorCode(error))
      if (parent === undefined) {
        return false
      }
      directory = parent
    }
  }
}

export function nextScannerSettingsAncestor(
  directory: string,
  code: string | undefined,
): string | undefined {
  if (code !== 'ENOENT') {
    return undefined
  }
  const parent = path.dirname(directory)
  return parent === directory ? undefined : parent
}

export function readScannerApiTokenSync(): string | undefined {
  return resolveSync({
    service: 'socketsecurity',
    accounts: SOCKET_API_TOKEN_ALIASES,
    allowEnvOnly: true,
  })?.value
}

export async function readScannerSettings(filename: string): Promise<string> {
  return await readFile(filename, 'utf8')
}

export async function resolveScannerSettingsCandidates(
  filenames: readonly string[],
): Promise<string | undefined> {
  let state: ScannerTokenResolutionState = {
    hadFailure: false,
    token: undefined,
  }
  let flatSettingsWasRead = false
  for (const [index, filename] of filenames.entries()) {
    let result: ScannerSettingsResult
    try {
      const raw = await readScannerSettings(filename)
      if (index === 0) {
        flatSettingsWasRead = true
      }
      result = decodeScannerSettings(raw)
    } catch (error) {
      const code = errorCode(error)
      if (
        (code === 'ENOENT' || code === 'ENOTDIR') &&
        ((index === 1 && flatSettingsWasRead) ||
          (await missingScannerSettingsAreAbsent(filename)))
      ) {
        continue
      }
      if (index === 0 && code === 'EISDIR') {
        continue
      }
      result = { kind: 'invalid' }
    }
    state = advanceScannerTokenResolution(state, result)
    if (state.token) {
      throwIfRetiredApiToken(state.token)
      return state.token
    }
  }
  if (state.hadFailure) {
    throw new Error(scannerCredentialReadError)
  }
  return undefined
}

export async function resolveScannerToken(
  config: ScannerTokenConfig,
): Promise<string | undefined> {
  if (config.envToken?.trim()) {
    throwIfRetiredApiToken(config.envToken)
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
  return await resolveScannerSettingsCandidates([
    settingsPath,
    path.join(settingsPath, 'config.json'),
  ])
}
