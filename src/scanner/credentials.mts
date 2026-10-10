import { Buffer } from 'node:buffer'
import { readFile, stat } from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'

export interface ScannerCredentialOptions {
  platform?: NodeJS.Platform | undefined
  home?: string | undefined
  xdgDataHome?: string | undefined
  localAppData?: string | undefined
}

export type ScannerCredentialOutcome =
  | { kind: 'absent' }
  | { kind: 'token'; token: string }
  | { kind: 'invalid' }
  | { kind: 'read-failure' }

export type ScannerCredentialSource =
  | { kind: 'absent' }
  | { kind: 'token'; token: string }

export function errorCode(error: unknown): string | undefined {
  if (typeof error === 'object' && error !== null && 'code' in error) {
    return typeof error.code === 'string' ? error.code : undefined
  }
  return undefined
}

export function parseScannerCredential(raw: string): ScannerCredentialOutcome {
  let parsed: unknown
  try {
    parsed = JSON.parse(Buffer.from(raw, 'base64').toString('utf8').trim())
  } catch {
    return { kind: 'invalid' }
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    return { kind: 'invalid' }
  }
  if (!('apiToken' in parsed)) {
    return { kind: 'absent' }
  }
  if (typeof parsed.apiToken !== 'string' || !parsed.apiToken.trim()) {
    return { kind: 'invalid' }
  }
  return { kind: 'token', token: parsed.apiToken }
}

export async function readScannerCredential(
  filename: string,
  allowDirectory = false,
): Promise<ScannerCredentialOutcome> {
  try {
    const metadata = await stat(filename)
    if (metadata.isDirectory()) {
      return allowDirectory ? { kind: 'absent' } : { kind: 'invalid' }
    }
    return parseScannerCredential(await readFile(filename, 'utf8'))
  } catch (error) {
    if (errorCode(error) === 'ENOENT' || errorCode(error) === 'ENOTDIR') {
      return { kind: 'absent' }
    }
    return { kind: 'read-failure' }
  }
}

export async function resolveScannerCredential(
  envToken: string | undefined,
  options: ScannerCredentialOptions = {},
): Promise<ScannerCredentialSource> {
  const {
    platform = process.platform,
    home = os.homedir(),
    xdgDataHome = process.env['XDG_DATA_HOME'],
    localAppData = process.env['LOCALAPPDATA'],
  } = options
  if (envToken?.trim()) {
    return { kind: 'token', token: envToken }
  }
  const candidates = settingsCandidates(
    platform,
    home,
    xdgDataHome,
    localAppData,
  )
  const outcomes: ScannerCredentialOutcome[] = []
  for (const [index, filename] of candidates.entries()) {
    outcomes.push(await readScannerCredential(filename, index === 0))
  }
  return selectScannerCredential(outcomes)
}

export function selectScannerCredential(
  outcomes: readonly ScannerCredentialOutcome[],
): ScannerCredentialSource {
  let sawFailure = false
  for (const outcome of outcomes) {
    if (outcome.kind === 'token') {
      return outcome
    }
    if (outcome.kind === 'invalid' || outcome.kind === 'read-failure') {
      sawFailure = true
    }
  }
  if (sawFailure) {
    throw new Error(
      'Socket Security Scanner: configured credentials are invalid or unreadable. Re-run `socket login`, remove the invalid saved settings file to use free mode, or set SOCKET_API_TOKEN.',
    )
  }
  return { kind: 'absent' }
}

export function settingsCandidates(
  platform: NodeJS.Platform,
  home: string,
  xdgDataHome: string | undefined,
  localAppData: string | undefined,
): readonly string[] {
  let dataHome = platform === 'win32' ? localAppData : xdgDataHome
  if (!dataHome) {
    if (platform === 'win32') {
      throw new Error(
        'Socket Security Scanner: cannot locate saved credentials. Where: %LOCALAPPDATA%. Saw: unset. Wanted: a user data directory. Fix: set LOCALAPPDATA or SOCKET_API_TOKEN.',
      )
    }
    dataHome = path.join(
      home,
      ...(platform === 'darwin'
        ? ['Library', 'Application Support']
        : ['.local', 'share']),
    )
  }
  const settingsPath = path.join(dataHome, 'socket', 'settings')
  return [settingsPath, path.join(settingsPath, 'config.json')]
}
