import { mkdirSync } from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import process from 'node:process'

export function isolateHomeEnv(): string {
  const sandbox = path.join(os.tmpdir(), `bun-scanner-test-home-${process.pid}`)
  const values: Record<string, string> = {
    HOME: sandbox,
    USERPROFILE: sandbox,
    XDG_CACHE_HOME: path.join(sandbox, '.cache'),
    XDG_CONFIG_HOME: path.join(sandbox, '.config'),
    XDG_DATA_HOME: path.join(sandbox, '.local', 'share'),
    XDG_STATE_HOME: path.join(sandbox, '.local', 'state'),
    npm_config_cache: path.join(sandbox, '.npm'),
  }
  for (const value of Object.values(values)) {
    mkdirSync(value, { recursive: true })
  }
  Object.assign(process.env, values)
  return sandbox
}
