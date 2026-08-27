import Bun from 'bun'
import os from 'node:os'
import { version } from '../../package.json'
export const userAgent = `socket-bun-security-scanner/${version} (${os.platform()} ${os.arch()}) Bun/${Bun.version}`
