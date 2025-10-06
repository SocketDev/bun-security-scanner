import Bun from 'bun'
import os from 'os'
import { version } from '../../package.json'
export const userAgent = `SocketBunSecurityScanner/${version} (${os.platform()} ${os.arch()}) Bun/${Bun.version}`
