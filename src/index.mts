import { bootstrapScanner } from './scanner-bootstrap.mts'
export { parseNpmPurl } from './advisories.mts'

// oxlint-disable-next-line socket/no-top-level-await -- Bun plugin bootstrap
export const scanner = await bootstrapScanner()
