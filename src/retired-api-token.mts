import crypto from 'node:crypto'

const RETIRED_API_TOKEN_SHA256 =
  '9cab58b24140ee12c08e265729d246f9200f8ef9b1d884f90c06c4e6b69adf18'
const RETIRED_API_TOKEN_MESSAGE =
  'What: the Bun security scanner cannot use the selected API token.\n' +
  'Where: scanner credential selection. Saw: a retired Socket API token.\n' +
  'Wanted: a current token. Fix: replace the selected token or unset its\n' +
  'environment variable, then use socket login.'

export class RetiredApiTokenError extends Error {
  readonly code = 'SOCKET_RETIRED_API_TOKEN'

  constructor() {
    super(RETIRED_API_TOKEN_MESSAGE)
    this.name = 'RetiredApiTokenError'
  }
}

export function isRetiredApiToken(value: string | undefined): boolean {
  if (typeof value !== 'string' || value.trim().length === 0) {
    return false
  }
  const digest = crypto.createHash('sha256').update(value.trim()).digest('hex')
  return digest === RETIRED_API_TOKEN_SHA256
}

export function throwIfRetiredApiToken(value: string | undefined): void {
  if (isRetiredApiToken(value)) {
    throw new RetiredApiTokenError()
  }
}
