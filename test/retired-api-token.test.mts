import { describe, expect, test } from 'bun:test'
import {
  isRetiredApiToken,
  RetiredApiTokenError,
  throwIfRetiredApiToken,
} from '../src/retired-api-token.mts'
import { authenticated } from '../src/modes/authenticated.mts'
import { retiredApiTokenFixture } from './retired-api-token.fixture.mts'

describe('retired API token detection', () => {
  test('matches the retired token exactly and with surrounding whitespace', () => {
    expect(isRetiredApiToken(retiredApiTokenFixture)).toBe(true)
    expect(isRetiredApiToken(` \t${retiredApiTokenFixture}\n `)).toBe(true)
  })

  test('rejects absent, blank, and neighboring tokens', () => {
    expect(isRetiredApiToken(undefined)).toBe(false)
    expect(isRetiredApiToken('')).toBe(false)
    expect(isRetiredApiToken(' \t\n ')).toBe(false)
    expect(isRetiredApiToken(`${retiredApiTokenFixture.slice(0, -1)}x`)).toBe(
      false,
    )
    expect(isRetiredApiToken('sktsec_t_synthetic-negative-test')).toBe(false)
  })

  test('throws a static coded error without exposing the token', () => {
    let thrown: unknown
    try {
      throwIfRetiredApiToken(retiredApiTokenFixture)
    } catch (error) {
      thrown = error
    }
    expect(thrown).toBeInstanceOf(RetiredApiTokenError)
    expect(thrown).toMatchObject({ code: 'SOCKET_RETIRED_API_TOKEN' })
    if (!(thrown instanceof Error)) {
      throw new Error('Expected a retired API token error.')
    }
    expect(thrown.message.includes('sktsec_')).toBe(false)
  })

  test('rejects a retired token at the authenticated entry point', () => {
    let thrown: unknown
    try {
      authenticated(retiredApiTokenFixture)
    } catch (error) {
      thrown = error
    }
    expect(thrown).toBeInstanceOf(RetiredApiTokenError)
    expect(thrown).toMatchObject({ code: 'SOCKET_RETIRED_API_TOKEN' })
  })
})
