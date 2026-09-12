import { afterEach, beforeEach, describe, expect, spyOn, test } from 'bun:test'
import nock from 'nock'
import http from 'node:http'
import https from 'node:https'

const TOKEN_ALIASES = [
  'SOCKET_API_TOKEN',
  'SOCKET_API_KEY',
  'SOCKET_CLI_API_TOKEN',
  'SOCKET_CLI_API_KEY',
  'SOCKET_SECURITY_API_TOKEN',
  'SOCKET_SECURITY_API_KEY',
] as const
const PACKAGE = {
  name: 'example-package',
  version: '1.0.0',
  requestedRange: '^1.0.0',
  tarball:
    'https://registry.npmjs.org/example-package/-/example-package-1.0.0.tgz',
}
const PURL = 'pkg:npm/example-package@1.0.0'
const ARTIFACT = {
  inputPurl: PURL,
  alerts: [
    {
      action: 'error',
      type: 'malware',
      props: { description: 'Fixture advisory' },
    },
  ],
}

export function scannerTransportTests(config: {
  name: string
  available?: boolean | undefined
  loadScanner: () => Promise<Bun.Security.Scanner>
}): void {
  describe.skipIf(config.available === false)(config.name, () => {
    const saved = new Map<string, string | undefined>()
    let status = 200
    let requests: Array<{
      url: string
      body: string
      authorization: string | null
    }> = []
    let server: ReturnType<typeof Bun.serve>
    let requestSpy: ReturnType<typeof spyOn<typeof https, 'request'>>
    beforeEach(() => {
      status = 200
      requests = []
      server = Bun.serve({
        hostname: '127.0.0.1',
        port: 0,
        async fetch(request) {
          requests.push({
            url: request.url,
            body: await request.text(),
            authorization: request.headers.get('authorization'),
          })
          return new Response(`${JSON.stringify(ARTIFACT)}\n`, {
            status,
            headers: { 'content-type': 'application/x-ndjson' },
          })
        },
      })
      requestSpy = spyOn(https, 'request').mockImplementation(
        (options: unknown, callback: unknown) => {
          if (
            !options ||
            typeof options !== 'object' ||
            !('hostname' in options) ||
            options.hostname !== 'api.socket.dev'
          ) {
            throw new Error('Unmocked HTTPS request in scanner transport test')
          }
          return http.request(
            {
              ...(options as http.RequestOptions),
              hostname: '127.0.0.1',
              port: server.port,
              protocol: 'http:',
              agent: undefined,
            },
            callback as (response: http.IncomingMessage) => void,
          )
        },
      )
      for (const key of TOKEN_ALIASES) {
        saved.set(key, process.env[key])
        delete process.env[key]
      }
    })
    afterEach(() => {
      requestSpy.mockRestore()
      server.stop(true)
      nock.cleanAll()
      for (const [key, value] of saved) {
        if (value === undefined) delete process.env[key]
        else process.env[key] = value
      }
    })
    for (const alias of ['SOCKET_API_TOKEN', 'SOCKET_API_KEY']) {
      test(`authenticated HTTP transport with ${alias}`, async () => {
        process.env[alias] = 'EXAMPLE_API_TOKEN'
        const scanner = await config.loadScanner()
        const advisories = await scanner.scan({ packages: [{ ...PACKAGE }] })
        expect(advisories).toMatchObject([
          {
            package: PURL,
            level: 'fatal',
            description: expect.stringContaining('Fixture advisory'),
          },
        ])
        expect(requests).toHaveLength(1)
        expect(JSON.parse(requests[0]!.body)).toEqual({
          components: [{ purl: PURL }],
        })
        const requestedUrl = new URL(requests[0]!.url)
        expect(requestedUrl.pathname).toBe('/v0/purl')
        expect(requestedUrl.searchParams.get('actions')).toBe('error,warn')
        expect(requests[0]!.authorization).toBe(
          `Basic ${Buffer.from('EXAMPLE_API_TOKEN:').toString('base64')}`,
        )
      })
    }
    test('free HTTP transport parses its fixture response', async () => {
      const endpoint = nock('https://firewall-api.socket.dev')
        .get(`/purl/${encodeURIComponent(PURL)}`)
        .reply(200, `${JSON.stringify(ARTIFACT)}\n`, {
          'content-type': 'application/x-ndjson',
        })
      const scanner = await config.loadScanner()
      expect(await scanner.scan({ packages: [{ ...PACKAGE }] })).toMatchObject([
        { package: PURL, level: 'fatal' },
      ])
      expect(endpoint.isDone()).toBe(true)
    })
    test.each([true, false])(
      'rejects provider HTTP failure, authenticated=%s',
      async authenticated => {
        if (authenticated) process.env['SOCKET_API_TOKEN'] = 'EXAMPLE_API_TOKEN'
        status = 400
        const endpoint = authenticated
          ? undefined
          : nock('https://firewall-api.socket.dev')
              .get(`/purl/${encodeURIComponent(PURL)}`)
              .reply(400, '{}')
        const scanner = await config.loadScanner()
        await expect(
          scanner.scan({ packages: [{ ...PACKAGE }] }),
        ).rejects.toThrow()
        if (authenticated) expect(requests).toHaveLength(1)
        else expect(endpoint?.isDone()).toBe(true)
      },
    )
  })
}
