# Socket's Bun Security Scanner

<a href="https://socket.dev/npm/package/@socketsecurity/bun-security-scanner"><img src="https://socket.dev/api/badge/npm/package/@socketsecurity/bun-security-scanner" alt="Socket Badge" height="20"></a>
<img src="assets/repo/badges/coverage.svg" width="97" height="20" alt="Coverage" />

[![Follow @SocketSecurity](assets/fleet/badge-follow-x.svg)](https://twitter.com/SocketSecurity)
[![Follow @socket.dev on Bluesky](assets/fleet/badge-follow-bluesky.svg)](https://bsky.app/profile/socket.dev)

Official Socket Security scanner for Bun's package installation process. Protects your projects from malicious packages, typosquatting, and other supply chain attacks.

## Why this repo exists

Bun's package installer exposes a security-provider API that lets a scanner
vet every package before it is installed. This repo is Socket's implementation
of that provider: it checks each package against Socket's threat intelligence
during `bun install`, blocking malware, typosquats, and other supply-chain
attacks before they reach your machine. It runs with no configuration in free
mode, and applies your Socket organization's policy when a token is present.

## Features

- 🛡️ Real-time security scanning during package installation
- 🔍 Detects malware, typosquatting, and supply chain attacks
- ⚡ Optimized batching for fast scans
- 🔐 Supports both authenticated (Socket org) and free modes
- 🎯 Native integration with Bun's security provider API

## Install

```bash
bun add -d @socketsecurity/bun-security-scanner
```

## Usage

Add to your `bunfig.toml`:

```toml
[install.security]
scanner = "@socketsecurity/bun-security-scanner"
```

### Authentication (Optional)

For enhanced scanning with your Socket organization settings, set the `SOCKET_API_KEY` environment variable:

```bash
export SOCKET_API_KEY="xyz"

bun install
```

> **Note**: required scope `packages`

The scanner will automatically read your token from:

1. `SOCKET_API_KEY` environment variable
2. Socket CLI settings file (if available)

Without a token, the scanner runs in free mode using Socket's public API.

## Development

<details>
<summary>Contributor commands</summary>

```sh
pnpm install
pnpm run build
pnpm run check
pnpm run test
```

</details>

### Support

- [Socket Documentation](https://socket.dev/docs)
- [Bun Security Scanner API](https://bun.com/docs/install/security-scanner-api)
- [Report Issues](https://github.com/SocketDev/bun-security-scanner/issues)

## License

MIT
