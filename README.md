# <picture><img width="32" height="32" alt="bun-security-scanner" src="https://raw.githubusercontent.com/SocketDev/bun-security-scanner/HEAD/assets/repo/logomark.svg"></picture> Socket Bun Security Scanner

[![Socket Badge](https://badge.socket.dev/npm/package/@socketsecurity/bun-security-scanner/1.1.3)](https://badge.socket.dev/npm/package/@socketsecurity/bun-security-scanner/1.1.3)
<picture><img src="https://raw.githubusercontent.com/SocketDev/bun-security-scanner/HEAD/assets/repo/coverage.svg?v=4b7ce6d0e5bf" height="20" alt="Coverage" /></picture>

[![Follow @SocketSecurity](https://raw.githubusercontent.com/SocketDev/bun-security-scanner/HEAD/assets/fleet/badge-follow-x.svg)](https://twitter.com/SocketSecurity)
[![Follow @socket.dev on Bluesky](https://raw.githubusercontent.com/SocketDev/bun-security-scanner/HEAD/assets/fleet/badge-follow-bluesky.svg)](https://bsky.app/profile/socket.dev)

Official Socket Security scanner for Bun's package installation process. Protects your projects from malicious packages, typosquatting, and other supply chain attacks.

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

Without a token, the scanner runs in free mode using Socket's public API.

<details>
<summary>Authentication (optional)</summary>

Use the [Socket CLI](https://www.npmjs.com/package/socket) to save a token for your Socket organization:

```sh
pnpm add --global socket
socket login
bun install
```

Enter a token with the `packages` scope when prompted. The scanner reads the saved token from your user-level Socket CLI settings.

</details>

## Development

See [Contributing](CONTRIBUTING.md) for setup and validation commands.

### Support

- [Socket Documentation](https://docs.socket.dev)
- [Bun Security Scanner API](https://bun.com/docs/install/security-scanner-api)

## License

MIT

<br/>
