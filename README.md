# @socketsecurity/bun-security-scanner

Official Socket Security scanner for Bun's package installation process. Protects your projects from malicious packages, typosquatting, and other supply chain attacks.

## Features

- 🛡️ Real-time security scanning during package installation
- 🔍 Detects malware, typosquatting, and supply chain attacks
- ⚡ Optimized batching for fast scans
- 🔐 Supports both authenticated (Socket org) and free modes
- 🎯 Native integration with Bun's security provider API

## Installation

```bash
bun add -d @socketsecurity/bun-security-scanner
```

## Configuration

Add to your `bunfig.toml`:

```toml
[install.security]
provider = "@socketsecurity/bun-security-scanner"
```

### Authentication (Optional)

For enhanced scanning with your Socket organization settings, set the `SOCKET_CLI_API_TOKEN` environment variable:

```bash
export SOCKET_CLI_API_TOKEN="xyz"

bun install
```

The scanner will automatically read your token from:

1. `SOCKET_CLI_API_TOKEN` environment variable
2. Socket CLI settings file (if available)

Without a token, the scanner runs in free mode using Socket's public API.

## Support

- [Socket Documentation](https://socket.dev/docs)
- [Bun Security Scanner API](https://bun.com/docs/install/security-scanner-api)
- [Report Issues](https://github.com/SocketDev/bun-security-scanner/issues)
