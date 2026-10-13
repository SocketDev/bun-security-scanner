# Bun Security Scanner

Socket's Bun security scanner integrates with Bun's package installer security
provider API. It checks packages during `bun install` and can apply Socket
organization policy when authenticated.

## Setup

Install the package as a development dependency:

```sh
bun add -d @socketsecurity/bun-security-scanner
```

Enable it in `bunfig.toml`:

```toml
[install.security]
scanner = "@socketsecurity/bun-security-scanner"
```

Bun loads the provider on package installation. See the [Bun security scanner
API](https://bun.com/docs/install/security-scanner-api) for Bun's provider
configuration and lifecycle.

## Authentication modes

Without a Socket token, the scanner uses Socket's public API in free mode. To
apply organization policy, save an API token with the Socket CLI:

```sh
pnpm add --global socket
socket login
bun install
```

The scanner reads the saved token from the user-level Socket CLI settings.
Provide a token with the `packages` scope. Keep user-level credentials out of
project files and logs.

## Scan behavior

The scanner handles the package checks Bun requests through its provider API.
It batches requests to reduce overhead. Findings and policy decisions come
from Socket's service; the scanner does not claim that an unreported package
is universally safe.

## Troubleshooting

- Confirm the package is installed and the `[install.security]` scanner entry
  is present in `bunfig.toml`.
- Check that the Bun version supports the security-provider API.
- For organization policy, confirm `socket login` completed with a token that
  has the `packages` scope.
- Review Bun's installer output and the Socket service response for scan
  failures.

For installation and provider details, see the [Bun security scanner
API](https://bun.com/docs/install/security-scanner-api). For Socket account
support, visit [Socket Documentation](https://docs.socket.dev).
