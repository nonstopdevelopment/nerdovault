# Security Policy

## Supported Versions

NerdoVault is pre-1.0 software. Security fixes will target the latest release
line only until the project has a stable release process.

## Reporting a Vulnerability

Please report suspected vulnerabilities privately by opening a GitHub Security
Advisory for `nonstopdevelopment/nerdovault`.

Do not open a public issue for:

- Secret disclosure bugs
- Vault decryption bypasses
- Keychain access-control bypasses
- Unsafe logging of secret values
- Release or packaging compromise

## Current Security Posture

NerdoVault is local-only and macOS-first.

- Secret values are encrypted in the local vault database.
- The vault master key is stored as one NerdoVault-owned macOS Keychain item.
- NerdoVault requires LocalAuthentication before reading or creating that
  master key.
- Project names, env var names, alias names, and audit metadata are not treated
  as secret.
- Deleting the Keychain master key makes existing encrypted values
  unrecoverable.

See `docs/THREAT_MODEL.md` and `docs/STORAGE_MODEL.md` for the current model
and known limitations.
