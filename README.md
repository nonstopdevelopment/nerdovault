# Nerdovault

Nerdovault is a macOS-first secrets CLI for keeping project environment
variables out of `.env` files and away from agent-readable workspaces.

It stores project metadata locally, encrypts secret values with an app master
key, keeps that master key as one Nerdovault-owned macOS Keychain item, and
requires LocalAuthentication before unlocking. On Macs with Touch ID, unlock
prompts can use Touch ID with password fallback.

## Quick Start

```sh
nerdovault init
nerdovault project create myapp
nerdovault set -p myapp XAI_API_KEY
nerdovault run -p myapp -- node index.js
```

The shorter run form is also supported:

```sh
nerdovault -p myapp -- node index.js
```

## Commands

```sh
nerdovault init [--biometry-current-set]
nerdovault project create myapp
nerdovault project list
nerdovault project delete myapp
nerdovault set -p myapp XAI_API_KEY
nerdovault list -p myapp
nerdovault get -p myapp XAI_API_KEY
nerdovault reveal -p myapp XAI_API_KEY
nerdovault delete -p myapp XAI_API_KEY
nerdovault import -p myapp .env
nerdovault project myapp add .env
nerdovault alias create xai/api-key
nerdovault alias set xai/api-key
nerdovault link -p myapp XAI_API_KEY --alias xai/api-key
nerdovault scan
nerdovault guard install
nerdovault doctor
nerdovault completions zsh
```

`get` is intentionally redacted. Use `reveal` when you truly need the raw
value; Nerdovault records that event in the local audit log.

The hidden `nerdovault complete projects|keys|aliases` command exposes
metadata-only dynamic values for future richer shell completion adapters.

## Safe Manifests

Run `nerdovault init` inside a repo to create `.nerdovault.toml`. The manifest
is safe to commit because it contains project names, required env names, and
alias links only. It never contains values.

## Homebrew Formula

The starter formula lives in `Formula/nerdovault.rb`. For a tap release, update
the `url` and `sha256` fields, then Homebrew will build the Rust binary and
install shell completions from the executable.

## Security Notes

- Secret values are encrypted before they are written to the local database.
- A single Nerdovault master key is stored in the macOS Keychain. Project
  secrets are not stored as individual Keychain passwords.
- `~/.nerdovault` is the default vault directory. Set `NERDOVAULT_HOME` to use a
  different location.
- `userPresence` is the default LocalAuthentication policy so Touch ID works
  when available, with password fallback.
- `--biometry-current-set` uses a stricter biometric-only LocalAuthentication
  policy and stores the evaluated biometric domain state so Nerdovault can stop
  unlocking if enrolled biometrics change.
- Runtime injection only sets environment variables on the child process.
  Nerdovault does not write `.env` files.
- Deleting the Nerdovault Keychain master key makes the encrypted local vault
  unrecoverable unless a future backup/recovery feature has been used.

More detail:

- [Storage model](docs/STORAGE_MODEL.md)
- [Threat model](docs/THREAT_MODEL.md)
- [Manual QA](docs/MANUAL_QA.md)
