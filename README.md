# NerdoVault

NerdoVault is a macOS-first secrets CLI for keeping project environment
variables out of `.env` files and away from agent-readable workspaces.

It stores project metadata locally, encrypts secret values with an app master
key, keeps that master key as one NerdoVault-owned macOS Keychain item, and
requires LocalAuthentication before unlocking. On Macs with Touch ID, unlock
prompts can use Touch ID with password fallback.

Human-facing name: **NerdoVault**. Terminal-facing command, package, paths, and
repo names stay lowercase `nerdovault`.

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

For the normal daily workflow, see [Regular use](docs/REGULAR_USE.md).

## Why

AI agents are helpful, but they can also read whatever we leave in a workspace.
NerdoVault moves secret values out of repo-local `.env` files, keeps committed
manifests metadata-only, and injects scoped env vars only when starting the
process that needs them.

## Daily Flow

```sh
nerdovault init
nerdovault import -p myapp .env
nerdovault guard install
nerdovault run -p myapp -- npm run dev
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
value; NerdoVault records that event in the local audit log.

The hidden `nerdovault complete projects|keys|aliases` command exposes
metadata-only dynamic values for future richer shell completion adapters.

## Safe Manifests

Run `nerdovault init` inside a repo to create `.nerdovault.toml`. The manifest
is safe to commit because it contains project names, required env names, and
alias links only. It never contains values.

## Homebrew

The formula lives in `Formula/nerdovault.rb`.

```sh
brew tap nonstopdevelopment/nerdovault https://github.com/nonstopdevelopment/nerdovault
brew install nerdovault
```

The explicit URL is needed because the project repo is named `nerdovault`, not
`homebrew-nerdovault`. A dedicated Homebrew tap repo can make this shorter later.

## Security Notes

- Secret values are encrypted before they are written to the local database.
- A single NerdoVault master key is stored in the macOS Keychain. Project
  secrets are not stored as individual Keychain passwords.
- `~/.nerdovault` is the default vault directory. Set `NERDOVAULT_HOME` to use a
  different location.
- NerdoVault enforces `0700` permissions on the vault directory and `0600`
  permissions on the SQLite database on Unix/macOS.
- `userPresence` is the default LocalAuthentication policy so Touch ID works
  when available, with password fallback.
- `--biometry-current-set` uses a stricter biometric-only LocalAuthentication
  policy and stores the evaluated biometric domain state so NerdoVault can stop
  unlocking if enrolled biometrics change.
- `nerdovault doctor` reports the active auth policy and whether macOS says
  device-owner auth and biometrics are available.
- Runtime injection only sets environment variables on the child process.
  NerdoVault does not write `.env` files.
- Avoid `--value` for real secrets in interactive shells because it can be
  captured in shell history or process lists. Prefer the hidden prompt or
  `--stdin`.
- Linked aliases cannot be deleted until project keys stop using them, which
  prevents silently breaking daily runtime injection.
- Deleting the NerdoVault Keychain master key makes the encrypted local vault
  unrecoverable unless a future backup/recovery feature has been used.

More detail:

- [Storage model](docs/STORAGE_MODEL.md)
- [Threat model](docs/THREAT_MODEL.md)
- [Manual QA](docs/MANUAL_QA.md)
