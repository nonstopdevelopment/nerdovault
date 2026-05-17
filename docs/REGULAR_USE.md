# Regular Use

This is the daily NerdoVault workflow for moving project secrets out of `.env`
files without turning the vault into a new source of accidental leaks.

## One-Time Machine Setup

```sh
brew tap nonstopdevelopment/nerdovault https://github.com/nonstopdevelopment/nerdovault
brew install nerdovault
nerdovault init
nerdovault doctor
```

Expected:

- `Vault directory` points at `~/.nerdovault` unless `NERDOVAULT_HOME` is set.
- `Vault directory permissions` is `ok (0700)`.
- `Database permissions` is `ok (0600)`.
- `Keychain master key` is `present`.
- Device-owner authentication is available.

## Migrating A Project

From the project root:

```sh
nerdovault init
nerdovault project create myapp
nerdovault import -p myapp .env
nerdovault list -p myapp
nerdovault scan .
```

After import:

- Commit `.nerdovault.toml`.
- Do not commit `.env`.
- Remove the local `.env` only after `list`, `reveal`, or `run` proves the
  imported values are correct.
- Run `nerdovault guard install` to block accidental `.env` commits in that
  repository.

## Running An App

```sh
nerdovault run -p myapp -- npm run dev
```

The shorter form is equivalent:

```sh
nerdovault -p myapp -- npm run dev
```

NerdoVault injects values into the child process environment only. It does not
write a `.env` file.

## Setting Values Safely

Prefer the hidden prompt:

```sh
nerdovault set -p myapp XAI_API_KEY
```

Or pipe from a password manager or command that does not echo:

```sh
op read "op://Private/XAI/api_key" | nerdovault set -p myapp XAI_API_KEY --stdin
```

Avoid `--value` for real secrets in interactive shells. It is useful for tests,
but it can be captured by shell history or process-list inspection while the
command is running.

## Shared Aliases

Use aliases when the same upstream credential powers multiple projects:

```sh
nerdovault alias create xai/api-key
nerdovault alias set xai/api-key
nerdovault link -p app1 XAI_API_KEY --alias xai/api-key
nerdovault link -p app2 XAI_API_KEY --alias xai/api-key
```

Rotating the shared key is one command:

```sh
nerdovault alias set xai/api-key
```

NerdoVault refuses to delete an alias while project keys still link to it. This
prevents a shared key from silently disappearing out from under a daily app.

## Daily Health Check

Run this when something feels off, after upgrades, or before trusting a migrated
project:

```sh
nerdovault doctor
nerdovault scan .
nerdovault audit --limit 20
```

`doctor` should report no project secret issues, no linked alias issues, no
manifest missing keys, and no manifest alias issues.
