# Threat Model

Nerdovault is designed to reduce accidental local secret exposure, especially
from `.env` files in agent-readable workspaces.

## In Scope

Nerdovault aims to protect against:

- AI agents scanning repo files and reading `.env` values
- accidental commits of `.env` files
- casual local inspection of the vault database
- raw secret values appearing in normal `list`, `get`, completion, or audit
  output
- stale duplicated keys across local projects through shared aliases

## Out of Scope for v1

Nerdovault does not currently protect against:

- malware running as the same user after the vault is unlocked
- shell history capture of commands that include `--value`
- child processes intentionally printing their environment
- terminal scrollback, screen recording, or clipboard capture after `reveal`
- another local admin modifying the binary or database
- cloud sync, team sharing, CI secret distribution, or backup recovery

## Metadata

The following metadata is intentionally visible locally:

- project names
- env var names
- alias names
- manifest requirements
- audit event names and timestamps

This lets autocomplete, manifests, and project inspection work without
unlocking secret values. Treat env var names as visible design metadata.

## Secret Handling Rules

- Default commands must print redacted values.
- Raw values require explicit `reveal` or runtime injection.
- Runtime injection sets environment variables only on the child process.
- Nerdovault must not write `.env` files in normal operation.
- The scanner and guard hook should help find and block `.env` files, but they
  are defense-in-depth rather than a complete DLP system.
