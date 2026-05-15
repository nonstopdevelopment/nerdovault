# Changelog

## v0.1.0 - 2026-05-15

Initial public release of Nerdovault, a macOS-first local secrets CLI for
keeping project environment variables out of `.env` files and away from
agent-readable workspaces.

### Added

- Project-scoped secret storage with `init`, `project`, `set`, `get`, `reveal`,
  `delete`, and `list` commands.
- Runtime env injection with `nerdovault run -p myapp -- command` and the
  shorter `nerdovault -p myapp -- command` form.
- Encrypted local SQLite vault stored under `~/.nerdovault` by default, with
  `NERDOVAULT_HOME` override support.
- Nerdovault-owned macOS Keychain master key gated by LocalAuthentication.
- Default `userPresence` unlock policy with Touch ID support when available and
  password fallback.
- Optional `--biometry-current-set` initialization mode for stricter biometric
  unlock checks.
- `.env` import workflow with duplicate warnings and no automatic source-file
  deletion.
- Shared aliases so one secret value can be linked into multiple project env
  names.
- Metadata-only `.nerdovault.toml` manifests that are safe to commit.
- Repository scanning for `.env` files and obvious secret assignments.
- Optional local pre-commit guard installation.
- Shell completion generation for zsh, bash, fish, elvish, and PowerShell.
- `doctor` diagnostics for vault path, Keychain state, auth policy, biometric
  availability, and manifest consistency.

### Notes

- v1 is local-only and macOS-first.
- Team sync, cloud backup, CI secret distribution, and cross-platform unlock
  backends are intentionally out of scope for this first release.
