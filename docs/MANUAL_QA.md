# Manual QA

These checks intentionally touch the macOS Keychain and may show a Touch ID or
password prompt.

Use a temporary Nerdovault home so the database is disposable:

```sh
export NERDOVAULT_HOME=/private/tmp/nerdovault-manual-qa
rm -rf "$NERDOVAULT_HOME"
```

## Default User-Presence Key

```sh
nerdovault init
nerdovault project create qaapp
nerdovault set -p qaapp XAI_API_KEY --value test-secret
nerdovault get -p qaapp XAI_API_KEY
nerdovault reveal -p qaapp XAI_API_KEY
nerdovault run -p qaapp -- env
nerdovault doctor
```

Expected:

- `init` creates a Keychain item for `dev.nonstop.nerdovault/master-key`.
- `get` prints `XAI_API_KEY=********`.
- `set`, `reveal`, and `run` prompt for LocalAuthentication. On Touch ID Macs,
  macOS should offer Touch ID with the configured fallback.
- `reveal` prints `XAI_API_KEY=test-secret`.
- `run` injects `XAI_API_KEY` into the child process only.
- `doctor` reports `Auth policy: userPresence` plus device-owner and biometric
  availability without unlocking the vault.

## Strict Biometry Key

Run this only on a disposable macOS test account or after deleting the existing
Nerdovault Keychain item:

```sh
nerdovault init --biometry-current-set
nerdovault doctor
```

Expected:

- `doctor` reports `Access policy: biometryCurrentSet`.
- Removing or changing enrolled biometrics invalidates access to that master
  key, matching Apple Keychain `biometryCurrentSet` behavior.
