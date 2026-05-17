# Manual QA

These checks intentionally touch the macOS Keychain and may show a Touch ID or
password prompt.

Use a temporary NerdoVault home so the database is disposable:

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
- `doctor` reports `Vault directory permissions: ok (0700)` and
  `Database permissions: ok (0600)` on Unix/macOS.
- `doctor` reports no project secret issues and no linked alias issues.

## Strict Biometry Key

Run this only on a disposable macOS test account or after deleting the existing
NerdoVault Keychain item:

```sh
nerdovault init --biometry-current-set
nerdovault doctor
```

Expected:

- `doctor` reports `Auth policy: biometryCurrentSet`.
- Removing or changing enrolled biometrics invalidates access to that master
  key, matching Apple Keychain `biometryCurrentSet` behavior.

## Alias Safety

```sh
nerdovault alias create shared/api-key
nerdovault alias set shared/api-key
nerdovault link -p qaapp SHARED_API_KEY --alias shared/api-key
nerdovault alias delete shared/api-key
```

Expected:

- The delete command fails while the alias is linked to `qaapp.SHARED_API_KEY`.
- `nerdovault doctor` reports no linked alias issues while the alias still has a
  value.
