# CapyVault

CapyVault is an offline personal password vault. The shared Rust workspace contains the encrypted container, credential model, USB-friendly file storage, encrypted backups, and CSV/XLSX exchange functions. The Spanish-language egui desktop application has Windows and Linux release builds. A native Android preview APK also reads and writes the same v1 container.

## Current implementation

- `.capyvault` v1 binary format: AES-256-GCM payload encryption, Argon2id key derivation, random salts/nonces, independent one-time recovery key.
- Credential model includes logins, passwordless accounts, notes, recovery methods, TOTP field, tags, and custom fields.
- File session locks, compares disk versions before saving, stages and verifies writes, preserves previous encrypted copies, detects conflicts, and refuses files at or above the FAT32 size ceiling.
- CSV preview and configurable column mapping, duplicate detection, selected-row import, plus CSV and XLSX export functions. Plaintext export requires an explicit UI confirmation.
- Android provides SAF open/create, password or recovery unlock, credential listing/creation, encrypted local pre-save copies, clipboard clearing, and screenshot blocking while the app is open. Autofill, biometric unlock, full backup/restore UI, and on-device verification remain unfinished.

The format and payload schema are documented in [docs/vault-format-v1.md](docs/vault-format-v1.md) and [docs/data-schema-v1.md](docs/data-schema-v1.md). See [docs/architecture.md](docs/architecture.md) for phase status and platform build requirements.

## Build and verification

Install Rust and the native platform build libraries, then run:

```sh
cargo test --workspace
cargo run -p capyvault-app
```

Windows GNU builds can use MinGW; `scripts/package-windows.ps1` assembles the portable package. On Linux, `scripts/package-appimage.sh` creates an AppImage when the official AppImage packaging tools are available. Release signing is not configured. The program makes no network calls and has no telemetry or online-account dependency.

## Recovery

The recovery key is generated from the operating system CSPRNG and shown once when a new vault is created. Keep it separately from the USB. If it is lost and the master password is forgotten, the vault cannot be recovered. Do not save it beside the vault.

## Downloads

- [Windows portable ZIP](https://github.com/Capybla/CapyVault/releases/download/v0.1.0-preview.1/CapyVault-Windows-x64.zip)
- [Linux AppImage](https://github.com/Capybla/CapyVault/releases/download/v0.1.0-preview.1/CapyVault-Linux-x86_64.AppImage)
- [Android debug APK](https://github.com/Capybla/CapyVault/releases/download/v0.1.0-preview.1/CapyVault-Android-debug.apk)

The Android package is a debug build and has not been tested on a physical device. See [architecture and verification status](docs/architecture.md) before relying on platform-specific behavior.
