# Architecture and phase status

## Architecture choice

CapyVault uses a shared Rust core and an egui desktop interface, plus a native Java Android client. The official Flutter Windows archive alone approached the requested 2 GB installation limit, so this architecture avoids installing Flutter and avoids the Android NDK. Android uses the already installed SDK and Java toolchain and implements the documented container format directly.

## Layers

- `capyvault-core`: versioned container, AES-256-GCM, Argon2id, recovery-key handling.
- `records`: credential model, search, duplicate and weak-password review, password generator.
- `storage`: cross-process file lock, disk-version checks, staged write and verification, encrypted backups and restore.
- `exchange`: configurable CSV preview/import, CSV/XLSX plaintext export functions.
- `capyvault-app`: Spanish-language egui desktop application and Windows/Linux workflows.
- `android/app`: native Java client, SAF file picker, shared v1 crypto format, encrypted private pre-save copies.
- `docs`: format, payload schema, implementation choices, and recovery instructions.

## Status

| Phase | State |
|---|---|
| 1. Crypto and container | Implemented; automated container and cross-format tests pass on Windows and Linux. Android unit tests cover v1 encryption/re-encryption and opening a Windows-created fixture. |
| 2. Interface and credentials | Desktop implemented; Windows create/edit/save/lock/reopen flow verified with fictional data. Android create/open and basic credential workflows are implemented but not device-tested. |
| 3. USB and shared storage | Desktop safe file session, collision detection, backups, and Windows removable-drive listing implemented. Android SAF access is implemented. No unplug-during-write test or physical OTG test has been performed. |
| 4. Import/export | Desktop CSV mapping, preview, duplicate selection, CSV/XLSX export implemented; automated exchange tests pass. Android import/export is not implemented. |
| 5. Android | Debug APK builds. Autofill, biometrics, full backup/restore interface, and physical-device verification remain. |
| 6. Build and cross-platform verification | Portable Windows ZIP, Linux AppImage, and Android debug APK produced. Desktop suites pass on Windows GNU and Linux; Android has two passing format tests. Linux GUI compatibility on a physical distribution, Android device testing, interrupted USB writes, and same-vault editing across real devices remain unverified. |

## Build constraints and limits

- A portable Windows GNU build includes its MinGW runtime DLLs and needs no administrator installation.
- The additional WSL packages used for the Linux build occupied about 623 MB. The AppImage remained running for a 12-second software-rendered WSL smoke check with no startup errors. A visible Linux desktop session and compatibility with older distributions still need a real desktop check.
- Android uses Java and Bouncy Castle to avoid an NDK install. Its format reader was tested against a fictional Windows Rust fixture. This is a debug APK, not a signed production release.
- Desktop session locking and version checks do not yet provide a shared cross-device lock protocol for Android. Do not concurrently edit the same vault from different devices.
- No physical USB was disconnected during a save. No Android device or native Linux desktop was available for end-to-end visual verification. The packaged outputs are deliverables for testing, not evidence those scenarios passed.
- No real credentials were used in tests.

## DuckDuckGo Password Manager on Android

DuckDuckGo's help documents direct import from Google Password Manager on Android. Its documented CSV export steps refer to exporting from the source browser/password manager for desktop import; it does not document a direct CSV export from DuckDuckGo Android. CapyVault does not claim a direct DuckDuckGo Android CSV export path.

Reference: [DuckDuckGo help: importing passwords](https://duckduckgo.com/duckduckgo-help-pages/sync-and-backup/importing-passwords).
