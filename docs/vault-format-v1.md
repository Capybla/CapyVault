# CapyVault encrypted container (.capyvault), version 1

This specification describes the version 1 binary container implemented by `capyvault-core`.
All integer fields are unsigned big-endian. No plaintext metadata, credentials, or user identifiers are stored in the header.

## Layout

The file is `core-header || password-wrapped-DEK || recovery-wrapped-DEK || ciphertext`.

| Offset | Size | Meaning |
|---:|---:|---|
| 0 | 8 | Magic `CAPYVLT\0` |
| 8 | 2 | Format version (1) |
| 10 | 4 | Argon2id memory KiB (65536 default) |
| 14 | 4 | Argon2id iterations (3 default) |
| 18 | 1 | Argon2id lanes (1 default) |
| 19 | 16 | Random vault identifier |
| 35 | 16 | Password KDF salt |
| 51 | 12 | Password DEK-wrap nonce |
| 63 | 16 | Recovery KDF salt |
| 79 | 12 | Recovery DEK-wrap nonce |
| 91 | 12 | Payload nonce |
| 103 | 8 | Ciphertext length including 16-byte GCM tag |
| 111 | 48 | AES-256-GCM encrypted 32-byte data encryption key (DEK), tag included |
| 159 | 48 | Recovery-key wrapped DEK, tag included |
| 207 | variable | AES-256-GCM payload ciphertext and tag |

Each unlock secret is independently passed through Argon2id v1.3 to a 256-bit wrapping key. The recovery secret is 32 random bytes encoded Base64 URL-safe without padding for display/copy by the UI. Both DEK wraps authenticate bytes 0 through 90 (the static header prefix) as AAD. The payload authenticates the complete header as AAD, so edits to metadata or either wrap invalidate payload authentication. Payload updates retain the DEK but change the payload nonce and length; they do not need to rewrap the DEK. Random nonces are independently generated for the two wraps and payload; all three operations use distinct keys or distinct nonces.

The payload is an opaque byte sequence in v1; its structured data schema is a later phase. Implementations must reject unknown versions, unreasonable KDF parameters, malformed lengths, and any authentication failure. Current implementation bounds memory to 256 MiB, iterations to 10, and lanes to 16 before invoking Argon2id.

## Security and format notes

- AES-256-GCM and Argon2id use maintained RustCrypto crates; no custom cryptographic primitive is implemented.
- Master passwords are never serialized. Callers should avoid retaining input buffers and should lock/zeroize plaintext after use. Rust zeroization covers derived keys, the DEK, recovery key, and returned plaintext buffer on drop where supported.
- v1 authenticates the header indirectly via authenticated DEK wrapping and directly as payload AAD. The core header is AAD for wraps; a damaged wrap cannot produce the original DEK except with negligible probability.
- The format does not itself provide atomic file replacement, cross-process locking, backup policy, or recovery from interrupted storage writes. Those belong to the storage phase.
- GCM nonce uniqueness is ensured probabilistically with OS CSPRNG-generated 96-bit values. Implementations must never reuse a nonce under the same key.
- Do not change field meanings in v1. A future incompatible encoding requires a new version.
