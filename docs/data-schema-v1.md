# CapyVault payload schema v1

The encrypted payload is UTF-8 JSON. It is parsed only after GCM authentication and is not written as a plaintext file. The top-level object contains `schema_version: 1` and `records`.

Each record has a stable random UUID and fields for service, username, password, URL, email, category, tags, creation/modification timestamps (Unix seconds), notes, recovery methods, a TOTP secret, and custom fields. A custom field contains a name, value, and a boolean indicating that the value is secret. Empty password strings represent passwordless accounts. Unknown payload schema versions are rejected.

This schema is independent of the container format version. A future migration must read the authenticated old payload, validate it, create a new schema payload, then save it through a new authenticated container version. Plaintext payloads must never be staged on disk.
