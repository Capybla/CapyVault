//! CapyVault v1 encrypted container core.
//! Callers supply and receive opaque plaintext bytes; this crate never logs secrets.
pub mod exchange;
pub mod records;
pub mod storage;
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::{rngs::OsRng, RngCore};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

const MAGIC: &[u8; 8] = b"CAPYVLT\0";
const VERSION: u16 = 1;
const CORE_LEN: usize = 8 + 2 + 4 + 4 + 1 + 16 + 16 + 12 + 16 + 12 + 12 + 8;
const HEADER_LEN: usize = CORE_LEN + 2 * 48;
const DEK_LEN: usize = 32;
const TAG_LEN: usize = 16;
const DEFAULT_MEMORY_KIB: u32 = 65536;
const DEFAULT_ITERATIONS: u32 = 3;
const DEFAULT_LANES: u8 = 1;
const MAX_MEMORY_KIB: u32 = 262144;
const MAX_ITERATIONS: u32 = 10;

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("invalid or unsupported vault format")]
    InvalidFormat,
    #[error("vault is truncated or has an invalid length")]
    InvalidLength,
    #[error("authentication failed: wrong key or damaged data")]
    Authentication,
    #[error("cryptographic operation failed")]
    Crypto,
    #[error("invalid KDF parameters")]
    KdfParameters,
}

#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct RecoveryKey([u8; 32]);
impl RecoveryKey {
    /// A one-time printable key. Persist it only through the UI's explicit user action.
    pub fn generate() -> Self {
        let mut b = [0; 32];
        OsRng.fill_bytes(&mut b);
        Self(b)
    }
    pub fn encode(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.0)
    }
    pub fn decode(s: &str) -> Result<Self, VaultError> {
        let b = URL_SAFE_NO_PAD
            .decode(s)
            .map_err(|_| VaultError::Authentication)?;
        let mut key = [0u8; 32];
        if b.len() != 32 {
            return Err(VaultError::Authentication);
        }
        key.copy_from_slice(&b);
        Ok(Self(key))
    }
}
impl std::fmt::Debug for RecoveryKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RecoveryKey([REDACTED])")
    }
}

#[derive(Clone, Copy)]
pub enum Unlock<'a> {
    MasterPassword(&'a [u8]),
    Recovery(&'a RecoveryKey),
}

/// Creates a vault and returns (serialized bytes, one-time recovery key).
pub fn create(plaintext: &[u8], password: &[u8]) -> Result<(Vec<u8>, RecoveryKey), VaultError> {
    if password.is_empty() {
        return Err(VaultError::Crypto);
    }
    let recovery = RecoveryKey::generate();
    let mut core = vec![0u8; CORE_LEN];
    core[0..8].copy_from_slice(MAGIC);
    core[8..10].copy_from_slice(&VERSION.to_be_bytes());
    core[10..14].copy_from_slice(&DEFAULT_MEMORY_KIB.to_be_bytes());
    core[14..18].copy_from_slice(&DEFAULT_ITERATIONS.to_be_bytes());
    core[18] = DEFAULT_LANES;
    OsRng.fill_bytes(&mut core[19..35]); // vault id
    OsRng.fill_bytes(&mut core[35..51]); // password salt
    OsRng.fill_bytes(&mut core[51..63]); // password wrap nonce
    OsRng.fill_bytes(&mut core[63..79]); // recovery salt
    OsRng.fill_bytes(&mut core[79..91]); // recovery wrap nonce
    OsRng.fill_bytes(&mut core[91..103]); // content nonce
    let encrypted_len = plaintext
        .len()
        .checked_add(TAG_LEN)
        .ok_or(VaultError::InvalidLength)?;
    let total_len = HEADER_LEN
        .checked_add(encrypted_len)
        .ok_or(VaultError::InvalidLength)?;
    let encrypted_len_u64 = u64::try_from(encrypted_len).map_err(|_| VaultError::InvalidLength)?;
    core[103..111].copy_from_slice(&encrypted_len_u64.to_be_bytes());

    let mut dek = Zeroizing::new([0u8; DEK_LEN]);
    OsRng.fill_bytes(&mut dek[..]);
    let pw_key = derive(password, &core[35..51], &core)?;
    let recovery_key = derive(&recovery.0, &core[63..79], &core)?;
    let mut header = core.clone();
    let wrap_aad = &core[..91];
    let pw_wrap = seal(&pw_key, &core[51..63], &dek[..], wrap_aad)?;
    let rec_wrap = seal(&recovery_key, &core[79..91], &dek[..], wrap_aad)?;
    header.extend_from_slice(&pw_wrap);
    header.extend_from_slice(&rec_wrap);
    let payload = seal(&dek[..], &core[91..103], plaintext, &header)?;
    let mut file = Vec::with_capacity(total_len);
    file.extend_from_slice(&header);
    file.extend_from_slice(&payload);
    Ok((file, recovery))
}

/// Decrypts the opaque payload using either unlock method.
pub fn open(file: &[u8], unlock: Unlock<'_>) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    unlock_vault(file, unlock)?.read_payload()
}

/// An unlocked vault retains only the content key and encrypted header in memory.
/// Dropping it zeroizes the content key. The UI should drop this object on lock.
pub struct UnlockedVault {
    header: Vec<u8>,
    payload: Vec<u8>,
    dek: Zeroizing<Vec<u8>>,
}

pub fn unlock_vault(file: &[u8], unlock: Unlock<'_>) -> Result<UnlockedVault, VaultError> {
    if file.len() < HEADER_LEN + TAG_LEN {
        return Err(VaultError::InvalidLength);
    }
    let core = &file[..CORE_LEN];
    if &core[..8] != MAGIC || u16::from_be_bytes([core[8], core[9]]) != VERSION {
        return Err(VaultError::InvalidFormat);
    }
    let declared = usize::try_from(u64::from_be_bytes(
        core[103..111]
            .try_into()
            .map_err(|_| VaultError::InvalidFormat)?,
    ))
    .map_err(|_| VaultError::InvalidLength)?;
    if declared < TAG_LEN || declared != file.len() - HEADER_LEN {
        return Err(VaultError::InvalidLength);
    }
    let memory = u32::from_be_bytes(
        core[10..14]
            .try_into()
            .map_err(|_| VaultError::InvalidFormat)?,
    );
    let iterations = u32::from_be_bytes(
        core[14..18]
            .try_into()
            .map_err(|_| VaultError::InvalidFormat)?,
    );
    let lanes = core[18];
    if memory < 8192
        || memory > MAX_MEMORY_KIB
        || iterations == 0
        || iterations > MAX_ITERATIONS
        || lanes == 0
        || lanes > 16
    {
        return Err(VaultError::KdfParameters);
    }
    let (salt, nonce, wrap, key_material) = match unlock {
        Unlock::MasterPassword(p) => (
            &core[35..51],
            &core[51..63],
            &file[CORE_LEN..CORE_LEN + 48],
            p,
        ),
        Unlock::Recovery(k) => (
            &core[63..79],
            &core[79..91],
            &file[CORE_LEN + 48..HEADER_LEN],
            &k.0[..],
        ),
    };
    let key = derive_params(key_material, salt, memory, iterations, lanes)?;
    let dek = Zeroizing::new(open_sealed(&key, nonce, wrap, &core[..91])?);
    let vault = UnlockedVault {
        header: file[..HEADER_LEN].to_vec(),
        payload: file[HEADER_LEN..].to_vec(),
        dek,
    };
    // Verify authentication immediately, before reporting a successful unlock.
    let _ = vault.read_payload()?;
    Ok(vault)
}

impl UnlockedVault {
    pub fn read_payload(&self) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        let core = &self.header[..CORE_LEN];
        let cipher_len = usize::try_from(u64::from_be_bytes(
            core[103..111]
                .try_into()
                .map_err(|_| VaultError::InvalidFormat)?,
        ))
        .map_err(|_| VaultError::InvalidLength)?;
        if self.header.len() != HEADER_LEN
            || self.payload.len() != cipher_len
            || cipher_len < TAG_LEN
        {
            return Err(VaultError::InvalidLength);
        }
        Ok(Zeroizing::new(open_sealed(
            &self.dek,
            &core[91..103],
            &self.payload,
            &self.header,
        )?))
    }

    /// Decrypts an older file version created from this same vault key.
    pub fn open_snapshot(&self, file: &[u8]) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        if file.len() < HEADER_LEN + TAG_LEN
            || file[..91] != self.header[..91]
            || file[CORE_LEN..HEADER_LEN] != self.header[CORE_LEN..HEADER_LEN]
        {
            return Err(VaultError::InvalidFormat);
        }
        let core = &file[..CORE_LEN];
        if &core[..8] != MAGIC || u16::from_be_bytes([core[8], core[9]]) != VERSION {
            return Err(VaultError::InvalidFormat);
        }
        let len = usize::try_from(u64::from_be_bytes(
            core[103..111]
                .try_into()
                .map_err(|_| VaultError::InvalidFormat)?,
        ))
        .map_err(|_| VaultError::InvalidLength)?;
        if len < TAG_LEN || file.len() != HEADER_LEN + len {
            return Err(VaultError::InvalidLength);
        }
        Ok(Zeroizing::new(open_sealed(
            &self.dek,
            &core[91..103],
            &file[HEADER_LEN..],
            &file[..HEADER_LEN],
        )?))
    }

    /// Re-encrypts updated plaintext under the same DEK with a fresh random nonce.
    pub fn replace_payload(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, VaultError> {
        let _ = self.read_payload()?;
        let payload_len = plaintext
            .len()
            .checked_add(TAG_LEN)
            .ok_or(VaultError::InvalidLength)?;
        let payload_len_u64 = u64::try_from(payload_len).map_err(|_| VaultError::InvalidLength)?;
        let mut header = self.header.clone();
        header[103..111].copy_from_slice(&payload_len_u64.to_be_bytes());
        let old_nonce = self.header[91..103].to_vec();
        loop {
            OsRng.fill_bytes(&mut header[91..103]);
            if header[91..103] != self.header[51..63]
                && header[91..103] != self.header[79..91]
                && header[91..103] != old_nonce
            {
                break;
            }
        }
        let encrypted = seal(&self.dek, &header[91..103], plaintext, &header)?;
        self.header = header;
        self.payload = encrypted;
        let mut output = Vec::with_capacity(HEADER_LEN + payload_len);
        output.extend_from_slice(&self.header);
        output.extend_from_slice(&self.payload);
        Ok(output)
    }
}

/// Inspect non-secret format metadata for UI display.
pub fn inspect(file: &[u8]) -> Result<VaultMetadata, VaultError> {
    if file.len() < HEADER_LEN || &file[..8] != MAGIC {
        return Err(VaultError::InvalidFormat);
    }
    let version = u16::from_be_bytes([file[8], file[9]]);
    if version != VERSION {
        return Err(VaultError::InvalidFormat);
    }
    let len = u64::from_be_bytes(
        file[103..111]
            .try_into()
            .map_err(|_| VaultError::InvalidFormat)?,
    );
    if len as usize != file.len() - HEADER_LEN {
        return Err(VaultError::InvalidLength);
    }
    Ok(VaultMetadata {
        version,
        vault_id: file[19..35].to_vec(),
        encrypted_payload_bytes: len as usize,
    })
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultMetadata {
    pub version: u16,
    pub vault_id: Vec<u8>,
    pub encrypted_payload_bytes: usize,
}

fn derive(password: &[u8], salt: &[u8], core: &[u8]) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    let m = u32::from_be_bytes(
        core[10..14]
            .try_into()
            .map_err(|_| VaultError::InvalidFormat)?,
    );
    let t = u32::from_be_bytes(
        core[14..18]
            .try_into()
            .map_err(|_| VaultError::InvalidFormat)?,
    );
    derive_params(password, salt, m, t, core[18])
}
fn derive_params(
    password: &[u8],
    salt: &[u8],
    m: u32,
    t: u32,
    p: u8,
) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    let params =
        Params::new(m, t, u32::from(p), Some(32)).map_err(|_| VaultError::KdfParameters)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = Zeroizing::new(vec![0u8; 32]);
    argon
        .hash_password_into(password, salt, &mut out)
        .map_err(|_| VaultError::KdfParameters)?;
    Ok(out)
}
fn seal(key: &[u8], nonce: &[u8], plain: &[u8], aad: &[u8]) -> Result<Vec<u8>, VaultError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| VaultError::Crypto)?;
    cipher
        .encrypt(Nonce::from_slice(nonce), Payload { msg: plain, aad })
        .map_err(|_| VaultError::Crypto)
}
fn open_sealed(
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, VaultError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| VaultError::Crypto)?;
    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| VaultError::Authentication)
}
