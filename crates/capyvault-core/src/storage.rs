use crate::records::{now_unix, Credential, VaultData};
use crate::{create, inspect, unlock_vault, RecoveryKey, Unlock, UnlockedVault, VaultError};
use fs2::FileExt;
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{Mutex, OnceLock},
};
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroizing;

const MAX_VAULT_BYTES: u64 = 4 * 1024 * 1024 * 1024 - 1; // safely below FAT32's per-file ceiling
#[derive(Debug, Error)]
pub enum StorageError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid vault: {0}")]
    Crypto(#[from] VaultError),
    #[error("vault data is invalid: {0}")]
    Data(String),
    #[error("another process has this vault open for editing")]
    Locked,
    #[error("the vault changed on disk since it was opened; reopen it before editing")]
    Conflict,
    #[error("vault exceeds the 4 GB cross-filesystem size limit")]
    TooLarge,
    #[error("vault path must have a parent folder and filename")]
    BadPath,
    #[error("saved file did not match the written encrypted bytes")]
    VerifyFailed,
}

pub struct VaultSession {
    path: PathBuf,
    lock_key: PathBuf,
    lock_file: File,
    encrypted: Vec<u8>,
    digest: [u8; 32],
    cipher: UnlockedVault,
    data: VaultData,
    auto_backup: bool,
}
impl VaultSession {
    pub fn create(
        path: impl AsRef<Path>,
        password: &[u8],
    ) -> Result<(Self, RecoveryKey), StorageError> {
        let path = path.as_ref().to_path_buf();
        validate_path(&path)?;
        if path.exists() {
            return Err(StorageError::Io(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "refusing to overwrite an existing vault",
            )));
        }
        let (lock_file, lock_key) = acquire_lock(&path)?;
        let data = VaultData::default();
        let mut plain = Zeroizing::new(Vec::new());
        serde_json::to_writer(&mut *plain, &data).map_err(|e| StorageError::Data(e.to_string()))?;
        let (encrypted, recovery) = create(&plain, password)?;
        if encrypted.len() as u64 > MAX_VAULT_BYTES {
            return Err(StorageError::TooLarge);
        }
        write_new(&path, &encrypted)?;
        let on_disk = read_all(&path)?;
        if on_disk != encrypted {
            let _ = fs::remove_file(&path);
            return Err(StorageError::VerifyFailed);
        }
        let cipher = unlock_vault(&encrypted, Unlock::Recovery(&recovery))?;
        let digest = hash(&encrypted);
        Ok((
            Self {
                path,
                lock_key,
                lock_file,
                encrypted,
                digest,
                cipher,
                data,
                auto_backup: true,
            },
            recovery,
        ))
    }
    pub fn open(path: impl AsRef<Path>, unlock: Unlock<'_>) -> Result<Self, StorageError> {
        let path = path.as_ref().to_path_buf();
        validate_path(&path)?;
        let (lock_file, lock_key) = acquire_lock(&path)?;
        let encrypted = read_all(&path)?;
        inspect(&encrypted)?;
        let cipher = unlock_vault(&encrypted, unlock)?;
        let plain = cipher.read_payload()?;
        let data: VaultData =
            serde_json::from_slice(&plain).map_err(|e| StorageError::Data(e.to_string()))?;
        data.validate().map_err(StorageError::Data)?;
        let digest = hash(&encrypted);
        Ok(Self {
            path,
            lock_key,
            lock_file,
            encrypted,
            digest,
            cipher,
            data,
            auto_backup: true,
        })
    }
    pub fn path(&self) -> &Path {
        &self.path
    }
    pub fn data(&self) -> &VaultData {
        &self.data
    }
    pub fn data_mut(&mut self) -> &mut VaultData {
        &mut self.data
    }
    pub fn set_auto_backup(&mut self, enabled: bool) {
        self.auto_backup = enabled;
    }
    pub fn add(&mut self, mut record: Credential) -> Result<(), StorageError> {
        if record.id.is_empty() {
            record.id = Uuid::new_v4().to_string();
        }
        if self.data.records.iter().any(|x| x.id == record.id) {
            return Err(StorageError::Data("duplicate record ID".into()));
        }
        if record.created_at == 0 {
            record.created_at = now_unix();
        }
        record.modified_at = now_unix();
        self.data.records.push(record);
        Ok(())
    }
    pub fn update(&mut self, id: &str, mut record: Credential) -> Result<(), StorageError> {
        let r = self
            .data
            .records
            .iter_mut()
            .find(|r| r.id == id)
            .ok_or_else(|| StorageError::Data("record not found".into()))?;
        record.id = id.to_owned();
        record.created_at = r.created_at;
        record.modified_at = now_unix();
        *r = record;
        Ok(())
    }
    pub fn delete(&mut self, id: &str) -> Result<(), StorageError> {
        let idx = self
            .data
            .records
            .iter()
            .position(|r| r.id == id)
            .ok_or_else(|| StorageError::Data("record not found".into()))?;
        self.data.records.remove(idx);
        Ok(())
    }
    pub fn save(&mut self) -> Result<(), StorageError> {
        self.data.validate().map_err(StorageError::Data)?;
        let current = read_all(&self.path)?;
        if hash(&current) != self.digest {
            return Err(StorageError::Conflict);
        }
        let mut plain = Zeroizing::new(Vec::new());
        serde_json::to_writer(&mut *plain, &self.data)
            .map_err(|e| StorageError::Data(e.to_string()))?;
        let next = self.cipher.replace_payload(&plain)?;
        if next.len() as u64 > MAX_VAULT_BYTES {
            return Err(StorageError::TooLarge);
        }
        let tmp = temp_path(&self.path);
        let result = (|| -> Result<Vec<u8>, StorageError> {
            let mut f = OpenOptions::new().write(true).create_new(true).open(&tmp)?;
            f.write_all(&next)?;
            f.sync_all()?;
            drop(f);
            let staged = read_all(&tmp)?;
            if staged != next {
                return Err(StorageError::VerifyFailed);
            }
            if self.auto_backup {
                self.backup_bytes(&current)?;
            }
            replace_file(&tmp, &self.path)?;
            sync_parent(&self.path);
            let saved = read_all(&self.path)?;
            if saved != next {
                return Err(StorageError::VerifyFailed);
            }
            let verified = self.cipher.open_snapshot(&saved)?;
            if verified.as_slice() != plain.as_slice() {
                return Err(StorageError::VerifyFailed);
            }
            Ok(saved)
        })();
        let _ = fs::remove_file(&tmp);
        let saved = result?;
        self.encrypted = saved;
        self.digest = hash(&self.encrypted);
        Ok(())
    }
    pub fn create_backup(&self) -> Result<PathBuf, StorageError> {
        self.backup_bytes(&self.encrypted)
    }
    pub fn export_encrypted_copy(&self, path: impl AsRef<Path>) -> Result<(), StorageError> {
        let path = path.as_ref();
        write_new(path, &self.encrypted)?;
        if read_all(path)? != self.encrypted {
            let _ = fs::remove_file(path);
            return Err(StorageError::VerifyFailed);
        }
        Ok(())
    }
    pub fn list_backups(&self) -> Result<Vec<PathBuf>, StorageError> {
        let dir = backup_dir(&self.path)?;
        if !dir.exists() {
            return Ok(Vec::new());
        }
        let mut v = fs::read_dir(dir)?
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.is_file() && p.extension().and_then(|x| x.to_str()) == Some("capyvault"))
            .collect::<Vec<_>>();
        v.sort();
        v.reverse();
        Ok(v)
    }
    pub fn restore_backup(&mut self, path: impl AsRef<Path>) -> Result<(), StorageError> {
        let bytes = read_all(path.as_ref())?;
        let plain = self.cipher.open_snapshot(&bytes)?;
        let restored: VaultData =
            serde_json::from_slice(&plain).map_err(|e| StorageError::Data(e.to_string()))?;
        restored.validate().map_err(StorageError::Data)?;
        self.data = restored;
        self.save()
    }
    fn backup_bytes(&self, bytes: &[u8]) -> Result<PathBuf, StorageError> {
        inspect(bytes)?;
        let dir = backup_dir(&self.path)?;
        fs::create_dir_all(&dir)?;
        let name = format!("{}-{}.capyvault", timestamp(), Uuid::new_v4());
        let destination = dir.join(name);
        write_new(&destination, bytes)?;
        if read_all(&destination)? != bytes {
            let _ = fs::remove_file(&destination);
            return Err(StorageError::VerifyFailed);
        }
        Ok(destination)
    }
}
impl Drop for VaultSession {
    fn drop(&mut self) {
        let _ = self.lock_file.unlock();
        if let Ok(mut set) = open_paths().lock() {
            set.remove(&self.lock_key);
        }
    }
}

fn validate_path(path: &Path) -> Result<(), StorageError> {
    if path.file_name().is_none() || path.parent().is_none() {
        Err(StorageError::BadPath)
    } else {
        Ok(())
    }
}
fn lock_path(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(".lock");
    PathBuf::from(s)
}
static OPEN_PATHS: OnceLock<Mutex<HashSet<PathBuf>>> = OnceLock::new();
fn open_paths() -> &'static Mutex<HashSet<PathBuf>> {
    OPEN_PATHS.get_or_init(|| Mutex::new(HashSet::new()))
}
fn canonical_key(path: &Path) -> Result<PathBuf, StorageError> {
    let parent = path.parent().ok_or(StorageError::BadPath)?.canonicalize()?;
    let name = path.file_name().ok_or(StorageError::BadPath)?;
    let key = parent.join(name);
    #[cfg(windows)]
    let key = PathBuf::from(key.to_string_lossy().to_lowercase());
    Ok(key)
}
fn acquire_lock(path: &Path) -> Result<(File, PathBuf), StorageError> {
    let key = canonical_key(path)?;
    {
        let mut set = open_paths().lock().map_err(|_| StorageError::Locked)?;
        if !set.insert(key.clone()) {
            return Err(StorageError::Locked);
        }
    }
    let f = match OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(lock_path(path))
    {
        Ok(f) => f,
        Err(e) => {
            if let Ok(mut set) = open_paths().lock() {
                set.remove(&key);
            }
            return Err(StorageError::Io(e));
        }
    };
    if let Err(e) = f.try_lock_exclusive() {
        if let Ok(mut set) = open_paths().lock() {
            set.remove(&key);
        }
        return Err(if e.kind() == std::io::ErrorKind::WouldBlock {
            StorageError::Locked
        } else {
            StorageError::Io(e)
        });
    }
    Ok((f, key))
}
fn read_all(path: &Path) -> Result<Vec<u8>, StorageError> {
    let mut f = File::open(path)?;
    let len = f.metadata()?.len();
    if len > MAX_VAULT_BYTES {
        return Err(StorageError::TooLarge);
    }
    let mut b = Vec::with_capacity(len as usize);
    f.read_to_end(&mut b)?;
    Ok(b)
}
fn write_new(path: &Path, bytes: &[u8]) -> Result<(), StorageError> {
    if bytes.len() as u64 > MAX_VAULT_BYTES {
        return Err(StorageError::TooLarge);
    }
    let mut f = OpenOptions::new().write(true).create_new(true).open(path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}
fn temp_path(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(format!(".{}.tmp", Uuid::new_v4()));
    PathBuf::from(s)
}
fn replace_file(from: &Path, to: &Path) -> Result<(), std::io::Error> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Storage::FileSystem::{
            MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
        };
        let src: Vec<u16> = from.as_os_str().encode_wide().chain(Some(0)).collect();
        let dst: Vec<u16> = to.as_os_str().encode_wide().chain(Some(0)).collect();
        let ok = unsafe {
            MoveFileExW(
                src.as_ptr(),
                dst.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        };
        if ok == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        fs::rename(from, to)
    }
}
fn sync_parent(_path: &Path) {
    #[cfg(unix)]
    if let Some(parent) = _path.parent() {
        if let Ok(d) = File::open(parent) {
            let _ = d.sync_all();
        }
    }
}
fn hash(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
fn backup_dir(path: &Path) -> Result<PathBuf, StorageError> {
    Ok(path.parent().ok_or(StorageError::BadPath)?.join("Backups"))
}
fn timestamp() -> String {
    let secs = now_unix();
    format!("{secs}")
}
