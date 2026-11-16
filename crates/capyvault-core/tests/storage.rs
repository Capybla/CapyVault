use capyvault_core::{
    records::Credential,
    storage::{StorageError, VaultSession},
    Unlock,
};
use std::{fs, path::PathBuf};
use uuid::Uuid;

fn location() -> (PathBuf, PathBuf) {
    let dir = std::env::temp_dir().join(format!("capyvault-test-{}", Uuid::new_v4()));
    fs::create_dir_all(&dir).unwrap();
    let file = dir.join("Main.capyvault");
    (dir, file)
}

#[test]
fn storage_round_trip_backup_restore_and_lock() {
    let (dir, path) = location();
    let (mut session, recovery) = VaultSession::create(&path, b"fictional password").unwrap();
    assert!(matches!(
        VaultSession::open(&path, Unlock::MasterPassword(b"fictional password")),
        Err(StorageError::Locked)
    ));
    let mut record = Credential::default();
    record.service = "Example Test".into();
    record.username = "fake@example.invalid".into();
    record.password = "not-a-real-password-4!".into();
    session.add(record).unwrap();
    session.save().unwrap();
    let encrypted = fs::read(&path).unwrap();
    assert!(!String::from_utf8_lossy(&encrypted).contains("not-a-real-password"));
    let backup = session.create_backup().unwrap();
    let id = session.data().records[0].id.clone();
    let mut changed = Credential::default();
    changed.service = "Changed".into();
    changed.password = "temporary-fictional-value".into();
    session.update(&id, changed).unwrap();
    session.save().unwrap();
    session.restore_backup(&backup).unwrap();
    assert_eq!(session.data().records[0].service, "Example Test");
    drop(session);
    let reopened = VaultSession::open(&path, Unlock::Recovery(&recovery)).unwrap();
    assert_eq!(
        reopened.data().records[0].password,
        "not-a-real-password-4!"
    );
    drop(reopened);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn refuses_to_overwrite_disk_changes() {
    let (dir, path) = location();
    let (mut session, _) = VaultSession::create(&path, b"test password").unwrap();
    fs::write(&path, b"external change").unwrap();
    assert!(matches!(session.save(), Err(StorageError::Conflict)));
    drop(session);
    fs::remove_dir_all(dir).unwrap();
}
