use capyvault_core::{create, inspect, open, unlock_vault, Unlock};

#[test]
fn round_trip_with_password_and_recovery() {
    let input = b"fictional test payload";
    let (file, recovery) = create(input, b"test-only master password").unwrap();
    assert_eq!(
        &*open(&file, Unlock::MasterPassword(b"test-only master password")).unwrap(),
        input
    );
    let encoded = recovery.encode();
    let decoded = capyvault_core::RecoveryKey::decode(&encoded).unwrap();
    assert_eq!(&*open(&file, Unlock::Recovery(&decoded)).unwrap(), input);
    assert_eq!(inspect(&file).unwrap().version, 1);
}

#[test]
fn rejects_wrong_password_and_modified_ciphertext() {
    let (mut file, _) = create(b"dummy", b"password").unwrap();
    assert!(open(&file, Unlock::MasterPassword(b"incorrect")).is_err());
    let last = file.len() - 1;
    file[last] ^= 1;
    assert!(open(&file, Unlock::MasterPassword(b"password")).is_err());
}

#[test]
fn rejects_modified_header_and_truncation() {
    let (mut file, _) = create(b"dummy", b"password").unwrap();
    file[19] ^= 1;
    assert!(open(&file, Unlock::MasterPassword(b"password")).is_err());
    assert!(inspect(&file[..100]).is_err());
}

#[test]
fn unlocked_vault_saves_with_fresh_nonce_and_reopens() {
    let (file, recovery) = create(b"first", b"password").unwrap();
    let mut unlocked = unlock_vault(&file, Unlock::Recovery(&recovery)).unwrap();
    let updated = unlocked.replace_payload(b"second version").unwrap();
    assert_ne!(&file[91..103], &updated[91..103]);
    assert_eq!(&*unlocked.read_payload().unwrap(), b"second version");
    assert_eq!(
        &*open(&updated, Unlock::MasterPassword(b"password")).unwrap(),
        b"second version"
    );
}
