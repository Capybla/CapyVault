use capyvault_core::{
    exchange::{export_csv, export_xlsx, CsvMapping, CsvPreview},
    records::{Credential, VaultData},
};

#[test]
fn csv_preview_selects_nonduplicates_and_writes_safe_plaintext_export() {
    let mut data = VaultData::default();
    let mut current = Credential::default();
    current.service = "Mail".into();
    current.username = "fake@example.invalid".into();
    current.password = "fictional".into();
    data.records.push(current);
    let csv=b"Name,Username,Password,URL,Note\nMail,fake@example.invalid,fictional,https://mail.example,duplicate\nForum,demo,AnotherPass9!,https://forum.example,note\n";
    let mapping = CsvMapping::suggest(&[
        "Name".into(),
        "Username".into(),
        "Password".into(),
        "URL".into(),
        "Note".into(),
    ]);
    let preview = CsvPreview::parse(csv, &data, &mapping).unwrap();
    assert_eq!(preview.candidates.len(), 2);
    assert!(preview.candidates[0].duplicate);
    assert!(!preview.candidates[0].selected);
    assert!(preview.candidates[1].selected);
    assert_eq!(preview.commit(&mut data).unwrap(), 1);
    assert_eq!(data.records.len(), 2);
    let mut export_record = Credential::default();
    export_record.service = "=1+2".into();
    export_record.password = "export-only-fictional-secret".into();
    let out = export_csv(&[export_record]).unwrap();
    let text = String::from_utf8(out).unwrap();
    assert!(text.contains("'=1+2"));
    assert!(text.contains("export-only-fictional-secret"));
}

#[test]
fn xlsx_export_produces_workbook() {
    let mut record = Credential::default();
    record.service = "Offline sample".into();
    record.password = "fictional".into();
    let xlsx = export_xlsx(&[record]).unwrap();
    assert!(xlsx.starts_with(b"PK"));
}
