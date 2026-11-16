use crate::records::{Credential, VaultData};
use csv::{ReaderBuilder, WriterBuilder};
use rust_xlsxwriter::{Workbook, XlsxError};
use std::{
    fs::{self, OpenOptions},
    io::Cursor,
    io::Write,
    path::Path,
};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

#[derive(Debug, Error)]
pub enum ExchangeError {
    #[error("CSV could not be read")]
    CsvRead,
    #[error("CSV could not be written")]
    CsvWrite,
    #[error("spreadsheet generation failed")]
    Xlsx,
    #[error("CSV exceeds the 50 MB import limit")]
    TooLarge,
    #[error("selected column index is outside the CSV header")]
    BadMapping,
    #[error("no records were selected")]
    NothingSelected,
    #[error("output already exists; choose a new file name")]
    Exists,
    #[error("file write failed: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone)]
pub struct CsvMapping {
    pub service: Option<usize>,
    pub username: Option<usize>,
    pub password: Option<usize>,
    pub url: Option<usize>,
    pub email: Option<usize>,
    pub category: Option<usize>,
    pub notes: Option<usize>,
    pub totp: Option<usize>,
}
#[derive(Debug)]
pub struct CsvCandidate {
    pub credential: Credential,
    pub selected: bool,
    pub duplicate: bool,
}
#[derive(Debug)]
pub struct CsvPreview {
    pub headers: Vec<String>,
    pub candidates: Vec<CsvCandidate>,
}

impl CsvMapping {
    pub fn suggest(headers: &[String]) -> Self {
        fn find(h: &[String], names: &[&str]) -> Option<usize> {
            h.iter().position(|x| {
                let n = normalize(x);
                names.iter().any(|m| n == *m)
            })
        }
        Self {
            service: find(
                headers,
                &["name", "title", "service", "sitename", "account"],
            ),
            username: find(headers, &["username", "user", "login", "loginusername"]),
            password: find(headers, &["password", "passwd"]),
            url: find(headers, &["url", "website", "origin"]),
            email: find(headers, &["email", "emailaddress"]),
            category: find(headers, &["category", "folder"]),
            notes: find(headers, &["note", "notes"]),
            totp: find(headers, &["totp", "otp", "2fa", "totpsecret"]),
        }
    }
}
impl CsvPreview {
    pub fn parse(
        bytes: &[u8],
        existing: &VaultData,
        mapping: &CsvMapping,
    ) -> Result<Self, ExchangeError> {
        if bytes.len() > 50 * 1024 * 1024 {
            return Err(ExchangeError::TooLarge);
        }
        let mut rdr = ReaderBuilder::new()
            .flexible(true)
            .from_reader(Cursor::new(bytes));
        let headers = rdr
            .headers()
            .map_err(|_| ExchangeError::CsvRead)?
            .iter()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        for index in [
            mapping.service,
            mapping.username,
            mapping.password,
            mapping.url,
            mapping.email,
            mapping.category,
            mapping.notes,
            mapping.totp,
        ]
        .into_iter()
        .flatten()
        {
            if index >= headers.len() {
                return Err(ExchangeError::BadMapping);
            }
        }
        let mut candidates = Vec::new();
        for row in rdr.records() {
            let row = row.map_err(|_| ExchangeError::CsvRead)?;
            let mut c = Credential::default();
            c.service = value(&row, mapping.service);
            c.username = value(&row, mapping.username);
            c.password = value(&row, mapping.password);
            c.url = value(&row, mapping.url);
            c.email = value(&row, mapping.email);
            c.category = value(&row, mapping.category);
            c.notes = value(&row, mapping.notes);
            c.totp_secret = value(&row, mapping.totp);
            if c.service.is_empty()
                && c.username.is_empty()
                && c.password.is_empty()
                && c.url.is_empty()
                && c.notes.is_empty()
            {
                c.zeroize();
                continue;
            }
            let duplicate = existing.records.iter().any(|e| same_identity(e, &c))
                || candidates
                    .iter()
                    .any(|x: &CsvCandidate| same_identity(&x.credential, &c));
            candidates.push(CsvCandidate {
                credential: c,
                selected: !duplicate,
                duplicate,
            });
            if candidates.len() > 1_000_000 {
                return Err(ExchangeError::TooLarge);
            }
        }
        Ok(Self {
            headers,
            candidates,
        })
    }
    pub fn select_all(&mut self, selected: bool) {
        for c in &mut self.candidates {
            c.selected = selected;
        }
    }
    pub fn selected_count(&self) -> usize {
        self.candidates.iter().filter(|c| c.selected).count()
    }
    pub fn commit(self, target: &mut VaultData) -> Result<usize, ExchangeError> {
        let mut count = 0;
        for mut c in self.candidates {
            if c.selected {
                if target
                    .records
                    .iter()
                    .any(|r| same_identity(r, &c.credential))
                {
                    c.credential.zeroize();
                    continue;
                }
                target.records.push(c.credential);
                count += 1;
            }
        }
        if count == 0 {
            Err(ExchangeError::NothingSelected)
        } else {
            Ok(count)
        }
    }
}

pub fn export_csv(records: &[Credential]) -> Result<Vec<u8>, ExchangeError> {
    let mut out = Vec::new();
    let mut w = WriterBuilder::new().from_writer(&mut out);
    w.write_record(columns())
        .map_err(|_| ExchangeError::CsvWrite)?;
    for r in records {
        let mut row = Zeroizing::new(values(r));
        for v in row.iter_mut() {
            if v.starts_with(['=', '+', '-', '@', '\t', '\r']) {
                v.insert(0, '\'');
            }
        }
        w.write_record(row.iter().map(String::as_str))
            .map_err(|_| ExchangeError::CsvWrite)?;
    }
    w.flush().map_err(|_| ExchangeError::CsvWrite)?;
    drop(w);
    Ok(out)
}
pub fn export_xlsx(records: &[Credential]) -> Result<Vec<u8>, ExchangeError> {
    let mut wb = Workbook::new();
    let ws = wb.add_worksheet();
    for (col, title) in columns().iter().enumerate() {
        ws.write_string(0, col as u16, *title)
            .map_err(|_| ExchangeError::Xlsx)?;
    }
    for (row, r) in records.iter().enumerate() {
        let vals = Zeroizing::new(values(r));
        for (col, val) in vals.iter().enumerate() {
            ws.write_string((row + 1) as u32, col as u16, val)
                .map_err(|_| ExchangeError::Xlsx)?;
        }
    }
    wb.save_to_buffer()
        .map_err(|_: XlsxError| ExchangeError::Xlsx)
}
/// Writes a user-confirmed plaintext export without overwriting another file.
pub fn write_export_new(path: impl AsRef<Path>, bytes: &[u8]) -> Result<(), ExchangeError> {
    let path = path.as_ref();
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                ExchangeError::Exists
            } else {
                ExchangeError::Io(e)
            }
        })?;
    if let Err(e) = f.write_all(bytes).and_then(|_| f.sync_all()) {
        drop(f);
        let _ = fs::remove_file(path);
        return Err(ExchangeError::Io(e));
    }
    Ok(())
}
fn columns() -> [&'static str; 14] {
    [
        "Name",
        "Username",
        "Password",
        "URL",
        "Email",
        "Category",
        "Tags",
        "Created",
        "Modified",
        "Notes",
        "Recovery methods",
        "TOTP secret",
        "Custom fields",
        "ID",
    ]
}
fn values(r: &Credential) -> Vec<String> {
    vec![
        r.service.clone(),
        r.username.clone(),
        r.password.clone(),
        r.url.clone(),
        r.email.clone(),
        r.category.clone(),
        r.tags.join("; "),
        r.created_at.to_string(),
        r.modified_at.to_string(),
        r.notes.clone(),
        r.recovery_methods.join("; "),
        r.totp_secret.clone(),
        r.custom_fields
            .iter()
            .map(|f| format!("{}={}", f.name, f.value))
            .collect::<Vec<_>>()
            .join("\n"),
        r.id.clone(),
    ]
}
fn value(row: &csv::StringRecord, index: Option<usize>) -> String {
    index
        .and_then(|i| row.get(i))
        .unwrap_or_default()
        .to_owned()
}
fn normalize(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}
fn same_identity(a: &Credential, b: &Credential) -> bool {
    (!a.url.is_empty() && a.url.eq_ignore_ascii_case(&b.url))
        || (!a.service.is_empty()
            && a.service.eq_ignore_ascii_case(&b.service)
            && a.username.eq_ignore_ascii_case(&b.username))
        || (!a.password.is_empty() && a.password == b.password)
}
