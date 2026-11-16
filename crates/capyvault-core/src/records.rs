use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use zeroize::Zeroize;

pub const DATA_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Serialize, Zeroize)]
#[serde(default)]
pub struct VaultData {
    pub schema_version: u32,
    pub records: Vec<Credential>,
}
impl Default for VaultData {
    fn default() -> Self {
        Self {
            schema_version: DATA_SCHEMA_VERSION,
            records: Vec::new(),
        }
    }
}
impl Drop for VaultData {
    fn drop(&mut self) {
        self.zeroize();
    }
}
impl<'de> Deserialize<'de> for VaultData {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct F {
            schema_version: u32,
            records: Vec<Credential>,
        }
        let f = F::deserialize(d)?;
        Ok(Self {
            schema_version: f.schema_version,
            records: f.records,
        })
    }
}

#[derive(Debug, Serialize, Zeroize)]
#[serde(default)]
pub struct Credential {
    pub id: String,
    pub service: String,
    pub username: String,
    pub password: String,
    pub url: String,
    pub email: String,
    pub category: String,
    pub tags: Vec<String>,
    pub created_at: u64,
    pub modified_at: u64,
    pub notes: String,
    pub recovery_methods: Vec<String>,
    pub totp_secret: String,
    pub custom_fields: Vec<CustomField>,
}
impl Credential {
    /// Makes the one intentional in-memory copy needed for an edit form.
    pub fn copy_for_edit(&self) -> Self {
        Self {
            id: self.id.clone(),
            service: self.service.clone(),
            username: self.username.clone(),
            password: self.password.clone(),
            url: self.url.clone(),
            email: self.email.clone(),
            category: self.category.clone(),
            tags: self.tags.clone(),
            created_at: self.created_at,
            modified_at: self.modified_at,
            notes: self.notes.clone(),
            recovery_methods: self.recovery_methods.clone(),
            totp_secret: self.totp_secret.clone(),
            custom_fields: self
                .custom_fields
                .iter()
                .map(|f| CustomField {
                    name: f.name.clone(),
                    value: f.value.clone(),
                    secret: f.secret,
                })
                .collect(),
        }
    }
}
impl Default for Credential {
    fn default() -> Self {
        let now = now_unix();
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            service: String::new(),
            username: String::new(),
            password: String::new(),
            url: String::new(),
            email: String::new(),
            category: String::from("General"),
            tags: Vec::new(),
            created_at: now,
            modified_at: now,
            notes: String::new(),
            recovery_methods: Vec::new(),
            totp_secret: String::new(),
            custom_fields: Vec::new(),
        }
    }
}
impl Drop for Credential {
    fn drop(&mut self) {
        self.zeroize();
    }
}
impl<'de> Deserialize<'de> for Credential {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct F {
            id: String,
            service: String,
            username: String,
            password: String,
            url: String,
            email: String,
            category: String,
            tags: Vec<String>,
            created_at: u64,
            modified_at: u64,
            notes: String,
            recovery_methods: Vec<String>,
            totp_secret: String,
            custom_fields: Vec<CustomField>,
        }
        let f = F::deserialize(d)?;
        Ok(Self {
            id: f.id,
            service: f.service,
            username: f.username,
            password: f.password,
            url: f.url,
            email: f.email,
            category: f.category,
            tags: f.tags,
            created_at: f.created_at,
            modified_at: f.modified_at,
            notes: f.notes,
            recovery_methods: f.recovery_methods,
            totp_secret: f.totp_secret,
            custom_fields: f.custom_fields,
        })
    }
}

#[derive(Debug, Serialize, Zeroize)]
#[serde(default)]
pub struct CustomField {
    pub name: String,
    pub value: String,
    pub secret: bool,
}
impl Default for CustomField {
    fn default() -> Self {
        Self {
            name: String::new(),
            value: String::new(),
            secret: false,
        }
    }
}
impl Drop for CustomField {
    fn drop(&mut self) {
        self.zeroize();
    }
}
impl<'de> Deserialize<'de> for CustomField {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct F {
            name: String,
            value: String,
            secret: bool,
        }
        let f = F::deserialize(d)?;
        Ok(Self {
            name: f.name,
            value: f.value,
            secret: f.secret,
        })
    }
}

pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

impl VaultData {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != DATA_SCHEMA_VERSION {
            return Err(format!("Unsupported data schema {}", self.schema_version));
        }
        if self.records.len() > 1_000_000 {
            return Err("Too many records".into());
        }
        let mut ids = HashSet::with_capacity(self.records.len());
        for record in &self.records {
            if record.id.is_empty() || !ids.insert(record.id.as_str()) {
                return Err("Record IDs must be present and unique".into());
            }
            if record.service.len() > 16_384
                || record.password.len() > 1_000_000
                || record.notes.len() > 1_000_000
            {
                return Err("A record field exceeds the supported size".into());
            }
        }
        Ok(())
    }
    pub fn search_indices(&self, query: &str, category: Option<&str>) -> Vec<usize> {
        let q = query.to_lowercase();
        self.records
            .iter()
            .enumerate()
            .filter(|(_, r)| {
                category.map_or(true, |c| r.category.eq_ignore_ascii_case(c))
                    && (q.is_empty()
                        || [
                            &r.service,
                            &r.username,
                            &r.email,
                            &r.url,
                            &r.category,
                            &r.notes,
                        ]
                        .iter()
                        .any(|v| v.to_lowercase().contains(&q))
                        || r.tags.iter().any(|v| v.to_lowercase().contains(&q)))
            })
            .map(|(i, _)| i)
            .collect()
    }
    pub fn duplicate_pairs(&self) -> Vec<(usize, usize)> {
        let mut out = Vec::new();
        for i in 0..self.records.len() {
            for j in i + 1..self.records.len() {
                let a = &self.records[i];
                let b = &self.records[j];
                let identity = (!a.url.is_empty() && a.url.eq_ignore_ascii_case(&b.url))
                    || (!a.service.is_empty()
                        && a.service.eq_ignore_ascii_case(&b.service)
                        && a.username.eq_ignore_ascii_case(&b.username));
                if identity || (!a.password.is_empty() && a.password == b.password) {
                    out.push((i, j));
                }
            }
        }
        out
    }
    pub fn weak_password_indices(&self) -> Vec<usize> {
        self.records
            .iter()
            .enumerate()
            .filter_map(|(i, r)| {
                if is_weak_password(&r.password) {
                    Some(i)
                } else {
                    None
                }
            })
            .collect()
    }
}

pub fn is_weak_password(s: &str) -> bool {
    if s.len() < 12 {
        return true;
    }
    let lower = s.chars().any(|c| c.is_ascii_lowercase());
    let upper = s.chars().any(|c| c.is_ascii_uppercase());
    let digit = s.chars().any(|c| c.is_ascii_digit());
    let symbol = s.chars().any(|c| !c.is_ascii_alphanumeric());
    !(lower && upper && digit && symbol)
}

pub fn generate_password(
    length: usize,
    lower: bool,
    upper: bool,
    digits: bool,
    symbols: bool,
) -> Result<String, String> {
    use rand::{
        distributions::{Distribution, Uniform},
        rngs::OsRng,
        seq::SliceRandom,
    };
    let mut groups = Vec::new();
    if lower {
        groups.push(b"abcdefghijkmnopqrstuvwxyz".as_slice());
    }
    if upper {
        groups.push(b"ABCDEFGHJKLMNPQRSTUVWXYZ".as_slice());
    }
    if digits {
        groups.push(b"23456789".as_slice());
    }
    if symbols {
        groups.push(b"!@#$%^&*()-_=+[]{}:,.?".as_slice());
    }
    if groups.is_empty() || length < groups.len() || length > 4096 {
        return Err("Select at least one character class and a length from 4 to 4096".into());
    }
    let mut rng = OsRng;
    let mut out = Vec::with_capacity(length);
    for group in &groups {
        out.push(*group.choose(&mut rng).unwrap());
    }
    let alphabet: Vec<u8> = groups.iter().flat_map(|g| g.iter().copied()).collect();
    let distribution = Uniform::from(0..alphabet.len());
    while out.len() < length {
        out.push(alphabet[distribution.sample(&mut rng)]);
    }
    out.shuffle(&mut rng);
    Ok(String::from_utf8(out).expect("ASCII alphabet"))
}
