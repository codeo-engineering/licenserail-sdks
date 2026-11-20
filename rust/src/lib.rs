//! LicenseRail client SDK: offline license verification, activation, refresh and floating leases.
//!
//! ```no_run
//! use licenserail::{LicenseClient, Options};
//! let mut client = LicenseClient::new(Options {
//!     server_url: "https://api.licenserail.com".into(),
//!     vendor: "acme".into(),
//!     product: "my-app".into(),
//!     public_key_pem: std::fs::read_to_string("public-key.pem").unwrap(),
//!     ..Options::default()
//! }).unwrap();
//! if !client.check().is_valid() {
//!     client.activate("XXXXX-XXXXX-XXXXX-XXXXX", None);
//! }
//! ```

mod client;
mod fingerprint;

pub use client::{ActivationResult, CheckResult, LicenseClient, Options};
pub use fingerprint::collect_fingerprint;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use hmac::{Hmac, Mac};
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::pkcs8::DecodePublicKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const UNAVAILABLE: &str = "none";

/// Server error codes on which the local license is deleted; any other error keeps it.
pub const REVOKING_CODES: &[&str] = &[
    "license_not_found", "license_suspended", "license_expired", "activation_revoked", "wrong_machine", "invalid_token", "license_revoked",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Valid,
    Missing,
    InvalidSignature,
    WrongProduct,
    WrongMachine,
    Expired,
    OfflineTooLong,
    ClockTampered,
    Unverified,
    Suspended,
}

impl Status {
    pub fn as_str(&self) -> &'static str {
        match self {
            Status::Valid => "Valid",
            Status::Missing => "Missing",
            Status::InvalidSignature => "InvalidSignature",
            Status::WrongProduct => "WrongProduct",
            Status::WrongMachine => "WrongMachine",
            Status::Expired => "Expired",
            Status::OfflineTooLong => "OfflineTooLong",
            Status::ClockTampered => "ClockTampered",
            Status::Unverified => "Unverified",
            Status::Suspended => "Suspended",
        }
    }
}

/// Hashed device components.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Fingerprint {
    pub machine_id: String,
    pub disk_id: String,
    pub host_name: String,
    pub board_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,
}

/// The signed license content.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Payload {
    pub license_id: String,
    pub activation_id: String,
    pub license_key: String,
    pub product: String,
    pub customer: String,
    pub kind: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub issued_at: DateTime<Utc>,
    pub refresh_after: DateTime<Utc>,
    pub offline_until: DateTime<Utc>,
    pub fingerprint: Fingerprint,
    #[serde(default)]
    pub suspended: bool,
    #[serde(default)]
    pub environment_id: Option<String>,
    #[serde(default)]
    pub test: Option<bool>,
    #[serde(default)]
    pub entitlements: Option<Vec<String>>,
    #[serde(default)]
    pub metadata: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default)]
    pub floating: Option<bool>,
    #[serde(default)]
    pub lease_expires_at: Option<DateTime<Utc>>,
}

impl Payload {
    pub fn features(&self) -> &[String] {
        self.entitlements.as_deref().unwrap_or(&[])
    }
    pub fn has_feature(&self, code: &str) -> bool {
        self.features().iter().any(|f| f == code)
    }
    pub fn is_test(&self) -> bool {
        self.test == Some(true)
    }
    pub fn is_floating(&self) -> bool {
        self.floating == Some(true)
    }
}

pub fn parse_public_key(pem: &str) -> Result<VerifyingKey, String> {
    VerifyingKey::from_public_key_pem(pem.trim()).map_err(|e| e.to_string())
}

fn b64(text: &str) -> Option<Vec<u8>> {
    if !text.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
        return None;
    }
    URL_SAFE_NO_PAD.decode(text).ok()
}

/// Verifies the ECDSA P-256/SHA-256 signature (IEEE P1363 r||s) over the ASCII encoded body; returns the payload or None.
pub fn verify_token(token: &str, key: &VerifyingKey) -> Option<Payload> {
    let parts: Vec<&str> = token.trim().split('.').collect();
    if parts.len() != 2 {
        return None;
    }
    let sig_bytes = b64(parts[1])?;
    if sig_bytes.len() != 64 {
        return None;
    }
    let sig = Signature::from_slice(&sig_bytes).ok()?;
    key.verify(parts[0].as_bytes(), &sig).ok()?;
    serde_json::from_slice(&b64(parts[0])?).ok()
}

/// hex(SHA256(vendor + ":" + product + ":" + part + ":" + upper(trim(raw)))); blank gives "none".
/// `vendor` is the organization's slug (fixed for life).
pub fn hash_component(vendor: &str, product: &str, part: &str, raw: Option<&str>) -> String {
    match raw.map(str::trim) {
        None | Some("") => UNAVAILABLE.to_string(),
        Some(t) => hex::encode(Sha256::digest(format!("{vendor}:{product}:{part}:{}", t.to_uppercase()).as_bytes())),
    }
}

fn available(v: &str) -> bool {
    !v.is_empty() && v != UNAVAILABLE
}
fn same(a: &str, b: &str) -> bool {
    available(a) && a == b
}

impl Fingerprint {
    /// Whether `presented` is the device this (registered) fingerprint was issued for.
    pub fn matches(&self, presented: &Fingerprint) -> bool {
        if let (Some(a), Some(b)) = (self.os.as_deref(), presented.os.as_deref()) {
            if !a.is_empty() && !b.is_empty() && !a.eq_ignore_ascii_case(b) {
                return false;
            }
        }
        let n = [(&self.machine_id, &presented.machine_id), (&self.disk_id, &presented.disk_id), (&self.host_name, &presented.host_name)]
            .iter()
            .filter(|(a, b)| same(a, b))
            .count();
        if available(&self.board_id) {
            same(&self.board_id, &presented.board_id) && n >= 1
        } else {
            n >= 2
        }
    }
}

/// The offline check (identical in every SDK).
pub fn evaluate(payload: Option<&Payload>, product: &str, machine: &Fingerprint, now: DateTime<Utc>, last_seen: Option<DateTime<Utc>>) -> Status {
    let Some(p) = payload else { return Status::InvalidSignature };
    if !p.product.eq_ignore_ascii_case(product) {
        return Status::WrongProduct;
    }
    if !p.fingerprint.matches(machine) {
        return Status::WrongMachine;
    }
    if p.suspended {
        return Status::Suspended;
    }
    let Some(seen) = last_seen else { return Status::Unverified };
    if now + Duration::days(1) < p.issued_at || now + Duration::minutes(10) < seen {
        return Status::ClockTampered;
    }
    if matches!(p.expires_at, Some(e) if now >= e) {
        return Status::Expired;
    }
    if now >= p.offline_until {
        return Status::OfflineTooLong;
    }
    Status::Valid
}

pub(crate) fn history_mac(ms: &str, vendor: &str, product: &str, m: &Fingerprint) -> String {
    let key = Sha256::digest(format!("{vendor}:run-history:{product}:{}:{}", m.machine_id, m.board_id).as_bytes());
    let mut mac = Hmac::<Sha256>::new_from_slice(&key).expect("any key length");
    mac.update(ms.as_bytes());
    hex::encode_upper(mac.finalize().into_bytes())[..32].to_string()
}
