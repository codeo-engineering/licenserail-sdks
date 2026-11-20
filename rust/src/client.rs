use crate::{evaluate, history_mac, parse_public_key, verify_token, Fingerprint, Payload, Status, REVOKING_CODES};
use chrono::{DateTime, TimeZone, Utc};
use p256::ecdsa::VerifyingKey;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::time::Duration;

/// Client options. `server_url`, `product` and `public_key_pem` are required.
#[derive(Clone)]
pub struct Options {
    pub server_url: String,
    pub product: String,
    pub public_key_pem: String,
    pub app_version: String,
    pub storage_dir: Option<PathBuf>,
    pub refresh_on_startup: bool,
    pub timeout: Duration,
    pub machine_name: Option<String>,
    /// Overrides device fingerprinting (tests, custom ids).
    pub fingerprint: Option<Fingerprint>,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            server_url: String::new(),
            product: String::new(),
            public_key_pem: String::new(),
            app_version: String::new(),
            storage_dir: None,
            refresh_on_startup: false,
            timeout: Duration::from_secs(10),
            machine_name: None,
            fingerprint: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ActivationResult {
    pub success: bool,
    pub error_code: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct CheckResult {
    pub status: Status,
    pub license: Option<Payload>,
}

impl CheckResult {
    pub fn is_valid(&self) -> bool {
        self.status == Status::Valid
    }
}

/// Licensing for a vendor's app (desktop, Tauri). Needs only the public key; never ship an API key.
pub struct LicenseClient {
    opts: Options,
    key: VerifyingKey,
    dir: PathBuf,
    fp: Option<Fingerprint>,
    agent: ureq::Agent,
    /// Why the server removed the license, if it did.
    pub last_server_message: Option<String>,
}

fn fail(code: &str, message: &str) -> ActivationResult {
    ActivationResult { success: false, error_code: Some(code.to_string()), message: message.to_string() }
}

impl LicenseClient {
    pub fn new(opts: Options) -> Result<Self, String> {
        if opts.server_url.is_empty() || opts.product.is_empty() || opts.public_key_pem.is_empty() {
            return Err("server_url, product and public_key_pem are required".into());
        }
        let key = parse_public_key(&opts.public_key_pem)?;
        let dir = opts.storage_dir.clone().unwrap_or_else(|| {
            let base = std::env::var_os("LOCALAPPDATA")
                .or_else(|| std::env::var_os("XDG_DATA_HOME"))
                .map(PathBuf::from)
                .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local").join("share")))
                .unwrap_or_else(std::env::temp_dir);
            base.join("licenserail").join(&opts.product)
        });
        let agent = ureq::AgentBuilder::new().timeout(opts.timeout).build();
        Ok(LicenseClient { fp: opts.fingerprint.clone(), opts, key, dir, agent, last_server_message: None })
    }

    fn fingerprint(&mut self) -> Fingerprint {
        if self.fp.is_none() {
            self.fp = Some(crate::collect_fingerprint(&self.opts.product));
        }
        self.fp.clone().unwrap()
    }

    pub fn license(&self) -> Option<Payload> {
        self.read("license.lic").and_then(|t| verify_token(&t, &self.key))
    }

    pub fn evaluate_local(&mut self) -> CheckResult {
        let Some(token) = self.read("license.lic") else { return CheckResult { status: Status::Missing, license: None } };
        let payload = verify_token(&token, &self.key);
        let fp = self.fingerprint();
        let last = self.read("license.seen").and_then(|v| self.decode_history(&v, &fp));
        let now = Utc::now();
        let status = evaluate(payload.as_ref(), &self.opts.product, &fp, now, last);
        if matches!(status, Status::Valid | Status::Expired | Status::OfflineTooLong) && last.map_or(true, |l| now > l) {
            let h = self.encode_history(now, &fp);
            self.write("license.seen", &h);
        }
        CheckResult { status, license: payload }
    }

    /// Call on startup: evaluates offline, refreshes online when due or when only the server can clear the state.
    pub fn check(&mut self) -> CheckResult {
        let mut r = self.evaluate_local();
        let due = r.is_valid() && (self.opts.refresh_on_startup || Utc::now() >= r.license.as_ref().unwrap().refresh_after);
        if due || matches!(r.status, Status::Expired | Status::Suspended | Status::OfflineTooLong | Status::ClockTampered | Status::Unverified) {
            let anomalies = match r.status {
                Status::ClockTampered => Some(vec!["clock_rollback"]),
                Status::Unverified => Some(vec!["history_missing"]),
                _ => None,
            };
            let _ = self.refresh(anomalies);
            r = self.evaluate_local();
        }
        if r.license.as_ref().map_or(false, |l| l.is_test()) {
            eprintln!("[licenserail] Test license: not for production use.");
        }
        r
    }

    pub fn activate(&mut self, license_key: &str, machine_name: Option<&str>) -> ActivationResult {
        let key = license_key.trim();
        if key.is_empty() {
            return fail("bad_request", "Enter the license key.");
        }
        let name = machine_name.map(str::to_string).or_else(|| self.opts.machine_name.clone()).unwrap_or_else(host_name);
        let body = json!({ "licenseKey": key, "product": self.opts.product, "fingerprint": self.fingerprint(), "machineName": name, "appVersion": self.opts.app_version });
        let mut res = self.post("/api/client/v2/activate", &body);
        let floating = matches!(&res, Ok((false, v)) if v["code"] == "bad_request"
            && v["message"].as_str().unwrap_or("").to_lowercase().contains("floating"));
        if floating {
            res = self.post("/api/client/v2/floating/checkout", &body);
        }
        match res {
            Err(_) => fail("network", "Could not connect to the license server."),
            Ok((false, v)) => fail(v["code"].as_str().unwrap_or("error"), v["message"].as_str().unwrap_or("Server error.")),
            Ok((true, v)) => {
                if !self.save_if_valid(v["token"].as_str().unwrap_or("")) {
                    return fail("invalid_token", "The server returned an invalid license.");
                }
                let r = self.evaluate_local();
                if r.is_valid() {
                    ActivationResult { success: true, error_code: None, message: "The license has been activated.".into() }
                } else {
                    fail(r.status.as_str(), r.status.as_str())
                }
            }
        }
    }

    pub fn deactivate(&mut self) -> ActivationResult {
        let Some(token) = self.read("license.lic") else {
            return ActivationResult { success: true, error_code: None, message: "There is no license on this device.".into() };
        };
        let floating = verify_token(&token, &self.key).map_or(false, |p| p.is_floating());
        let path = if floating { "/api/client/v2/floating/release" } else { "/api/client/v2/deactivate" };
        let body = json!({ "token": token, "fingerprint": self.fingerprint() });
        match self.post(path, &body) {
            Err(_) => fail("network", "Removing the license needs an internet connection."),
            Ok((ok, v)) => {
                let code = v["code"].as_str().unwrap_or("").to_string();
                if !ok && !REVOKING_CODES.contains(&code.as_str()) {
                    return fail(&code, v["message"].as_str().unwrap_or("Server error."));
                }
                self.remove("license.lic");
                if !ok && code == "wrong_machine" {
                    return fail(&code, v["message"].as_str().unwrap_or(""));
                }
                ActivationResult { success: true, error_code: None, message: "The license has been removed from this device.".into() }
            }
        }
    }

    /// Fresh token now (floating: a heartbeat; call every lease/2 while the app runs).
    pub fn refresh(&mut self, anomalies: Option<Vec<&str>>) -> Result<(), String> {
        let Some(token) = self.read("license.lic") else { return Ok(()) };
        let floating = verify_token(&token, &self.key).map_or(false, |p| p.is_floating());
        let path = if floating { "/api/client/v2/floating/heartbeat" } else { "/api/client/v2/refresh" };
        let body = json!({ "token": token, "fingerprint": self.fingerprint(), "appVersion": self.opts.app_version, "anomalies": anomalies });
        let (ok, v) = self.post(path, &body)?;
        let code = v["code"].as_str().unwrap_or("");
        if ok {
            self.save_if_valid(v["token"].as_str().unwrap_or(""));
        } else if REVOKING_CODES.contains(&code) || code == "lease_expired" {
            self.remove("license.lic");
            self.last_server_message = v["message"].as_str().map(str::to_string);
        }
        Ok(())
    }

    fn post(&self, path: &str, body: &Value) -> Result<(bool, Value), String> {
        let url = format!("{}{}", self.opts.server_url.trim_end_matches('/'), path);
        match self.agent.post(&url).send_json(body.clone()) {
            Ok(r) => {
                let text = r.into_string().map_err(|e| e.to_string())?;
                Ok((true, if text.is_empty() { Value::Null } else { serde_json::from_str(&text).map_err(|e| e.to_string())? }))
            }
            Err(ureq::Error::Status(_, r)) => Ok((false, r.into_json::<Value>().unwrap_or(Value::Null))),
            Err(e) => Err(e.to_string()),
        }
    }

    fn save_if_valid(&mut self, token: &str) -> bool {
        match verify_token(token, &self.key) {
            Some(p) if p.product.eq_ignore_ascii_case(&self.opts.product) => {
                self.write("license.lic", token);
                let fp = self.fingerprint();
                let h = self.encode_history(Utc::now(), &fp);
                self.write("license.seen", &h);
                true
            }
            _ => false,
        }
    }

    fn encode_history(&self, at: DateTime<Utc>, fp: &Fingerprint) -> String {
        let ms = at.timestamp_millis().to_string();
        format!("{ms}.{}", history_mac(&ms, &self.opts.product, fp))
    }

    fn decode_history(&self, v: &str, fp: &Fingerprint) -> Option<DateTime<Utc>> {
        let (ms, mac) = v.trim().split_once('.')?;
        let n: i64 = ms.parse().ok()?;
        if mac != history_mac(ms, &self.opts.product, fp) {
            return None;
        }
        Utc.timestamp_millis_opt(n).single()
    }

    fn read(&self, name: &str) -> Option<String> {
        std::fs::read_to_string(self.dir.join(name)).ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
    }

    fn write(&self, name: &str, value: &str) {
        let _ = std::fs::create_dir_all(&self.dir);
        let _ = std::fs::write(self.dir.join(name), value);
    }

    fn remove(&self, name: &str) {
        let _ = std::fs::remove_file(self.dir.join(name));
    }
}

fn host_name() -> String {
    std::env::var("COMPUTERNAME").or_else(|_| std::env::var("HOSTNAME")).unwrap_or_else(|_| {
        std::fs::read_to_string("/etc/hostname").map(|s| s.trim().to_string()).unwrap_or_else(|_| "Unknown".into())
    })
}
