use licenserail::{ActivationResult, Fingerprint, LicenseClient, Options};
use serde_json::{json, Value};
use std::time::Duration;

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_default()
}

fn put(r: ActivationResult) -> Value {
    json!({ "success": r.success, "errorCode": r.error_code, "message": r.message })
}

fn main() {
    let device = env("LR_DEVICE");
    let d: Vec<&str> = device.split(',').collect();
    let fingerprint = (d.len() == 4).then(|| Fingerprint {
        machine_id: d[0].into(),
        disk_id: d[1].into(),
        host_name: d[2].into(),
        board_id: d[3].into(),
        os: Some("linux".into()),
    });
    let mut client = LicenseClient::new(Options {
        server_url: env("LR_URL"),
        vendor: env("LR_VENDOR"),
        product: env("LR_PRODUCT"),
        public_key_pem: std::fs::read_to_string(env("LR_PUBLIC_KEY_FILE")).unwrap(),
        app_version: "1.2.3".into(),
        storage_dir: Some(env("LR_STORAGE").into()),
        timeout: Duration::from_secs(env("LR_TIMEOUT").parse().unwrap()),
        fingerprint,
        ..Options::default()
    })
    .unwrap();
    let args: Vec<String> = std::env::args().collect();
    let out = match args[1].as_str() {
        "activate" => put(client.activate(&args[2], None)),
        "deactivate" => put(client.deactivate()),
        "refresh" => match client.refresh(None) {
            Ok(()) => json!({ "success": true }),
            Err(e) => json!({ "success": false, "errorCode": "network", "message": e }),
        },
        _ => {
            let r = client.check();
            let features: Vec<String> = r.license.as_ref().map(|l| l.features().to_vec()).unwrap_or_default();
            json!({ "status": r.status.as_str(), "features": features, "test": r.license.map_or(false, |l| l.is_test()) })
        }
    };
    println!("{out}");
}
