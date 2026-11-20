use chrono::{DateTime, Utc};
use licenserail::{evaluate, hash_component, parse_public_key, verify_token, Fingerprint};
use serde_json::Value;

fn load(name: &str) -> Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../test-vectors").join(name);
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn time(v: &Value) -> Option<DateTime<Utc>> {
    v.as_str().map(|s| DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc))
}

#[test]
fn tokens() {
    let v = load("tokens.json");
    let key = parse_public_key(v["publicKeyPem"].as_str().unwrap()).unwrap();
    for c in v["cases"].as_array().unwrap() {
        let p = verify_token(c["token"].as_str().unwrap(), &key);
        assert_eq!(p.is_some(), c["expect"]["signatureValid"].as_bool().unwrap(), "{}", c["name"]);
        if let (Some(p), Some(exp)) = (p, c["expect"]["payload"].as_object()) {
            let actual = serde_json::to_value(&p).unwrap();
            for k in ["licenseKey", "product", "customer", "kind", "suspended", "entitlements", "metadata"] {
                if let Some(e) = exp.get(k) {
                    assert_eq!(&actual[k], e, "{}: {}", c["name"], k);
                }
            }
        }
    }
}

#[test]
fn fingerprint_hashing() {
    for c in load("fingerprint.json")["cases"].as_array().unwrap() {
        let got = hash_component(c["product"].as_str().unwrap(), c["part"].as_str().unwrap(), c["raw"].as_str());
        assert_eq!(got, c["hash"].as_str().unwrap(), "{}", c);
    }
}

#[test]
fn matching() {
    for c in load("match.json")["cases"].as_array().unwrap() {
        let r: Fingerprint = serde_json::from_value(c["registered"].clone()).unwrap();
        let p: Fingerprint = serde_json::from_value(c["presented"].clone()).unwrap();
        assert_eq!(r.matches(&p), c["matches"].as_bool().unwrap(), "{}", c["name"]);
    }
}

#[test]
fn evaluation() {
    let v = load("evaluate.json");
    let key = parse_public_key(v["publicKeyPem"].as_str().unwrap()).unwrap();
    for c in v["cases"].as_array().unwrap() {
        let p = verify_token(c["token"].as_str().unwrap(), &key);
        let m: Fingerprint = serde_json::from_value(c["machine"].clone()).unwrap();
        let s = evaluate(p.as_ref(), c["product"].as_str().unwrap(), &m, time(&c["now"]).unwrap(), time(&c["lastSeen"]));
        assert_eq!(s.as_str(), c["status"].as_str().unwrap(), "{}", c["name"]);
    }
}
