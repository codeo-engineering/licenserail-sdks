use crate::{hash_component, Fingerprint};
use std::process::Command;

fn run(cmd: &str, args: &[&str]) -> Option<String> {
    Command::new(cmd).args(args).output().ok().filter(|o| o.status.success()).map(|o| String::from_utf8_lossy(&o.stdout).to_string())
}

fn after<'a>(text: &'a str, marker: &str) -> Option<&'a str> {
    let rest = &text[text.find(marker)? + marker.len()..];
    let rest = rest.trim_start_matches(|c: char| c == ' ' || c == '=' || c == '"' || c == ':');
    rest.split(|c: char| c == '"' || c == '\n' || c == '\r').next().map(str::trim).filter(|s| !s.is_empty())
}

fn read(path: &str) -> Option<String> {
    std::fs::read_to_string(path).ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

/// Hashes this device's identifiers for `product` (Windows, macOS, Linux).
pub fn collect_fingerprint(product: &str) -> Fingerprint {
    let host = std::env::var("COMPUTERNAME").ok().or_else(|| read("/etc/hostname")).or_else(|| run("hostname", &[]).map(|s| s.trim().to_string()));
    let (machine, disk, board, os): (Option<String>, Option<String>, Option<String>, &str) = if cfg!(windows) {
        let reg = run("reg", &["query", r"HKLM\SOFTWARE\Microsoft\Cryptography", "/v", "MachineGuid", "/reg:64"]).unwrap_or_default();
        let machine = reg.split_whitespace().skip_while(|w| *w != "REG_SZ").nth(1).map(str::to_string);
        let vol = run("cmd", &["/c", "vol", "C:"]).unwrap_or_default();
        let disk = vol.split_whitespace().last().map(|s| s.replace('-', "").to_uppercase()).filter(|s| s.len() == 8);
        let board = run("powershell", &["-NoProfile", "-Command", "(Get-CimInstance Win32_ComputerSystemProduct).UUID"]).map(|s| s.trim().to_string());
        (machine, disk, board, "windows")
    } else if cfg!(target_os = "macos") {
        let io = run("ioreg", &["-rd1", "-c", "IOPlatformExpertDevice"]).unwrap_or_default();
        let disk = run("diskutil", &["info", "/"]).and_then(|d| after(&d, "Volume UUID").map(str::to_string));
        (after(&io, "\"IOPlatformSerialNumber\"").map(str::to_string), disk, after(&io, "\"IOPlatformUUID\"").map(str::to_string), "macos")
    } else {
        (read("/etc/machine-id").or_else(|| read("/var/lib/dbus/machine-id")), None, read("/sys/class/dmi/id/product_uuid"), "linux")
    };
    let board = board.filter(|b| !b.replace('-', "").chars().all(|c| c == '0' || c == 'F' || c == 'f'));
    Fingerprint {
        machine_id: hash_component(product, "machine", machine.as_deref()),
        disk_id: hash_component(product, "disk", disk.as_deref()),
        host_name: hash_component(product, "host", host.as_deref()),
        board_id: hash_component(product, "board", board.as_deref()),
        os: Some(os.to_string()),
    }
}
