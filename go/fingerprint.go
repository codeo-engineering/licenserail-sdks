package licenserail

import (
	"context"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"time"
)

func run(name string, args ...string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).Output()
	if err != nil {
		return ""
	}
	return string(out)
}

func find(text, pattern string) string {
	m := regexp.MustCompile(`(?i)` + pattern).FindStringSubmatch(text)
	if len(m) < 2 {
		return ""
	}
	return m[1]
}

func readFirst(paths ...string) string {
	for _, p := range paths {
		if b, err := os.ReadFile(p); err == nil && strings.TrimSpace(string(b)) != "" {
			return strings.TrimSpace(string(b))
		}
	}
	return ""
}

var placeholder = regexp.MustCompile(`(?i)^[0F]*$`)

// CollectFingerprint hashes this device's identifiers for product (Windows, macOS, Linux).
func CollectFingerprint(vendor, product string) Fingerprint {
	host, _ := os.Hostname()
	var machine, disk, board, osName string
	switch runtime.GOOS {
	case "windows":
		osName = "windows"
		machine = find(run("reg", "query", `HKLM\SOFTWARE\Microsoft\Cryptography`, "/v", "MachineGuid", "/reg:64"), `MachineGuid\s+REG_SZ\s+(\S+)`)
		if m := regexp.MustCompile(`(?i)([0-9A-F]{4})-([0-9A-F]{4})`).FindStringSubmatch(run("cmd", "/c", "vol", "C:")); len(m) == 3 {
			disk = strings.ToUpper(m[1] + m[2])
		}
		board = strings.TrimSpace(run("powershell", "-NoProfile", "-Command", "(Get-CimInstance Win32_ComputerSystemProduct).UUID"))
	case "darwin":
		osName = "macos"
		io := run("ioreg", "-rd1", "-c", "IOPlatformExpertDevice")
		machine = find(io, `"IOPlatformSerialNumber"\s*=\s*"([^"]+)"`)
		board = find(io, `"IOPlatformUUID"\s*=\s*"([^"]+)"`)
		disk = find(run("diskutil", "info", "/"), `Volume UUID:\s*([0-9A-F-]+)`)
		if h := strings.TrimSpace(run("scutil", "--get", "LocalHostName")); h != "" {
			host = h
		}
	default:
		osName = "linux"
		machine = readFirst("/etc/machine-id", "/var/lib/dbus/machine-id")
		board = readFirst("/sys/class/dmi/id/product_uuid")
		for _, line := range strings.Split(readFirst("/proc/self/mountinfo"), "\n") {
			f := strings.Fields(line)
			for i, v := range f {
				if v == "-" && len(f) > 4 && f[4] == "/" && i+2 < len(f) {
					disk = strings.TrimSpace(run("blkid", "-s", "UUID", "-o", "value", f[i+2]))
				}
			}
		}
	}
	if placeholder.MatchString(strings.ReplaceAll(board, "-", "")) {
		board = ""
	}
	return Fingerprint{
		MachineID: HashComponent(vendor, product, "machine", machine),
		DiskID:    HashComponent(vendor, product, "disk", disk),
		HostName:  HashComponent(vendor, product, "host", host),
		BoardID:   HashComponent(vendor, product, "board", board),
		OS:        osName,
	}
}
