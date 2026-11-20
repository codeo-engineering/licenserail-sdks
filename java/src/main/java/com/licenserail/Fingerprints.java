package com.licenserail;

import java.io.IOException;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Locale;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Desktop fingerprint (Windows, macOS, Linux). On Android pass your own supplier (an app-scoped install id). */
public final class Fingerprints {
    private Fingerprints() {}

    public static Licensing.Fingerprint collect(String product) {
        String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
        String machine, disk, host = hostName(), board;
        String osName;
        if (os.contains("win")) {
            machine = find(run("reg", "query", "HKLM\\SOFTWARE\\Microsoft\\Cryptography", "/v", "MachineGuid", "/reg:64"), "MachineGuid\\s+REG_SZ\\s+(\\S+)");
            Matcher m = Pattern.compile("([0-9A-F]{4})-([0-9A-F]{4})", Pattern.CASE_INSENSITIVE).matcher(nz(run("cmd", "/c", "vol", "C:")));
            disk = m.find() ? (m.group(1) + m.group(2)).toUpperCase(Locale.ROOT) : null;
            board = nz(run("powershell", "-NoProfile", "-Command", "(Get-CimInstance Win32_ComputerSystemProduct).UUID")).trim();
            osName = "windows";
        } else if (os.contains("mac")) {
            String io = nz(run("ioreg", "-rd1", "-c", "IOPlatformExpertDevice"));
            machine = find(io, "\"IOPlatformSerialNumber\"\\s*=\\s*\"([^\"]+)\"");
            board = find(io, "\"IOPlatformUUID\"\\s*=\\s*\"([^\"]+)\"");
            disk = find(run("diskutil", "info", "/"), "Volume UUID:\\s*([0-9A-F-]+)");
            osName = "macos";
        } else {
            machine = file("/etc/machine-id");
            if (machine == null) machine = file("/var/lib/dbus/machine-id");
            disk = null;
            board = file("/sys/class/dmi/id/product_uuid");
            osName = "linux";
        }
        if (board != null && board.replace("-", "").matches("(?i)[0F]*")) board = null;
        return new Licensing.Fingerprint(Licensing.hashComponent(product, "machine", machine), Licensing.hashComponent(product, "disk", disk),
            Licensing.hashComponent(product, "host", host), Licensing.hashComponent(product, "board", board), osName);
    }

    private static String hostName() {
        try { return InetAddress.getLocalHost().getHostName(); } catch (IOException e) { return null; }
    }

    private static String nz(String s) { return s == null ? "" : s; }

    private static String find(String text, String regex) {
        if (text == null) return null;
        Matcher m = Pattern.compile(regex, Pattern.CASE_INSENSITIVE).matcher(text);
        return m.find() ? m.group(1) : null;
    }

    private static String file(String path) {
        try { String v = Files.readString(Path.of(path)).trim(); return v.isEmpty() ? null : v; } catch (IOException | SecurityException e) { return null; }
    }

    private static String run(String... cmd) {
        try {
            Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
            String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            return p.waitFor(5, TimeUnit.SECONDS) ? out : null;
        } catch (IOException | InterruptedException e) {
            return null;
        }
    }
}
