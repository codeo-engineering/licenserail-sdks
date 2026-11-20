package com.licenserail;

import java.io.IOException;
import java.net.InetAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Licensing for a vendor's app (desktop Java, Kotlin, Android): offline verification on every start, online refresh when due,
 * activation, deactivation and floating leases. Needs only the public key; never ship an API key.
 */
public final class LicenseClient {
    public record ActivationResult(boolean success, String errorCode, String message) {}

    public record CheckResult(Licensing.Status status, License license) {
        public boolean isValid() { return status == Licensing.Status.Valid; }
    }

    /** Read-only view of the current license. */
    public record License(Map<String, Object> payload) {
        public String key() { return (String) payload.get("licenseKey"); }
        public String customer() { return (String) payload.get("customer"); }
        public Instant expiresAt() { return Licensing.time(payload.get("expiresAt")); }
        public boolean isTest() { return Boolean.TRUE.equals(payload.get("test")); }
        public boolean isFloating() { return Boolean.TRUE.equals(payload.get("floating")); }
        @SuppressWarnings("unchecked")
        public List<String> features() { Object f = payload.get("entitlements"); return f == null ? List.of() : (List<String>) f; }
        @SuppressWarnings("unchecked")
        public Map<String, Object> metadata() { Object m = payload.get("metadata"); return m == null ? Map.of() : (Map<String, Object>) m; }
        public boolean hasFeature(String code) { return features().contains(code); }
    }

    private final LicenseOptions options;
    private final PublicKey key;
    private final HttpClient http;
    private final Path dir;
    private final Supplier<Licensing.Fingerprint> fingerprintSupplier;
    private Licensing.Fingerprint fp;
    private String lastServerMessage;

    public LicenseClient(LicenseOptions options) {
        this.options = options;
        this.key = Licensing.importPublicKey(options.publicKeyPem());
        this.http = HttpClient.newBuilder().connectTimeout(options.timeout()).build();
        this.dir = options.storageDir() != null ? options.storageDir()
            : Path.of(System.getProperty("user.home"), ".licenserail", options.product());
        this.fingerprintSupplier = options.fingerprint() != null ? options.fingerprint() : () -> Fingerprints.collect(options.product());
    }

    private Licensing.Fingerprint fingerprint() { if (fp == null) fp = fingerprintSupplier.get(); return fp; }
    public String lastServerMessage() { return lastServerMessage; }

    public License license() {
        Map<String, Object> p = Licensing.verifyToken(read("license.lic"), key);
        return p == null ? null : new License(p);
    }

    public CheckResult evaluateLocal() {
        String token = read("license.lic");
        if (token == null) return new CheckResult(Licensing.Status.Missing, null);
        Map<String, Object> payload = Licensing.verifyToken(token, key);
        Instant lastSeen = decodeHistory(read("license.seen"));
        Instant now = Instant.now();
        Licensing.Status status = Licensing.evaluate(payload, options.product(), fingerprint(), now, lastSeen);
        if ((status == Licensing.Status.Valid || status == Licensing.Status.Expired || status == Licensing.Status.OfflineTooLong)
            && (lastSeen == null || now.isAfter(lastSeen))) write("license.seen", encodeHistory(now));
        return new CheckResult(status, payload == null ? null : new License(payload));
    }

    /** Call on startup: evaluates offline, refreshes online when due or when only the server can clear the state. */
    public CheckResult check() {
        CheckResult r = evaluateLocal();
        boolean due = r.isValid() && (options.refreshOnStartup() || !Instant.now().isBefore(Licensing.time(r.license().payload().get("refreshAfter"))));
        if (due || List.of(Licensing.Status.Expired, Licensing.Status.Suspended, Licensing.Status.OfflineTooLong, Licensing.Status.ClockTampered,
            Licensing.Status.Unverified).contains(r.status())) {
            List<String> anomalies = r.status() == Licensing.Status.ClockTampered ? List.of("clock_rollback")
                : r.status() == Licensing.Status.Unverified ? List.of("history_missing") : null;
            try { refresh(anomalies); } catch (IOException | InterruptedException e) { /* offline: the local result stands */ }
            r = evaluateLocal();
        }
        if (r.license() != null && r.license().isTest()) System.err.println("[licenserail] Test license: not for production use.");
        return r;
    }

    public ActivationResult activate(String licenseKey) {
        if (licenseKey == null || licenseKey.isBlank()) return new ActivationResult(false, "bad_request", "Enter the license key.");
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("licenseKey", licenseKey.trim());
        body.put("product", options.product());
        body.put("fingerprint", fingerprint().toMap());
        body.put("machineName", machineName());
        body.put("appVersion", options.appVersion());
        try {
            Map<String, Object> r = post("/api/client/v2/activate", body);
            if (r.get("error") != null && String.valueOf(r.get("message")).toLowerCase().contains("floating"))
                r = post("/api/client/v2/floating/checkout", body);
            if (r.get("error") != null) return new ActivationResult(false, (String) r.get("code"), String.valueOf(r.get("message")));
            if (!saveIfValid((String) r.get("token"))) return new ActivationResult(false, "invalid_token", "The server returned an invalid license.");
        } catch (IOException | InterruptedException e) {
            return new ActivationResult(false, "network", "Could not connect to the license server.");
        }
        CheckResult c = evaluateLocal();
        return c.isValid() ? new ActivationResult(true, null, "The license has been activated.") : new ActivationResult(false, c.status().name(), c.status().name());
    }

    public ActivationResult deactivate() {
        String token = read("license.lic");
        if (token == null) return new ActivationResult(true, null, "There is no license on this device.");
        Map<String, Object> p = Licensing.verifyToken(token, key);
        boolean floating = p != null && Boolean.TRUE.equals(p.get("floating"));
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("token", token);
        body.put("fingerprint", fingerprint().toMap());
        try {
            Map<String, Object> r = post(floating ? "/api/client/v2/floating/release" : "/api/client/v2/deactivate", body);
            String code = (String) r.get("code");
            if (r.get("error") != null && !Licensing.REVOKING_CODES.contains(code)) return new ActivationResult(false, code, String.valueOf(r.get("message")));
            delete("license.lic");
            return "wrong_machine".equals(code) ? new ActivationResult(false, code, String.valueOf(r.get("message")))
                : new ActivationResult(true, null, "The license has been removed from this device.");
        } catch (IOException | InterruptedException e) {
            return new ActivationResult(false, "network", "Removing the license needs an internet connection.");
        }
    }

    /** Fresh token now (floating licenses: a heartbeat; call it every lease/2 while running). */
    public void refresh(List<String> anomalies) throws IOException, InterruptedException {
        String token = read("license.lic");
        if (token == null) return;
        Map<String, Object> p = Licensing.verifyToken(token, key);
        boolean floating = p != null && Boolean.TRUE.equals(p.get("floating"));
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("token", token);
        body.put("fingerprint", fingerprint().toMap());
        body.put("appVersion", options.appVersion());
        body.put("anomalies", anomalies);
        Map<String, Object> r = post(floating ? "/api/client/v2/floating/heartbeat" : "/api/client/v2/refresh", body);
        if (r.get("error") == null) saveIfValid((String) r.get("token"));
        else if (Licensing.REVOKING_CODES.contains(r.get("code")) || "lease_expired".equals(r.get("code"))) {
            delete("license.lic");
            lastServerMessage = String.valueOf(r.get("message"));
        }
    }

    private String machineName() {
        try { return options.machineName() != null ? options.machineName() : InetAddress.getLocalHost().getHostName(); }
        catch (IOException e) { return "Unknown"; }
    }

    /** POSTs JSON; on an HTTP error the map carries "error": true plus the server's code/message. */
    private Map<String, Object> post(String path, Map<String, Object> body) throws IOException, InterruptedException {
        HttpRequest req = HttpRequest.newBuilder(URI.create(options.serverUrl().replaceAll("/+$", "") + path))
            .timeout(options.timeout()).header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(Json.write(body))).build();
        HttpResponse<String> res = http.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        Map<String, Object> map = res.body() == null || res.body().isBlank() ? new LinkedHashMap<>() : new LinkedHashMap<>(Json.object(res.body()));
        if (res.statusCode() >= 400) map.put("error", true);
        return map;
    }

    private boolean saveIfValid(String token) {
        Map<String, Object> p = Licensing.verifyToken(token, key);
        if (p == null || !String.valueOf(p.get("product")).equalsIgnoreCase(options.product())) return false;
        write("license.lic", token);
        write("license.seen", encodeHistory(Instant.now()));
        return true;
    }

    private String mac(String ms) {
        try {
            byte[] k = MessageDigest.getInstance("SHA-256").digest(
                ("codeo-run-history:" + options.product() + ":" + fingerprint().machineId + ":" + fingerprint().boardId).getBytes(StandardCharsets.UTF_8));
            Mac m = Mac.getInstance("HmacSHA256");
            m.init(new SecretKeySpec(k, "HmacSHA256"));
            return HexFormat.of().withUpperCase().formatHex(m.doFinal(ms.getBytes(StandardCharsets.US_ASCII))).substring(0, 32);
        } catch (Exception e) { throw new IllegalStateException(e); }
    }

    private String encodeHistory(Instant at) { String ms = Long.toString(at.toEpochMilli()); return ms + "." + mac(ms); }

    private Instant decodeHistory(String v) {
        if (v == null) return null;
        String[] p = v.trim().split("\\.");
        if (p.length != 2 || !p[0].matches("\\d{1,15}") || !MessageDigest.isEqual(p[1].getBytes(), mac(p[0]).getBytes())) return null;
        return Instant.ofEpochMilli(Long.parseLong(p[0]));
    }

    private String read(String name) {
        try { Path f = dir.resolve(name); return Files.exists(f) ? Files.readString(f).trim() : null; } catch (IOException e) { return null; }
    }

    private void write(String name, String value) {
        try { Files.createDirectories(dir); Files.writeString(dir.resolve(name), value); } catch (IOException e) { throw new IllegalStateException(e); }
    }

    private void delete(String name) { try { Files.deleteIfExists(dir.resolve(name)); } catch (IOException ignored) { } }

    static Duration defaultTimeout() { return Duration.ofSeconds(10); }
}
