package com.licenserail;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/** Offline license logic shared by every LicenseRail SDK (see the test vectors). */
public final class Licensing {
    private Licensing() {}

    public static final String UNAVAILABLE = "none";
    public static final Duration CLOCK_TOLERANCE = Duration.ofMinutes(10);
    public static final Duration ISSUED_AT_TOLERANCE = Duration.ofDays(1);
    /** Error codes on which the local license is deleted; others (network, 402...) keep it. */
    public static final Set<String> REVOKING_CODES = Set.of("license_not_found", "license_suspended", "license_expired", "activation_revoked",
        "wrong_machine", "invalid_token", "license_revoked");

    public enum Status { Valid, Missing, InvalidSignature, WrongProduct, WrongMachine, Expired, OfflineTooLong, ClockTampered, Unverified, Suspended }

    /** Hashed device components. */
    public static final class Fingerprint {
        public final String machineId, diskId, hostName, boardId, os;

        public Fingerprint(String machineId, String diskId, String hostName, String boardId, String os) {
            this.machineId = machineId; this.diskId = diskId; this.hostName = hostName; this.boardId = boardId; this.os = os;
        }

        public static Fingerprint fromMap(Map<?, ?> m) {
            return new Fingerprint((String) m.get("machineId"), (String) m.get("diskId"), (String) m.get("hostName"), (String) m.get("boardId"),
                (String) m.get("os"));
        }

        public Map<String, Object> toMap() {
            Map<String, Object> m = new java.util.LinkedHashMap<>();
            m.put("machineId", machineId); m.put("diskId", diskId); m.put("hostName", hostName); m.put("boardId", boardId);
            if (os != null) m.put("os", os);
            return m;
        }
    }

    public static PublicKey importPublicKey(String pem) {
        try {
            String b64 = pem.replaceAll("-----[A-Z ]+-----", "").replaceAll("\\s", "");
            return KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(b64)));
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid public key PEM", e);
        }
    }

    /** Verifies ECDSA P-256 / SHA-256 (IEEE P1363 r||s) over the ASCII encoded body; returns the payload or null. */
    public static Map<String, Object> verifyToken(String token, PublicKey key) {
        if (token == null) return null;
        String[] parts = token.trim().split("\\.", -1);
        if (parts.length != 2 || !parts[0].matches("[A-Za-z0-9_-]*") || !parts[1].matches("[A-Za-z0-9_-]*")) return null;
        try {
            byte[] sig = Base64.getUrlDecoder().decode(parts[1]);
            if (sig.length != 64) return null;
            Signature v = Signature.getInstance("SHA256withECDSAinP1363Format");
            v.initVerify(key);
            v.update(parts[0].getBytes(StandardCharsets.US_ASCII));
            if (!v.verify(sig)) return null;
            Map<String, Object> payload = Json.object(new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8));
            return payload.get("fingerprint") instanceof Map ? payload : null;
        } catch (Exception e) {
            return null;
        }
    }

    /** hex(SHA256(vendor + ":" + product + ":" + part + ":" + upper(trim(raw)))); vendor = the organization ID (ten_..., never changes). */
    public static String hashComponent(String vendor, String product, String part, String raw) {
        if (raw == null || raw.strip().isEmpty()) return UNAVAILABLE;
        try {
            byte[] h = MessageDigest.getInstance("SHA-256")
                .digest((vendor + ":" + product + ":" + part + ":" + raw.strip().toUpperCase(Locale.ROOT)).getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(h);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static boolean available(String v) { return v != null && !v.isEmpty() && !UNAVAILABLE.equals(v); }
    private static boolean same(String a, String b) { return available(a) && a.equals(b); }

    public static boolean matches(Fingerprint registered, Fingerprint presented) {
        if (registered.os != null && !registered.os.isEmpty() && presented.os != null && !presented.os.isEmpty()
            && !registered.os.equalsIgnoreCase(presented.os)) return false;
        int n = 0;
        if (same(registered.machineId, presented.machineId)) n++;
        if (same(registered.diskId, presented.diskId)) n++;
        if (same(registered.hostName, presented.hostName)) n++;
        return available(registered.boardId) ? same(registered.boardId, presented.boardId) && n >= 1 : n >= 2;
    }

    public static Instant time(Object iso) { return iso == null ? null : OffsetDateTime.parse((String) iso).toInstant(); }

    public static Status evaluate(Map<String, Object> payload, String product, Fingerprint machine, Instant now, Instant lastSeen) {
        if (payload == null) return Status.InvalidSignature;
        if (!Objects.toString(payload.get("product"), "").equalsIgnoreCase(product)) return Status.WrongProduct;
        if (!matches(Fingerprint.fromMap((Map<?, ?>) payload.get("fingerprint")), machine)) return Status.WrongMachine;
        if (Boolean.TRUE.equals(payload.get("suspended"))) return Status.Suspended;
        if (lastSeen == null) return Status.Unverified;
        if (now.plus(ISSUED_AT_TOLERANCE).isBefore(time(payload.get("issuedAt"))) || now.plus(CLOCK_TOLERANCE).isBefore(lastSeen)) return Status.ClockTampered;
        Instant expires = time(payload.get("expiresAt"));
        if (expires != null && !now.isBefore(expires)) return Status.Expired;
        if (!now.isBefore(time(payload.get("offlineUntil")))) return Status.OfflineTooLong;
        return Status.Valid;
    }
}
