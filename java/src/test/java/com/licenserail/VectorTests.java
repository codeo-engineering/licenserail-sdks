package com.licenserail;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PublicKey;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/** Runs the shared test vectors (plain main so the SDK needs no test framework). Exit code 1 on failure. */
public final class VectorTests {
    private static int failures = 0;

    @SuppressWarnings("unchecked")
    public static void main(String[] args) throws Exception {
        Path dir = Path.of(args.length > 0 ? args[0] : "../test-vectors");

        Map<String, Object> tokens = Json.object(Files.readString(dir.resolve("tokens.json")));
        PublicKey key = Licensing.importPublicKey((String) tokens.get("publicKeyPem"));
        for (Object o : (List<Object>) tokens.get("cases")) {
            Map<String, Object> c = (Map<String, Object>) o;
            Map<String, Object> expect = (Map<String, Object>) c.get("expect");
            Map<String, Object> p = Licensing.verifyToken((String) c.get("token"), key);
            check((p != null) == (Boolean) expect.get("signatureValid"), "token " + c.get("name"));
            if (expect.get("payload") != null)
                for (Map.Entry<String, Object> e : ((Map<String, Object>) expect.get("payload")).entrySet())
                    check(Objects.equals(Json.write(e.getValue()), Json.write(p.get(e.getKey()))), "token " + c.get("name") + " field " + e.getKey());
        }

        for (Object o : (List<Object>) Json.object(Files.readString(dir.resolve("fingerprint.json"))).get("cases")) {
            Map<String, Object> c = (Map<String, Object>) o;
            check(Licensing.hashComponent((String) c.get("vendor"), (String) c.get("product"), (String) c.get("part"), (String) c.get("raw")).equals(c.get("hash")), "hash " + c.get("raw"));
        }

        for (Object o : (List<Object>) Json.object(Files.readString(dir.resolve("match.json"))).get("cases")) {
            Map<String, Object> c = (Map<String, Object>) o;
            boolean m = Licensing.matches(Licensing.Fingerprint.fromMap((Map<?, ?>) c.get("registered")), Licensing.Fingerprint.fromMap((Map<?, ?>) c.get("presented")));
            check(m == (Boolean) c.get("matches"), "match " + c.get("name"));
        }

        Map<String, Object> ev = Json.object(Files.readString(dir.resolve("evaluate.json")));
        PublicKey evKey = Licensing.importPublicKey((String) ev.get("publicKeyPem"));
        for (Object o : (List<Object>) ev.get("cases")) {
            Map<String, Object> c = (Map<String, Object>) o;
            Licensing.Status s = Licensing.evaluate(Licensing.verifyToken((String) c.get("token"), evKey), (String) c.get("product"),
                Licensing.Fingerprint.fromMap((Map<?, ?>) c.get("machine")), Licensing.time(c.get("now")), Licensing.time(c.get("lastSeen")));
            check(s.name().equals(c.get("status")), "evaluate " + c.get("name") + " got " + s);
        }

        System.out.println(failures == 0 ? "All vectors passed." : failures + " vector(s) failed.");
        if (failures > 0) System.exit(1);
    }

    private static void check(boolean ok, String what) {
        if (!ok) { failures++; System.out.println("FAIL: " + what); }
    }
}
