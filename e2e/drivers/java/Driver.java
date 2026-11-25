import com.licenserail.Json;
import com.licenserail.LicenseClient;
import com.licenserail.LicenseOptions;
import com.licenserail.Licensing;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class Driver {
    public static void main(String[] args) throws Exception {
        Map<String, String> e = System.getenv();
        LicenseOptions.Builder o = LicenseOptions.builder().serverUrl(e.get("LR_URL")).vendor(e.get("LR_VENDOR")).product(e.get("LR_PRODUCT"))
            .publicKeyPem(Files.readString(Path.of(e.get("LR_PUBLIC_KEY_FILE")))).storageDir(Path.of(e.get("LR_STORAGE"))).appVersion("1.2.3")
            .timeout(Duration.ofSeconds(Long.parseLong(e.get("LR_TIMEOUT"))));
        String[] d = e.getOrDefault("LR_DEVICE", "").split(",");
        if (d.length == 4) o.fingerprint(() -> new Licensing.Fingerprint(d[0], d[1], d[2], d[3], "linux"));
        LicenseClient client = new LicenseClient(o.build());

        Map<String, Object> out = new LinkedHashMap<>();
        switch (args[0]) {
            case "activate": put(out, client.activate(args[1])); break;
            case "deactivate": put(out, client.deactivate()); break;
            case "refresh":
                try {
                    client.refresh(null);
                    out.put("success", true);
                } catch (IOException x) {
                    out.put("success", false);
                    out.put("errorCode", "network");
                    out.put("message", String.valueOf(x.getMessage()));
                }
                break;
            default:
                LicenseClient.CheckResult r = client.check();
                out.put("status", r.status().name());
                out.put("features", r.license() == null ? List.of() : r.license().features());
                out.put("test", r.license() != null && r.license().isTest());
        }
        System.out.println(Json.write(out));
    }

    private static void put(Map<String, Object> out, LicenseClient.ActivationResult r) {
        out.put("success", r.success());
        out.put("errorCode", r.errorCode());
        out.put("message", r.message());
    }
}
