package com.licenserail;

import java.nio.file.Path;
import java.time.Duration;
import java.util.function.Supplier;

/** Client options; build with {@link #builder()}. */
public record LicenseOptions(String serverUrl, String vendor, String product, String publicKeyPem, String appVersion, Path storageDir, boolean refreshOnStartup,
                             Duration timeout, String machineName, Supplier<Licensing.Fingerprint> fingerprint) {

    public static Builder builder() { return new Builder(); }

    public static final class Builder {
        private String serverUrl, vendor, product, publicKeyPem, appVersion, machineName;
        private Path storageDir;
        private boolean refreshOnStartup;
        private Duration timeout = LicenseClient.defaultTimeout();
        private Supplier<Licensing.Fingerprint> fingerprint;

        public Builder serverUrl(String v) { serverUrl = v; return this; }
        /** Your organization ID from the dashboard (ten_...; part of every device identity). */
        public Builder vendor(String v) { vendor = v; return this; }
        public Builder product(String v) { product = v; return this; }
        public Builder publicKeyPem(String v) { publicKeyPem = v; return this; }
        public Builder appVersion(String v) { appVersion = v; return this; }
        public Builder storageDir(Path v) { storageDir = v; return this; }
        public Builder refreshOnStartup(boolean v) { refreshOnStartup = v; return this; }
        public Builder timeout(Duration v) { timeout = v; return this; }
        public Builder machineName(String v) { machineName = v; return this; }
        /** Custom device id (Android: an app-scoped install id hashed with Licensing.hashComponent). */
        public Builder fingerprint(Supplier<Licensing.Fingerprint> v) { fingerprint = v; return this; }

        public LicenseOptions build() {
            if (serverUrl == null || vendor == null || product == null || publicKeyPem == null)
                throw new IllegalArgumentException("serverUrl, vendor, product and publicKeyPem are required");
            return new LicenseOptions(serverUrl, vendor, product, publicKeyPem, appVersion, storageDir, refreshOnStartup, timeout, machineName, fingerprint);
        }
    }
}
