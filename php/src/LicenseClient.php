<?php

declare(strict_types=1);

namespace LicenseRail;

final class ActivationResult
{
    public function __construct(public readonly bool $success, public readonly string $message, public readonly ?string $errorCode = null) {}
}

final class CheckResult
{
    public function __construct(public readonly string $status, public readonly ?License $license) {}

    public function isValid(): bool
    {
        return $this->status === 'Valid';
    }
}

final class License
{
    public function __construct(public readonly array $payload) {}

    public function key(): string { return $this->payload['licenseKey']; }
    public function customer(): string { return $this->payload['customer']; }
    public function isTest(): bool { return ($this->payload['test'] ?? false) === true; }
    public function features(): array { return $this->payload['entitlements'] ?? []; }
    public function metadata(): array { return $this->payload['metadata'] ?? []; }
    public function hasFeature(string $code): bool { return in_array($code, $this->features(), true); }
}

/**
 * Licensing for PHP apps and WordPress plugins. Licenses are per site by default: the fingerprint is built from the site's
 * host and an install id stored next to the license, so a copied plugin folder on another site doesn't validate.
 * Needs only the public key; never ship an API key.
 */
final class LicenseClient
{
    private string $server;
    /** Your organization ID from the dashboard (ten_...; part of every device identity). */
    private string $vendor;
    private string $product;
    private string $publicKey;
    private string $dir;
    private ?string $appVersion;
    private bool $refreshOnStartup;
    private ?array $fingerprint;
    private int $timeout;
    public ?string $lastServerMessage = null;

    /** @param array{serverUrl:string,vendor:string,product:string,publicKeyPem:string,storageDir?:string,appVersion?:string,refreshOnStartup?:bool,fingerprint?:array,siteUrl?:string,timeout?:int} $options */
    public function __construct(array $options)
    {
        foreach (['serverUrl', 'vendor', 'product', 'publicKeyPem'] as $k) {
            if (empty($options[$k])) {
                throw new \InvalidArgumentException("$k is required");
            }
        }
        $this->server = rtrim($options['serverUrl'], '/');
        $this->vendor = $options['vendor'];
        $this->product = $options['product'];
        $this->publicKey = $options['publicKeyPem'];
        $this->appVersion = $options['appVersion'] ?? null;
        $this->refreshOnStartup = $options['refreshOnStartup'] ?? false;
        $this->timeout = $options['timeout'] ?? 10;
        $default = function_exists('wp_upload_dir') ? wp_upload_dir()['basedir'] . '/licenserail/' . $this->product : sys_get_temp_dir() . '/licenserail/' . $this->product;
        $this->dir = $options['storageDir'] ?? $default;
        $this->fingerprint = $options['fingerprint'] ?? $this->siteFingerprint($options['siteUrl'] ?? null);
    }

    /** Site-bound fingerprint: the normalized site host and an install id (WordPress: home_url() and wp_salt()). */
    private function siteFingerprint(?string $siteUrl): array
    {
        $url = $siteUrl ?? (function_exists('home_url') ? home_url() : ($_SERVER['HTTP_HOST'] ?? gethostname()));
        $host = strtolower((string) (parse_url(str_contains((string) $url, '://') ? (string) $url : 'https://' . $url, PHP_URL_HOST) ?: $url));
        $host = preg_replace('/^www\./', '', $host);
        $installFile = $this->dir . '/install.id';
        $install = is_file($installFile) ? trim((string) file_get_contents($installFile)) : '';
        if ($install === '') {
            $install = function_exists('wp_salt') ? hash('sha256', wp_salt('auth') . $host) : bin2hex(random_bytes(16));
            @mkdir($this->dir, 0700, true);
            @file_put_contents($installFile, $install);
        }
        return [
            'machineId' => Licensing::hashComponent($this->vendor, $this->product, 'machine', $install),
            'diskId' => Licensing::UNAVAILABLE,
            'hostName' => Licensing::hashComponent($this->vendor, $this->product, 'host', $host),
            'boardId' => Licensing::UNAVAILABLE,
            'os' => 'linux',
        ];
    }

    public function license(): ?License
    {
        $p = Licensing::verifyToken($this->read('license.lic'), $this->publicKey);
        return $p === null ? null : new License($p);
    }

    public function evaluateLocal(): CheckResult
    {
        $token = $this->read('license.lic');
        if ($token === null) {
            return new CheckResult('Missing', null);
        }
        $p = Licensing::verifyToken($token, $this->publicKey);
        $last = $this->decodeHistory($this->read('license.seen'));
        $now = new \DateTimeImmutable('now', new \DateTimeZone('UTC'));
        $status = Licensing::evaluate($p, $this->product, $this->fingerprint, $now, $last);
        if (in_array($status, ['Valid', 'Expired', 'OfflineTooLong'], true) && ($last === null || $now > $last)) {
            $this->write('license.seen', $this->encodeHistory($now));
        }
        return new CheckResult($status, $p === null ? null : new License($p));
    }

    /** Call on load: evaluates offline, refreshes online when due or when only the server can clear the state. */
    public function check(): CheckResult
    {
        $r = $this->evaluateLocal();
        $due = $r->isValid() && ($this->refreshOnStartup || new \DateTimeImmutable() >= Licensing::time($r->license->payload['refreshAfter']));
        if ($due || in_array($r->status, ['Expired', 'Suspended', 'OfflineTooLong', 'ClockTampered', 'Unverified'], true)) {
            $anomalies = $r->status === 'ClockTampered' ? ['clock_rollback'] : ($r->status === 'Unverified' ? ['history_missing'] : null);
            $this->refresh($anomalies);
            $r = $this->evaluateLocal();
        }
        return $r;
    }

    public function activate(string $licenseKey, ?string $machineName = null): ActivationResult
    {
        if (trim($licenseKey) === '') {
            return new ActivationResult(false, 'Enter the license key.', 'bad_request');
        }
        $body = ['licenseKey' => trim($licenseKey), 'product' => $this->product, 'fingerprint' => $this->fingerprint,
            'machineName' => $machineName ?? (string) gethostname(), 'appVersion' => $this->appVersion];
        [$ok, $data] = $this->post('/api/client/v2/activate', $body);
        if (!$ok && ($data['code'] ?? '') === 'bad_request' && stripos($data['message'] ?? '', 'floating') !== false) {
            [$ok, $data] = $this->post('/api/client/v2/floating/checkout', $body);
        }
        if ($data === null) {
            return new ActivationResult(false, 'Could not connect to the license server.', 'network');
        }
        if (!$ok) {
            return new ActivationResult(false, $data['message'] ?? 'Server error.', $data['code'] ?? null);
        }
        if (!$this->saveIfValid($data['token'] ?? '')) {
            return new ActivationResult(false, 'The server returned an invalid license.', 'invalid_token');
        }
        $r = $this->evaluateLocal();
        return $r->isValid() ? new ActivationResult(true, 'The license has been activated.') : new ActivationResult(false, $r->status, $r->status);
    }

    public function deactivate(): ActivationResult
    {
        $token = $this->read('license.lic');
        if ($token === null) {
            return new ActivationResult(true, 'There is no license on this site.');
        }
        $floating = (Licensing::verifyToken($token, $this->publicKey)['floating'] ?? false) === true;
        [$ok, $data] = $this->post($floating ? '/api/client/v2/floating/release' : '/api/client/v2/deactivate', ['token' => $token, 'fingerprint' => $this->fingerprint]);
        if ($data === null && !$ok) {
            return new ActivationResult(false, 'Removing the license needs an internet connection.', 'network');
        }
        $code = $data['code'] ?? null;
        if (!$ok && !in_array($code, Licensing::REVOKING_CODES, true)) {
            return new ActivationResult(false, $data['message'] ?? 'Server error.', $code);
        }
        @unlink($this->dir . '/license.lic');
        return new ActivationResult(true, 'The license has been removed from this site.');
    }

    public function refresh(?array $anomalies = null): void
    {
        $token = $this->read('license.lic');
        if ($token === null) {
            return;
        }
        $floating = (Licensing::verifyToken($token, $this->publicKey)['floating'] ?? false) === true;
        [$ok, $data] = $this->post($floating ? '/api/client/v2/floating/heartbeat' : '/api/client/v2/refresh',
            ['token' => $token, 'fingerprint' => $this->fingerprint, 'appVersion' => $this->appVersion, 'anomalies' => $anomalies]);
        if ($ok) {
            $this->saveIfValid($data['token'] ?? '');
        } elseif ($data !== null && (in_array($data['code'] ?? '', Licensing::REVOKING_CODES, true) || ($data['code'] ?? '') === 'lease_expired')) {
            @unlink($this->dir . '/license.lic');
            $this->lastServerMessage = $data['message'] ?? null;
        }
    }

    /** @return array{0:bool,1:?array} [ok, decoded body] — body null when the server couldn't be reached. */
    private function post(string $path, array $body): array
    {
        $json = json_encode($body, JSON_UNESCAPED_SLASHES);
        if (function_exists('wp_remote_post')) {
            $r = wp_remote_post($this->server . $path, ['headers' => ['Content-Type' => 'application/json'], 'body' => $json, 'timeout' => $this->timeout]);
            if (is_wp_error($r)) {
                return [false, null];
            }
            $status = (int) wp_remote_retrieve_response_code($r);
            $text = (string) wp_remote_retrieve_body($r);
        } else {
            $ctx = stream_context_create(['http' => ['method' => 'POST', 'header' => "Content-Type: application/json\r\n", 'content' => $json,
                'timeout' => $this->timeout, 'ignore_errors' => true]]);
            $text = @file_get_contents($this->server . $path, false, $ctx);
            if ($text === false) {
                return [false, null];
            }
            $status = isset($http_response_header[0]) && preg_match('/\s(\d{3})\s?/', $http_response_header[0], $m) ? (int) $m[1] : 0;
        }
        $ok = $status >= 200 && $status < 300;
        $data = $text === '' ? [] : json_decode($text, true);
        if ($ok && !is_array($data)) {
            // Not our server (a captive portal, a proxy): the same as being offline.
            return [false, null];
        }
        return [$ok, is_array($data) ? $data : []];
    }

    private function saveIfValid(mixed $token): bool
    {
        $p = is_string($token) ? Licensing::verifyToken($token, $this->publicKey) : null;
        if ($p === null || strcasecmp($p['product'], $this->product) !== 0) {
            return false;
        }
        $this->write('license.lic', $token);
        $this->write('license.seen', $this->encodeHistory(new \DateTimeImmutable('now', new \DateTimeZone('UTC'))));
        return true;
    }

    private function mac(string $ms): string
    {
        $key = hash('sha256', "{$this->vendor}:run-history:{$this->product}:{$this->fingerprint['machineId']}:{$this->fingerprint['boardId']}", true);
        return strtoupper(substr(hash_hmac('sha256', $ms, $key), 0, 32));
    }

    private function encodeHistory(\DateTimeImmutable $at): string
    {
        $ms = (string) intdiv((int) $at->format('Uv'), 1);
        return $ms . '.' . $this->mac($ms);
    }

    private function decodeHistory(?string $v): ?\DateTimeImmutable
    {
        if ($v === null || !preg_match('/^(\d{1,15})\.([0-9A-F]{32})$/', trim($v), $m) || !hash_equals($this->mac($m[1]), $m[2])) {
            return null;
        }
        return (new \DateTimeImmutable('@' . intdiv((int) $m[1], 1000)))->setTimezone(new \DateTimeZone('UTC'));
    }

    private function read(string $name): ?string
    {
        $f = $this->dir . '/' . $name;
        $v = is_file($f) ? trim((string) file_get_contents($f)) : '';
        return $v === '' ? null : $v;
    }

    private function write(string $name, string $value): void
    {
        if (!is_dir($this->dir)) {
            mkdir($this->dir, 0700, true);
        }
        file_put_contents($this->dir . '/' . $name, $value);
    }
}
