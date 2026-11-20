<?php

declare(strict_types=1);

namespace LicenseRail;

/** Offline license logic shared by every LicenseRail SDK (see the test vectors). */
final class Licensing
{
    public const UNAVAILABLE = 'none';
    public const REVOKING_CODES = ['license_not_found', 'license_suspended', 'license_expired', 'activation_revoked', 'wrong_machine', 'invalid_token', 'license_revoked'];

    private static function b64(string $text): ?string
    {
        if (!preg_match('/^[A-Za-z0-9_-]*$/', $text) || strlen($text) % 4 === 1) {
            return null;
        }
        $decoded = base64_decode(strtr($text, '-_', '+/') . str_repeat('=', (4 - strlen($text) % 4) % 4), true);
        return $decoded === false ? null : $decoded;
    }

    /** IEEE P1363 r||s (64 bytes) → DER, which openssl_verify expects. */
    private static function p1363ToDer(string $sig): string
    {
        $int = static function (string $x): string {
            $x = ltrim($x, "\x00");
            if ($x === '' || (ord($x[0]) & 0x80)) {
                $x = "\x00" . $x;
            }
            return "\x02" . chr(strlen($x)) . $x;
        };
        $seq = $int(substr($sig, 0, 32)) . $int(substr($sig, 32, 32));
        return "\x30" . chr(strlen($seq)) . $seq;
    }

    /** Verifies ECDSA P-256 / SHA-256 over the ASCII encoded body; returns the payload array or null. */
    public static function verifyToken(?string $token, string $publicKeyPem): ?array
    {
        if ($token === null) {
            return null;
        }
        $parts = explode('.', trim($token));
        if (count($parts) !== 2) {
            return null;
        }
        $sig = self::b64($parts[1]);
        $body = self::b64($parts[0]);
        if ($sig === null || $body === null || strlen($sig) !== 64) {
            return null;
        }
        $key = openssl_pkey_get_public($publicKeyPem);
        if ($key === false || openssl_verify($parts[0], self::p1363ToDer($sig), $key, OPENSSL_ALGO_SHA256) !== 1) {
            return null;
        }
        $payload = json_decode($body, true);
        return is_array($payload) && isset($payload['fingerprint']) ? $payload : null;
    }

    /** hex(SHA256(vendor . ':' . product . ':' . part . ':' . upper(trim(raw)))); \$vendor is the organization's slug (fixed for life). */
    public static function hashComponent(string $vendor, string $product, string $part, ?string $raw): string
    {
        if ($raw === null || trim($raw) === '') {
            return self::UNAVAILABLE;
        }
        return hash('sha256', "{$vendor}:{$product}:{$part}:" . mb_strtoupper(trim($raw), 'UTF-8'));
    }

    private static function available(?string $v): bool
    {
        return $v !== null && $v !== '' && $v !== self::UNAVAILABLE;
    }

    private static function same(?string $a, ?string $b): bool
    {
        return self::available($a) && $a === $b;
    }

    public static function matches(array $registered, array $presented): bool
    {
        $ro = $registered['os'] ?? null;
        $po = $presented['os'] ?? null;
        if ($ro && $po && strcasecmp($ro, $po) !== 0) {
            return false;
        }
        $n = 0;
        foreach (['machineId', 'diskId', 'hostName'] as $k) {
            if (self::same($registered[$k] ?? null, $presented[$k] ?? null)) {
                $n++;
            }
        }
        return self::available($registered['boardId'] ?? null)
            ? self::same($registered['boardId'], $presented['boardId'] ?? null) && $n >= 1
            : $n >= 2;
    }

    public static function time(?string $iso): ?\DateTimeImmutable
    {
        // .NET writes up to 7 fractional digits; keep PHP's 6.
        return $iso === null ? null : new \DateTimeImmutable(preg_replace('/(\.\d{6})\d+/', '$1', $iso));
    }

    public static function evaluate(?array $payload, string $product, array $machine, \DateTimeImmutable $now, ?\DateTimeImmutable $lastSeen): string
    {
        if ($payload === null) return 'InvalidSignature';
        if (strcasecmp((string) ($payload['product'] ?? ''), $product) !== 0) return 'WrongProduct';
        if (!self::matches($payload['fingerprint'], $machine)) return 'WrongMachine';
        if (!empty($payload['suspended'])) return 'Suspended';
        if ($lastSeen === null) return 'Unverified';
        if ($now->modify('+1 day') < self::time($payload['issuedAt']) || $now->modify('+10 minutes') < $lastSeen) return 'ClockTampered';
        $expires = self::time($payload['expiresAt'] ?? null);
        if ($expires !== null && $now >= $expires) return 'Expired';
        if ($now >= self::time($payload['offlineUntil'])) return 'OfflineTooLong';
        return 'Valid';
    }
}
