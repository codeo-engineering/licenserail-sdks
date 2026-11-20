<?php

declare(strict_types=1);

require __DIR__ . '/../src/Licensing.php';

use LicenseRail\Licensing;

$dir = __DIR__ . '/../../test-vectors/';
$load = static fn(string $n): array => json_decode(file_get_contents($dir . $n), true);
$fail = 0;
$check = static function (bool $ok, string $what) use (&$fail): void {
    if (!$ok) {
        $fail++;
        echo "FAIL: $what\n";
    }
};

$t = $load('tokens.json');
foreach ($t['cases'] as $c) {
    $p = Licensing::verifyToken($c['token'], $t['publicKeyPem']);
    $check(($p !== null) === $c['expect']['signatureValid'], 'token ' . $c['name']);
    foreach ($c['expect']['payload'] ?? [] as $k => $v) {
        $check(json_encode($p[$k] ?? null) === json_encode($v), "token {$c['name']} $k");
    }
}
foreach ($load('fingerprint.json')['cases'] as $c) {
    $check(Licensing::hashComponent($c['vendor'], $c['product'], $c['part'], $c['raw']) === $c['hash'], 'hash ' . json_encode($c['raw']));
}
foreach ($load('match.json')['cases'] as $c) {
    $check(Licensing::matches($c['registered'], $c['presented']) === $c['matches'], 'match ' . $c['name']);
}
$e = $load('evaluate.json');
foreach ($e['cases'] as $c) {
    $s = Licensing::evaluate(Licensing::verifyToken($c['token'], $e['publicKeyPem']), $c['product'], $c['machine'],
        new DateTimeImmutable($c['now']), $c['lastSeen'] === null ? null : new DateTimeImmutable($c['lastSeen']));
    $check($s === $c['status'], "evaluate {$c['name']} got $s");
}
echo $fail === 0 ? "All vectors passed.\n" : "$fail vector(s) failed.\n";
exit($fail === 0 ? 0 : 1);
