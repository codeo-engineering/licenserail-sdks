<?php

declare(strict_types=1);

require __DIR__ . '/vendor/autoload.php';

use LicenseRail\ActivationResult;
use LicenseRail\LicenseClient;

// Warnings and notices of the SDK fail the test.
set_error_handler(function (int $level, string $message, string $file, int $line): bool {
    if ((error_reporting() & $level) !== 0) {
        throw new ErrorException($message, 0, $level, $file, $line);
    }
    return false;
});

$options = [
    'serverUrl' => getenv('LR_URL'), 'vendor' => getenv('LR_VENDOR'), 'product' => getenv('LR_PRODUCT'),
    'publicKeyPem' => file_get_contents(getenv('LR_PUBLIC_KEY_FILE')), 'storageDir' => getenv('LR_STORAGE'),
    'appVersion' => '1.2.3', 'timeout' => (int) getenv('LR_TIMEOUT'), 'siteUrl' => 'https://www.shop.example',
];
$d = explode(',', (string) getenv('LR_DEVICE'));
if (count($d) === 4) {
    $options['fingerprint'] = ['machineId' => $d[0], 'diskId' => $d[1], 'hostName' => $d[2], 'boardId' => $d[3], 'os' => 'linux'];
}
$client = new LicenseClient($options);
$put = fn (ActivationResult $r): array => ['success' => $r->success, 'errorCode' => $r->errorCode, 'message' => $r->message];

switch ($argv[1]) {
    case 'activate':
        $out = $put($client->activate($argv[2]));
        break;
    case 'deactivate':
        $out = $put($client->deactivate());
        break;
    case 'refresh':
        $client->refresh();
        $out = ['success' => true];
        break;
    default:
        $r = $client->check();
        $out = ['status' => $r->status, 'features' => $r->license?->features() ?? [], 'test' => $r->license?->isTest() ?? false];
}
echo json_encode($out, JSON_UNESCAPED_SLASHES), "\n";
