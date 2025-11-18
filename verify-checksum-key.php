<?php
/**
 * Quick script to verify HELPER_SECRET (formerly LICENSE_SECRET) is set correctly
 * Run this from your application root (e.g., agent-panel)
 * 
 * Note: This script checks for HELPER_SECRET. For backward compatibility,
 * LICENSE_SECRET is also supported but deprecated.
 */

// Adjust this path if needed
$autoloadPath = __DIR__ . '/../../Askpolicy/agent-panel/vendor/autoload.php';

if (!file_exists($autoloadPath)) {
    echo "Error: autoload.php not found. Adjust the path in this script.\n";
    exit(1);
}

require $autoloadPath;

$app = require_once dirname($autoloadPath) . '/bootstrap/app.php';
$app->make(\Illuminate\Contracts\Console\Kernel::class)->bootstrap();

// Check for HELPER_SECRET first (preferred), fallback to LICENSE_SECRET (deprecated), then APP_KEY
$helperSecret = env('HELPER_SECRET');
$licenseSecret = env('LICENSE_SECRET'); // Legacy/deprecated
$appKey = env('APP_KEY');
$cryptoKey = $helperSecret ?: $licenseSecret ?: $appKey;
$keyType = $helperSecret ? 'HELPER_SECRET' : ($licenseSecret ? 'LICENSE_SECRET (deprecated)' : 'APP_KEY');

echo "=== Client (agent-panel) Crypto Key Check ===\n\n";
echo "HELPER_SECRET: " . ($helperSecret ? "SET (" . substr($helperSecret, 0, 15) . "...)" : "NOT SET") . "\n";
if ($licenseSecret) {
    echo "LICENSE_SECRET (deprecated): SET (" . substr($licenseSecret, 0, 15) . "...)\n";
    echo "⚠ WARNING: LICENSE_SECRET is deprecated. Please migrate to HELPER_SECRET.\n";
}
echo "APP_KEY: " . ($appKey ? "SET (" . substr($appKey, 0, 15) . "...)" : "NOT SET") . "\n";
echo "Crypto Key Used: " . $keyType . "\n";
echo "Key Preview: " . substr($cryptoKey, 0, 20) . "...\n\n";

echo "=== For checksum validation ===\n";
echo "Both license-server and agent-panel MUST use the SAME crypto key.\n";
echo "Set HELPER_SECRET on both .env files with the SAME value.\n";
if ($licenseSecret && !$helperSecret) {
    echo "⚠ MIGRATION: Update your .env file to use HELPER_SECRET instead of LICENSE_SECRET.\n";
}

