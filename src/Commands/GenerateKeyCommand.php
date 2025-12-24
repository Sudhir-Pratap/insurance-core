<?php
namespace Acme\Utils\Commands;

use Acme\Utils\Manager;
use Illuminate\Console\Command;

class GenerateKeyCommand extends Command {
    protected $signature   = 'utils:generate-key {--product-id=} {--domain=*} {--ip=*} {--expiry=1 year} {--client-id=} {--hardware-fingerprint=} {--installation-id=}';
    protected $description = 'Generate a system key for the application';

    public function handle(Manager $manager) {
        $productId = $this->option('product-id');
        $domain    = $this->option('domain');
        $ip        = $this->option('ip');
        $expiry    = $this->option('expiry') ?? now()->addYear()->toDateTimeString();
        $clientId  = $this->option('client-id') ?? 'default_client';
        $hardwareFingerprint = $this->option('hardware-fingerprint');
        $installationId = $this->option('installation-id');

        if (!$hardwareFingerprint || !$installationId) {
            $this->error('You must provide both --hardware-fingerprint and --installation-id. Run php artisan utils:info to get these values.');
            return 1;
        }

        // Support multiple domains and IPs
        if (is_array($domain)) {
            $domain = implode(',', $domain);
        }
        if (is_array($ip)) {
            $ip = implode(',', $ip);
        }

        $systemKey = $manager->generateSystemKey($productId, $domain, $ip, $expiry, $clientId, $hardwareFingerprint, $installationId);

        $this->info('System Key: ' . $systemKey);
        $this->info('Store this key in your .env file as UTILS_KEY');
    }
}

