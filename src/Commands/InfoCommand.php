<?php

namespace Acme\Utils\Commands;

use Acme\Utils\Manager;
use Illuminate\Console\Command;

class InfoCommand extends Command
{
    protected $signature = 'utils:info';
    protected $description = 'Show system information for key generation.';

    public function handle()
    {
        $manager = app(Manager::class);
        $fingerprint = $manager->generateHardwareFingerprint();
        $currentIp = request()->ip() ?? '127.0.0.1';
        $installationId = $manager->getOrCreateInstallationId();
        
        $this->info('System Information:');
        $this->line('');
        $this->info('Hardware Fingerprint: ' . $fingerprint);
        $this->info('Installation ID: ' . $installationId);
        $this->info('Current IP: ' . $currentIp);
        
        // Show current configuration
        $this->line('');
        $this->info('Current Configuration:');
        $this->info('System Key: ' . (config('utils.system_key') ? 'Configured' : 'Not set'));
        $this->info('Product ID: ' . (config('utils.product_id') ?: 'Not set'));
        $this->info('Client ID: ' . (config('utils.client_id') ?: 'Not set'));
        $this->info('System Server: ' . config('utils.validation_server'));
        
        $this->line('');
        $this->info('Use this information to generate a system key:');
        $this->info('php artisan utils:generate-key --product-id=YOUR_PRODUCT_ID --domain=' . request()->getHost() . ' --ip=' . $currentIp . ' --client-id=YOUR_CLIENT_ID');
    }
}

