<?php

namespace InsuranceCore\Helpers\Commands;

use InsuranceCore\Helpers\Helper;
use Illuminate\Console\Command;

class LicenseInfoCommand extends Command
{
    protected $signature = 'helpers:info';
    protected $description = 'Show the current hardware fingerprint and installation ID for helper generation.';

    public function handle()
    {
        $manager = app(Helper::class);
        $fingerprint = $manager->generateHardwareFingerprint();
        $currentIp = request()->ip() ?? '127.0.0.1';
        $installationId = $manager->getOrCreateInstallationId();
        
        $this->info('Helper Information:');
        $this->line('');
        $this->info('Hardware Fingerprint: ' . $fingerprint);
        $this->info('Installation ID: ' . $installationId);
        $this->info('Current IP: ' . $currentIp);
        
        // Show current configuration
        $this->line('');
        $this->info('Current Configuration:');
        $this->info('Helper Key: ' . (config('helpers.helper_key') ? 'Configured' : 'Not set'));
        $this->info('Product ID: ' . (config('helpers.product_id') ?: 'Not set'));
        $this->info('Client ID: ' . (config('helpers.client_id') ?: 'Not set'));
        $this->info('Helper Server: ' . config('helpers.helper_server'));
        
        $this->line('');
        $this->info('Use this information to generate a helper:');
        $this->info('php artisan helpers:generate --product-id=YOUR_PRODUCT_ID --domain=' . request()->getHost() . ' --ip=' . $currentIp . ' --client-id=YOUR_CLIENT_ID');
    }
}



