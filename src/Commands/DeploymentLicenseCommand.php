<?php

namespace InsuranceCore\Helpers\Commands;

use InsuranceCore\Helpers\Helper;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Cache;

class DeploymentLicenseCommand extends Command
{
    protected $signature = 'helpers:deployment
                           {--check : Check current deployment status}
                           {--fix : Attempt to fix deployment issues}
                           {--regenerate : Force regenerate hardware fingerprint}
                           {--test : Test license after fixes}';
    
    protected $description = 'Help troubleshoot and fix license issues during deployment';

    public function handle(Helper $helper)
    {
        if ($this->option('check')) {
            $this->checkDeploymentStatus($helper);
        }
        
        if ($this->option('fix')) {
            $this->attemptFixDeploymentIssues($helper);
        }
        
        if ($this->option('regenerate')) {
            $this->regenerateHardwareFingerprint($helper);
        }
        
        if ($this->option('test')) {
            $this->testHelperValidation($helper);
        }
        
        if (!$this->option('check') && !$this->option('fix') && !$this->option('regenerate') && !$this->option('test')) {
            $this->info('License Deployment Helper');
            $this->line('');
            $this->info('Available options:');
            $this->line('--check     : Check current deployment status');
            $this->line('--fix       : Attempt to fix deployment issues');
            $this->line('--regenerate: Force regenerate hardware fingerprint');
            $this->line('--test      : Test helper validation');
            $this->line('');
            $this->info('Example: php artisan helpers:deployment --check --fix');
        }
    }

    public function checkDeploymentStatus(Helper $helper)
    {
        $this->info('=== License Deployment Status ===');
        
        // Check configuration
        $this->line('');
        $this->info('Configuration:');
        $this->line('Helper Key: ' . (config('helpers.helper_key') ? '✓ Set' : '✗ Missing'));
        $this->line('Product ID: ' . (config('helpers.product_id') ?: 'Missing'));
        $this->line('Client ID: ' . (config('helpers.client_id') ?: 'Missing'));
        $this->line('Helper Server: ' . config('helpers.helper_server'));
        
        // Check hardware fingerprint
        $fingerprint = $helper->generateHardwareFingerprint();
        $this->line('');
        $this->info('Hardware Information:');
        $this->line('Fingerprint: ' . substr($fingerprint, 0, 32) . '...');
        $this->line('Installation ID: ' . $helper->getOrCreateInstallationId());
        
        // Check environment
        $this->line('');
        $this->info('Environment:');
        $this->line('App Environment: ' . config('app.env'));
        $this->line('App Key: ' . (config('app.key') ? '✓ Set' : '✗ Missing'));
        $this->line('DB Connection: ' . ($this->testDatabaseConnection() ? '✓ Connected' : '✗ Failed'));
        
        // Check installation details
        $details = $helper->getInstallationDetails();
        $this->line('');
        $this->info('Current Installation:');
        $this->line('Domain: ' . ($details['server_info']['domain'] ?? 'Unknown'));
        $this->line('IP: ' . ($details['server_info']['ip'] ?? 'Unknown'));
    }

    public function attemptFixDeploymentIssues(Helper $helper)
    {
        // Clear license cache
        Cache::flush();
        $this->info('✓ Cleared helper validation cache');
        
        // Reset installation tracking
        try {
            $helper->getOrCreateInstallationId();
            $this->info('✓ Reset installation tracking');
        } catch (\Exception $e) {
            $this->error('✗ Failed to reset installation tracking: ' . $e->getMessage());
        }
        
        $this->line('');
        $this->info('✓ Deployment fixes applied');
         $this->info('You should now regenerate your license with new hardware fingerprint');
     }

    public function regenerateHardwareFingerprint(Helper $helper)
    {
        // Set environment variable to force regeneration
        putenv('LICENSE_FORCE_REGENERATE_FINGERPRINT=true');
         
         $oldFingerprint = config('helpers.hardware_fingerprint') ?: 'Previous not stored';
         $newFingerprint = $helper->generateHardwareFingerprint();
         
         $this->info('Hardware Fingerprint Regenerated');
        $this->line('Old: ' . substr($oldFingerprint, 0, 32) . '...');
        $this->line('New: ' . substr($newFingerprint, 0, 32) . '...');
         $this->line('');
         $this->info('⚠️  You must regenerate your license with the new fingerprint');
         $this->info('Run: php artisan helpers:info');
     }

     public function testHelperValidation(Helper $helper)
     {
         $this->info('Testing Helper Validation...');
         
         $helperKey = config('helpers.helper_key');
         $productId = config('helpers.product_id');
         $clientId = config('helpers.client_id');
         
         if (!$helperKey || !$productId || !$clientId) {
             $this->error('Missing required helper configuration');
             return;
         }
         
         try {
             $isValid = $helper->validateHelper(
                 $helperKey,
                 $productId,
                 request()->getHost() ?: 'localhost',
                 request()->ip() ?: '127.0.0.1',
                 $clientId
             );
             
             if ($isValid) {
                 $this->info('✅ Helper validation successful');
             } else {
                 $this->error('❌ Helper validation failed');
                 $this->line('');
                 $this->info('Common fixes:');
                 $this->line('1. Check if helper server is accessible');
                 $this->line('2. Verify API token is correct');
                 $this->line('3. Ensure hardware fingerprint matches');
                 $this->line('4. Run: php artisan helpers:deployment --fix');
             }
         } catch (\Exception $e) {
             $this->error('Helper validation error: ' . $e->getMessage());
         }
     }

    public function testDatabaseConnection(): bool
    {
        try {
            \DB::connection()->getPdo();
            return true;
        } catch (\Exception $e) {
            return false;
        }
    }
}



