<?php

namespace InsuranceCore\Utils\Commands;

use InsuranceCore\Utils\Manager;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Cache;

class DeploymentCommand extends Command
{
    protected $signature = 'utils:deployment
                           {--check : Check current deployment status}
                           {--fix : Attempt to fix deployment issues}
                           {--regenerate : Force regenerate hardware fingerprint}
                           {--test : Test system after fixes}';
    
    protected $description = 'Help troubleshoot and fix system issues during deployment';

    public function handle(Manager $manager)
    {
        if ($this->option('check')) {
            $this->checkDeploymentStatus($manager);
        }
        
        if ($this->option('fix')) {
            $this->attemptFixDeploymentIssues($manager);
        }
        
        if ($this->option('regenerate')) {
            $this->regenerateHardwareFingerprint($manager);
        }
        
        if ($this->option('test')) {
            $this->testSystemValidation($manager);
        }
        
        if (!$this->option('check') && !$this->option('fix') && !$this->option('regenerate') && !$this->option('test')) {
            $this->info('System Deployment Tool');
            $this->line('');
            $this->info('Available options:');
            $this->line('--check     : Check current deployment status');
            $this->line('--fix       : Attempt to fix deployment issues');
            $this->line('--regenerate: Force regenerate hardware fingerprint');
            $this->line('--test      : Test system validation');
            $this->line('');
            $this->info('Example: php artisan utils:deployment --check --fix');
        }
    }

    public function checkDeploymentStatus(Manager $manager)
    {
        $this->info('=== System Deployment Status ===');
        
        // Check configuration
        $this->line('');
        $this->info('Configuration:');
        $this->line('System Key: ' . (config('utils.system_key') ? '✓ Set' : '✗ Missing'));
        $this->line('Product ID: ' . (config('utils.product_id') ?: 'Missing'));
        $this->line('Client ID: ' . (config('utils.client_id') ?: 'Missing'));
        $this->line('System Server: ' . config('utils.validation_server'));
        
        // Check hardware fingerprint
        $fingerprint = $manager->generateHardwareFingerprint();
        $this->line('');
        $this->info('Hardware Information:');
        $this->line('Fingerprint: ' . substr($fingerprint, 0, 32) . '...');
        $this->line('Installation ID: ' . $manager->getOrCreateInstallationId());
        
        // Check environment
        $this->line('');
        $this->info('Environment:');
        $this->line('App Environment: ' . config('app.env'));
        $this->line('App Key: ' . (config('app.key') ? '✓ Set' : '✗ Missing'));
        $this->line('DB Connection: ' . ($this->testDatabaseConnection() ? '✓ Connected' : '✗ Failed'));
        
        // Check installation details
        $details = $manager->getInstallationDetails();
        $this->line('');
        $this->info('Current Installation:');
        $this->line('Domain: ' . ($details['server_info']['domain'] ?? 'Unknown'));
        $this->line('IP: ' . ($details['server_info']['ip'] ?? 'Unknown'));
    }

    public function attemptFixDeploymentIssues(Manager $manager)
    {
        // Clear system cache
        Cache::flush();
        $this->info('✓ Cleared system validation cache');
        
        // Reset installation tracking
        try {
            $manager->getOrCreateInstallationId();
            $this->info('✓ Reset installation tracking');
        } catch (\Exception $e) {
            $this->error('✗ Failed to reset installation tracking: ' . $e->getMessage());
        }
        
        $this->line('');
        $this->info('✓ Deployment fixes applied');
         $this->info('You should now regenerate your system key with new hardware fingerprint');
     }

    public function regenerateHardwareFingerprint(Manager $manager)
    {
        // Set environment variable to force regeneration
        putenv('SYSTEM_FORCE_REGENERATE_FINGERPRINT=true');
         
         $oldFingerprint = config('utils.deployment.hardware_fingerprint') ?: 'Previous not stored';
         $newFingerprint = $manager->generateHardwareFingerprint();
         
         $this->info('Hardware Fingerprint Regenerated');
        $this->line('Old: ' . substr($oldFingerprint, 0, 32) . '...');
        $this->line('New: ' . substr($newFingerprint, 0, 32) . '...');
         $this->line('');
         $this->info('⚠️  You must regenerate your system key with the new fingerprint');
         $this->info('Run: php artisan utils:info');
     }

     public function testSystemValidation(Manager $manager)
     {
         $this->info('Testing System Validation...');
         
         $systemKey = config('utils.system_key');
         $productId = config('utils.product_id');
         $clientId = config('utils.client_id');
         
         if (!$systemKey || !$productId || !$clientId) {
             $this->error('Missing required system configuration');
             return;
         }
         
         try {
             $isValid = $manager->validateSystem(
                 $systemKey,
                 $productId,
                 request()->getHost() ?: 'localhost',
                 request()->ip() ?: '127.0.0.1',
                 $clientId
             );
             
             if ($isValid) {
                 $this->info('✅ System validation successful');
             } else {
                 $this->error('❌ System validation failed');
                 $this->line('');
                 $this->info('Common fixes:');
                 $this->line('1. Check if system server is accessible');
                 $this->line('2. Verify API token is correct');
                 $this->line('3. Ensure hardware fingerprint matches');
                 $this->line('4. Run: php artisan utils:deployment --fix');
             }
         } catch (\Exception $e) {
             $this->error('System validation error: ' . $e->getMessage());
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

