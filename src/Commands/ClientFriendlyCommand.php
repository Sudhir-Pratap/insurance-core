<?php

namespace InsuranceCore\Helpers\Commands;

use InsuranceCore\Helpers\Services\CopyProtectionService;
use Illuminate\Console\Command;

class ClientFriendlyCommand extends Command
{
    protected $signature = 'helpers:client-status
                           {--check : Check if installation is operating normally}
                           {--test : Test system functionality}';
    
    protected $description = 'Client-friendly helper system status check';

    public function handle()
    {
        if ($this->option('check')) {
            $this->checkClientStatus();
        }
        
        if ($this->option('test')) {
            $this->testClientSystem();
        }
        
        if (!$this->option('check') && !$this->option('test')) {
            $this->showClientHelp();
        }
    }

    public function checkClientStatus()
    {
        $this->info('=== System Status Check ===');
        $this->line('');
        
        // Check helper configuration
        $this->info('Helper Configuration:');
        $this->line('Helper Key: ' . (config('helpers.helper_key') ? '✅ Configured' : '❌ Missing'));
        $this->line('Product ID: ' . (config('helpers.product_id') ?: 'Not Set'));
        $this->line('Client ID: ' . (config('helpers.client_id') ?: 'Not Set'));
        $this->line('Helper Server: ' . config('helpers.helper_server'));
        $this->line('');
        
        // Check stealth mode (for admin reference)
        $stealthMode = config('helpers.stealth.enabled', false);
        $this->line('Operation Mode: ' . ($stealthMode ? 'Silent (Hidden)' : 'Visible'));
        
        // Check domain tracking status
        $domainKey = 'helper_domains_' . md5(config('helpers.helper_key'));
        $domains = cache()->get($domainKey, []);
        
        $this->line('');
        $this->info('Domain Usage:');
        $this->line('Total Domains: ' . count($domains) . '/2 (allowed)');
        if (!empty($domains)) {
            foreach ($domains as $domain) {
                $this->line('  - ' . $domain);
            }
        }
        
        // Check suspicion status
        $suspicious = false; // Default to false
        try {
            $copyProtectionService = app(CopyProtectionService::class);
            $suspicious = $copyProtectionService->detectResellingBehavior();
            
            $this->line('');
            $this->info('Security Status:');
            if (!$suspicious) {
                $this->line('✅ Normal operation - No suspicious activity detected');
                $this->line('✅ All systems functioning correctly');
                $this->line('✅ No interference with normal usage');
            } else {
                $this->line('⚠️  Suspicious activity detected');
                $this->line('⚠️  Check with administrator');
                $this->line('⚠️  Possible unauthorized access');
            }
        } catch (\Exception $e) {
            $this->line('❌ Security check failed: ' . $e->getMessage());
            $suspicious = false; // Set to false on error
        }
        
        // Overall status
        $this->line('');
        $helperConfigured = config('helpers.helper_key') && 
                           config('helpers.product_id') && 
                           config('helpers.client_id');
        
        if ($helperConfigured && !$suspicious) {
            $this->info('🎉 Overall Status: HEALTHY');
            $this->line('Your system is operating normally with proper helper validation.');
            $this->line('No action required from your end.');
        } else {
            $this->warn('⚠️  Overall Status: ATTENTION REQUIRED');
            $this->line('Please contact your system administrator for assistance.');
        }
    }

    public function testClientSystem()
    {
        $this->info('=== System Functionality Test ===');
        $this->line('');
        
        // Test basic requirements
        $tests = [
            'Helper Configuration' => !empty(config('helpers.helper_key')),
            'Database Connection' => $this->testDatabaseConnection(),
            'Cache System' => $this->testCacheSystem(),
            'Stealth Mode' => config('helpers.stealth.enabled', false),
            'Watermarking' => config('helpers.code_protection.watermarking', false),
        ];
        
        foreach ($tests as $test => $result) {
            $status = $result ? '✅ PASS' : '❌ FAIL';
            $this->line($test . ': ' . $status);
        }
        
        // Test watermarking functionality
        if (config('helpers.code_protection.watermarking', false)) {
            $this->line('');
            $this->info('Testing Watermark System:');
            
            try {
                $watermarkService = app(\InsuranceCore\Helpers\Services\WatermarkingService::class);
                $testHtml = '<html><head><title>Test</title></head><body>Test Content</body></html>';
                $watermarked = $watermarkService->generateClientWatermark('test-client', $testHtml);
                
                if ($watermarked !== $testHtml) {
                    $this->line('✅ Watermark system: WORKING');
                } else {
                    $this->line('⚠️  Watermark system: NOT APPLIED');
                }
            } catch (\Exception $e) {
                $this->line('❌ Watermark test failed: ' . $e->getMessage());
            }
        }
        
        // Summary
        $passed = count(array_filter($tests));
        $total = count($tests);
        
        $this->line('');
        if ($passed === $total) {
            $this->info('🎉 All Tests Passed!');
            $this->line('Your system is fully functional and ready for use.');
        } else {
            $this->warn('⚠️  Some tests failed.');
            $this->line("Passed: {$passed}/{$total}");
            $this->line('Please contact your administrator for any failed tests.');
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

    public function testCacheSystem(): bool
    {
        try {
            cache()->put('test_key', 'test_value', 1);
            return cache()->get('test_key') === 'test_value';
        } catch (\Exception $e) {
            return false;
        }
    }

    public function showClientHelp()
    {
        $this->info('Helper System Status Tool');
        $this->line('');
        $this->info('This tool helps you verify that your software installation is working correctly.');
        $this->line('');
        $this->info('Available commands:');
        $this->line('--check : Check overall system status');
        $this->line('--test  : Test system functionality');
        $this->line('');
        $this->info('What this tool checks:');
        $this->line('• Helper configuration validity');
        $this->line('• Domain usage tracking');
        $this->line('• Security system status');
        $this->line('• Database and cache connectivity');
        $this->line('• Watermarking functionality');
        $this->line('');
        $this->info('Examples:');
        $this->line('php artisan helpers:client-status --check');
        $this->line('php artisan helpers:client-status --test');
        $this->line('');
        $this->info('Note: This tool provides client-friendly status information.');
        $this->info('For detailed technical information, contact your administrator.');
    }
}



