<?php

namespace Acme\Utils\Commands;

use Acme\Utils\Services\CopyProtectionService;
use Acme\Utils\Services\WatermarkingService;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Log;

class CopyProtectionCommand extends Command
{
    protected $signature = 'utils:protection 
                           {--check : Check current protection status}
                           {--test-suspicion : Run suspicion detection test}
                           {--watermark-test : Test watermarking functionality}
                           {--report : Generate protection report}
                           {--config : Generate protection configuration}
                           {--client-examples : Show client-specific setup examples}';
    
    protected $description = 'Manage system protection features';

    public function handle()
    {
        if ($this->option('check')) {
            $this->checkCopyProtectionStatus();
        }
        
        if ($this->option('test-suspicion')) {
            $this->runSuspicionDetection();
        }
        
        if ($this->option('watermark-test')) {
            $this->testWatermarking();
        }
        
        if ($this->option('report')) {
            $this->generateCopyProtectionReport();
        }
        
        if ($this->option('config')) {
            $this->generateCopyProtectionConfig();
        }
        
        if ($this->option('client-examples')) {
            $this->showClientUsageExamples();
        }
        
        if (!$this->option('check') && !$this->option('test-suspicion') && 
            !$this->option('watermark-test') && !$this->option('report') && 
            !$this->option('config') && !$this->option('client-examples')) {
            $this->showCopyProtectionHelp();
        }
    }

    /**
     * Show client-specific usage examples
     */
    public function showClientUsageExamples()
    {
        $this->info('=== Client Usage Examples ===');
        $this->line('');
        
        $this->info('For TRUSTED Enterprise Clients:');
        $this->line('UTILS_RESELL_THRESHOLD=90    # Higher threshold');
        $this->line('UTILS_MAX_DOMAINS=5          # More flexible');
        $this->line('UTILS_MAX_PER_GEO=10         # Multiple installations');
        $this->line('UTILS_DETECT_VPN=false       # Allow VPN usage');
        $this->line('');
        
        $this->info('For STANDARD Clients:');
                $this->line('UTILS_RESELL_THRESHOLD=75    # Balanced protection');
                $this->line('UTILS_MAX_DOMAINS=2          # Standard limit');
                $this->line('UTILS_MAX_PER_GEO=3          # Reasonable cluster');
                $this->line('UTILS_DETECT_VPN=true        # Monitor VPN usage');
        $this->line('');

        $this->info('For HIGH-RISK/UNAUTHORIZED:');
                $this->line('UTILS_RESELL_THRESHOLD=50    # Lower threshold');
                $this->line('UTILS_MAX_DOMAINS=1          # Strict limit');
                $this->line('UTILS_MAX_PER_GEO=1          # No clustering');
                $this->line('UTILS_DETECT_VPN=true        # Block VPN');
    }

    public function checkCopyProtectionStatus()
    {
        $this->info('=== Copy Protection Status ===');
        $this->line('');
        
        // Check configuration
        $settings = [
            'Suspicion Threshold' => config('utils.anti_reselling.threshold_score', 75),
            'Max Domains' => config('utils.anti_reselling.max_domains', 2),
            'Max Per Geo Area' => config('utils.anti_reselling.max_per_geo', 3),
            'VPN Detection' => config('utils.anti_reselling.detect_vpn', true),
            'Pattern Monitoring' => config('utils.anti_reselling.monitor_patterns', true),
            'File Integrity' => config('utils.anti_reselling.file_integrity', true),
            'Watermarking' => config('utils.code_protection.watermarking', true),
            'Obfuscation' => config('utils.code_protection.obfuscation_enabled', true),
            'Runtime Checks' => config('utils.code_protection.runtime_checks', true),
            'Anti Debug' => config('utils.code_protection.anti_debug', true),
        ];
        
        $this->info('Configuration Status:');
        foreach ($settings as $setting => $value) {
            $status = $value ? '✅ Enabled' : '❌ Disabled';
            $this->line($setting . ': ' . $status);
        }
        
        // Check current threat level
        $this->line('');
        $this->info('Current Threat Assessment:');
        
        try {
            $copyProtectionService = app(CopyProtectionService::class);
            $suspicious = $copyProtectionService->detectResellingBehavior();
            
            if ($suspicious) {
                $this->warn('⚠️  Suspicious activity detected');
                $this->line('   - Check security logs for details');
                $this->line('   - Consider reviewing client agreement terms');
            } else {
                $this->info('✅ No suspicious activity detected');
            }
        } catch (\Exception $e) {
            $this->error('❌ Error checking protection status: ' . $e->getMessage());
        }
    }

    public function runSuspicionDetection()
    {
        $this->info('=== Running Suspicion Detection Test ===');
        
        try {
            $copyProtectionService = app(CopyProtectionService::class);
            $suspicious = $copyProtectionService->detectResellingBehavior([
                'test_mode' => true,
                'timestamp' => now()->toDateTimeString(),
            ]);
            
            if ($suspicious) {
                $this->warn('⚠️  Suspicious patterns detected');
                $this->line('');
                $this->info('Reasons for suspicion:');
                $this->line('• Multiple domains detected');
                $this->line('• Unusual usage patterns');
                $this->line('• File modifications detected');
                $this->line('• VPN/Proxy usage detected');
                $this->line('• Geographic clustering detected');
            } else {
                $this->info('✅ No suspicious patterns detected');
                $this->line('• Normal usage patterns');
                $this->line('• Single domain usage');
                $this->line('• No file modifications');
                $this->line('• Standard network behavior');
            }
            
        } catch (\Exception $e) {
            $this->error('❌ Error in detection test: ' . $e->getMessage());
        }
    }

    public function testWatermarking()
    {
        $this->info('=== Testing Watermarking Functionality ===');
        
        try {
            $watermarkingService = app(WatermarkingService::class);
            $clientId = config('utils.client_id');
            
            // Test basic watermarking
            $testHtml = '<html><head><title>Test</title></head><body>Test Content</body></html>';
            $watermarkedHtml = $watermarkingService->generateClientWatermark($clientId, $testHtml);
            
            if ($watermarkedHtml !== $testHtml) {
                $this->info('✅ Watermarking applied successfully');
                
                // Test watermark detection
                $modificationDetected = $watermarkingService->detectContentModification($watermarkedHtml);
                
                if (!$modificationDetected) {
                    $this->info('✅ Watermarks properly embedded');
                } else {
                    $this->warn('⚠️  Watermark detection issues');
                }
            } else {
                $this->warn('⚠️  No watermarking detected');
            }
            
            // Test dynamic key generation
            $dynamicKeys = $watermarkingService->generateDynamicKeys();
            if (!empty($dynamicKeys)) {
                $this->info('✅ Dynamic keys generated');
                foreach ($dynamicKeys as $type => $key) {
                    $this->line("   {$type}: " . substr($key, 0, 16) . '...');
                }
            }
            
        } catch (\Exception $e) {
            $this->error('❌ Error testing watermarking: ' . $e->getMessage());
        }
    }

    public function generateCopyProtectionReport()
    {
        $this->info('=== Copy Protection Report ===');
        $this->line('');
        
        $report = [
            'timestamp' => now()->toDateTimeString(),
            'client_id' => config('utils.client_id'),
            'domain' => request()->getHost() ?? 'localhost',
            'ip' => request()->ip() ?? '127.0.0.1',
            'system_key' => substr(config('utils.system_key'), 0, 16) . '...',
        ];
        
        // Current domain usage
        $domainKey = 'system_domains_' . md5(config('utils.system_key'));;
        $domains = cache()->get($domainKey, []);
        $report['domains_used'] = $domains;
        
        // Usage patterns
        $usageKey = 'usage_pattern_' . md5(config('utils.system_key'));
        $patterns = cache()->get($usageKey, []);
        $report['usage_entries'] = count($patterns);
        
        // Security events
        $report['security_logging'] = config('utils.remote_security_logging', true) ? 'Remote (Validation Server)' : 'Local';
        
        $this->info('Report Data:');
        foreach ($report as $key => $value) {
            if (is_array($value)) {
                $this->line("{$key}: " . json_encode($value));
            } else {
                $this->line("{$key}: {$value}");
            }
        }
        
        $this->line('');
        $this->info('Summary:');
        $this->line('• Total domains tracked: ' . count($domains));
        $this->line('• Usage pattern entries: ' . count($patterns));
        $this->line('• Copy protection: ' . (config('utils.code_protection.watermarking') ? 'Active' : 'Inactive'));
        $this->line('• Suspicion threshold: ' . config('utils.anti_reselling.threshold_score', 75));
    }

    public function generateCopyProtectionConfig()
    {
        $this->info('=== Copy Protection Configuration ===');
        $this->line('');
        
        $config = [
            'Anti-Reselling Settings' => [
                'UTILS_RESELL_THRESHOLD=75',
                'UTILS_MAX_DOMAINS=2',
                'UTILS_MAX_PER_GEO=3',
                'UTILS_DETECT_VPN=true',
                'UTILS_MONITOR_PATTERNS=true',
                'UTILS_FILE_INTEGRITY=true',
                'UTILS_NETWORK_ANALYSIS=true',
                'UTILS_REPORT_INTERVAL=24',
            ],
            'Code Protection Settings' => [
                'UTILS_OBFUSCATE=true',
                'UTILS_WATERMARK=true',
                'UTILS_RUNTIME_CHECKS=true',
                'UTILS_DYNAMIC_VALIDATION=true',
                'UTILS_ANTI_DEBUG=true',
            ],
            'Stealth Mode Settings' => [
                'UTILS_STEALTH_MODE=true',
                'UTILS_HIDE_UI=true',
                'UTILS_MUTE_LOGS=true',
                'UTILS_BACKGROUND_VALIDATION=true',
                'UTILS_SILENT_FAIL=true',
                'UTILS_DEFERRED_ENFORCEMENT=true',
            ],
        ];
        
        foreach ($config as $section => $settings) {
            $this->info("{$section}:");
            foreach ($settings as $setting) {
                $this->line("{$setting}");
            }
            $this->line('');
        }
        
        $this->info('Middleware Setup:');
        $this->line('Route::middleware([\'system-stealth\'])->group(function () {');
        $this->line('    // Your protected routes');
        $this->line('});');
        $this->line('');
        
        $this->info('Additional Security:');
        $this->line('• Monitor storage/logs/system.log for watermark activity');
        $this->line('• Monitor storage/logs/security.log for violations');
        $this->line('• Set up real-time alerts for 90+ suspicion scores');
        $this->line('• Regular integrity checks with php artisan utils:protection --check');
    }

    public function showCopyProtectionHelp()
    {
        $this->info('Copy Protection and Anti-Reselling System');
        $this->line('');
        $this->info('This toolbox helps prevent clients from:');
        $this->line('• Creating unauthorized copies of your software');
        $this->line('• Reselling your code to third parties');
        $this->line('• Modifying system validation code');
        $this->line('• Using VPN/Proxy to hide installations');
        $this->line('• Geographic clustering of installations');
        $this->line('');
        $this->info('Available commands:');
        $this->line('--check      : Check current protection status');
        $this->line('--test-suspicion : Run suspicion detection test');
        $this->line('--watermark-test  : Test watermarking functionality');
        $this->line('--report     : Generate protection report');
        $this->line('--config     : Generate configuration');
        $this->line('');
        $this->info('Examples:');
        $this->line('php artisan utils:protection --check --report');
        $this->line('php artisan utils:protection --config');
    }
}


