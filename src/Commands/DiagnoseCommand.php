<?php

namespace InsuranceCore\Utils\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use InsuranceCore\Utils\SecurityManager;
use InsuranceCore\Utils\Manager;

class DiagnoseCommand extends Command
{
    protected $signature = 'utils:diagnose {--fix : Attempt to fix common issues}';
    protected $description = 'Diagnose system configuration issues';

    public function handle()
    {
        $this->info('🔍 System Diagnosis Started');
        $this->newLine();

        $issues = [];
        $fixes = [];

        // Check configuration
        $this->checkConfiguration($issues, $fixes);

        // Check cache status
        $this->checkCacheStatus($issues, $fixes);

        // Check hardware fingerprint
        $this->checkHardwareFingerprint($issues, $fixes);

        // Check server communication
        $this->checkServerCommunication($issues, $fixes);

        // Display results
        $this->displayResults($issues, $fixes);

        // Attempt fixes if requested
        if ($this->option('fix') && !empty($fixes)) {
            $this->attemptFixes($fixes);
        }
    }

    private function checkConfiguration(&$issues, &$fixes)
    {
        $this->info('📋 Checking Configuration...');

        $requiredConfig = [
            'utils.system_key' => 'System Key',
            'utils.product_id' => 'Product ID',
            'utils.client_id' => 'Client ID',
            'utils.validation_server' => 'Validation Server',
            'utils.api_token' => 'API Token',
        ];

        foreach ($requiredConfig as $key => $label) {
            $value = config($key);
            if (empty($value)) {
                $issues[] = "❌ {$label} is not configured";
                $fixes[] = [
                    'type' => 'config',
                    'key' => $key,
                    'label' => $label,
                ];
            } else {
                $this->line("✅ {$label}: Configured");
            }
        }

        $this->newLine();
    }

    private function checkCacheStatus(&$issues, &$fixes)
    {
        $this->info('💾 Checking Cache Status...');

        try {
            $testKey = 'diagnosis_test_' . time();
            Cache::put($testKey, 'test', 60);
            $value = Cache::get($testKey);
            Cache::forget($testKey);

            if ($value === 'test') {
                $this->line("✅ Cache: Working");
            } else {
                $issues[] = "⚠️  Cache: Not working properly";
                $fixes[] = [
                    'type' => 'cache',
                    'action' => 'clear',
                ];
            }
        } catch (\Exception $e) {
            $issues[] = "❌ Cache: Error - " . $e->getMessage();
            $fixes[] = [
                'type' => 'cache',
                'action' => 'clear',
            ];
        }

        // Check for cached validation results
        $cacheKey = 'system_valid_' . md5(config('utils.system_key', ''));
        $cached = Cache::get($cacheKey);
        if ($cached) {
            $this->line("✅ System cache: Valid");
        } else {
            $this->line("⚠️  System cache: Not found");
        }

        $this->newLine();
    }

    private function checkHardwareFingerprint(&$issues, &$fixes)
    {
        $this->info('🖥️  Checking Hardware Fingerprint...');

        try {
            $manager = app(Manager::class);
            $fingerprint = $manager->generateHardwareFingerprint();
            $installationId = $manager->getOrCreateInstallationId();

            if ($fingerprint && $installationId) {
                $this->line("✅ Hardware Fingerprint: Generated");
                $this->line("✅ Installation ID: {$installationId}");
            } else {
                $issues[] = "❌ Hardware Fingerprint: Failed to generate";
            }
        } catch (\Exception $e) {
            $issues[] = "❌ Hardware Fingerprint: Error - " . $e->getMessage();
        }

        $this->newLine();
    }

    private function checkServerCommunication(&$issues, &$fixes)
    {
        $this->info('🌐 Checking Server Communication...');

        try {
            $manager = app(\InsuranceCore\Utils\Manager::class);
            $systemKey = config('utils.system_key');
            $productId = config('utils.product_id');
            $domain = request()->getHost() ?? 'localhost';
            $ip = request()->ip() ?? '127.0.0.1';
            $clientId = config('utils.client_id');

            if ($systemKey && $productId && $clientId) {
                $isValid = $manager->validateSystem($systemKey, $productId, $domain, $ip, $clientId);

                if ($isValid) {
                    $this->line("✅ System validation: Success");
                } else {
                    $issues[] = "❌ System validation: Failed";
                }
            } else {
                $issues[] = "⚠️  System validation: Cannot test (missing configuration)";
            }
        } catch (\Exception $e) {
            $issues[] = "❌ System validation error: " . $e->getMessage();
        }

        $this->newLine();
    }

    public function checkSystemValidation(&$issues, &$fixes)
    {
        $this->info('🔐 Checking System Validation...');

        try {
            $manager = app(\InsuranceCore\Utils\Manager::class);
            $systemKey = config('utils.system_key');
            $productId = config('utils.product_id');
            $domain = request()->getHost() ?? 'localhost';
            $ip = request()->ip() ?? '127.0.0.1';
            $clientId = config('utils.client_id');

            if ($systemKey && $productId && $clientId) {
                $isValid = $manager->validateSystem($systemKey, $productId, $domain, $ip, $clientId);

                if ($isValid) {
                    $this->line("✅ System validation: Success");
                } else {
                    $issues[] = "❌ System validation: Failed";
                }
            } else {
                $issues[] = "❌ System validation: Cannot test (missing configuration)";
            }
        } catch (\Exception $e) {
            $issues[] = "❌ System validation error: " . $e->getMessage();
        }
    }

    private function displayResults($issues, $fixes)
    {
        $this->info('📊 Diagnosis Results:');
        $this->newLine();

        if (empty($issues)) {
            $this->info('✅ No issues found! System is configured correctly.');
        } else {
            $this->warn('⚠️  Found ' . count($issues) . ' issue(s):');
            foreach ($issues as $issue) {
                $this->line("  {$issue}");
            }
        }

        $this->newLine();
    }

    private function attemptFixes($fixes)
    {
        $this->info('🔧 Attempting to fix issues...');
        $this->newLine();

        foreach ($fixes as $fix) {
            if ($fix['type'] === 'cache' && $fix['action'] === 'clear') {
                try {
                    Cache::flush();
                    $this->line("✅ Cleared cache");
                } catch (\Exception $e) {
                    $this->error("❌ Failed to clear cache: " . $e->getMessage());
                }
            }
        }

        $this->newLine();
        $this->info('✅ Fix attempts completed. Please run diagnosis again to verify.');
    }
}

