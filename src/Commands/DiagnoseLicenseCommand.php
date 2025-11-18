<?php

namespace InsuranceCore\Helpers\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use InsuranceCore\Helpers\ProtectionManager;
use InsuranceCore\Helpers\Helper;

class DiagnoseLicenseCommand extends Command
{
    protected $signature = 'helpers:diagnose {--fix : Attempt to fix common issues}';
    protected $description = 'Diagnose helper validation issues';

    public function handle()
    {
        $this->info('🔍 Helper Diagnosis Started');
        $this->newLine();

        $issues = [];
        $fixes = [];

        // Check configuration
        $this->checkConfiguration($issues, $fixes);

        // Check cache status
        $this->checkCacheStatus($issues, $fixes);

        // Check hardware fingerprint
        $this->checkHardwareFingerprint($issues, $fixes);

        // Check helper validation
        $this->checkHelperValidation($issues, $fixes);

        // Check anti-piracy validation
        $this->checkAntiPiracyValidation($issues, $fixes);

        // Display results
        $this->displayResults($issues, $fixes);

        // Apply fixes if requested
        if ($this->option('fix') && !empty($fixes)) {
            $this->applyFixes($fixes);
        }

        return empty($issues) ? 0 : 1;
    }

    public function checkConfiguration(&$issues, &$fixes)
    {
        $this->info('📋 Checking Configuration...');

        $requiredConfigs = [
            'helpers.helper_key' => 'HELPER_KEY',
            'helpers.product_id' => 'HELPER_PRODUCT_ID',
            'helpers.api_token' => 'HELPER_API_TOKEN',
            'helpers.helper_server' => 'HELPER_SERVER',
        ];

        foreach ($requiredConfigs as $config => $env) {
            $value = config($config);
            if (empty($value)) {
                $issues[] = "❌ Missing {$env} environment variable";
                $fixes[] = "Set {$env} in your .env file";
            } else {
                $this->line("✅ {$env}: " . substr($value, 0, 10) . '...');
            }
        }
    }

    public function checkCacheStatus(&$issues, &$fixes)
    {
        $this->info('💾 Checking Cache Status...');

        $helperKey = config('helpers.helper_key');
        $productId = config('helpers.product_id');
        $clientId = config('helpers.client_id');

        if ($helperKey && $productId && $clientId) {
            $cacheKey = "helper_valid_{$helperKey}_{$productId}_{$clientId}";
            $cached = Cache::get($cacheKey);
            
            if ($cached) {
                $this->line("✅ Helper cache: Valid");
            } else {
                $this->line("⚠️  Helper cache: Not found");
                $fixes[] = "Run: php artisan helpers:clear-cache";
            }
        }

        $hardwareFingerprint = Cache::get('hardware_fingerprint');
        if ($hardwareFingerprint) {
            $this->line("✅ Hardware fingerprint: Cached");
        } else {
            $this->line("⚠️  Hardware fingerprint: Not cached");
        }
    }

    public function checkHardwareFingerprint(&$issues, &$fixes)
    {
        $this->info('🖥️  Checking Hardware Fingerprint...');

        $helper = app(Helper::class);
        $currentFingerprint = $helper->generateHardwareFingerprint();
        $storedFingerprint = Cache::get('hardware_fingerprint');

        if ($storedFingerprint) {
            $similarity = similar_text($storedFingerprint, $currentFingerprint, $percent);
            
            if ($percent < 70) {
                $issues[] = "❌ Hardware fingerprint mismatch (similarity: {$percent}%)";
                $fixes[] = "Run: php artisan helpers:clear-cache";
            } else {
                $this->line("✅ Hardware fingerprint: Valid (similarity: {$percent}%)");
            }
        } else {
            $this->line("ℹ️  Hardware fingerprint: Not stored (will be created on first validation)");
        }
    }

    public function checkHelperValidation(&$issues, &$fixes)
    {
        $this->info('🔐 Checking Helper Validation...');

        try {
            $helper = app(Helper::class);
            $helperKey = config('helpers.helper_key');
            $productId = config('helpers.product_id');
            $clientId = config('helpers.client_id');
            $domain = request()->getHost() ?: 'localhost';
            $ip = request()->ip() ?: '127.0.0.1';

            $isValid = $helper->validateHelper($helperKey, $productId, $domain, $ip, $clientId);
            
            if ($isValid) {
                $this->line("✅ Helper validation: Success");
            } else {
                $issues[] = "❌ Helper validation: Failed";
                $fixes[] = "Check helper server connectivity and helper key validity";
            }
        } catch (\Exception $e) {
            $issues[] = "❌ Helper validation error: " . $e->getMessage();
            $fixes[] = "Check network connectivity to helper server";
        }
    }

    public function checkAntiPiracyValidation(&$issues, &$fixes)
    {
        $this->info('🛡️  Checking Anti-Piracy Validation...');

        try {
            $antiPiracyManager = app(ProtectionManager::class);
            $isValid = $antiPiracyManager->validateAntiPiracy();
            
            if ($isValid) {
                $this->line("✅ Anti-piracy validation: Success");
            } else {
                $issues[] = "❌ Anti-piracy validation: Failed";
                $fixes[] = "Run: php artisan helpers:clear-cache";
            }
        } catch (\Exception $e) {
            $issues[] = "❌ Anti-piracy validation error: " . $e->getMessage();
        }
    }

    public function displayResults($issues, $fixes)
    {
        $this->newLine();
        $this->info('📊 Diagnosis Results:');
        $this->newLine();

        if (empty($issues)) {
            $this->info('🎉 All checks passed! Your license system is working correctly.');
        } else {
            $this->error('❌ Found ' . count($issues) . ' issue(s):');
            foreach ($issues as $issue) {
                $this->line($issue);
            }

            if (!empty($fixes)) {
                $this->newLine();
                $this->warn('🔧 Suggested fixes:');
                foreach ($fixes as $fix) {
                    $this->line("• {$fix}");
                }
            }
        }
    }

    public function applyFixes($fixes)
    {
        $this->newLine();
        $this->info('🔧 Applying fixes...');

        foreach ($fixes as $fix) {
            if (str_contains($fix, 'helpers:clear-cache')) {
                $this->call('helpers:clear-cache', ['--force' => true]);
                $this->line("✅ Applied: Reset license cache");
            } else {
                $this->line("ℹ️  Manual fix required: {$fix}");
            }
        }
    }
} 

