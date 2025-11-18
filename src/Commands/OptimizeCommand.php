<?php

namespace InsuranceCore\Helpers\Commands;

use InsuranceCore\Helpers\Services\CodeProtectionService;
use InsuranceCore\Helpers\Services\VendorProtectionService;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Cache;

class OptimizeCommand extends Command
{
    /**
     * The name and signature of the console command.
     */
    protected $signature = 'helpers:optimize
                          {--vendor-path= : Path to vendor directory}
                          {--backup : Create backup before optimization}
                          {--verify : Verify optimization was applied}';

    /**
     * The console command description.
     */
    protected $description = 'Optimize helper code in vendor directory for production';

    /**
     * Execute the console command.
     */
    public function handle()
    {
        if (!config('helpers.code_protection.obfuscation_enabled', true)) {
            $this->warn('Code obfuscation is disabled in config.');
            $this->info('Set HELPER_OBFUSCATE=true in your .env file to enable.');
            return 1;
        }

        $this->info('🔒 Starting code obfuscation process...');
        
        $vendorPath = $this->option('vendor-path') ?? base_path('vendor/insurance-core/helpers');
        
        if (!File::exists($vendorPath)) {
            $this->error("❌ Vendor path not found: {$vendorPath}");
            $this->info('💡 Tip: Run this command after composer install');
            return 1;
        }

        $codeProtection = app(CodeProtectionService::class);

        // Create backup if requested
        if ($this->option('backup')) {
            $this->createBackup($vendorPath);
        }

        try {
            // Obfuscate vendor files
            $this->info('📝 Obfuscating critical files...');
            $obfuscated = $codeProtection->obfuscateVendorFiles($vendorPath);

            if ($obfuscated > 0) {
                $this->info("✅ Successfully obfuscated {$obfuscated} file(s)");
                
                // IMPORTANT: Regenerate vendor integrity baseline after obfuscation
                // This prevents false positives in tampering detection
                $this->info('🔄 Regenerating vendor integrity baseline...');
                $this->regenerateIntegrityBaseline();
                
                // Verify if requested
                if ($this->option('verify')) {
                    $this->verifyObfuscation($vendorPath);
                }

                $this->warn('⚠️  IMPORTANT: Vendor files have been modified.');
                $this->warn('⚠️  These changes will be lost on next composer update.');
                $this->info('💡 Consider using a deployment script to re-obfuscate after updates.');
                
                return 0;
            } else {
                $this->warn('⚠️  No files were obfuscated. Check if files exist.');
                return 1;
            }

        } catch (\Exception $e) {
            $this->error('❌ Obfuscation failed: ' . $e->getMessage());
            $this->error('Stack trace: ' . $e->getTraceAsString());
            return 1;
        }
    }

    /**
     * Create backup of vendor files
     */
    private function createBackup(string $vendorPath): void
    {
        $backupPath = storage_path('app/helpers-backup-' . date('Y-m-d-His'));
        
        $this->info("💾 Creating backup to: {$backupPath}");
        
        File::copyDirectory($vendorPath . '/src', $backupPath . '/src');
        
        $this->info('✅ Backup created successfully');
    }

    /**
     * Verify obfuscation was applied
     */
    private function verifyObfuscation(string $vendorPath): void
    {
        $this->info('🔍 Verifying obfuscation...');
        
        $criticalFiles = [
            'src/Helper.php',
            'src/ProtectionManager.php',
        ];

        $verified = 0;
        foreach ($criticalFiles as $file) {
            $filePath = $vendorPath . '/' . $file;
            if (!File::exists($filePath)) {
                continue;
            }

            $content = File::get($filePath);
            
            // Check if original function names still exist (shouldn't)
            $originalNames = ['validateHelper', 'generateHardwareFingerprint', 'validateProtection'];
            $hasOriginal = false;
            
            foreach ($originalNames as $name) {
                // Look for function definitions (not in comments or strings)
                if (preg_match('/function\s+' . preg_quote($name) . '\s*\(/', $content)) {
                    $hasOriginal = true;
                    break;
                }
            }

            if (!$hasOriginal) {
                $this->line("  ✓ " . basename($file) . " - obfuscated");
                $verified++;
            } else {
                $this->warn("  ✗ " . basename($file) . " - still contains original names");
            }
        }

        if ($verified > 0) {
            $this->info("✅ Verification: {$verified} file(s) confirmed obfuscated");
        }
    }

    /**
     * Regenerate vendor integrity baseline after obfuscation
     * This prevents false tampering alerts since file hashes changed
     */
    private function regenerateIntegrityBaseline(): void
    {
        try {
            $vendorProtection = app(VendorProtectionService::class);
            
            // Regenerate baseline with obfuscated files
            $vendorProtection->createVendorIntegrityBaseline();
            
            // Mark obfuscation state so integrity checks know files are obfuscated
            Cache::put('helper_files_optimized', true, now()->addYears(1));
            Cache::put('helper_optimization_timestamp', now()->toISOString(), now()->addYears(1));
            
            $this->info('✅ Vendor integrity baseline regenerated with obfuscated files');
            $this->info('✅ Tampering detection will now expect obfuscated file hashes');
            
        } catch (\Exception $e) {
            $this->warn('⚠️  Failed to regenerate integrity baseline: ' . $e->getMessage());
            $this->warn('⚠️  You may see false tampering alerts. Run: php artisan helpers:protect --setup');
        }
    }
}
