<?php

namespace InsuranceCore\Helpers\Services;

use Illuminate\Support\Facades\Log;                                             
use Illuminate\Support\Facades\Cache;                                           
use Illuminate\Support\Facades\File;
use InsuranceCore\Helpers\Services\RemoteSecurityLogger;
use Illuminate\Support\Str;

class CodeProtectionService
{
    /**
     * Apply code obfuscation and protection measures
     */
    public function applyProtection(): void
    {
        if (!config('helpers.code_protection.obfuscation_enabled', true)) {
            return;
        }

        $this->obfuscateCriticalFunctions();
        $this->addRuntimeIntegrityChecks();
        $this->implementAntiDebugMeasures();
        $this->addWatermarking();
    }

        /**
     * Obfuscate critical license functions in vendor directory
     */
    public function obfuscateCriticalFunctions(): void
    {
        // This method is called during runtime, but actual obfuscation
        // should be done via artisan command: php artisan helpers:optimize
        // This is because vendor files shouldn't be modified at runtime
        
        $this->verifyObfuscationApplied();
    }

    /**
     * Obfuscate vendor files (called by command)
     */
    public function obfuscateVendorFiles(string $vendorPath): int
    {
        $criticalFiles = [
            'src/Helper.php',
            'src/ProtectionManager.php',
            'src/Services/CodeProtectionService.php',
            'src/Services/WatermarkingService.php',
        ];

        $obfuscatedCount = 0;
        $mappings = [];

        foreach ($criticalFiles as $file) {
            $filePath = $vendorPath . '/' . $file;
            if (File::exists($filePath)) {
                $mapping = $this->obfuscateFile($filePath);
                if ($mapping) {
                    $mappings[basename($file)] = $mapping;
                    $obfuscatedCount++;
                }
            }
        }

        // Store obfuscation mappings for runtime deobfuscation if needed
        if (!empty($mappings)) {
            Cache::put('helper_obfuscation_mappings', $mappings, now()->addYears(1));
        }

        return $obfuscatedCount;
    }

    /**
     * Verify if obfuscation is already applied
     */
    private function verifyObfuscationApplied(): void
    {
        $mappings = Cache::get('helper_obfuscation_mappings');
        if (empty($mappings)) {
            Log::debug('Code obfuscation not detected. Run: php artisan helpers:optimize');
        }
    }

    /**
     * Add runtime integrity checks
     */
    public function addRuntimeIntegrityChecks(): void
    {
        // Add integrity verification at runtime
        $integrityHash = $this->generateIntegrityHash();
        Cache::put('code_integrity_hash', $integrityHash, now()->addDays(30));

        // This would be called during license validation
        $this->verifyIntegrity($integrityHash);
    }

    /**
     * Implement anti-debugging measures
     */
    public function implementAntiDebugMeasures(): void
    {
        // Detect debugging tools and development environments
        $debugIndicators = [
            'xdebug' => extension_loaded('xdebug'),
            'debug_backtrace' => count(debug_backtrace()) > 10,
            'eval_usage' => $this->detectEvalUsage(),
            'development_headers' => $this->detectDevelopmentHeaders(),
        ];

        if (array_filter($debugIndicators)) {
            Log::warning('Debugging environment detected', array_keys(array_filter($debugIndicators)));
        }
    }

    /**
     * Add invisible watermarking to HTML output
     */
    public function addWatermarking(): void
    {
        if (!config('helpers.code_protection.watermarking', true)) {
            return;
        }

        // This would hook into Laravel's response rendering
        // For now, we'll document the implementation approach
    }

    /**
     * Generate integrity hash for critical files
     * NOTE: Checks vendor files if obfuscated, otherwise checks package source files
     */
    public function generateIntegrityHash(): string
    {
        // Check if files are obfuscated - if so, check vendor files
        $isObfuscated = Cache::get('helper_files_optimized', false);
        
        if ($isObfuscated) {
            // Check obfuscated vendor files
            $vendorPath = base_path('vendor/insurance-core/helpers');
            $criticalFiles = [
                'src/Helper.php',
                'src/ProtectionManager.php',
            ];
        } else {
            // Check package source files
            $vendorPath = __DIR__ . '/..';
            $criticalFiles = [
                'Helper.php',
                'ProtectionManager.php',
            ];
        }

        $hashes = [];
        foreach ($criticalFiles as $file) {
            $filePath = $vendorPath . '/' . $file;
            if (File::exists($filePath)) {
                $hashes[] = hash_file('sha256', $filePath);
            }
        }

        return hash('sha256', implode('', $hashes));
    }

    /**
     * Verify code integrity
     */
    public function verifyIntegrity(string $expectedHash): bool
    {
        $currentHash = $this->generateIntegrityHash();

                if ($currentHash !== $expectedHash) {
            app(RemoteSecurityLogger::class)->critical('Code integrity violation detected', [
                'expected_hash' => $expectedHash,
                'current_hash' => $currentHash,
            ]);

            return false;
        }

        return true;
    }

    /**
     * Detect eval() usage (security risk)
     */
    public function detectEvalUsage(): bool
    {
        // Check if eval function is disabled
        $disabled = explode(',', ini_get('disable_functions'));
        return !in_array('eval', $disabled);
    }

    /**
     * Detect development headers that might indicate debugging
     */
    public function detectDevelopmentHeaders(): bool
    {
        $headers = [
            'X-Debug-Token',
            'X-Debug-Token-Link',
            'X-Php-Debugbar',
        ];

        foreach ($headers as $header) {
            if (request()->hasHeader($header)) {
                return true;
            }
        }

        return false;
    }

        /**
     * Obfuscate a single file using regex-based function name replacement
     * This is safer than simple string replacement as it targets function definitions
     */
    public function obfuscateFile(string $filePath): ?array
    {
        $content = File::get($filePath);
        $originalContent = $content;
        
        // Function names to obfuscate with their contexts
        $functionsToObfuscate = [
            'validateLicense',
            'generateHardwareFingerprint', 
            'validateAntiPiracy',
            'checkLicenseStatus',
            'generateClientWatermark',
            'createWatermark',
            'detectContentModification',
            'addRuntimeChecks',
            'generateIntegrityCheckScript',
        ];

        $replacements = [];
        
        foreach ($functionsToObfuscate as $original) {
            // Check if function exists in file first
            $functionExists = preg_match('/\b' . preg_quote($original, '/') . '\s*\(/', $content);
            
            if (!$functionExists) {
                continue; // Skip if function doesn't exist in this file
            }
            
            // Generate unique obfuscated name
            $obfuscated = 'v' . Str::random(3) . Str::random(5); // e.g., vA3bX2mK7
            
            // Replace function definitions: public/protected/private function functionName(
            $content = preg_replace(
                '/(public|protected|private|static)\s+function\s+' . preg_quote($original, '/') . '\s*\(/',
                '$1 function ' . $obfuscated . '(',
                $content
            );
            
            // Replace method calls: ->functionName( or ::functionName(
            $content = preg_replace(
                '/(->|::)' . preg_quote($original, '/') . '\s*\(/',
                '$1' . $obfuscated . '(',
                $content
            );
            
            // Replace standalone function calls: functionName(
            // But only if it's not part of another word
            $content = preg_replace(
                '/(?<![a-zA-Z0-9_$])' . preg_quote($original, '/') . '\s*\(/',
                $obfuscated . '(',
                $content
            );
            
            $replacements[$original] = $obfuscated;
        }

        // Only write if changes were made
        if (!empty($replacements)) {
            File::put($filePath, $content);
            
            Log::info('File obfuscated', [
                'file' => basename($filePath),
                'functions_obfuscated' => count($replacements),
            ]);
            
            return $replacements;
        }

        return null;
    }

    /**
     * Dynamic validation key generation
     */
    public function generateDynamicKey(): string
    {
        $components = [
            config('app.key'),
            config('helpers.helper_key'),
            now()->format('Y-m-d-H'),
            request()->ip(),
        ];

        return hash('sha256', implode('|', $components));
    }
}

