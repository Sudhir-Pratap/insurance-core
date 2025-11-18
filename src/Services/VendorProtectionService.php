<?php

namespace InsuranceCore\Helpers\Services;

use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Artisan;

class VendorProtectionService
{
    /**
     * Monitor and protect vendor directory integrity
     */
    public function protectVendorIntegrity(): void
    {
        $this->createVendorIntegrityBaseline();
        $this->setupVendorModificationDetection();
        $this->implementVendorFileLocking();
        $this->addVendorTamperingCountermeasures();
    }

    /**
     * Create initial integrity baseline for vendor files
     * 
     * NOTE: Only checks files within vendor/insurance-core/helpers directory.
     * Clients can freely modify their own code, Laravel core, and other vendor packages.
     */
    public function createVendorIntegrityBaseline(): void
    {
        // Only check our package directory - clients can modify everything else
        $vendorPath = base_path('vendor/insurance-core/helpers');

        if (!File::exists($vendorPath)) {
            Log::info('Helper package not found in vendor directory - skipping baseline creation');
            return;
        }

        // Ensure decoy files are present before generating baseline
        $this->createDecoyFiles();

        $baseline = $this->generateVendorBaseline($vendorPath);

        // Store multiple backups of the baseline
        Cache::put('vendor_baseline_primary', $baseline, now()->addYears(1));   
        Cache::put('vendor_baseline_backup', $baseline, now()->addYears(1));    
        Cache::put('vendor_baseline_timestamp', now()->toISOString(), now()->addYears(1));
        
        // Mark if baseline was created for obfuscated files
        $isObfuscated = Cache::get('helper_files_optimized', false);
        if ($isObfuscated) {
            Cache::put('vendor_baseline_obfuscated', true, now()->addYears(1));
        }

        Log::info('Vendor integrity baseline created', [
            'file_count' => count($baseline['files']),
            'total_size' => $baseline['total_size']
        ]);
    }

    /**
     * Generate comprehensive baseline for vendor directory
     * 
     * IMPORTANT: Only processes files within the helpers package directory.
     * This ensures clients can modify their own code, Laravel core, and other packages.
     */
    public function generateVendorBaseline(string $vendorPath): array
    {
        // Validate that we're only checking our package directory
        $normalizedPath = realpath($vendorPath);
        $expectedPath = realpath(base_path('vendor/insurance-core/helpers'));
        
        // Handle cases where realpath might fail (permissions, symlinks, etc.)
        if (!$normalizedPath || !$expectedPath) {
            // Fallback to string comparison with normalized separators
            $normalizedPath = str_replace(['/', '\\'], DIRECTORY_SEPARATOR, $vendorPath);
            $expectedPath = str_replace(['/', '\\'], DIRECTORY_SEPARATOR, base_path('vendor/insurance-core/helpers'));
        }
        
        // Normalize paths for comparison (handle Windows case-insensitivity)
        $normalizedPathLower = strtolower(str_replace(['/', '\\'], DIRECTORY_SEPARATOR, $normalizedPath));
        $expectedPathLower = strtolower(str_replace(['/', '\\'], DIRECTORY_SEPARATOR, $expectedPath));
        
        if ($normalizedPathLower !== $expectedPathLower) {
            Log::error('Attempted to generate baseline for wrong directory', [
                'requested' => $vendorPath,
                'expected' => base_path('vendor/insurance-core/helpers')
            ]);
            throw new \InvalidArgumentException('Can only generate baseline for helpers package directory');
        }

        $baseline = [
            'files' => [],
            'total_size' => 0,
            'structure_hash' => '',
            'critical_files' => [],
            'package_path' => $vendorPath, // Store for verification
        ];

        $criticalPatterns = [
            'Helper.php',
            'ProtectionManager.php',
            'Services/',
            'Http/Middleware/',
            'Commands/',
        ];

        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($vendorPath, \RecursiveDirectoryIterator::SKIP_DOTS)
        );

        foreach ($iterator as $file) {
            // Only check PHP files within our package directory
            if ($file->isFile() && $file->getExtension() === 'php') {
                $filePath = $file->getPathname();
                
                // Double-check we're still within our package directory
                // Normalize paths for cross-platform compatibility
                $fileRealPath = realpath($filePath);
                $baseRealPath = realpath($vendorPath);
                
                if ($fileRealPath && $baseRealPath) {
                    // Use realpath if available
                    if (!str_starts_with(strtolower($fileRealPath), strtolower($baseRealPath))) {
                        Log::warning('Skipping file outside package directory', ['file' => $filePath]);
                        continue;
                    }
                } else {
                    // Fallback: normalize separators and compare
                    $normalizedFilePath = str_replace(['/', '\\'], DIRECTORY_SEPARATOR, $filePath);
                    $normalizedBasePath = str_replace(['/', '\\'], DIRECTORY_SEPARATOR, $vendorPath);
                    if (!str_starts_with(strtolower($normalizedFilePath), strtolower($normalizedBasePath))) {
                        Log::warning('Skipping file outside package directory', ['file' => $filePath]);
                        continue;
                    }
                }

                $relativePath = str_replace($vendorPath . DIRECTORY_SEPARATOR, '', $filePath);
                $content = File::get($filePath);

                $fileHash = [
                    'path' => $relativePath,
                    'size' => $file->getSize(),
                    'modified' => $file->getMTime(),
                    'hash' => hash('sha256', $content),
                    'permissions' => substr(sprintf('%o', $file->getPerms()), -4),
                ];

                $baseline['files'][$relativePath] = $fileHash;
                $baseline['total_size'] += $file->getSize();

                // Mark critical files
                foreach ($criticalPatterns as $pattern) {
                    if (str_contains($relativePath, $pattern)) {
                        $baseline['critical_files'][$relativePath] = $fileHash;
                        break;
                    }
                }
            }
        }

        // Create structure hash
        ksort($baseline['files']);
        $baseline['structure_hash'] = hash('sha256', serialize($baseline['files']));

        return $baseline;
    }

    /**
     * Setup real-time vendor modification detection
     */
    public function setupVendorModificationDetection(): void
    {
        // This would be called during license validation
        $this->verifyVendorIntegrity();

        // Setup periodic integrity checks
        if (!Cache::has('vendor_integrity_check_scheduled')) {
            Cache::put('vendor_integrity_check_scheduled', true, now()->addHours(1));
        }
    }

    /**
     * Verify vendor directory integrity
     *
     * NOTE: Only verifies files within vendor/insurance-core/helpers directory.                                                                             
     * Clients can modify their own code, Laravel core, and other vendor packages without triggering violations.                                                
     * 
     * IMPORTANT: If files are obfuscated, baseline must be regenerated after obfuscation.
     */
    public function verifyVendorIntegrity(): array
    {
        $baseline = Cache::get('vendor_baseline_primary');
        $backupBaseline = Cache::get('vendor_baseline_backup');

        // Check if files are obfuscated - if so, baseline should already reflect obfuscated state
        $isObfuscated = Cache::get('helper_files_optimized', false);
        
        if (!$baseline) {
            // If obfuscation is expected but no baseline exists, create one
            if ($isObfuscated) {
                Log::warning('Obfuscated files detected but no baseline found - creating baseline for obfuscated files');
                $this->createVendorIntegrityBaseline();
                return ['status' => 'baseline_created_for_obfuscated', 'violations' => []];
            }
            
            Log::warning('No vendor integrity baseline found - creating new one');                                                                              
            $this->createVendorIntegrityBaseline();
            return ['status' => 'baseline_created', 'violations' => []];        
        }

        // Only check our package directory - not Laravel core or other packages
        $vendorPath = base_path('vendor/insurance-core/helpers');
        
        if (!File::exists($vendorPath)) {
            Log::warning('Helper package not found - skipping integrity check');
            return ['status' => 'package_not_found', 'violations' => []];
        }

        $currentState = $this->generateVendorBaseline($vendorPath);

        $violations = [];

        // Check for modified files
        foreach ($baseline['files'] as $path => $originalData) {
            if (!isset($currentState['files'][$path])) {
                $violations[] = [
                    'type' => 'file_deleted',
                    'file' => $path,
                    'severity' => 'critical'
                ];
            } elseif ($currentState['files'][$path]['hash'] !== $originalData['hash']) {
                $violations[] = [
                    'type' => 'file_modified',
                    'file' => $path,
                    'severity' => isset($baseline['critical_files'][$path]) ? 'critical' : 'high',
                    'original_hash' => $originalData['hash'],
                    'current_hash' => $currentState['files'][$path]['hash']
                ];
            }
        }

        // Check for new files
        foreach ($currentState['files'] as $path => $currentData) {
            if (!isset($baseline['files'][$path])) {
                $violations[] = [
                    'type' => 'file_added',
                    'file' => $path,
                    'severity' => 'medium'
                ];
            }
        }

        // Check structure integrity
        if ($currentState['structure_hash'] !== $baseline['structure_hash']) {
            $violations[] = [
                'type' => 'structure_modified',
                'severity' => 'high',
                'original_structure' => $baseline['structure_hash'],
                'current_structure' => $currentState['structure_hash']
            ];
        }

        // Handle violations
        if (!empty($violations)) {
            // Check if violations are due to obfuscation (expected changes)
            $obfuscationTimestamp = Cache::get('helper_optimization_timestamp');
            $baselineTimestamp = Cache::get('vendor_baseline_timestamp');
            
            // If baseline was created after obfuscation, violations are legitimate
            // If baseline was created before obfuscation but files are obfuscated, 
            // we need to ignore violations on obfuscated files
            if ($isObfuscated && $obfuscationTimestamp) {
                // Filter out violations that match expected obfuscation pattern
                $legitimateViolations = [];
                foreach ($violations as $violation) {
                    // If it's a file modification on a critical file, it might be obfuscation
                    if ($violation['type'] === 'file_modified' && 
                        isset($baseline['critical_files'][$violation['file']])) {
                        // Check if this is expected obfuscation change
                        // (we can't fully verify without knowing exact mappings, so we'll be lenient)
                        Log::debug('File modification detected on obfuscated file - may be expected', [
                            'file' => $violation['file'],
                            'obfuscation_timestamp' => $obfuscationTimestamp
                        ]);
                        // Only flag if baseline was created AFTER obfuscation (meaning it should match)
                        if ($baselineTimestamp && strtotime($baselineTimestamp) >= strtotime($obfuscationTimestamp)) {
                            // Baseline was created after obfuscation, so violations are real
                            $legitimateViolations[] = $violation;
                        }
                        // Otherwise, baseline was created before obfuscation, so ignore this violation
                    } else {
                        // Non-obfuscation related violations are always legitimate
                        $legitimateViolations[] = $violation;
                    }
                }
                
                if (empty($legitimateViolations)) {
                    Log::info('All violations appear to be from obfuscation - ignoring', [
                        'obfuscation_timestamp' => $obfuscationTimestamp
                    ]);
                    return [
                        'status' => 'integrity_verified',
                        'violations' => [],
                        'obfuscation_aware' => true,
                        'checked_at' => now()->toISOString()
                    ];
                }
                
                $violations = $legitimateViolations;
            }
            
            $this->handleVendorTampering($violations);

            // If primary baseline is compromised, try backup
            if (count($violations) > 2 && $backupBaseline) {
                Log::warning('Primary baseline may be compromised, checking backup');
                $backupViolations = $this->compareWithBaseline($currentState, $backupBaseline);
                if (count($backupViolations) < count($violations)) {
                    $this->handleVendorTampering($backupViolations, 'backup');
                }
            }
        }

        return [
            'status' => empty($violations) ? 'integrity_verified' : 'violations_detected',
            'violations' => $violations,
            'checked_at' => now()->toISOString()
        ];
    }

    /**
     * Compare current state with a specific baseline
     */
    public function compareWithBaseline(array $currentState, array $baseline): array
    {
        $violations = [];

        foreach ($baseline['files'] as $path => $originalData) {
            if (!isset($currentState['files'][$path])) {
                $violations[] = ['type' => 'file_deleted', 'file' => $path, 'severity' => 'critical'];
            } elseif ($currentState['files'][$path]['hash'] !== $originalData['hash']) {
                $violations[] = [
                    'type' => 'file_modified',
                    'file' => $path,
                    'severity' => isset($baseline['critical_files'][$path]) ? 'critical' : 'high'
                ];
            }
        }

        return $violations;
    }

    /**
     * Handle detected vendor tampering
     */
    public function handleVendorTampering(array $violations, string $baselineType = 'primary'): void
    {
        $criticalViolations = array_filter($violations, function($v) {
            return in_array($v['severity'], ['critical', 'high']);
        });

        // Log the incident
        Log::critical('Vendor file tampering detected', [
            'baseline_type' => $baselineType,
            'violations' => $violations,
            'critical_count' => count($criticalViolations),
            'total_violations' => count($violations)
        ]);

        // Send immediate alert
        app(RemoteSecurityLogger::class)->critical('Vendor File Tampering Detected', [
            'violations' => $violations,
            'baseline_type' => $baselineType,
            'server_info' => [
                'host' => gethostname(),
                'ip' => request()->ip(),
                'user_agent' => request()->userAgent(),
            ]
        ]);

        // Implement countermeasures based on severity
        if (count($criticalViolations) > 0) {
            $this->implementCriticalCountermeasures($violations);
        } else {
            $this->implementWarningCountermeasures($violations);
        }

        // Store violation record
        $violationRecord = [
            'timestamp' => now()->toISOString(),
            'violations' => $violations,
            'baseline_type' => $baselineType,
            'ip' => request()->ip(),
            'user_agent' => request()->userAgent(),
        ];

        $existingRecords = Cache::get('helper_tampering_records', []);
        $existingRecords[] = $violationRecord;

        // Keep only last 50 records
        if (count($existingRecords) > 50) {
            $existingRecords = array_slice($existingRecords, -50);
        }

        Cache::put('helper_tampering_records', $existingRecords, now()->addDays(30));
    }

    /**
     * Implement critical countermeasures for severe tampering
     */
    public function implementCriticalCountermeasures(array $violations): void
    {
        // Immediate license suspension
        Cache::put('helper_force_invalid', true, now()->addHours(24));

        // Clear all license caches
        Cache::forget('helper_valid_' . md5(config('helpers.helper_key') ?? ''));
        Cache::forget('helper_last_check_' . md5(config('helpers.helper_key') ?? ''));

        // Log critical security event
        Log::emergency('CRITICAL: Vendor tampering detected - license suspended', [
            'violations' => $violations,
            'action' => 'license_suspended'
        ]);

        // In extreme cases, you might want to:
        // - Send notification to license server to blacklist this installation
        // - Terminate the application
        // - Create forensic logs

        // For now, we'll make the application non-functional
        if (config('helpers.vendor_protection.terminate_on_critical', false)) {
            // Log and exit (be careful with this in production)
            Log::emergency('Application terminated due to critical vendor tampering');
            exit(1);
        }
    }

    /**
     * Implement warning countermeasures for minor tampering
     */
    public function implementWarningCountermeasures(array $violations): void
    {
        // Reduce license cache duration
        Cache::put('helper_cache_reduced', true, now()->addHours(1));

        // Force immediate server validation
        Cache::put('force_helper_validation', true, now()->addMinutes(30));

        // Log warning
        Log::warning('Vendor tampering warning - enhanced monitoring activated', [
            'violations' => $violations
        ]);
    }

    /**
     * Implement vendor file locking mechanisms
     */
    public function implementVendorFileLocking(): void
    {
        $vendorPath = base_path('vendor/insurance-core/helpers');

        if (!File::exists($vendorPath)) {
            return;
        }

        // Create .htaccess to prevent web access (if Apache)
        $htaccessContent = "# Deny access to vendor helper files\n" .
                          "<FilesMatch \"\\.(php)$\">\n" .
                          "    Order Deny,Allow\n" .
                          "    Deny from all\n" .
                          "</FilesMatch>\n";

        $htaccessPath = $vendorPath . '/.htaccess';
        if (!File::exists($htaccessPath)) {
            File::put($htaccessPath, $htaccessContent);
        }

        // Set restrictive permissions on critical files
        $criticalFiles = [
            'Helper.php',
            'ProtectionManager.php',
        ];

        foreach ($criticalFiles as $file) {
            $filePath = $vendorPath . '/' . $file;
            if (File::exists($filePath)) {
                // Set read-only for owner, no permissions for group/others
                chmod($filePath, 0400);
            }
        }

        // Create integrity verification file
        $integrityFile = $vendorPath . '/.integrity_check';
        $integrityData = [
            'created' => now()->toISOString(),
            'version' => '1.0',
            'protected' => true,
        ];

        File::put($integrityFile, json_encode($integrityData));
        chmod($integrityFile, 0400);
    }

    /**
     * Add additional vendor tampering countermeasures
     */
    public function addVendorTamperingCountermeasures(): void
    {
        // Setup file system monitoring (if available)
        $this->setupFilesystemMonitoring();

        // Create decoy files to detect tampering attempts
        $this->createDecoyFiles();

        // Implement self-healing mechanisms
        $this->setupSelfHealing();
    }

    /**
     * Setup file system monitoring
     */
    public function setupFilesystemMonitoring(): void
    {
        // This would integrate with system file monitoring tools
        // For now, we'll implement periodic checks

        $monitoringConfig = [
            'enabled' => true,
            'check_interval' => 300, // 5 minutes
            'last_check' => now()->toISOString(),
        ];

        Cache::put('vendor_filesystem_monitoring', $monitoringConfig, now()->addHours(1));
    }

    /**
     * Create decoy files to detect tampering
     * 
     * Creates decoy files only within our package directory.
     * These files help detect if someone is tampering with our package specifically.
     */
    public function createDecoyFiles(): void
    {
        // Only create decoy files in our package directory
        $vendorPath = base_path('vendor/insurance-core/helpers');

        if (!File::exists($vendorPath)) {
            return;
        }

        // Create hidden decoy files that should not be modified
        // These only exist within our package, not in client code
        $decoyFiles = [
            '.decoy_1.php' => '<?php // This is a decoy file - do not modify ?>',
            '.decoy_2.php' => '<?php /* Decoy file for tampering detection */ ?>',
        ];

        foreach ($decoyFiles as $filename => $content) {
            $filePath = $vendorPath . '/' . $filename;
            if (!File::exists($filePath)) {
                File::put($filePath, $content);
                chmod($filePath, 0400);

                // Store hash for monitoring
                $hash = hash('sha256', $content);
                Cache::put('decoy_file_' . $filename, $hash, now()->addYears(1));
            }
        }
    }

    /**
     * Setup self-healing mechanisms
     */
    public function setupSelfHealing(): void
    {
        // In a real implementation, this could restore files from backups
        // For now, we'll implement detection and alerting

        $healingConfig = [
            'enabled' => config('helpers.vendor_protection.self_healing', false),
            'backup_location' => storage_path('vendor_backups'),
            'auto_restore' => false, // Manual intervention required
        ];

        Cache::put('vendor_self_healing_config', $healingConfig, now()->addDays(30));
    }

    /**
     * Restore vendor files from backup (manual process)
     */
    public function restoreFromBackup(): bool
    {
        $backupLocation = storage_path('vendor_backups');
        $vendorPath = base_path('vendor/insurance-core/helpers');

        if (!File::exists($backupLocation)) {
            Log::error('No vendor backup found for restoration');
            return false;
        }

        try {
            // This would require manual intervention and verification
            Log::warning('Vendor restoration initiated - manual verification required');

            // Clear tampering detection
            Cache::forget('helper_force_invalid');

            // Recreate baseline
            $this->createVendorIntegrityBaseline();

            return true;
        } catch (\Exception $e) {
            Log::error('Vendor restoration failed', ['error' => $e->getMessage()]);
            return false;
        }
    }

    /**
     * Get vendor tampering report
     */
    public function getTamperingReport(): array
    {
        $records = Cache::get('helper_tampering_records', []);

        return [
            'total_incidents' => count($records),
            'recent_incidents' => array_slice($records, -10),
            'last_incident' => !empty($records) ? end($records) : null,
            'integrity_status' => $this->verifyVendorIntegrity(),
        ];
    }
}


