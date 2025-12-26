<?php

namespace InsuranceCore\Utils;

use Carbon\Carbon;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Str;

/**
 * Security manager for application protection and validation
 * @internal This class is obfuscated - do not reference directly
 */
class SecurityManager
{
    public $manager; // System manager instance
    public $hardwareFingerprint;
    public $installationId;
    public $lastValidationTime;
    public $lastValidationResults = [];
    
    public function __construct(Manager $manager)
    {
        $this->manager = $manager; // System manager instance
        $this->hardwareFingerprint = $this->manager->generateHardwareFingerprint();
        $this->installationId = $this->getOrCreateInstallationId();
    }

    /**
     * Comprehensive anti-piracy validation with stealth mode support
     */
    public function validateAntiPiracy(): bool
    {
        // Prevent duplicate validation calls within the same request lifecycle
        // This avoids false positives when called from both service provider and middleware
        $requestId = request()->header('X-Request-ID') 
            ?: md5(request()->ip() . request()->userAgent() . request()->path() . request()->method());
        $requestCacheKey = 'validation_result_' . $requestId;
        $inProgressKey = 'validation_in_progress_' . $requestId;
        
        // If we have a cached result for this request, return it immediately
        if (Cache::has($requestCacheKey)) {
            $cachedResult = Cache::get($requestCacheKey);
            Log::debug('Using cached validation result for same request', [
                'request_id' => substr($requestId, 0, 8),
                'cached_result' => $cachedResult,
            ]);
            return $cachedResult;
        }
        
        // If validation is already in progress, wait briefly and check again
        // This handles race conditions when called simultaneously from multiple places
        if (Cache::has($inProgressKey)) {
            // Wait up to 100ms for the other call to complete
            $maxWait = 10;
            $waited = 0;
            while (Cache::has($inProgressKey) && $waited < $maxWait) {
                usleep(10000); // 10ms
                $waited++;
                if (Cache::has($requestCacheKey)) {
                    return Cache::get($requestCacheKey);
                }
            }
        }
        
        // Mark validation as in progress (expires in 2 seconds)
        Cache::put($inProgressKey, true, now()->addSeconds(2));
        
        try {
            // Check stealth mode configuration
            $stealthMode = config('utils.stealth.enabled', false);
        
            if ($stealthMode) {
                $result = $this->validateInStealthMode();
                Cache::put($requestCacheKey, $result, now()->addSeconds(5));
                Cache::forget($inProgressKey);
                return $result;
            }

            // Standard validation layers
            $validations = [
                'system' => $this->validateSystem(),
                'hardware' => $this->validateHardwareFingerprint(),
                'installation' => $this->validateInstallationId(),
                'tampering' => $this->detectTampering(),
                'vendor_integrity' => $this->validateVendorIntegrity(),
                'environment' => $this->validateEnvironment(),
                'usage_patterns' => $this->validateUsagePatterns(),
                'server_communication' => $this->validateServerCommunication(),
            ];
            
            // Store results for debugging
            $this->lastValidationResults = $validations;

            // Log validation results (always log failures, muted in stealth mode for successes)
            $failedValidations = array_filter($validations, function($result) { return $result === false; });
            if (!empty($failedValidations)) {
                Log::error('Anti-piracy validation failures', [
                    'failed' => array_keys($failedValidations),
                    'all_results' => $validations
                ]);
            } elseif (!config('utils.stealth.mute_logs', false)) {
                Log::info('Anti-piracy validation results', $validations);
            }

            // More lenient validation - allow some failures but require critical ones to pass
            $criticalValidations = [
                'system' => $validations['system'] ?? false,
                'installation' => $validations['installation'] ?? false,
                'tampering' => $validations['tampering'] ?? false,
                'vendor_integrity' => $validations['vendor_integrity'] ?? false,
            ];

            // All critical validations must pass
            $failedCritical = array_filter($criticalValidations, function($result) { return $result === false; });
            if (!empty($failedCritical)) {
                Log::error('Critical anti-piracy validation failed', [
                    'failed_critical' => array_keys($failedCritical),
                    'all_critical' => $criticalValidations
                ]);
                $result = false;
            } else {
                // For non-critical validations, allow failures but log them
                // ENHANCED: usage_patterns and server_communication failures should NOT block validation
                // Only block if critical non-system validations fail (hardware, vendor_integrity, environment)
                $nonCriticalFailures = 0;
                $criticalNonSystemFailures = 0;
                
                foreach ($validations as $key => $valResult) {
                    // Exclude system, installation, tampering (already checked above)
                    // Also exclude usage_patterns and server_communication (too sensitive, can have false positives)
                    if (!in_array($key, ['system', 'installation', 'tampering', 'usage_patterns', 'server_communication']) && !$valResult) {
                        $nonCriticalFailures++;
                        // Count hardware, vendor_integrity, environment as critical non-system
                        if (in_array($key, ['hardware', 'vendor_integrity', 'environment'])) {
                            $criticalNonSystemFailures++;
                        }
                    }
                }

                // Only fail if critical non-system validations fail (hardware, vendor, environment)
                // usage_patterns and server_communication failures are logged but don't block
                if ($criticalNonSystemFailures > 0) {
                    if (!config('utils.stealth.mute_logs', false)) {
                        Log::warning('Critical non-system validation failures', [
                            'failures' => $criticalNonSystemFailures,
                            'validations' => $validations
                        ]);
                    }
                    $result = false;
                } else {
                    // All critical validations passed - allow access even if usage_patterns or server_communication failed
                    $result = true;
                    
                    // Log non-critical failures for monitoring (but don't block)
                    if ($nonCriticalFailures > 0 || !($validations['usage_patterns'] ?? true) || !($validations['server_communication'] ?? true)) {
                        Log::info('Non-critical validation warnings (not blocking)', [
                            'usage_patterns' => $validations['usage_patterns'] ?? true,
                            'server_communication' => $validations['server_communication'] ?? true,
                            'other_failures' => $nonCriticalFailures,
                        ]);
                    }
                }
            }

            // Store result in per-request cache before returning
            Cache::put($requestCacheKey, $result, now()->addSeconds(5));
            Cache::forget($inProgressKey);
            
            return $result;
        } catch (\Exception $e) {
            // On error, allow access but log it
            Log::error('Validation error: ' . $e->getMessage());
            $result = true; // Fail open for errors
            Cache::put($requestCacheKey, $result, now()->addSeconds(5));
            Cache::forget($inProgressKey);
            return $result;
        }
    }

    /**
     * Get last validation results for debugging
     */
    public function getLastValidationResults(): array
    {
        return $this->lastValidationResults;
    }

    /**
     * Generate unique hardware fingerprint
     */
    public function generateHardwareFingerprint(): string
    {
        // Use the persisted hardware fingerprint from Manager
        return $this->manager->generateHardwareFingerprint();
    }

    /**
     * Get or create unique installation ID
     */
    public function getOrCreateInstallationId(): string
    {
        $idFile = storage_path('app/installation.id');
        
        if (File::exists($idFile)) {
            $id = File::get($idFile);
            if (Str::isUuid($id)) {
                return $id;
            }
        }

        $id = Str::uuid()->toString();
        File::put($idFile, $id);
        
        return $id;
    }

    /**
     * Validate system key with enhanced security
     */
    public function validateSystem(): bool
    {
        $systemKey = config('utils.system_key');
        $productId = config('utils.product_id');
        $clientId = config('utils.client_id');
        
        // Gracefully handle fresh installations where configuration may not be set yet
        if (empty($systemKey) || empty($productId) || empty($clientId)) {
            $env = config('app.env', 'local');
            
            // Development environments: always allow (no validation needed)
            if (in_array($env, ['local', 'dev', 'development', 'testing'])) {
                return true;
            }
            
            // Production/staging: Check grace period
            $gracePeriodDays = config('utils.grace_period_days', 7); // Default 7 days grace period
            $installKey = 'utils_package_install_date';
            $installDate = Cache::get($installKey);
            
            // Track when package was first used (if not already tracked)
            if (!$installDate) {
                $installDate = now();
                Cache::put($installKey, $installDate, now()->addYears(1)); // Store for 1 year
            }
            
            $daysSinceInstall = $installDate->diffInDays(now());
            
            // Within grace period: Allow but warn
            if ($daysSinceInstall <= $gracePeriodDays) {
                $warningKey = 'utils_config_missing_warning_logged_' . $daysSinceInstall;
                if (!Cache::has($warningKey)) {
                    $daysRemaining = $gracePeriodDays - $daysSinceInstall;
                    Log::warning("Insurance Core Utils: System key not configured. Grace period: {$daysRemaining} days remaining. Run 'php artisan utils:info' to get your system identifiers, then configure UTILS_KEY, UTILS_PRODUCT_ID, and UTILS_CLIENT_ID in your .env file.", [
                        'environment' => $env,
                        'days_since_install' => $daysSinceInstall,
                        'grace_period_days' => $gracePeriodDays,
                        'days_remaining' => $daysRemaining,
                        'missing_config' => [
                            'system_key' => empty($systemKey),
                            'product_id' => empty($productId),
                            'client_id' => empty($clientId),
                        ],
                    ]);
                    // Log warning once per day
                    Cache::put($warningKey, true, now()->addDay());
                }
                return true; // Still allow during grace period
            }
            
            // Grace period expired: Still allow but log critical warning
            $criticalWarningKey = 'utils_config_missing_critical_warning';
            if (!Cache::has($criticalWarningKey)) {
                Log::critical('Insurance Core Utils: System key not configured after grace period. Validation is disabled. Please configure UTILS_KEY, UTILS_PRODUCT_ID, and UTILS_CLIENT_ID immediately.', [
                    'environment' => $env,
                    'days_since_install' => $daysSinceInstall,
                    'grace_period_expired' => true,
                ]);
                // Log critical warning once per day
                Cache::put($criticalWarningKey, true, now()->addDay());
            }
            
            // Still return true to prevent breaking the app, but validation is effectively disabled
            return true;
        }

        $currentDomain = request()->getHost();
        $currentIp = request()->ip();

        // Use the original client ID for validation (not enhanced with hardware fingerprint)
        // The hardware fingerprint is sent separately to the validation server
		
        return $this->manager->validateSystem(
            $systemKey, 
            $productId, 
            $currentDomain, 
            $currentIp, 
            $clientId
        );
    }

    /**
     * PHASE 3: Validate hardware fingerprint with enhanced stability
     * Better handling of legitimate hardware changes (server migration, upgrades, etc.)
     */
    public function validateHardwareFingerprint(): bool
    {
        $remoteLogger = app(\InsuranceCore\Utils\Services\RemoteSecurityLogger::class);
        
        $storedFingerprint = Cache::get('hardware_fingerprint');
        $fingerprintHistory = Cache::get('hardware_fingerprint_history', []);
        
        if (!$storedFingerprint) {
            // First time - store fingerprint and initialize history
            Cache::put('hardware_fingerprint', $this->hardwareFingerprint, now()->addDays(30));
            Cache::put('hardware_fingerprint_history', [[
                'fingerprint' => $this->hardwareFingerprint,
                'timestamp' => now()->toISOString(),
                'change_type' => 'initial',
            ]], now()->addDays(30));
            return true;
        }

        // ENHANCED: Multi-factor similarity calculation
        $similarity = similar_text($storedFingerprint, $this->hardwareFingerprint, $percent);
        
        // Calculate additional similarity metrics
        $levenshteinDistance = levenshtein($storedFingerprint, $this->hardwareFingerprint);
        $maxLength = max(strlen($storedFingerprint), strlen($this->hardwareFingerprint));
        $levenshteinSimilarity = $maxLength > 0 ? (1 - ($levenshteinDistance / $maxLength)) * 100 : 0;
        
        // Combined similarity score (weighted average)
        $combinedSimilarity = ($percent * 0.7) + ($levenshteinSimilarity * 0.3);
        
        // ENHANCED: Check if change is gradual (legitimate) or sudden (suspicious)
        $isGradualChange = $this->isGradualHardwareChange($fingerprintHistory, $this->hardwareFingerprint);
        
        // ENHANCED: Thresholds based on change pattern
        $threshold = $isGradualChange ? 60 : 70; // Lower threshold for gradual changes
        
        if ($combinedSimilarity < $threshold) {
            // Significant change detected
            $changeSeverity = $this->assessChangeSeverity($combinedSimilarity, $isGradualChange);
            
            // Log hardware fingerprint change
            $remoteLogger->logResellingAttempt([
                'check_type' => 'hardware_fingerprint_change',
                'hardware_fingerprint_changed' => true,
                'similarity_percent' => $percent,
                'combined_similarity' => $combinedSimilarity,
                'levenshtein_similarity' => $levenshteinSimilarity,
                'is_gradual_change' => $isGradualChange,
                'change_severity' => $changeSeverity,
            ]);
            
            Log::warning('Hardware fingerprint changed', [
                'stored' => substr($storedFingerprint, 0, 32) . '...',
                'current' => substr($this->hardwareFingerprint, 0, 32) . '...',
                'similarity' => $percent,
                'combined_similarity' => $combinedSimilarity,
                'is_gradual' => $isGradualChange,
                'severity' => $changeSeverity,
            ]);
            
            // ENHANCED: Handle based on change severity and pattern
            if ($changeSeverity === 'legitimate' || ($changeSeverity === 'moderate' && $isGradualChange)) {
                // Legitimate change or gradual moderate change - update fingerprint
                $this->updateHardwareFingerprint($this->hardwareFingerprint, $changeSeverity);
                return true;
            } elseif ($changeSeverity === 'moderate' && $combinedSimilarity > 50) {
                // Moderate change with reasonable similarity - allow but monitor
                $this->updateHardwareFingerprint($this->hardwareFingerprint, 'moderate', true);
                return true;
            }
            
            // Severe or suspicious change - fail validation
            return false;
        }

        // No significant change - fingerprint is stable
        return true;
    }

    /**
     * PHASE 3: Check if hardware change is gradual (legitimate) or sudden (suspicious)
     * 
     * @param array $history Previous fingerprint history
     * @param string $currentFingerprint Current fingerprint
     * @return bool True if change appears gradual
     */
    protected function isGradualHardwareChange(array $history, string $currentFingerprint): bool
    {
        if (empty($history)) {
            return false; // No history, can't determine
        }
        
        // Check if there's a pattern of gradual changes
        $recentChanges = array_slice($history, -5); // Last 5 changes
        
        if (count($recentChanges) < 2) {
            return false; // Not enough history
        }
        
        // Calculate similarity progression
        $similarities = [];
        foreach ($recentChanges as $entry) {
            if (isset($entry['fingerprint'])) {
                similar_text($entry['fingerprint'], $currentFingerprint, $sim);
                $similarities[] = $sim;
            }
        }
        
        // If similarities are gradually decreasing, it's a gradual change
        if (count($similarities) >= 2) {
            $trend = $similarities[0] > $similarities[count($similarities) - 1];
            $variance = max($similarities) - min($similarities);
            
            // Gradual if trend exists and variance is moderate (not sudden)
            return $trend && $variance < 30;
        }
        
        return false;
    }

    /**
     * PHASE 3: Assess severity of hardware fingerprint change
     * 
     * @param float $similarity Combined similarity score
     * @param bool $isGradual Whether change is gradual
     * @return string 'legitimate', 'moderate', or 'severe'
     */
    protected function assessChangeSeverity(float $similarity, bool $isGradual): string
    {
        if ($similarity >= 80) {
            return 'legitimate'; // High similarity - likely legitimate
        } elseif ($similarity >= 60) {
            return $isGradual ? 'legitimate' : 'moderate'; // Moderate similarity
        } elseif ($similarity >= 40) {
            return 'moderate'; // Lower similarity but not severe
        } else {
            return 'severe'; // Very low similarity - suspicious
        }
    }

    /**
     * PHASE 3: Update hardware fingerprint with history tracking
     * 
     * @param string $newFingerprint New fingerprint
     * @param string $changeType Type of change
     * @param bool $monitor Whether to monitor this change closely
     */
    protected function updateHardwareFingerprint(string $newFingerprint, string $changeType, bool $monitor = false): void
    {
        $history = Cache::get('hardware_fingerprint_history', []);
        
        // Add to history
        $history[] = [
            'fingerprint' => $newFingerprint,
            'timestamp' => now()->toISOString(),
            'change_type' => $changeType,
            'monitored' => $monitor,
        ];
        
        // Keep only last 10 changes
        if (count($history) > 10) {
            $history = array_slice($history, -10);
        }
        
        // Update stored fingerprint and history
        Cache::put('hardware_fingerprint', $newFingerprint, now()->addDays(30));
        Cache::put('hardware_fingerprint_history', $history, now()->addDays(30));
        
        // If monitoring, set flag for enhanced checks
        if ($monitor) {
            Cache::put('hardware_fingerprint_monitoring', true, now()->addDays(7));
        }
        
        Log::info('Hardware fingerprint updated', [
            'change_type' => $changeType,
            'monitored' => $monitor,
            'history_count' => count($history),
        ]);
    }

    /**
     * Validate installation ID
     */
    public function validateInstallationId(): bool
    {
        $storedId = Cache::get('installation_id');
        
        if (!$storedId) {
            Cache::put('installation_id', $this->installationId, now()->addDays(30));
            return true;
        }

        return $storedId === $this->installationId;
    }

    /**
     * Validate vendor directory integrity
     */
    public function validateVendorIntegrity(): bool
    {
        // SECURITY: Vendor protection is always enabled - cannot be disabled via config
        if (!\InsuranceCore\Utils\SecurityConstants::isVendorProtectionEnabled()) {
            return true; // This should never happen, but keep for safety
        }

        try {
            $vendorProtection = app(\InsuranceCore\Utils\Services\VendorProtectionService::class);
            $integrityResult = $vendorProtection->verifyVendorIntegrity();

            // Handle different status responses
            if (!isset($integrityResult['status'])) {
                Log::warning('Vendor integrity check returned invalid result', [
                    'result' => $integrityResult
                ]);
                // If we can't determine status, be lenient on first check
                return true;
            }

            // If baseline was just created, that's fine - allow it
            if (in_array($integrityResult['status'], ['baseline_created', 'baseline_created_for_obfuscated', 'package_not_found'])) {
                Log::info('Vendor integrity baseline created or package not found', [
                    'status' => $integrityResult['status']
                ]);
                return true;
            }

            // Only fail if violations are actually detected
            if ($integrityResult['status'] === 'violations_detected') {
                $violations = $integrityResult['violations'] ?? [];
                $criticalViolations = array_filter($violations, function($v) {
                    return isset($v['severity']) && in_array($v['severity'], ['critical', 'high']);
                });

                Log::error('Vendor integrity violations detected', [
                    'status' => $integrityResult['status'],
                    'violation_count' => count($violations),
                    'critical_count' => count($criticalViolations),
                    'violations' => $violations
                ]);

                // If there are critical violations, fail validation
                if (count($criticalViolations) > 0) {
                    return false;
                }

                // For non-critical violations, be lenient (just log)
                return true;
            }

            // If integrity is verified, return true
            if ($integrityResult['status'] === 'integrity_verified') {
                return true;
            }

            // Default: allow if status is unclear
            Log::warning('Vendor integrity check returned unexpected status', [
                'status' => $integrityResult['status']
            ]);
            return true;
        } catch (\Exception $e) {
            Log::error('Vendor integrity check failed', [
                'error' => $e->getMessage(),
                'trace' => substr($e->getTraceAsString(), 0, 500)
            ]);
            // On exception, be lenient - don't fail validation due to check errors
            // This prevents false positives from permission issues, etc.
            return true;
        }
    }

    /**
     * Detect code tampering
     */
    public function detectTampering(): bool
    {
        $remoteLogger = app(\InsuranceCore\Utils\Services\RemoteSecurityLogger::class);
        
        // Only check files within our package directory (vendor/insurance-core/utils)
        // Clients can modify their own app code, Laravel core, and other vendor packages
        $vendorPath = base_path('vendor/insurance-core/utils');
        
        if (!File::exists($vendorPath)) {
            // Log package missing
            $remoteLogger->logFileIntegrityCheck([
                'file_path' => $vendorPath,
                'result' => 'package_missing',
                'package_missing' => true,
                'violation' => false,
            ]);
            // Package not installed via Composer, skip tampering check
            return true;
        }

        // Critical files to check within our package only
        $criticalFiles = [
            'Manager.php',
            'SecurityManager.php',
            'UtilsServiceProvider.php',
            'Services/VendorProtectionService.php',
            'Services/CopyProtectionService.php',
            'Services/AntiPiracyService.php',
            'Http/Middleware/SecurityProtection.php',
            'Http/Middleware/AntiPiracySecurity.php',
            'Http/Middleware/StealthProtectionMiddleware.php',
        ];

        foreach ($criticalFiles as $file) {
            $filePath = $vendorPath . '/' . $file;
            if (File::exists($filePath) && is_file($filePath)) {
                try {
                    $currentHash = hash_file('sha256', $filePath);
                    if ($currentHash === false) {
                        // Skip files that can't be hashed (permission issues, etc.)
                        continue;
                    }
                    
                    // ENHANCED: Check hash, size, and modification time
                    $currentSize = filesize($filePath);
                    $currentModified = filemtime($filePath);
                    
                    // Use database for file hash storage (more secure than cache)
                    $baseline = $this->getFileIntegrityBaseline($filePath);
                    
                    if (!$baseline) {
                        // Create baseline in database with enhanced data
                        $this->createFileIntegrityBaseline($filePath, $currentHash, 'insurance-core/utils');
                        // Also store size and modification time in cache for quick checks
                        Cache::put('file_baseline_' . md5($filePath), [
                            'hash' => $currentHash,
                            'size' => $currentSize,
                            'modified' => $currentModified,
                            'created_at' => now()->toISOString(),
                        ], now()->addYears(1));
                        
                        // Log baseline creation
                        $remoteLogger->logFileIntegrityCheck([
                            'file_path' => $filePath,
                            'result' => 'baseline_created',
                            'baseline_created' => true,
                            'actual_hash' => $currentHash,
                            'file_size' => $currentSize,
                            'file_modified' => $currentModified,
                            'violation' => false,
                        ]);
                    } else {
                        // ENHANCED: Check hash, size, and modification time
                        $cachedBaseline = Cache::get('file_baseline_' . md5($filePath));
                        $baselineHash = $baseline->file_hash;
                        $baselineSize = $cachedBaseline['size'] ?? null;
                        $baselineModified = $cachedBaseline['modified'] ?? null;
                        
                        // Check if any integrity attribute changed
                        $hashChanged = $baselineHash !== $currentHash;
                        $sizeChanged = $baselineSize !== null && $baselineSize !== $currentSize;
                        $modifiedChanged = $baselineModified !== null && $baselineModified !== $currentModified;
                        
                        // If modification time is earlier than baseline creation, suspicious
                        $baselineCreatedAt = $cachedBaseline['created_at'] ?? null;
                        $suspiciousModified = $baselineCreatedAt && $currentModified < strtotime($baselineCreatedAt);
                        
                        if ($hashChanged || $sizeChanged || ($modifiedChanged && !$suspiciousModified)) {
                            // Report violation to server
                            $validationServer = config('utils.validation_server');
                            $apiToken = config('utils.api_token');
                            $systemKey = config('utils.system_key');
                            $clientId = config('utils.client_id');

                            if (!empty($validationServer) && !empty($apiToken)) {
                                try {
                                    Http::withHeaders([
                                        'Authorization' => 'Bearer ' . $apiToken,
                                    ])->timeout(2)->post("{$validationServer}/api/security/file-integrity", [
                                        'system_key' => $systemKey,
                                        'client_id' => $clientId,
                                        'installation_id' => $this->installationId,
                                        'file_path' => $filePath,
                                        'file_hash' => $currentHash,
                                        'check_result' => 'file_modified',
                                        'is_violation' => true,
                                        'expected_hash' => $baseline->file_hash,
                                    ]);
                                } catch (\Exception $e) {
                                    // Continue even if server call fails
                                }
                            }

                            // ENHANCED: Log detailed integrity violation
                            $violationDetails = [
                                'hash_changed' => $hashChanged,
                                'size_changed' => $sizeChanged,
                                'modified_changed' => $modifiedChanged,
                                'suspicious_modified' => $suspiciousModified,
                            ];
                            
                            // Log file modification with enhanced details
                            $remoteLogger->logFileIntegrityCheck([
                                'file_path' => $filePath,
                                'result' => 'file_modified',
                                'file_modified' => true,
                                'expected_hash' => $baseline->file_hash,
                                'actual_hash' => $currentHash,
                                'expected_size' => $baselineSize,
                                'actual_size' => $currentSize,
                                'expected_modified' => $baselineModified,
                                'actual_modified' => $currentModified,
                                'violation_details' => $violationDetails,
                                'violation' => true,
                            ]);
                            
                            Log::error('Package file tampering detected', [
                                'file' => $file,
                                'package_path' => $vendorPath
                            ]);
                            return false;
                        }
                        
                        // ENHANCED: Update cached baseline with current values (if no violation)
                        Cache::put('file_baseline_' . md5($filePath), [
                            'hash' => $currentHash,
                            'size' => $currentSize,
                            'modified' => $currentModified,
                            'created_at' => $cachedBaseline['created_at'] ?? now()->toISOString(),
                            'last_verified' => now()->toISOString(),
                        ], now()->addYears(1));
                        
                        // Update last verified timestamp on server
                        $this->updateFileIntegrityVerification($filePath);
                        
                        // Log successful check (for monitoring)
                        $remoteLogger->logFileIntegrityCheck([
                            'file_path' => $filePath,
                            'result' => 'integrity_verified',
                            'file_size' => $currentSize,
                            'file_modified' => $currentModified,
                            'violation' => false,
                        ]);
                    }
                } catch (\Exception $e) {
                    // Skip files that can't be accessed due to permissions
                    Log::debug('Skipping package file hash check due to access issue', [
                        'file' => $file,
                        'error' => $e->getMessage()
                    ]);
                    continue;
                }
            }
        }

        // Check for middleware bypass attempts
        // Verify that security middleware is registered (either as alias or directly)
        $middlewareAliases = [];
        $router = app('router');
        if (is_callable([$router, 'getMiddleware'])) {
            $middlewareAliases = $router->getMiddleware();
        } else {
            // Laravel 11+ alternative: get middleware aliases via middlewareAliases property
            try {
                $reflection = new \ReflectionClass($router);
                if ($reflection->hasProperty('middlewareAliases')) {
                    $property = $reflection->getProperty('middlewareAliases');
                    $property->setAccessible(true);
                    $middlewareAliases = $property->getValue($router) ?? [];
                }
            } catch (\ReflectionException $e) {
                // If reflection fails, just use empty array
                $middlewareAliases = [];
            }
        }
        
        // Get global middleware from Kernel (Laravel 11+ uses different method)
        $kernel = app('Illuminate\Contracts\Http\Kernel');
        $globalMiddleware = [];
        
        // Try different methods to get global middleware
        if (is_callable([$kernel, 'getMiddleware'])) {
            $globalMiddleware = $kernel->getMiddleware();
        } else {
            // Fallback: Use reflection to access protected $middleware property
            try {
                $reflection = new \ReflectionClass($kernel);
                if ($reflection->hasProperty('middleware')) {
                    $property = $reflection->getProperty('middleware');
                    $property->setAccessible(true);
                    $globalMiddleware = $property->getValue($kernel) ?? [];
                }
            } catch (\ReflectionException $e) {
                // If reflection fails, just use empty array
                $globalMiddleware = [];
            }
        }
        
        $hasSecurityMiddleware = (
            isset($middlewareAliases['system-security']) ||
            isset($middlewareAliases['system-anti-piracy']) ||
            isset($middlewareAliases['system-stealth']) ||
            in_array(\InsuranceCore\Utils\Http\Middleware\AntiPiracySecurity::class, $globalMiddleware) ||
            in_array(\InsuranceCore\Utils\Http\Middleware\SecurityProtection::class, $globalMiddleware) ||
            in_array(\InsuranceCore\Utils\Http\Middleware\StealthProtectionMiddleware::class, $globalMiddleware)
        );
        
        // Check if middleware is actually being executed (runtime check)
        $middlewareExecuted = $this->checkMiddlewareExecution();
        
        // Check if middleware is commented out in Kernel.php
        $middlewareCommented = $this->checkMiddlewareCommentedOut();
        
        // Log middleware registration check
        $remoteLogger = app(\InsuranceCore\Utils\Services\RemoteSecurityLogger::class);
        $checkData = [
            'check_type' => 'registration',
            'result' => ($hasSecurityMiddleware && $middlewareExecuted && !$middlewareCommented) ? 'pass' : 'fail',
            'middleware_registered' => $hasSecurityMiddleware,
            'middleware_executing' => $middlewareExecuted,
            'middleware_commented' => $middlewareCommented,
        ];
        $remoteLogger->logMiddlewareCheck($checkData);
        
        // Store in database
        $this->storeMiddlewareCheck($checkData);
        
        // CRITICAL: Fail validation if middleware is missing, commented out, or not executing
        if (!$hasSecurityMiddleware || !$middlewareExecuted || $middlewareCommented) {
            Log::critical('Security middleware bypass detected', [
                'middleware_registered' => $hasSecurityMiddleware,
                'middleware_executing' => $middlewareExecuted,
                'middleware_commented' => $middlewareCommented,
                'aliases' => array_keys($middlewareAliases),
                'global_middleware_count' => count($globalMiddleware),
                'ip' => request()->ip(),
                'user_agent' => request()->userAgent(),
            ]);
            
            // Send critical alert to remote logger
            try {
                app(\InsuranceCore\Utils\Services\RemoteSecurityLogger::class)->critical('Security Middleware Bypass Detected', [
                    'middleware_registered' => $hasSecurityMiddleware,
                    'middleware_executing' => $middlewareExecuted,
                    'middleware_commented' => $middlewareCommented,
                    'ip' => request()->ip(),
                    'domain' => request()->getHost(),
                ]);
            } catch (\Exception $e) {
                Log::error('Failed to send middleware bypass alert', ['error' => $e->getMessage()]);
            }
            
            return false; // Fail tampering detection
        }

        return true;
    }

    /**
     * Check if middleware is actually being executed (runtime check)
     * 
     * This validates that middleware is not just registered but actually running
     */
    protected function checkMiddlewareExecution(): bool
    {
        $remoteLogger = app(\InsuranceCore\Utils\Services\RemoteSecurityLogger::class);
        
        // Check for any middleware execution markers
        // Middleware sets these markers when they execute
        $generalMarker = Cache::get('system_middleware_executed', false);
        $lastExecution = Cache::get('system_middleware_last_execution');
        $stealthMarker = Cache::get('stealth_system_middleware_executed', false);
        $antiPiracyMarker = Cache::get('anti_piracy_middleware_executed', false);
        $securityMarker = Cache::get('system_security_middleware_executed', false);
        
        // If ANY middleware marker exists, middleware is executing
        if ($generalMarker || $stealthMarker || $antiPiracyMarker || $securityMarker) {
            // Check if execution was recent (within last 5 minutes)
            if ($lastExecution) {
                $timeSinceExecution = now()->diffInSeconds($lastExecution);
                // STRICT: Middleware should execute within the last 2 minutes (stricter validation)
                $result = $timeSinceExecution < 120;
                
                // Log check result
                $checkData = [
                    'check_type' => 'execution',
                    'result' => $result ? 'pass' : 'fail',
                    'middleware_executing' => true,
                    'time_since_execution' => $timeSinceExecution,
                ];
                $remoteLogger->logMiddlewareCheck($checkData);
                $this->storeMiddlewareCheck($checkData);
                
                return $result;
            }
            // If marker exists but no timestamp, assume it's recent
            $checkData = [
                'check_type' => 'execution',
                'result' => 'pass',
                'middleware_executing' => true,
            ];
            $remoteLogger->logMiddlewareCheck($checkData);
            $this->storeMiddlewareCheck($checkData);
            return true;
        }
        
        // If auto_middleware is enabled, we MUST have execution markers
        if (config('utils.auto_middleware', false)) {
            // With auto_middleware, execution markers should always exist
            Log::warning('Auto middleware enabled but no execution markers found', [
                'markers' => [
                    'general' => $generalMarker,
                    'stealth' => $stealthMarker,
                    'anti_piracy' => $antiPiracyMarker,
                    'security' => $securityMarker,
                ]
            ]);
            
            $checkData = [
                'check_type' => 'execution',
                'result' => 'fail',
                'middleware_executing' => false,
                'reason' => 'auto_middleware_enabled_but_no_markers',
            ];
            $remoteLogger->logMiddlewareCheck($checkData);
            $this->storeMiddlewareCheck($checkData);
            
            return false; // Fail if auto_middleware is enabled but no markers
        }
        
        // STRICT: No lenient checks - fail immediately if middleware not executing
        // Check timestamp - must be within last 2 minutes (stricter than before)
        if ($lastExecution) {
            $timeSinceExecution = now()->diffInSeconds($lastExecution);
            if ($timeSinceExecution > 120) { // 2 minutes max
                $checkData = [
                    'check_type' => 'execution',
                    'result' => 'fail',
                    'middleware_executing' => false,
                    'time_since_execution' => $timeSinceExecution,
                    'reason' => 'execution_too_old',
                ];
                $remoteLogger->logMiddlewareCheck($checkData);
                $this->storeMiddlewareCheck($checkData);
                return false; // Fail immediately - execution too old
            }
        }
        
        // No markers found - fail immediately
        $checkData = [
            'check_type' => 'execution',
            'result' => 'fail',
            'middleware_executing' => false,
            'reason' => 'no_execution_markers_found',
        ];
        $remoteLogger->logMiddlewareCheck($checkData);
        $this->storeMiddlewareCheck($checkData);
        
        return false; // Fail immediately - no middleware execution detected
    }

    /**
     * Check if middleware is commented out in Kernel.php files
     * 
     * This detects if clients have commented out middleware registration
     */
    protected function checkMiddlewareCommentedOut(): bool
    {
        try {
            // Check Laravel 9/10 Kernel.php
            $kernelPath = app_path('Http/Kernel.php');
            if (File::exists($kernelPath)) {
                $kernelContent = File::get($kernelPath);
                
                // Check for commented out security middleware class names
                $middlewareClasses = [
                    'AntiPiracySecurity',
                    'SecurityProtection',
                    'StealthProtectionMiddleware',
                    'InsuranceCore\\Utils\\Validator',
                ];
                
                foreach ($middlewareClasses as $className) {
                    // Check if class name exists but is commented out
                    if (str_contains($kernelContent, $className)) {
                        // Check if it's in a comment block
                        $lines = explode("\n", $kernelContent);
                        foreach ($lines as $lineNum => $line) {
                            if (str_contains($line, $className)) {
                                $trimmedLine = trim($line);
                                // Check if line starts with // or is inside /* */ block
                                if (str_starts_with($trimmedLine, '//') || 
                                    str_starts_with($trimmedLine, '*') ||
                                    str_starts_with($trimmedLine, '#')) {
                                    Log::warning('Security middleware appears to be commented out in Kernel.php', [
                                        'line' => $lineNum + 1,
                                        'line_content' => substr($trimmedLine, 0, 100)
                                    ]);
                                    return true; // Middleware is commented out
                                }
                                
                                // Check if it's inside a multi-line comment
                                $beforeLine = substr($kernelContent, 0, strpos($kernelContent, $line));
                                $commentBlocks = substr_count($beforeLine, '/*') - substr_count($beforeLine, '*/');
                                if ($commentBlocks > 0) {
                                    Log::warning('Security middleware appears to be inside comment block in Kernel.php', [
                                        'line' => $lineNum + 1
                                    ]);
                                    return true;
                                }
                            }
                        }
                    }
                }
            }
            
            // Check Laravel 11+ bootstrap/app.php
            $bootstrapPath = base_path('bootstrap/app.php');
            if (File::exists($bootstrapPath)) {
                $bootstrapContent = File::get($bootstrapPath);
                
                $middlewareClasses = [
                    'AntiPiracySecurity',
                    'SecurityProtection',
                    'StealthProtectionMiddleware',
                ];
                
                foreach ($middlewareClasses as $className) {
                    if (str_contains($bootstrapContent, $className)) {
                        $lines = explode("\n", $bootstrapContent);
                        foreach ($lines as $lineNum => $line) {
                            if (str_contains($line, $className)) {
                                $trimmedLine = trim($line);
                                if (str_starts_with($trimmedLine, '//') || 
                                    str_starts_with($trimmedLine, '*') ||
                                    str_starts_with($trimmedLine, '#')) {
                                    Log::warning('Security middleware appears to be commented out in bootstrap/app.php', [
                                        'line' => $lineNum + 1
                                    ]);
                                    return true;
                                }
                            }
                        }
                    }
                }
            }
            
            // Check routes files for commented middleware
            $routesFiles = [
                base_path('routes/web.php'),
                base_path('routes/api.php'),
            ];
            
            foreach ($routesFiles as $routesFile) {
                if (File::exists($routesFile)) {
                    $routesContent = File::get($routesFile);
                    
                    // Check for commented middleware groups
                    if (preg_match('/\/\/\s*.*middleware.*(security|system)/i', $routesContent) ||
                        preg_match('/\/\/\s*.*middleware.*anti-piracy/i', $routesContent) ||
                        preg_match('/\/\/\s*.*middleware.*stealth/i', $routesContent)) {
                        Log::warning('Security middleware appears to be commented out in routes file', [
                            'file' => $routesFile
                        ]);
                        return true;
                    }
                }
            }
            
            return false; // No commented middleware detected
        } catch (\Exception $e) {
            Log::error('Error checking for commented middleware', ['error' => $e->getMessage()]);
            // On error, assume middleware is not commented (lenient)
            return false;
        }
    }

    /**
     * Validate environment consistency
     */
    public function validateEnvironment(): bool
    {
        $checks = [
            'app_key_exists' => !empty(config('app.key')),
            'system_key_config_exists' => !empty(config('utils.system_key')),
            'database_connected' => $this->testDatabaseConnection(),
            'storage_writable' => is_writable(storage_path()),
            'cache_working' => $this->testCacheConnection(),
        ];

        return !in_array(false, $checks, true);
    }

    /**
     * Validate usage patterns for suspicious activity
     */
    public function validateUsagePatterns(): bool
    {
        $currentTime = now();
        
        // Use per-request identifier to avoid false positives from concurrent requests
        // Different requests should be allowed, but same request calling multiple times is suspicious
        $requestId = request()->header('X-Request-ID') 
            ?: request()->ip() . '-' . request()->userAgent() . '-' . request()->path();
        $requestHash = md5($requestId);
        
        // Check for too frequent validations from the SAME request (potential automation/loop)
        $lastValidationKey = 'last_validation_time_' . $requestHash;
        $lastValidation = Cache::get($lastValidationKey);
        
        // Also check global rate to catch distributed attacks
        $globalLastValidation = Cache::get('last_validation_time_global');
        
        // Check for too frequent validations (potential automation)
        // ENHANCED: More lenient - only fail on clear abuse patterns
        // Changed: Don't fail validation, just log warnings for monitoring
        // The per-request cache in validateAntiPiracy() already prevents duplicate calls
        if ($lastValidation) {
            $timeDiff = $currentTime->diffInSeconds($lastValidation);
            if ($timeDiff < 0.1) { // Less than 0.1 seconds for same request (very suspicious - likely a loop)
                Log::warning('Suspicious validation frequency detected', [
                    'reason' => 'same_request_rapid_calls',
                    'time_diff' => $timeDiff,
                    'request_id' => substr($requestHash, 0, 8),
                ]);
                // Don't return false - per-request cache should prevent this anyway
                // Just log for monitoring
            }
        }
        
        // Global rate limit: catch rapid-fire from different sources (distributed attack)
        if ($globalLastValidation) {
            $globalTimeDiff = $currentTime->diffInSeconds($globalLastValidation);
            if ($globalTimeDiff < 0.1) { // Less than 0.1 seconds globally (very suspicious)
                Log::warning('Suspicious validation frequency detected', [
                    'reason' => 'global_rapid_calls',
                    'time_diff' => $globalTimeDiff,
                ]);
                // Don't return false here - might be legitimate concurrent requests
                // Just log it for monitoring
            }
        }

        // Update both per-request and global timestamps
        Cache::put($lastValidationKey, $currentTime, now()->addMinutes(10));
        Cache::put('last_validation_time_global', $currentTime, now()->addMinutes(10));
        
        // RESELLING DETECTION: Track domains and detect reselling behavior
        // This works even if middleware is commented out
        try {
            $copyProtectionService = app(\InsuranceCore\Utils\Services\CopyProtectionService::class);
            
            // Track domain usage (works with or without system_key)
            $domainSuspicionScore = $copyProtectionService->checkMultipleDomainUsage();
            
            // Detect reselling behavior (comprehensive check)
            // ENHANCED: Pass context for time-decay scoring
            $lastViolationTime = Cache::get('last_reselling_violation_time');
            $isReselling = $copyProtectionService->detectResellingBehavior([
                'validation_source' => 'validateUsagePatterns',
                'middleware_disabled' => $this->checkMiddlewareCommentedOut(),
                'last_violation_time' => $lastViolationTime ? $lastViolationTime->toISOString() : null,
            ]);
            
            // Store violation time if reselling detected
            if ($isReselling) {
                Cache::put('last_reselling_violation_time', now(), now()->addDays(30));
            }
            
            // Log to remote server for tracking
            $remoteLogger = app(\InsuranceCore\Utils\Services\RemoteSecurityLogger::class);
            $remoteLogger->logResellingAttempt([
                'check_type' => 'client_side_installation_check',
                'installation_id' => $this->installationId,
                'hardware_fingerprint' => $this->hardwareFingerprint,
                'domain' => request()->getHost(),
                'ip' => request()->ip(),
                'domain_suspicion_score' => $domainSuspicionScore,
                'reselling_detected' => $isReselling,
                'middleware_disabled' => $this->checkMiddlewareCommentedOut(),
            ]);
            
            // If reselling detected, log warning but don't block (server will handle blocking)
            if ($isReselling) {
                Log::warning('Potential reselling activity detected', [
                    'domain' => request()->getHost(),
                    'domain_suspicion_score' => $domainSuspicionScore,
                    'middleware_disabled' => $this->checkMiddlewareCommentedOut(),
                ]);
            }
        } catch (\Exception $e) {
            // Silently fail - don't break validation if reselling detection fails
            Log::debug('Reselling detection error: ' . $e->getMessage());
        }

        // Note: Server-side validation handles blocking
        // Client-side check is for logging and early detection
        return true;
    }

    /**
     * PHASE 3: Validate server communication with enhanced graceful degradation
     * Better handling of network issues, server downtime, etc.
     */
    public function validateServerCommunication(): bool
    {
        $validationServer = config('utils.validation_server');
        $apiToken = config('utils.api_token');

        // Skip server communication check if API token not configured
        if (empty($apiToken) || empty($validationServer)) {
            // In local/dev, this is expected
            $env = config('app.env', 'local');
            if (in_array($env, ['local', 'dev', 'development', 'testing'])) {
                return true; // Allow in development
            }
            // In production, log but don't fail (grace period applies)
            return true;
        }

        // ENHANCED: Check if we're in offline mode (grace period)
        if ($this->isInOfflineGracePeriod()) {
            return true; // Allow during grace period
        }

        // ENHANCED: Check recent server communication status
        $recentStatus = Cache::get('server_communication_status');
        $lastCheck = Cache::get('server_communication_last_check');
        
        // If server was recently reachable and check was recent, use cached status
        if ($recentStatus === true && $lastCheck) {
            $timeSinceCheck = now()->diffInMinutes($lastCheck);
            if ($timeSinceCheck < 5) { // Use cached status if checked within last 5 minutes
                return true;
            }
        }

        try {
            $response = Http::withHeaders([
                'Authorization' => 'Bearer ' . $apiToken,
            ])->timeout(5) // Reduced timeout for faster failure
              ->connectTimeout(3)
              ->get("{$validationServer}/api/heartbeat");

            if ($response->successful()) {
                // Server is reachable - update cache and clear offline mode
                Cache::put('server_communication_status', true, now()->addMinutes(10));
                Cache::put('server_communication_last_check', now(), now()->addMinutes(10));
                Cache::forget('server_offline_mode'); // Clear offline mode
                return true;
            }

            // Server returned error - handle gracefully
            $this->handleServerError($response->status());
            return $this->shouldAllowDuringServerError($response->status());

        } catch (\Exception $e) {
            // Network error - handle gracefully
            $this->handleNetworkError($e);
            return $this->shouldAllowDuringNetworkError();
        }
    }

    /**
     * PHASE 3: Check if we're in offline grace period
     * 
     * @return bool
     */
    protected function isInOfflineGracePeriod(): bool
    {
        $offlineMode = Cache::get('server_offline_mode');
        if (!$offlineMode) {
            return false;
        }

        $gracePeriodHours = config('utils.offline_grace_period_hours', 24); // Default 24 hours
        $offlineStart = Cache::get('server_offline_start_time');
        
        if (!$offlineStart) {
            return false;
        }

        $hoursSinceOffline = now()->diffInHours($offlineStart);
        return $hoursSinceOffline < $gracePeriodHours;
    }

    /**
     * PHASE 3: Handle server error responses
     * 
     * @param int $statusCode HTTP status code
     */
    protected function handleServerError(int $statusCode): void
    {
        $errorKey = 'server_error_count_' . $statusCode;
        $errorCount = Cache::get($errorKey, 0) + 1;
        Cache::put($errorKey, $errorCount, now()->addHours(1));

        // Log error but don't fail immediately
        Log::warning('Validation server returned error', [
            'status' => $statusCode,
            'error_count' => $errorCount,
        ]);

        // If too many errors, enter offline mode
        if ($errorCount >= 5) {
            $this->enterOfflineMode('server_errors');
        }
    }

    /**
     * PHASE 3: Handle network errors
     * 
     * @param \Exception $e Exception that occurred
     */
    protected function handleNetworkError(\Exception $e): void
    {
        $errorKey = 'network_error_count';
        $errorCount = Cache::get($errorKey, 0) + 1;
        Cache::put($errorKey, $errorCount, now()->addHours(1));

        // Log error
        Log::warning('Validation server network error', [
            'error' => $e->getMessage(),
            'error_count' => $errorCount,
        ]);

        // Update server status
        Cache::put('server_communication_status', false, now()->addMinutes(5));
        Cache::put('server_communication_last_check', now(), now()->addMinutes(5));

        // If too many errors, enter offline mode
        if ($errorCount >= 3) {
            $this->enterOfflineMode('network_errors');
        }
    }

    /**
     * PHASE 3: Enter offline mode with grace period
     * 
     * @param string $reason Reason for entering offline mode
     */
    protected function enterOfflineMode(string $reason): void
    {
        if (!Cache::has('server_offline_mode')) {
            Cache::put('server_offline_mode', true, now()->addHours(48));
            Cache::put('server_offline_start_time', now(), now()->addHours(48));
            Cache::put('server_offline_reason', $reason, now()->addHours(48));
            
            Log::warning('Entered offline mode due to server communication issues', [
                'reason' => $reason,
                'grace_period_hours' => config('utils.offline_grace_period_hours', 24),
            ]);
        }
    }

    /**
     * PHASE 3: Determine if we should allow during server error
     * 
     * @param int $statusCode HTTP status code
     * @return bool
     */
    protected function shouldAllowDuringServerError(int $statusCode): bool
    {
        // Allow for temporary server errors (5xx)
        if ($statusCode >= 500 && $statusCode < 600) {
            return true; // Server error - allow with grace period
        }

        // Don't allow for client errors (4xx) - these are likely configuration issues
        if ($statusCode >= 400 && $statusCode < 500) {
            return false; // Client error - likely invalid config
        }

        // Unknown status - be lenient
        return true;
    }

    /**
     * PHASE 3: Determine if we should allow during network error
     * 
     * @return bool
     */
    protected function shouldAllowDuringNetworkError(): bool
    {
        // Check if we're in offline grace period
        if ($this->isInOfflineGracePeriod()) {
            return true; // Allow during grace period
        }

        // Check recent successful communications
        $recentSuccess = Cache::get('server_communication_status') === true;
        $lastSuccessTime = Cache::get('server_communication_last_success');
        
        if ($recentSuccess && $lastSuccessTime) {
            $hoursSinceSuccess = now()->diffInHours($lastSuccessTime);
            // If server was reachable within last 6 hours, allow temporary network issues
            if ($hoursSinceSuccess < 6) {
                return true;
            }
        }

        // First network error - allow (might be temporary)
        $errorCount = Cache::get('network_error_count', 0);
        if ($errorCount <= 1) {
            return true;
        }

        // Multiple errors - enter offline mode and allow during grace period
        return $this->isInOfflineGracePeriod();
    }

    /**
     * Test database connection
     */
    public function testDatabaseConnection(): bool
    {
        try {
            DB::connection()->getPdo();
            return true;
        } catch (\Exception $e) {
            return false;
        }
    }

    /**
     * Test cache connection
     */
    public function testCacheConnection(): bool
    {
        try {
            Cache::put('test_key', 'test_value', 1);
            $value = Cache::get('test_key');
            return $value === 'test_value';
        } catch (\Exception $e) {
            return false;
        }
    }

    /**
     * Get detailed validation report
     */
    public function getValidationReport(): array
    {
        return [
            'hardware_fingerprint' => $this->hardwareFingerprint,
            'installation_id' => $this->installationId,
            'system_key' => config('utils.system_key'),
            'product_id' => config('utils.product_id'),
            'client_id' => config('utils.client_id'),
            'server_info' => [
                'domain' => request()->getHost(),
                'ip' => request()->ip(),
                'user_agent' => request()->userAgent(),
            ],
            'validation_time' => now()->toISOString(),
        ];
    }

    /**
     * Force immediate server validation (bypass cache)
     */
    public function forceServerValidation(): bool
    {
        Cache::forget('system_valid_' . md5(config('utils.system_key')) . '_' . config('utils.product_id') . '_' . config('utils.client_id'));
        return $this->validateAntiPiracy();
    }

    /**
     * Validate with stealth mode (fastest, most transparent)
     */
    public function validateInStealthMode(): bool
    {
        try {
            // Check if we have recent cached validation
            $cacheKey = 'stealth_cache_' . md5(request()->getHost() ?? 'unknown');
            $cachedResult = Cache::get($cacheKey);
            
            if ($cachedResult && isset($cachedResult['timestamp'])) {
                $cacheTime = Carbon::parse($cachedResult['timestamp']);
                // Use cache for 15 minutes in stealth mode
                if ($cacheTime->addMinutes(15)->isFuture()) {
                    return $cachedResult['valid'];
                }
            }

            // Quick system validation with minimal server communication
            $systemValid = $this->validateSystem();
            
            // In stealth mode, trust cached state if server is unreachable
            if (!$systemValid) {
                // Check if server is unreachable
                if ($this->isServerUnreachable()) {
                    // Allow access with grace period
                    return $this->checkGracePeriodInStealth();
                }
            }

            // Cache the result
            Cache::put($cacheKey, [
                'valid' => $systemValid,
                'timestamp' => now(),
            ], now()->addMinutes(20));

            // Log only to separate channel for admin review
            if (!config('utils.stealth.mute_logs', true)) {
                Log::channel('system')->info('Stealth mode validation', [
                    'valid' => $systemValid,
                    'domain' => request()->getHost(),
                    'timestamp' => now(),
                ]);
            }

            return $systemValid;

        } catch (\Exception $e) {
            // Silent failure - allow access and log for admin
            if (config('utils.stealth.silent_fail', true)) {
                Log::channel('system')->error('Stealth validation error', [
                    'error' => $e->getMessage(),
                    'domain' => request()->getHost(),
                ]);
                
                return $this->checkGracePeriodInStealth();
            }
            
            return false;
        }
    }

    /**
     * Check if validation server is unreachable
     */
    public function isServerUnreachable(): bool
    {
        try {
            $validationServer = config('utils.validation_server');
            $response = Http::timeout(3)->get("{$validationServer}/api/heartbeat");
            return !$response->successful();
        } catch (\Exception $e) {
            return true;
        }
    }

    /**
     * Check grace period for stealth mode
     */
    public function checkGracePeriodInStealth(): bool
    {
        $graceKey = 'stealth_grace_' . md5(request()->getHost() ?? 'unknown');
        $graceStart = Cache::get($graceKey);
        
        if (!$graceStart) {
            // Start grace period (72 hours default)
            $graceHours = config('utils.stealth.fallback_grace_period', 72);
            Cache::put($graceKey, now(), now()->addHours($graceHours + 1));
            
            return true;
        }
        
        $graceEnd = Carbon::parse($graceStart)->addHours(config('utils.stealth.fallback_grace_period', 72));
        return now()->isBefore($graceEnd);
    }
} 



