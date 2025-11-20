<?php

namespace InsuranceCore\Helpers;

use Carbon\Carbon;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

class ProtectionManager
{
    public $helper;
    public $hardwareFingerprint;
    public $installationId;
    public $lastValidationTime;
    public $lastValidationResults = [];
    
    public function __construct(Helper $helper)
    {
        $this->helper = $helper;
        $this->hardwareFingerprint = $this->helper->generateHardwareFingerprint();
        $this->installationId = $this->getOrCreateInstallationId();
    }

    /**
     * Comprehensive protection validation with stealth mode support
     */
    public function validateAntiPiracy(): bool
    {
        // Skip validation in non-production environments (local, dev, testing)
        // Production always enforces checks
        if ($this->shouldSkipEnvironmentChecks()) {
            Log::debug('Skipping security validation - non-production environment', [
                'environment' => config('app.env'),
            ]);
            return true; // Always pass in non-production
        }
        
        // Check stealth mode configuration
        $stealthMode = config('helpers.stealth.enabled', false);
        
        if ($stealthMode) {
            return $this->validateInStealthMode();
        }

        // Standard validation layers with exception handling
        $validations = [];
        
        try {
            $validations['helper'] = $this->validateHelper();
        } catch (\Exception $e) {
            Log::error('Security validation exception', ['error' => $e->getMessage(), 'trace' => substr($e->getTraceAsString(), 0, 500)]);
            $validations['helper'] = false;
        }
        
        try {
            $validations['hardware'] = $this->validateHardwareFingerprint();
        } catch (\Exception $e) {
            Log::error('Hardware fingerprint validation exception', ['error' => $e->getMessage()]);
            $validations['hardware'] = false;
        }
        
        try {
            $validations['installation'] = $this->validateInstallationId();
        } catch (\Exception $e) {
            Log::error('Installation ID validation exception', ['error' => $e->getMessage()]);
            $validations['installation'] = false;
        }
        
        try {
            $validations['tampering'] = $this->detectTampering();
        } catch (\Exception $e) {
            Log::error('Tampering detection exception', ['error' => $e->getMessage()]);
            $validations['tampering'] = false;
        }
        
        try {
            $validations['vendor_integrity'] = $this->validateVendorIntegrity();
        } catch (\Exception $e) {
            Log::error('Vendor integrity validation exception', ['error' => $e->getMessage()]);
            $validations['vendor_integrity'] = false;
        }
        
        try {
            $validations['environment'] = $this->validateEnvironment();
        } catch (\Exception $e) {
            Log::error('Environment validation exception', ['error' => $e->getMessage()]);
            $validations['environment'] = false;
        }
        
        try {
            $validations['usage_patterns'] = $this->validateUsagePatterns();
        } catch (\Exception $e) {
            Log::error('Usage patterns validation exception', ['error' => $e->getMessage()]);
            $validations['usage_patterns'] = false;
        }
        
        try {
            $validations['server_communication'] = $this->validateServerCommunication();
        } catch (\Exception $e) {
            Log::error('Server communication validation exception', ['error' => $e->getMessage()]);
            $validations['server_communication'] = false;
        }
        
        // Store results for debugging
        $this->lastValidationResults = $validations;

        // CRITICAL: Vendor tampering - check if grace period has expired
        // This is the main security focus - no modifications to package files allowed
        // But we give 48 hours grace period to allow clients to restore files
        if (isset($validations['vendor_integrity']) && $validations['vendor_integrity'] === false) {
            // Check if any tampering has exceeded grace period
            $tamperingFiles = Cache::get('vendor_tampering_files', []);
            $gracePeriodHours = config('helpers.vendor_protection.grace_period_hours', 48);
            
            foreach ($tamperingFiles as $file => $firstDetected) {
                $gracePeriodEnds = Carbon::parse($firstDetected)->addHours($gracePeriodHours);
                if (now()->greaterThan($gracePeriodEnds)) {
                    Log::emergency('CRITICAL: Vendor package tampering - grace period expired - validation failed', [
                        'file' => $file,
                        'first_detected' => $firstDetected,
                        'grace_period_ended' => $gracePeriodEnds->toISOString(),
                    ]);
                    return false; // Fail after grace period expires
                }
            }
            
            // Still in grace period - don't fail yet, but log warning
            $firstFile = array_key_first($tamperingFiles);
            $firstDetected = $tamperingFiles[$firstFile];
            $gracePeriodEnds = Carbon::parse($firstDetected)->addHours($gracePeriodHours);
            $hoursRemaining = now()->diffInHours($gracePeriodEnds, false);
            
            Log::warning('Vendor package tampering detected - grace period active - will fail after grace period', [
                'grace_period_hours' => $gracePeriodHours,
                'hours_remaining' => $hoursRemaining,
                'grace_period_ends' => $gracePeriodEnds->toISOString(),
            ]);
        }
        
        // Anti-reselling check - use threshold score system (more flexible)
        // Don't immediately fail, but log and report - let threshold score handle it
        // This allows legitimate multi-domain setups while catching actual resellers
        if (isset($validations['usage_patterns']) && $validations['usage_patterns'] === false) {
            Log::warning('Reselling activity detected - will be evaluated by threshold score');
            // Continue validation - threshold score will determine if it's actual reselling
        }

        // Log validation results (always log failures, muted in stealth mode for successes)
        $failedValidations = array_filter($validations, function($result) { return $result === false; });
        if (!empty($failedValidations)) {
            Log::error('Protection validation failures', [
                'failed' => array_keys($failedValidations),
                'all_results' => $validations
            ]);
        } elseif (!config('helpers.stealth.mute_logs', false)) {
            Log::info('Protection validation results', $validations);
        }

        // More lenient validation - only truly critical validations must pass
        // Critical: System security validation and vendor integrity (these are non-negotiable)
        // Non-critical: Installation ID, hardware fingerprint, server communication (can change legitimately)
        $criticalValidations = [
            'helper' => $validations['helper'] ?? false,
            'vendor_integrity' => $validations['vendor_integrity'] ?? false,
        ];

        // Critical validations must pass (helper license and vendor integrity)
        $failedCritical = array_filter($criticalValidations, function($result) { return $result === false; });
        if (!empty($failedCritical)) {
            Log::error('Critical protection validation failed', [
                'failed_critical' => array_keys($failedCritical),
                'all_critical' => $criticalValidations
            ]);
            return false;
        }
        
        // Non-critical validations are warnings only (don't fail validation)
        // These can change legitimately: server migrations, hardware upgrades, network issues
        $nonCriticalValidations = [
            'installation' => $validations['installation'] ?? true,
            'hardware' => $validations['hardware'] ?? true,
            'server_communication' => $validations['server_communication'] ?? true,
            'environment' => $validations['environment'] ?? true,
        ];
        
        $failedNonCritical = array_filter($nonCriticalValidations, function($result) { return $result === false; });
        if (!empty($failedNonCritical)) {
            Log::warning('Non-critical protection validation warnings', [
                'warnings' => array_keys($failedNonCritical),
                'note' => 'These are warnings only - validation continues (legitimate changes allowed)',
            ]);
            // Don't fail - these are warnings only
        }

        // For non-critical validations, allow some failures but log them
        $nonCriticalFailures = 0;
        foreach ($validations as $key => $result) {
            if (!in_array($key, ['helper', 'installation', 'tampering']) && !$result) {
                $nonCriticalFailures++;
            }
        }

        // Allow up to 2 non-critical failures
        if ($nonCriticalFailures > 2) {
            if (!config('helpers.stealth.mute_logs', false)) {
                Log::warning('Too many non-critical validation failures', [
                    'failures' => $nonCriticalFailures,
                    'validations' => $validations
                ]);
            }
            return false;
        }

        return true;
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
        // Use the persisted hardware fingerprint from Helper
        return $this->helper->generateHardwareFingerprint();
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
     * Validate license with enhanced security
     */
    public function validateHelper(): bool
    {
        $licenseKey = config('helpers.helper_key');
        $productId = config('helpers.product_id');
        $clientId = config('helpers.client_id');
        $currentDomain = request()->getHost();
        $currentIp = request()->ip();

        		// Use the original client ID for validation (not enhanced with hardware fingerprint)
		// The hardware fingerprint is sent separately to the license server
		
		return $this->helper->validateHelper(
			$licenseKey, 
			$productId, 
			$currentDomain, 
			$currentIp, 
			$clientId
		);
    }

    /**
     * Validate hardware fingerprint hasn't changed
     */
    public function validateHardwareFingerprint(): bool
    {
        $storedFingerprint = Cache::get('hardware_fingerprint');
        
        if (!$storedFingerprint) {
            Cache::put('hardware_fingerprint', $this->hardwareFingerprint, now()->addDays(30));
            return true;
        }

        // Allow small variations (up to 20% difference)
        $similarity = similar_text($storedFingerprint, $this->hardwareFingerprint, $percent);
        
        // Lenient threshold - allow up to 50% difference for legitimate server migrations/upgrades
        // This prevents false positives when clients move servers or upgrade hardware
        $threshold = config('helpers.anti_reselling.lenient_mode', true) ? 50 : 70;
        if ($percent < $threshold) {
            Log::warning('Hardware fingerprint changed significantly', [
                'stored' => $storedFingerprint,
                'current' => $this->hardwareFingerprint,
                'similarity' => $percent,
                'threshold' => $threshold
            ]);
            
            // If this is a significant change, update the stored fingerprint
            // This allows for legitimate hardware changes (server migration, etc.)
            // Even more lenient: allow 30% similarity for major but legitimate changes
            if ($percent > 30) { // Reduced from 50 to 30 for more flexibility
                Log::info('Updating hardware fingerprint due to significant but acceptable change', [
                    'old_similarity' => $percent,
                    'new_fingerprint' => $this->hardwareFingerprint
                ]);
                Cache::put('hardware_fingerprint', $this->hardwareFingerprint, now()->addDays(30));
                return true;
            }
            
            return false;
        }

        return true;
    }

    /**
     * Validate installation ID
     * More lenient: allows installation ID changes (server migrations, fresh installs)
     * Only logs warning instead of failing
     */
    public function validateInstallationId(): bool
    {
        $storedId = Cache::get('installation_id');
        
        if (!$storedId) {
            Cache::put('installation_id', $this->installationId, now()->addDays(30));
            return true;
        }

        if ($storedId !== $this->installationId) {
            // Installation ID changed - could be legitimate (server migration, fresh install)
            // Don't fail, but log warning for monitoring
            Log::warning('Installation ID changed', [
                'stored_id' => $storedId,
                'current_id' => $this->installationId,
                'note' => 'This may be legitimate (server migration, fresh install)',
            ]);
            
            // Update stored ID to new one (allow the change)
            Cache::put('installation_id', $this->installationId, now()->addDays(30));
            return true; // Don't fail - allow installation ID changes
        }

        return true;
    }

    /**
     * Validate vendor directory integrity
     */
    public function validateVendorIntegrity(): bool
    {
        if (!config('helpers.vendor_protection.enabled', true)) {
            return true; // Skip if disabled
        }

        try {
            $vendorProtection = app(\InsuranceCore\Helpers\Services\VendorProtectionService::class);
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
        // Only check files within our package directory (vendor/insurance-core/helpers)
        // Clients can modify their own app code, Laravel core, and other vendor packages
        $vendorPath = base_path('vendor/insurance-core/helpers');
        
        if (!File::exists($vendorPath)) {
            // Package not installed via Composer, skip tampering check
            return true;
        }

        // Critical files to check within our package only
        $criticalFiles = [
            'Helper.php',
            'ProtectionManager.php',
            'HelperServiceProvider.php',
            'Services/VendorProtectionService.php',
            'Services/CopyProtectionService.php',
            'Services/AntiPiracyService.php',
            'Http/Middleware/SecurityProtection.php',
            'Http/Middleware/AntiPiracySecurity.php',
            'Http/Middleware/StealthProtectionMiddleware.php',
            'config/helpers.php',
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
                    
                    // Use package-specific cache key
                    $cacheKey = "helper_package_file_hash_{$file}";
                    $storedHash = Cache::get($cacheKey);
                    
                    if (!$storedHash) {
                        Cache::put($cacheKey, $currentHash, now()->addDays(30));
                    } elseif ($storedHash === $currentHash) {
                        // File hash matches - clear any tampering tracking if it exists
                        $tamperingKey = 'vendor_tampering_' . md5($file);
                        if (Cache::has($tamperingKey)) {
                            Cache::forget($tamperingKey);
                            
                            // Remove from tampered files list
                            $tamperedFiles = Cache::get('vendor_tampering_files', []);
                            if (isset($tamperedFiles[$file])) {
                                unset($tamperedFiles[$file]);
                                Cache::put('vendor_tampering_files', $tamperedFiles, now()->addHours(49));
                                
                                Log::info('Vendor package file restored - tampering tracking cleared', [
                                    'file' => $file,
                                ]);
                            }
                        }
                    } elseif ($storedHash !== $currentHash) {
                        // CRITICAL: File was modified - but give grace period (default 48 hours)
                        $gracePeriodHours = config('helpers.vendor_protection.grace_period_hours', 48);
                        $tamperingKey = 'vendor_tampering_' . md5($file);
                        $firstDetected = Cache::get($tamperingKey);
                        
                        if (!$firstDetected) {
                            // First time detected - start grace period
                            $firstDetected = now()->toISOString();
                            Cache::put($tamperingKey, $firstDetected, now()->addHours($gracePeriodHours + 1));
                            
                            // Track all tampered files
                            $tamperedFiles = Cache::get('vendor_tampering_files', []);
                            $tamperedFiles[$file] = $firstDetected;
                            Cache::put('vendor_tampering_files', $tamperedFiles, now()->addHours($gracePeriodHours + 1));
                            
                            $gracePeriodEnds = Carbon::parse($firstDetected)->addHours($gracePeriodHours);
                            
                            Log::emergency('CRITICAL: Vendor package file tampering detected - grace period started', [
                                'file' => $file,
                                'package_path' => $vendorPath,
                                'stored_hash' => substr($storedHash, 0, 16) . '...',
                                'current_hash' => substr($currentHash, 0, 16) . '...',
                                'grace_period_hours' => $gracePeriodHours,
                                'grace_period_ends' => $gracePeriodEnds->toISOString(),
                                'action' => 'grace_period_started',
                            ]);
                            
                            // Report to license server immediately
                            try {
                                app(\InsuranceCore\Helpers\Services\RemoteSecurityLogger::class)->critical('Vendor File Tampering - Package Modified - Grace Period Started', [
                                    'file' => $file,
                                    'package_path' => $vendorPath,
                                    'grace_period_hours' => $gracePeriodHours,
                                    'grace_period_ends' => $gracePeriodEnds->toISOString(),
                                ]);
                            } catch (\Exception $e) {
                                // Continue even if reporting fails
                            }
                        } else {
                            // Check if grace period has expired
                            $gracePeriodEnds = Carbon::parse($firstDetected)->addHours($gracePeriodHours);
                            $hoursRemaining = now()->diffInHours($gracePeriodEnds, false);
                            
                            if ($hoursRemaining <= 0) {
                                // Grace period expired - fail validation
                                Log::emergency('CRITICAL: Vendor package file tampering - grace period expired - validation failed', [
                                    'file' => $file,
                                    'package_path' => $vendorPath,
                                    'first_detected' => $firstDetected,
                                    'grace_period_ended' => $gracePeriodEnds->toISOString(),
                                    'action' => 'validation_failed',
                                ]);
                                
                                // Report to license server
                                try {
                                    app(\InsuranceCore\Helpers\Services\RemoteSecurityLogger::class)->critical('Vendor File Tampering - Grace Period Expired - Validation Failed', [
                                        'file' => $file,
                                        'package_path' => $vendorPath,
                                        'first_detected' => $firstDetected,
                                    ]);
                                } catch (\Exception $e) {
                                    // Continue even if reporting fails
                                }
                                
                                return false; // Fail after grace period
                            } else {
                                // Still in grace period - warn but don't fail
                                Log::warning('Vendor package file tampering detected - grace period active', [
                                    'file' => $file,
                                    'package_path' => $vendorPath,
                                    'hours_remaining' => $hoursRemaining,
                                    'grace_period_ends' => $gracePeriodEnds->toISOString(),
                                    'action' => 'grace_period_active',
                                ]);
                            }
                        }
                    }
                } catch (\Exception $e) {
                    // Skip files that can't be accessed due to permissions
                    Log::debug('Skipping license package file hash check due to access issue', [
                        'file' => $file,
                        'error' => $e->getMessage()
                    ]);
                    continue;
                }
            }
        }

        // Check for security middleware bypass attempts
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
        
        $hasLicenseMiddleware = (
            isset($middlewareAliases['helper-security']) ||
            isset($middlewareAliases['helper-anti-piracy']) ||
            isset($middlewareAliases['helper-stealth']) ||
            in_array(\InsuranceCore\Helpers\Http\Middleware\AntiPiracySecurity::class, $globalMiddleware) ||
            in_array(\InsuranceCore\Helpers\Http\Middleware\SecurityProtection::class, $globalMiddleware) ||
            in_array(\InsuranceCore\Helpers\Http\Middleware\StealthProtectionMiddleware::class, $globalMiddleware)
        );
        
        // Check if middleware is actually being executed (runtime check)
        $middlewareExecuted = $this->checkMiddlewareExecution();
        
        // Check if middleware is commented out in Kernel.php
        $middlewareCommented = $this->checkMiddlewareCommentedOut();
        
        // CRITICAL: Fail validation if middleware is missing, commented out, or not executing
        if (!$hasLicenseMiddleware || !$middlewareExecuted || $middlewareCommented) {
            Log::critical('Security middleware bypass detected', [
                'middleware_registered' => $hasLicenseMiddleware,
                'middleware_executing' => $middlewareExecuted,
                'middleware_commented' => $middlewareCommented,
                'aliases' => array_keys($middlewareAliases),
                'global_middleware_count' => count($globalMiddleware),
                'ip' => request()->ip(),
                'user_agent' => request()->userAgent(),
            ]);
            
            // Send critical alert to remote logger
            try {
                app(\InsuranceCore\Helpers\Services\RemoteSecurityLogger::class)->critical('Security Middleware Bypass Detected', [
                    'middleware_registered' => $hasLicenseMiddleware,
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
        // Check for any middleware execution markers
        // Middleware sets these markers when they execute
        $generalMarker = Cache::get('helper_middleware_executed', false);
        $lastExecution = Cache::get('helper_middleware_last_execution');
        $stealthMarker = Cache::get('stealth_helper_middleware_executed', false);
        $antiPiracyMarker = Cache::get('anti_piracy_middleware_executed', false);
        $securityMarker = Cache::get('helper_security_middleware_executed', false);
        
        // If ANY middleware marker exists, middleware is executing
        if ($generalMarker || $stealthMarker || $antiPiracyMarker || $securityMarker) {
            // Check if execution was recent (within last 5 minutes)
            if ($lastExecution) {
                $timeSinceExecution = now()->diffInSeconds($lastExecution);
                // Middleware should execute within the last 5 minutes (allowing for slow requests)
                return $timeSinceExecution < 300;
            }
            // If marker exists but no timestamp, assume it's recent
            return true;
        }
        
        // If auto_middleware is enabled, we MUST have execution markers
        if (config('helpers.auto_middleware', false)) {
            // With auto_middleware, execution markers should always exist
            Log::warning('Auto middleware enabled but no execution markers found', [
                'markers' => [
                    'general' => $generalMarker,
                    'stealth' => $stealthMarker,
                    'anti_piracy' => $antiPiracyMarker,
                    'security' => $securityMarker,
                ]
            ]);
            return false; // Fail if auto_middleware is enabled but no markers
        }
        
        // If no markers exist and we're checking, assume middleware might not be executing
        // But be lenient on first check (middleware might not have run yet)
        $checkCount = Cache::get('middleware_execution_check_count', 0);
        Cache::put('middleware_execution_check_count', $checkCount + 1, now()->addMinutes(10));
        
        // Allow 3 checks before failing (to account for cold start)
        if ($checkCount < 3) {
            return true; // Lenient on first few checks
        }
        
        // After 3 checks, require execution markers
        return false;
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
                    'InsuranceCore\\Validator',
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
                    if (preg_match('/\/\/\s*.*middleware.*license/i', $routesContent) ||
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
            'license_config_exists' => !empty(config('helpers.helper_key')),
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
        $lastValidation = Cache::get('last_validation_time');
        
        // Check for too frequent validations (potential automation)
        // More lenient: only flag if extremely frequent (less than 1 second)
        if ($lastValidation) {
            $timeDiff = $currentTime->diffInSeconds($lastValidation);
            if ($timeDiff < 1) { // Less than 1 second between validations (was 5 seconds)
                Log::warning('Suspicious validation frequency detected', [
                    'time_diff' => $timeDiff,
                    'note' => 'Very frequent validations - may be legitimate (load balancer, etc.)',
                ]);
                // Don't fail - just log warning
                return true; // Allow frequent validations - may be legitimate
            }
        }

        Cache::put('last_validation_time', $currentTime, now()->addMinutes(10));
        
        // Check for multiple installations with same license
        $activeInstallations = Cache::get('active_helpers_' . md5(config('helpers.helper_key')), []);
        $currentInstallation = $this->installationId;
        
        if (!in_array($currentInstallation, $activeInstallations)) {
            $activeInstallations[] = $currentInstallation;
            Cache::put('active_helpers_' . md5(config('helpers.helper_key')), $activeInstallations, now()->addHours(1));
        }

        // Allow maximum 3 installations per license (more lenient - allows staging + production + dev)
        $maxInstallations = config('helpers.anti_reselling.max_installations', 3);
        if (count($activeInstallations) > $maxInstallations) {
            Log::warning('Multiple installations detected for same license', [
                'count' => count($activeInstallations),
                'max_allowed' => $maxInstallations,
                'note' => 'This may be legitimate (staging, production, dev environments)',
            ]);
            // Don't fail - use threshold score system instead
            return true; // Allow multiple installations - let threshold score handle reselling detection
        }

        return true;
    }

    /**
     * Validate server communication
     * More lenient: server communication failures don't fail validation
     * Network issues, server downtime, etc. are legitimate reasons for failures
     */
    public function validateServerCommunication(): bool
    {
        $licenseServer = config('helpers.helper_server');
        $apiToken = config('helpers.api_token');

        try {
            $response = Http::withHeaders([
                'Authorization' => 'Bearer ' . $apiToken,
            ])->timeout(5)->get("{$licenseServer}/api/heartbeat"); // Reduced timeout to 5 seconds

            if (!$response->successful()) {
                // Server communication failed - but don't fail validation
                // Network issues, server downtime are legitimate
                Log::warning('Server communication failed (non-critical)', [
                    'status' => $response->status(),
                    'body' => substr($response->body(), 0, 100),
                    'note' => 'This is a warning only - validation continues',
                ]);
                return true; // Don't fail - allow network/server issues
            }

            return true;
        } catch (\Exception $e) {
            // Server unreachable - but don't fail validation
            // Network issues, server downtime are legitimate
            Log::warning('Server communication error (non-critical): ' . $e->getMessage(), [
                'note' => 'This is a warning only - validation continues',
            ]);
            return true; // Don't fail - allow network/server issues
        }
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
            'license_key' => config('helpers.helper_key'),
            'product_id' => config('helpers.product_id'),
            'client_id' => config('helpers.client_id'),
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
        Cache::forget('helper_valid_' . md5(config('helpers.helper_key')) . '_' . config('helpers.product_id') . '_' . config('helpers.client_id'));
        return $this->validateAntiPiracy();
    }

    /**
     * Validate with stealth mode (fastest, most transparent)
     */
    public function validateInStealthMode(): bool
    {
        // Initialize validation results for stealth mode
        $validations = [];
        
        try {
            // Check if we have recent cached validation
            $cacheKey = 'stealth_cache_' . md5(request()->getHost() ?? 'unknown');
            $cachedResult = Cache::get($cacheKey);
            
            if ($cachedResult && isset($cachedResult['timestamp'])) {
                $cacheTime = Carbon::parse($cachedResult['timestamp']);
                // Use cache for 15 minutes in stealth mode
                if ($cacheTime->addMinutes(15)->isFuture()) {
                    // Store cached result in validation results
                    $validations['helper'] = $cachedResult['valid'];
                    $validations['stealth_cached'] = true;
                    $this->lastValidationResults = $validations;
                    return $cachedResult['valid'];
                }
            }

            // Quick security validation with minimal server communication
            $licenseValid = $this->validateHelper();
            $validations['helper'] = $licenseValid;
            
            // In stealth mode, trust cached state if server is unreachable
            if (!$licenseValid) {
                // Check if server is unreachable
                if ($this->isServerUnreachable()) {
                    // Allow access with grace period
                    $gracePeriodValid = $this->checkGracePeriodInStealth();
                    $validations['helper'] = $gracePeriodValid;
                    $validations['grace_period'] = $gracePeriodValid;
                    $this->lastValidationResults = $validations;
                    return $gracePeriodValid;
                }
            }

            // Store validation results
            $this->lastValidationResults = $validations;
            
            // Cache the result
            Cache::put($cacheKey, [
                'valid' => $licenseValid,
                'timestamp' => now(),
            ], now()->addMinutes(20));

            // Don't log to separate files - use remote logging only to avoid exposing package
            // Separate log files in storage/logs/ are accessible to clients

            return $licenseValid;

        } catch (\Exception $e) {
            // Store exception in validation results
            $validations['helper'] = false;
            $validations['exception'] = $e->getMessage();
            $this->lastValidationResults = $validations;
            
            // Silent failure - only remote logging, no local files to avoid exposure
            // Local log files can be accessed by clients
            
            return $this->checkGracePeriodInStealth();
        }
    }
    
    /**
     * Check if validation should be skipped based on environment
     * Simple automatic detection: Only enforce in production
     * Local/dev/testing automatically skip (no config needed)
     */
    protected function shouldSkipEnvironmentChecks(): bool
    {
        $environment = strtolower(config('app.env', 'production'));
        
        // Only enforce in production - all other environments skip automatically
        // This is automatic - no configuration needed
        if ($environment === 'production') {
            return false; // Enforce checks in production
        }
        
        // Skip in all non-production environments (local, dev, testing, staging, etc.)
        return true; // Skip checks in non-production
    }
    
    /**
     * Check if license server is unreachable
     */
    public function isServerUnreachable(): bool
    {
        try {
            $licenseServer = config('helpers.helper_server');
            $response = Http::timeout(3)->get("{$licenseServer}/api/heartbeat");
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
            $graceHours = config('helpers.stealth.fallback_grace_period', 72);
            Cache::put($graceKey, now(), now()->addHours($graceHours + 1));
            
            return true;
        }
        
        $graceEnd = Carbon::parse($graceStart)->addHours(config('helpers.stealth.fallback_grace_period', 72));
        return now()->isBefore($graceEnd);
    }
} 



