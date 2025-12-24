<?php

namespace Acme\Utils;

use Carbon\Carbon;
use Illuminate\Support\Facades\Cache;
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
        // Check stealth mode configuration
        $stealthMode = config('utils.stealth.enabled', false);
        
        if ($stealthMode) {
            return $this->validateInStealthMode();
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
            return false;
        }

        // For non-critical validations, allow some failures but log them
        $nonCriticalFailures = 0;
        foreach ($validations as $key => $result) {
            if (!in_array($key, ['system', 'installation', 'tampering']) && !$result) {
                $nonCriticalFailures++;
            }
        }

        // Allow up to 2 non-critical failures
        if ($nonCriticalFailures > 2) {
            if (!config('utils.stealth.mute_logs', false)) {
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
     * Validate hardware fingerprint hasn't changed
     */
    public function validateHardwareFingerprint(): bool
    {
        $remoteLogger = app(\Acme\Utils\Services\RemoteSecurityLogger::class);
        
        $storedFingerprint = Cache::get('hardware_fingerprint');
        
        if (!$storedFingerprint) {
            Cache::put('hardware_fingerprint', $this->hardwareFingerprint, now()->addDays(30));
            return true;
        }

        // Allow small variations (up to 20% difference)
        $similarity = similar_text($storedFingerprint, $this->hardwareFingerprint, $percent);
        
        // More lenient threshold - allow up to 30% difference instead of 80%
        if ($percent < 70) {
            // Log hardware fingerprint change
            $remoteLogger->logResellingAttempt([
                'check_type' => 'hardware_fingerprint_change',
                'hardware_fingerprint_changed' => true,
                'similarity_percent' => $percent,
            ]);
            
            Log::warning('Hardware fingerprint changed significantly', [
                'stored' => $storedFingerprint,
                'current' => $this->hardwareFingerprint,
                'similarity' => $percent
            ]);
            
            // If this is a significant change, update the stored fingerprint
            // This allows for legitimate hardware changes (server migration, etc.)
            if ($percent > 50) { // Still reasonable similarity
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
        if (!config('utils.vendor_protection.enabled', true)) {
            return true; // Skip if disabled
        }

        try {
            $vendorProtection = app(\Acme\Utils\Services\VendorProtectionService::class);
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
        $remoteLogger = app(\Acme\Utils\Services\RemoteSecurityLogger::class);
        
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
            'ProtectionManager.php',
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
                    
                    // Use database for file hash storage (more secure than cache)
                    $baseline = $this->getFileIntegrityBaseline($filePath);
                    
                    if (!$baseline) {
                        // Create baseline in database
                        $this->createFileIntegrityBaseline($filePath, $currentHash, 'insurance-core/utils');
                        
                        // Log baseline creation
                        $remoteLogger->logFileIntegrityCheck([
                            'file_path' => $filePath,
                            'result' => 'baseline_created',
                            'baseline_created' => true,
                            'actual_hash' => $currentHash,
                            'violation' => false,
                        ]);
                    } elseif ($baseline->file_hash !== $currentHash) {
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

                        // Log file modification
                        $remoteLogger->logFileIntegrityCheck([
                            'file_path' => $filePath,
                            'result' => 'file_modified',
                            'file_modified' => true,
                            'expected_hash' => $baseline->file_hash,
                            'actual_hash' => $currentHash,
                            'violation' => true,
                        ]);
                        
                        Log::error('Package file tampering detected', [
                            'file' => $file,
                            'package_path' => $vendorPath
                        ]);
                        return false;
                    } else {
                        // Update last verified timestamp on server
                        $this->updateFileIntegrityVerification($filePath);
                        
                        // Log successful check (for monitoring)
                        $remoteLogger->logFileIntegrityCheck([
                            'file_path' => $filePath,
                            'result' => 'integrity_verified',
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
            in_array(\Acme\Utils\Http\Middleware\AntiPiracySecurity::class, $globalMiddleware) ||
            in_array(\Acme\Utils\Http\Middleware\SecurityProtection::class, $globalMiddleware) ||
            in_array(\Acme\Utils\Http\Middleware\StealthProtectionMiddleware::class, $globalMiddleware)
        );
        
        // Check if middleware is actually being executed (runtime check)
        $middlewareExecuted = $this->checkMiddlewareExecution();
        
        // Check if middleware is commented out in Kernel.php
        $middlewareCommented = $this->checkMiddlewareCommentedOut();
        
        // Log middleware registration check
        $remoteLogger = app(\Acme\Utils\Services\RemoteSecurityLogger::class);
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
                app(\Acme\Utils\Services\RemoteSecurityLogger::class)->critical('Security Middleware Bypass Detected', [
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
        $remoteLogger = app(\Acme\Utils\Services\RemoteSecurityLogger::class);
        
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
                    'Acme\\Utils\\Validator',
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
        $lastValidation = Cache::get('last_validation_time');
        
        // Check for too frequent validations (potential automation)
        if ($lastValidation) {
            $timeDiff = $currentTime->diffInSeconds($lastValidation);
            if ($timeDiff < 5) { // Less than 5 seconds between validations
                Log::warning('Suspicious validation frequency detected');
                return false;
            }
        }

        Cache::put('last_validation_time', $currentTime, now()->addMinutes(10));
        
        // RESELLING DETECTION: Log to server for tracking
        // Server-side validation is the authority - client just logs
        $remoteLogger = app(\Acme\Utils\Services\RemoteSecurityLogger::class);
        $remoteLogger->logResellingAttempt([
            'check_type' => 'client_side_installation_check',
            'installation_id' => $this->installationId,
            'hardware_fingerprint' => $this->hardwareFingerprint,
            'domain' => request()->getHost(),
            'ip' => request()->ip(),
        ]);

        // Note: Server-side validation handles blocking
        // Client-side check is just for logging - server will block reselling
        return true;
    }

    /**
     * Validate server communication
     */
    public function validateServerCommunication(): bool
    {
        $validationServer = config('utils.validation_server');
        $apiToken = config('utils.api_token');

        try {
            $response = Http::withHeaders([
                'Authorization' => 'Bearer ' . $apiToken,
            ])->timeout(10)->get("{$validationServer}/api/heartbeat");

            if (!$response->successful()) {
                Log::error('Validation server communication failed', [
                    'status' => $response->status(),
                    'body' => $response->body()
                ]);
                return false;
            }

            return true;
        } catch (\Exception $e) {
            Log::error('Validation server communication error: ' . $e->getMessage());
            return false;
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



