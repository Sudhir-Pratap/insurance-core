<?php

namespace InsuranceCore\Helpers\Services;

use InsuranceCore\Helpers\ProtectionManager;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Http;
use Carbon\Carbon;

class BackgroundValidator
{
    public $protectionManager;

    public function __construct(ProtectionManager $protectionManager)
    {
        $this->protectionManager = $protectionManager;
    }

    /**
     * Validate license in background without affecting user experience
     */
    public function validateInBackground(array $context = []): bool
    {
        try {
            // Quick server health check first
            if (!$this->quickHealthCheck()) {
                return $this->handleOfflineMode($context);
            }

            // Perform validation with shorter timeout
            $timeout = config('helpers.stealth.validation_timeout', 5);
            $originalTimeout = config('helpers.validation_timeout', 15);
            
            // Temporarily reduce timeout for background validation
            config(['helpers.validation_timeout' => $timeout]);
            
            $isValid = $this->protectionManager->validateAntiPiracy();
            
            // Restore original timeout
            config(['helpers.validation_timeout' => $originalTimeout]);

            // Cache result for immediate future requests
            $this->cacheValidationResult($isValid, $context);

            // Log validation result (separate log channel for stealth)
            if (config('helpers.stealth.enabled', true)) {
                $this->logValidationResult($isValid, $context);
            }

            return $isValid;

        } catch (\Exception $e) {
            return $this->handleOfflineMode($context, $e->getMessage());
        }
    }

    /**
     * Quick health check of license server
     */
    public function quickHealthCheck(): bool
    {
        try {
            $licenseServer = config('helpers.helper_server');
            $response = Http::timeout(3)->get("{$licenseServer}/api/heartbeat");
            return $response->successful();
        } catch (\Exception $e) {
            return false;
        }
    }

    /**
     * Handle offline mode gracefully
     */
    public function handleOfflineMode(array $context, string $error = ''): bool
    {
        // Check if we're within grace period
        $gracePeriodHours = config('helpers.stealth.fallback_grace_period', 72);
        $domainKey = md5(request()->getHost() ?? 'unknown');
        $graceKey = "grace_period_{$domainKey}";

        $graceStart = Cache::get($graceKey);
        
        if (!$graceStart) {
            // Start grace period
            Cache::put($graceKey, now(), now()->addHours($gracePeriodHours + 1));
            $graceStart = now();
        }

        $graceEnd = Carbon::parse($graceStart)->addHours($gracePeriodHours);
        $isWithinGrace = now()->isBefore($graceEnd);

        if ($isWithinGrace && config('helpers.stealth.silent_fail', true)) {
            // Log grace period usage
            Log::channel('helper')->info('License server offline - grace period active', [
                'domain' => request()->getHost(),
                'grace_end' => $graceEnd->toDateTimeString(),
                'error' => $error,
                'context' => $context,
            ]);
            
            return true; // Allow access during grace period
        }

        return false;
    }

    /**
     * Cache validation result for quick access
     */
    public function cacheValidationResult(bool $isValid, array $context): void
    {
        $domainKey = md5(request()->getHost() ?? 'unknown');
        $cacheKey = "bg_validation_{$domainKey}";
        
        Cache::put($cacheKey, [
            'valid' => $isValid,
            'timestamp' => now(),
            'context' => $context,
        ], now()->addMinutes(10));
    }

    /**
     * Log validation result separately from main application logs
     */
    public function logValidationResult(bool $isValid, array $context): void
    {
        $logData = [
            'valid' => $isValid,
            'domain' => request()->getHost(),
            'timestamp' => now(),
            'context' => $context,
            'background_validation' => true,
        ];

        if ($isValid) {
            Log::channel('helper')->info('Background license validation successful', $logData);
        } else {
            Log::channel('helper')->warning('Background license validation failed', $logData);
        }
    }

    /**
     * Check cached validation result
     */
    public function getCachedValidation(): ?array
    {
        $domainKey = md5(request()->getHost() ?? 'unknown');
        $cacheKey = "bg_validation_{$domainKey}";
        
        return Cache::get($cacheKey);
    }

    /**
     * Schedule periodic validation (for job queues)
     */
    public function schedulePeriodicValidation(string $domain, string $fingerprint, string $installationId): void
    {
        try {
            // This would be called by a scheduled job
            dispatch(function () use ($domain, $fingerprint, $installationId) {
                $this->performPeriodicCheck($domain, $fingerprint, $installationId);
            })->onQueue('license-validation');
            
        } catch (\Exception $e) {
            Log::channel('helper')->error('Failed to schedule license validation', [
                'error' => $e->getMessage(),
                'domain' => $domain,
            ]);
        }
    }

    /**
     * Perform actual periodic validation check
     */
    public function performPeriodicCheck(string $domain, string $fingerprint, string $installationId): void
    {
        try {
            $licenseServer = config('helpers.helper_server');
            $apiToken = config('helpers.api_token');
            $licenseKey = config('helpers.helper_key');
            $productId = config('helpers.product_id');
            $clientId = config('helpers.client_id');

            // Create a minimal request context
            $requestData = [
                'license_key' => $licenseKey,
                'product_id' => $productId,
                'domain' => $domain,
                'ip' => request()->ip() ?? '127.0.0.1',
                'client_id' => $clientId,
                'hardware_fingerprint' => $fingerprint,
                'installation_id' => $installationId,
                // Use HELPER_SECRET for consistency, fallback to LICENSE_SECRET (deprecated), then APP_KEY
                'checksum' => hash('sha256', $licenseKey . $productId . $clientId . $fingerprint . env('HELPER_SECRET', env('LICENSE_SECRET', env('APP_KEY')))),
            ];

            $response = Http::timeout(10)
                ->withHeaders(['Authorization' => 'Bearer ' . $apiToken])
                ->post("{$licenseServer}/api/validate", $requestData);

            $logData = [
                'domain' => $domain,
                'status' => $response->status(),
                'valid' => $response->json('valid'),
                'timestamp' => now(),
                'periodic_check' => true,
            ];

            if ($response->successful() && $response->json('valid')) {
                Log::channel('helper')->info('Periodic license validation successful', $logData);
                
                // Update cache
                $this->cacheValidationResult(true, ['periodic' => true]);
            } else {
                Log::channel('helper')->warning('Periodic license validation failed', $logData);
                
                // Update cache
                $this->cacheValidationResult(false, ['periodic' => true]);
            }

        } catch (\Exception $e) {
            Log::channel('helper')->error('Periodic license validation error', [
                'domain' => $domain,
                'error' => $e->getMessage(),
                'timestamp' => now(),
            ]);
        }
    }
}




