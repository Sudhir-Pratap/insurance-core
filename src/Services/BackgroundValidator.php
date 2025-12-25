<?php

namespace InsuranceCore\Utils\Services;

use InsuranceCore\Utils\SecurityManager;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Http;
use Carbon\Carbon;

class BackgroundValidator
{
    public $protectionManager;

    public function __construct(SecurityManager $protectionManager)
    {
        $this->protectionManager = $protectionManager;
    }

    /**
     * Validate system key in background without affecting user experience
     */
    public function validateInBackground(array $context = []): bool
    {
        try {
            // Quick server health check first
            if (!$this->quickHealthCheck()) {
                return $this->handleOfflineMode($context);
            }

            // Perform validation with shorter timeout
            $timeout = config('utils.stealth.validation_timeout', 5);
            $originalTimeout = config('utils.validation.timeout', 15);
            
            // Temporarily reduce timeout for background validation
            config(['utils.validation.timeout' => $timeout]);
            
            $isValid = $this->protectionManager->validateAntiPiracy();
            
            // Restore original timeout
            config(['utils.validation.timeout' => $originalTimeout]);

            // Cache result for immediate future requests
            $this->cacheValidationResult($isValid, $context);

            // Log validation result (separate log channel for stealth)
            if (config('utils.stealth.enabled', true)) {
                $this->logValidationResult($isValid, $context);
            }

            return $isValid;

        } catch (\Exception $e) {
            return $this->handleOfflineMode($context, $e->getMessage());
        }
    }

    /**
     * Quick health check of validation server
     */
    public function quickHealthCheck(): bool
    {
        try {
            $validationServer = config('utils.validation_server');
            $response = Http::timeout(3)->get("{$validationServer}/api/heartbeat");
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
        $gracePeriodHours = config('utils.stealth.fallback_grace_period', 72);
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

        if ($isWithinGrace && config('utils.stealth.silent_fail', true)) {
            // Log grace period usage
            Log::channel('system')->info('Validation server offline - grace period active', [
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
            Log::channel('system')->info('Background system validation successful', $logData);
        } else {
            Log::channel('system')->warning('Background system validation failed', $logData);
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
            })->onQueue('system-validation');
            
        } catch (\Exception $e) {
            Log::channel('system')->error('Failed to schedule system validation', [
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
            $validationServer = config('utils.validation_server');
            $apiToken = config('utils.api_token');
            $systemKey = config('utils.system_key');
            $productId = config('utils.product_id');
            $clientId = config('utils.client_id');

            // Create a minimal request context
            $requestData = [
                'system_key' => $systemKey,
                'product_id' => $productId,
                'domain' => $domain,
                'ip' => request()->ip() ?? '127.0.0.1',
                'client_id' => $clientId,
                'hardware_fingerprint' => $fingerprint,
                'installation_id' => $installationId,
                'checksum' => hash('sha256', $systemKey . $productId . $clientId . $fingerprint . env('UTILS_SECRET', env('APP_KEY'))),
            ];

            $response = Http::timeout(10)
                ->withHeaders(['Authorization' => 'Bearer ' . $apiToken])
                ->post("{$validationServer}/api/validate", $requestData);

            $logData = [
                'domain' => $domain,
                'status' => $response->status(),
                'valid' => $response->json('valid'),
                'timestamp' => now(),
                'periodic_check' => true,
            ];

            if ($response->successful() && $response->json('valid')) {
                Log::channel('system')->info('Periodic system validation successful', $logData);
                
                // Update cache
                $this->cacheValidationResult(true, ['periodic' => true]);
            } else {
                Log::channel('system')->warning('Periodic system validation failed', $logData);
                
                // Update cache
                $this->cacheValidationResult(false, ['periodic' => true]);
            }

        } catch (\Exception $e) {
            Log::channel('system')->error('Periodic system validation error', [
                'domain' => $domain,
                'error' => $e->getMessage(),
                'timestamp' => now(),
            ]);
        }
    }
}




