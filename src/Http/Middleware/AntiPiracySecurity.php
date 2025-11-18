<?php

namespace InsuranceCore\Helpers\Http\Middleware;

use InsuranceCore\Helpers\ProtectionManager;
use InsuranceCore\Helpers\Http\Middleware\MiddlewareHelper;
use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Cache;

class AntiPiracySecurity
{
    protected $antiPiracyManager;

    public function __construct()
    {
        // Don't inject dependencies in constructor to avoid circular dependencies
        // We'll resolve them in the handle method
    }

    protected function getAntiPiracyManager()
    {
        if (!$this->antiPiracyManager) {
            $this->antiPiracyManager = app(ProtectionManager::class);
        }
        return $this->antiPiracyManager;
    }

    public function handle(Request $request, Closure $next)
    {
        // Mark middleware execution for tampering detection
        Cache::put('helper_middleware_executed', true, now()->addMinutes(5));
        Cache::put('helper_middleware_last_execution', now(), now()->addMinutes(5));
        Cache::put('anti_piracy_middleware_executed', true, now()->addMinutes(5));
        
        // Skip validation for certain routes (if needed)
        if ($this->shouldSkipValidation($request)) {
            return $next($request);
        }

        // Check if we're in maintenance mode or have a bypass
        if ($this->hasBypass($request)) {
            return $next($request);
        }

        // Perform comprehensive protection validation
        try {
            $isValid = $this->getAntiPiracyManager()->validateAntiPiracy();
            if (!$isValid) {
                $this->handleValidationFailure($request);
                return $this->getFailureResponse($request);
            }
        } catch (\Exception $e) {
            // Log the exception and treat as validation failure
            Log::error('Protection validation exception in middleware', [
                'error' => $e->getMessage(),
                'trace' => substr($e->getTraceAsString(), 0, 1000),
                'ip' => $request->ip(),
                'domain' => $request->getHost(),
            ]);
            $this->handleValidationFailure($request);
            return $this->getFailureResponse($request);
        }

        // Log successful validation (for monitoring)
        $this->logSuccessfulValidation($request);

        return $next($request);
    }

    /**
     * Check if validation should be skipped for this request
     */
    public function shouldSkipValidation(Request $request): bool
    {
        $skipRoutes = config('helpers.skip_routes', []);
        $path = $request->path();

        // Skip specific routes
        foreach ($skipRoutes as $route) {
            $cleanRoute = trim($route, '/');
            if (str_starts_with($path, $cleanRoute)) {
                return true;
            }
        }

        // Skip file extensions (assets, images, etc.)
        $skipExtensions = ['.css', '.js', '.png', '.jpg', '.gif', '.ico', '.svg', '.woff', '.woff2'];
        foreach ($skipExtensions as $ext) {
            if (str_ends_with($path, $ext)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check for bypass conditions (development, testing, etc.)
     */
    public function hasBypass(Request $request): bool
    {
        // Allow bypass in local environment (unless explicitly disabled for testing)
        if (app()->environment('local') && !config('helpers.disable_local_bypass', false)) {
            return true;
        }

        // Check for bypass token (for emergency access)
        $bypassToken = config('helpers.bypass_token');
        if ($bypassToken && $request->header('X-Helper-Bypass') === $bypassToken) {
            Log::warning('Helper bypass used', [
                'ip' => $request->ip(),
                'user_agent' => $request->userAgent(),
            ]);
            return true;
        }

        return false;
    }

    /**
     * Handle validation failure
     */
    public function handleValidationFailure(Request $request): void
    {
        try {
            $report = $this->getAntiPiracyManager()->getValidationReport();
        } catch (\Exception $e) {
            $report = ['error' => 'Failed to get validation report: ' . $e->getMessage()];
        }
        
        // Get detailed validation results from AntiPiracyManager
        $validationResults = [];
        try {
            $validationResults = $this->getAntiPiracyManager()->getLastValidationResults();
        } catch (\Exception $e) {
            Log::warning('Failed to get validation results', ['error' => $e->getMessage()]);
        }
        
        $failedChecks = [];
        if (is_array($validationResults) && !empty($validationResults)) {
            $failedChecks = array_keys(array_filter($validationResults, function($result) { return $result === false; }));
        } else {
            // If results are empty, log a warning
            Log::warning('Validation results are empty - this may indicate an exception during validation', [
                'results_type' => gettype($validationResults),
                'results_count' => is_array($validationResults) ? count($validationResults) : 0
            ]);
        }
        
        Log::error('Protection validation failed', [
            'ip' => $request->ip(),
            'user_agent' => $request->userAgent(),
            'path' => $request->path(),
            'method' => $request->method(),
            'domain' => $request->getHost(),
            'failed_checks' => $failedChecks,
            'validation_results' => $validationResults ?? 'not_available',
            'all_validation_results' => $validationResults, // Always include full results
            'report' => $report,
        ]);
        
        // Also send to remote security logger
        if (!empty($failedChecks)) {
            app(\InsuranceCore\Helpers\Services\RemoteSecurityLogger::class)->error('Protection validation failed', [
                'failed_checks' => $failedChecks,
                'domain' => $request->getHost(),
                'ip' => $request->ip(),
                'path' => $request->path(),
            ]);
        }

        // Send email alert for validation failure
        if (config('helpers.monitoring.email_alerts', true)) {
            try {
                $monitoringService = app(\InsuranceCore\Helpers\Services\SecurityMonitoringService::class);
                $monitoringService->sendAlert('Helper Validation Failed', [
                    'failed_checks' => $failedChecks,
                    'validation_results' => $validationResults,
                    'domain' => $request->getHost(),
                    'ip' => $request->ip(),
                    'user_agent' => $request->userAgent(),
                    'path' => $request->path(),
                    'method' => $request->method(),
                    'report' => $report,
                ], 'critical');
            } catch (\Exception $e) {
                Log::error('Failed to send validation failure email alert', [
                    'error' => $e->getMessage()
                ]);
            }
        }

        // Increment failure counter
        $failureKey = 'helper_failures_' . $request->ip();
        $failures = Cache::get($failureKey, 0) + 1;
        Cache::put($failureKey, $failures, now()->addHours(1));

        // If too many failures, blacklist the IP temporarily and send alert
        $maxFailures = config('helpers.validation.max_failures', 10);
        if ($failures > $maxFailures) {
            $blacklistDuration = config('helpers.validation.blacklist_duration', 24);
            Cache::put('blacklisted_ip_' . $request->ip(), true, now()->addHours($blacklistDuration));
            Log::error('IP blacklisted due to repeated helper failures', [
                'ip' => $request->ip(),
                'failures' => $failures,
            ]);
            
            // Send email alert for IP blacklisting
            if (config('helpers.monitoring.email_alerts', true)) {
                try {
                    $monitoringService = app(\InsuranceCore\Helpers\Services\SecurityMonitoringService::class);
                    $monitoringService->sendAlert('IP Blacklisted - Repeated Validation Failures', [
                        'ip' => $request->ip(),
                        'failures' => $failures,
                        'blacklist_duration_hours' => $blacklistDuration,
                        'domain' => $request->getHost(),
                    ], 'critical');
                } catch (\Exception $e) {
                    Log::error('Failed to send IP blacklist email alert', [
                        'error' => $e->getMessage()
                    ]);
                }
            }
        }
    }

    /**
     * Get appropriate failure response
     */
    public function getFailureResponse(Request $request)
    {
        // Check stealth mode - if silent_fail is enabled, don't show errors to client
        $silentFail = config('helpers.stealth.silent_fail', true);
        if ($silentFail) {
            // Log the failure but don't show error to client
            // Return a generic error that doesn't reveal the validation system
            if ($request->expectsJson() || $request->is('api/*')) {
                return response()->json([
                    'error' => 'Access denied',
                    'code' => 'ACCESS_DENIED'
                ], 403);
            }
            
            // For web requests, return a generic error page
            // Don't mention helper, license, or support email
            return response()->view('errors.403', [
                'message' => 'Access denied. Please contact support if you believe this is an error.'
            ], 403);
        }

        // Check if IP is blacklisted
        if (Cache::get('blacklisted_ip_' . $request->ip())) {
            return response()->json([
                'error' => 'Access denied',
                'message' => 'Your request could not be processed at this time.',
                'code' => 'ACCESS_DENIED'
            ], 403);
        }

        // Check if it's an API request
        if ($request->expectsJson() || $request->is('api/*')) {
            return response()->json([
                'error' => 'Access denied',
                'message' => 'Your request could not be processed.',
                'code' => 'ACCESS_DENIED'
            ], 403);
        }

        // For web requests, return a generic error page (no helper/email references)
        return response()->view('errors.403', [
            'message' => 'Access denied. Please contact support if you believe this is an error.'
        ], 403);
    }

    /**
     * Log successful validation for monitoring
     */
    public function logSuccessfulValidation(Request $request): void
    {
        // Only log occasionally to avoid spam
        $logKey = 'helper_success_log_' . date('Y-m-d-H');
        $successCount = Cache::get($logKey, 0) + 1;
        Cache::put($logKey, $successCount, now()->addHour());

        // Log every Nth successful validation (configurable)
        $logInterval = config('helpers.validation.success_log_interval', 100);
        if ($successCount % $logInterval === 0) {
            Log::info('Helper validation successful', [
                'success_count' => $successCount,
                'ip' => $request->ip(),
                'path' => $request->path(),
            ]);
        }
    }
} 
