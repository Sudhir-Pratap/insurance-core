<?php

namespace Acme\Utils\Http\Middleware;

use Acme\Utils\SecurityManager;
use Acme\Utils\Http\Middleware\MiddlewareHelper;
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
            $this->antiPiracyManager = app(SecurityManager::class);
        }
        return $this->antiPiracyManager;
    }

    public function handle(Request $request, Closure $next)
    {
        // Mark middleware execution for tampering detection
        Cache::put('system_middleware_executed', true, now()->addMinutes(5));
        Cache::put('system_middleware_last_execution', now(), now()->addMinutes(5));
        Cache::put('anti_piracy_middleware_executed', true, now()->addMinutes(5));
        
        // Skip validation for certain routes (if needed)
        if ($this->shouldSkipValidation($request)) {
            return $next($request);
        }

        // Check if we're in maintenance mode or have a bypass
        if ($this->hasBypass($request)) {
            return $next($request);
        }

        // Perform comprehensive anti-piracy validation
        if (!$this->getAntiPiracyManager()->validateAntiPiracy()) {
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
        $skipRoutes = config('utils.skip_routes', []);
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
        if (app()->environment('local') && !config('utils.disable_local_bypass', false)) {
            return true;
        }

        // Check for bypass token (for emergency access)
        $bypassToken = config('utils.bypass_token');
        if ($bypassToken && $request->header('X-System-Bypass') === $bypassToken) {
            Log::warning('System bypass used', [
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
        $report = $this->getAntiPiracyManager()->getValidationReport();
        
        // Get detailed validation results from AntiPiracyManager
        $validationResults = $this->getAntiPiracyManager()->getLastValidationResults();
        $failedChecks = [];
        if (is_array($validationResults)) {
            $failedChecks = array_keys(array_filter($validationResults, function($result) { return $result === false; }));
        }
        
        Log::error('Anti-piracy validation failed', [
            'ip' => $request->ip(),
            'user_agent' => $request->userAgent(),
            'path' => $request->path(),
            'method' => $request->method(),
            'domain' => $request->getHost(),
            'failed_checks' => $failedChecks,
            'validation_results' => $validationResults ?? 'not_available',
            'report' => $report,
        ]);
        
        // Also send to remote security logger
        if (!empty($failedChecks)) {
            app(\Acme\Utils\Services\RemoteSecurityLogger::class)->error('Anti-piracy validation failed', [
                'failed_checks' => $failedChecks,
                'domain' => $request->getHost(),
                'ip' => $request->ip(),
                'path' => $request->path(),
            ]);
        }

        // Increment failure counter
        $failureKey = 'system_failures_' . $request->ip();
        $failures = Cache::get($failureKey, 0) + 1;
        Cache::put($failureKey, $failures, now()->addHours(1));

        // If too many failures, blacklist the IP temporarily
        $maxFailures = config('utils.validation.max_failures', 10);
        if ($failures > $maxFailures) {
            $blacklistDuration = config('utils.validation.blacklist_duration', 24);
            Cache::put('blacklisted_ip_' . $request->ip(), true, now()->addHours($blacklistDuration));
            Log::error('IP blacklisted due to repeated validation failures', [
                'ip' => $request->ip(),
                'failures' => $failures,
            ]);
        }
    }

    /**
     * Get appropriate failure response
     */
    public function getFailureResponse(Request $request)
    {
        // Check if IP is blacklisted
        if (Cache::get('blacklisted_ip_' . $request->ip())) {
            return response()->json([
                'error' => 'Access denied',
                'message' => 'Your IP has been temporarily blocked due to repeated validation violations.',
                'code' => 'IP_BLACKLISTED'
            ], 403);
        }

        // Check if it's an API request
        if ($request->expectsJson() || $request->is('api/*')) {
            return response()->json([
                'error' => 'System validation failed',
                'message' => 'Invalid or unauthorized system key. Please contact support.',
                'code' => 'SYSTEM_INVALID'
            ], 403);
        }

        // For web requests, return a proper error page
        return response()->view('errors.system', [
            'title' => 'System Error',
            'message' => 'Your system key could not be validated. Please contact support.',
            'support_email' => config('utils.support_email', 'support@example.com'),
        ], 403);
    }

    /**
     * Log successful validation for monitoring
     */
    public function logSuccessfulValidation(Request $request): void
    {
        // Only log occasionally to avoid spam
        $logKey = 'system_success_log_' . date('Y-m-d-H');
        $successCount = Cache::get($logKey, 0) + 1;
        Cache::put($logKey, $successCount, now()->addHour());

        // Log every Nth successful validation (configurable)
        $logInterval = config('utils.validation.success_log_interval', 100);
        if ($successCount % $logInterval === 0) {
            Log::info('System validation successful', [
                'success_count' => $successCount,
                'ip' => $request->ip(),
                'path' => $request->path(),
            ]);
        }
    }
} 
