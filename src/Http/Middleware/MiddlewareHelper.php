<?php

namespace InsuranceCore\Helpers\Http\Middleware;

use Illuminate\Http\Request;

class MiddlewareHelper
{
    /**
     * Check if request should skip helper validation
     */
    public static function shouldSkipValidation(Request $request): bool
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
     * Check if request has bypass enabled
     */
    public static function hasBypass(Request $request): bool
    {
        // Allow bypass in local environment (unless explicitly disabled for testing)
        if (app()->environment('local') && !config('helpers.disable_local_bypass', false)) {
            return true;
        }

        // Check for bypass token
        $bypassToken = config('helpers.bypass_token');
        if ($bypassToken && $request->header('X-Helper-Bypass') === $bypassToken) {
            return true;
        }

        return false;
    }

    /**
     * Get appropriate error response based on request type
     */
    public static function getFailureResponse(Request $request, string $message = 'Helper validation failed'): \Illuminate\Http\Response|\Illuminate\Http\JsonResponse
    {
        // Check stealth mode - if silent_fail is enabled, don't show errors to client
        $silentFail = config('helpers.stealth.silent_fail', true);
        if ($silentFail) {
            // Return generic error without revealing validation system
            if ($request->expectsJson() || $request->is('api/*')) {
                return response()->json([
                    'error' => 'Access denied',
                    'code' => 'ACCESS_DENIED'
                ], 403);
            }
            
            // For web requests, return generic error page (no helper/email references)
            return response()->view('errors.403', [
                'message' => 'Access denied. Please contact support if you believe this is an error.'
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

        // For web requests, return generic error page (no helper/email references)
        return response()->view('errors.403', [
            'message' => 'Access denied. Please contact support if you believe this is an error.'
        ], 403);
    }
}

