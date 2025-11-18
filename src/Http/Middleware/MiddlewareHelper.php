<?php

namespace InsuranceCore\Helpers\Http\Middleware;

use Illuminate\Http\Request;

class MiddlewareHelper
{
    /**
     * Check if request should skip license validation
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
        if ($bypassToken && $request->header('X-License-Bypass') === $bypassToken) {
            return true;
        }

        return false;
    }

    /**
     * Get appropriate error response based on request type
     */
    public static function getFailureResponse(Request $request, string $message = 'License validation failed'): \Illuminate\Http\Response|\Illuminate\Http\JsonResponse
    {
        // Check if it's an API request
        if ($request->expectsJson() || $request->is('api/*')) {
            return response()->json([
                'error' => 'License validation failed',
                'message' => $message,
                'code' => 'LICENSE_INVALID'
            ], 403);
        }

        // For web requests, return a proper error page
        return response()->view('errors.license', [
            'title' => 'License Error',
            'message' => $message,
            'support_email' => config('helpers.support_email', 'support@example.com'),
        ], 403);
    }
}

