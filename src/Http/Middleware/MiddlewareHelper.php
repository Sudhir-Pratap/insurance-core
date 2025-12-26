<?php

namespace InsuranceCore\Utils\Http\Middleware;

use Illuminate\Http\Request;

class MiddlewareHelper
{
    /**
     * Check if request should skip system validation
     */
    public static function shouldSkipValidation(Request $request): bool
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
     * Check if request has bypass enabled
     */
    public static function hasBypass(Request $request): bool
    {
        // Allow bypass in local environment (unless explicitly disabled for testing)
        if (app()->environment('local') && !config('utils.disable_local_bypass', false)) {
            return true;
        }

        // Check for bypass token
        $bypassToken = config('utils.bypass_token');
        if ($bypassToken && $request->header('X-System-Bypass') === $bypassToken) {
            return true;
        }

        return false;
    }

    /**
     * Get appropriate error response based on request type
     */
    public static function getFailureResponse(Request $request, string $message = 'System validation failed'): \Illuminate\Http\Response|\Illuminate\Http\JsonResponse
    {
        // Check if it's an API request
        if ($request->expectsJson() || $request->is('api/*')) {
            return response()->json([
                'error' => 'System validation failed',
                'message' => $message,
                'code' => 'SYSTEM_INVALID'
            ], 403);
        }

        // For web requests, return a simple HTML error response
        // Don't require clients to create views - use simple HTML response
        $supportEmail = config('utils.support_email', 'support@example.com');
        $html = <<<HTML
<!DOCTYPE html>
<html>
<head>
    <title>System Error</title>
    <style>
        body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
        .error { color: #d32f2f; }
        .message { margin: 20px 0; }
    </style>
</head>
<body>
    <h1 class="error">System Error</h1>
    <div class="message">
        <p>{$message}</p>
        <p>Support: <a href="mailto:{$supportEmail}">{$supportEmail}</a></p>
    </div>
</body>
</html>
HTML;
        return response($html, 403)->header('Content-Type', 'text/html');
    }
}

