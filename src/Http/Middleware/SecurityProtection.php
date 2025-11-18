<?php
namespace InsuranceCore\Helpers\Http\Middleware;

use InsuranceCore\Helpers\Helper;                                    
use InsuranceCore\Helpers\Services\WatermarkingService;
use Closure;                                                                    
use Illuminate\Http\Request;                                                    
use Illuminate\Support\Facades\Log;                                             
use Illuminate\Support\Facades\Cache;

class SecurityProtection {
	protected $helperManager;

	public function __construct() {
		// Don't inject dependencies in constructor to avoid circular dependencies
	}

	protected function getHelperManager() {
		if (!$this->helperManager) {
			$this->helperManager = app(\InsuranceCore\Helpers\Helper::class);
		}
		return $this->helperManager;
	}

	public function handle(Request $request, Closure $next) {
		// Mark middleware execution for tampering detection
		Cache::put('helper_middleware_executed', true, now()->addMinutes(5));
		Cache::put('helper_middleware_last_execution', now(), now()->addMinutes(5));
		Cache::put('helper_security_middleware_executed', true, now()->addMinutes(5));
		
		// Skip validation for certain routes
		if ($this->shouldSkipValidation($request)) {
			return $next($request);
		}
		$helperKey    = config('helpers.helper_key');
		$productId     = config('helpers.product_id');
		$clientId      = config('helpers.client_id');
		$currentDomain = $request->getHost();
		$currentIp     = $request->ip();

		                if (! $this->getHelperManager()->validateHelper($helperKey, $productId, $currentDomain, $currentIp, $clientId)) {                            
                        Log::error('Helper check failed, aborting request', [
                                'helper_key' => $helperKey,
                                'product_id'  => $productId,
                                'domain'      => $currentDomain,
                                'ip'          => $currentIp,
                                'client_id'   => $clientId,
                        ]);
                        abort(403, 'Invalid or unauthorized license.');
                }

                $response = $next($request);

                // Apply watermarking to HTML responses
                $this->applyWatermarking($response);

                return $response;
	}

	protected function shouldSkipValidation(Request $request): bool {
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

		// Allow bypass in local environment (unless explicitly disabled for testing)
		if (app()->environment('local') && !config('helpers.disable_local_bypass', false)) {
			return true;
		}

		return false;
	}

        /**
         * Apply watermarking to HTML responses for copy protection
         */
        protected function applyWatermarking($response): void
        {
                if (!config('helpers.code_protection.watermarking', true)) {    
                        return;
                }

                // Only watermark HTML responses
                if ($response instanceof \Illuminate\Http\Response &&
                        str_contains($response->headers->get('Content-Type', ''), 'text/html')) {                                                                           

                        $watermarkingService = app(WatermarkingService::class);
                        $clientId = config('helpers.client_id');

                        $content = $response->getContent();
                        if ($content === false) {
                                return;
                        }

                        // Apply watermarking
                        $content = $watermarkingService->generateClientWatermark($clientId, $content);                                                                      

                        // Add runtime checks
                        $watermarkingService->addRuntimeChecks($content);

                        // Add anti-debug protection
                        $watermarkingService->addAntiDebugProtection($content);

                        $response->setContent($content);
                }
        }
}


