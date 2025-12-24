<?php
namespace Acme\Utils;

use Carbon\Carbon;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Str;

/**
 * Generic utility manager for application security and validation
 * @internal This class is obfuscated - do not reference directly
 */
class Manager {
	/**
	 * Normalize domain for consistent comparison (matches server-side normalization)
	 * - Removes protocol (http://, https://)
	 * - Removes trailing slashes
	 * - Converts to lowercase
	 * - Removes port numbers
	 * 
	 * @param string $domain
	 * @return string
	 */
	protected function normalizeDomain(string $domain): string
	{
		// Remove protocol
		$domain = preg_replace('#^https?://#', '', $domain);
		
		// Remove trailing slash
		$domain = rtrim($domain, '/');
		
		// Remove port
		$domain = preg_replace('#:\d+$#', '', $domain);
		
		// Convert to lowercase
		$domain = strtolower($domain);
		
		return trim($domain);
	}

	public function validateSystem(string $systemKey, string $productId, string $domain, string $ip, string $clientId): bool {
		$validationServer = config('utils.validation_server');
		$apiToken      = config('utils.api_token');
		// Hash the system key in cache keys to avoid database key length limits
		$systemKeyHash = md5($systemKey);
		$cacheKey      = "system_valid_{$systemKeyHash}_{$productId}_{$clientId}";
		$lastCheckKey  = "system_last_check_{$systemKeyHash}_{$productId}_{$clientId}";

		// Generate hardware fingerprint
		$hardwareFingerprint = $this->generateHardwareFingerprint();
		$installationId = $this->getOrCreateInstallationId();

		// Use the original client ID for checksum calculation (not the enhanced one)
		$originalClientId = $clientId;

		// Use UTILS_SECRET for cryptography, fallback to APP_KEY if not set
		$cryptoKey = env('UTILS_SECRET', env('APP_KEY'));
		// Ensure hardware_fingerprint is not null (use empty string if null)
		$hardwareFingerprint = $hardwareFingerprint ?? '';
		// Generate enhanced checksum
		$checksum = hash('sha256', $systemKey . $productId . $originalClientId . $hardwareFingerprint . $cryptoKey);

		// Get remote logger for comprehensive logging
		$remoteLogger = app(\Acme\Utils\Services\RemoteSecurityLogger::class);

		// Force server check every 30 minutes (reduced from 60)
		$lastCheck = Cache::get($lastCheckKey);
		if (! $lastCheck || Carbon::parse($lastCheck)->addMinutes(30)->isPast()) {
			Cache::forget($cacheKey);
		}

		// Check cache first
		if (Cache::get($cacheKey)) {
			// Log cache usage
			$remoteLogger->logValidationAttempt([
				'product_id' => $productId,
				'domain' => $domain,
				'ip' => $ip,
				'client_id' => $originalClientId,
				'hardware_fingerprint' => $hardwareFingerprint,
				'installation_id' => $installationId,
				'result' => 'success',
				'used_cache' => true,
				'used_grace_period' => false,
				'server_reachable' => true,
			]);
			return true;
		}

		try {
			// Log validation attempt BEFORE server call
			$remoteLogger->logValidationAttempt([
				'product_id' => $productId,
				'domain' => $domain,
				'ip' => $ip,
				'client_id' => $originalClientId,
				'hardware_fingerprint' => $hardwareFingerprint,
				'installation_id' => $installationId,
				'result' => 'pending',
				'used_cache' => false,
				'used_grace_period' => false,
				'server_reachable' => true,
			]);

			// Enhanced debug log for deployment debugging
			Log::info('System validation request', [
				'system_key' => substr($systemKey, 0, 20) . '...', // Partial key for security
				'product_id' => $productId,
				'domain' => $domain,
				'ip' => $ip,
				'client_id' => $originalClientId,
				'hardware_fingerprint' => $hardwareFingerprint ? substr($hardwareFingerprint, 0, 16) . '...' : 'NULL',
				'installation_id' => $installationId,
				'checksum' => substr($checksum, 0, 16) . '...',
				'full_checksum' => $checksum, // Full checksum for debugging
				'crypto_key_set' => !empty($cryptoKey) ? 'YES' : 'NO',
				'input_string' => substr($systemKey, 0, 20) . '...' . $productId . $originalClientId . ($hardwareFingerprint ? substr($hardwareFingerprint, 0, 16) . '...' : 'NULL'),
				'validation_server' => $validationServer,
				'environment' => config('app.env'),
				'deployment_context' => request()->header('X-Deployment-Context'),
			]);

			// Validate required config values
			if (empty($systemKey) || empty($productId) || empty($originalClientId)) {
				Log::error('System validation failed: Missing required configuration', [
					'system_key_set' => !empty($systemKey),
					'product_id_set' => !empty($productId),
					'client_id_set' => !empty($originalClientId),
				]);
				
				// Fallback to cache if available
				$cachedResult = Cache::get($cacheKey, false);
				if ($cachedResult) {
					Log::info('Using cached system validation due to missing config');
					return true;
				}
				return false;
			}

			if (empty($validationServer) || empty($apiToken)) {
				Log::error('System validation failed: Missing server configuration', [
					'validation_server_set' => !empty($validationServer),
					'api_token_set' => !empty($apiToken),
				]);
				
				// Fallback to cache if available
				$cachedResult = Cache::get($cacheKey, false);
				if ($cachedResult) {
					Log::info('Using cached system validation due to missing server config');
					return true;
				}
				return false;
			}

			// Build request payload - domain and IP are optional (server will auto-detect if not provided)
			$payload = [
				'system_key' => $systemKey,
				'product_id'  => $productId,
				'client_id'   => $originalClientId,
				'checksum'    => $checksum,
			];
			
			// Only include domain/IP if explicitly provided (server can auto-detect from request)
			// Normalize domain to match server-side normalization (for domain whitelisting support)
			if (!empty($domain) && $domain !== 'unknown') {
				$payload['domain'] = $this->normalizeDomain($domain);
			}
			if (!empty($ip) && $ip !== 'unknown') {
				$payload['ip'] = $ip;
			}
			
			// Optional fields for reselling detection
			if (!empty($hardwareFingerprint)) {
				$payload['hardware_fingerprint'] = $hardwareFingerprint;
			}
			if (!empty($installationId)) {
				$payload['installation_id'] = $installationId;
			}
			
			$response = Http::withHeaders([
				'Authorization' => 'Bearer ' . $apiToken,
			])->timeout(15)->post("{$validationServer}/api/validate", $payload);

			// Handle response safely
			$responseData = [];
			try {
				$responseData = $response->json();
			} catch (\Exception $jsonError) {
				Log::error('Failed to parse server response as JSON', [
					'status' => $response->status(),
					'body' => substr($response->body(), 0, 200),
					'error' => $jsonError->getMessage(),
				]);
			}

			if ($response->successful() && isset($responseData['valid']) && $responseData['valid'] === true) {
				// Log successful validation
				$remoteLogger->logValidationAttempt([
					'product_id' => $productId,
					'domain' => $domain,
					'ip' => $ip,
					'client_id' => $originalClientId,
					'hardware_fingerprint' => $hardwareFingerprint,
					'installation_id' => $installationId,
					'result' => 'success',
					'used_cache' => false,
					'used_grace_period' => false,
					'server_reachable' => true,
				]);

				Cache::put($cacheKey, true, now()->addMinutes(config('utils.cache_duration')));
				Cache::put($lastCheckKey, now(), now()->addDays(30));
				// Store successful validation timestamp for fallback
				Cache::put($cacheKey . '_recent_success', now(), now()->addDays(30));
				return true;
			}

			// If server validation fails, check if we have a recent successful cache
			$recentSuccess = Cache::get($cacheKey . '_recent_success');
			if ($recentSuccess && Carbon::parse($recentSuccess)->addHours(6)->isFuture()) {
				// Log grace period usage
				$remoteLogger->logGracePeriod([
					'type' => 'recent_success_cache',
					'hours' => 6,
					'reason' => 'Server validation failed, using recent success cache',
					'validation_result' => 'allowed',
				]);

				$remoteLogger->logValidationAttempt([
					'product_id' => $productId,
					'domain' => $domain,
					'ip' => $ip,
					'client_id' => $originalClientId,
					'hardware_fingerprint' => $hardwareFingerprint,
					'installation_id' => $installationId,
					'result' => 'success',
					'used_cache' => false,
					'used_grace_period' => true,
					'server_reachable' => false,
					'failure_reason' => $responseData['message'] ?? 'Server validation failed',
				]);

				Log::warning('Validation server check failed, using recent cache', [
					'product_id' => $productId,
					'domain' => $domain,
					'last_success' => $recentSuccess,
					'response_status' => $response->status(),
					'response_message' => $responseData['message'] ?? 'No message provided',
				]);
				return true;
			}

			// Log failed validation
			$remoteLogger->logValidationAttempt([
				'product_id' => $productId,
				'domain' => $domain,
				'ip' => $ip,
				'client_id' => $originalClientId,
				'hardware_fingerprint' => $hardwareFingerprint,
				'installation_id' => $installationId,
				'result' => 'failed',
				'used_cache' => false,
				'used_grace_period' => false,
				'server_reachable' => true,
				'failure_reason' => $responseData['message'] ?? 'Unknown error',
			]);

			Log::warning('System validation failed', [
				'product_id' => $productId,
				'domain'     => $domain,
				'ip'         => $ip,
				'client_id'  => $clientId,
				'hardware_fingerprint' => $hardwareFingerprint,
				'installation_id' => $installationId,
				'error'      => $responseData['message'] ?? 'Unknown error',
				'response_status' => $response->status(),
				'response_body' => substr($response->body(), 0, 500),
				'has_cached_result' => Cache::has($cacheKey),
			]);
			
			// If we have a cached result, use it even if server validation failed
			// This helps in cases where server is temporarily unavailable
			$cachedResult = Cache::get($cacheKey, false);
			if ($cachedResult) {
				// Log cache usage after server failure
				$remoteLogger->logValidationAttempt([
					'product_id' => $productId,
					'domain' => $domain,
					'ip' => $ip,
					'client_id' => $originalClientId,
					'result' => 'success',
					'used_cache' => true,
					'used_grace_period' => false,
					'server_reachable' => false,
					'failure_reason' => 'Server validation failed, using cached result',
				]);

				Log::info('Using cached system validation due to server validation failure');
				return true;
			}
			
			return false;
		} catch (\Exception $e) {
			// Fallback to cache if server is unreachable
			$cachedResult = Cache::get($cacheKey, false);
			
			// Log server error and cache usage
			$remoteLogger->logValidationAttempt([
				'product_id' => $productId,
				'domain' => $domain,
				'ip' => $ip,
				'client_id' => $originalClientId,
				'hardware_fingerprint' => $hardwareFingerprint,
				'installation_id' => $installationId,
				'result' => $cachedResult ? 'success' : 'failed',
				'used_cache' => (bool)$cachedResult,
				'used_grace_period' => false,
				'server_reachable' => false,
				'failure_reason' => 'Server unreachable: ' . $e->getMessage(),
			]);

			Log::error('Validation server error: ' . $e->getMessage(), [
				'client_id' => $clientId,
				'hardware_fingerprint' => $hardwareFingerprint,
				'validation_server' => $validationServer,
				'exception_type' => get_class($e),
				'trace' => substr($e->getTraceAsString(), 0, 500),
			]);

			if ($cachedResult) {
				Log::info('Using cached system validation due to server error', [
					'error' => $e->getMessage(),
				]);
				return true;
			}
			
			// If no cache, return false to trigger validation failure
			Log::error('No cached system validation available, validation will fail', [
				'error' => $e->getMessage(),
			]);
			return false;
		}
	}

	/**
	 * Generate hardware fingerprint (deployment-safe)
	 */
	public function generateHardwareFingerprint(): string
	{
		$fingerprintFile = storage_path('app/hardware_fingerprint.id');
		
		// Check if fingerprint exists and force regeneration if in deployment mode
		$forceRegenerate = env('UTILS_FORCE_REGENERATE_FINGERPRINT', false);
		
		if (!$forceRegenerate && File::exists($fingerprintFile)) {
			$fingerprint = File::get($fingerprintFile);
			if ($fingerprint && strlen($fingerprint) === 64) {
				return $fingerprint;
			}
		}
		
		// Use more stable components for deployment environments
		$components = [
			// Core server identity (more stable)
			'app_key_hash' => hash('sha256', config('app.key')), // Laravel app key
			'app_name' => config('app.name'), // App name
			'app_env' => config('app.env'), // Environment
			
			// System identity (stabilized for deployment)
			'server_software' => php_sapi_name(),
			'php_version' => PHP_VERSION,
			'os_family' => PHP_OS_FAMILY ?? PHP_OS, // More stable OS identifier
			
			// Database identity (stable connection fingerprint)
			'db_connection_hash' => $this->getDatabaseConnectionFingerprint(),
			
			// File system identity (relative paths, not absolute)
			'app_signature' => $this->getApplicationSignature(),
		];
		
		// Add domain-specific component if available
		if (config('utils.deployment.bind_to_domain_only', false)) {
			$components['domain_bind'] = $this->getStableDomainIdentifier();
		}
		
		$fingerprint = hash('sha256', serialize($components));
		
		// Log fingerprint generation for debugging
		Log::info('Hardware fingerprint generated', [
			'components' => array_keys($components),
			'fingerprint' => $fingerprint,
			'force_regenerate' => $forceRegenerate,
			'environment' => config('app.env'),
		]);
		
		File::put($fingerprintFile, $fingerprint);
		return $fingerprint;
	}

	/**
	 * Get or create installation ID (database-persisted for deployment safety)
	 */
	public function getOrCreateInstallationId(): string
	{
		// Try to get from config first (for deployment environments)
		$configId = config('utils.deployment.installation_id');
		if ($configId && Str::isUuid($configId)) {
			return $configId;
		}
		
		// Try file-based storage (no database dependency)
		$idFile = storage_path('app/installation.id');
		if (File::exists($idFile)) {
			$id = File::get($idFile);
			if ($id && Str::isUuid(trim($id))) {
				return trim($id);
			}
		}
		
		// Generate new installation ID
		$id = Str::uuid()->toString();
		
		// Save to file
		File::put($idFile, $id);
		Log::info('Installation ID saved to file', ['installation_id' => $id]);
		
		return $id;
	}

	public function generateSystemKey(string $productId, string $domain, string $ip, string $expiry, string $clientId, string $hardwareFingerprint, string $installationId): string {
		$expiryFormatted = Carbon::parse($expiry)->format('Y-m-d H:i:s');
		$keyString   = "{$productId}|{$domain}|{$ip}|{$expiryFormatted}|{$clientId}|{$hardwareFingerprint}|{$installationId}";
		// Use UTILS_SECRET for consistency, fallback to APP_KEY if not set
		$cryptoKey = env('UTILS_SECRET', env('APP_KEY'));
		$signature       = hash_hmac('sha256', $keyString, $cryptoKey);
		return encrypt("{$keyString}|{$signature}");
	}

	/**
	 * Get installation details
	 */
	public function getInstallationDetails(): array
	{
		return [
			'hardware_fingerprint' => $this->generateHardwareFingerprint(),
			'installation_id' => $this->getOrCreateInstallationId




(),
			'server_info' => [
				'domain' => request()->getHost(),
				'ip' => request()->ip(),
				'user_agent' => request()->userAgent(),
			],
		];
	}

	/**
	 * Get stable database connection fingerprint
	 */
	public function getDatabaseConnectionFingerprint(): string
	{
		try {
			$connection = config('database.default');
			$config = config("database.connections.{$connection}");
			
			if (!$config) return '';
			
			// Use stable database identifiers
			$dbFingerprint = [
				'driver' => $config['driver'] ?? '',
				'host' => $config['host'] ?? '',
				'port' => $config['port'] ?? '',
				'database' => $config['database'] ?? '',
				'charset' => $config['charset'] ?? '',
			];
			
			return hash('sha256', serialize($dbFingerprint));
		} catch (\Exception $e) {
			return '';
		}
	}

	/**
	 * Get application signature (file-based fingerprint)
	 */
	public function getApplicationSignature(): string
	{
		try {
			// Use composer.json to create app signature
			$composerPath = base_path('composer.json');
			if (File::exists($composerPath)) {
				$composer = json_decode(File::get($composerPath), true);
				$signature = [
					'name' => $composer['name'] ?? '',
					'description' => $composer['description'] ?? '',
					'version' => $composer['version'] ?? '1.0.0',
				];
				return hash('sha256', serialize($signature));
			}
			
			// Fallback to app config
			return hash('sha256', config('app.name') . config('app.env'));
		} catch (\Exception $e) {
			return hash('sha256', 'fallback_app_signature');
		}
	}

	/**
	 * Get stable domain identifier
	 */
	public function getStableDomainIdentifier(): string
	{
		try {
			// Try to get the canonical domain
			$currentDomain = request()->getHost();
			
			// For deployment, check if there's a canonical domain configured
			$canonicalDomain = config('utils.deployment.canonical_domain');
			if ($canonicalDomain) {
				return hash('sha256', $canonicalDomain);
			}
			
			// Normalize the domain (matches server-side normalization for whitelisting)
			$normalizedDomain = $this->normalizeDomain($currentDomain);
			
			// Remove www. prefix for consistency (additional normalization for domain identifier)
			if (str_starts_with($normalizedDomain, 'www.')) {
				$normalizedDomain = substr($normalizedDomain, 4);
			}
			
			return hash('sha256', $normalizedDomain);
		} catch (\Exception $e) {
			return hash('sha256', 'unknown_domain');
		}
	}

}


