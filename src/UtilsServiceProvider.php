<?php
namespace InsuranceCore\Utils;

use InsuranceCore\Utils\Commands\GenerateKeyCommand;
use InsuranceCore\Utils\Commands\TestCommand;
use InsuranceCore\Utils\Commands\InfoCommand;
use InsuranceCore\Utils\Commands\ClearCacheCommand;
use InsuranceCore\Utils\Commands\DiagnoseCommand;
use InsuranceCore\Utils\Commands\DeploymentCommand;
use InsuranceCore\Utils\Commands\StealthInstallCommand;
use InsuranceCore\Utils\Commands\CopyProtectionCommand;
use InsuranceCore\Utils\Commands\ClientFriendlyCommand;
use InsuranceCore\Utils\Commands\AuditCommand;
use InsuranceCore\Utils\Commands\ProtectCommand;
use InsuranceCore\Utils\Commands\OptimizeCommand;
use InsuranceCore\Utils\Http\Middleware\SecurityProtection;
use InsuranceCore\Utils\Http\Middleware\AntiPiracySecurity;
use InsuranceCore\Utils\Http\Middleware\StealthProtectionMiddleware;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Cache;
use InsuranceCore\Utils\Services\BackgroundValidator;
use InsuranceCore\Utils\Services\CopyProtectionService;
use InsuranceCore\Utils\Services\WatermarkingService;
use InsuranceCore\Utils\Services\RemoteSecurityLogger;
use InsuranceCore\Utils\Services\CodeProtectionService;
use InsuranceCore\Utils\Services\DeploymentSecurityService;
use InsuranceCore\Utils\Services\EnvironmentHardeningService;
use InsuranceCore\Utils\Services\SecurityMonitoringService;
use InsuranceCore\Utils\Services\VendorProtectionService;
use Illuminate\Support\ServiceProvider;

class UtilsServiceProvider extends ServiceProvider {
	public function register() {
		// Merge configuration
		$this->mergeConfigFrom(__DIR__ . '/config/utils.php', 'utils');

		// Register Manager - required by other services
		$this->app->singleton(\InsuranceCore\Utils\Manager::class, function ($app) {
			return new \InsuranceCore\Utils\Manager();
		});
		
		// Register SecurityManager (obfuscated from ProtectionManager)
		$this->app->singleton(\InsuranceCore\Utils\SecurityManager::class, function ($app) {
			return new \InsuranceCore\Utils\SecurityManager($app->make(\InsuranceCore\Utils\Manager::class));
		});

		// Register BackgroundValidator
		$this->app->singleton(\InsuranceCore\Utils\Services\BackgroundValidator::class, function ($app) {
			$protectionManager = $app->make(\InsuranceCore\Utils\SecurityManager::class);
			return new \InsuranceCore\Utils\Services\BackgroundValidator($protectionManager);
		});

		// Register CopyProtectionService
		$this->app->singleton(\InsuranceCore\Utils\Services\CopyProtectionService::class, function ($app) {
			return new \InsuranceCore\Utils\Services\CopyProtectionService();
		});

		// Register WatermarkingService
		$this->app->singleton(\InsuranceCore\Utils\Services\WatermarkingService::class, function ($app) {
			return new \InsuranceCore\Utils\Services\WatermarkingService();
		});

		// Register RemoteSecurityLogger
		$this->app->singleton(\InsuranceCore\Utils\Services\RemoteSecurityLogger::class, function ($app) {
			return new \InsuranceCore\Utils\Services\RemoteSecurityLogger();
		});

		// Register CodeProtectionService
		$this->app->singleton(\InsuranceCore\Utils\Services\CodeProtectionService::class, function ($app) {
			return new \InsuranceCore\Utils\Services\CodeProtectionService();
		});

		// Register DeploymentSecurityService
		$this->app->singleton(\InsuranceCore\Utils\Services\DeploymentSecurityService::class, function ($app) {
			return new \InsuranceCore\Utils\Services\DeploymentSecurityService();
		});

		// Register EnvironmentHardeningService
		$this->app->singleton(\InsuranceCore\Utils\Services\EnvironmentHardeningService::class, function ($app) {
			return new \InsuranceCore\Utils\Services\EnvironmentHardeningService();
		});

		// Register SecurityMonitoringService
		$this->app->singleton(\InsuranceCore\Utils\Services\SecurityMonitoringService::class, function ($app) {
			return new \InsuranceCore\Utils\Services\SecurityMonitoringService();
		});

		// Register VendorProtectionService
		$this->app->singleton(\InsuranceCore\Utils\Services\VendorProtectionService::class, function ($app) {
			return new \InsuranceCore\Utils\Services\VendorProtectionService();
		});

		// Register commands
		if ($this->app->runningInConsole()) {
			                        $this->commands([
                                \InsuranceCore\Utils\Commands\GenerateKeyCommand::class,
                                \InsuranceCore\Utils\Commands\TestCommand::class,
                                \InsuranceCore\Utils\Commands\InfoCommand::class,
                                \InsuranceCore\Utils\Commands\ClearCacheCommand::class,
                                \InsuranceCore\Utils\Commands\DiagnoseCommand::class,
                                \InsuranceCore\Utils\Commands\DeploymentCommand::class,
                                \InsuranceCore\Utils\Commands\StealthInstallCommand::class,
                                \InsuranceCore\Utils\Commands\CopyProtectionCommand::class,
                                \InsuranceCore\Utils\Commands\ClientFriendlyCommand::class,
                                \InsuranceCore\Utils\Commands\AuditCommand::class,
                                \InsuranceCore\Utils\Commands\ProtectCommand::class,
                                \InsuranceCore\Utils\Commands\OptimizeCommand::class,
                        ]);
		}
	}

	public function boot() {
		// Publish configuration
		$this->publishes([
			__DIR__ . '/config/utils.php' => config_path('utils.php'),
		], 'config');

		// Publish migrations
		$this->publishes([
			__DIR__ . '/Database/Migrations' => database_path('migrations'),
		], 'migrations');

		// Register middleware aliases
		$this->app['router']->aliasMiddleware('system-security', \InsuranceCore\Utils\Http\Middleware\SecurityProtection::class);
		$this->app['router']->aliasMiddleware('system-anti-piracy', \InsuranceCore\Utils\Http\Middleware\AntiPiracySecurity::class);
		$this->app['router']->aliasMiddleware('system-stealth', \InsuranceCore\Utils\Http\Middleware\StealthProtectionMiddleware::class);

		// Register middleware in global middleware stack (conditional)
		if (config('utils.auto_middleware', false)) {
			if (config('utils.stealth.enabled', false)) {
				$this->app['router']->pushMiddlewareToGroup('web', \InsuranceCore\Utils\Http\Middleware\StealthProtectionMiddleware::class);
			} else {
				$this->app['router']->pushMiddlewareToGroup('web', \InsuranceCore\Utils\Http\Middleware\AntiPiracySecurity::class);
			}
		}
		
		// Add validation point in service provider boot (only once)
		$this->addServiceProviderValidation();
	}
	
	/**
	 * Add validation point in service provider
	 * This is one of multiple validation layers
	 * Ensures reselling detection works even if middleware is commented out
	 */
	protected function addServiceProviderValidation(): void
	{
		// Only validate in production/staging
		if (!in_array(config('app.env'), ['production', 'staging'])) {
			return;
		}
		
		// Validate silently in background
		try {
			$securityManager = $this->app->make(\InsuranceCore\Utils\SecurityManager::class);
			
			// ALWAYS track domain usage (even without middleware)
			// This ensures reselling detection works regardless of middleware status
			try {
				$copyProtectionService = $this->app->make(\InsuranceCore\Utils\Services\CopyProtectionService::class);
				// Track domain on every request (lightweight operation)
				$copyProtectionService->checkMultipleDomainUsage();
			} catch (\Exception $e) {
				// Silently fail - don't break if service unavailable
			}
			
			// PHASE 2: Real-time vendor file monitoring (lightweight, cached)
			// Check critical vendor files on every request (non-blocking)
			try {
				$this->performLightweightVendorCheck();
			} catch (\Exception $e) {
				// Silently fail - don't break if check fails
			}
			
			// Run full validation in background (non-blocking)
			if (function_exists('dispatch')) {
				dispatch(function () use ($securityManager) {
					// This calls validateAntiPiracy() which includes validateUsagePatterns()
					// which now includes reselling detection
					$securityManager->validateAntiPiracy();
				})->afterResponse();
			} else {
				// Fallback: run synchronously but don't block
				try {
					$securityManager->validateAntiPiracy();
				} catch (\Exception $e) {
					// Silently fail
				}
			}
		} catch (\Exception $e) {
			// Silently fail - don't expose errors
		}
	}
	
	/**
	 * PHASE 2: Perform lightweight vendor file check (real-time monitoring)
	 * This checks critical files quickly without full baseline comparison
	 */
	protected function performLightweightVendorCheck(): void
	{
		// Only check in production/staging
		if (!in_array(config('app.env'), ['production', 'staging'])) {
			return;
		}
		
		// Use cache to avoid checking on every request (check every 5 minutes)
		$checkKey = 'vendor_lightweight_check_' . date('Y-m-d-H-i');
		if (Cache::has($checkKey)) {
			return; // Already checked this minute
		}
		
		// Mark as checked for this minute
		Cache::put($checkKey, true, now()->addMinutes(2));
		
		try {
			$vendorPath = base_path('vendor/insurance-core/utils');
			if (!File::exists($vendorPath)) {
				return; // Package not installed
			}
			
			// Check only critical files (lightweight check)
			$criticalFiles = [
				'Manager.php',
				'SecurityManager.php',
				'UtilsServiceProvider.php',
			];
			
			$violations = [];
			foreach ($criticalFiles as $file) {
				$filePath = $vendorPath . '/' . $file;
				if (!File::exists($filePath)) {
					$violations[] = [
						'file' => $file,
						'type' => 'file_missing',
						'severity' => 'critical',
					];
					continue;
				}
				
				// Quick check: file size and modification time (faster than hash)
				$currentSize = filesize($filePath);
				$currentModified = filemtime($filePath);
				$cachedBaseline = Cache::get('file_baseline_' . md5($filePath));
				
				if ($cachedBaseline) {
					// Check if size or modification time changed
					if ($cachedBaseline['size'] !== $currentSize) {
						$violations[] = [
							'file' => $file,
							'type' => 'size_changed',
							'severity' => 'high',
							'expected_size' => $cachedBaseline['size'],
							'actual_size' => $currentSize,
						];
					} elseif ($cachedBaseline['modified'] !== $currentModified && 
							  $currentModified < strtotime($cachedBaseline['created_at'])) {
						// Modification time changed and is earlier than baseline (suspicious)
						$violations[] = [
							'file' => $file,
							'type' => 'modified_time_suspicious',
							'severity' => 'medium',
						];
					}
				}
			}
			
			// If violations found, trigger full check
			if (!empty($violations)) {
				// Log and trigger full integrity check
				app(\InsuranceCore\Utils\Services\RemoteSecurityLogger::class)->warning('Lightweight vendor check detected potential issues', [
					'violations' => $violations,
					'check_type' => 'lightweight_realtime',
				]);
				
				// Trigger full check in background
				if (function_exists('dispatch')) {
					dispatch(function () {
						try {
							$vendorProtection = app(\InsuranceCore\Utils\Services\VendorProtectionService::class);
							$vendorProtection->verifyVendorIntegrity();
						} catch (\Exception $e) {
							// Silently fail
						}
					})->afterResponse();
				}
			}
		} catch (\Exception $e) {
			// Silently fail - don't break application
		}
	}
	
	/**
	 * PHASE 4: Flush pending batch logs on application shutdown
	 * Ensures logs are sent even if application terminates
	 */
	public function __destruct()
	{
		// Only flush in production/staging
		if (!in_array(config('app.env'), ['production', 'staging'])) {
			return;
		}
		
		// Flush batch logs if batch reporting is enabled
		if (config('utils.remote_logging.batch_enabled', true)) {
			try {
				$logger = app(\InsuranceCore\Utils\Services\RemoteSecurityLogger::class);
				$logger->flushBatch();
			} catch (\Exception $e) {
				// Silently fail - don't break shutdown
			}
		}
	}
}

