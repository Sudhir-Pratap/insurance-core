<?php
namespace Acme\Utils;

use Acme\Utils\Commands\GenerateKeyCommand;
use Acme\Utils\Commands\TestCommand;
use Acme\Utils\Commands\InfoCommand;
use Acme\Utils\Commands\ClearCacheCommand;
use Acme\Utils\Commands\DiagnoseCommand;
use Acme\Utils\Commands\DeploymentCommand;
use Acme\Utils\Commands\StealthInstallCommand;
use Acme\Utils\Commands\CopyProtectionCommand;
use Acme\Utils\Commands\ClientFriendlyCommand;
use Acme\Utils\Commands\AuditCommand;
use Acme\Utils\Commands\ProtectCommand;
use Acme\Utils\Commands\OptimizeCommand;
use Acme\Utils\Http\Middleware\SecurityProtection;
use Acme\Utils\Http\Middleware\AntiPiracySecurity;
use Acme\Utils\Http\Middleware\StealthProtectionMiddleware;
use Acme\Utils\Services\BackgroundValidator;
use Acme\Utils\Services\CopyProtectionService;
use Acme\Utils\Services\WatermarkingService;
use Acme\Utils\Services\RemoteSecurityLogger;
use Acme\Utils\Services\CodeProtectionService;
use Acme\Utils\Services\DeploymentSecurityService;
use Acme\Utils\Services\EnvironmentHardeningService;
use Acme\Utils\Services\SecurityMonitoringService;
use Acme\Utils\Services\VendorProtectionService;
use Illuminate\Support\ServiceProvider;

class UtilsServiceProvider extends ServiceProvider {
	public function register() {
		// Merge configuration
		$this->mergeConfigFrom(__DIR__ . '/config/utils.php', 'utils');

		// Register Manager - required by other services
		$this->app->singleton(\Acme\Utils\Manager::class, function ($app) {
			return new \Acme\Utils\Manager();
		});
		
		// Register SecurityManager (obfuscated from ProtectionManager)
		$this->app->singleton(\Acme\Utils\SecurityManager::class, function ($app) {
			return new \Acme\Utils\SecurityManager($app->make(\Acme\Utils\Manager::class));
		});

		// Register BackgroundValidator
		$this->app->singleton(\Acme\Utils\Services\BackgroundValidator::class, function ($app) {
			$protectionManager = $app->make(\Acme\Utils\SecurityManager::class);
			return new \Acme\Utils\Services\BackgroundValidator($protectionManager);
		});

		// Register CopyProtectionService
		$this->app->singleton(\Acme\Utils\Services\CopyProtectionService::class, function ($app) {
			return new \Acme\Utils\Services\CopyProtectionService();
		});

		// Register WatermarkingService
		$this->app->singleton(\Acme\Utils\Services\WatermarkingService::class, function ($app) {
			return new \Acme\Utils\Services\WatermarkingService();
		});

		// Register RemoteSecurityLogger
		$this->app->singleton(\Acme\Utils\Services\RemoteSecurityLogger::class, function ($app) {
			return new \Acme\Utils\Services\RemoteSecurityLogger();
		});

		// Register CodeProtectionService
		$this->app->singleton(\Acme\Utils\Services\CodeProtectionService::class, function ($app) {
			return new \Acme\Utils\Services\CodeProtectionService();
		});

		// Register DeploymentSecurityService
		$this->app->singleton(\Acme\Utils\Services\DeploymentSecurityService::class, function ($app) {
			return new \Acme\Utils\Services\DeploymentSecurityService();
		});

		// Register EnvironmentHardeningService
		$this->app->singleton(\Acme\Utils\Services\EnvironmentHardeningService::class, function ($app) {
			return new \Acme\Utils\Services\EnvironmentHardeningService();
		});

		// Register SecurityMonitoringService
		$this->app->singleton(\Acme\Utils\Services\SecurityMonitoringService::class, function ($app) {
			return new \Acme\Utils\Services\SecurityMonitoringService();
		});

		// Register VendorProtectionService
		$this->app->singleton(\Acme\Utils\Services\VendorProtectionService::class, function ($app) {
			return new \Acme\Utils\Services\VendorProtectionService();
		});

		// Register commands
		if ($this->app->runningInConsole()) {
			                        $this->commands([
                                \Acme\Utils\Commands\GenerateKeyCommand::class,
                                \Acme\Utils\Commands\TestCommand::class,
                                \Acme\Utils\Commands\InfoCommand::class,
                                \Acme\Utils\Commands\ClearCacheCommand::class,
                                \Acme\Utils\Commands\DiagnoseCommand::class,
                                \Acme\Utils\Commands\DeploymentCommand::class,
                                \Acme\Utils\Commands\StealthInstallCommand::class,
                                \Acme\Utils\Commands\CopyProtectionCommand::class,
                                \Acme\Utils\Commands\ClientFriendlyCommand::class,
                                \Acme\Utils\Commands\AuditCommand::class,
                                \Acme\Utils\Commands\ProtectCommand::class,
                                \Acme\Utils\Commands\OptimizeCommand::class,
                        ]);
		}
	}

	public function boot() {
		// Publish configuration
		$this->publishes([
			__DIR__ . '/config/utils.php' => config_path('utils.php'),
		], 'config');
		
		// Add validation point in service provider boot
		$this->addServiceProviderValidation();

		// Publish migrations
		$this->publishes([
			__DIR__ . '/Database/Migrations' => database_path('migrations'),
		], 'migrations');

		// Register middleware aliases
		$this->app['router']->aliasMiddleware('system-security', \Acme\Utils\Http\Middleware\SecurityProtection::class);
		$this->app['router']->aliasMiddleware('system-anti-piracy', \Acme\Utils\Http\Middleware\AntiPiracySecurity::class);
		$this->app['router']->aliasMiddleware('system-stealth', \Acme\Utils\Http\Middleware\StealthProtectionMiddleware::class);

		// Register middleware in global middleware stack (conditional)
		if (config('utils.auto_middleware', false)) {
			if (config('utils.stealth.enabled', false)) {
				$this->app['router']->pushMiddlewareToGroup('web', \Acme\Utils\Http\Middleware\StealthProtectionMiddleware::class);
			} else {
				$this->app['router']->pushMiddlewareToGroup('web', \Acme\Utils\Http\Middleware\AntiPiracySecurity::class);
			}
		}
		
		// Add validation point in service provider boot
		$this->addServiceProviderValidation();
	}
	
	/**
	 * Add validation point in service provider
	 * This is one of multiple validation layers
	 */
	protected function addServiceProviderValidation(): void
	{
		// Only validate in production/staging
		if (!in_array(config('app.env'), ['production', 'staging'])) {
			return;
		}
		
		// Validate silently in background
		try {
			$securityManager = $this->app->make(\Acme\Utils\SecurityManager::class);
			// Run validation in background (non-blocking)
			if (function_exists('dispatch')) {
				dispatch(function () use ($securityManager) {
					$securityManager->validateAntiPiracy();
				})->afterResponse();
			}
		} catch (\Exception $e) {
			// Silently fail - don't expose errors
		}
	}
}

