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
		
		// Add validation point in service provider boot
		$this->addServiceProviderValidation();

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
			$securityManager = $this->app->make(\InsuranceCore\Utils\SecurityManager::class);
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

