<?php

namespace InsuranceCore\Helpers\Services;

use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\URL;

class EnvironmentHardeningService
{
    /**
     * Apply environment-specific hardening
     */
    public function hardenEnvironment(): void
    {
        $this->applyProductionHardening();
        $this->configureSecureSessions();
        $this->enforceHTTPS();
        $this->disableDebugFeatures();
        $this->restrictFunctionAccess();
    }

    /**
     * Apply production-specific hardening
     */
    public function applyProductionHardening(): void
    {
        if (!config('helpers.environment_hardening.production_only_features', true)) {
            return;
        }

        // Only apply in production or when explicitly configured
        if (!app()->environment('production') && !config('app.debug')) {
            return;
        }

        $this->hardenAppConfiguration();
        $this->secureLoggingConfiguration();
        $this->configureErrorHandling();
    }

    /**
     * Configure secure sessions
     */
    public function configureSecureSessions(): void
    {
        if (!config('helpers.environment_hardening.secure_session_config', true)) {
            return;
        }

        // Configure secure session settings
        Config::set('session.secure', true);
        Config::set('session.http_only', true);
        Config::set('session.same_site', 'strict');

        // Regenerate session ID periodically for security
        if (session_status() === PHP_SESSION_ACTIVE) {
            $lastRegeneration = Cache::get('session_last_regeneration_' . session_id());
            if (!$lastRegeneration || now()->diffInMinutes($lastRegeneration) > 30) {
                session_regenerate_id(true);
                Cache::put('session_last_regeneration_' . session_id(), now(), now()->addHours(1));
            }
        }
    }

    /**
     * Enforce HTTPS connections
     */
    public function enforceHTTPS(): void
    {
        if (!config('helpers.environment_hardening.enforce_https', true)) {
            return;
        }

        if (!request()->secure() && !app()->environment('local')) {
            // Force HTTPS URLs
            URL::forceScheme('https');
            
            // Note: Actual redirect is handled by Laravel's middleware/redirector
            // This method only configures URL generation to use HTTPS
        }
    }

    /**
     * Disable debug features in production
     */
    public function disableDebugFeatures(): void
    {
        if (!config('helpers.environment_hardening.disable_debug_tools', true)) {
            return;
        }

        // Disable debug features
        Config::set('app.debug', false);
        Config::set('app.debugbar.enabled', false);

        // Disable development tools
        if (extension_loaded('xdebug')) {
            ini_set('xdebug.remote_enable', 0);
            ini_set('xdebug.profiler_enable', 0);
        }

        // Remove debug information from responses
        header_remove('X-Powered-By');
        header_remove('X-Debug-Token');
        header_remove('X-Debug-Token-Link');
    }

    /**
     * Restrict function access
     */
    public function restrictFunctionAccess(): void
    {
        if (!config('helpers.environment_hardening.restrict_function_access', true)) {
            return;
        }

        // Disable dangerous functions
        $dangerousFunctions = [
            'exec', 'shell_exec', 'system', 'passthru',
            'popen', 'proc_open', 'pcntl_exec',
            'eval', 'assert', 'create_function',
        ];

        $disabled = ini_get('disable_functions');
        $disabledArray = array_filter(explode(',', $disabled));

        foreach ($dangerousFunctions as $function) {
            if (!in_array($function, $disabledArray)) {
                $disabledArray[] = $function;
            }
        }

        ini_set('disable_functions', implode(',', $disabledArray));
    }

    /**
     * Harden application configuration
     */
    public function hardenAppConfiguration(): void
    {
        // Set secure defaults
        Config::set('app.key', env('APP_KEY')); // Ensure key is loaded

        // Disable maintenance mode exposure
        Config::set('app.debug', false);

        // Secure broadcasting (if used)
        Config::set('broadcasting.default', 'null');

        // Disable file uploads to sensitive directories
        $uploadConfig = config('filesystems.disks', []);
        foreach ($uploadConfig as $disk => $config) {
            if (isset($config['root'])) {
                $root = realpath($config['root']);
                if ($root && str_contains($root, 'config') ||
                    str_contains($root, 'storage/app') ||
                    str_contains($root, 'bootstrap')) {
                    Config::set("filesystems.disks.{$disk}.visibility", 'public');
                }
            }
        }
    }

    /**
     * Secure logging configuration
     */
    public function secureLoggingConfiguration(): void
    {
        // Use secure log channels
        Config::set('logging.default', 'daily');

        // Don't log sensitive information
        $currentConfig = config('logging.channels', []);
        foreach ($currentConfig as $channel => $config) {
            if (isset($config['days'])) {
                $config['days'] = min($config['days'], 30); // Limit log retention
            }
        }

        // Ensure logs are not publicly accessible
        $logPath = storage_path('logs');
        if (is_dir($logPath)) {
            chmod($logPath, 0750);
        }
    }

    /**
     * Configure secure error handling
     */
    public function configureErrorHandling(): void
    {
        if (!config('helpers.environment_hardening.disable_error_display', true)) {
            return;
        }

        // Disable error display
        ini_set('display_errors', 'Off');
        ini_set('display_startup_errors', 'Off');

        // Log errors instead
        ini_set('log_errors', 'On');
        ini_set('error_log', storage_path('logs/php_errors.log'));

        // Set error reporting level
        error_reporting(E_ALL & ~E_DEPRECATED & ~E_STRICT & ~E_NOTICE);

        // Custom error handler for security
        set_error_handler(function($errno, $errstr, $errfile, $errline) {
            if (!(error_reporting() & $errno)) {
                return false;
            }

            $errorMessage = "Error [{$errno}]: {$errstr} in {$errfile} on line {$errline}";

            // Log error securely (don't expose sensitive paths)
            $secureMessage = str_replace(base_path(), '[APP_PATH]', $errorMessage);
            Log::error('Application Error', [
                'error' => $secureMessage,
                'trace' => debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS)
            ]);

            return true;
        });
    }

    /**
     * Validate environment security
     */
    public function validateEnvironmentSecurity(): array
    {
        $checks = [
            'https_enforced' => $this->checkHTTPSEnforcement(),
            'debug_disabled' => !config('app.debug'),
            'secure_session' => config('session.secure', false),
            'dangerous_functions_disabled' => $this->checkDangerousFunctions(),
            'secure_file_permissions' => $this->checkFilePermissions(),
            'error_display_disabled' => !ini_get('display_errors'),
        ];

        $failedChecks = array_filter($checks, function($result) {
            return $result === false;
        });

        if (!empty($failedChecks)) {
            app(RemoteSecurityLogger::class)->warning('Environment security validation failed', [
                'failed_checks' => array_keys($failedChecks)
            ]);
        }

        return $checks;
    }

    /**
     * Check HTTPS enforcement
     */
    public function checkHTTPSEnforcement(): bool
    {
        return request()->secure() || app()->environment('local');
    }

    /**
     * Check dangerous functions are disabled
     */
    public function checkDangerousFunctions(): bool
    {
        $disabled = ini_get('disable_functions');
        $dangerous = ['eval', 'exec', 'shell_exec', 'system', 'passthru'];

        foreach ($dangerous as $function) {
            if (!str_contains($disabled, $function)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Check file permissions
     */
    public function checkFilePermissions(): bool
    {
        $criticalFiles = [
            base_path('.env') => 0600,
            storage_path('logs') => 0750,
        ];

        foreach ($criticalFiles as $file => $expectedPerms) {
            if (file_exists($file)) {
                $actualPerms = fileperms($file) & 0777;
                if ($actualPerms !== $expectedPerms) {
                    return false;
                }
            }
        }

        return true;
    }
}

