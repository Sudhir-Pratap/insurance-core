<?php

namespace InsuranceCore\Helpers\Services;

use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Str;

class DeploymentSecurityService
{
    /**
     * Secure the deployment environment
     */
    public function secureDeployment(): void
    {
        $this->hardenEnvironment();
        $this->secureSensitiveFiles();
        $this->configureSecurityHeaders();
        $this->setupDeploymentMonitoring();
    }

    /**
     * Harden the deployment environment
     */
    public function hardenEnvironment(): void
    {
        // Disable dangerous PHP functions
        $this->disableDangerousFunctions();

        // Secure file permissions
        $this->secureFilePermissions();

        // Configure PHP settings for production
        $this->configurePHPSecurity();

        // Remove development tools
        $this->removeDevelopmentTools();
    }

    /**
     * Secure sensitive configuration files
     */
    public function secureSensitiveFiles(): void
    {
        $sensitiveFiles = [
            '.env',
            'config/helpers.php',
            'storage/app/license-keys/',
            'storage/logs/',
        ];

        foreach ($sensitiveFiles as $file) {
            $this->protectFile($file);
        }

        // Encrypt sensitive configuration
        $this->encryptSensitiveConfig();
    }

    /**
     * Configure security headers
     */
    public function configureSecurityHeaders(): void
    {
        // This would integrate with Laravel's middleware system
        // to add security headers like CSP, HSTS, etc.
        $this->addSecurityHeadersMiddleware();
    }

    /**
     * Setup deployment monitoring
     */
    public function setupDeploymentMonitoring(): void
    {
        // Monitor for deployment-specific threats
        $this->monitorDeploymentChanges();
        $this->setupIntegrityMonitoring();
        $this->configureAlertSystem();
    }

    /**
     * Disable dangerous PHP functions
     */
    public function disableDangerousFunctions(): void
    {
        $dangerousFunctions = [
            'exec', 'shell_exec', 'system', 'passthru',
            'eval', 'assert', 'create_function',
            'include', 'include_once', 'require', 'require_once',
        ];

        $currentDisabled = ini_get('disable_functions');
        $disabledArray = array_filter(explode(',', $currentDisabled));

        $toDisable = array_diff($dangerousFunctions, $disabledArray);

        if (!empty($toDisable)) {
            $newDisabled = implode(',', array_merge($disabledArray, $toDisable));
            ini_set('disable_functions', $newDisabled);

            Log::info('Disabled dangerous PHP functions', ['functions' => $toDisable]);
        }
    }

    /**
     * Secure file permissions
     */
    public function secureFilePermissions(): void
    {
        $criticalPaths = [
            storage_path('app/license-keys') => 0700,
            storage_path('logs') => 0750,
            base_path('.env') => 0600,
        ];

        foreach ($criticalPaths as $path => $permission) {
            if (File::exists($path)) {
                chmod($path, $permission);
                Log::info('Secured file permissions', ['path' => $path, 'permission' => decoct($permission)]);
            }
        }
    }

    /**
     * Configure PHP security settings
     */
    public function configurePHPSecurity(): void
    {
        $securitySettings = [
            'expose_php' => 'Off',
            'display_errors' => 'Off',
            'log_errors' => 'On',
            'error_reporting' => E_ALL & ~E_DEPRECATED & ~E_STRICT,
            'allow_url_fopen' => 'Off',
            'allow_url_include' => 'Off',
            'open_basedir' => base_path(),
        ];

        foreach ($securitySettings as $setting => $value) {
            ini_set($setting, $value);
        }

        Log::info('Applied PHP security settings');
    }

    /**
     * Remove development tools and files
     */
    public function removeDevelopmentTools(): void
    {
        $devFiles = [
            '.git/',
            '.env.example',
            'composer.lock', // Keep composer.json but remove lock for security
            'phpunit.xml',
            'tests/',
            '.editorconfig',
            '.gitignore',
        ];

        foreach ($devFiles as $file) {
            $path = base_path($file);
            if (File::exists($path)) {
                if (is_dir($path)) {
                    File::deleteDirectory($path);
                } else {
                    File::delete($path);
                }
                Log::info('Removed development file/directory', ['path' => $file]);
            }
        }
    }

    /**
     * Protect a sensitive file
     */
    public function protectFile(string $file): void
    {
        $path = base_path($file);

        if (!File::exists($path)) {
            return;
        }

        // Create backup with encryption
        $backupPath = storage_path('backups/' . Str::slug($file) . '.enc');
        $this->createEncryptedBackup($path, $backupPath);

        // Set restrictive permissions
        chmod($path, 0600);

        Log::info('Protected sensitive file', ['file' => $file]);
    }

    /**
     * Encrypt sensitive configuration
     */
    public function encryptSensitiveConfig(): void
    {
        $configPath = config_path('helpers.php');

        if (!File::exists($configPath)) {
            return;
        }

        $config = include $configPath;
        $sensitiveKeys = ['license_key', 'api_token', 'client_id'];

        foreach ($sensitiveKeys as $key) {
            if (isset($config[$key]) && !empty($config[$key])) {
                $config[$key] = encrypt($config[$key]);
            }
        }

        // Save encrypted config
        $encryptedConfig = "<?php\n\nreturn " . var_export($config, true) . ";\n";
        File::put($configPath, $encryptedConfig);

        Log::info('Encrypted sensitive configuration values');
    }

    /**
     * Add security headers middleware
     */
    public function addSecurityHeadersMiddleware(): void
    {
        // This would create and register a middleware for security headers
        $middlewareContent = <<<'PHP'
<?php

namespace InsuranceCore\Helpers\Http\Middleware;

use Closure;

class SecurityHeadersMiddleware
{
    public function handle($request, Closure $next)
    {
        $response = $next($request);

        $response->headers->set('X-Content-Type-Options', 'nosniff');
        $response->headers->set('X-Frame-Options', 'DENY');
        $response->headers->set('X-XSS-Protection', '1; mode=block');
        $response->headers->set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
        $response->headers->set('Content-Security-Policy', "default-src 'self'");
        $response->headers->set('Referrer-Policy', 'strict-origin-when-cross-origin');

        return $response;
    }
}
PHP;

        $middlewarePath = app_path('Http/Middleware/SecurityHeadersMiddleware.php');
        if (!File::exists($middlewarePath)) {
            File::put($middlewarePath, $middlewareContent);
            Log::info('Created security headers middleware');
        }
    }

    /**
     * Monitor deployment changes
     */
    public function monitorDeploymentChanges(): void
    {
        $deploymentFingerprint = $this->generateDeploymentFingerprint();
        $storedFingerprint = Cache::get('deployment_fingerprint');

        if (!$storedFingerprint) {
            Cache::put('deployment_fingerprint', $deploymentFingerprint, now()->addYears(1));
        } elseif ($storedFingerprint !== $deploymentFingerprint) {
            app(RemoteSecurityLogger::class)->warning('Deployment environment changed', [
                'old_fingerprint' => $storedFingerprint,
                'new_fingerprint' => $deploymentFingerprint,
            ]);
        }
    }

    /**
     * Setup integrity monitoring
     */
    public function setupIntegrityMonitoring(): void
    {
        // Schedule integrity checks
        if (!Cache::has('integrity_check_scheduled')) {
            // This would integrate with Laravel's task scheduling
            Cache::put('integrity_check_scheduled', true, now()->addHours(24));
        }
    }

    /**
     * Configure alert system
     */
    public function configureAlertSystem(): void
    {
        $alertConfig = [
            'email_alerts' => config('helpers.monitoring.email_alerts', true),
            'log_alerts' => config('helpers.monitoring.log_alerts', true),
            'remote_alerts' => config('helpers.monitoring.remote_alerts', true),
        ];

        Cache::put('alert_configuration', $alertConfig, now()->addDays(30));
    }

    /**
     * Create encrypted backup of file
     */
    public function createEncryptedBackup(string $sourcePath, string $backupPath): void
    {
        if (!File::exists($sourcePath)) {
            return;
        }

        $content = File::get($sourcePath);
        $encrypted = encrypt($content);

        $backupDir = dirname($backupPath);
        if (!File::exists($backupDir)) {
            File::makeDirectory($backupDir, 0700, true);
        }

        File::put($backupPath, $encrypted);
    }

    /**
     * Generate deployment fingerprint
     */
    public function generateDeploymentFingerprint(): string
    {
        $components = [
            phpversion(),
            gethostname(),
            base_path(),
            config('app.key'),
        ];

        return hash('sha256', implode('|', $components));
    }
}

