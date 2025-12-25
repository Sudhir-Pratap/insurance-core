<?php

namespace InsuranceCore\Utils\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Config;
use InsuranceCore\Utils\Http\Middleware\StealthProtectionMiddleware;
use InsuranceCore\Utils\Http\Middleware\AntiPiracySecurity;
use InsuranceCore\Utils\Http\Middleware\SecurityProtection;

class StealthInstallCommand extends Command
{
    protected $signature = 'utils:install
                           {--config : Generate installation configuration} 
                           {--check : Check installation setup}
                           {--enable : Enable silent mode}
                           {--disable : Disable silent mode}';
    
    protected $description = 'Setup silent system installation';

    public function handle()
    {
        if ($this->option('config')) {
            $this->generateStealthConfig();
        }
        
        if ($this->option('check')) {
            $this->checkStealthSetup();
        }
        
        if ($this->option('enable')) {
            $this->enableStealthMode();
        }
        
        if ($this->option('disable')) {
            $this->disableStealthMode();
        }
        
        if (!$this->option('config') && !$this->option('check') && !$this->option('enable') && !$this->option('disable')) {
            $this->showStealthHelp();
        }
    }

    public function generateStealthConfig()
    {
        $this->info('=== Silent Installation Configuration ===');
        $this->line('');
        
        $config = [
            'STEALTH_MODE_ENABLED' => 'UTILS_STEALTH_MODE=true',
            'HIDE_UI_ELEMENTS' => 'UTILS_HIDE_UI=true',
            'MUTE_LOG_OUTPUT' => 'UTILS_MUTE_LOGS=true',
            'BACKGROUND_VALIDATION' => 'UTILS_BACKGROUND_VALIDATION=true',
            'QUICK_TIMEOUT' => 'UTILS_VALIDATION_TIMEOUT=5',
            'GRACE_PERIOD' => 'UTILS_GRACE_PERIOD=72',
            'SILENT_FAILURE' => 'UTILS_SILENT_FAIL=true',
            'DEFERRED_ENFORCEMENT' => 'UTILS_DEFERRED_ENFORCEMENT=true',
        ];
        
        $this->info('Add these variables to your .env file:');
        $this->line('');
        
        foreach ($config as $description => $setting) {
            $this->line("{$setting}  # {$description}");
        }
        
        $this->line('');
        $this->info('Middleware setup (in routes files):');
        $this->line("Route::middleware(['utils-stealth'])->group(function () {");
        $this->line("    // Your routes here");
        $this->line("});");
        
        $this->line('');
        $this->info('Auto-register (add to .env):');
        $this->line('UTILS_AUTO_MIDDLEWARE=true');
        
        $this->line('');
        $this->info('Logging setup (in config/logging.php):');
        $this->line("'system' => [");
        $this->line("    'driver' => 'single',");
        $this->line("    'path' => storage_path('logs/system.log'),");
        $this->line("],");
    }

    public function checkStealthSetup()
    {
        $this->info('=== Stealth Mode Status Check ===');
        $this->line('');
        
        // Check stealth mode status
        $stealthEnabled = config('utils.stealth.enabled', false);
        $this->line('Stealth Mode: ' . ($stealthEnabled ? '✅ Enabled' : '❌ Disabled'));
        
        // Check individual stealth settings
        $settings = [
            'Hide UI Elements' => config('utils.stealth.hide_ui_elements', false),
            'Mute Logs' => config('utils.stealth.mute_logs', false),
            'Background Validation' => config('utils.stealth.background_validation', false),
            'Silent Fail' => config('utils.stealth.silent_fail', false),
            'Deferred Enforcement' => config('utils.stealth.deferred_enforcement', false),
        ];
        
        $this->line('');
        $this->info('Individual Settings:');
        foreach ($settings as $setting => $value) {
            $this->line($setting . ': ' . ($value ? '✅' : '❌'));
        }
        
        // Check grace period
        $gracePeriod = config('utils.stealth.fallback_grace_period', 72);
        $this->line('');
        $this->line("Grace Period: {$gracePeriod} hours");
        
        // Check validation timeout
        $timeout = config('utils.stealth.validation_timeout', 5);
        $this->line("Validation Timeout: {$timeout} seconds");
        
        // Check middleware registration
        $this->line('');
        $middlewareAliases = [];
        $router = app('router');
        if (is_callable([$router, 'getMiddleware'])) {
            $middlewareAliases = $router->getMiddleware();
        } else {
            // Laravel 11+ alternative: get middleware aliases via middlewareAliases property
            try {
                $reflection = new \ReflectionClass($router);
                if ($reflection->hasProperty('middlewareAliases')) {
                    $property = $reflection->getProperty('middlewareAliases');
                    $property->setAccessible(true);
                    $middlewareAliases = $property->getValue($router) ?? [];
                }
            } catch (\ReflectionException $e) {
                // If reflection fails, just use empty array
                $middlewareAliases = [];
            }
        }
        
        // Get global middleware from Kernel (Laravel 11+ uses different method)
        $kernel = app('Illuminate\Contracts\Http\Kernel');
        $globalMiddleware = [];
        
        // Try different methods to get global middleware
        if (is_callable([$kernel, 'getMiddleware'])) {
            $globalMiddleware = $kernel->getMiddleware();
        } else {
            // Fallback: Use reflection to access protected $middleware property
            try {
                $reflection = new \ReflectionClass($kernel);
                if ($reflection->hasProperty('middleware')) {
                    $property = $reflection->getProperty('middleware');
                    $property->setAccessible(true);
                    $globalMiddleware = $property->getValue($kernel) ?? [];
                }
            } catch (\Exception $e) {
                // If reflection fails, check via router middleware groups
                $globalMiddleware = [];
            }
        }
        
        // Convert to array if needed and flatten
        if (!is_array($globalMiddleware)) {
            $globalMiddleware = [];
        }
        $globalMiddlewareFlat = [];
        foreach ($globalMiddleware as $item) {
            if (is_string($item)) {
                $globalMiddlewareFlat[] = $item;
            } elseif (is_array($item)) {
                $globalMiddlewareFlat = array_merge($globalMiddlewareFlat, $item);
            }
        }
        
        $hasStealthAlias = isset($middlewareAliases['system-stealth']);
        $hasAntiPiracyAlias = isset($middlewareAliases['system-anti-piracy']);
        $hasSystemAlias = isset($middlewareAliases['system-security']);
        
        // Check using class names (handle with or without leading backslash)
        $antiPiracyFullName = '\\' . AntiPiracySecurity::class;
        $stealthFullName = '\\' . StealthProtectionMiddleware::class;
        $systemFullName = '\\' . SecurityProtection::class;
        
        $hasStealthClass = in_array(StealthProtectionMiddleware::class, $globalMiddlewareFlat) || 
                          in_array($stealthFullName, $globalMiddlewareFlat);
        $hasAntiPiracyClass = in_array(AntiPiracySecurity::class, $globalMiddlewareFlat) || 
                             in_array($antiPiracyFullName, $globalMiddlewareFlat) ||
                             str_contains(json_encode($globalMiddlewareFlat), 'AntiPiracySecurity');
        $hasSystemClass = in_array(SecurityProtection::class, $globalMiddlewareFlat) || 
                          in_array($systemFullName, $globalMiddlewareFlat);
        
        // Check Kernel.php file directly (most reliable - doesn't depend on runtime registration)
        $kernelPath = app_path('Http/Kernel.php');
        $hasInKernelFile = false;
        $kernelContent = '';
        
        if (file_exists($kernelPath)) {
            $kernelContent = @file_get_contents($kernelPath);
            
            // Simple check: look for the middleware class names
            // This works even if middleware is registered in Kernel.php directly
            $hasInKernelFile = (
                stripos($kernelContent, 'AntiPiracySecurity') !== false ||
                stripos($kernelContent, 'StealthProtectionMiddleware') !== false ||
                stripos($kernelContent, 'SecurityProtection') !== false
            );
        }
        
            $hasMiddleware = $hasStealthAlias || $hasAntiPiracyAlias || $hasSecurityAlias || 
                        $hasStealthClass || $hasAntiPiracyClass || $hasSecurityClass ||
                        $hasInKernelFile;
        
        $this->line('Stealth Middleware Registered: ' . ($hasMiddleware ? '✅' : '❌'));
        if ($hasMiddleware) {
            $methods = [];
            if ($hasStealthAlias) $methods[] = 'system-stealth alias';
            if ($hasAntiPiracyAlias) $methods[] = 'system-anti-piracy alias';
            if ($hasSystemAlias) $methods[] = 'system-security alias';
            if ($hasStealthClass) $methods[] = 'StealthProtectionMiddleware class';
            if ($hasAntiPiracyClass) $methods[] = 'AntiPiracySecurity class';
            if ($hasSecurityClass) $methods[] = 'SecurityProtection class';
            if ($hasInKernelFile) $methods[] = 'detected in Kernel.php file';
            $this->line('  Method: ' . implode(', ', $methods));
        } else {
            $this->warn('  Middleware not detected. Make sure it\'s registered in app/Http/Kernel.php');
            // Debug info
            $this->line('  Debug: Kernel.php exists = ' . (file_exists($kernelPath) ? 'Yes' : 'No'));
            if (file_exists($kernelPath)) {
                $this->line('  Debug: Kernel.php path = ' . $kernelPath);
                $this->line('  Debug: Contains AntiPiracySecurity = ' . (str_contains($kernelContent, 'AntiPiracySecurity') ? 'Yes' : 'No'));
            }
        }
        
        // Recommendations
        $this->line('');
        if (!$stealthEnabled || !$settings['Silent Fail']) {
            $this->warn('Recommendation: Enable stealth mode for silent operation');
        }
        
        if ($gracePeriod < 24) {
            $this->warn('Recommendation: Increase grace period to at least 24 hours');
        }
        
        if ($timeout > 10) {
            $this->warn('Recommendation: Reduce timeout to 5 seconds or less');
        }
    }

    public function enableStealthMode()
    {
        $this->info('Enabling Stealth Mode...');
        
        // Update running configuration
        config([
            'utils.stealth.enabled' => true,
            'utils.stealth.hide_ui_elements' => true,
            'utils.stealth.mute_logs' => true,
            'utils.stealth.background_validation' => true,
            'utils.stealth.silent_fail' => true,
            'utils.stealth.deferred_enforcement' => true,
            'utils.stealth.validation_timeout' => 5,
            'utils.stealth.fallback_grace_period' => 72,
        ]);
        
        $this->info('✅ Stealth mode enabled temporarily');
        $this->warn('⚠️  To persist changes, update your .env file with:');
        $this->line('UTILS_STEALTH_MODE=true');
        $this->line('UTILS_HIDE_UI=true');
        $this->line('UTILS_MUTE_LOGS=true');
        $this->line('UTILS_BACKGROUND_VALIDATION=true');
        $this->line('UTILS_SILENT_FAIL=true');
        $this->line('UTILS_DEFERRED_ENFORCEMENT=true');
        $this->line('UTILS_VALIDATION_TIMEOUT=5');
        $this->line('UTILS_GRACE_PERIOD=72');
    }

    public function disableStealthMode()
    {
        $this->info('Disabling Stealth Mode...');
        
        config([
            'utils.stealth.enabled' => false,
            'utils.stealth.hide_ui_elements' => false,
            'utils.stealth.mute_logs' => false,
            'utils.stealth.background_validation' => false,
            'utils.stealth.silent_fail' => false,
            'utils.stealth.deferred_enforcement' => false,
        ]);
        
        $this->info('✅ Stealth mode disabled temporarily');
        $this->warn('⚠️  To persist changes, update your .env file with:');
        $this->line('UTILS_STEALTH_MODE=false');
    }

    public function showStealthHelp()
    {
        $this->info('Stealth System Installation Tool');
        $this->line('');
        $this->info('This tool helps you install system validation that is:');
        $this->line('• Transparent to end users');
        $this->line('• Never shows system error messages');
        $this->line('• Validates in background without blocking requests');
        $this->line('• Has graceful fallbacks when offline');
        $this->line('• Operates without user knowledge');
        $this->line('');
        $this->info('Available commands:');
        $this->line('--config : Generate stealth configuration');
        $this->line('--check  : Check current stealth setup');
        $this->line('--enable : Enable stealth mode');
        $this->line('--disable: Disable stealth mode');
        $this->line('');
        $this->info('Examples:');
        $this->line('php artisan utils:install --config');
        $this->line('php artisan utils:install --enable --check');
    }
}

