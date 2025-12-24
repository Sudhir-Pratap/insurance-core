<?php

namespace Acme\Utils\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;

class ClearCacheCommand extends Command
{
    protected $signature = 'utils:clear-cache {--force : Force reset without confirmation}';
    protected $description = 'Clear system cache and identifiers';

    public function handle()
    {
        if (!$this->option('force')) {
            if (!$this->confirm('This will reset all system cache and system identifiers. Continue?')) {
                $this->info('Operation cancelled.');
                return 0;
            }
        }

        $this->info('Clearing system cache...');

        // Clear all system-related cache
        $cacheKeys = [
            'hardware_fingerprint',
            'installation_id',
            'last_validation_time',
        ];

        // Add system-specific cache keys
        $systemKey = config('utils.system_key');
        $productId = config('utils.product_id');
        $clientId = config('utils.client_id');

        if ($systemKey && $productId && $clientId) {
            $cacheKeys[] = "utils_valid_{$systemKey}_{$productId}_{$clientId}";
            $cacheKeys[] = "utils_last_check_{$systemKey}_{$productId}_{$clientId}";
            $cacheKeys[] = "utils_valid_{$systemKey}_{$productId}_{$clientId}_recent_success";
        }

        // Clear cache keys
        foreach ($cacheKeys as $key) {
            Cache::forget($key);
        }

        // Clear file hashes cache
        $criticalFiles = [
            'app/Http/Kernel.php',
            'config/app.php',
            'routes/web.php',
            'routes/agent.php',
        ];

        foreach ($criticalFiles as $file) {
            Cache::forget("file_hash_{$file}");
        }

        // Clear active installations cache
        if ($systemKey) {
            Cache::forget('active_utils_' . $systemKey);
        }

        // Clear IP blacklist
        $this->clearIpBlacklist();

        $this->info('System cache reset successfully!');
        $this->info('Hardware fingerprint will be regenerated on next request.');
        
        Log::info('System cache reset by command', [
            'user' => $this->getUserInfo(),
            'timestamp' => now()->toISOString(),
        ]);

        return 0;
    }

    public function clearIpBlacklist()
    {
        // Clear IP blacklist cache
        $blacklistPattern = 'blacklisted_ip_*';
        $keys = Cache::get('cache_keys', []);
        
        // This is a simplified approach - in production you might want to use Redis SCAN
        // or implement a more sophisticated cache key management
        foreach ($keys as $key) {
            if (str_starts_with($key, 'blacklisted_ip_')) {
                Cache::forget($key);
            }
        }
    }

    public function getUserInfo()
    {
        return [
            'ip' => request()->ip() ?? 'CLI',
            'user_agent' => request()->userAgent() ?? 'Artisan Command',
        ];
    }
} 


