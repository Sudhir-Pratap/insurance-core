<?php

namespace InsuranceCore\Helpers\Commands;

use InsuranceCore\Helpers\Helper;
use Illuminate\Console\Command;

class LicenseInfoCommand extends Command
{
    protected $signature = 'helpers:info';
    protected $description = 'Display system information and identifiers';

    public function handle()
    {
        $manager = app(Helper::class);
        $fingerprint = $manager->generateHardwareFingerprint();
        $currentIp = $this->getServerIp();
        $installationId = $manager->getOrCreateInstallationId();
        $domain = $this->getServerDomain();
        
        $this->info('System Information:');
        $this->line('');
        $this->info('Hardware Fingerprint: ' . $fingerprint);
        $this->info('Installation ID: ' . $installationId);
        $this->info('Server IP: ' . $currentIp);
        $this->info('Domain: ' . $domain);
        
        // Show current configuration
        $this->line('');
        $this->info('Current Configuration:');
        $this->info('System Key: ' . (config('helpers.helper_key') ? 'Configured' : 'Not set'));
        $this->info('Product ID: ' . (config('helpers.product_id') ?: 'Not set'));
        $this->info('Client ID: ' . (config('helpers.client_id') ?: 'Not set'));
        $this->info('Server URL: ' . config('helpers.helper_server'));
        
        $this->line('');
        $this->info('Use this information to generate system configuration:');
        $this->info('php artisan helpers:generate --product-id=YOUR_PRODUCT_ID --domain=' . $domain . ' --ip=' . $currentIp . ' --client-id=YOUR_CLIENT_ID');
    }
    
    /**
     * Get the actual server IP address
     */
    protected function getServerIp(): string
    {
        // Try multiple methods to get the server IP
        $ip = null;
        
        // Method 1: Check $_SERVER['SERVER_ADDR'] (if available)
        if (isset($_SERVER['SERVER_ADDR']) && $_SERVER['SERVER_ADDR'] !== '127.0.0.1' && $_SERVER['SERVER_ADDR'] !== '::1') {
            $ip = $_SERVER['SERVER_ADDR'];
        }
        
        // Method 2: Try to get IP from hostname
        if (!$ip || $ip === '127.0.0.1') {
            try {
                $hostname = gethostname();
                $hostIp = gethostbyname($hostname);
                if ($hostIp && $hostIp !== $hostname && $hostIp !== '127.0.0.1' && $hostIp !== '::1') {
                    $ip = $hostIp;
                }
            } catch (\Exception $e) {
                // Ignore
            }
        }
        
        // Method 3: Try to get public IP via external service (as fallback)
        if (!$ip || $ip === '127.0.0.1') {
            try {
                $publicIp = @file_get_contents('https://api.ipify.org');
                if ($publicIp && filter_var($publicIp, FILTER_VALIDATE_IP)) {
                    $ip = $publicIp;
                }
            } catch (\Exception $e) {
                // Ignore
            }
        }
        
        // Method 4: Check network interfaces (Linux/Unix)
        if (!$ip || $ip === '127.0.0.1') {
            if (PHP_OS_FAMILY !== 'Windows') {
                try {
                    $output = shell_exec("hostname -I 2>/dev/null");
                    if ($output) {
                        $ips = explode(' ', trim($output));
                        foreach ($ips as $candidate) {
                            $candidate = trim($candidate);
                            if ($candidate && $candidate !== '127.0.0.1' && filter_var($candidate, FILTER_VALIDATE_IP)) {
                                $ip = $candidate;
                                break;
                            }
                        }
                    }
                } catch (\Exception $e) {
                    // Ignore
                }
            }
        }
        
        return $ip ?: '127.0.0.1';
    }
    
    /**
     * Get the server domain
     */
    protected function getServerDomain(): string
    {
        // Try to get from request if available
        if (app()->runningInConsole()) {
            // Check APP_URL from config
            $appUrl = config('app.url');
            if ($appUrl) {
                $parsed = parse_url($appUrl);
                if (isset($parsed['host'])) {
                    return $parsed['host'];
                }
            }
            
            // Try SERVER_NAME
            if (isset($_SERVER['SERVER_NAME'])) {
                return $_SERVER['SERVER_NAME'];
            }
            
            // Try HTTP_HOST
            if (isset($_SERVER['HTTP_HOST'])) {
                return $_SERVER['HTTP_HOST'];
            }
            
            return 'localhost';
        }
        
        return request()->getHost() ?: 'localhost';
    }
}



