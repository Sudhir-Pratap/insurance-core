<?php

namespace InsuranceCore\Utils\Services;

use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Cache;

class RemoteSecurityLogger
{
    protected $validationServer;
    protected $apiToken;
    protected $systemKey;
    protected $clientId;
    
    public function __construct()
    {
        $this->validationServer = config('utils.validation_server');
        $this->apiToken = config('utils.api_token');
        $this->systemKey = config('utils.system_key');
        $this->clientId = config('utils.client_id');
    }

    /**
     * Send security log to validation server
     * Returns true if successfully sent, false otherwise
     */
    public function log($level, $message, array $context = []): bool
    {
        // Don't send if remote logging is disabled
        if (!config('utils.remote_security_logging', true)) {
            return false;
        }

        // Send all security logs including info for comprehensive monitoring
        $securityLevels = ['critical', 'alert', 'error', 'warning', 'info'];
        if (!in_array(strtolower($level), $securityLevels)) {
            return false;
        }

        try {
            // Prepare log data
            $logData = [
                'level' => $level,
                'message' => $message,
                'context' => $context,
                'system_key' => $this->systemKey,
                'client_id' => $this->clientId,
                'product_id' => config('utils.product_id'),
                'domain' => request()->getHost() ?? 'unknown',
                'ip_address' => request()->ip() ?? 'unknown',
                'user_agent' => request()->userAgent() ?? 'unknown',
                'timestamp' => now()->toISOString(),
                'installation_id' => Cache::get('installation_id') ?? 'unknown',
                'hardware_fingerprint' => substr(config('utils.system_key') ? md5(config('utils.system_key')) : 'unknown', 0, 16),
            ];

            // Send to validation server asynchronously (don't block request)
            $this->sendAsync($logData);

            return true;
        } catch (\Exception $e) {
            // Silently fail - don't break application if logging fails
            // Only log locally if not in stealth mode
            if (!config('utils.stealth.mute_logs', false)) {
                Log::debug('Failed to send security log to server', [
                    'error' => $e->getMessage()
                ]);
            }
            return false;
        }
    }

    /**
     * Send log data asynchronously (fire and forget - never blocks client)
     */
    protected function sendAsync(array $logData): void
    {
        // Always send asynchronously to avoid blocking client requests
        // Use queue if available, otherwise use a very short timeout HTTP call
        
        // Option 1: Queue job (best - truly async, no delay)
        if (function_exists('dispatch') && class_exists(\Illuminate\Queue\QueueManager::class)) {
            try {
                dispatch(function () use ($logData) {
                    $this->sendToServer($logData);
                })->afterResponse();
                return; // Successfully queued
            } catch (\Exception $e) {
                // Queue failed, fall through to HTTP
            }
        }

        // Option 2: HTTP with minimal timeout (non-blocking, fire-and-forget)
        // Use stream context to make it truly non-blocking
        $this->sendNonBlocking($logData);
    }

    /**
     * Send log non-blocking via HTTP (fire and forget)
     */
    protected function sendNonBlocking(array $logData): void
    {
        // Send in background without waiting for response
        try {
            $endpoint = rtrim($this->validationServer, '/') . '/api/report-suspicious';
            $payload = [
                'system_key' => $logData['system_key'] ?? $this->systemKey,
                'client_id' => $logData['client_id'] ?? $this->clientId,
                'violation_type' => 'security_log_' . $logData['level'],
                'suspicion_score' => $this->calculateSuspicionScore($logData['level']),
                'violation_data' => json_encode([
                    'log_message' => $logData['message'],
                    'log_context' => $logData['context'],
                    'timestamp' => $logData['timestamp'],
                    'domain' => $logData['domain'],
                    'ip_address' => $logData['ip_address'],
                ]),
                'domain' => $logData['domain'],
                'ip_address' => $logData['ip_address'],
                'user_agent' => $logData['user_agent'],
            ];

            // Use Http::asJson()->post() with very short timeout (doesn't block)
            Http::withHeaders([
                'Authorization' => 'Bearer ' . $this->apiToken,
                'Content-Type' => 'application/json',
            ])->timeout(1) // 1 second max - won't block long
              ->connectTimeout(1)
              ->post($endpoint, $payload);
        } catch (\Exception $e) {
            // Silently cache for retry - never show error to client
            $this->cacheFailedLog($logData);
        }
    }

    /**
     * Actually send the log to the server
     */
    protected function sendToServer(array $logData): void
    {
        try {
            $endpoint = rtrim($this->validationServer, '/') . '/api/report-suspicious';
            
            $response = Http::withHeaders([
                'Authorization' => 'Bearer ' . $this->apiToken,
                'Content-Type' => 'application/json',
            ])->timeout(3) // Short timeout - don't delay
              ->post($endpoint, [
                'system_key' => $logData['system_key'] ?? $this->systemKey,
                'client_id' => $logData['client_id'] ?? $this->clientId,
                'violation_type' => 'security_log_' . $logData['level'],
                'suspicion_score' => $this->calculateSuspicionScore($logData['level']),
                'violation_data' => json_encode([
                    'log_message' => $logData['message'],
                    'log_context' => $logData['context'],
                    'timestamp' => $logData['timestamp'],
                    'domain' => $logData['domain'],
                    'ip_address' => $logData['ip_address'],
                ]),
                'domain' => $logData['domain'],
                'ip_address' => $logData['ip_address'],
                'user_agent' => $logData['user_agent'],
            ]);

            // Only log locally if response failed and not in stealth mode
            if (!$response->successful() && !config('utils.stealth.mute_logs', false)) {
                Log::debug('Security log server response', [
                    'status' => $response->status(),
                    'body' => $response->body()
                ]);
            }
        } catch (\Exception $e) {
            // Silently fail - don't break application
            // Cache failed logs locally for later retry (optional)
            $this->cacheFailedLog($logData);
        }
    }

    /**
     * Calculate suspicion score based on log level
     */
    protected function calculateSuspicionScore(string $level): int
    {
        return match(strtolower($level)) {
            'critical' => 30,
            'alert' => 25,
            'error' => 15,
            'warning' => 10,
            default => 5,
        };
    }

    /**
     * Cache failed logs for retry (optional - prevents log loss)
     */
    protected function cacheFailedLog(array $logData): void
    {
        // Only cache critical/alert logs for retry
        if (!in_array(strtolower($logData['level']), ['critical', 'alert'])) {
            return;
        }

        $cacheKey = 'pending_security_logs_' . md5($this->systemKey);
        $pendingLogs = Cache::get($cacheKey, []);
        
        // Limit cached logs (keep last 50)
        $pendingLogs[] = $logData;
        if (count($pendingLogs) > 50) {
            $pendingLogs = array_slice($pendingLogs, -50);
        }
        
        Cache::put($cacheKey, $pendingLogs, now()->addHours(24));
    }

    /**
     * Retry sending cached logs
     */
    public function retryFailedLogs(): void
    {
        $cacheKey = 'pending_security_logs_' . md5($this->systemKey);
        $pendingLogs = Cache::get($cacheKey, []);
        
        if (empty($pendingLogs)) {
            return;
        }

        foreach ($pendingLogs as $logData) {
            $this->sendToServer($logData);
        }

        // Clear after attempt
        Cache::forget($cacheKey);
    }

    /**
     * Convenience methods for different log levels
     */
    public function critical(string $message, array $context = []): bool
    {
        return $this->log('critical', $message, $context);
    }

    public function alert(string $message, array $context = []): bool
    {
        return $this->log('alert', $message, $context);
    }

    public function error(string $message, array $context = []): bool
    {
        return $this->log('error', $message, $context);
    }

    public function warning(string $message, array $context = []): bool
    {
        return $this->log('warning', $message, $context);
    }

    public function info(string $message, array $context = []): bool
    {
        return $this->log('info', $message, $context);
    }

    /**
     * Log validation attempt (always log, even successful)
     */
    public function logValidationAttempt(array $data): void
    {
        $this->log('info', 'System validation attempt', [
            'validation_result' => $data['result'] ?? 'unknown',
            'used_cache' => $data['used_cache'] ?? false,
            'used_grace_period' => $data['used_grace_period'] ?? false,
            'server_reachable' => $data['server_reachable'] ?? true,
            'product_id' => $data['product_id'] ?? null,
            'domain' => $data['domain'] ?? null,
            'ip' => $data['ip'] ?? null,
            'hardware_fingerprint' => isset($data['hardware_fingerprint']) ? substr($data['hardware_fingerprint'], 0, 16) . '...' : null,
            'installation_id' => $data['installation_id'] ?? null,
            'failure_reason' => $data['failure_reason'] ?? null,
        ]);
    }

    /**
     * Log middleware check (always log, even when passing)
     */
    public function logMiddlewareCheck(array $data): void
    {
        $this->log('info', 'Middleware security check', [
            'check_type' => $data['check_type'] ?? 'unknown',
            'check_result' => $data['result'] ?? 'unknown',
            'middleware_registered' => $data['middleware_registered'] ?? false,
            'middleware_executing' => $data['middleware_executing'] ?? false,
            'middleware_commented' => $data['middleware_commented'] ?? false,
            'lenient_check_count' => $data['lenient_check_count'] ?? 0,
            'will_fail_after' => $data['will_fail_after'] ?? null,
        ]);
    }

    /**
     * Log file integrity check (always log)
     */
    public function logFileIntegrityCheck(array $data): void
    {
        $level = ($data['violation'] ?? false) ? 'warning' : 'info';
        $this->log($level, 'File integrity check', [
            'file_path' => isset($data['file_path']) ? basename($data['file_path']) : null,
            'check_result' => $data['result'] ?? 'unknown',
            'baseline_created' => $data['baseline_created'] ?? false,
            'file_modified' => $data['file_modified'] ?? false,
            'package_missing' => $data['package_missing'] ?? false,
            'expected_hash' => isset($data['expected_hash']) ? substr($data['expected_hash'], 0, 16) . '...' : null,
            'actual_hash' => isset($data['actual_hash']) ? substr($data['actual_hash'], 0, 16) . '...' : null,
        ]);
    }

    /**
     * Log reselling attempt (always log)
     */
    public function logResellingAttempt(array $data): void
    {
        $this->log('warning', 'Potential reselling detected', [
            'check_type' => $data['check_type'] ?? 'unknown',
            'multiple_installations' => $data['multiple_installations'] ?? false,
            'hardware_fingerprint_changed' => $data['hardware_fingerprint_changed'] ?? false,
            'domain_changed' => $data['domain_changed'] ?? false,
            'ip_changed' => $data['ip_changed'] ?? false,
            'installation_count' => $data['installation_count'] ?? 0,
            'similarity_percent' => $data['similarity_percent'] ?? null,
        ]);
    }

    /**
     * Log grace period activation
     */
    public function logGracePeriod(array $data): void
    {
        $this->log('info', 'Grace period activated', [
            'grace_period_type' => $data['type'] ?? 'unknown',
            'grace_period_hours' => $data['hours'] ?? 0,
            'reason' => $data['reason'] ?? null,
            'validation_result' => $data['validation_result'] ?? 'allowed',
        ]);
    }
}




