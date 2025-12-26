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
     * PHASE 4: Send security log to validation server with enhanced structure
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
            // PHASE 4: Enhanced structured log data
            $logData = $this->prepareEnhancedLogData($level, $message, $context);

            // PHASE 4: Use batch reporting if enabled
            if (config('utils.remote_logging.batch_enabled', true)) {
                $this->addToBatch($logData);
            } else {
                // Send immediately (legacy behavior)
                $this->sendAsync($logData);
            }

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
     * PHASE 4: Prepare enhanced structured log data
     * 
     * @param string $level Log level
     * @param string $message Log message
     * @param array $context Additional context
     * @return array Enhanced log data structure
     */
    protected function prepareEnhancedLogData(string $level, string $message, array $context = []): array
    {
        // Get hardware fingerprint properly
        $hardwareFingerprint = 'unknown';
        try {
            $manager = app(\InsuranceCore\Utils\Manager::class);
            $hardwareFingerprint = substr($manager->generateHardwareFingerprint(), 0, 32);
        } catch (\Exception $e) {
            // Fallback if manager not available
        }

        // Enhanced structured log data
        return [
            // Core log information
            'level' => strtolower($level),
            'message' => $message,
            'timestamp' => now()->toISOString(),
            'timestamp_unix' => now()->timestamp,
            
            // System identification
            'system_key' => $this->systemKey,
            'client_id' => $this->clientId,
            'product_id' => config('utils.product_id'),
            'installation_id' => Cache::get('installation_id') ?? 'unknown',
            'hardware_fingerprint' => $hardwareFingerprint,
            
            // Request context
            'request' => [
                'domain' => request()->getHost() ?? 'unknown',
                'ip_address' => request()->ip() ?? 'unknown',
                'user_agent' => request()->userAgent() ?? 'unknown',
                'method' => request()->method() ?? 'unknown',
                'path' => request()->path() ?? 'unknown',
                'referer' => request()->header('referer'),
            ],
            
            // Enhanced context
            'context' => $this->enrichContext($context),
            
            // Metadata
            'metadata' => [
                'environment' => config('app.env', 'unknown'),
                'app_version' => config('app.version', 'unknown'),
                'laravel_version' => app()->version(),
                'php_version' => PHP_VERSION,
            ],
            
            // Logging metadata
            'log_metadata' => [
                'source' => 'insurance-core-utils',
                'version' => '4.1.9',
                'log_id' => $this->generateLogId(),
            ],
        ];
    }

    /**
     * PHASE 4: Enrich context with additional information
     * 
     * @param array $context Original context
     * @return array Enriched context
     */
    protected function enrichContext(array $context): array
    {
        // Add common context that might be missing
        if (!isset($context['session_id'])) {
            try {
                $context['session_id'] = session()->getId() ?? 'no-session';
            } catch (\Exception $e) {
                $context['session_id'] = 'session-unavailable';
            }
        }

        // Add validation state if available
        if (!isset($context['validation_state'])) {
            try {
                $context['validation_state'] = [
                    'middleware_enabled' => Cache::get('system_middleware_executed', false),
                    'last_validation' => Cache::get('last_validation_time'),
                ];
            } catch (\Exception $e) {
                // Skip if unavailable
            }
        }

        return $context;
    }

    /**
     * PHASE 4: Generate unique log ID for tracking
     * 
     * @return string Unique log ID
     */
    protected function generateLogId(): string
    {
        return md5(now()->toISOString() . uniqid('', true) . $this->systemKey);
    }

    /**
     * PHASE 4: Add log to batch queue for batch reporting
     * 
     * @param array $logData Log data to batch
     */
    protected function addToBatch(array $logData): void
    {
        $batchKey = 'security_logs_batch_' . md5($this->systemKey);
        $batch = Cache::get($batchKey, []);
        
        // Add log to batch
        $batch[] = $logData;
        
        // Get batch size limit (default: 10 logs per batch)
        $batchSize = config('utils.remote_logging.batch_size', 10);
        $batchTimeout = config('utils.remote_logging.batch_timeout', 60); // seconds
        
        // Check if batch should be sent
        $shouldSend = false;
        
        // Send if batch is full
        if (count($batch) >= $batchSize) {
            $shouldSend = true;
        }
        
        // Send if batch timeout reached
        $lastBatchTime = Cache::get('security_logs_batch_last_sent');
        if ($lastBatchTime) {
            $timeSinceLastBatch = now()->diffInSeconds($lastBatchTime);
            if ($timeSinceLastBatch >= $batchTimeout) {
                $shouldSend = true;
            }
        } else {
            // First log in batch - set timeout
            Cache::put('security_logs_batch_last_sent', now(), now()->addMinutes(5));
        }
        
        if ($shouldSend) {
            // Send batch and clear
            $this->sendBatch($batch);
            Cache::forget($batchKey);
            Cache::put('security_logs_batch_last_sent', now(), now()->addMinutes(5));
        } else {
            // Store batch for later
            Cache::put($batchKey, $batch, now()->addMinutes(5));
        }
    }

    /**
     * PHASE 4: Send batch of logs to server
     * 
     * @param array $batch Array of log data
     */
    protected function sendBatch(array $batch): void
    {
        if (empty($batch)) {
            return;
        }

        // Send batch asynchronously
        if (function_exists('dispatch') && class_exists(\Illuminate\Queue\QueueManager::class)) {
            try {
                dispatch(function () use ($batch) {
                    $this->sendBatchToServer($batch);
                })->afterResponse();
                return;
            } catch (\Exception $e) {
                // Queue failed, fall through to HTTP
            }
        }

        // Fallback: send via HTTP (non-blocking)
        $this->sendBatchNonBlocking($batch);
    }

    /**
     * PHASE 4: Actually send batch to server
     * 
     * @param array $batch Array of log data
     * @return bool True if successfully sent
     */
    protected function sendBatchToServer(array $batch): bool
    {
        try {
            $endpoint = rtrim($this->validationServer, '/') . '/api/report-batch';
            
            // Prepare batch payload
            $payload = [
                'system_key' => $this->systemKey,
                'client_id' => $this->clientId,
                'product_id' => config('utils.product_id'),
                'batch_size' => count($batch),
                'batch_timestamp' => now()->toISOString(),
                'logs' => $batch,
            ];

            $response = Http::withHeaders([
                'Authorization' => 'Bearer ' . $this->apiToken,
                'Content-Type' => 'application/json',
            ])->timeout(5) // Slightly longer timeout for batch
              ->connectTimeout(3)
              ->post($endpoint, $payload);

            if ($response->successful()) {
                // Track successful batch communication
                Cache::put('server_communication_last_success', now(), now()->addHours(24));
                Cache::put('batch_send_success_count', Cache::get('batch_send_success_count', 0) + 1, now()->addDays(1));
                return true;
            }

            // Batch failed - fall back to individual sends
            $this->fallbackToIndividualSends($batch);
            return false;
        } catch (\Exception $e) {
            // Batch failed - fall back to individual sends
            $this->fallbackToIndividualSends($batch);
            return false;
        }
    }

    /**
     * PHASE 4: Fallback to individual log sends if batch fails
     * 
     * @param array $batch Array of log data
     */
    protected function fallbackToIndividualSends(array $batch): void
    {
        // If batch fails, send logs individually (but still async)
        foreach ($batch as $logData) {
            try {
                $this->sendAsync($logData);
            } catch (\Exception $e) {
                // Cache for retry
                $this->cacheFailedLog($logData);
            }
        }
    }

    /**
     * PHASE 4: Send batch non-blocking via HTTP
     * 
     * @param array $batch Array of log data
     */
    protected function sendBatchNonBlocking(array $batch): void
    {
        try {
            $endpoint = rtrim($this->validationServer, '/') . '/api/report-batch';
            
            $payload = [
                'system_key' => $this->systemKey,
                'client_id' => $this->clientId,
                'product_id' => config('utils.product_id'),
                'batch_size' => count($batch),
                'batch_timestamp' => now()->toISOString(),
                'logs' => $batch,
            ];

            // Fire and forget
            Http::withHeaders([
                'Authorization' => 'Bearer ' . $this->apiToken,
                'Content-Type' => 'application/json',
            ])->timeout(1) // Very short timeout
              ->connectTimeout(1)
              ->post($endpoint, $payload);
        } catch (\Exception $e) {
            // Silently cache for retry
            foreach ($batch as $logData) {
                $this->cacheFailedLog($logData);
            }
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
     * PHASE 4: Send log non-blocking via HTTP (fire and forget)
     * Updated to use enhanced log structure
     */
    protected function sendNonBlocking(array $logData): void
    {
        // Send in background without waiting for response
        try {
            $endpoint = rtrim($this->validationServer, '/') . '/api/report-suspicious';
            
            // PHASE 4: Extract data from enhanced structure
            $request = $logData['request'] ?? [];
            $domain = $request['domain'] ?? $logData['domain'] ?? 'unknown';
            $ipAddress = $request['ip_address'] ?? $logData['ip_address'] ?? 'unknown';
            $userAgent = $request['user_agent'] ?? $logData['user_agent'] ?? 'unknown';
            
            $payload = [
                'system_key' => $logData['system_key'] ?? $this->systemKey,
                'client_id' => $logData['client_id'] ?? $this->clientId,
                'violation_type' => 'security_log_' . ($logData['level'] ?? 'info'),
                'suspicion_score' => $this->calculateSuspicionScore($logData['level'] ?? 'info'),
                'violation_data' => json_encode([
                    'log_message' => $logData['message'] ?? '',
                    'log_context' => $logData['context'] ?? [],
                    'timestamp' => $logData['timestamp'] ?? now()->toISOString(),
                    'domain' => $domain,
                    'ip_address' => $ipAddress,
                    'log_id' => $logData['log_metadata']['log_id'] ?? null,
                ]),
                'domain' => $domain,
                'ip_address' => $ipAddress,
                'user_agent' => $userAgent,
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
     * PHASE 4: Actually send the log to the server with enhanced error handling
     * Updated to use enhanced log structure
     * 
     * @param array $logData Log data to send
     * @return bool True if successfully sent
     */
    protected function sendToServer(array $logData): bool
    {
        try {
            $endpoint = rtrim($this->validationServer, '/') . '/api/report-suspicious';
            
            // PHASE 4: Extract data from enhanced structure
            $request = $logData['request'] ?? [];
            $domain = $request['domain'] ?? $logData['domain'] ?? 'unknown';
            $ipAddress = $request['ip_address'] ?? $logData['ip_address'] ?? 'unknown';
            $userAgent = $request['user_agent'] ?? $logData['user_agent'] ?? 'unknown';
            
            $response = Http::withHeaders([
                'Authorization' => 'Bearer ' . $this->apiToken,
                'Content-Type' => 'application/json',
            ])->timeout(3) // Short timeout - don't delay
              ->connectTimeout(2)
              ->post($endpoint, [
                'system_key' => $logData['system_key'] ?? $this->systemKey,
                'client_id' => $logData['client_id'] ?? $this->clientId,
                'violation_type' => 'security_log_' . ($logData['level'] ?? 'info'),
                'suspicion_score' => $this->calculateSuspicionScore($logData['level'] ?? 'info'),
                'violation_data' => json_encode([
                    'log_message' => $logData['message'] ?? '',
                    'log_context' => $logData['context'] ?? [],
                    'timestamp' => $logData['timestamp'] ?? now()->toISOString(),
                    'domain' => $domain,
                    'ip_address' => $ipAddress,
                    'log_id' => $logData['log_metadata']['log_id'] ?? null,
                    'metadata' => $logData['metadata'] ?? [],
                ]),
                'domain' => $domain,
                'ip_address' => $ipAddress,
                'user_agent' => $userAgent,
            ]);

            if ($response->successful()) {
                // Track successful communication
                Cache::put('server_communication_last_success', now(), now()->addHours(24));
                return true;
            }

            // Non-successful response - log and return false for retry
            if (!config('utils.stealth.mute_logs', false)) {
                Log::debug('Security log server response', [
                    'status' => $response->status(),
                    'body' => $response->body()
                ]);
            }
            return false;
        } catch (\Exception $e) {
            // Exception occurred - cache for retry and return false
            $this->cacheFailedLog($logData);
            return false;
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
     * PHASE 3: Retry sending cached logs with enhanced error recovery
     */
    public function retryFailedLogs(): void
    {
        $cacheKey = 'pending_security_logs_' . md5($this->systemKey);
        $pendingLogs = Cache::get($cacheKey, []);
        
        if (empty($pendingLogs)) {
            return;
        }

        $successCount = 0;
        $failedLogs = [];

        foreach ($pendingLogs as $index => $logData) {
            try {
                $success = $this->sendToServer($logData);
                if ($success) {
                    $successCount++;
                } else {
                    // Track failed logs with retry count
                    $logData['retry_count'] = ($logData['retry_count'] ?? 0) + 1;
                    $logData['last_retry'] = now()->toISOString();
                    
                    // Only keep logs that haven't exceeded max retries
                    $maxRetries = config('utils.remote_logging.max_retries', 5);
                    if ($logData['retry_count'] < $maxRetries) {
                        $failedLogs[] = $logData;
                    } else {
                        // Log exceeded max retries - log locally and discard
                        Log::warning('Security log exceeded max retries, discarding', [
                            'log_level' => $logData['level'] ?? 'unknown',
                            'retry_count' => $logData['retry_count'],
                        ]);
                    }
                }
            } catch (\Exception $e) {
                // Track exception and retry
                $logData['retry_count'] = ($logData['retry_count'] ?? 0) + 1;
                $logData['last_retry'] = now()->toISOString();
                $logData['last_error'] = $e->getMessage();
                
                $maxRetries = config('utils.remote_logging.max_retries', 5);
                if ($logData['retry_count'] < $maxRetries) {
                    $failedLogs[] = $logData;
                }
            }
        }

        // Update cache with failed logs (for next retry)
        if (!empty($failedLogs)) {
            Cache::put($cacheKey, $failedLogs, now()->addHours(24));
        } else {
            // All logs sent successfully - clear cache
            Cache::forget($cacheKey);
        }

        // Log retry results
        if ($successCount > 0 || !empty($failedLogs)) {
            Log::info('Retried failed security logs', [
                'successful' => $successCount,
                'failed' => count($failedLogs),
                'total' => count($pendingLogs),
            ]);
        }
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

    /**
     * PHASE 4: Flush pending batch logs (call on shutdown or periodically)
     * Useful for ensuring logs are sent before application shutdown
     */
    public function flushBatch(): void
    {
        $batchKey = 'security_logs_batch_' . md5($this->systemKey);
        $batch = Cache::get($batchKey, []);
        
        if (!empty($batch)) {
            $this->sendBatch($batch);
            Cache::forget($batchKey);
        }
    }

    /**
     * PHASE 4: Get batch statistics for monitoring
     * 
     * @return array Batch statistics
     */
    public function getBatchStats(): array
    {
        $batchKey = 'security_logs_batch_' . md5($this->systemKey);
        $batch = Cache::get($batchKey, []);
        
        return [
            'pending_logs' => count($batch),
            'batch_size_limit' => config('utils.remote_logging.batch_size', 10),
            'batch_timeout' => config('utils.remote_logging.batch_timeout', 60),
            'last_batch_sent' => Cache::get('security_logs_batch_last_sent'),
            'batch_enabled' => config('utils.remote_logging.batch_enabled', true),
            'success_count' => Cache::get('batch_send_success_count', 0),
        ];
    }
}




