<?php

namespace InsuranceCore\Helpers\Services;

use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Http;
use Carbon\Carbon;

class SecurityMonitoringService
{
    /**
     * Monitor security events and send alerts
     */
    public function monitorAndAlert(): void
    {
        $this->monitorLicenseViolations();
        $this->monitorSystemIntegrity();
        $this->monitorSuspiciousActivity();
        $this->sendScheduledAlerts();
        $this->cleanupOldAlerts();
    }

    /**
     * Monitor license violations
     */
    public function monitorLicenseViolations(): void
    {
        $violations = Cache::get('helper_violations', []);

        // Remove old violations (older than 24 hours)
        $violations = array_filter($violations, function($violation) {
            return Carbon::parse($violation['timestamp'])->isAfter(now()->subHours(24));
        });

        $violationCount = count($violations);
        $threshold = config('helpers.monitoring.alert_threshold', 5);

        if ($violationCount >= $threshold) {
            $this->sendAlert('High License Violation Rate', [
                'violation_count' => $violationCount,
                'threshold' => $threshold,
                'recent_violations' => array_slice($violations, -10), // Last 10 violations
            ], 'critical');
        }

        Cache::put('helper_violations', $violations, now()->addHours(24));
    }

    /**
     * Monitor system integrity
     */
    public function monitorSystemIntegrity(): void
    {
        $integrityChecks = [
            'file_integrity' => $this->checkFileIntegrity(),
            'config_integrity' => $this->checkConfigIntegrity(),
            'environment_security' => $this->checkEnvironmentSecurity(),
        ];

        $failedChecks = array_filter($integrityChecks, function($result) {
            return $result === false;
        });

        if (!empty($failedChecks)) {
            $this->sendAlert('System Integrity Compromised', [
                'failed_checks' => array_keys($failedChecks),
                'details' => $integrityChecks,
            ], 'critical');
        }
    }

    /**
     * Monitor suspicious activity
     */
    public function monitorSuspiciousActivity(): void
    {
        $suspiciousPatterns = [
            'multiple_ip_failures' => $this->checkMultipleIPFailures(),
            'rapid_requests' => $this->checkRapidRequests(),
            'unusual_times' => $this->checkUnusualAccessTimes(),
            'tampering_attempts' => $this->checkTamperingAttempts(),
        ];

        foreach ($suspiciousPatterns as $pattern => $detected) {
            if ($detected) {
                $this->sendAlert('Suspicious Activity Detected', [
                    'pattern' => $pattern,
                    'details' => $detected,
                ], 'warning');
            }
        }
    }

    /**
     * Send scheduled security reports
     */
    public function sendScheduledAlerts(): void
    {
        $lastReport = Cache::get('last_security_report');
        $reportInterval = config('helpers.monitoring.report_interval', 24); // hours

        if (!$lastReport || Carbon::parse($lastReport)->addHours($reportInterval)->isPast()) {
            $this->sendSecurityReport();
            Cache::put('last_security_report', now(), now()->addHours($reportInterval));
        }
    }

    /**
     * Send an alert through configured channels
     */
    public function sendAlert(string $title, array $data, string $severity = 'warning'): void
    {
        $alertKey = 'alert_' . md5($title . serialize($data));
        $lastSent = Cache::get($alertKey);

        // Prevent alert spam (same alert within 1 hour)
        if ($lastSent && Carbon::parse($lastSent)->addHour()->isFuture()) {
            return;
        }

        $alertData = [
            'title' => $title,
            'data' => $data,
            'severity' => $severity,
            'timestamp' => now(),
            'server_info' => [
                'host' => gethostname(),
                'ip' => request()->ip(),
                'environment' => app()->environment(),
            ],
        ];

        // Send through configured channels
        if (config('helpers.monitoring.email_alerts', true)) {
            $this->sendEmailAlert($alertData);
        }

        if (config('helpers.monitoring.log_alerts', true)) {
            $this->logAlert($alertData);
        }

        if (config('helpers.monitoring.remote_alerts', true)) {
            $this->sendRemoteAlert($alertData);
        }

        Cache::put($alertKey, now(), now()->addHour());
    }

    /**
     * Send email alert
     */
    public function sendEmailAlert(array $alertData): void
    {
        try {
            $alertEmail = config('helpers.monitoring.alert_email', 'security@insurance-core.com');

            // In a real implementation, you'd create a proper mail class
            Log::info('Security Alert Email', [
                'to' => $alertEmail,
                'subject' => "Security Alert: {$alertData['title']}",
                'data' => $alertData,
            ]);

        } catch (\Exception $e) {
            Log::error('Failed to send security email alert', [
                'error' => $e->getMessage(),
                'alert' => $alertData,
            ]);
        }
    }

    /**
     * Log alert to security log
     */
    public function logAlert(array $alertData): void
    {
        $logChannel = Log::channel('security');

        $message = "SECURITY ALERT [{$alertData['severity']}]: {$alertData['title']}";
        $context = array_merge($alertData['data'], [
            'server_info' => $alertData['server_info'],
            'alert_id' => uniqid('alert_', true),
        ]);

        match($alertData['severity']) {
            'critical' => $logChannel->error($message, $context),
            'warning' => $logChannel->warning($message, $context),
            default => $logChannel->info($message, $context),
        };
    }

    /**
     * Send alert to remote security service
     */
    public function sendRemoteAlert(array $alertData): void
    {
        try {
            $licenseServer = config('helpers.helper_server');
            $apiToken = config('helpers.api_token');

            Http::withHeaders([
                'Authorization' => 'Bearer ' . $apiToken,
            ])->timeout(10)->post("{$licenseServer}/api/security-alert", [
                'alert' => $alertData,
                'license_key' => config('helpers.helper_key'),
                'client_id' => config('helpers.client_id'),
            ]);

        } catch (\Exception $e) {
            Log::error('Failed to send remote security alert', [
                'error' => $e->getMessage(),
                'alert' => $alertData,
            ]);
        }
    }

    /**
     * Send comprehensive security report
     */
    public function sendSecurityReport(): void
    {
        $report = $this->generateSecurityReport();

        // Only send if there are significant issues or it's a weekly report
        $hasIssues = $report['critical_issues'] > 0 || $report['warnings'] > 0;

        if ($hasIssues || now()->dayOfWeek === 1) { // Weekly on Monday
            $this->sendAlert('Weekly Security Report', $report, 'info');
        }
    }

    /**
     * Generate comprehensive security report
     */
    public function generateSecurityReport(): array
    {
        return [
            'period' => 'last_24_hours',
            'critical_issues' => $this->countCriticalIssues(),
            'warnings' => $this->countWarnings(),
            'helper_violations' => count(Cache::get('helper_violations', [])),
            'suspicious_activities' => $this->countSuspiciousActivities(),
            'integrity_status' => $this->getIntegrityStatus(),
            'system_health' => $this->getSystemHealth(),
            'recommendations' => $this->generateRecommendations(),
        ];
    }

    /**
     * Check file integrity
     */
    public function checkFileIntegrity(): bool
    {
        $criticalFiles = [
            'composer.json',
            'config/app.php',
            'config/helpers.php',
        ];

        foreach ($criticalFiles as $file) {
            $filePath = base_path($file);
            if (file_exists($filePath)) {
                $storedHash = Cache::get("file_integrity_{$file}");
                $currentHash = hash_file('sha256', $filePath);

                if ($storedHash && $storedHash !== $currentHash) {
                    return false;
                }

                if (!$storedHash) {
                    Cache::put("file_integrity_{$file}", $currentHash, now()->addDays(30));
                }
            }
        }

        return true;
    }

    /**
     * Check configuration integrity
     */
    public function checkConfigIntegrity(): bool
    {
        // Check if sensitive config values are properly encrypted
        $sensitiveConfigs = [
            'helpers.license_key',
            'helpers.api_token',
            'helpers.client_id',
        ];

        foreach ($sensitiveConfigs as $config) {
            $value = config($config);
            if (!empty($value) && !str_starts_with($value, 'eyJ')) { // Not encrypted
                return false;
            }
        }

        return true;
    }

    /**
     * Check environment security
     */
    public function checkEnvironmentSecurity(): bool
    {
        return app(EnvironmentHardeningService::class)->validateEnvironmentSecurity();
    }

    /**
     * Check for multiple IP failures
     */
    public function checkMultipleIPFailures(): ?array
    {
        $ipFailures = Cache::get('ip_failure_counts', []);
        $suspiciousIPs = array_filter($ipFailures, function($count) {
            return $count > 10; // More than 10 failures per IP
        });

        return !empty($suspiciousIPs) ? ['suspicious_ips' => $suspiciousIPs] : null;
    }

    /**
     * Check for rapid requests
     */
    public function checkRapidRequests(): ?array
    {
        $requestCount = Cache::get('request_count_last_hour', 0);
        if ($requestCount > 1000) { // More than 1000 requests per hour
            return ['request_count' => $requestCount];
        }

        return null;
    }

    /**
     * Check for unusual access times
     */
    public function checkUnusualAccessTimes(): ?array
    {
        $accessTimes = Cache::get('access_times_today', []);
        $unusualHours = array_filter($accessTimes, function($count, $hour) {
            return intval($hour) < 6 || intval($hour) > 22; // Outside 6 AM - 10 PM
        }, ARRAY_FILTER_USE_BOTH);

        return !empty($unusualHours) ? ['unusual_hours' => $unusualHours] : null;
    }

    /**
     * Check for tampering attempts
     */
    public function checkTamperingAttempts(): ?array
    {
        $tamperingAttempts = Cache::get('tampering_attempts', 0);
        if ($tamperingAttempts > 0) {
            return ['attempts' => $tamperingAttempts];
        }

        return null;
    }

    /**
     * Count critical issues
     */
    public function countCriticalIssues(): int
    {
        $criticalEvents = Cache::get('critical_security_events', []);
        return count(array_filter($criticalEvents, function($event) {
            return Carbon::parse($event['timestamp'])->isAfter(now()->subHours(24));
        }));
    }

    /**
     * Count warnings
     */
    public function countWarnings(): int
    {
        $warningEvents = Cache::get('warning_security_events', []);
        return count(array_filter($warningEvents, function($event) {
            return Carbon::parse($event['timestamp'])->isAfter(now()->subHours(24));
        }));
    }

    /**
     * Count suspicious activities
     */
    public function countSuspiciousActivities(): int
    {
        return app(CopyProtectionService::class)->detectResellingBehavior() ? 1 : 0;
    }

    /**
     * Get integrity status
     */
    public function getIntegrityStatus(): array
    {
        return [
            'file_integrity' => $this->checkFileIntegrity(),
            'config_integrity' => $this->checkConfigIntegrity(),
            'environment_security' => $this->checkEnvironmentSecurity(),
        ];
    }

    /**
     * Get system health
     */
    public function getSystemHealth(): array
    {
        return [
            'php_version' => PHP_VERSION,
            'laravel_version' => app()->version(),
            'server_software' => $_SERVER['SERVER_SOFTWARE'] ?? 'unknown',
            'memory_usage' => memory_get_peak_usage(true),
            'uptime' => $this->getSystemUptime(),
        ];
    }

    /**
     * Generate security recommendations
     */
    public function generateRecommendations(): array
    {
        $recommendations = [];

        if (!$this->checkFileIntegrity()) {
            $recommendations[] = 'Verify file integrity and check for unauthorized modifications';
        }

        if (!$this->checkConfigIntegrity()) {
            $recommendations[] = 'Encrypt sensitive configuration values';
        }

        if ($this->countCriticalIssues() > 0) {
            $recommendations[] = 'Review critical security events and take appropriate action';
        }

        if (empty($recommendations)) {
            $recommendations[] = 'System security status is good';
        }

        return $recommendations;
    }

    /**
     * Get system uptime (simplified)
     */
    public function getSystemUptime(): string
    {
        // This is a simplified implementation
        // In production, you'd use system-specific methods
        return 'unknown';
    }

    /**
     * Cleanup old alerts and logs
     */
    public function cleanupOldAlerts(): void
    {
        // Clean up old alert caches (older than 7 days)
        $oldKeys = Cache::store('file')->getStore()->many(['alert_*']);
        foreach ($oldKeys as $key => $value) {
            if (str_starts_with($key, 'alert_') && isset($value['timestamp'])) {
                if (Carbon::parse($value['timestamp'])->addDays(7)->isPast()) {
                    Cache::forget($key);
                }
            }
        }
    }
}



