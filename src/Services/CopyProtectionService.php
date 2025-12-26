<?php

namespace InsuranceCore\Utils\Services;

use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;
use Carbon\Carbon;

class CopyProtectionService
{
    /**
     * Detect potential reselling activity
     * 
     * ENHANCED: Now includes domain switching detection and improved scoring
     */
    public function detectResellingBehavior(array $context = []): bool
    {
        $suspiciousIndicators = [
            'multiple_domains' => $this->checkMultipleDomainUsage(),
            'domain_switching' => $this->detectDomainSwitching(), // NEW: Domain switching detection
            'usage_patterns' => $this->analyzeUsagePatterns(),
            'deployment_patterns' => $this->analyzeDeploymentPatterns(),
            'code_modifications' => $this->detectCodeModifications(),
            'network_behavior' => $this->analyzeNetworkBehavior(),
            'installation_clustering' => $this->checkInstallationClustering(),
        ];

        // ENHANCED: Use weighted scoring algorithm with time-decay
        $score = $this->calculateWeightedSuspiciousScore($suspiciousIndicators, $context);
        // SECURITY: Threshold is hardcoded - cannot be modified by clients
        $threshold = \InsuranceCore\Utils\SecurityConstants::getResellingThreshold();

        if ($score >= $threshold) {
            $this->handlePotentiallySuspiciousActivity($suspiciousIndicators, $score);
            return true;
        }

        return false;
    }

    /**
     * Detect rapid domain switching patterns (indicator of reselling)
     * 
     * @return int Suspicion score (0-40)
     */
    protected function detectDomainSwitching(): int
    {
        $currentDomain = request()->getHost();
        $switchingKey = 'domain_switching_history';
        $switchingHistory = Cache::get($switchingKey, []);
        
        // Track domain changes with timestamps
        $currentTime = now();
        $switchingHistory[] = [
            'domain' => $currentDomain,
            'timestamp' => $currentTime->toISOString(),
            'ip' => request()->ip(),
        ];
        
        // Keep only last 7 days of history
        $cutoff = $currentTime->copy()->subDays(7);
        $switchingHistory = array_filter($switchingHistory, function($entry) use ($cutoff) {
            return Carbon::parse($entry['timestamp'])->isAfter($cutoff);
        });
        
        // Limit to last 100 entries
        $switchingHistory = array_slice($switchingHistory, -100);
        Cache::put($switchingKey, $switchingHistory, now()->addDays(7));
        
        // Analyze switching patterns
        $score = 0;
        
        // Count unique domains in last 7 days
        $uniqueDomains = array_unique(array_column($switchingHistory, 'domain'));
        $domainCount = count($uniqueDomains);
        
        // Multiple domains in short time = suspicious
        if ($domainCount > 3) {
            $score += 30; // High suspicion
        } elseif ($domainCount > 2) {
            $score += 15; // Medium suspicion
        } elseif ($domainCount > 1) {
            $score += 5; // Low suspicion
        }
        
        // Check for rapid switching (multiple domains in same day)
        $domainsByDay = [];
        foreach ($switchingHistory as $entry) {
            $day = Carbon::parse($entry['timestamp'])->format('Y-m-d');
            if (!isset($domainsByDay[$day])) {
                $domainsByDay[$day] = [];
            }
            $domainsByDay[$day][] = $entry['domain'];
        }
        
        // If same day has multiple unique domains, very suspicious
        foreach ($domainsByDay as $day => $domains) {
            $uniqueDayDomains = count(array_unique($domains));
            if ($uniqueDayDomains > 2) {
                $score += 20; // Very suspicious - multiple domains in one day
            } elseif ($uniqueDayDomains > 1) {
                $score += 10; // Suspicious - domain switching in one day
            }
        }
        
        // Check for IP changes with domain changes (suggests different installations)
        $ipDomainPairs = [];
        foreach ($switchingHistory as $entry) {
            $key = $entry['ip'] . '|' . $entry['domain'];
            if (!isset($ipDomainPairs[$key])) {
                $ipDomainPairs[$key] = 0;
            }
            $ipDomainPairs[$key]++;
        }
        
        // If many different IP+domain combinations, suggests reselling
        if (count($ipDomainPairs) > 5) {
            $score += 15;
        }
        
        // Cap at 40
        return min($score, 40);
    }

    /**
     * Check for multiple domains using same system key or hardware fingerprint
     * 
     * ENHANCED: Multi-layer domain tracking (system_key + hardware fingerprint + installation_id)
     */
    public function checkMultipleDomainUsage(): int
    {
        // Multi-layer tracking: track domains via multiple identifiers simultaneously
        $allDomains = $this->getMultiLayerDomainTracking();
        
        $currentDomain = request()->getHost();
        // SECURITY: Max domains is hardcoded - cannot be modified by clients
        $maxAllowed = \InsuranceCore\Utils\SecurityConstants::getMaxDomainsPerKey();
        
        // Check if current domain exceeds limit across all tracking methods
        if (count($allDomains) > $maxAllowed) {
            $systemKey = config('utils.system_key');
            app(\InsuranceCore\Utils\Services\RemoteSecurityLogger::class)->critical('Multiple domains detected (multi-layer tracking)', [
                'domains' => $allDomains,
                'domain_count' => count($allDomains),
                'system_key' => $systemKey ? 'configured' : 'not_configured',
                'tracking_methods' => $this->getActiveTrackingMethods(),
                'excess_count' => count($allDomains) - $maxAllowed,
            ]);
            return 50; // High suspicion score
        }

        // Return suspicion score based on domain count
        if (count($allDomains) > 1) {
            return 20;
        }

        return 0;
    }

    /**
     * Multi-layer domain tracking - tracks domains via multiple identifiers
     * This provides better detection even if one identifier is missing or changed
     * 
     * @return array Array of unique domains tracked across all methods
     */
    protected function getMultiLayerDomainTracking(): array
    {
        $allDomains = [];
        $currentDomain = request()->getHost();
        
        // Layer 1: Track by system_key
        $systemKey = config('utils.system_key');
        if (!empty($systemKey)) {
            $domainKey = 'system_domains_' . md5($systemKey);
            $domainsBySystemKey = Cache::get($domainKey, []);
            
            if (!in_array($currentDomain, $domainsBySystemKey)) {
                $domainsBySystemKey[] = $currentDomain;
                Cache::put($domainKey, $domainsBySystemKey, now()->addDays(30));
            }
            
            $allDomains = array_merge($allDomains, $domainsBySystemKey);
        }
        
        // Layer 2: Track by hardware fingerprint (fallback if system_key not configured)
        try {
            $hardwareFingerprint = app(\InsuranceCore\Utils\Manager::class)->generateHardwareFingerprint();
            $domainKey = 'system_domains_fingerprint_' . md5($hardwareFingerprint);
            $domainsByFingerprint = Cache::get($domainKey, []);
            
            if (!in_array($currentDomain, $domainsByFingerprint)) {
                $domainsByFingerprint[] = $currentDomain;
                Cache::put($domainKey, $domainsByFingerprint, now()->addDays(30));
            }
            
            $allDomains = array_merge($allDomains, $domainsByFingerprint);
        } catch (\Exception $e) {
            // Silently fail - don't break if fingerprint generation fails
        }
        
        // Layer 3: Track by installation_id (additional layer for better detection)
        try {
            $installationId = Cache::get('installation_id');
            if ($installationId) {
                $domainKey = 'system_domains_installation_' . md5($installationId);
                $domainsByInstallation = Cache::get($domainKey, []);
                
                if (!in_array($currentDomain, $domainsByInstallation)) {
                    $domainsByInstallation[] = $currentDomain;
                    Cache::put($domainKey, $domainsByInstallation, now()->addDays(30));
                }
                
                $allDomains = array_merge($allDomains, $domainsByInstallation);
            }
        } catch (\Exception $e) {
            // Silently fail - don't break if installation ID not available
        }
        
        // Return unique domains across all tracking methods
        return array_unique($allDomains);
    }

    /**
     * Get list of active tracking methods for reporting
     * 
     * @return array
     */
    protected function getActiveTrackingMethods(): array
    {
        $methods = [];
        
        if (!empty(config('utils.system_key'))) {
            $methods[] = 'system_key';
        }
        
        try {
            app(\InsuranceCore\Utils\Manager::class)->generateHardwareFingerprint();
            $methods[] = 'hardware_fingerprint';
        } catch (\Exception $e) {
            // Skip if not available
        }
        
        if (Cache::get('installation_id')) {
            $methods[] = 'installation_id';
        }
        
        return $methods;
    }

    /**
     * Analyze usage patterns for suspicious behavior
     */
    public function analyzeUsagePatterns(): int
    {
        $usageKey = 'usage_pattern_' . md5(config('utils.system_key'));
        $patterns = Cache::get($usageKey, []);

        $currentPattern = [
            'time' => now()->hour,
            'user_agent' => substr(request()->userAgent(), 0, 50),
            'referer' => request()->header('referer'),
            'ip_range' => $this->getIPRange(request()->ip()),
            'session_fingerprint' => $this->generateSessionFingerprint(),
        ];

        $patterns[] = $currentPattern;
        
        // Keep only last 48 hours of data
        $cutoff = now()->subHours(48);
        $patterns = array_filter($patterns, function($pattern) use ($cutoff) {
            $patternTime = \Carbon\Carbon::parse($pattern['time']);
            return $patternTime->isAfter($cutoff);
        });

        Cache::put($usageKey, array_slice($patterns, -500), now()->addHours(48)); // Keep last 500 entries

        // Analyze patterns for suspicious indicators
        $score = 0;
        
        // Different IP ranges suggest multiple installations
        $uniqueIPRanges = count(array_unique(array_column($patterns, 'ip_range')));
        if ($uniqueIPRanges > 2) {
            $score += 30;
        }

        // Different user agents suggest different clients
        $uniqueUserAgents = count(array_unique(array_column($patterns, 'user_agent')));
        if ($uniqueUserAgents > 5) {
            $score += 25;
        }

        // Access patterns indicating demo/trial behavior
        $hourDistribution = array_count_values(array_column($patterns, 'time'));
        $unusualHours = count(array_filter($hourDistribution, function($count) {
            return $count > 100; // More than 100 requests in single hour
        }));
        
        if ($unusualHours > 0) {
            $score += 20;
        }

        return $score;
    }

    /**
     * Analyze deployment patterns
     */
    public function analyzeDeploymentPatterns(): int
    {
        $score = 0;
        
        // Check if application has been downloaded/moved recently
        $installFingerprint = app(\InsuranceCore\Utils\Manager::class)->generateHardwareFingerprint();
        $storedFingerprint = Cache::get('original_fingerprint_' . md5(config('utils.system_key')));
        
        if (!$storedFingerprint) {
            // First time, store current fingerprint
            Cache::put('original_fingerprint_' . md5(config('utils.system_key')), $installFingerprint, now()->addYears(1));
            $score += 0; // Not suspicious on first run
        } else {
            // Check if fingerprint changed significantly
            $similarity = similar_text($storedFingerprint, $installFingerprint, $percent);
            if ($percent < 85) {
                $score += 40; // High suspicion - significant hardware change
                
                app(\InsuranceCore\Utils\Services\RemoteSecurityLogger::class)->warning('Significant hardware fingerprint change', [
                    'old_fingerprint' => substr($storedFingerprint, 0, 32) . '...',
                    'new_fingerprint' => substr($installFingerprint, 0, 32) . '...',
                    'similarity' => $percent,
                ]);
            }
        }

        return $score;
    }

    /**
     * Detect unauthorized code modifications
     */
    public function detectCodeModifications(): int
    {
        $score = 0;
        
        // List of critical files that shouldn't be modified
        $criticalFiles = [
            'app/Http/Kernel.php',
            'config/app.php',
            'routes/web.php',
        ];

        foreach ($criticalFiles as $filePath) {
            $fullPath = base_path($filePath);
            if (file_exists($fullPath) && is_file($fullPath)) {
                try {
                    $currentHash = hash_file('sha256', $fullPath);
                    if ($currentHash === false) {
                        // Skip files that can't be hashed (permission issues, etc.)
                        continue;
                    }
                    
                    $storedHash = Cache::get("file_hash_{$filePath}");
                    
                    if (!$storedHash) {
                        // Store initial hash
                        Cache::put("file_hash_{$filePath}", $currentHash, now()->addYears(1));
                    } elseif ($storedHash !== $currentHash) {
                        $score += 25; // High suspicion - file modification
                        
                        app(\InsuranceCore\Utils\Services\RemoteSecurityLogger::class)->critical('Unauthorized file modification detected', [
                            'file' => $filePath,
                            'old_hash' => $storedHash,
                            'new_hash' => $currentHash
                        ]);
                    }
                } catch (\Exception $e) {
                    // Skip files that can't be accessed due to permissions
                    Log::debug('Skipping file hash check due to access issue', [
                        'file' => $filePath,
                        'error' => $e->getMessage()
                    ]);
                    continue;
                }
            }
        }

        return $score;
    }

    /**
     * Analyze network behavior for suspicious patterns
     */
    public function analyzeNetworkBehavior(): int
    {
        $score = 0;
        
        // Check for VPN/Proxy usage patterns
        $ip = request()->ip();
        $ipData = Cache::get("ip_data_{$ip}");
        
        if (!$ipData) {
            // Simple IP analysis (could be enhanced with external services)
            $ipData = [
                'first_seen' => now(),
                'request_count' => 0,
                'is_vpn_suspicious' => $this->detectVPNSuspicious($ip),
            ];
        }
        
        $ipData['request_count']++;
        Cache::put("ip_data_{$ip}", $ipData, now()->addDays(7));

        // VPN/Proxy detection (basic heuristics)
        if ($ipData['is_vpn_suspicious']) {
            $score += 15;
        }

        // Rapid request patterns suggesting automated tools
        if ($ipData['request_count'] > 1000) {
            $score += 20;
        }

        return $score;
    }

    /**
     * Check for installation clustering (multiple installations in same area)
     */
    public function checkInstallationClustering(): int
    {
        $geoKey = $this->getApproximateGeoLocation(request()->ip());
        $clusterKey = "geo_cluster_{$geoKey}";
        
        $installations = Cache::get($clusterKey, []);
        $currentInstallation = md5(config('utils.system_key') . config('utils.client_id'));
        
        if (!in_array($currentInstallation, $installations)) {
            $installations[] = $currentInstallation;
            Cache::put($clusterKey, $installations, now()->addDays(30));
        }

        // Too many installations in same geographic area
        // SECURITY: Max per geo is hardcoded - cannot be modified by clients
        $maxAllowedInCluster = \InsuranceCore\Utils\SecurityConstants::getMaxInstallationsPerGeo();
        if (count($installations) > $maxAllowedInCluster) {
            return 35; // Suspicious clustering
        }

        return count($installations) > 1 ? 10 : 0;
    }

    /**
     * Calculate overall suspicious score
     * 
     * @deprecated Use calculateWeightedSuspiciousScore() for enhanced scoring
     * Kept for backward compatibility
     */
    public function calculateSuspiciousScore(array $indicators): int
    {
        return $this->calculateWeightedSuspiciousScore($indicators);
    }

    /**
     * ENHANCED: Calculate suspicious score with weighted factors and time-decay
     * 
     * @param array $indicators Suspicion indicators with scores
     * @param array $context Additional context (e.g., validation_source, timestamps)
     * @return int Weighted suspicion score (0-100)
     */
    protected function calculateWeightedSuspiciousScore(array $indicators, array $context = []): int
    {
        // Weight factors for different indicators (higher weight = more important)
        $weights = [
            'multiple_domains' => 1.2,      // Very important - direct reselling indicator
            'domain_switching' => 1.3,     // Very important - rapid switching is suspicious
            'deployment_patterns' => 1.1,  // Important - hardware changes
            'code_modifications' => 0.9,    // Less important - might be legitimate
            'usage_patterns' => 0.8,       // Less important - can vary
            'network_behavior' => 0.7,     // Less important - VPN usage is common
            'installation_clustering' => 0.9, // Important - geographic clustering
        ];
        
        // Calculate weighted score
        $weightedScore = 0;
        foreach ($indicators as $indicator => $score) {
            $weight = $weights[$indicator] ?? 1.0;
            $weightedScore += $score * $weight;
        }
        
        // Apply time-decay for older violations
        if (isset($context['last_violation_time'])) {
            try {
                $lastViolation = Carbon::parse($context['last_violation_time']);
                $daysSinceViolation = $lastViolation->diffInDays(now());
                
                // Decay factor: reduce score by 5% per day (max 50% reduction)
                $decayFactor = max(0.5, 1 - ($daysSinceViolation * 0.05));
                $weightedScore *= $decayFactor;
            } catch (\Exception $e) {
                // If parsing fails, use score as-is
            }
        }
        
        // Cap at 100
        return min((int)round($weightedScore), 100);
    }

    /**
     * Handle potentially suspicious activity
     */
    public function handlePotentiallySuspiciousActivity(array $indicators, int $score): void
    {
        // Record incident
        app(\InsuranceCore\Utils\Services\RemoteSecurityLogger::class)->alert('Potentially suspicious activity detected', [
            'system_key' => config('utils.system_key'),
            'client_id' => config('utils.client_id'),
            'domain' => request()->getHost(),
            'ip' => request()->ip(),
            'score' => $score,
            'indicators' => $indicators,
            'timestamp' => now(),
        ]);

        // Report to validation server
        $this->reportSuspiciousActivity($score, $indicators);

        // Trigger additional security measures
        $this->triggerSecurityMeasures($score);
    }

    /**
     * Report suspicious activity to validation server
     */
    public function reportSuspiciousActivity(int $score, array $indicators): void
    {
        try {
            $validationServer = config('utils.validation_server');
            $apiToken = config('utils.api_token');

            Http::timeout(10)->withHeaders([
                'Authorization' => 'Bearer ' . $apiToken,
            ])->post("{$validationServer}/api/report-suspicious", [
                'system_key' => config('utils.system_key'),
                'client_id' => config('utils.client_id'),
                'score' => $score,
                'indicators' => $indicators,
                'domain' => request()->getHost(),
                'ip' => request()->ip(),
                'timestamp' => now()->toISOString(),
            ]);

        } catch (\Exception $e) {
            app(\InsuranceCore\Utils\Services\RemoteSecurityLogger::class)->error('Failed to report suspicious activity', [
                'error' => $e->getMessage(),
            ]);
        }
    }

    /**
     * Trigger additional security measures
     */
    public function triggerSecurityMeasures(int $score): void
    {
        // Higher scores trigger more aggressive measures
        if ($score >= 90) {
            // Immediate cache block for this installation
            Cache::put('security_block_' . md5(config('utils.system_key')), true, now()->addHours(24));
            
            // Force validation server check
            Cache::forget('system_valid_' . md5(config('utils.system_key')));
            
        } elseif ($score >= 75) {
            // Reduce cache duration for frequent validation
            Cache::put('high_attention_' . md5(config('utils.system_key')), true, now()->addHours(12));
        }
    }

    /**
     * Utility methods
     */
    public function getIPRange(string $ip): string
    {
        // Return first 3 octets for IP range identification
        $parts = explode('.', $ip);
        return implode('.', array_slice($parts, 0, 3));
    }

    public function generateSessionFingerprint(): string
    {
        return hash('sha256', implode('|', [
            request()->ip(),
            request()->header('User-Agent'),
            request()->header('Accept-Language'),
            request()->header('Accept-Encoding'),
        ]));
    }

    public function detectVPNSuspicious(string $ip): bool
    {
        // Basic heuristic - could be enhanced with external VPN detection services
        // Check for known VPN IP ranges or unusual patterns
        $publicRanges = [
            '10.',
            '172.16.',
            '172.17.',
            '172.18.',
            '172.19.',
            '172.20.',
            '172.21.',
            '172.22.',
            '172.23.',
            '172.24.',
            '172.25.',
            '172.26.',
            '172.27.',
            '172.28.',
            '172.29.',
            '172.30.',
            '172.31.',
            '192.168.',
        ];

        // Non-public IPs might be VPNs (heuristic)
        foreach ($publicRanges as $range) {
            if (str_starts_with($ip, $range)) {
                return false;
            }
        }

        return true; // Potential VPN/Proxy
    }

    public function getApproximateGeoLocation(string $ip): string
    {
        // Simple geo approximation based on IP patterns
        // Could be enhanced with geo IP services
        $parts = explode('.', $ip);
        
        if (count($parts) >= 3) {
            // Use first 3 octets as geographic approximation
            return implode('.', array_slice($parts, 0, 2)) . '.X';
        }
        
        return 'unknown';
    }
}



