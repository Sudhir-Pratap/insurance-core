<?php

namespace InsuranceCore\Helpers\Commands;

use InsuranceCore\Helpers\Services\CodeProtectionService;
use InsuranceCore\Helpers\Services\DeploymentSecurityService;
use InsuranceCore\Helpers\Services\EnvironmentHardeningService;
use InsuranceCore\Helpers\Services\SecurityMonitoringService;
use Illuminate\Console\Command;

class AuditCommand extends Command
{
    /**
     * The name and signature of the console command.
     */
    protected $signature = 'helpers:audit
                          {--fix : Automatically fix issues}
                          {--report : Generate detailed report}
                          {--monitor : Run monitoring checks}';

    /**
     * The console command description.
     */
    protected $description = 'Run comprehensive audit for helper system';

    /**
     * Execute the console command.
     */
    public function handle()
    {
        $this->info('🔒 Helper System Security Audit');
        $this->info('================================');

        $issues = [];
        $warnings = [];

        // Run code protection audit
        $this->info('Checking code protection...');
        $codeIssues = $this->auditCodeProtection();
        $issues = array_merge($issues, $codeIssues);

        // Run deployment security audit
        $this->info('Checking deployment security...');
        $deploymentIssues = $this->auditDeploymentSecurity();
        $issues = array_merge($issues, $deploymentIssues);

        // Run environment hardening audit
        $this->info('Checking environment hardening...');
        $envIssues = $this->auditEnvironmentHardening();
        $issues = array_merge($issues, $envIssues);
        $warnings = array_merge($warnings, $this->auditEnvironmentWarnings());

        // Run vendor protection audit
        $this->info('Checking vendor directory protection...');
        $vendorIssues = $this->auditVendorProtection();
        $issues = array_merge($issues, $vendorIssues);

        // Run monitoring audit
        if ($this->option('monitor')) {
            $this->info('Running monitoring checks...');
            app(SecurityMonitoringService::class)->monitorAndAlert();
        }

        // Display results
        $this->displayResults($issues, $warnings);

        // Auto-fix if requested
        if ($this->option('fix') && !empty($issues)) {
            $this->fixIssues($issues);
        }

        // Generate report if requested
        if ($this->option('report')) {
            $this->generateReport($issues, $warnings);
        }

        return count($issues) > 0 ? 1 : 0;
    }

    /**
     * Audit code protection
     */
    private function auditCodeProtection(): array
    {
        $issues = [];

        // Check if obfuscation is enabled
        if (!config('helpers.code_protection.obfuscation_enabled', true)) {
            $issues[] = [
                'type' => 'code_protection',
                'severity' => 'medium',
                'message' => 'Code obfuscation is disabled',
                'fix' => 'enable_obfuscation'
            ];
        }

        // Check runtime integrity
        $integrityService = app(CodeProtectionService::class);
        if (!$integrityService->verifyIntegrity($integrityService->generateIntegrityHash())) {
            $issues[] = [
                'type' => 'code_protection',
                'severity' => 'high',
                'message' => 'Code integrity verification failed',
                'fix' => 'verify_integrity'
            ];
        }

        return $issues;
    }

    /**
     * Audit deployment security
     */
    private function auditDeploymentSecurity(): array
    {
        $issues = [];

        // Check file permissions
        $criticalFiles = [
            base_path('.env') => 0600,
            storage_path('logs') => 0750,
        ];

        foreach ($criticalFiles as $file => $expectedPerms) {
            if (file_exists($file)) {
                $actualPerms = fileperms($file) & 0777;
                if ($actualPerms !== $expectedPerms) {
                    $issues[] = [
                        'type' => 'deployment',
                        'severity' => 'high',
                        'message' => "Incorrect permissions on {$file}",
                        'details' => sprintf('Expected: %o, Actual: %o', $expectedPerms, $actualPerms),
                        'fix' => 'fix_permissions'
                    ];
                }
            }
        }

        // Check for development files
        $devFiles = ['.git', '.env.example', 'phpunit.xml'];
        foreach ($devFiles as $file) {
            if (file_exists(base_path($file))) {
                $issues[] = [
                    'type' => 'deployment',
                    'severity' => 'medium',
                    'message' => "Development file present: {$file}",
                    'fix' => 'remove_dev_files'
                ];
            }
        }

        return $issues;
    }

    /**
     * Audit environment hardening
     */
    private function auditEnvironmentHardening(): array
    {
        $issues = [];
        $hardeningService = app(EnvironmentHardeningService::class);
        $securityStatus = $hardeningService->validateEnvironmentSecurity();

        foreach ($securityStatus as $check => $passed) {
            if (!$passed) {
                $issues[] = [
                    'type' => 'environment',
                    'severity' => 'high',
                    'message' => "Environment security check failed: {$check}",
                    'fix' => 'harden_environment'
                ];
            }
        }

        return $issues;
    }

    /**
     * Audit vendor protection
     */
    private function auditVendorProtection(): array
    {
        $issues = [];

        // Check if vendor protection is enabled
        if (!config('helpers.vendor_protection.enabled', true)) {
            $issues[] = [
                'type' => 'vendor_protection',
                'severity' => 'medium',
                'message' => 'Vendor protection is disabled',
                'fix' => 'enable_vendor_protection'
            ];
        }

        // Check vendor integrity
        try {
            $vendorProtection = app(\InsuranceCore\Helpers\Services\VendorProtectionService::class);
            $integrityResult = $vendorProtection->verifyVendorIntegrity();

            if ($integrityResult['status'] === 'violations_detected') {
                foreach ($integrityResult['violations'] as $violation) {
                    $file = $violation['file'] ?? 'N/A';
                    $issues[] = [
                        'type' => 'vendor_protection',
                        'severity' => $violation['severity'],
                        'message' => "Vendor integrity violation: {$violation['type']} - {$file}",
                        'details' => json_encode($violation),
                        'fix' => 'investigate_vendor_tampering'
                    ];
                }
            }

            // Check if baseline exists
            $baseline = \Illuminate\Support\Facades\Cache::get('vendor_baseline_primary');
            if (!$baseline) {
                $issues[] = [
                    'type' => 'vendor_protection',
                    'severity' => 'high',
                    'message' => 'No vendor integrity baseline found',
                    'fix' => 'create_vendor_baseline'
                ];
            }

        } catch (\Exception $e) {
            $issues[] = [
                'type' => 'vendor_protection',
                'severity' => 'high',
                'message' => 'Vendor protection check failed: ' . $e->getMessage(),
                'fix' => 'fix_vendor_protection'
            ];
        }

        return $issues;
    }

    /**
     * Get environment warnings
     */
    private function auditEnvironmentWarnings(): array
    {
        $warnings = [];

        if (config('app.debug')) {
            $warnings[] = 'Debug mode is enabled in production';
        }

        if (!request()->secure() && !app()->environment('local')) {
            $warnings[] = 'HTTPS is not enforced';
        }

        return $warnings;
    }

    /**
     * Display audit results
     */
    private function displayResults(array $issues, array $warnings): void
    {
        if (empty($issues) && empty($warnings)) {
            $this->info('✅ All security checks passed!');
            return;
        }

        if (!empty($issues)) {
            $this->error('❌ Security Issues Found:');
            foreach ($issues as $issue) {
                $severity = match($issue['severity']) {
                    'high' => '🔴 HIGH',
                    'medium' => '🟡 MEDIUM',
                    'low' => '🟢 LOW',
                    default => '⚪ UNKNOWN'
                };

                $this->line("  {$severity}: {$issue['message']}");
                if (isset($issue['details'])) {
                    $this->line("    Details: {$issue['details']}");
                }
            }
        }

        if (!empty($warnings)) {
            $this->warn('⚠️  Security Warnings:');
            foreach ($warnings as $warning) {
                $this->line("  🟡 {$warning}");
            }
        }

        $this->info("\nRun with --fix to automatically resolve issues");
        $this->info("Run with --report to generate detailed report");
    }

    /**
     * Auto-fix security issues
     */
    private function fixIssues(array $issues): void
    {
        $this->info('🔧 Attempting to fix security issues...');

        foreach ($issues as $issue) {
            $this->line("Fixing: {$issue['message']}");

            switch ($issue['fix']) {
                case 'fix_permissions':
                    $this->fixFilePermissions();
                    break;
                case 'remove_dev_files':
                    $this->removeDevelopmentFiles();
                    break;
                case 'harden_environment':
                    app(EnvironmentHardeningService::class)->hardenEnvironment();
                    break;
                case 'enable_obfuscation':
                    $this->enableObfuscation();
                    break;
                case 'enable_vendor_protection':
                    $this->enableVendorProtection();
                    break;
                case 'create_vendor_baseline':
                    $this->createVendorBaseline();
                    break;
                default:
                    $this->warn("No auto-fix available for: {$issue['fix']}");
            }
        }

        $this->info('✅ Auto-fix completed. Run audit again to verify.');
    }

    /**
     * Fix file permissions
     */
    private function fixFilePermissions(): void
    {
        app(DeploymentSecurityService::class)->secureFilePermissions();
    }

    /**
     * Remove development files
     */
    private function removeDevelopmentFiles(): void
    {
        app(DeploymentSecurityService::class)->removeDevelopmentTools();
    }

    /**
     * Enable code obfuscation
     */
    private function enableObfuscation(): void
        {
        config(['helpers.code_protection.obfuscation_enabled' => true]);
        app(CodeProtectionService::class)->applyProtection();
    }

    /**
     * Enable vendor protection
     */
    private function enableVendorProtection(): void
    {
        config(['helpers.vendor_protection.enabled' => true]);
        app(\InsuranceCore\Helpers\Services\VendorProtectionService::class)->protectVendorIntegrity();
    }

    /**
     * Create vendor baseline
     */
    private function createVendorBaseline(): void
    {
        $vendorProtection = app(\InsuranceCore\Helpers\Services\VendorProtectionService::class);
        $vendorProtection->protectVendorIntegrity();
    }

    /**
     * Generate detailed security report
     */
    private function generateReport(array $issues, array $warnings): void
    {
        $reportPath = storage_path('security-audit-report-' . now()->format('Y-m-d-H-i-s') . '.json');

        $report = [
            'timestamp' => now()->toISOString(),
            'server_info' => [
                'hostname' => gethostname(),
                'php_version' => PHP_VERSION,
                'laravel_version' => app()->version(),
                'environment' => app()->environment(),
            ],
            'summary' => [
                'total_issues' => count($issues),
                'high_severity' => count(array_filter($issues, fn($i) => $i['severity'] === 'high')),
                'medium_severity' => count(array_filter($issues, fn($i) => $i['severity'] === 'medium')),
                'total_warnings' => count($warnings),
            ],
            'issues' => $issues,
            'warnings' => $warnings,
            'recommendations' => $this->generateRecommendations($issues),
        ];

        file_put_contents($reportPath, json_encode($report, JSON_PRETTY_PRINT));

        $this->info("📄 Detailed report saved to: {$reportPath}");
    }

    /**
     * Generate recommendations based on issues
     */
    private function generateRecommendations(array $issues): array
    {
        $recommendations = [];

        $hasPermissionIssues = array_filter($issues, fn($i) => $i['fix'] === 'fix_permissions');
        if (!empty($hasPermissionIssues)) {
            $recommendations[] = 'Regularly audit and correct file permissions';
        }

        $hasDevFiles = array_filter($issues, fn($i) => $i['fix'] === 'remove_dev_files');
        if (!empty($hasDevFiles)) {
            $recommendations[] = 'Remove development files before deployment';
        }

        $hasIntegrityIssues = array_filter($issues, fn($i) => $i['type'] === 'code_protection');
        if (!empty($hasIntegrityIssues)) {
            $recommendations[] = 'Implement code integrity monitoring and obfuscation';
        }

        if (empty($recommendations)) {
            $recommendations[] = 'Continue regular security audits';
        }

        return $recommendations;
    }
}

