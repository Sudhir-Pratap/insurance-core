<?php

namespace InsuranceCore\Helpers\Commands;

use InsuranceCore\Helpers\Services\VendorProtectionService;
use Illuminate\Console\Command;

class ProtectCommand extends Command
{
    /**
     * The name and signature of the console command.
     */
    protected $signature = 'helpers:protect
                          {--setup : Setup vendor protection}
                          {--verify : Verify vendor integrity}
                          {--report : Generate tampering report}
                          {--restore : Restore from backup (dangerous)}';

    /**
     * The console command description.
     */
    protected $description = 'Manage helper directory protection and integrity monitoring';

    /**
     * Execute the console command.
     */
    public function handle()
    {
        $vendorProtection = app(VendorProtectionService::class);

        if ($this->option('setup')) {
            return $this->setupProtection($vendorProtection);
        }

        if ($this->option('verify')) {
            return $this->verifyIntegrity($vendorProtection);
        }

        if ($this->option('report')) {
            return $this->generateReport($vendorProtection);
        }

        if ($this->option('restore')) {
            return $this->restoreFromBackup($vendorProtection);
        }

        $this->info('Vendor Protection Manager');
        $this->info('=======================');
        $this->line('Use --setup to initialize protection');
        $this->line('Use --verify to check integrity');
        $this->line('Use --report to view tampering incidents');
        $this->line('Use --restore to restore from backup (dangerous)');

        return 0;
    }

    /**
     * Setup vendor protection
     */
    private function setupProtection(VendorProtectionService $vendorProtection): int
    {
        $this->info('🔒 Setting up vendor directory protection...');

        if (!$this->confirm('This will create integrity baselines and protect vendor files. Continue?')) {
            $this->warn('Setup cancelled.');
            return 1;
        }

        try {
            $vendorProtection->protectVendorIntegrity();

            $this->info('✅ Vendor protection setup completed successfully!');
            $this->info('');
            $this->info('Protection measures implemented:');
            $this->line('  ✓ Integrity baseline created');
            $this->line('  ✓ File locking enabled');
            $this->line('  ✓ Decoy files created');
            $this->line('  ✓ Monitoring activated');

            return 0;
        } catch (\Exception $e) {
            $this->error('❌ Setup failed: ' . $e->getMessage());
            return 1;
        }
    }

    /**
     * Verify vendor integrity
     */
    private function verifyIntegrity(VendorProtectionService $vendorProtection): int
    {
        $this->info('🔍 Verifying vendor directory integrity...');

        $result = $vendorProtection->verifyVendorIntegrity();

        if ($result['status'] === 'integrity_verified') {
            $this->info('✅ Vendor integrity verified - no tampering detected');
            return 0;
        }

        $this->error('❌ Vendor integrity violations detected!');

        if (!empty($result['violations'])) {
            $this->table(
                ['Type', 'File', 'Severity'],
                array_map(function($violation) {
                    return [
                        $violation['type'],
                        $violation['file'] ?? 'N/A',
                        $violation['severity']
                    ];
                }, $result['violations'])
            );
        }

        return 1;
    }

    /**
     * Generate tampering report
     */
    private function generateReport(VendorProtectionService $vendorProtection): int
    {
        $this->info('📊 Generating vendor tampering report...');

        $report = $vendorProtection->getTamperingReport();

        $this->info("Total Incidents: {$report['total_incidents']}");

        if (!empty($report['recent_incidents'])) {
            $this->info("\nRecent Incidents:");
            foreach ($report['recent_incidents'] as $incident) {
                $this->line("  " . $incident['timestamp'] . " - " . count($incident['violations']) . " violations");
            }
        }

        $integrityStatus = $report['integrity_status'];
        $this->info("\nIntegrity Status: {$integrityStatus['status']}");

        if ($integrityStatus['status'] === 'violations_detected') {
            $this->warn('Violations found:');
            foreach ($integrityStatus['violations'] as $violation) {
                $file = $violation['file'] ?? 'N/A';
                $this->line("  - {$violation['type']}: {$file} ({$violation['severity']})");
            }
        }

        // Save detailed report
        $reportPath = storage_path('vendor-protection-report-' . now()->format('Y-m-d-H-i-s') . '.json');
        file_put_contents($reportPath, json_encode($report, JSON_PRETTY_PRINT));

        $this->info("\n📄 Detailed report saved to: {$reportPath}");

        return 0;
    }

    /**
     * Restore from backup
     */
    private function restoreFromBackup(VendorProtectionService $vendorProtection): int
    {
        $this->error('⚠️  WARNING: This is a dangerous operation!');
        $this->error('Restoring vendor files can introduce security vulnerabilities.');

        if (!$this->confirm('Are you absolutely sure you want to restore vendor files from backup?')) {
            $this->warn('Restore cancelled.');
            return 1;
        }

        $confirmation = $this->ask('Type "RESTORE VENDOR FILES" to confirm');
        if ($confirmation !== 'RESTORE VENDOR FILES') {
            $this->warn('Incorrect confirmation. Restore cancelled.');
            return 1;
        }

        $this->info('🔄 Attempting vendor file restoration...');

        try {
            $success = $vendorProtection->restoreFromBackup();

            if ($success) {
                $this->info('✅ Vendor files restored successfully');
                $this->warn('⚠️  IMPORTANT: Run security audit immediately after restoration');
                return 0;
            } else {
                $this->error('❌ Vendor restoration failed');
                return 1;
            }
        } catch (\Exception $e) {
            $this->error('❌ Restoration error: ' . $e->getMessage());
            return 1;
        }
    }
}

