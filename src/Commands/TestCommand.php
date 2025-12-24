<?php
namespace Acme\Utils\Commands;

use Acme\Utils\SecurityManager;
use Illuminate\Console\Command;

class TestCommand extends Command {
	protected $signature   = 'utils:test {--detailed}';
	protected $description = 'Test system functionality and generate a detailed report';

	public function handle(SecurityManager $securityManager) {
		$this->info('🔒 Testing System...');
		$this->newLine();

		// Test basic validation
		$isValid = $securityManager->validateAntiPiracy();
		
		if ($isValid) {
			$this->info('✅ System validation passed');
		} else {
			$this->error('❌ System validation failed');
		}

		// Get detailed report
		$report = $securityManager->getValidationReport();
		
		$this->newLine();
		$this->info('📊 Installation Details:');
		$this->table(
			['Property', 'Value'],
			[
				['Installation ID', $report['installation_id']],
				['Hardware Fingerprint', substr($report['hardware_fingerprint'], 0, 16) . '...'],
				['Domain', $report['server_info']['domain']],
				['IP Address', $report['server_info']['ip']],
				['User Agent', substr($report['server_info']['user_agent'], 0, 50) . '...'],
				['Validation Time', $report['validation_time']],
			]
		);

		if ($this->option('detailed')) {
			$this->newLine();
			$this->info('🔍 Detailed Hardware Fingerprint Components:');
			
			// Get hardware components (you would need to expose this from SecurityManager)
			$this->warn('Hardware fingerprint includes:');
			$this->line('• Server characteristics');
			$this->line('• File system paths');
			$this->line('• Database configuration');
			$this->line('• PHP environment');
			$this->line('• System resources');
		}

		// Test server communication
		$this->newLine();
		$this->info('🌐 Testing Server Communication...');
		
		try {
			$systemServer = config('utils.validation_server');
			$apiToken = config('utils.api_token');
			
			$response = \Illuminate\Support\Facades\Http::withHeaders([
				'Authorization' => 'Bearer ' . $apiToken,
			])->timeout(10)->get("{$systemServer}/api/heartbeat");

			if ($response->successful()) {
				$this->info('✅ Server communication successful');
			} else {
				$this->error('❌ Server communication failed');
			}
		} catch (\Exception $e) {
			$this->error('❌ Server communication error: ' . $e->getMessage());
		}

		// Security recommendations
		$this->newLine();
		$this->info('🛡️ Security Recommendations:');
		$this->line('1. Keep your system keys secure');
		$this->line('2. Monitor system logs regularly');
		$this->line('3. Use HTTPS for all communications');
		$this->line('4. Regularly update your system server');
		$this->line('5. Monitor for suspicious activity');

		$this->newLine();
		$this->info('✅ System test completed');
	}
} 

