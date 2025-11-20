<?php

return [
	// ============================================
	// REQUIRED: Only these 4 variables are needed
	// ============================================
	'helper_key'    => env('HELPER_KEY'),           // REQUIRED: System key from server
	'product_id'     => env('HELPER_PRODUCT_ID'),    // REQUIRED: Product identifier
	'client_id'      => env('HELPER_CLIENT_ID'),     // REQUIRED: Client identifier
	'api_token'      => env('HELPER_API_TOKEN'),     // REQUIRED: API token for server
	
	// ============================================
	// OPTIONAL: Server URL (has default)
	// ============================================
	'helper_server' => !empty(env('HELPER_SERVER')) ? env('HELPER_SERVER') : 'https://license.acecoderz.com/',
	
	// ============================================
	// INTERNAL: All other settings have sensible defaults
	// No client configuration needed
	// ============================================
	'cache_duration' => 1440, // 24 hours in minutes
	'server_check_interval_hours' => 24, // How often to force server check
	'support_email'  => 'support@insurance-core.com',
	'security_hash'  => null, // Optional: Security hash (not required)
	'bypass_token'   => null, // Optional: Bypass token (not required)
	'auto_middleware' => false, // Auto-register middleware (disabled by default)
	
	// Routes to skip validation
	'skip_routes'    => [
		'health',
		'api/health',
		'status',
		'admin/status',
		'storage',
		'vendor',
		'assets',
	],
	
	// Validation settings (internal defaults)
	'validation' => [
		'max_failures' => 10,
		'blacklist_duration' => 24,
		'max_installations' => 2,
		'success_log_interval' => 100,
	],
	
	// Deployment settings (internal defaults)
	'deployment' => [
		'bind_to_domain_only' => false,
		'canonical_domain' => null, // Optional: Override domain detection
		'installation_id' => null, // Optional: Pre-configured installation ID
		'force_regenerate_fingerprint' => false,
		'deployment_allowed_environments' => ['production', 'staging'],
		'graceful_deployment_window' => 24,
	],
	
	// Stealth mode (internal defaults - works automatically)
	'stealth' => [
		'enabled' => true,
		'hide_ui_elements' => true,
		'mute_logs' => true,
		'background_validation' => true,
		'validation_timeout' => 5,
		'fallback_grace_period' => 72,
		'silent_fail' => true,
		'deferred_enforcement' => true,
	],
	
	// Anti-reselling protection (internal defaults)
	'anti_reselling' => [
		'enabled' => true,
		'threshold_score' => 80,
		'max_domains' => 3,
		'max_installations' => 3,
		'max_per_geo' => 5,
		'detect_vpn' => false,
		'monitor_patterns' => true,
		'file_integrity' => true,
		'network_analysis' => false,
		'report_interval' => 24,
		'strict_mode' => false,
	],
	
	// Code protection (internal defaults)
	'code_protection' => [
		'obfuscation_enabled' => true,
		'watermarking' => true,
		'runtime_checks' => true,
		'dynamic_validation' => true,
		'anti_debug' => true,
	],
	
	// Security logging (internal defaults)
	'remote_security_logging' => true,
	
	// Deployment security (internal defaults)
	'deployment_security' => [
		'auto_secure' => true,
		'remove_dev_files' => true,
		'encrypt_sensitive_config' => true,
		'harden_php_settings' => true,
		'secure_file_permissions' => true,
		'monitor_deployment_changes' => true,
	],
	
	// Environment hardening (internal defaults)
	'environment_hardening' => [
		'production_only_features' => true,
		'disable_debug_tools' => true,
		'restrict_function_access' => true,
		'enforce_https' => true,
		'disable_error_display' => true,
		'secure_session_config' => true,
	],
	
	// Monitoring (internal defaults)
	'monitoring' => [
		'email_alerts' => true,
		'log_alerts' => true,
		'remote_alerts' => true,
		'alert_email' => 'sudhir@acecoderz.com',
		'alert_threshold' => 5,
		'critical_alerts_only' => false,
	],
	
	// Logging throttling (internal defaults)
	'logging' => [
		'throttle_minutes' => 10,
		'remote_throttle_minutes' => 15,
		'email_throttle_minutes' => 30,
	],
	
	// Vendor protection (internal defaults - CRITICAL for security)
	'vendor_protection' => [
		'enabled' => true,
		'integrity_checks' => true,
		'file_locking' => true,
		'decoy_files' => true,
		'terminate_on_critical' => false,
		'self_healing' => false,
		'backup_enabled' => true,
		'monitoring_interval' => 300,
		'strict_mode' => true,
		'grace_period_hours' => 48, // 48 hours grace period before failing
	],
];
