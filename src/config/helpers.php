<?php

return [
	// Note: HELPER_SECRET (cryptographic key for license generation/validation) is accessed directly via env()
	// It falls back to LICENSE_SECRET (deprecated) and then APP_KEY if not set
	
	'helper_key'    => env('HELPER_KEY'),
	'product_id'     => env('HELPER_PRODUCT_ID'),
	'client_id'      => env('HELPER_CLIENT_ID'),
	'helper_server' => env('HELPER_SERVER', 'https://license.acecoderz.com/'),
	'api_token'      => env('HELPER_API_TOKEN'),
	'cache_duration' => env('HELPER_CACHE_DURATION', 1440), // 24 hours in minutes
	'security_hash'  => env('HELPER_SECURITY_HASH'),
	'bypass_token'   => env('HELPER_BYPASS_TOKEN'),
	'support_email'  => env('HELPER_SUPPORT_EMAIL', 'support@insurance-core.com'),
	'auto_middleware' => env('HELPER_AUTO_MIDDLEWARE', false), // Auto-register middleware globally
	'disable_local_bypass' => filter_var(env('HELPER_DISABLE_LOCAL_BYPASS', 'false'), FILTER_VALIDATE_BOOLEAN), // Force validation even in local environment (for testing)
	'skip_routes'    => [
		'health',
		'api/health',
		'helper/status',
		'admin/helper',
		'storage',
		'vendor',
		'assets',
	],
	'validation' => [
		'max_failures' => 10, // Max failures before IP blacklist
		'blacklist_duration' => 24, // Hours to blacklist IP
		'max_installations' => 2, // Max installations per license
		'success_log_interval' => 100, // Log every N successful validations
	],
	'deployment' => [
		'bind_to_domain_only' => env('HELPER_BIND_DOMAIN_ONLY', false), // Lock helper to domain instead of IP/fingerprint
		'canonical_domain' => env('HELPER_CANONICAL_DOMAIN'), // Override domain detection
		'installation_id' => env('HELPER_INSTALLATION_ID'), // Pre-configured installation ID
		'force_regenerate_fingerprint' => env('HELPER_FORCE_REGENERATE_FINGERPRINT', false),
		'deployment_allowed_environments' => ['production', 'staging'], // Environments where deployment constraints apply
		'graceful_deployment_window' => 24, // Hours to allow license mismatch during deployment
	],
	'stealth' => [
		'enabled' => env('HELPER_STEALTH_MODE', true), // Enable silent operation
		'hide_ui_elements' => env('HELPER_HIDE_UI', true), // Hide all helper UI elements
		'mute_logs' => env('HELPER_MUTE_LOGS', true), // Suppress helper logs from client view
		'background_validation' => env('HELPER_BACKGROUND_VALIDATION', true), // Validate in background
		'validation_timeout' => env('HELPER_VALIDATION_TIMEOUT', 5), // Quick timeout for stealth
		'fallback_grace_period' => env('HELPER_GRACE_PERIOD', 72), // Hours of grace when server unreachable
		'silent_fail' => env('HELPER_SILENT_FAIL', true), // Don't show errors to client
		'deferred_enforcement' => env('HELPER_DEFERRED_ENFORCEMENT', true), // Delay enforcement for UX
	],
	'anti_reselling' => [
		'threshold_score' => env('HELPER_RESELL_THRESHOLD', 75), // Suspicion score threshold
		'max_domains' => env('HELPER_MAX_DOMAINS', 2), // Max domains per helper
		'max_per_geo' => env('HELPER_MAX_PER_GEO', 3), // Max installations per geographic area
		'detect_vpn' => env('HELPER_DETECT_VPN', true), // Enable VPN/Proxy detection
		'monitor_patterns' => env('HELPER_MONITOR_PATTERNS', true), // Monitor usage patterns
		'file_integrity' => env('HELPER_FILE_INTEGRITY', true), // Check critical file integrity
		'network_analysis' => env('HELPER_NETWORK_ANALYSIS', true), // Analyze network behavior
		'report_interval' => env('HELPER_REPORT_INTERVAL', 24), // Hours between suspicious activity reports
	],
	'code_protection' => [
		'obfuscation_enabled' => env('HELPER_OBFUSCATE', true), // Enable code obfuscation
		'watermarking' => env('HELPER_WATERMARK', true), // Add invisible watermarks
		'runtime_checks' => env('HELPER_RUNTIME_CHECKS', true), // Runtime integrity checks
		'dynamic_validation' => env('HELPER_DYNAMIC_VALIDATION', true), // Dynamic validation keys
		'anti_debug' => env('HELPER_ANTI_DEBUG', true), // Anti-debugging measures
	],
	'remote_security_logging' => env('HELPER_REMOTE_SECURITY_LOGGING', true),
	'deployment_security' => [
		'auto_secure' => env('HELPER_AUTO_SECURE_DEPLOYMENT', true),
		'remove_dev_files' => env('HELPER_REMOVE_DEV_FILES', true),
		'encrypt_sensitive_config' => env('HELPER_ENCRYPT_CONFIG', true),
		'harden_php_settings' => env('HELPER_HARDEN_PHP', true),
		'secure_file_permissions' => env('HELPER_SECURE_PERMISSIONS', true),
		'monitor_deployment_changes' => env('HELPER_MONITOR_DEPLOYMENT', true),
	],
	'environment_hardening' => [
		'production_only_features' => env('HELPER_PRODUCTION_ONLY', true),
		'disable_debug_tools' => env('HELPER_DISABLE_DEBUG_TOOLS', true),
		'restrict_function_access' => env('HELPER_RESTRICT_FUNCTIONS', true),
		'enforce_https' => env('HELPER_ENFORCE_HTTPS', true),
		'disable_error_display' => env('HELPER_DISABLE_ERROR_DISPLAY', true),
		'secure_session_config' => env('HELPER_SECURE_SESSIONS', true),
	],
	'monitoring' => [
		'email_alerts' => env('HELPER_EMAIL_ALERTS', true),
		'log_alerts' => env('HELPER_LOG_ALERTS', true),
		'remote_alerts' => env('HELPER_REMOTE_ALERTS', true),
		'alert_email' => env('HELPER_ALERT_EMAIL', 'security@insurance-core.com'),
		'alert_threshold' => env('HELPER_ALERT_THRESHOLD', 5), // alerts per hour
		'critical_alerts_only' => env('HELPER_CRITICAL_ALERTS_ONLY', false),
	],
	'vendor_protection' => [
		'enabled' => env('HELPER_VENDOR_PROTECTION', true),
		'integrity_checks' => env('HELPER_VENDOR_INTEGRITY_CHECKS', true),
		'file_locking' => env('HELPER_VENDOR_FILE_LOCKING', true),
		'decoy_files' => env('HELPER_VENDOR_DECOY_FILES', true),
		'terminate_on_critical' => env('HELPER_TERMINATE_ON_CRITICAL', false),
		'self_healing' => env('HELPER_VENDOR_SELF_HEALING', false),
		'backup_enabled' => env('HELPER_VENDOR_BACKUP', true),
		'monitoring_interval' => env('HELPER_VENDOR_MONITOR_INTERVAL', 300), // seconds
	],
];

