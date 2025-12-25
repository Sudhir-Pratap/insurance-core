<?php

return [
	// Note: UTILS_SECRET (cryptographic key for system key generation/validation) is accessed directly via env()
	// It falls back to APP_KEY if not set
	
	// Generic environment variable names
	'system_key'    => env('UTILS_KEY'),
	'product_id'     => env('UTILS_PRODUCT_ID'),
	'client_id'      => env('UTILS_CLIENT_ID'),
	'validation_server' => env('UTILS_SERVER', 'https://license.acecoderz.com/'),
	'api_token'      => env('UTILS_API_TOKEN'),
	'cache_duration' => env('UTILS_CACHE_DURATION', 1440), // 24 hours in minutes
	'security_hash'  => env('UTILS_SECURITY_HASH'),
	'bypass_token'   => env('UTILS_BYPASS_TOKEN'),
	'support_email'  => env('UTILS_SUPPORT_EMAIL', 'support@insurancecore.com'),
	'auto_middleware' => env('UTILS_AUTO_MIDDLEWARE', false), // Auto-register middleware globally
	'disable_local_bypass' => filter_var(env('UTILS_DISABLE_LOCAL_BYPASS', 'false'), FILTER_VALIDATE_BOOLEAN), // Force validation even in local environment (for testing)
	'skip_routes'    => [
		'health',
		'api/health',
		'system/status',
		'admin/system',
		'storage',
		'vendor',
		'assets',
	],
	'validation' => [
		'max_failures' => 10, // Max failures before IP blacklist
		'blacklist_duration' => 24, // Hours to blacklist IP
		'max_installations' => 2, // Max installations per system key
		'success_log_interval' => 100, // Log every N successful validations
	],
	'deployment' => [
		'bind_to_domain_only' => env('UTILS_BIND_DOMAIN_ONLY', false), // Lock system to domain instead of IP/fingerprint
		'canonical_domain' => env('UTILS_CANONICAL_DOMAIN'), // Override domain detection
		'installation_id' => env('UTILS_INSTALLATION_ID'), // Pre-configured installation ID
		'force_regenerate_fingerprint' => env('UTILS_FORCE_REGENERATE_FINGERPRINT', false),
		'deployment_allowed_environments' => ['production', 'staging'], // Environments where deployment constraints apply
		'graceful_deployment_window' => 24, // Hours to allow system key mismatch during deployment
	],
	'stealth' => [
		'enabled' => env('UTILS_STEALTH_MODE', true), // Enable silent operation
		'hide_ui_elements' => env('UTILS_HIDE_UI', true), // Hide all system UI elements
		'mute_logs' => env('UTILS_MUTE_LOGS', true), // Suppress system logs from client view
		'background_validation' => env('UTILS_BACKGROUND_VALIDATION', true), // Validate in background
		'validation_timeout' => env('UTILS_VALIDATION_TIMEOUT', 5), // Quick timeout for stealth
		'fallback_grace_period' => env('UTILS_GRACE_PERIOD', 72), // Hours of grace when server unreachable
		'silent_fail' => env('UTILS_SILENT_FAIL', true), // Don't show errors to client
		'deferred_enforcement' => env('UTILS_DEFERRED_ENFORCEMENT', true), // Delay enforcement for UX
	],
	'anti_reselling' => [
		'threshold_score' => env('UTILS_RESELL_THRESHOLD', 75), // Suspicion score threshold
		'max_domains' => env('UTILS_MAX_DOMAINS', 2), // Max domains per system key
		'max_per_geo' => env('UTILS_MAX_PER_GEO', 3), // Max installations per geographic area
		'detect_vpn' => env('UTILS_DETECT_VPN', true), // Enable VPN/Proxy detection
		'monitor_patterns' => env('UTILS_MONITOR_PATTERNS', true), // Monitor usage patterns
		'file_integrity' => env('UTILS_FILE_INTEGRITY', true), // Check critical file integrity
		'network_analysis' => env('UTILS_NETWORK_ANALYSIS', true), // Analyze network behavior
		'report_interval' => env('UTILS_REPORT_INTERVAL', 24), // Hours between suspicious activity reports
	],
	'code_protection' => [
		'obfuscation_enabled' => env('UTILS_OBFUSCATE', true), // Enable code obfuscation
		'watermarking' => env('UTILS_WATERMARK', true), // Add invisible watermarks
		'runtime_checks' => env('UTILS_RUNTIME_CHECKS', true), // Runtime integrity checks
		'dynamic_validation' => env('UTILS_DYNAMIC_VALIDATION', true), // Dynamic validation keys
		'anti_debug' => env('UTILS_ANTI_DEBUG', true), // Anti-debugging measures
	],
	'remote_security_logging' => env('UTILS_REMOTE_SECURITY_LOGGING', true),
	'deployment_security' => [
		'auto_secure' => env('UTILS_AUTO_SECURE_DEPLOYMENT', true),
		'remove_dev_files' => env('UTILS_REMOVE_DEV_FILES', true),
		'encrypt_sensitive_config' => env('UTILS_ENCRYPT_CONFIG', true),
		'harden_php_settings' => env('UTILS_HARDEN_PHP', true),
		'secure_file_permissions' => env('UTILS_SECURE_PERMISSIONS', true),
		'monitor_deployment_changes' => env('UTILS_MONITOR_DEPLOYMENT', true),
	],
	'environment_hardening' => [
		'production_only_features' => env('UTILS_PRODUCTION_ONLY', true),
		'disable_debug_tools' => env('UTILS_DISABLE_DEBUG_TOOLS', true),
		'restrict_function_access' => env('UTILS_RESTRICT_FUNCTIONS', true),
		'enforce_https' => env('UTILS_ENFORCE_HTTPS', true),
		'disable_error_display' => env('UTILS_DISABLE_ERROR_DISPLAY', true),
		'secure_session_config' => env('UTILS_SECURE_SESSIONS', true),
	],
	'monitoring' => [
		'email_alerts' => env('UTILS_EMAIL_ALERTS', true),
		'log_alerts' => env('UTILS_LOG_ALERTS', true),
		'remote_alerts' => env('UTILS_REMOTE_ALERTS', true),
		'alert_email' => env('UTILS_ALERT_EMAIL', 'security@insurancecore.com'),
		'alert_threshold' => env('UTILS_ALERT_THRESHOLD', 5), // alerts per hour
		'critical_alerts_only' => env('UTILS_CRITICAL_ALERTS_ONLY', false),
	],
	'vendor_protection' => [
		'enabled' => env('UTILS_VENDOR_PROTECTION', true),
		'integrity_checks' => env('UTILS_VENDOR_INTEGRITY_CHECKS', true),
		'file_locking' => env('UTILS_VENDOR_FILE_LOCKING', true),
		'decoy_files' => env('UTILS_VENDOR_DECOY_FILES', true),
		'terminate_on_critical' => env('UTILS_TERMINATE_ON_CRITICAL', false),
		'self_healing' => env('UTILS_VENDOR_SELF_HEALING', false),
		'backup_enabled' => env('UTILS_VENDOR_BACKUP', true),
		'monitoring_interval' => env('UTILS_VENDOR_MONITOR_INTERVAL', 300), // seconds
	],
];
