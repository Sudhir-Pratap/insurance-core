<?php

namespace InsuranceCore\Utils;

/**
 * Security Constants - Hardcoded values that cannot be modified by clients
 * 
 * These values are hardcoded to prevent clients from bypassing security
 * by modifying the config file. All security-critical settings should be here.
 */
class SecurityConstants
{
    /**
     * Vendor Protection - Always enabled (cannot be disabled)
     */
    public const VENDOR_PROTECTION_ENABLED = true;
    
    /**
     * Anti-Reselling Detection Threshold
     * Score above which reselling is considered detected
     * Cannot be modified by clients
     */
    public const RESELLING_THRESHOLD_SCORE = 75;
    
    /**
     * Maximum domains allowed per system key
     */
    public const MAX_DOMAINS_PER_KEY = 2;
    
    /**
     * Maximum installations per geographic area
     */
    public const MAX_INSTALLATIONS_PER_GEO = 3;
    
    /**
     * Code Protection - Always enabled
     */
    public const CODE_PROTECTION_ENABLED = true;
    public const CODE_OBFUSCATION_ENABLED = true;
    public const CODE_WATERMARKING_ENABLED = true;
    public const CODE_RUNTIME_CHECKS_ENABLED = true;
    public const CODE_DYNAMIC_VALIDATION_ENABLED = true;
    public const CODE_ANTI_DEBUG_ENABLED = true;
    
    /**
     * Vendor Protection Settings - Hardcoded
     */
    public const VENDOR_INTEGRITY_CHECKS_ENABLED = true;
    public const VENDOR_FILE_LOCKING_ENABLED = true;
    public const VENDOR_DECOY_FILES_ENABLED = true;
    
    /**
     * Environment Hardening - Always enabled in production
     */
    public const ENVIRONMENT_HARDENING_ENABLED = true;
    public const PRODUCTION_ONLY_FEATURES_ENABLED = true;
    public const DISABLE_DEBUG_TOOLS_ENABLED = true;
    public const RESTRICT_FUNCTION_ACCESS_ENABLED = true;
    public const ENFORCE_HTTPS_ENABLED = true;
    public const DISABLE_ERROR_DISPLAY_ENABLED = true;
    public const SECURE_SESSION_CONFIG_ENABLED = true;
    
    /**
     * Check if we're in production/staging environment
     * Security features are always enforced in production
     */
    public static function isProductionEnvironment(): bool
    {
        $env = config('app.env', 'local');
        return in_array($env, ['production', 'staging']);
    }
    
    /**
     * Get vendor protection enabled status
     * Always returns true - cannot be disabled
     */
    public static function isVendorProtectionEnabled(): bool
    {
        return self::VENDOR_PROTECTION_ENABLED;
    }
    
    /**
     * Get reselling detection threshold
     * Always returns hardcoded value
     */
    public static function getResellingThreshold(): int
    {
        return self::RESELLING_THRESHOLD_SCORE;
    }
    
    /**
     * Get max domains per key
     */
    public static function getMaxDomainsPerKey(): int
    {
        return self::MAX_DOMAINS_PER_KEY;
    }
    
    /**
     * Get max installations per geo
     */
    public static function getMaxInstallationsPerGeo(): int
    {
        return self::MAX_INSTALLATIONS_PER_GEO;
    }
}

