# Reselling Detection Without Middleware

## Overview

The `insurance-core` package has **multiple layers** of reselling detection that work **even if middleware is commented out**. This ensures that reselling can still be detected and reported to the license server.

## How Reselling Detection Works

### 1. **Service Provider Layer** (Always Active)

The `UtilsServiceProvider` runs on **every request** and includes:

- **Domain Tracking**: Tracks domains using the same system key or hardware fingerprint
- **Background Validation**: Runs `validateAntiPiracy()` in the background
- **Works Without Middleware**: This layer is independent of middleware registration

```php
// In UtilsServiceProvider::addServiceProviderValidation()
// Always tracks domain usage
$copyProtectionService->checkMultipleDomainUsage();

// Runs full validation including reselling detection
$securityManager->validateAntiPiracy();
```

### 2. **validateAntiPiracy() Method**

This method is called by:
- Service provider (every request)
- Middleware (if enabled)
- Background validator
- Manual validation calls

It includes `validateUsagePatterns()` which now includes reselling detection.

### 3. **validateUsagePatterns() Method** (Enhanced)

Now includes comprehensive reselling detection:

```php
// Track domain usage
$domainSuspicionScore = $copyProtectionService->checkMultipleDomainUsage();

// Detect reselling behavior
$isReselling = $copyProtectionService->detectResellingBehavior([
    'validation_source' => 'validateUsagePatterns',
    'middleware_disabled' => $this->checkMiddlewareCommentedOut(),
]);
```

### 4. **CopyProtectionService**

Tracks multiple indicators:

- **Multiple Domains**: Detects if same system key/hardware fingerprint is used on multiple domains
- **Usage Patterns**: Analyzes request patterns for suspicious behavior
- **Deployment Patterns**: Checks for unusual deployment configurations
- **Code Modifications**: Detects tampering attempts
- **Network Behavior**: Analyzes network patterns
- **Installation Clustering**: Detects multiple installations

## Detection Mechanisms

### Domain Tracking

Works with or without `system_key`:

```php
// If system_key is configured
$domainKey = 'system_domains_' . md5($systemKey);

// If system_key is NOT configured (fallback)
$hardwareFingerprint = generateHardwareFingerprint();
$domainKey = 'system_domains_fingerprint_' . md5($hardwareFingerprint);
```

**Tracks:**
- All domains using the same system key
- All domains using the same hardware fingerprint
- Maximum allowed: 2 domains (configurable)

### Reselling Indicators

The system calculates a suspicion score based on:

1. **Multiple Domains** (0-50 points)
   - 1 domain: 0 points
   - 2 domains: 20 points
   - 3+ domains: 50 points (high suspicion)

2. **Usage Patterns** (0-30 points)
   - Unusual request patterns
   - Suspicious user agents
   - Rapid domain switching

3. **Deployment Patterns** (0-20 points)
   - Multiple IP ranges
   - Geographic clustering
   - VPN/proxy usage

4. **Code Modifications** (0-40 points)
   - File integrity violations
   - Code tampering
   - Vendor protection bypass

5. **Network Behavior** (0-30 points)
   - Unusual network patterns
   - Suspicious traffic patterns

6. **Installation Clustering** (0-25 points)
   - Multiple installations in short time
   - Geographic clustering

**Threshold**: Default 75 points (configurable via `UTILS_RESELL_THRESHOLD`)

## What Happens When Reselling is Detected

### Client-Side (Even Without Middleware)

1. **Domain Tracking**: Always tracks domains via service provider
2. **Detection**: `validateUsagePatterns()` detects reselling
3. **Logging**: Logs to remote server via `RemoteSecurityLogger`
4. **Warning**: Logs warning but doesn't block (server handles blocking)

### Server-Side

1. **Receives Reports**: Gets reselling attempts from client
2. **Analyzes Data**: Server-side analysis of all reports
3. **Blocks License**: Server can block/revoke license
4. **Tracks Violations**: Records in `license_violations` table

## Ensuring Detection Works

### Even If Middleware is Commented Out

✅ **Service Provider** - Runs on every request  
✅ **validateAntiPiracy()** - Called by service provider  
✅ **validateUsagePatterns()** - Includes reselling detection  
✅ **Domain Tracking** - Happens in service provider  
✅ **Remote Logging** - Reports to license server  

### Configuration

Ensure these are set in `.env`:

```env
UTILS_KEY=your_system_key
UTILS_PRODUCT_ID=your_product_id
UTILS_CLIENT_ID=your_client_id
UTILS_API_TOKEN=your_api_token
UTILS_SERVER=https://your-license-server.com/api
```

### Optional Configuration

```env
# Reselling detection threshold (default: 75)
UTILS_RESELL_THRESHOLD=75

# Max domains allowed (default: 2)
UTILS_MAX_DOMAINS=2

# Max installations per geographic area (default: 3)
UTILS_MAX_PER_GEO=3
```

## Testing Reselling Detection

### Check if Detection is Working

```bash
php artisan utils:test
```

This will show:
- Domain tracking status
- Reselling detection status
- Middleware status
- Validation results

### Manual Check

```bash
php artisan utils:copy-protection
```

Shows:
- Current domains tracked
- Suspicion score
- Reselling status

## Important Notes

1. **Middleware is Optional**: Reselling detection works without middleware
2. **Service Provider is Key**: This is the primary detection mechanism
3. **Server-Side Authority**: Client detects and reports, server blocks
4. **Grace Period**: Works even during grace period (fresh installations)
5. **Hardware Fingerprint Fallback**: Works even without `system_key` configured

## Summary

**Reselling detection works through multiple layers:**

1. ✅ Service Provider (always active)
2. ✅ validateAntiPiracy() (called by service provider)
3. ✅ validateUsagePatterns() (includes reselling detection)
4. ✅ CopyProtectionService (tracks domains and patterns)
5. ✅ RemoteSecurityLogger (reports to server)

**Even if middleware is commented out, reselling detection still works!**

