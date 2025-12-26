# When Does the Application Terminate?

This document explains exactly when and how the application will be terminated (blocked) by the security system.

## Summary

**The app ONLY terminates when middleware is enabled AND validation fails.**

If middleware is commented out, the app **NEVER terminates** - it only logs violations and reports them to the license server.

---

## Termination Points

### 1. **Middleware Layer (Primary Termination Point)**

The app terminates at the middleware level when validation fails. There are two middleware classes:

#### A. `SecurityProtection` Middleware
**Location:** `src/Http/Middleware/SecurityProtection.php`

**Terminates when:**
- Middleware is enabled in `Kernel.php`
- System validation fails (`validateSystem()` returns `false`)
- **Action:** Calls `abort(403, 'Invalid or unauthorized system key.')`

```php
if (! $this->getSystemManager()->validateSystem($systemKey, $productId, $currentDomain, $currentIp, $clientId)) {
    Log::error('System validation failed, aborting request', [...]);
    abort(403, 'Invalid or unauthorized system key.'); // ← TERMINATES HERE
}
```

#### B. `AntiPiracySecurity` Middleware
**Location:** `src/Http/Middleware/AntiPiracySecurity.php`

**Terminates when:**
- Middleware is enabled in `Kernel.php`
- Comprehensive anti-piracy validation fails (`validateAntiPiracy()` returns `false`)
- **Action:** Returns HTTP 403 response (JSON for API, error page for web)

```php
if (!$this->getAntiPiracyManager()->validateAntiPiracy()) {
    $this->handleValidationFailure($request);
    return $this->getFailureResponse($request); // ← TERMINATES HERE (403 response)
}
```

**Failure Response Types:**
- **API Requests:** JSON error with `SYSTEM_INVALID` code
- **Web Requests:** Error view page
- **Blacklisted IPs:** JSON error with `IP_BLACKLISTED` code

---

## What Causes Validation to Fail?

### Critical Validations (Must Pass - Otherwise App Terminates)

If any of these fail **AND middleware is enabled**, the app will terminate:

#### 1. **System Validation** (`validateSystem()`)
**Fails when:**
- System key is invalid or unauthorized
- Product ID doesn't match
- Client ID doesn't match
- Domain/IP not authorized
- **Exception:** Fresh installs get 7-day grace period (configurable via `UTILS_GRACE_PERIOD_DAYS`)

#### 2. **Installation ID Validation** (`validateInstallationId()`)
**Fails when:**
- Installation ID file is missing or changed
- Installation ID doesn't match stored value
- **Note:** First run creates the ID, so it always passes initially

#### 3. **Tampering Detection** (`detectTampering()`)
**Fails when:**
- Package files in `vendor/insurance-core/utils` are modified
- Critical files have different SHA256 hashes than baseline
- Middleware is removed from `Kernel.php` (detected via cache checks)
- **Critical files checked:**
  - `Manager.php`
  - `SecurityManager.php`
  - `UtilsServiceProvider.php`
  - `Services/VendorProtectionService.php`
  - `Services/CopyProtectionService.php`
  - `Http/Middleware/*.php`

#### 4. **Vendor Integrity** (`validateVendorIntegrity()`)
**Fails when:**
- Critical or high-severity violations detected in vendor directory
- Package files are deleted or modified
- **Note:** Non-critical violations are logged but don't cause termination

### Non-Critical Validations (Can Fail Up to 2 Times)

These can fail without termination, but if **more than 2 fail simultaneously**, validation returns `false`:

- Hardware fingerprint validation
- Environment validation
- Usage patterns validation
- Server communication validation

---

## What Does NOT Terminate the App?

### 1. **Service Provider Layer** (`UtilsServiceProvider`)
**Location:** `src/UtilsServiceProvider.php`

**Never terminates** - runs silently in background:
- Domain tracking (`checkMultipleDomainUsage()`)
- Background validation (`validateAntiPiracy()`)
- All exceptions are caught and silently logged
- Runs even if middleware is commented out

```php
// This NEVER terminates the app
protected function addServiceProviderValidation(): void
{
    try {
        // ... validation code ...
    } catch (\Exception $e) {
        // Silently fail - don't expose errors
    }
}
```

### 2. **Reselling Detection**
**Location:** `src/Services/CopyProtectionService.php`

**Never terminates** - only logs and reports:
- Detects multiple domain usage
- Detects suspicious reselling patterns
- Logs to remote server for server-side blocking
- **Client-side app continues to work** (server blocks license instead)

### 3. **Remote Security Logging**
**Location:** `src/Services/RemoteSecurityLogger.php`

**Never terminates** - only reports:
- Sends security events to license server
- Server-side can block/revoke licenses
- Client-side app continues until server blocks the license

---

## Environment-Based Behavior

### Local/Development Environments
**Never terminates** - validation is bypassed:
- `app.env` = `local`, `dev`, `development`, `testing`
- Middleware skips validation
- Service provider skips validation
- **Exception:** Can be disabled via `utils.disable_local_bypass = true`

### Production/Staging Environments
**Terminates when validation fails:**
- Middleware validates on every request
- Service provider validates in background
- Grace period applies for fresh installs (7 days default)

---

## Grace Period for Fresh Installs

**When:** System key not configured in production/staging

**Behavior:**
- **Days 0-7:** App works, warnings logged daily
- **After Day 7:** App still works, critical warnings logged daily
- **Never terminates** due to missing config (prevents breaking fresh installs)

**Configurable via:** `UTILS_GRACE_PERIOD_DAYS` (default: 7)

---

## Middleware Status Impact

### Middleware Enabled
```
Request → Middleware → validateAntiPiracy() → Returns false → App TERMINATES (403)
```

### Middleware Commented Out
```
Request → Service Provider → validateAntiPiracy() → Returns false → App CONTINUES
                                                                    → Logs violation
                                                                    → Reports to server
```

**Key Point:** If middleware is commented out, the app **NEVER terminates** on the client side. All violations are logged and reported to the license server, which can then block/revoke the license server-side.

---

## IP Blacklisting

**Terminates when:**
- IP has more than 10 validation failures (configurable via `utils.validation.max_failures`)
- Blacklist duration: 24 hours (configurable via `utils.validation.blacklist_duration`)
- Returns 403 with `IP_BLACKLISTED` code

---

## Summary Table

| Scenario | Middleware Enabled | Middleware Disabled |
|----------|----------------|----------------------|
| System validation fails | ❌ **TERMINATES** (403) | ✅ Continues (logs only) |
| Installation ID fails | ❌ **TERMINATES** (403) | ✅ Continues (logs only) |
| Tampering detected | ❌ **TERMINATES** (403) | ✅ Continues (logs only) |
| Vendor integrity fails | ❌ **TERMINATES** (403) | ✅ Continues (logs only) |
| Reselling detected | ✅ Continues (logs + reports) | ✅ Continues (logs + reports) |
| Multiple domains | ✅ Continues (logs + reports) | ✅ Continues (logs + reports) |
| Service provider validation | ✅ Continues (background) | ✅ Continues (background) |

---

## Configuration Options

### Disable Termination (Not Recommended)
```php
// In Kernel.php - comment out middleware
// protected $middlewareGroups = [
//     'web' => [
//         // \InsuranceCore\Utils\Http\Middleware\AntiPiracySecurity::class,
//     ],
// ];
```

### Skip Routes
```php
// config/utils.php
'skip_routes' => [
    'api/webhook',
    'health-check',
],
```

### Bypass Token (Emergency Access)
```php
// config/utils.php
'bypass_token' => 'your-secret-token',

// Use: Add header to request
// X-System-Bypass: your-secret-token
```

---

## Best Practices

1. **Always enable middleware in production** for client-side protection
2. **Service provider layer** ensures reselling detection works even without middleware
3. **Server-side blocking** is the ultimate protection (can't be bypassed)
4. **Grace period** prevents breaking fresh installs
5. **Logging** ensures all violations are tracked for server-side action

---

## Conclusion

**The app terminates ONLY when:**
1. ✅ Middleware is enabled
2. ✅ Validation fails (critical checks)
3. ✅ Request is not in local/dev environment
4. ✅ No bypass token is provided

**The app NEVER terminates when:**
1. ❌ Middleware is commented out
2. ❌ Only service provider validation runs
3. ❌ Only reselling detection runs
4. ❌ Only remote logging runs
5. ❌ In local/dev environments (unless bypass disabled)

**Server-side blocking** is the final protection layer that cannot be bypassed by commenting out middleware.

