# 🛠️ Insurance Core Helpers Package

Utility helpers package for Laravel applications.

A comprehensive collection of utility helpers and tools for Laravel applications, providing essential functionality for development and deployment.

## 🎯 Key Features

✅ **Seamless Integration**: Zero disruption to legitimate users  
✅ **Advanced Protection**: Multi-layered security detection  
✅ **Stealth Operation**: Invisible protection for production  
✅ **No Dependencies**: Self-contained with file-based storage  
✅ **Client-Friendly**: Minimal configuration required (only 4 env variables)  
✅ **Deployment Safe**: Automatic handling of hosting environment changes  
✅ **Environment Aware**: Auto-skips validation in non-production environments  
✅ **Legal Evidence**: Comprehensive violation tracking and reporting  

## 🚀 Quick Installation

```bash
# Install package
composer require insurance-core/helpers

# Publish configuration
php artisan vendor:publish --provider="InsuranceCore\Helpers\HelperServiceProvider"

# Check system information
php artisan helpers:info
```

## 📝 Configuration

**Minimal Setup - Only 4 Required Environment Variables:**

Add to your `.env` file:
```env
# REQUIRED: Only these 4 variables are needed
HELPER_KEY=your_generated_system_key
HELPER_PRODUCT_ID=your_product_id
HELPER_CLIENT_ID=your_client_id
HELPER_API_TOKEN=your_secure_api_token

# OPTIONAL: Server URL (has default)
# HELPER_SERVER=https://license.acecoderz.com/
```

**That's it!** All other settings have sensible defaults and work automatically.

### Environment-Based Validation

- **Production**: Full validation enforced automatically
- **Local/Dev/Testing**: Validation automatically skipped (no config needed)
- **Staging**: Validation automatically skipped (no config needed)

No environment variables needed for environment detection - it's automatic!

## 🔧 Management Commands

- `helpers:info` - Display system information and identifiers
- `helpers:diagnose` - Diagnose system validation issues
- `helpers:deployment` - Troubleshoot and fix system configuration issues during deployment
- `helpers:protect` - Manage directory protection and integrity monitoring
- `helpers:audit` - Run comprehensive system security audit
- `helpers:optimize` - Optimize vendor code for production
- `helpers:clear-cache` - Clear system cache and identifiers

## 🛡️ Protection Features

**For You:**
- Advanced violation detection
- Geographic clustering analysis
- Automatic blocking of suspicious activity
- Evidence collection for legal action
- **Vendor file tampering protection with 48-hour grace period**
- **Real-time integrity monitoring**
- **Automatic system suspension on tampering**

**For Your Clients:**
- Transparent operation
- No interference with normal usage
- Built-in status checking
- Seamless deployment compatibility
- **Zero package exposure** - completely stealth operation

## 🔒 Vendor Directory Protection

**Critical Security Feature:** Automatic detection and response to vendor file modifications.

### Setup Vendor Protection
```bash
# Initialize vendor protection (run after installation)
php artisan helpers:protect --setup

# Verify vendor integrity
php artisan helpers:protect --verify

# Generate tampering report
php artisan helpers:protect --report
```

### What Happens When Files Are Modified

1. **Immediate Detection:** Every security validation checks vendor file integrity
2. **48-Hour Grace Period:** 
   - Tampering is detected and logged immediately
   - Alerts are sent to security team
   - Validation fails only after 48 hours (allows time for legitimate updates)
   - If file is restored, grace period is cleared automatically
3. **Automatic Response:**
   - **During grace period:** Enhanced monitoring and warnings
   - **After grace period:** System suspension and immediate alerts
   - **Severe violations:** Application termination (optional)
4. **Remote Alerting:** Security team notified instantly
5. **Evidence Collection:** Detailed logs for legal action

### Protection Features
- **Integrity Baselines:** SHA-256 hashes of all vendor files
- **File Locking:** Restrictive permissions on critical files
- **Decoy Files:** Hidden files to detect tampering attempts
- **Real-time Monitoring:** Continuous integrity verification
- **Backup Baselines:** Multiple integrity checkpoints
- **Grace Period:** 48-hour window for legitimate file updates

### Security Response Levels
- **Warning (Grace Period):** Enhanced monitoring, email alerts, 48-hour window
- **Critical (Post-Grace):** System suspended, immediate alerts
- **Severe:** Application termination, full security lockdown

## 🔐 Security Features

### Client-Facing Security
- **Zero Package Exposure:** All client-facing messages are generic
- **No Separate Log Files:** All logs use default channel (no client-accessible files)
- **Generic Error Messages:** All errors show "Access denied" without package references
- **Stealth Operation:** Package is completely invisible to clients

### Anti-Reselling Protection
- **Multi-Domain Detection:** Monitors for suspicious domain switching
- **Usage Pattern Analysis:** Detects reselling behavior patterns
- **Geographic Clustering:** Identifies installations across multiple locations
- **Configurable Thresholds:** Balanced detection (catches resellers, allows legitimate use)

### Environment Hardening
- **Production-Only Features:** Security features automatically enabled in production
- **HTTPS Enforcement:** Automatic HTTPS enforcement
- **Debug Tool Disabling:** Automatically disables debug tools in production
- **Secure Session Configuration:** Enhanced session security

## 📊 Monitoring & Alerts

- **Email Alerts:** Automatic email notifications for security events
- **Remote Logging:** All security events logged to remote server
- **Throttled Alerts:** Prevents alert spam (configurable intervals)
- **Comprehensive Reports:** Detailed violation tracking and reporting

## 🎯 Best Practices

1. **Installation:** Run `php artisan helpers:info` after installation to get system identifiers
2. **Vendor Protection:** Run `php artisan helpers:protect --setup` after installation
3. **Deployment:** Use `php artisan helpers:deployment` to troubleshoot deployment issues
4. **Monitoring:** Regularly check `php artisan helpers:audit` for security status
5. **Environment:** No special configuration needed - production automatically enforces, others automatically skip

## 🔄 Version History

### v4.1.0 (Current)
- Complete client-facing message sanitization
- Removed all separate log files
- Reduced environment variables from 72 to 5 (4 required + 1 optional)
- Added 48-hour grace period for vendor file tampering
- Auto-skip validation in non-production environments
- Enhanced security and stealth operation

**Professional security protection made simple!** ✨
