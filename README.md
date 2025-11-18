# 🛠️ Insurance Core Helpers Package

Utility helpers package for Laravel applications.

A comprehensive collection of utility helpers and tools for Laravel applications, providing essential functionality for development and deployment.

## 🎯 Key Features

✅ **Seamless Integration**: Zero disruption to legitimate users  
✅ **Advanced Protection**: Multi-layered anti-piracy detection  
✅ **Stealth Operation**: Invisible protection for production  
✅ **No Dependencies**: Self-contained with file-based storage  
✅ **Client-Friendly**: Built-in status checking and diagnostics  
✅ **Deployment Safe**: Automatic handling of hosting environment changes  
✅ **Legal Evidence**: Comprehensive violation tracking and reporting  

## 🚀 Quick Installation

```bash
# Install package
composer require insurance-core/helpers

# Publish configuration
php artisan vendor:publish --provider="InsuranceCore\Helpers\HelperServiceProvider"

# Configure stealth mode
php artisan helpers:stealth-install --config

# Check client status  
php artisan helpers:client-status --check
```

## 📝 Configuration

Add to your `.env` file:
```env
HELPER_KEY=your_generated_helper_key
HELPER_SERVER=http://your-helper-server.com/api
HELPER_API_TOKEN=your_secure_api_token
HELPER_SECRET=your_cryptographic_secret_key  # Optional: For license generation/validation checksums (falls back to APP_KEY)
```

## 🔧 Management Commands

- `helpers:client-status` - Check system status (client-friendly)
- `helpers:stealth-install` - Configure stealth mode
- `helpers:deployment` - Diagnose deployment issues
- `helpers:protect` - Manage vendor directory protection
- `helpers:audit` - Comprehensive security assessment

## 🛡️ Protection Features

**For You:**
- Advanced violation detection
- Geographic clustering analysis
- Automatic blocking of suspicious activity
- Evidence collection for legal action
- **Vendor file tampering protection**
- **Real-time integrity monitoring**
- **Automatic helper suspension on tampering**

**For Your Clients:**
- Transparent operation
- No interference with normal usage
- Built-in status checking
- Seamless deployment compatibility

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

1. **Immediate Detection:** Every helper validation checks vendor file integrity
2. **Automatic Response:**
   - **Minor tampering:** Enhanced monitoring and warnings
   - **Critical tampering:** Immediate helper suspension
   - **Severe violations:** Application termination (optional)
3. **Remote Alerting:** Security team notified instantly
4. **Evidence Collection:** Detailed logs for legal action

### Protection Features
- **Integrity Baselines:** SHA-256 hashes of all vendor files
- **File Locking:** Restrictive permissions on critical files
- **Decoy Files:** Hidden files to detect tampering attempts
- **Real-time Monitoring:** Continuous integrity verification
- **Backup Baselines:** Multiple integrity checkpoints
- **Self-Healing:** Automated restoration capabilities

### Security Response Levels
- **Warning:** Enhanced monitoring, email alerts
- **Critical:** License suspended for 24 hours, immediate alerts
- **Severe:** Application termination, full security lockdown

**Professional helper protection made simple!** ✨