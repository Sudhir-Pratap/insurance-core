# 🔐 Complete Activation Guide

This guide will walk you through the complete process of activating the Insurance Core Helpers package.

## 📋 Prerequisites

- Laravel application installed
- Access to license server
- Admin access to the application

## 🚀 Step-by-Step Activation

### Step 1: Install Package

```bash
composer require insurance-core/helpers
```

### Step 2: Publish Configuration

```bash
php artisan vendor:publish --provider="InsuranceCore\Helpers\HelperServiceProvider"
```

This creates the `config/helpers.php` file with all default settings.

### Step 3: Get System Information

Run the following command to get your system identifiers:

```bash
php artisan helpers:info
```

**Output Example:**
```
System Information:

Hardware Fingerprint: beb22a5c13036385df8dfea73188de7114b359c5dacbee6412e1d341382a7e23
Installation ID: 32a62ae2-c019-470d-887e-521b9030c612
Server IP: 192.168.1.100
Domain: example.com

Current Configuration:
System Key: Not set
Product ID: Not set
Client ID: Not set
Server URL: https://license.acecoderz.com/
```

**📝 Copy these values** - you'll need them for license generation:
- Hardware Fingerprint
- Installation ID
- Server IP
- Domain

### Step 4: Generate System Key on License Server

You need to generate a system key on your license server using the information from Step 3.

#### Option A: Using Artisan Command (if you have access to license server)

```bash
php artisan helpers:generate \
  --product-id=YOUR_PRODUCT_ID \
  --domain=example.com \
  --ip=192.168.1.100 \
  --client-id=YOUR_CLIENT_ID \
  --hardware-fingerprint=beb22a5c13036385df8dfea73188de7114b359c5dacbee6412e1d341382a7e23 \
  --installation-id=32a62ae2-c019-470d-887e-521b9030c612
```

#### Option B: Using License Server Web Interface

1. Log in to your license server admin panel
2. Navigate to "Generate License" or "Create License"
3. Enter the following information:
   - **Product ID**: Your product identifier
   - **Client ID**: Your client identifier
   - **Domain**: The domain from Step 3
   - **IP Address**: The server IP from Step 3
   - **Hardware Fingerprint**: The fingerprint from Step 3
   - **Installation ID**: The installation ID from Step 3
4. Click "Generate" to create the system key
5. **Copy the generated system key** - you'll need it for Step 5

#### Option C: Using License Server API

```bash
curl -X POST https://your-license-server.com/api/generate \
  -H "Authorization: Bearer YOUR_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "product_id": "YOUR_PRODUCT_ID",
    "client_id": "YOUR_CLIENT_ID",
    "domain": "example.com",
    "ip": "192.168.1.100",
    "hardware_fingerprint": "beb22a5c13036385df8dfea73188de7114b359c5dacbee6412e1d341382a7e23",
    "installation_id": "32a62ae2-c019-470d-887e-521b9030c612"
  }'
```

### Step 5: Configure Environment Variables

Add the following to your `.env` file:

```env
# ============================================
# REQUIRED: System Activation
# ============================================
HELPER_KEY=your_generated_system_key_from_step_4
HELPER_PRODUCT_ID=your_product_id
HELPER_CLIENT_ID=your_client_id
HELPER_API_TOKEN=your_secure_api_token

# ============================================
# OPTIONAL: Server URL (has default)
# ============================================
# HELPER_SERVER=https://license.acecoderz.com/
```

**Important Notes:**
- `HELPER_KEY` is the system key generated in Step 4
- `HELPER_PRODUCT_ID` is your product identifier
- `HELPER_CLIENT_ID` is your client identifier
- `HELPER_API_TOKEN` is your API token for license server authentication
- `HELPER_SERVER` is optional (defaults to `https://license.acecoderz.com/`)

### Step 6: Clear Configuration Cache

After adding environment variables, clear the config cache:

```bash
php artisan config:clear
php artisan cache:clear
```

### Step 7: Verify Configuration

Check if your configuration is correct:

```bash
php artisan helpers:info
```

**Expected Output:**
```
System Information:

Hardware Fingerprint: beb22a5c13036385df8dfea73188de7114b359c5dacbee6412e1d341382a7e23
Installation ID: 32a62ae2-c019-470d-887e-521b9030c612
Server IP: 192.168.1.100
Domain: example.com

Current Configuration:
System Key: Configured ✅
Product ID: YOUR_PRODUCT_ID ✅
Client ID: YOUR_CLIENT_ID ✅
Server URL: https://license.acecoderz.com/
```

### Step 8: Setup Vendor Protection (Recommended)

Initialize vendor file protection to detect tampering:

```bash
php artisan helpers:protect --setup
```

This creates integrity baselines for all vendor files.

### Step 9: Run Diagnostics

Verify everything is working correctly:

```bash
php artisan helpers:diagnose
```

This will check:
- ✅ Configuration completeness
- ✅ Cache status
- ✅ Hardware fingerprint
- ✅ System validation
- ✅ Protection validation
- ✅ Server connectivity

### Step 10: Run Security Audit

Perform a comprehensive security audit:

```bash
php artisan helpers:audit
```

This will verify:
- ✅ All security features are active
- ✅ Vendor protection is configured
- ✅ Middleware is registered
- ✅ All validations are working

### Step 11: Test Validation

Test that validation is working:

```bash
php artisan helpers:deployment --test
```

This will:
- Test system validation
- Verify server connectivity
- Check all security checks

### Step 12: Deploy to Production

When deploying to production:

1. **Environment Detection**: The package automatically detects production environment
2. **Auto-Enforcement**: Validation is automatically enforced in production
3. **Auto-Skip**: Validation is automatically skipped in local/dev/testing/staging

**No additional configuration needed!**

## 🔍 Troubleshooting

### Issue: "System Key: Not set"

**Solution:**
1. Verify `HELPER_KEY` is in your `.env` file
2. Run `php artisan config:clear`
3. Check for typos in the environment variable name

### Issue: "Server validation failed"

**Solution:**
1. Check `HELPER_API_TOKEN` is correct
2. Verify `HELPER_SERVER` URL is accessible
3. Check server connectivity: `php artisan helpers:diagnose`
4. Verify the system key matches the server records

### Issue: "Hardware fingerprint mismatch"

**Solution:**
1. This is normal if server hardware changed
2. Run `php artisan helpers:deployment --fix` to update fingerprint
3. Or regenerate system key with new fingerprint

### Issue: "Domain/IP mismatch"

**Solution:**
1. Run `php artisan helpers:deployment --check` to see current values
2. Update system key on license server with new domain/IP
3. Or use `php artisan helpers:deployment --fix` to attempt automatic fix

## 📝 Quick Reference Commands

```bash
# Get system information
php artisan helpers:info

# Diagnose issues
php artisan helpers:diagnose

# Fix deployment issues
php artisan helpers:deployment --fix

# Test validation
php artisan helpers:deployment --test

# Setup vendor protection
php artisan helpers:protect --setup

# Run security audit
php artisan helpers:audit

# Clear cache
php artisan helpers:clear-cache
```

## ✅ Activation Checklist

- [ ] Package installed via Composer
- [ ] Configuration published
- [ ] System information retrieved (`helpers:info`)
- [ ] System key generated on license server
- [ ] Environment variables added to `.env`
- [ ] Configuration cache cleared
- [ ] Configuration verified (`helpers:info`)
- [ ] Vendor protection setup (`helpers:protect --setup`)
- [ ] Diagnostics passed (`helpers:diagnose`)
- [ ] Security audit passed (`helpers:audit`)
- [ ] Validation tested (`helpers:deployment --test`)

## 🎯 Post-Activation

After activation, the package will:

- ✅ **Automatically validate** in production environment
- ✅ **Automatically skip** validation in non-production environments
- ✅ **Monitor vendor files** for tampering (48-hour grace period)
- ✅ **Detect reselling** attempts
- ✅ **Send alerts** for security violations
- ✅ **Log events** remotely for monitoring

**No further action needed!** The package works automatically.

## 📞 Support

If you encounter issues during activation:

1. Run `php artisan helpers:diagnose` to identify problems
2. Check the troubleshooting section above
3. Review server logs for detailed error messages
4. Contact support with diagnostic output

---

**Activation complete! Your system is now protected.** 🛡️

