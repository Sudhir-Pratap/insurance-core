# 🛠️ Insurance Core Utils Package

Utility helpers package for Laravel applications.

A comprehensive collection of utility helpers and tools for Laravel applications, providing essential functionality for development and deployment.

## 🎯 Key Features

✅ **Seamless Integration**: Easy to integrate with existing Laravel projects  
✅ **System Validation**: Built-in system validation and configuration checks  
✅ **Domain Whitelisting**: Supports domain whitelisting with wildcard patterns (e.g., `*.example.com`)  
✅ **Deployment Tools**: Helpful utilities for deployment and environment management  
✅ **Cache Management**: Efficient cache handling and optimization  
✅ **System Monitoring**: Built-in status checking and diagnostics  
✅ **Configuration Management**: Centralized configuration management  

## 🚀 Quick Installation

```bash
# Install package
composer require insurance-core/helpers

# Publish configuration
php artisan vendor:publish --provider="InsuranceCore\Utils\UtilsServiceProvider" --tag=config

# Check system status  
php artisan utils:info
```

## 📝 Configuration

Add to your `.env` file:
```env
UTILS_KEY=your_system_key
UTILS_SERVER=https://your-server.com/api
UTILS_API_TOKEN=your_secure_api_token
UTILS_PRODUCT_ID=your_product_id
UTILS_CLIENT_ID=your_client_id
UTILS_SECRET=your_cryptographic_secret_key  # Optional: For key generation/validation checksums (falls back to APP_KEY)
```


## 🔧 Management Commands

### System Information
- `utils:info` - Show system information and hardware fingerprint
- `utils:diagnose` - Diagnose system configuration issues
- `utils:test` - Test system functionality

### Key Management
- `utils:generate-key` - Generate a system key for the application

### Deployment
- `utils:deployment` - Help troubleshoot and fix system issues during deployment
  - `--check` - Check current deployment status
  - `--fix` - Attempt to fix deployment issues
  - `--regenerate` - Force regenerate hardware fingerprint
  - `--test` - Test system after fixes

### Utilities
- `utils:clear-cache` - Clear system cache
- `utils:optimize` - Optimize system performance
- `utils:audit` - Comprehensive system assessment

## 📋 Usage Examples

### Check System Status
```bash
php artisan utils:info
```

### Diagnose Issues
```bash
php artisan utils:diagnose --fix
```

### Generate System Key
```bash
# First, get your hardware fingerprint
php artisan utils:info

# Then generate key
php artisan utils:generate-key \
  --product-id=YOUR_PRODUCT_ID \
  --domain=example.com \
  --ip=192.168.1.1 \
  --client-id=YOUR_CLIENT_ID \
  --hardware-fingerprint=YOUR_FINGERPRINT \
  --installation-id=YOUR_INSTALLATION_ID
```

### Deployment Helper
```bash
# Check deployment status
php artisan utils:deployment --check

# Fix deployment issues
php artisan utils:deployment --fix

# Regenerate hardware fingerprint
php artisan utils:deployment --regenerate
```

## 🔐 Security

This package includes built-in security features:
- Hardware fingerprinting for installation tracking
- Secure key generation and validation
- Configuration encryption support
- System integrity monitoring

## 📦 Requirements

- PHP 8.1 or higher
- Laravel 9.0 or higher
- Composer

## 🤝 Support

For support, email support@insurancecore.com or visit https://github.com/Sudhir-Pratap/insurance-core

## 📄 License

This package is open-sourced software licensed under the [MIT license](LICENSE.md).

## 🔄 Version History

See [CHANGELOG.md](CHANGELOG.md) for version history and updates.

---

**Note**: This package is designed to work seamlessly with your Laravel application. All configuration is optional and the package will work with sensible defaults.
