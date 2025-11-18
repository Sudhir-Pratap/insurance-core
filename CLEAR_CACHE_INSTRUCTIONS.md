# Clear Cache Instructions for "Cannot declare class OptimizeCommand" Error

## Problem
If you're seeing the error:
```
Cannot declare class InsuranceCore\Helpers\Commands\OptimizeCommand, because the name is already in use
```

This happens when the consuming Laravel application has cached autoload files that still reference the old `ObfuscateCodeCommand.php` file.

## Solution

### If you're testing the package in a Laravel application:

1. **Clear Composer Autoload Cache:**
   ```bash
   composer dump-autoload
   ```

2. **Remove the package from vendor and reinstall:**
   ```bash
   # On Windows PowerShell:
   Remove-Item -Recurse -Force vendor/insurance-core/helpers
   composer install
   ```

   Or if using the package from a local path:
   ```bash
   composer update insurance-core/helpers
   ```

3. **Clear Laravel Cache:**
   ```bash
   php artisan optimize:clear
   php artisan config:clear
   php artisan cache:clear
   ```

4. **If using opcache, restart PHP:**
   ```bash
   # Restart your PHP-FPM or web server
   ```

### If you're developing the package itself:

The autoload files have been regenerated. If you're still seeing the error:

1. **Make sure you've committed and pushed all changes:**
   ```bash
   git status
   git add .
   git commit -m "Your message"
   git push
   ```

2. **In your test Laravel application, update the package:**
   ```bash
   composer update insurance-core/helpers
   composer dump-autoload
   ```

## Verification

After clearing caches, verify the fix:
```bash
php artisan list | grep helpers:
```

You should see all `helpers:*` commands without errors.

## Root Cause

The error occurred because:
1. The old `ObfuscateCodeCommand.php` file (which also declared `OptimizeCommand`) was removed
2. But cached autoload files in the consuming Laravel app still referenced it
3. When both files tried to load, PHP saw the class declared twice

This has been fixed in the package code, but you need to clear caches in the consuming application.

