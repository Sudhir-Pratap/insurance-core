# 📋 Command Files Update Report

## Commands That Need Updates

### ✅ Already Updated
1. **DiagnoseCommand.php** - ✅ Updated to `utils:diagnose`
2. **InfoCommand.php** - ✅ Updated to `utils:info`
3. **GenerateKeyCommand.php** - ✅ Updated to `utils:generate-key`
4. **TestCommand.php** - ✅ Updated to `utils:test`
5. **DeploymentCommand.php** - ✅ Updated to `utils:deployment`
6. **OptimizeCommand.php** - ✅ Updated to `utils:optimize`

### ⚠️ Need Updates

#### 1. ClearCacheCommand.php
- **Current**: `helpers:clear-cache`
- **Should be**: `utils:clear-cache`
- **Issues**: References to `HELPER_*` env vars, `helper_key`, `license`

#### 2. ClientFriendlyCommand.php
- **Current**: `helpers:client-status`
- **Should be**: `utils:status` or `utils:client-status`
- **Issues**: References to "helper system", `helpers:client-status`

#### 3. StealthInstallCommand.php
- **Current**: `helpers:stealth-install`
- **Should be**: `utils:stealth-install` or `utils:install`
- **Issues**: References to "license", "stealth license", `HELPER_*` env vars

#### 4. CopyProtectionCommand.php
- **Current**: `helpers:copy-protection`
- **Should be**: `utils:copy-protection` or `utils:protection`
- **Issues**: References to `HELPER_*` env vars, "license", `helpers:copy-protection`

#### 5. ProtectCommand.php
- **Current**: `helpers:protect`
- **Should be**: `utils:protect`
- **Issues**: References to "helper", `helpers:protect`

#### 6. AuditCommand.php
- **Current**: `helpers:audit`
- **Should be**: `utils:audit`
- **Issues**: References to "helper", `helpers:audit`

---

## Summary

**Total Commands**: 12
- ✅ **Updated**: 6 commands
- ⚠️ **Need Updates**: 6 commands

---

## Common Issues Found

1. **Command Signatures**: All still use `helpers:*` prefix
2. **Environment Variables**: References to `HELPER_*` instead of `UTILS_*`
3. **Package Paths**: References to `insurance-core/helpers` instead of `acme/utils`
4. **Class Names**: References to `Helper.php`, `ProtectionManager.php`
5. **Terminology**: "license", "helper system", etc.

---

## Recommended Actions

1. Update all command signatures to use `utils:*` prefix
2. Replace `HELPER_*` with `UTILS_*` (with fallback)
3. Update package paths to `acme/utils`
4. Update class file references
5. Remove/replace "license" terminology
6. Update command descriptions to be generic


