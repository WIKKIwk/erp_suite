# ERPNext Security Suite

Enterprise-focused security extension app for ERPNext/Frappe.

## V3 modular layout

- `security_v3/config`: central runtime settings from `site_config.json`
- `security_v3/policies`: request/IP policies
- `security_v3/detectors`: threat detection logic
- `security_v3/responders`: lock/block response handlers
- `security_v3/services`: cache and audit helpers
- `security_v3/hooks`: lightweight hook entrypoints
- `security_v3/api`: whitelisted admin APIs
- `security_v3/tasks`: scheduled maintenance jobs

## Current V3 features (without 2FA)

- IP denylist and optional allowlist enforcement on protected routes
- Rate-limiting layer for protected routes
- Failed login anomaly detection from `Activity Log`
- Temporary user lock and IP block on repeated failed logins
- Trusted users and exempt paths support
- Admin APIs for lock/unlock, block/unblock, state and runtime status
- Daily cleanup for old Security V3 activity events

## `site_config.json` options

```json
{
  "enterprise_security_enabled": true,
  "enterprise_security_enforce_ip_allowlist": false,
  "enterprise_security_ip_allowlist": ["10.10.10.10"],
  "enterprise_security_blocked_ips": ["45.77.100.12"],
  "enterprise_security_protected_paths": ["/api/", "/app", "/api/method/login"],
  "enterprise_security_exempt_paths": ["/assets/", "/socket.io/", "/api/method/ping"],
  "enterprise_security_trusted_users": ["Administrator"],
  "enterprise_security_rate_limit_count": 120,
  "enterprise_security_rate_limit_window_sec": 60,
  "enterprise_security_login_fail_threshold": 5,
  "enterprise_security_login_fail_window_sec": 900,
  "enterprise_security_lock_minutes": 30,
  "enterprise_security_log_retention_days": 30
}
```

## Admin API methods

- `erpnext_security_suite.erpnext_security_suite.security_v3.api.security_center.get_security_status`
- `erpnext_security_suite.erpnext_security_suite.security_v3.api.security_center.get_lock_state`
- `erpnext_security_suite.erpnext_security_suite.security_v3.api.security_center.lock_user_account`
- `erpnext_security_suite.erpnext_security_suite.security_v3.api.security_center.unlock_user_account`
- `erpnext_security_suite.erpnext_security_suite.security_v3.api.security_center.block_ip_address`
- `erpnext_security_suite.erpnext_security_suite.security_v3.api.security_center.unblock_ip_address`
- `erpnext_security_suite.erpnext_security_suite.security_v3.api.security_center.reload_settings`
