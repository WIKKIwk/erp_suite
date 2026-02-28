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
- Permanent user disable on rapid brute-force pattern (configurable)
- Trusted users and exempt paths support
- Admin APIs for lock/unlock, block/unblock, state and runtime status
- Runtime `security mode` support: `standard` and `ultra_hard`
- Optional encrypted audit payloads in `Activity Log`
- Fail2ban-ready dedicated security event log (`sites/<site>/logs/ess_security.log`)
- Daily cleanup for old Security V3 activity events

## `site_config.json` options

```json
{
  "enterprise_security_enabled": true,
  "enterprise_security_mode": "standard",
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
  "enterprise_security_rapid_fail_threshold": 5,
  "enterprise_security_rapid_fail_window_sec": 10,
  "enterprise_security_permanent_user_disable_on_rapid_fail": false,
  "enterprise_security_encrypt_audit_payload": false,
  "enterprise_security_fail2ban_log_enabled": true,
  "enterprise_security_lock_minutes": 30,
  "enterprise_security_log_retention_days": 30
}
```

## Admin API methods

- `erpnext_security_suite.erpnext_security_suite.security_v3.api.security_center.get_security_status`
- `erpnext_security_suite.erpnext_security_suite.security_v3.api.security_center.get_lock_state`
- `erpnext_security_suite.erpnext_security_suite.security_v3.api.security_center.lock_user_account`
- `erpnext_security_suite.erpnext_security_suite.security_v3.api.security_center.unlock_user_account`
- `erpnext_security_suite.erpnext_security_suite.security_v3.api.security_center.restore_user_account`
- `erpnext_security_suite.erpnext_security_suite.security_v3.api.security_center.block_ip_address`
- `erpnext_security_suite.erpnext_security_suite.security_v3.api.security_center.unblock_ip_address`
- `erpnext_security_suite.erpnext_security_suite.security_v3.api.security_center.reload_settings`
- `erpnext_security_suite.erpnext_security_suite.security_v3.api.security_center.set_security_mode`
- `erpnext_security_suite.erpnext_security_suite.security_v3.api.security_center.set_ultra_hard_mode`

## Edge hardening (Nginx + Fail2ban)

Use the provided templates:

- `deploy/nginx/erpnext-security-ratelimit.conf`
- `deploy/fail2ban/filter.d/erpnext-security-login.conf`
- `deploy/fail2ban/filter.d/erpnext-security-api.conf`
- `deploy/fail2ban/jail.d/erpnext-security.local.example`

Quick install outline:

1. Copy nginx snippet into your ERPNext `server` block and adjust upstream name if needed.
2. Reload nginx.
3. Copy fail2ban filter files to `/etc/fail2ban/filter.d/`.
4. Copy jail file to `/etc/fail2ban/jail.d/erpnext-security.local` and set bench base path in `logpath`.
   The provided jail uses wildcard `sites/*/logs/ess_security.log` so one config protects all sites on that bench.
5. Restart fail2ban and validate:

```bash
sudo fail2ban-client reload
sudo fail2ban-regex /home/frappe/frappe-bench/sites/erp.localhost/logs/ess_security.log /etc/fail2ban/filter.d/erpnext-security-login.conf
sudo fail2ban-client status erpnext-security-login
```

## Local test poligon (this PC)

Run synthetic attack-event smoke test:

```bash
cd apps/erpnext_security_suite
./deploy/scripts/local_poligon_smoke.sh erp.localhost
```

This writes sample `ESS_SECURITY` events and prints latest lines from:

- `sites/<site>/logs/ess_security.log`
