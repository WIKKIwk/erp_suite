from __future__ import annotations

import frappe

from erpnext_security_suite.erpnext_security_suite.security_v3.config.settings import load_settings
from erpnext_security_suite.erpnext_security_suite.security_v3.responders.account_lock import unblock_ip, unlock_user


def _require_security_admin() -> None:
	frappe.only_for("System Manager")


@frappe.whitelist()
def get_security_status() -> dict:
	_require_security_admin()
	settings = load_settings()
	return {
		"enabled": settings.enabled,
		"enforce_ip_allowlist": settings.enforce_ip_allowlist,
		"allowlist_ips": list(settings.allowlist_ips),
		"blocked_ips": list(settings.blocked_ips),
		"request_limit": settings.request_limit,
		"request_window_seconds": settings.request_window_seconds,
		"login_fail_threshold": settings.login_fail_threshold,
		"login_fail_window_seconds": settings.login_fail_window_seconds,
		"lock_duration_seconds": settings.lock_duration_seconds,
		"protected_paths": list(settings.protected_paths),
	}


@frappe.whitelist()
def unlock_user_account(user: str) -> dict:
	_require_security_admin()
	clean_user = (user or "").strip().lower()
	if not clean_user:
		frappe.throw("User is required")
	unlock_user(clean_user)
	return {"ok": True, "user": clean_user}


@frappe.whitelist()
def unblock_ip_address(ip_address: str) -> dict:
	_require_security_admin()
	clean_ip = (ip_address or "").strip()
	if not clean_ip:
		frappe.throw("IP address is required")
	unblock_ip(clean_ip)
	return {"ok": True, "ip_address": clean_ip}


@frappe.whitelist()
def reload_settings() -> dict:
	_require_security_admin()
	settings = load_settings(refresh=True)
	return {"ok": True, "enabled": settings.enabled}
