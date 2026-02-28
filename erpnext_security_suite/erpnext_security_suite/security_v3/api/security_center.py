from __future__ import annotations

import frappe
from frappe import _
from frappe.utils import cint

from erpnext_security_suite.erpnext_security_suite.security_v3.config.settings import load_settings
from erpnext_security_suite.erpnext_security_suite.security_v3.responders.account_lock import (
	block_ip,
	get_ip_block_reason,
	get_ip_block_ttl_seconds,
	get_user_lock_reason,
	get_user_lock_ttl_seconds,
	unblock_ip,
	unlock_user,
	lock_user,
)
from erpnext_security_suite.erpnext_security_suite.security_v3.services.audit import log_security_event
from erpnext_security_suite.erpnext_security_suite.security_v3.services.runtime import normalize_user


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
		"exempt_paths": list(settings.exempt_paths),
		"trusted_users": list(settings.trusted_users),
	}


@frappe.whitelist()
def unlock_user_account(user: str) -> dict:
	_require_security_admin()
	clean_user = normalize_user(user)
	if not clean_user:
		frappe.throw(_("User is required"))
	unlock_user(clean_user)
	log_security_event(subject="Manual user unlock", content=f"user={clean_user}")
	return {"ok": True, "user": clean_user}


@frappe.whitelist()
def unblock_ip_address(ip_address: str) -> dict:
	_require_security_admin()
	clean_ip = (ip_address or "").strip()
	if not clean_ip:
		frappe.throw(_("IP address is required"))
	unblock_ip(clean_ip)
	log_security_event(subject="Manual IP unblock", content=f"ip={clean_ip}")
	return {"ok": True, "ip_address": clean_ip}


@frappe.whitelist()
def reload_settings() -> dict:
	_require_security_admin()
	settings = load_settings(refresh=True)
	return {"ok": True, "enabled": settings.enabled}


@frappe.whitelist()
def lock_user_account(user: str, minutes: int = 30, reason: str = "manual_lock") -> dict:
	_require_security_admin()
	clean_user = normalize_user(user)
	if not clean_user:
		frappe.throw(_("User is required"))
	lock_minutes = max(cint(minutes), 1)
	lock_user(clean_user, ttl_seconds=lock_minutes * 60, reason=(reason or "manual_lock").strip())
	log_security_event(subject="Manual user lock", content=f"user={clean_user} minutes={lock_minutes}")
	return {"ok": True, "user": clean_user, "minutes": lock_minutes}


@frappe.whitelist()
def block_ip_address(ip_address: str, minutes: int = 30, reason: str = "manual_block") -> dict:
	_require_security_admin()
	clean_ip = (ip_address or "").strip()
	if not clean_ip:
		frappe.throw(_("IP address is required"))
	lock_minutes = max(cint(minutes), 1)
	block_ip(clean_ip, ttl_seconds=lock_minutes * 60, reason=(reason or "manual_block").strip())
	log_security_event(subject="Manual IP block", content=f"ip={clean_ip} minutes={lock_minutes}")
	return {"ok": True, "ip_address": clean_ip, "minutes": lock_minutes}


@frappe.whitelist()
def get_lock_state(user: str | None = None, ip_address: str | None = None) -> dict:
	_require_security_admin()
	clean_user = normalize_user(user)
	clean_ip = (ip_address or "").strip()

	return {
		"user": {
			"name": clean_user or None,
			"is_locked": bool(clean_user and get_user_lock_reason(clean_user)),
			"reason": get_user_lock_reason(clean_user) if clean_user else None,
			"ttl_seconds": get_user_lock_ttl_seconds(clean_user) if clean_user else 0,
		},
		"ip": {
			"address": clean_ip or None,
			"is_blocked": bool(clean_ip and get_ip_block_reason(clean_ip)),
			"reason": get_ip_block_reason(clean_ip) if clean_ip else None,
			"ttl_seconds": get_ip_block_ttl_seconds(clean_ip) if clean_ip else 0,
		},
	}
