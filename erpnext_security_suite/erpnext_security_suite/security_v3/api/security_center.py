from __future__ import annotations

import frappe
from frappe import _
from frappe.installer import update_site_config
from frappe.utils import cint

from erpnext_security_suite.erpnext_security_suite.security_v3.config.settings import (
	SECURITY_MODE_STANDARD,
	SECURITY_MODE_ULTRA_HARD,
	load_settings,
)
from erpnext_security_suite.erpnext_security_suite.security_v3.responders.account_lock import (
	block_ip,
	enable_user_account,
	get_ip_block_reason,
	get_ip_block_ttl_seconds,
	get_user_lock_reason,
	get_user_lock_ttl_seconds,
	is_user_disabled,
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
		"mode": settings.mode,
		"mode_profile": settings.mode_profile,
		"is_ultra_hard": settings.mode == SECURITY_MODE_ULTRA_HARD,
		"enforce_ip_allowlist": settings.enforce_ip_allowlist,
		"allowlist_ips": list(settings.allowlist_ips),
		"blocked_ips": list(settings.blocked_ips),
		"request_limit": settings.request_limit,
		"request_window_seconds": settings.request_window_seconds,
		"login_fail_threshold": settings.login_fail_threshold,
		"login_fail_window_seconds": settings.login_fail_window_seconds,
		"rapid_login_fail_threshold": settings.rapid_login_fail_threshold,
		"rapid_login_fail_window_seconds": settings.rapid_login_fail_window_seconds,
		"lock_duration_seconds": settings.lock_duration_seconds,
		"permanent_user_disable_on_rapid_fail": settings.permanent_user_disable_on_rapid_fail,
		"encrypt_audit_payload": settings.encrypt_audit_payload,
		"fail2ban_log_enabled": settings.fail2ban_log_enabled,
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
	log_security_event(subject="Manual user unlock", content=f"user={clean_user}", event_type="manual_user_unlock")
	return {"ok": True, "user": clean_user}


@frappe.whitelist()
def restore_user_account(user: str) -> dict:
	_require_security_admin()
	clean_user = normalize_user(user)
	if not clean_user:
		frappe.throw(_("User is required"))

	restored = enable_user_account(clean_user)
	unlock_user(clean_user)
	log_security_event(
		subject="Manual user restore",
		content=f"user={clean_user} restored={int(restored)}",
		event_type="manual_user_restore",
	)
	return {"ok": True, "user": clean_user, "restored": restored}


@frappe.whitelist()
def unblock_ip_address(ip_address: str) -> dict:
	_require_security_admin()
	clean_ip = (ip_address or "").strip()
	if not clean_ip:
		frappe.throw(_("IP address is required"))
	unblock_ip(clean_ip)
	log_security_event(subject="Manual IP unblock", content=f"ip={clean_ip}", ip_address=clean_ip, event_type="manual_ip_unblock")
	return {"ok": True, "ip_address": clean_ip}


@frappe.whitelist()
def reload_settings() -> dict:
	_require_security_admin()
	settings = load_settings(refresh=True)
	return {"ok": True, "enabled": settings.enabled, "mode": settings.mode, "mode_profile": settings.mode_profile}


@frappe.whitelist()
def set_security_mode(mode: str) -> dict:
	_require_security_admin()
	clean_mode = (mode or "").strip().lower()
	if clean_mode not in {SECURITY_MODE_STANDARD, SECURITY_MODE_ULTRA_HARD}:
		frappe.throw(_("Invalid security mode"))

	update_site_config("enterprise_security_mode", clean_mode)
	settings = load_settings(refresh=True)
	log_security_event(
		subject="Security mode updated",
		content=f"mode={settings.mode} by={frappe.session.user}",
		user=frappe.session.user,
		event_type="security_mode_updated",
	)
	return {
		"ok": True,
		"mode": settings.mode,
		"mode_profile": settings.mode_profile,
		"is_ultra_hard": settings.mode == SECURITY_MODE_ULTRA_HARD,
	}


@frappe.whitelist()
def set_ultra_hard_mode(enabled: int | bool = 1) -> dict:
	_require_security_admin()
	target_mode = SECURITY_MODE_ULTRA_HARD if cint(enabled) else SECURITY_MODE_STANDARD
	return set_security_mode(target_mode)


@frappe.whitelist()
def lock_user_account(user: str, minutes: int = 30, reason: str = "manual_lock") -> dict:
	_require_security_admin()
	clean_user = normalize_user(user)
	if not clean_user:
		frappe.throw(_("User is required"))
	lock_minutes = max(cint(minutes), 1)
	lock_user(clean_user, ttl_seconds=lock_minutes * 60, reason=(reason or "manual_lock").strip())
	log_security_event(
		subject="Manual user lock",
		content=f"user={clean_user} minutes={lock_minutes}",
		event_type="manual_user_lock",
	)
	return {"ok": True, "user": clean_user, "minutes": lock_minutes}


@frappe.whitelist()
def block_ip_address(ip_address: str, minutes: int = 30, reason: str = "manual_block") -> dict:
	_require_security_admin()
	clean_ip = (ip_address or "").strip()
	if not clean_ip:
		frappe.throw(_("IP address is required"))
	lock_minutes = max(cint(minutes), 1)
	block_ip(clean_ip, ttl_seconds=lock_minutes * 60, reason=(reason or "manual_block").strip())
	log_security_event(
		subject="Manual IP block",
		content=f"ip={clean_ip} minutes={lock_minutes}",
		ip_address=clean_ip,
		event_type="manual_ip_block",
	)
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
			"is_disabled": is_user_disabled(clean_user) if clean_user else False,
		},
		"ip": {
			"address": clean_ip or None,
			"is_blocked": bool(clean_ip and get_ip_block_reason(clean_ip)),
			"reason": get_ip_block_reason(clean_ip) if clean_ip else None,
			"ttl_seconds": get_ip_block_ttl_seconds(clean_ip) if clean_ip else 0,
		},
	}
