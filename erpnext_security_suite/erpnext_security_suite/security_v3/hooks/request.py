from __future__ import annotations

import frappe
from frappe import _

from erpnext_security_suite.erpnext_security_suite.security_v3.config.settings import load_settings
from erpnext_security_suite.erpnext_security_suite.security_v3.policies.ip_guard import enforce_ip_policy
from erpnext_security_suite.erpnext_security_suite.security_v3.policies.request_guard import enforce_rate_limit
from erpnext_security_suite.erpnext_security_suite.security_v3.responders.account_lock import get_user_lock_reason
from erpnext_security_suite.erpnext_security_suite.security_v3.services.runtime import (
	is_exempt_path,
	is_trusted_user,
)
from erpnext_security_suite.erpnext_security_suite.security_v3.services.audit import log_security_event


_LOGIN_PATHS = {"/api/method/login", "/login"}


def before_request() -> None:
	settings = load_settings()
	if not settings.enabled or not getattr(frappe.local, "request", None):
		return

	request_path = frappe.request.path or ""
	request_ip = (getattr(frappe.local, "request_ip", "") or "").strip()
	user = (getattr(frappe.session, "user", "Guest") or "Guest").strip()

	if is_exempt_path(request_path, settings.exempt_paths):
		return

	enforce_ip_policy(settings, request_ip=request_ip, request_path=request_path)
	if is_trusted_user(user, settings.trusted_users):
		return

	assert_login_not_locked(request_path)
	enforce_rate_limit(settings, request_path=request_path, request_ip=request_ip, user=user)


def after_request(response=None, request=None) -> None:
	settings = load_settings()
	if not settings.enabled:
		return
	if response and getattr(response, "headers", None) is not None:
		response.headers["X-Enterprise-Security"] = "ERPNext Security Suite V3"
		response.headers["X-Enterprise-Security-Mode"] = settings.mode
		if settings.mode == "ultra_hard":
			# Add hardened defaults that don't break same-origin ERP usage.
			response.headers.setdefault("X-Content-Type-Options", "nosniff")
			response.headers.setdefault("Referrer-Policy", "same-origin")
			response.headers.setdefault("Permissions-Policy", "geolocation=(), camera=(), microphone=()")


def assert_login_not_locked(request_path: str) -> None:
	if request_path not in _LOGIN_PATHS:
		return
	login_user = ((frappe.form_dict.get("usr") or "").strip()).lower()
	if not login_user:
		return

	if not get_user_lock_reason(login_user):
		return

	log_security_event(
		subject="Blocked login attempt for locked account",
		status="Failed",
		content=f"user={login_user}",
		user=login_user,
		event_type="locked_account_login_blocked",
	)
	frappe.throw(
		_("This account is temporarily locked because of repeated failed login attempts."),
		frappe.AuthenticationError,
	)
