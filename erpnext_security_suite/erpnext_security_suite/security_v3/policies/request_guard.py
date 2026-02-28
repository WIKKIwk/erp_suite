from __future__ import annotations

import frappe
from frappe import _

from erpnext_security_suite.erpnext_security_suite.security_v3.config.settings import SecurityV3Settings
from erpnext_security_suite.erpnext_security_suite.security_v3.services import cache_keys, cache_store
from erpnext_security_suite.erpnext_security_suite.security_v3.services.audit import log_security_event


def enforce_rate_limit(
	settings: SecurityV3Settings,
	*,
	request_path: str,
	request_ip: str,
	user: str,
) -> None:
	if not _is_protected_path(request_path, settings.protected_paths):
		return

	identity = (user or "").strip()
	is_guest = not identity or identity == "Guest"
	if is_guest:
		identity = (request_ip or "guest").strip()

	effective_limit = _resolve_effective_limit(settings, request_path=request_path, user=user)
	key = cache_keys.request_counter_key(identity, request_path, settings.request_window_seconds)
	count = cache_store.increment_with_expiry(key, settings.request_window_seconds)
	if count <= effective_limit:
		return

	log_security_event(
		subject="Request limit exceeded",
		status="Failed",
		content=f"identity={identity} path={request_path} limit={effective_limit}",
		user=user or "Guest",
		ip_address=request_ip,
		event_type="request_limit_exceeded",
	)
	frappe.throw(
		_("Too many requests. Please wait and try again."),
		frappe.TooManyRequestsError,
	)


def _is_protected_path(path: str, protected_paths: tuple[str, ...]) -> bool:
	if not path:
		return False
	return any(path.startswith(prefix) for prefix in protected_paths)


def _resolve_effective_limit(settings: SecurityV3Settings, *, request_path: str, user: str) -> int:
	clean_user = (user or "").strip()
	if request_path in {"/api/method/login", "/login"}:
		return settings.request_limit

	# Desk form load performs many API calls during page open; keep hardened but usable limits.
	if clean_user and clean_user != "Guest":
		return max(settings.request_limit * 8, 300)

	# Guest/public paths stay stricter than authenticated traffic.
	return max(settings.request_limit * 3, 120)
