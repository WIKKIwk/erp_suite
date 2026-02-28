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
	if not identity or identity == "Guest":
		identity = (request_ip or "guest").strip()

	key = cache_keys.request_counter_key(identity, request_path, settings.request_window_seconds)
	count = cache_store.increment_with_expiry(key, settings.request_window_seconds)
	if count <= settings.request_limit:
		return

	log_security_event(
		subject="Request limit exceeded",
		status="Failed",
		content=f"identity={identity} path={request_path} limit={settings.request_limit}",
		user=user or "Guest",
	)
	frappe.throw(
		_("Too many requests. Please wait and try again."),
		frappe.TooManyRequestsError,
	)


def _is_protected_path(path: str, protected_paths: tuple[str, ...]) -> bool:
	if not path:
		return False
	return any(path.startswith(prefix) for prefix in protected_paths)
