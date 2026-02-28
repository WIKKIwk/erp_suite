from __future__ import annotations

import frappe
from frappe import _

from erpnext_security_suite.erpnext_security_suite.security_v3.config.settings import SecurityV3Settings
from erpnext_security_suite.erpnext_security_suite.security_v3.responders.account_lock import is_ip_blocked
from erpnext_security_suite.erpnext_security_suite.security_v3.services.audit import log_security_event


_LOCAL_NETWORK_IPS = {"127.0.0.1", "::1", "localhost"}


def enforce_ip_policy(settings: SecurityV3Settings, *, request_ip: str, request_path: str) -> None:
	ip = (request_ip or "").strip()
	if not ip or ip in _LOCAL_NETWORK_IPS:
		return

	if ip in settings.blocked_ips or is_ip_blocked(ip):
		log_security_event(
			subject="Blocked request from denied IP",
			status="Failed",
			content=f"ip={ip} path={request_path}",
			ip_address=ip,
			event_type="blocked_ip_request_denied",
		)
		frappe.throw(_("Your IP address is temporarily blocked."), frappe.PermissionError)

	if settings.enforce_ip_allowlist and _is_protected_path(request_path, settings.protected_paths):
		if ip not in settings.allowlist_ips:
			log_security_event(
				subject="Protected route denied by IP allowlist policy",
				status="Failed",
				content=f"ip={ip} path={request_path}",
				ip_address=ip,
				event_type="ip_allowlist_policy_denied",
			)
			frappe.throw(_("Your IP address is not allowed for protected routes."), frappe.PermissionError)


def _is_protected_path(path: str, protected_paths: tuple[str, ...]) -> bool:
	if not path:
		return False
	return any(path.startswith(prefix) for prefix in protected_paths)
