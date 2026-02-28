from __future__ import annotations

import frappe
from frappe.utils.password import decrypt, encrypt

from erpnext_security_suite.erpnext_security_suite.security_v3.services.security_log import (
	append_security_line,
	normalize_event_type,
)

_ENCRYPTION_PREFIX = "enc:v1:"


def log_security_event(
	*,
	subject: str,
	status: str = "Success",
	content: str | None = None,
	user: str | None = None,
	ip_address: str | None = None,
	event_type: str | None = None,
) -> None:
	event_key = normalize_event_type(event_type or subject)
	resolved_user = user or frappe.session.user or "Administrator"
	resolved_ip = (ip_address or getattr(frappe.local, "request_ip", "") or "").strip()
	append_security_line(
		event_type=event_key,
		status=status,
		user=resolved_user,
		ip_address=resolved_ip,
		subject=subject,
		content=content,
	)

	try:
		stored_content = _encode_content(content)
		frappe.get_doc(
			{
				"doctype": "Activity Log",
				"subject": f"Security V3: {subject}",
				"status": status,
				"user": resolved_user,
				"content": stored_content,
			}
		).insert(ignore_permissions=True, ignore_links=True)
	except Exception:
		# Never break business requests because of audit log failures.
		frappe.log_error(title="Security V3 Audit Log Error")


def clear_old_security_events(days: int) -> None:
	frappe.db.delete(
		"Activity Log",
		{
			"subject": ["like", "Security V3:%"],
			"creation": ["<", frappe.utils.add_days(frappe.utils.nowdate(), -abs(int(days)))],
		},
	)


def decode_security_content(content: str | None) -> str:
	raw = (content or "").strip()
	if not raw.startswith(_ENCRYPTION_PREFIX):
		return raw
	encrypted_payload = raw[len(_ENCRYPTION_PREFIX) :]
	try:
		return decrypt(encrypted_payload)
	except Exception:
		return "[encrypted-content-unavailable]"


def _encode_content(content: str | None) -> str | None:
	raw = (content or "").strip()
	if not raw:
		return None
	if not _should_encrypt_audit_payload():
		return raw
	try:
		return f"{_ENCRYPTION_PREFIX}{encrypt(raw)}"
	except Exception:
		# Fallback to plain text to avoid losing incident records.
		return raw


def _should_encrypt_audit_payload() -> bool:
	mode = str(frappe.conf.get("enterprise_security_mode") or "").strip().lower()
	if mode == "ultra_hard":
		return True
	value = frappe.conf.get("enterprise_security_encrypt_audit_payload")
	if value is None:
		return False
	if isinstance(value, bool):
		return value
	return str(value).strip().lower() in {"1", "true", "yes", "on"}
