from __future__ import annotations

import hashlib
import os
import re
from datetime import UTC, datetime

import frappe

from erpnext_security_suite.erpnext_security_suite.security_v3.config.settings import load_settings


_TOKEN_SANITIZER = re.compile(r"[^a-zA-Z0-9_.:@/-]+")


def append_security_line(
	*,
	event_type: str,
	status: str,
	user: str | None,
	ip_address: str | None,
	subject: str,
	content: str | None,
) -> None:
	settings = load_settings()
	if not settings.fail2ban_log_enabled:
		return

	log_path = frappe.get_site_path("logs", "ess_security.log")
	os.makedirs(os.path.dirname(log_path), exist_ok=True)

	timestamp = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
	line = (
		f"{timestamp} ESS_SECURITY"
		f" site={_token(frappe.local.site or 'unknown_site')}"
		f" event={_token(event_type or 'unknown_event')}"
		f" status={_token(status or 'unknown')}"
		f" user={_token(user or 'guest')}"
		f" ip={_token(ip_address or 'na')}"
		f" subject={_token(subject or 'unknown_subject')}"
		f" content_sha1={_digest(content)}"
	)

	try:
		with open(log_path, "a", encoding="utf-8") as log_file:
			log_file.write(line + "\n")
	except Exception:
		# Logging must never break business flows.
		pass


def normalize_event_type(subject: str | None) -> str:
	value = (subject or "").strip().lower()
	if not value:
		return "security_event"
	return _token(value)


def _token(value: str) -> str:
	clean = (value or "").strip()
	if not clean:
		return "na"
	return _TOKEN_SANITIZER.sub("_", clean)[:120]


def _digest(content: str | None) -> str:
	raw = (content or "").strip()
	if not raw:
		return "na"
	return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:20]
