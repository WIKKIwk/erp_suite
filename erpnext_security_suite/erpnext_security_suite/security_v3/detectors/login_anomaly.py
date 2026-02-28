from __future__ import annotations

from erpnext_security_suite.erpnext_security_suite.security_v3.config.settings import SecurityV3Settings
from erpnext_security_suite.erpnext_security_suite.security_v3.responders.account_lock import block_ip, lock_user, unlock_user
from erpnext_security_suite.erpnext_security_suite.security_v3.services import cache_keys, cache_store
from erpnext_security_suite.erpnext_security_suite.security_v3.services.audit import log_security_event


def process_login_activity(doc, settings: SecurityV3Settings) -> None:
	if getattr(doc, "operation", None) != "Login":
		return

	status = (getattr(doc, "status", "") or "").strip()
	user = _normalize(getattr(doc, "user", ""))
	ip_address = _normalize(getattr(doc, "ip_address", ""))
	identity = user or ip_address
	if not identity:
		return

	counter_key = cache_keys.failed_login_counter_key(identity)
	if status == "Failed":
		failed_count = cache_store.increment_with_expiry(counter_key, settings.login_fail_window_seconds)
		if failed_count >= settings.login_fail_threshold:
			if user:
				lock_user(user, ttl_seconds=settings.lock_duration_seconds, reason="too_many_failed_logins")
			if ip_address:
				block_ip(ip_address, ttl_seconds=settings.lock_duration_seconds, reason="bruteforce_risk")
			log_security_event(
				subject="Account/IP locked after repeated failed login",
				status="Failed",
				content=f"identity={identity} failed_count={failed_count}",
				user=user or "Guest",
			)
		return

	if status == "Success":
		cache_store.delete_value(counter_key)
		if user:
			unlock_user(user)


def _normalize(value: str) -> str:
	return (value or "").strip().lower()
