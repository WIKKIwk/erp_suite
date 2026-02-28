from __future__ import annotations

from erpnext_security_suite.erpnext_security_suite.security_v3.config.settings import SecurityV3Settings
from erpnext_security_suite.erpnext_security_suite.security_v3.responders.account_lock import (
	block_ip,
	disable_user_permanently,
	lock_user,
	unlock_user,
)
from erpnext_security_suite.erpnext_security_suite.security_v3.services import cache_keys, cache_store
from erpnext_security_suite.erpnext_security_suite.security_v3.services.audit import log_security_event
from erpnext_security_suite.erpnext_security_suite.security_v3.services.runtime import is_trusted_user


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
		rapid_failed_count = 0
		if user:
			rapid_key = cache_keys.rapid_failed_login_counter_key(user)
			rapid_failed_count = cache_store.increment_with_expiry(rapid_key, settings.rapid_login_fail_window_seconds)
		log_security_event(
			subject="Failed login attempt detected",
			status="Failed",
			content=(
				f"identity={identity} failed_count={failed_count} "
				f"rapid_failed_count={rapid_failed_count}"
			),
			user=user or "Guest",
			ip_address=ip_address,
			event_type="login_failed_attempt",
		)

		if (
			user
			and not is_trusted_user(user, settings.trusted_users)
			and settings.permanent_user_disable_on_rapid_fail
			and rapid_failed_count >= settings.rapid_login_fail_threshold
		):
			disabled_now = disable_user_permanently(user, reason="rapid_failed_login")
			if ip_address:
				block_ip(
					ip_address,
					ttl_seconds=max(settings.lock_duration_seconds, 24 * 60 * 60),
					reason="rapid_bruteforce_risk",
				)
			if disabled_now:
				log_security_event(
					subject="User permanently disabled after rapid failed login attempts",
					status="Failed",
					content=(
						f"user={user} rapid_failed_count={rapid_failed_count} "
						f"window={settings.rapid_login_fail_window_seconds}"
					),
					user=user,
					ip_address=ip_address,
					event_type="rapid_bruteforce_permanent_user_disable",
				)
			return

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
				ip_address=ip_address,
				event_type="temporary_lock_after_failed_logins",
			)
		return

	if status == "Success":
		cache_store.delete_value(counter_key)
		if user:
			cache_store.delete_value(cache_keys.rapid_failed_login_counter_key(user))
			unlock_user(user)


def _normalize(value: str) -> str:
	return (value or "").strip().lower()
