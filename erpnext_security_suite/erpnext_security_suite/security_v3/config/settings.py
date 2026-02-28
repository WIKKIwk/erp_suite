from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from typing import Any

import frappe

DEFAULT_PROTECTED_PATHS = (
	"/api/",
	"/app",
	"/api/method/login",
)

DEFAULT_EXEMPT_PATHS = (
	"/assets/",
	"/socket.io/",
	"/api/method/frappe.health.check",
	"/api/method/ping",
)

DEFAULT_TRUSTED_USERS = ("Administrator",)


@dataclass(frozen=True)
class SecurityV3Settings:
	enabled: bool
	enforce_ip_allowlist: bool
	allowlist_ips: tuple[str, ...]
	blocked_ips: tuple[str, ...]
	protected_paths: tuple[str, ...]
	exempt_paths: tuple[str, ...]
	trusted_users: tuple[str, ...]
	request_limit: int
	request_window_seconds: int
	login_fail_threshold: int
	login_fail_window_seconds: int
	lock_duration_seconds: int
	log_retention_days: int


def load_settings(*, refresh: bool = False) -> SecurityV3Settings:
	if refresh:
		_load_settings_cached.cache_clear()
	return _load_settings_cached()


@lru_cache(maxsize=1)
def _load_settings_cached() -> SecurityV3Settings:
	conf = frappe.conf
	return SecurityV3Settings(
		enabled=_to_bool(conf.get("enterprise_security_enabled"), default=True),
		enforce_ip_allowlist=_to_bool(conf.get("enterprise_security_enforce_ip_allowlist"), default=False),
		allowlist_ips=_to_tuple(conf.get("enterprise_security_ip_allowlist")),
		blocked_ips=_to_tuple(conf.get("enterprise_security_blocked_ips")),
		protected_paths=_to_tuple(conf.get("enterprise_security_protected_paths"), default=DEFAULT_PROTECTED_PATHS),
		exempt_paths=_to_tuple(conf.get("enterprise_security_exempt_paths"), default=DEFAULT_EXEMPT_PATHS),
		trusted_users=_to_tuple(conf.get("enterprise_security_trusted_users"), default=DEFAULT_TRUSTED_USERS),
		request_limit=_to_int(conf.get("enterprise_security_rate_limit_count"), default=120, minimum=10),
		request_window_seconds=_to_int(
			conf.get("enterprise_security_rate_limit_window_sec"),
			default=60,
			minimum=10,
		),
		login_fail_threshold=_to_int(
			conf.get("enterprise_security_login_fail_threshold"),
			default=5,
			minimum=2,
		),
		login_fail_window_seconds=_to_int(
			conf.get("enterprise_security_login_fail_window_sec"),
			default=15 * 60,
			minimum=60,
		),
		lock_duration_seconds=_to_int(
			conf.get("enterprise_security_lock_minutes"),
			default=30,
			minimum=1,
		)
		* 60,
		log_retention_days=_to_int(conf.get("enterprise_security_log_retention_days"), default=30, minimum=7),
	)


def _to_bool(value: Any, *, default: bool) -> bool:
	if value is None:
		return default
	if isinstance(value, bool):
		return value
	if isinstance(value, str):
		return value.strip().lower() in {"1", "true", "yes", "on"}
	return bool(value)


def _to_int(value: Any, *, default: int, minimum: int) -> int:
	try:
		parsed = int(value)
	except (TypeError, ValueError):
		parsed = default
	return max(parsed, minimum)


def _to_tuple(value: Any, *, default: tuple[str, ...] = ()) -> tuple[str, ...]:
	if value is None:
		return tuple(default)
	if isinstance(value, (list, tuple, set)):
		items = value
	else:
		items = str(value).split(",")

	cleaned = tuple(str(item).strip() for item in items if str(item).strip())
	return cleaned or tuple(default)
