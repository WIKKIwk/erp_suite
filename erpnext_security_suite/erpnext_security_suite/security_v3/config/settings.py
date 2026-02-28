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
	"/api/method/frappe.ping",
	"/api/method/ping",
)

DEFAULT_TRUSTED_USERS = ("Administrator",)

SECURITY_MODE_STANDARD = "standard"
SECURITY_MODE_ULTRA_HARD = "ultra_hard"
VALID_SECURITY_MODES = {SECURITY_MODE_STANDARD, SECURITY_MODE_ULTRA_HARD}


@dataclass(frozen=True)
class SecurityV3Settings:
	enabled: bool
	mode: str
	mode_profile: str
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
	rapid_login_fail_threshold: int
	rapid_login_fail_window_seconds: int
	lock_duration_seconds: int
	log_retention_days: int
	permanent_user_disable_on_rapid_fail: bool
	encrypt_audit_payload: bool
	fail2ban_log_enabled: bool


def load_settings(*, refresh: bool = False) -> SecurityV3Settings:
	if refresh:
		_load_settings_cached.cache_clear()
	return _load_settings_cached()


@lru_cache(maxsize=1)
def _load_settings_cached() -> SecurityV3Settings:
	conf = frappe.conf
	mode = _normalize_mode(conf.get("enterprise_security_mode"))

	enforce_ip_allowlist = _to_bool(conf.get("enterprise_security_enforce_ip_allowlist"), default=False)
	allowlist_ips = _to_tuple(conf.get("enterprise_security_ip_allowlist"))
	request_limit = _to_int(conf.get("enterprise_security_rate_limit_count"), default=120, minimum=10)
	request_window_seconds = _to_int(
		conf.get("enterprise_security_rate_limit_window_sec"),
		default=60,
		minimum=10,
	)
	login_fail_threshold = _to_int(
		conf.get("enterprise_security_login_fail_threshold"),
		default=5,
		minimum=2,
	)
	login_fail_window_seconds = _to_int(
		conf.get("enterprise_security_login_fail_window_sec"),
		default=15 * 60,
		minimum=60,
	)
	rapid_login_fail_threshold = _to_int(
		conf.get("enterprise_security_rapid_fail_threshold"),
		default=5,
		minimum=2,
	)
	rapid_login_fail_window_seconds = _to_int(
		conf.get("enterprise_security_rapid_fail_window_sec"),
		default=10,
		minimum=5,
	)
	lock_duration_seconds = (
		_to_int(
			conf.get("enterprise_security_lock_minutes"),
			default=30,
			minimum=1,
		)
		* 60
	)
	log_retention_days = _to_int(conf.get("enterprise_security_log_retention_days"), default=30, minimum=7)
	permanent_user_disable_on_rapid_fail = _to_bool(
		conf.get("enterprise_security_permanent_user_disable_on_rapid_fail"),
		default=False,
	)
	encrypt_audit_payload = _to_bool(conf.get("enterprise_security_encrypt_audit_payload"), default=False)
	fail2ban_log_enabled = _to_bool(conf.get("enterprise_security_fail2ban_log_enabled"), default=True)

	if mode == SECURITY_MODE_ULTRA_HARD:
		# Keep this strict but safe for existing deployments:
		# enable allowlist only when at least one allowlist IP exists.
		enforce_ip_allowlist = enforce_ip_allowlist or bool(allowlist_ips)
		request_limit = min(request_limit, 40)
		request_window_seconds = min(request_window_seconds, 45)
		login_fail_threshold = min(login_fail_threshold, 3)
		login_fail_window_seconds = min(login_fail_window_seconds, 10 * 60)
		rapid_login_fail_threshold = min(rapid_login_fail_threshold, 5)
		rapid_login_fail_window_seconds = min(rapid_login_fail_window_seconds, 10)
		lock_duration_seconds = max(lock_duration_seconds, 120 * 60)
		log_retention_days = max(log_retention_days, 90)
		permanent_user_disable_on_rapid_fail = True
		encrypt_audit_payload = True
		fail2ban_log_enabled = True

	return SecurityV3Settings(
		enabled=_to_bool(conf.get("enterprise_security_enabled"), default=True),
		mode=mode,
		mode_profile="Ultra Hard Suit" if mode == SECURITY_MODE_ULTRA_HARD else "Standard Shield",
		enforce_ip_allowlist=enforce_ip_allowlist,
		allowlist_ips=allowlist_ips,
		blocked_ips=_to_tuple(conf.get("enterprise_security_blocked_ips")),
		protected_paths=_to_tuple(conf.get("enterprise_security_protected_paths"), default=DEFAULT_PROTECTED_PATHS),
		exempt_paths=_to_tuple(conf.get("enterprise_security_exempt_paths"), default=DEFAULT_EXEMPT_PATHS),
		trusted_users=_to_tuple(conf.get("enterprise_security_trusted_users"), default=DEFAULT_TRUSTED_USERS),
		request_limit=request_limit,
		request_window_seconds=request_window_seconds,
		login_fail_threshold=login_fail_threshold,
		login_fail_window_seconds=login_fail_window_seconds,
		rapid_login_fail_threshold=rapid_login_fail_threshold,
		rapid_login_fail_window_seconds=rapid_login_fail_window_seconds,
		lock_duration_seconds=lock_duration_seconds,
		log_retention_days=log_retention_days,
		permanent_user_disable_on_rapid_fail=permanent_user_disable_on_rapid_fail,
		encrypt_audit_payload=encrypt_audit_payload,
		fail2ban_log_enabled=fail2ban_log_enabled,
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


def _normalize_mode(value: Any) -> str:
	mode = str(value or SECURITY_MODE_STANDARD).strip().lower()
	if mode not in VALID_SECURITY_MODES:
		return SECURITY_MODE_STANDARD
	return mode
