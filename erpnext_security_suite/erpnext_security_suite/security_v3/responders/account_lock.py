from __future__ import annotations

from erpnext_security_suite.erpnext_security_suite.security_v3.services import cache_keys, cache_store


_LOCK_REASON = "locked"


def lock_user(user: str, *, ttl_seconds: int, reason: str | None = None) -> None:
	if not user:
		return
	cache_store.set_with_expiry(cache_keys.user_lock_key(user), reason or _LOCK_REASON, ttl_seconds)


def unlock_user(user: str) -> None:
	if not user:
		return
	cache_store.delete_value(cache_keys.user_lock_key(user))


def get_user_lock_reason(user: str) -> str | None:
	if not user:
		return None
	return cache_store.get_value(cache_keys.user_lock_key(user))


def block_ip(ip_address: str, *, ttl_seconds: int, reason: str | None = None) -> None:
	if not ip_address:
		return
	cache_store.set_with_expiry(cache_keys.ip_block_key(ip_address), reason or _LOCK_REASON, ttl_seconds)


def unblock_ip(ip_address: str) -> None:
	if not ip_address:
		return
	cache_store.delete_value(cache_keys.ip_block_key(ip_address))


def is_ip_blocked(ip_address: str) -> bool:
	if not ip_address:
		return False
	return bool(cache_store.get_value(cache_keys.ip_block_key(ip_address)))
