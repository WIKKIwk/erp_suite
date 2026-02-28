from __future__ import annotations

import frappe
from frappe.sessions import clear_sessions

from erpnext_security_suite.erpnext_security_suite.security_v3.services import cache_keys, cache_store


_LOCK_REASON = "locked"
_UNBLOCKABLE_USERS = {"administrator", "guest"}


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


def get_user_lock_ttl_seconds(user: str) -> int:
	if not user:
		return 0
	return cache_store.ttl_seconds(cache_keys.user_lock_key(user))


def disable_user_permanently(user: str, *, reason: str | None = None) -> bool:
	clean_user = (user or "").strip().lower()
	if not clean_user or clean_user in _UNBLOCKABLE_USERS:
		return False
	if not frappe.db.exists("User", clean_user):
		return False
	if not frappe.db.get_value("User", clean_user, "enabled"):
		return False

	frappe.db.set_value("User", clean_user, "enabled", 0, update_modified=True)
	frappe.cache.delete_value(cache_keys.user_lock_key(clean_user))
	clear_sessions(user=clean_user, force=True)
	return True


def enable_user_account(user: str) -> bool:
	clean_user = (user or "").strip().lower()
	if not clean_user or clean_user in _UNBLOCKABLE_USERS:
		return False
	if not frappe.db.exists("User", clean_user):
		return False
	if frappe.db.get_value("User", clean_user, "enabled"):
		return False

	frappe.db.set_value("User", clean_user, "enabled", 1, update_modified=True)
	return True


def is_user_disabled(user: str) -> bool:
	clean_user = (user or "").strip().lower()
	if not clean_user or not frappe.db.exists("User", clean_user):
		return False
	return not bool(frappe.db.get_value("User", clean_user, "enabled"))


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


def get_ip_block_reason(ip_address: str) -> str | None:
	if not ip_address:
		return None
	return cache_store.get_value(cache_keys.ip_block_key(ip_address))


def get_ip_block_ttl_seconds(ip_address: str) -> int:
	if not ip_address:
		return 0
	return cache_store.ttl_seconds(cache_keys.ip_block_key(ip_address))
