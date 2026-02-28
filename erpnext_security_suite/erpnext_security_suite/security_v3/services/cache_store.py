from __future__ import annotations

from typing import Any

import frappe
from frappe.utils import cint


def increment_with_expiry(key: str, expiry_seconds: int) -> int:
	value = cint(frappe.cache.incrby(key, 1))
	if value == 1:
		frappe.cache.expire(key, expiry_seconds)
	return value


def set_with_expiry(key: str, value: Any, expiry_seconds: int) -> None:
	frappe.cache.set_value(key, value, expires_in_sec=expiry_seconds)


def get_value(key: str) -> Any:
	return frappe.cache.get_value(key)


def delete_value(key: str) -> None:
	frappe.cache.delete_value(key)


def ttl_seconds(key: str) -> int:
	try:
		raw_ttl = frappe.cache.ttl(frappe.cache.make_key(key))
	except Exception:
		return 0
	if raw_ttl is None:
		return 0
	return max(cint(raw_ttl), 0)
