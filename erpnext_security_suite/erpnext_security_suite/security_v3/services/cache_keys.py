from __future__ import annotations

import hashlib

PREFIX = "ess_v3"


def user_lock_key(user: str) -> str:
	return f"{PREFIX}:lock:user:{_digest(user)}"


def ip_block_key(ip_address: str) -> str:
	return f"{PREFIX}:lock:ip:{_digest(ip_address)}"


def failed_login_counter_key(identity: str) -> str:
	return f"{PREFIX}:fail:login:{_digest(identity)}"


def rapid_failed_login_counter_key(identity: str) -> str:
	return f"{PREFIX}:fail:rapid:{_digest(identity)}"


def request_counter_key(identity: str, path: str, window_seconds: int) -> str:
	path_digest = hashlib.sha1(path.encode("utf-8")).hexdigest()[:16]
	return f"{PREFIX}:rate:{window_seconds}:{_digest(identity)}:{path_digest}"


def _clean(value: str) -> str:
	return (value or "").strip().lower().replace(" ", "_")


def _digest(value: str) -> str:
	clean = _clean(value)
	return hashlib.sha256(clean.encode("utf-8")).hexdigest()[:24]
