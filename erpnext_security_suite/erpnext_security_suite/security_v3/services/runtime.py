from __future__ import annotations


def normalize_user(user: str | None) -> str:
	return (user or "").strip().lower()


def is_trusted_user(user: str | None, trusted_users: tuple[str, ...]) -> bool:
	clean_user = normalize_user(user)
	if not clean_user:
		return False
	trusted_set = {normalize_user(value) for value in trusted_users}
	return clean_user in trusted_set


def is_exempt_path(path: str | None, exempt_paths: tuple[str, ...]) -> bool:
	clean_path = (path or "").strip()
	if not clean_path:
		return False
	return any(clean_path.startswith(prefix) for prefix in exempt_paths)
