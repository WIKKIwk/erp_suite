from __future__ import annotations

from erpnext_security_suite.erpnext_security_suite.security_v3.config.settings import load_settings
from erpnext_security_suite.erpnext_security_suite.security_v3.services.audit import clear_old_security_events


def daily() -> None:
	settings = load_settings(refresh=True)
	clear_old_security_events(settings.log_retention_days)
