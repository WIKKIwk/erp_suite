from __future__ import annotations

from erpnext_security_suite.erpnext_security_suite.security_v3.config.settings import load_settings
from erpnext_security_suite.erpnext_security_suite.security_v3.detectors.login_anomaly import process_login_activity


def on_activity_log_after_insert(doc, method=None) -> None:
	settings = load_settings()
	if not settings.enabled:
		return
	process_login_activity(doc, settings)
