from __future__ import annotations

import unittest

import frappe

from erpnext_security_suite.erpnext_security_suite.security_v3.config.settings import (
	SECURITY_MODE_STANDARD,
	SECURITY_MODE_ULTRA_HARD,
	load_settings,
)


class TestSecuritySettings(unittest.TestCase):
	CONF_KEYS = (
		"enterprise_security_mode",
		"enterprise_security_exempt_paths",
		"enterprise_security_rate_limit_count",
		"enterprise_security_rate_limit_window_sec",
		"enterprise_security_login_fail_threshold",
		"enterprise_security_login_fail_window_sec",
		"enterprise_security_rapid_fail_threshold",
		"enterprise_security_rapid_fail_window_sec",
		"enterprise_security_lock_minutes",
		"enterprise_security_log_retention_days",
		"enterprise_security_permanent_user_disable_on_rapid_fail",
		"enterprise_security_encrypt_audit_payload",
		"enterprise_security_fail2ban_log_enabled",
	)

	def setUp(self):
		self._saved_conf = {key: frappe.conf.get(key) for key in self.CONF_KEYS}
		load_settings(refresh=True)

	def tearDown(self):
		for key, value in self._saved_conf.items():
			if value is None:
				frappe.conf.pop(key, None)
			else:
				frappe.conf[key] = value
		load_settings(refresh=True)

	def _set_conf(self, **values):
		for key in self.CONF_KEYS:
			if key in values:
				frappe.conf[key] = values[key]
		load_settings(refresh=True)

	def test_default_exempt_paths_include_ping_endpoints(self):
		self._set_conf(enterprise_security_exempt_paths="")

		settings = load_settings(refresh=True)

		self.assertIn("/api/method/ping", settings.exempt_paths)
		self.assertIn("/api/method/frappe.ping", settings.exempt_paths)

	def test_invalid_mode_falls_back_to_standard(self):
		self._set_conf(enterprise_security_mode="invalid-mode")

		settings = load_settings(refresh=True)

		self.assertEqual(settings.mode, SECURITY_MODE_STANDARD)

	def test_ultra_hard_caps_limits_and_enforces_hardening(self):
		self._set_conf(
			enterprise_security_mode=SECURITY_MODE_ULTRA_HARD,
			enterprise_security_rate_limit_count=999,
			enterprise_security_rate_limit_window_sec=90,
			enterprise_security_login_fail_threshold=9,
			enterprise_security_login_fail_window_sec=3600,
			enterprise_security_rapid_fail_threshold=9,
			enterprise_security_rapid_fail_window_sec=60,
			enterprise_security_lock_minutes=5,
			enterprise_security_log_retention_days=30,
			enterprise_security_permanent_user_disable_on_rapid_fail=0,
			enterprise_security_encrypt_audit_payload=0,
			enterprise_security_fail2ban_log_enabled=0,
		)

		settings = load_settings(refresh=True)

		self.assertEqual(settings.mode, SECURITY_MODE_ULTRA_HARD)
		self.assertEqual(settings.request_limit, 40)
		self.assertEqual(settings.request_window_seconds, 45)
		self.assertEqual(settings.login_fail_threshold, 3)
		self.assertEqual(settings.login_fail_window_seconds, 600)
		self.assertEqual(settings.rapid_login_fail_threshold, 5)
		self.assertEqual(settings.rapid_login_fail_window_seconds, 10)
		self.assertEqual(settings.lock_duration_seconds, 7200)
		self.assertEqual(settings.log_retention_days, 90)
		self.assertTrue(settings.permanent_user_disable_on_rapid_fail)
		self.assertTrue(settings.encrypt_audit_payload)
		self.assertTrue(settings.fail2ban_log_enabled)
