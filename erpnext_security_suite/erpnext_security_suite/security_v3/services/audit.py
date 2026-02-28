from __future__ import annotations

import frappe


def log_security_event(*, subject: str, status: str = "Success", content: str | None = None, user: str | None = None) -> None:
	try:
		frappe.get_doc(
			{
				"doctype": "Activity Log",
				"subject": f"Security V3: {subject}",
				"status": status,
				"user": user or frappe.session.user or "Administrator",
				"content": content,
			}
		).insert(ignore_permissions=True, ignore_links=True)
	except Exception:
		# Never break business requests because of audit log failures.
		frappe.log_error(title="Security V3 Audit Log Error")


def clear_old_security_events(days: int) -> None:
	frappe.db.delete(
		"Activity Log",
		{
			"subject": ["like", "Security V3:%"],
			"creation": ["<", frappe.utils.add_days(frappe.utils.nowdate(), -abs(int(days)))],
		},
	)
