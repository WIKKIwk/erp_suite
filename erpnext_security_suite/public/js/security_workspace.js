(function () {
	"use strict";

	const WORKSPACE_TITLE = "Security Operations";
	const ROOT_CLASS = "ess-security-workspace";

	const isSecurityWorkspace = () => {
		if (!window.frappe || !frappe.get_route) {
			return false;
		}
		const route = frappe.get_route();
		return Array.isArray(route) && route[0] === "Workspaces" && route[1] === WORKSPACE_TITLE;
	};

	const updateBodyClass = () => {
		document.body.classList.toggle(ROOT_CLASS, isSecurityWorkspace());
	};

	const init = () => {
		updateBodyClass();
		if (window.frappe && frappe.router && frappe.router.on) {
			frappe.router.on("change", updateBodyClass);
		}
	};

	if (window.frappe && frappe.ready) {
		frappe.ready(init);
	} else {
		document.addEventListener("DOMContentLoaded", init);
	}
})();
