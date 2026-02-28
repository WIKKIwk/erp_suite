(function () {
	"use strict";

	const WORKSPACE_TITLE = "Security Operations";
	const WORKSPACE_SLUG = "security-operations";
	const ROOT_CLASS = "ess-security-workspace";

	const normalize = (value) =>
		String(value || "")
			.trim()
			.toLowerCase()
			.replace(/\s+/g, "-");

	const isWorkspaceTitleInDOM = () => {
		const titleEl = document.querySelector(".page-title .title-text");
		if (!titleEl) return false;
		const title = normalize(titleEl.textContent || "");
		return title === normalize(WORKSPACE_TITLE) || title === WORKSPACE_SLUG;
	};

	const isSecurityWorkspace = () => {
		if (!window.frappe || !frappe.get_route) {
			return isWorkspaceTitleInDOM();
		}
		const route = frappe.get_route() || [];
		if (!Array.isArray(route) || route[0] !== "Workspaces") {
			return isWorkspaceTitleInDOM();
		}
		const normalizedRouteParts = route.slice(1).filter(Boolean).map(normalize);
		if (normalizedRouteParts.includes(normalize(WORKSPACE_TITLE))) return true;
		if (normalizedRouteParts.includes(WORKSPACE_SLUG)) return true;
		return isWorkspaceTitleInDOM();
	};

	const applyCompactShortcutClass = () => {
		const widgets = document.querySelectorAll(
			".editor-js-container .widget.shortcut-widget-box, .editor-js-container .widget.shortcut.edit-mode"
		);
		widgets.forEach((node) => node.classList.add("ess-pill-shortcut"));
	};

	const clearCompactShortcutClass = () => {
		const widgets = document.querySelectorAll(".editor-js-container .widget.ess-pill-shortcut");
		widgets.forEach((node) => node.classList.remove("ess-pill-shortcut"));
	};

	const syncWorkspaceStyles = () => {
		const active = isSecurityWorkspace();
		document.body.classList.toggle(ROOT_CLASS, active);
		if (active) {
			applyCompactShortcutClass();
		} else {
			clearCompactShortcutClass();
		}
	};

	const scheduleSync = () => {
		syncWorkspaceStyles();
		window.setTimeout(syncWorkspaceStyles, 120);
		window.setTimeout(syncWorkspaceStyles, 380);
		window.setTimeout(syncWorkspaceStyles, 900);
	};

	const init = () => {
		scheduleSync();
		$(document).on("page-change", scheduleSync);
		if (window.frappe && frappe.router && frappe.router.on) {
			frappe.router.on("change", scheduleSync);
		}
	};

	if (window.frappe && frappe.ready) {
		frappe.ready(init);
	} else {
		document.addEventListener("DOMContentLoaded", init);
	}
})();
