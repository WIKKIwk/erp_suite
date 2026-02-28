(function () {
	"use strict";

	const WORKSPACE_TITLE = "Security Operations";
	const WORKSPACE_SLUG = "security-operations";
	const ROOT_CLASS = "ess-security-workspace";

	const ACTIONS = [
		{ label: "Activity Log", doctype: "Activity Log", type: "DocType" },
		{ label: "Access Log", doctype: "Access Log", type: "DocType" },
		{ label: "Users", doctype: "User", type: "DocType" },
	];

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

	const onActionClick = (action) => {
		if (!window.frappe) return;
		if (action.type === "DocType") {
			frappe.set_route("List", action.doctype);
		}
	};

	const renderActionButtons = () => {
		const root = document.querySelector(".editor-js-container");
		if (!root || root.querySelector(".ess-security-actions")) {
			return;
		}

		const actions = document.createElement("div");
		actions.className = "ess-security-actions";

		ACTIONS.forEach((action) => {
			const btn = document.createElement("button");
			btn.type = "button";
			btn.className = "btn btn-default btn-sm ess-security-btn";
			btn.textContent = action.label;
			btn.addEventListener("click", () => onActionClick(action));
			actions.appendChild(btn);
		});

		const firstBlock = root.querySelector(".ce-block");
		if (firstBlock) {
			firstBlock.insertAdjacentElement("afterend", actions);
		} else {
			root.prepend(actions);
		}
	};

	const hideShortcutBlocks = () => {
		const widgets = document.querySelectorAll(
			".editor-js-container .widget.shortcut-widget-box, .editor-js-container .widget.shortcut.edit-mode"
		);
		widgets.forEach((widget) => {
			const block = widget.closest(".ce-block");
			if (block) {
				block.classList.add("ess-shortcut-hidden");
			} else {
				widget.classList.add("ess-shortcut-hidden-widget");
			}
		});
	};

	const clearWorkspaceEnhancements = () => {
		document.querySelectorAll(".ess-security-actions").forEach((node) => node.remove());
		document
			.querySelectorAll(".editor-js-container .ce-block.ess-shortcut-hidden")
			.forEach((node) => node.classList.remove("ess-shortcut-hidden"));
		document
			.querySelectorAll(".editor-js-container .widget.ess-shortcut-hidden-widget")
			.forEach((node) => node.classList.remove("ess-shortcut-hidden-widget"));
	};

	const syncWorkspace = () => {
		const active = isSecurityWorkspace();
		document.body.classList.toggle(ROOT_CLASS, active);
		if (!active) {
			clearWorkspaceEnhancements();
			return;
		}
		renderActionButtons();
		hideShortcutBlocks();
	};

	const scheduleSync = () => {
		syncWorkspace();
		window.setTimeout(syncWorkspace, 120);
		window.setTimeout(syncWorkspace, 380);
		window.setTimeout(syncWorkspace, 900);
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
