(function () {
	"use strict";

	const WORKSPACE_TITLE = "security operations";
	const WORKSPACE_SLUG = "security-operations";
	const ROOT_CLASS = "ess-security-workspace";
	const BUTTONS_CLASS = "ess-real-buttons";

	const ACTIONS = [
		{ label: "Activity Log", doctype: "Activity Log", hint: "Monitor sign-ins" },
		{ label: "Access Log", doctype: "Access Log", hint: "Track data access" },
		{ label: "Users", doctype: "User", hint: "Manage accounts" },
	];

	const normalize = (value) =>
		String(value || "")
			.trim()
			.toLowerCase();

	const isSecurityWorkspace = () => {
		const path = normalize(window.location.pathname || "");
		if (path.includes("/app/security-operations")) {
			return true;
		}

		if (window.frappe && frappe.get_route) {
			const route = frappe.get_route() || [];
			const joined = route.map((part) => normalize(part)).join("/");
			if (joined.includes(WORKSPACE_SLUG) || joined.includes(WORKSPACE_TITLE)) {
				return true;
			}
		}

		const titleEl = document.querySelector(".page-title .title-text");
		if (!titleEl) return false;
		const title = normalize(titleEl.textContent || "");
		return title === WORKSPACE_TITLE || title === WORKSPACE_SLUG;
	};

	const hideOldShortcuts = (container) => {
		const widgets = container.querySelectorAll(
			".widget.shortcut-widget-box, .widget.shortcut.edit-mode"
		);
		widgets.forEach((widget) => {
			const block = widget.closest(".ce-block");
			if (block) block.style.display = "none";
			widget.style.display = "none";
		});
	};

	const makeButton = (action, index) => {
		const btn = document.createElement("button");
		btn.type = "button";
		btn.className = "btn btn-default btn-sm ess-real-button";
		btn.style.setProperty("--ess-delay", String(index * 90) + "ms");
		btn.innerHTML = `<span class="ess-btn-label">${action.label}</span><span class="ess-btn-hint">${action.hint}</span>`;
		btn.addEventListener("pointerdown", function (event) {
			const ripple = document.createElement("span");
			ripple.className = "ess-ripple";
			const rect = btn.getBoundingClientRect();
			const x = event.clientX - rect.left;
			const y = event.clientY - rect.top;
			ripple.style.left = `${x}px`;
			ripple.style.top = `${y}px`;
			btn.appendChild(ripple);
			window.setTimeout(() => ripple.remove(), 460);
		});
		btn.addEventListener("click", function () {
			if (window.frappe && frappe.set_route) {
				frappe.set_route("List", action.doctype);
			}
		});
		return btn;
	};

	const ensureButtons = (container) => {
		let row = container.querySelector("." + BUTTONS_CLASS);
		if (!row) {
			row = document.createElement("div");
			row.className = BUTTONS_CLASS;
			ACTIONS.forEach((action, index) => row.appendChild(makeButton(action, index)));
			const firstBlock = container.querySelector(".ce-block");
			if (firstBlock) {
				firstBlock.insertAdjacentElement("afterend", row);
			} else {
				container.prepend(row);
			}
			window.requestAnimationFrame(() => row.classList.add("ess-buttons-ready"));
		}
	};

	const cleanup = () => {
		document.body.classList.remove(ROOT_CLASS);
		document.querySelectorAll("." + BUTTONS_CLASS).forEach((node) => node.remove());
	};

	const run = () => {
		if (!isSecurityWorkspace()) {
			cleanup();
			return;
		}

		document.body.classList.add(ROOT_CLASS);
		const container = document.querySelector(".editor-js-container");
		if (!container) return;
		hideOldShortcuts(container);
		ensureButtons(container);
	};

	const init = () => {
		run();
		window.setTimeout(run, 120);
		window.setTimeout(run, 450);
		window.setTimeout(run, 1200);

		const observer = new MutationObserver(run);
		observer.observe(document.body, { childList: true, subtree: true });

		setInterval(run, 2500);
		$(document).on("page-change", run);
		if (window.frappe && frappe.router && frappe.router.on) {
			frappe.router.on("change", run);
		}
	};

	if (window.frappe && frappe.ready) {
		frappe.ready(init);
	} else {
		document.addEventListener("DOMContentLoaded", init);
	}
})();
