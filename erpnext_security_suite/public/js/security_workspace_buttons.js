(function () {
	"use strict";

	const WORKSPACE_TITLE = "security operations";
	const WORKSPACE_SLUG = "security-operations";
	const ROOT_CLASS = "ess-security-workspace";
	const BUTTONS_CLASS = "ess-real-buttons";
	const MODE_PANEL_CLASS = "ess-mode-panel";
	const MODE_STATUS_CLASS = "ess-mode-status";
	const MODE_BUTTON_CLASS = "ess-mode-toggle";
	const API_BASE =
		"erpnext_security_suite.erpnext_security_suite.security_v3.api.security_center.";

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

	const callApi = (method, args) => {
		if (window.frappe && typeof frappe.xcall === "function") {
			return frappe.xcall(method, args || {});
		}

		return new Promise((resolve, reject) => {
			if (!window.frappe || typeof frappe.call !== "function") {
				reject(new Error("Frappe API is not available"));
				return;
			}

			frappe.call({
				method,
				args: args || {},
				callback: (response) => resolve(response && response.message ? response.message : {}),
				error: (error) => reject(error),
			});
		});
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

	const applyModeUI = (panel, status) => {
		const isUltra = Boolean(status && status.is_ultra_hard);
		const profile = status && status.mode_profile ? status.mode_profile : isUltra ? "Ultra Hard Suit" : "Standard Shield";
		const modeStatus = panel.querySelector("." + MODE_STATUS_CLASS);
		const modeBtn = panel.querySelector("." + MODE_BUTTON_CLASS);
		if (!modeStatus || !modeBtn) return;

		modeStatus.textContent = isUltra ? "Ultra Hard: ON" : "Ultra Hard: OFF";
		modeStatus.classList.toggle("is-on", isUltra);
		modeBtn.textContent = isUltra ? "Switch to Standard" : "Enable Ultra Hard";
		modeBtn.setAttribute("data-ultra-hard", isUltra ? "1" : "0");
		modeBtn.setAttribute("title", profile);
	};

	const refreshModeStatus = (panel) => {
		if (!panel || panel.dataset.loading === "1") return;
		panel.dataset.loading = "1";
		callApi(API_BASE + "get_security_status")
			.then((status) => {
				applyModeUI(panel, status || {});
				panel.dataset.lastSync = String(Date.now());
			})
			.catch(() => {
				const modeStatus = panel.querySelector("." + MODE_STATUS_CLASS);
				if (modeStatus) modeStatus.textContent = "Mode status unavailable";
			})
			.finally(() => {
				panel.dataset.loading = "0";
			});
	};

	const wireModeToggle = (panel) => {
		const modeBtn = panel.querySelector("." + MODE_BUTTON_CLASS);
		if (!modeBtn) return;

		modeBtn.addEventListener("click", () => {
			if (modeBtn.dataset.busy === "1") return;
			const currentlyUltra = modeBtn.getAttribute("data-ultra-hard") === "1";
			const enableUltra = !currentlyUltra;

			modeBtn.dataset.busy = "1";
			modeBtn.classList.add("is-busy");
			modeBtn.disabled = true;

			callApi(API_BASE + "set_ultra_hard_mode", { enabled: enableUltra ? 1 : 0 })
				.then((result) => {
					applyModeUI(panel, result || {});
					if (window.frappe && typeof frappe.show_alert === "function") {
						frappe.show_alert({
							message: enableUltra
								? "Ultra Hard Suit mode enabled"
								: "Standard security mode enabled",
							indicator: enableUltra ? "orange" : "green",
						});
					}
				})
				.catch((error) => {
					if (window.frappe && typeof frappe.msgprint === "function") {
						frappe.msgprint({
							title: "Security Mode",
							indicator: "red",
							message:
								(error && error.message) || "Failed to change security mode. Check permissions.",
						});
					}
				})
				.finally(() => {
					modeBtn.dataset.busy = "0";
					modeBtn.classList.remove("is-busy");
					modeBtn.disabled = false;
				});
		});
	};

	const ensureModePanel = (container, anchor) => {
		let panel = container.querySelector("." + MODE_PANEL_CLASS);
		if (!panel) {
			panel = document.createElement("div");
			panel.className = MODE_PANEL_CLASS;
			panel.innerHTML =
				'<div class="ess-mode-title">Security Mode</div><div class="ess-mode-row"><span class="' +
				MODE_STATUS_CLASS +
				'">Loading...</span><button type="button" class="btn btn-default btn-sm ' +
				MODE_BUTTON_CLASS +
				'">Enable Ultra Hard</button></div>';

			if (anchor) {
				anchor.insertAdjacentElement("afterend", panel);
			} else {
				container.prepend(panel);
			}

			wireModeToggle(panel);
			refreshModeStatus(panel);
		} else if (anchor && panel.previousElementSibling !== anchor) {
			anchor.insertAdjacentElement("afterend", panel);
		}

		const lastSync = Number(panel.dataset.lastSync || 0);
		if (!lastSync || Date.now() - lastSync > 60 * 1000) {
			refreshModeStatus(panel);
		}

		return panel;
	};

	const ensureButtons = (container) => {
		let row = container.querySelector("." + BUTTONS_CLASS);
		const headerBlock = container.querySelector(".ce-block");
		const modePanel = ensureModePanel(container, headerBlock);
		const anchorForButtons = modePanel || headerBlock;

		if (!row) {
			row = document.createElement("div");
			row.className = BUTTONS_CLASS;
			ACTIONS.forEach((action, index) => row.appendChild(makeButton(action, index)));
			if (anchorForButtons) {
				anchorForButtons.insertAdjacentElement("afterend", row);
			} else {
				container.prepend(row);
			}
			window.requestAnimationFrame(() => row.classList.add("ess-buttons-ready"));
		} else if (anchorForButtons && row.previousElementSibling !== anchorForButtons) {
			anchorForButtons.insertAdjacentElement("afterend", row);
		}
	};

	const cleanup = () => {
		document.body.classList.remove(ROOT_CLASS);
		document
			.querySelectorAll("." + BUTTONS_CLASS + ", ." + MODE_PANEL_CLASS)
			.forEach((node) => node.remove());
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
