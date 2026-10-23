/**
 * AICAC-EXIT-INTERVIEW (#328): opt-in deactivation feedback on plugins.php.
 * Never blocks deactivate — errors, Esc, Skip, and timeouts all proceed.
 */
(function () {
	'use strict';

	var cfg = window.handlAicacExitInterview;
	if (!cfg || !cfg.pluginBasename) {
		return;
	}

	var activeLink = null;
	var dialog = null;
	var previousFocus = null;
	var submitting = false;

	function deactivateHref(link) {
		return link && link.getAttribute('href') ? link.getAttribute('href') : '';
	}

	function isOurDeactivate(link) {
		if (!link || link.tagName !== 'A') {
			return false;
		}
		var href = deactivateHref(link);
		if (!href || href.indexOf('action=deactivate') === -1) {
			return false;
		}
		// Core marks the row with data-plugin="<basename>".
		var row = link.closest('tr[data-plugin]');
		if (row && row.getAttribute('data-plugin') === cfg.pluginBasename) {
			return true;
		}
		// Fallback: slug in the deactivate URL.
		try {
			var u = new URL(href, window.location.origin);
			var plugin = u.searchParams.get('plugin');
			return plugin === cfg.pluginBasename;
		} catch (e) {
			return href.indexOf(encodeURIComponent(cfg.pluginBasename)) !== -1;
		}
	}

	function proceed() {
		var href = deactivateHref(activeLink);
		teardown();
		if (href) {
			window.location.href = href;
		}
	}

	function teardown() {
		if (dialog && dialog.parentNode) {
			dialog.parentNode.removeChild(dialog);
		}
		dialog = null;
		activeLink = null;
		submitting = false;
		document.removeEventListener('keydown', onDocKey, true);
		if (previousFocus && typeof previousFocus.focus === 'function') {
			try {
				previousFocus.focus();
			} catch (e) {
				/* ignore */
			}
		}
		previousFocus = null;
	}

	function focusables() {
		if (!dialog) {
			return [];
		}
		return Array.prototype.slice.call(
			dialog.querySelectorAll(
				'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
			)
		).filter(function (el) {
			return !el.disabled && el.offsetParent !== null;
		});
	}

	function onDocKey(ev) {
		if (!dialog) {
			return;
		}
		if (ev.key === 'Escape') {
			ev.preventDefault();
			proceed();
			return;
		}
		if (ev.key !== 'Tab') {
			return;
		}
		var nodes = focusables();
		if (!nodes.length) {
			return;
		}
		var first = nodes[0];
		var last = nodes[nodes.length - 1];
		if (ev.shiftKey && document.activeElement === first) {
			ev.preventDefault();
			last.focus();
		} else if (!ev.shiftKey && document.activeElement === last) {
			ev.preventDefault();
			first.focus();
		}
	}

	function selectedReason() {
		var checked = dialog.querySelector('input[name="handl-aicac-exit-reason"]:checked');
		return checked ? checked.value : '';
	}

	function otherText() {
		var field = dialog.querySelector('#handl-aicac-exit-other');
		return field ? field.value : '';
	}

	function syncOther() {
		var other = dialog.querySelector('#handl-aicac-exit-other');
		var wrap = dialog.querySelector('.handl-aicac-exit-interview__other');
		if (!other || !wrap) {
			return;
		}
		var show = selectedReason() === 'other';
		wrap.hidden = !show;
		other.required = show;
		if (!show) {
			other.value = '';
		}
	}

	function sendFeedback() {
		if (submitting) {
			return;
		}
		var reason = selectedReason();
		if (!reason) {
			return;
		}
		if (reason === 'other' && !otherText().trim()) {
			var other = dialog.querySelector('#handl-aicac-exit-other');
			if (other) {
				other.focus();
			}
			return;
		}
		submitting = true;
		var body = new window.FormData();
		body.append('action', cfg.action);
		body.append('nonce', cfg.nonce);
		body.append('reason', reason);
		body.append('other', otherText());

		var done = false;
		function finish() {
			if (done) {
				return;
			}
			done = true;
			proceed();
		}
		// Hard ceiling — never leave the admin waiting on a hung request.
		var timer = window.setTimeout(finish, 4000);

		try {
			window
				.fetch(cfg.ajaxUrl, {
					method: 'POST',
					credentials: 'same-origin',
					body: body,
				})
				.then(function () {
					window.clearTimeout(timer);
					finish();
				})
				.catch(function () {
					window.clearTimeout(timer);
					finish();
				});
		} catch (e) {
			window.clearTimeout(timer);
			finish();
		}
	}

	function openModal(link) {
		if (dialog) {
			teardown();
		}
		activeLink = link;
		previousFocus = document.activeElement;

		var i18n = cfg.i18n || {};
		var reasons = i18n.reasons || {};
		var reasonHtml = Object.keys(reasons)
			.map(function (slug, idx) {
				var id = 'handl-aicac-exit-reason-' + slug;
				return (
					'<label class="handl-aicac-exit-interview__reason" for="' +
					id +
					'">' +
					'<input type="radio" name="handl-aicac-exit-reason" id="' +
					id +
					'" value="' +
					slug +
					'"' +
					(idx === 0 ? ' checked' : '') +
					' /> ' +
					'<span>' +
					reasons[slug] +
					'</span></label>'
				);
			})
			.join('');

		dialog = document.createElement('div');
		dialog.className = 'handl-aicac-exit-interview';
		dialog.setAttribute('role', 'dialog');
		dialog.setAttribute('aria-modal', 'true');
		dialog.setAttribute('aria-labelledby', 'handl-aicac-exit-title');
		dialog.innerHTML =
			'<div class="handl-aicac-exit-interview__backdrop" data-exit-skip="1"></div>' +
			'<div class="handl-aicac-exit-interview__panel">' +
			'<h2 id="handl-aicac-exit-title" class="handl-aicac-exit-interview__title">' +
			(i18n.title || '') +
			'</h2>' +
			'<div class="handl-aicac-exit-interview__reasons" role="radiogroup" aria-labelledby="handl-aicac-exit-title">' +
			reasonHtml +
			'</div>' +
			'<div class="handl-aicac-exit-interview__other" hidden>' +
			'<label for="handl-aicac-exit-other">' +
			(i18n.otherLabel || '') +
			'</label>' +
			'<textarea id="handl-aicac-exit-other" rows="2" maxlength="500"></textarea>' +
			'<p class="description">' +
			(i18n.otherHint || '') +
			'</p></div>' +
			'<div class="handl-aicac-exit-interview__actions">' +
			'<button type="button" class="button button-primary" data-exit-skip="1">' +
			(i18n.skip || '') +
			'</button>' +
			'<button type="button" class="button" data-exit-send="1">' +
			(i18n.send || '') +
			'</button></div></div>';

		document.body.appendChild(dialog);
		document.addEventListener('keydown', onDocKey, true);

		dialog.addEventListener('change', function (ev) {
			if (ev.target && ev.target.name === 'handl-aicac-exit-reason') {
				syncOther();
			}
		});
		dialog.addEventListener('click', function (ev) {
			var t = ev.target;
			if (!t) {
				return;
			}
			if (t.closest('[data-exit-skip]')) {
				ev.preventDefault();
				proceed();
				return;
			}
			if (t.closest('[data-exit-send]')) {
				ev.preventDefault();
				sendFeedback();
			}
		});

		syncOther();
		var skipBtn = dialog.querySelector('[data-exit-skip].button');
		if (skipBtn) {
			skipBtn.focus();
		}
	}

	document.addEventListener(
		'click',
		function (ev) {
			var link = ev.target && ev.target.closest ? ev.target.closest('a') : null;
			if (!isOurDeactivate(link)) {
				return;
			}
			ev.preventDefault();
			ev.stopPropagation();
			openModal(link);
		},
		true
	);
})();
