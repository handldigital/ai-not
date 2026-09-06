/**
 * Read-only auditor UI: hide mutating controls; leave plain export forms usable.
 * Controls may sit outside <form> and use the HTML form="" attribute (Rules matrix).
 */
(function () {
	'use strict';
	var cfg = window.handlAicacReadOnly || {};
	var allowed = cfg.exportActions || [];
	var wrap = document.querySelector('.wrap.handl-aicac-read-only');
	if (!wrap) {
		return;
	}

	function formAction(form) {
		var actionInput = form.querySelector(
			'input[name="handl_aicac_action"], button[name="handl_aicac_action"]'
		);
		if (actionInput && actionInput.value) {
			return String(actionInput.value);
		}
		return '';
	}

	var exportFormIds = {};
	var forms = wrap.querySelectorAll('form');
	for (var i = 0; i < forms.length; i++) {
		var form = forms[i];
		if (allowed.indexOf(formAction(form)) === -1) {
			continue;
		}
		form.classList.add('handl-aicac-read-ok');
		if (form.id) {
			exportFormIds[form.id] = true;
		}
	}

	function isExportControl(el) {
		if (el.closest && el.closest('form.handl-aicac-read-ok')) {
			return true;
		}
		var formId = el.getAttribute('form');
		return !!(formId && exportFormIds[formId]);
	}

	var controls = wrap.querySelectorAll('button, input, select, textarea');
	for (var c = 0; c < controls.length; c++) {
		var el = controls[c];
		if (el.type === 'hidden') {
			continue;
		}
		if (isExportControl(el)) {
			continue;
		}
		el.disabled = true;
		if (
			el.tagName === 'BUTTON' ||
			el.type === 'submit' ||
			el.type === 'button'
		) {
			el.setAttribute('aria-disabled', 'true');
			el.style.display = 'none';
		}
	}
})();
