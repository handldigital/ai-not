/**
 * Read-only auditor UI: hide mutating controls; leave plain export forms usable.
 */
(function () {
	'use strict';
	var cfg = window.handlAicacReadOnly || {};
	var allowed = cfg.exportActions || [];
	var wrap = document.querySelector('.wrap.handl-aicac-read-only');
	if (!wrap) {
		return;
	}
	var forms = wrap.querySelectorAll('form');
	for (var i = 0; i < forms.length; i++) {
		var form = forms[i];
		var actionInput = form.querySelector('input[name="handl_aicac_action"], button[name="handl_aicac_action"]');
		var action = '';
		if (actionInput && actionInput.value) {
			action = String(actionInput.value);
		}
		var isExport = allowed.indexOf(action) !== -1;
		if (isExport) {
			form.classList.add('handl-aicac-read-ok');
			continue;
		}
		var controls = form.querySelectorAll('button, input[type="submit"], input[type="button"]');
		for (var c = 0; c < controls.length; c++) {
			controls[c].disabled = true;
			controls[c].setAttribute('aria-disabled', 'true');
			controls[c].style.display = 'none';
		}
		var fields = form.querySelectorAll('input, select, textarea');
		for (var f = 0; f < fields.length; f++) {
			var el = fields[f];
			if (el.type === 'hidden') {
				continue;
			}
			el.disabled = true;
		}
	}
})();
