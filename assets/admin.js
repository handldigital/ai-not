/**
 * AICAC-PREMIUM-POLISH (#248): shared admin-shell behaviour.
 *
 * Presentational only. It must never disable, rename, remove, or move a
 * submitted field, and it must never change which form a control belongs to.
 */
( function () {
	'use strict';

	/**
	 * Mark a submitting form busy and show the WordPress spinner.
	 *
	 * Called from a zero-delay timeout so the browser has already captured
	 * the form data before anything is inserted into the DOM.
	 *
	 * @param {HTMLFormElement} form
	 * @param {Element|null}    submitter
	 */
	function markBusy( form, submitter ) {
		if ( ! form || 'true' === form.getAttribute( 'aria-busy' ) ) {
			return;
		}
		form.setAttribute( 'aria-busy', 'true' );

		var spinner = document.createElement( 'span' );
		spinner.className = 'spinner is-active handl-aicac-busy-spinner';
		spinner.setAttribute( 'aria-hidden', 'true' );

		if ( submitter && submitter.parentNode ) {
			submitter.parentNode.insertBefore( spinner, submitter.nextSibling );
		} else {
			form.appendChild( spinner );
		}
	}

	document.addEventListener(
		'submit',
		function ( event ) {
			var form = event.target;
			if ( ! form || 'FORM' !== form.nodeName || event.defaultPrevented ) {
				return;
			}
			var submitter = event.submitter || null;
			window.setTimeout( function () {
				markBusy( form, submitter );
			}, 0 );
		},
		true
	);

	/**
	 * A disclosure must never hide an error, confirmation, preview, or result.
	 * PHP opens the owning disclosure for the states it knows about; this is
	 * the catch-all for notices rendered by shared helpers.
	 */
	function openDisclosuresAroundNotices() {
		var selector = '.notice-error, .handl-aicac-autofocus';
		var flagged = document.querySelectorAll( selector );
		var i;
		var node;
		var owner;

		for ( i = 0; i < flagged.length; i++ ) {
			node = flagged[ i ].parentNode;
			while ( node && node.nodeType === 1 ) {
				if ( 'DETAILS' === node.nodeName && ! node.open ) {
					node.open = true;
				}
				node = node.parentNode;
			}
		}

		owner = window.location.hash ? document.querySelector( window.location.hash ) : null;
		if ( ! owner ) {
			return;
		}
		node = owner.parentNode;
		while ( node && node.nodeType === 1 ) {
			if ( 'DETAILS' === node.nodeName && ! node.open ) {
				node.open = true;
			}
			node = node.parentNode;
		}
	}

	/**
	 * Move focus to the notice or heading inside a disclosure that PHP opened
	 * because it carries a validation error, preview, or action result.
	 */
	function focusAutoOpenedDisclosure() {
		var target = document.querySelector( '.handl-aicac-autofocus' );
		if ( ! target ) {
			return;
		}
		if ( ! target.hasAttribute( 'tabindex' ) ) {
			target.setAttribute( 'tabindex', '-1' );
		}
		target.focus();
	}

	if ( 'loading' === document.readyState ) {
		document.addEventListener( 'DOMContentLoaded', function () {
			openDisclosuresAroundNotices();
			focusAutoOpenedDisclosure();
		} );
	} else {
		openDisclosuresAroundNotices();
		focusAutoOpenedDisclosure();
	}
}() );
