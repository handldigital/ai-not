/**
 * AICAC-FIND (#198): type-ahead jump to registered settings.
 *
 * Keyboard: ArrowUp/Down, Enter, Escape. Announces via aria-live.
 * Same-screen jumps scroll + briefly highlight; other screens navigate
 * with a hash so the destination can open disclosures and highlight.
 */
( function () {
	'use strict';

	var cfg = window.handlAicacSettingsSearch || {};
	var index = Array.isArray( cfg.index ) ? cfg.index : [];
	var i18n = cfg.i18n || {};
	var currentScreen = cfg.currentScreen || '';
	var MAX_RESULTS = 8;
	var HIGHLIGHT_MS = 2200;

	/**
	 * @param {string} template
	 * @param {string|number} value
	 * @return {string}
	 */
	function format( template, value ) {
		return String( template || '' ).replace( '%d', String( value ) ).replace( '%s', String( value ) );
	}

	/**
	 * @param {string} query
	 * @return {Array}
	 */
	function match( query ) {
		var q = String( query || '' ).toLowerCase().replace( /^\s+|\s+$/g, '' );
		var hits = [];
		var i;
		var row;
		if ( ! q ) {
			return hits;
		}
		for ( i = 0; i < index.length; i++ ) {
			row = index[ i ];
			if ( row && row.haystack && row.haystack.indexOf( q ) !== -1 ) {
				hits.push( row );
				if ( hits.length >= MAX_RESULTS ) {
					break;
				}
			}
		}
		return hits;
	}

	/**
	 * @param {Element} root
	 * @param {string} message
	 */
	function announce( root, message ) {
		var status = root.querySelector( '#handl-aicac-settings-search-status' );
		if ( ! status ) {
			return;
		}
		status.textContent = '';
		window.setTimeout( function () {
			status.textContent = message || '';
		}, 20 );
	}

	/**
	 * Open ancestor <details> so a target is not hidden.
	 *
	 * @param {Element|null} node
	 */
	function openAncestors( node ) {
		var cur = node;
		while ( cur && cur.nodeType === 1 ) {
			if ( cur.nodeName === 'DETAILS' && ! cur.open ) {
				cur.open = true;
			}
			cur = cur.parentNode;
		}
	}

	/**
	 * @param {string} selector
	 * @return {Element|null}
	 */
	function findTarget( selector ) {
		if ( ! selector ) {
			return null;
		}
		try {
			return document.querySelector( selector );
		} catch ( err ) {
			return null;
		}
	}

	/**
	 * @param {Element} el
	 */
	function highlight( el ) {
		if ( ! el ) {
			return;
		}
		el.classList.add( 'handl-aicac-settings-search-target' );
		if ( typeof el.focus === 'function' ) {
			try {
				el.focus( { preventScroll: true } );
			} catch ( err ) {
				try {
					el.focus();
				} catch ( err2 ) {
					/* ignore */
				}
			}
		}
		window.setTimeout( function () {
			el.classList.remove( 'handl-aicac-settings-search-target' );
		}, HIGHLIGHT_MS );
	}

	/**
	 * @param {Object} row
	 * @param {Element} root
	 */
	function jumpTo( row, root ) {
		if ( ! row ) {
			return;
		}
		announce( root, format( i18n.jumpingTo, row.label || '' ) );

		var sameScreen = row.screen && row.screen === currentScreen;
		var selector = row.selector || '';
		var hash = '';

		if ( selector && selector.charAt( 0 ) === '#' && selector.indexOf( ' ' ) === -1 && selector.indexOf( '[' ) === -1 ) {
			hash = selector;
		}

		if ( ! sameScreen ) {
			var url = row.url || '';
			if ( ! url ) {
				return;
			}
			if ( hash ) {
				url = url.split( '#' )[ 0 ] + hash;
			} else if ( selector ) {
				try {
					window.sessionStorage.setItem( 'handlAicacSettingsSearchSelector', selector );
				} catch ( err ) {
					/* ignore */
				}
			}
			window.location.assign( url );
			return;
		}

		var target = findTarget( selector );
		if ( ! target ) {
			return;
		}
		openAncestors( target );
		if ( typeof target.scrollIntoView === 'function' ) {
			target.scrollIntoView( { block: 'center', behavior: 'smooth' } );
		}
		highlight( target );
	}

	function applyPendingSelector() {
		var selector = '';
		try {
			selector = window.sessionStorage.getItem( 'handlAicacSettingsSearchSelector' ) || '';
			window.sessionStorage.removeItem( 'handlAicacSettingsSearchSelector' );
		} catch ( err ) {
			selector = '';
		}
		if ( ! selector && window.location.hash ) {
			selector = window.location.hash;
		}
		if ( ! selector ) {
			return;
		}
		window.setTimeout( function () {
			var target = findTarget( selector );
			if ( ! target ) {
				return;
			}
			openAncestors( target );
			if ( typeof target.scrollIntoView === 'function' ) {
				target.scrollIntoView( { block: 'center' } );
			}
			highlight( target );
		}, 60 );
	}

	/**
	 * @param {Element} root
	 */
	function bind( root ) {
		var input = root.querySelector( '#handl-aicac-settings-search-input' );
		var list = root.querySelector( '#handl-aicac-settings-search-list' );
		if ( ! input || ! list ) {
			return;
		}

		var active = -1;
		var results = [];

		function closeList() {
			list.hidden = true;
			list.innerHTML = '';
			input.setAttribute( 'aria-expanded', 'false' );
			input.removeAttribute( 'aria-activedescendant' );
			active = -1;
			results = [];
		}

		/**
		 * @param {number} next
		 */
		function setActive( next ) {
			var items = list.querySelectorAll( '[role="option"]' );
			var i;
			if ( ! items.length ) {
				active = -1;
				input.removeAttribute( 'aria-activedescendant' );
				return;
			}
			if ( next < 0 ) {
				next = items.length - 1;
			}
			if ( next >= items.length ) {
				next = 0;
			}
			active = next;
			for ( i = 0; i < items.length; i++ ) {
				if ( i === active ) {
					items[ i ].setAttribute( 'aria-selected', 'true' );
					items[ i ].classList.add( 'is-active' );
					input.setAttribute( 'aria-activedescendant', items[ i ].id );
				} else {
					items[ i ].setAttribute( 'aria-selected', 'false' );
					items[ i ].classList.remove( 'is-active' );
				}
			}
		}

		function render() {
			var q = input.value;
			results = match( q );
			list.innerHTML = '';
			active = -1;
			input.removeAttribute( 'aria-activedescendant' );

			if ( ! String( q || '' ).replace( /^\s+|\s+$/g, '' ) ) {
				closeList();
				announce( root, '' );
				return;
			}

			if ( ! results.length ) {
				list.hidden = false;
				input.setAttribute( 'aria-expanded', 'true' );
				var empty = document.createElement( 'li' );
				empty.className = 'handl-aicac-settings-search__empty';
				empty.setAttribute( 'role', 'presentation' );
				empty.textContent = i18n.noResults || 'No matching settings';
				list.appendChild( empty );
				announce( root, i18n.noResults || 'No matching settings' );
				return;
			}

			var frag = document.createDocumentFragment();
			var i;
			var li;
			var row;
			for ( i = 0; i < results.length; i++ ) {
				row = results[ i ];
				li = document.createElement( 'li' );
				li.id = 'handl-aicac-settings-search-opt-' + i;
				li.className = 'handl-aicac-settings-search__option';
				li.setAttribute( 'role', 'option' );
				li.setAttribute( 'aria-selected', 'false' );
				li.setAttribute( 'data-index', String( i ) );
				li.textContent = row.label || '';
				frag.appendChild( li );
			}
			list.appendChild( frag );
			list.hidden = false;
			input.setAttribute( 'aria-expanded', 'true' );
			setActive( 0 );

			if ( results.length === 1 ) {
				announce( root, i18n.oneResult || '1 match' );
			} else {
				announce( root, format( i18n.nResults, results.length ) );
			}
		}

		function choose( idx ) {
			var row = results[ idx ];
			if ( ! row ) {
				return;
			}
			closeList();
			input.value = '';
			jumpTo( row, root );
		}

		input.addEventListener( 'input', render );
		input.addEventListener( 'focus', function () {
			if ( input.value ) {
				render();
			}
		} );

		input.addEventListener( 'keydown', function ( event ) {
			if ( event.key === 'ArrowDown' ) {
				if ( list.hidden ) {
					render();
				}
				event.preventDefault();
				setActive( active + 1 );
				return;
			}
			if ( event.key === 'ArrowUp' ) {
				if ( list.hidden ) {
					render();
				}
				event.preventDefault();
				setActive( active - 1 );
				return;
			}
			if ( event.key === 'Enter' ) {
				if ( ! list.hidden && active >= 0 && results[ active ] ) {
					event.preventDefault();
					choose( active );
				}
				return;
			}
			if ( event.key === 'Escape' ) {
				if ( ! list.hidden ) {
					event.preventDefault();
					closeList();
					announce( root, '' );
				}
			}
		} );

		list.addEventListener( 'mousedown', function ( event ) {
			var opt = event.target && event.target.closest ? event.target.closest( '[role="option"]' ) : null;
			if ( ! opt ) {
				return;
			}
			event.preventDefault();
			choose( parseInt( opt.getAttribute( 'data-index' ) || '-1', 10 ) );
		} );

		document.addEventListener( 'click', function ( event ) {
			if ( ! root.contains( event.target ) ) {
				closeList();
			}
		} );
	}

	function init() {
		var roots = document.querySelectorAll( '[data-aicac-settings-search]' );
		var i;
		for ( i = 0; i < roots.length; i++ ) {
			bind( roots[ i ] );
		}
		applyPendingSelector();
	}

	if ( document.readyState === 'loading' ) {
		document.addEventListener( 'DOMContentLoaded', init );
	} else {
		init();
	}
}() );
