<?php
/**
 * Shared admin list pagination helper (Rules matrix, Activity log).
 *
 * Server-side only — no JS. Callers own filter/search query args; this class
 * sanitizes page/per-page, slices lists, and renders WP-native tablenav pages.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Bounded page size + WP-admin tablenav-pages markup.
 */
final class Pager {

	public const DEFAULT_PER_PAGE = 25;

	/** Query arg for the current page (1-based). */
	public const PAGE_ARG = 'handl_aicac_paged';

	/** Query arg for rows per page. */
	public const PER_PAGE_ARG = 'handl_aicac_per_page';

	/**
	 * Allowed per-page sizes.
	 *
	 * @var list<int>
	 */
	public const ALLOWED_PER_PAGE = array( 25, 50, 100 );

	/**
	 * @param mixed $raw
	 */
	public static function sanitize_per_page( $raw ): int {
		$n = is_numeric( $raw ) ? (int) $raw : 0;
		if ( in_array( $n, self::ALLOWED_PER_PAGE, true ) ) {
			return $n;
		}
		return self::DEFAULT_PER_PAGE;
	}

	/**
	 * Total page count for a filtered set.
	 */
	public static function total_pages( int $total_items, int $per_page ): int {
		$per_page = self::sanitize_per_page( $per_page );
		$total    = max( 0, $total_items );
		if ( 0 === $total ) {
			return 1;
		}
		return (int) max( 1, (int) ceil( $total / $per_page ) );
	}

	/**
	 * Clamp a 1-based page into range.
	 *
	 * @param mixed $raw
	 */
	public static function sanitize_page( $raw, int $total_pages = 1 ): int {
		$page        = is_numeric( $raw ) ? (int) $raw : 1;
		$total_pages = max( 1, $total_pages );
		if ( $page < 1 ) {
			return 1;
		}
		if ( $page > $total_pages ) {
			return $total_pages;
		}
		return $page;
	}

	/**
	 * Zero-based offset for array_slice / SQL LIMIT.
	 */
	public static function offset( int $page, int $per_page ): int {
		$per_page = self::sanitize_per_page( $per_page );
		$page     = max( 1, $page );
		return ( $page - 1 ) * $per_page;
	}

	/**
	 * Slice a 0-based list to the requested page.
	 *
	 * @template T
	 * @param list<T>|array<int|string,T> $items
	 * @return list<T>|array<int|string,T>
	 */
	public static function slice( array $items, int $page, int $per_page ): array {
		$per_page = self::sanitize_per_page( $per_page );
		$page     = max( 1, $page );
		$offset   = self::offset( $page, $per_page );
		return array_slice( $items, $offset, $per_page, true );
	}

	/**
	 * Build a page URL from a base URL + preserved query args.
	 *
	 * Omits page=1 and default per_page so URLs stay short.
	 *
	 * @param array<string, scalar> $query_args Preserved filters (status, search, …).
	 * @param array<string, scalar> $overrides  Merged on top (page / per_page).
	 */
	public static function url( string $base_url, array $query_args, array $overrides = array() ): string {
		$args = array_merge( $query_args, $overrides );

		$page = isset( $args[ self::PAGE_ARG ] )
			? self::sanitize_page( $args[ self::PAGE_ARG ] )
			: 1;
		$per_page = isset( $args[ self::PER_PAGE_ARG ] )
			? self::sanitize_per_page( $args[ self::PER_PAGE_ARG ] )
			: self::DEFAULT_PER_PAGE;

		unset( $args[ self::PAGE_ARG ], $args[ self::PER_PAGE_ARG ] );

		if ( $page > 1 ) {
			$args[ self::PAGE_ARG ] = $page;
		}
		if ( self::DEFAULT_PER_PAGE !== $per_page ) {
			$args[ self::PER_PAGE_ARG ] = $per_page;
		}

		// Drop empty scalars so filter clears stay clean.
		foreach ( $args as $key => $value ) {
			if ( '' === $value || null === $value ) {
				unset( $args[ $key ] );
			}
		}

		return add_query_arg( $args, $base_url );
	}

	/**
	 * Echo WP-native tablenav-pages controls (links only — safe inside a POST form).
	 *
	 * @param array{
	 *   base_url: string,
	 *   total: int,
	 *   page?: int,
	 *   per_page?: int,
	 *   query_args?: array<string, scalar>,
	 *   which?: string
	 * } $args
	 */
	public static function render_tablenav_pages( array $args ): void {
		$base_url   = isset( $args['base_url'] ) ? (string) $args['base_url'] : '';
		$total      = isset( $args['total'] ) ? max( 0, (int) $args['total'] ) : 0;
		$per_page   = self::sanitize_per_page( $args['per_page'] ?? self::DEFAULT_PER_PAGE );
		$total_pages = self::total_pages( $total, $per_page );
		$page       = self::sanitize_page( $args['page'] ?? 1, $total_pages );
		$query_args = isset( $args['query_args'] ) && is_array( $args['query_args'] )
			? $args['query_args']
			: array();
		$which = isset( $args['which'] ) ? sanitize_key( (string) $args['which'] ) : 'top';

		echo '<div class="tablenav-pages">';
		echo '<span class="displaying-num">';
		echo esc_html(
			sprintf(
				/* translators: %s: number of items */
				_n( '%s item', '%s items', $total, 'handl-ai-connector-access-control' ),
				number_format_i18n( $total )
			)
		);
		echo '</span>';

		if ( $total_pages <= 1 ) {
			echo '</div>';
			return;
		}

		$disable_first = $page <= 1;
		$disable_last  = $page >= $total_pages;

		echo '<span class="pagination-links">';

		self::echo_page_button(
			'first-page',
			$disable_first,
			self::url( $base_url, $query_args, array( self::PAGE_ARG => 1, self::PER_PAGE_ARG => $per_page ) ),
			__( 'First page', 'handl-ai-connector-access-control' ),
			'&laquo;',
			$which
		);
		self::echo_page_button(
			'prev-page',
			$disable_first,
			self::url( $base_url, $query_args, array( self::PAGE_ARG => max( 1, $page - 1 ), self::PER_PAGE_ARG => $per_page ) ),
			__( 'Previous page', 'handl-ai-connector-access-control' ),
			'&lsaquo;',
			$which
		);

		echo '<span class="paging-input">';
		echo '<label for="handl-aicac-current-page-' . esc_attr( $which ) . '" class="screen-reader-text">';
		echo esc_html__( 'Current page', 'handl-ai-connector-access-control' );
		echo '</label>';
		echo '<span class="tablenav-paging-text">';
		echo esc_html( (string) $page );
		echo ' ' . esc_html__( 'of', 'handl-ai-connector-access-control' ) . ' ';
		echo '<span class="total-pages">' . esc_html( (string) $total_pages ) . '</span>';
		echo '</span>';
		echo '</span>';

		self::echo_page_button(
			'next-page',
			$disable_last,
			self::url( $base_url, $query_args, array( self::PAGE_ARG => min( $total_pages, $page + 1 ), self::PER_PAGE_ARG => $per_page ) ),
			__( 'Next page', 'handl-ai-connector-access-control' ),
			'&rsaquo;',
			$which
		);
		self::echo_page_button(
			'last-page',
			$disable_last,
			self::url( $base_url, $query_args, array( self::PAGE_ARG => $total_pages, self::PER_PAGE_ARG => $per_page ) ),
			__( 'Last page', 'handl-ai-connector-access-control' ),
			'&raquo;',
			$which
		);

		echo '</span>';
		echo '</div>';
	}

	/**
	 * Echo a per-page <select> that navigates via data-url (no nested form).
	 *
	 * @param array<string, scalar> $query_args Filters to preserve; page resets to 1.
	 */
	public static function render_per_page_select(
		string $base_url,
		int $per_page,
		array $query_args,
		string $id = 'handl-aicac-per-page'
	): void {
		$per_page = self::sanitize_per_page( $per_page );

		echo '<label for="' . esc_attr( $id ) . '" class="screen-reader-text">';
		echo esc_html__( 'Plugins per page', 'handl-ai-connector-access-control' );
		echo '</label>';
		echo '<select id="' . esc_attr( $id ) . '" class="handl-aicac-per-page" onchange="if (this.selectedOptions.length) { window.location = this.selectedOptions[0].getAttribute(\'data-url\'); }">';
		foreach ( self::ALLOWED_PER_PAGE as $size ) {
			$url = self::url(
				$base_url,
				$query_args,
				array(
					self::PAGE_ARG     => 1,
					self::PER_PAGE_ARG => $size,
				)
			);
			printf(
				'<option value="%1$s" data-url="%2$s"%3$s>%4$s</option>',
				esc_attr( (string) $size ),
				esc_url( $url ),
				selected( $per_page, $size, false ),
				esc_html(
					sprintf(
						/* translators: %d: number of rows per page */
						__( '%d per page', 'handl-ai-connector-access-control' ),
						$size
					)
				)
			);
		}
		echo '</select>';
	}

	/**
	 * @param bool $disabled
	 */
	private static function echo_page_button(
		string $class,
		bool $disabled,
		string $url,
		string $screen_reader,
		string $glyph,
		string $which
	): void {
		if ( $disabled ) {
			echo '<span class="tablenav-pages-navspan button disabled" aria-hidden="true">' . $glyph . '</span> ';
			return;
		}
		printf(
			'<a class="%1$s button" href="%2$s"><span class="screen-reader-text">%3$s</span><span aria-hidden="true">%4$s</span></a> ',
			esc_attr( $class ),
			esc_url( $url ),
			esc_html( $screen_reader ),
			$glyph
		);
		unset( $which );
	}
}
