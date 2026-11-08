<?php
/**
 * AICAC-FOYER (#508): Simple mode — seven core screens plus a More tools hall.
 *
 * Presentation-only. Hides feature-class submenus via a late admin_menu pass.
 * Page hooks stay registered so direct URLs, dashboard links, and alerts work.
 * Zero edits to feature classes, admin.php, or readme.txt.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Simple/full menu mode, searchable More tools directory, and per-tool pins.
 */
final class Foyer {

	public const PAGE_SLUG = 'handl-aicac-foyer';

	public const MODE_OPTION = 'handl_aicac_ui_mode';

	public const STATE_OPTION = 'handl_aicac_foyer';

	public const MODE_SIMPLE = 'simple';

	public const MODE_FULL = 'full';

	public const ACTION_MODE = 'handl_aicac_foyer_mode';

	public const ACTION_PIN = 'handl_aicac_foyer_pin';

	public const ACTION_UNPIN = 'handl_aicac_foyer_unpin';

	public const SEARCH_ARG = 'handl_aicac_foyer_q';

	public const FRAMING = 'presentation_only_never_edits_features';

	public const GROUP_COST = 'cost';

	public const GROUP_PRIVACY = 'privacy';

	public const GROUP_RELIABILITY = 'reliability';

	public const GROUP_COMPLIANCE = 'compliance';

	public const GROUP_HYGIENE = 'hygiene';

	private const VISIT_CAP = 100;

	/** @var bool */
	private static $registered = false;

	/** @var bool */
	private static $posted = false;

	/** @var int|null */
	private static $test_now = null;

	/** @var list<array{0:string,1:string,2:string,3?:string}>|null */
	private static $catalog_items = null;

	public static function init(): void {
		if ( self::$registered ) {
			return;
		}
		self::$registered = true;
		self::maybe_seed_mode();
		add_action( 'admin_menu', array( self::class, 'maybe_handle_post' ), 5 );
		add_action( 'admin_menu', array( self::class, 'register_menu' ), 20 );
		add_action( 'admin_menu', array( self::class, 'snapshot_menu' ), 998 );
		add_action( 'admin_menu', array( self::class, 'apply_simple_menu' ), 999 );
		add_action( 'admin_init', array( self::class, 'maybe_handle_post' ), 1 );
		add_action( 'admin_init', array( self::class, 'maybe_record_visit' ), 20 );
		add_action( 'admin_notices', array( self::class, 'maybe_render_mode_toggle' ) );
	}

	public static function reset_for_tests(): void {
		self::$registered    = false;
		self::$posted        = false;
		self::$test_now      = null;
		self::$catalog_items = null;
	}

	public static function set_test_now( ?int $now ): void {
		self::$test_now = $now;
	}

	/**
	 * @param list<array{0:string,1:string,2:string,3?:string}>|null $rows
	 */
	public static function set_test_submenu( ?array $rows ): void {
		self::$catalog_items = $rows;
		if ( null === $rows ) {
			return;
		}
		$parent = class_exists( Admin::class, false ) ? Admin::MENU_SLUG : 'handl-aicac';
		$GLOBALS['submenu'][ $parent ] = $rows;
	}

	public static function snapshot_menu(): void {
		if ( null !== self::$catalog_items ) {
			return;
		}
		self::$catalog_items = self::submenu_items_from_global();
	}

	public static function now(): int {
		if ( null !== self::$test_now ) {
			return (int) self::$test_now;
		}
		if ( class_exists( Clock::class, false ) && method_exists( Clock::class, 'now' ) ) {
			return (int) Clock::now();
		}

		return time();
	}

	public static function maybe_seed_mode(): void {
		$existing = get_option( self::MODE_OPTION, false );
		if ( false !== $existing && null !== $existing && '' !== $existing ) {
			return;
		}
		$fresh = true;
		if ( class_exists( Onboarding::class, false ) && method_exists( Onboarding::class, 'is_fresh_install' ) ) {
			$fresh = Onboarding::is_fresh_install();
		} elseif ( class_exists( Plugin::class, false ) ) {
			$raw   = get_option( Plugin::OPTION_KEY, null );
			$fresh = null === $raw || false === $raw;
		}
		update_option( self::MODE_OPTION, $fresh ? self::MODE_SIMPLE : self::MODE_FULL, false );
	}

	public static function mode(): string {
		self::maybe_seed_mode();
		$mode = (string) get_option( self::MODE_OPTION, self::MODE_SIMPLE );

		return self::MODE_FULL === $mode ? self::MODE_FULL : self::MODE_SIMPLE;
	}

	public static function is_simple(): bool {
		return self::MODE_SIMPLE === self::mode();
	}

	public static function set_mode( string $mode ): void {
		update_option( self::MODE_OPTION, self::MODE_FULL === $mode ? self::MODE_FULL : self::MODE_SIMPLE, false );
	}

	/**
	 * @return list<string>
	 */
	public static function pins(): array {
		$state = self::state();

		return is_array( $state['pins'] ?? null ) ? array_values( array_filter( $state['pins'] ) ) : array();
	}

	public static function pin( string $slug ): void {
		$slug = self::sanitize_tool_slug( $slug );
		if ( '' === $slug || self::is_reserved_slug( $slug ) ) {
			return;
		}
		$state = self::state();
		$pins  = is_array( $state['pins'] ?? null ) ? $state['pins'] : array();
		if ( ! in_array( $slug, $pins, true ) ) {
			$pins[] = $slug;
		}
		$state['pins'] = array_values( array_unique( $pins ) );
		self::save_state( $state );
	}

	public static function unpin( string $slug ): void {
		$slug  = self::sanitize_tool_slug( $slug );
		$state = self::state();
		$pins  = is_array( $state['pins'] ?? null ) ? $state['pins'] : array();
		$state['pins'] = array_values(
			array_filter(
				$pins,
				static function ( $item ) use ( $slug ) {
					return (string) $item !== $slug;
				}
			)
		);
		self::save_state( $state );
	}

	public static function is_pinned( string $slug ): bool {
		return in_array( self::sanitize_tool_slug( $slug ), self::pins(), true );
	}

	/**
	 * @return array<string,int>
	 */
	public static function visits(): array {
		$state  = self::state();
		$visits = is_array( $state['visits'] ?? null ) ? $state['visits'] : array();
		$out    = array();
		foreach ( $visits as $slug => $ts ) {
			$slug = self::sanitize_tool_slug( (string) $slug );
			if ( '' !== $slug ) {
				$out[ $slug ] = (int) $ts;
			}
		}

		return $out;
	}

	public static function record_visit( string $slug ): void {
		$slug = self::sanitize_tool_slug( $slug );
		if ( '' === $slug ) {
			return;
		}
		$state           = self::state();
		$visits          = is_array( $state['visits'] ?? null ) ? $state['visits'] : array();
		$visits[ $slug ] = self::now();
		if ( count( $visits ) > self::VISIT_CAP ) {
			asort( $visits, SORT_NUMERIC );
			$visits = array_slice( $visits, -1 * self::VISIT_CAP, null, true );
		}
		$state['visits'] = $visits;
		self::save_state( $state );
	}

	/**
	 * @return array<string,string>
	 */
	public static function core_slugs(): array {
		if ( class_exists( Admin::class, false ) ) {
			$out = array();
			foreach ( Admin::SCREEN_SLUGS as $slug ) {
				$slug = self::sanitize_tool_slug( (string) $slug );
				if ( '' !== $slug ) {
					$out[ $slug ] = $slug;
				}
			}

			return $out;
		}

		return array(
			'handl-aicac'               => 'handl-aicac',
			'handl-aicac-rules'         => 'handl-aicac-rules',
			'handl-aicac-protections'   => 'handl-aicac-protections',
			'handl-aicac-activity'      => 'handl-aicac-activity',
			'handl-aicac-insights'      => 'handl-aicac-insights',
			'handl-aicac-policy-tools'  => 'handl-aicac-policy-tools',
			'handl-aicac-alerts'        => 'handl-aicac-alerts',
		);
	}

	public static function is_reserved_slug( string $slug ): bool {
		$slug = self::sanitize_tool_slug( $slug );
		if ( self::PAGE_SLUG === $slug ) {
			return true;
		}

		return isset( self::core_slugs()[ $slug ] );
	}

	/**
	 * @return array<string,string>
	 */
	public static function keep_slugs(): array {
		$keep = self::core_slugs();
		$keep[ self::PAGE_SLUG ] = self::PAGE_SLUG;
		if ( self::is_simple() ) {
			foreach ( self::pins() as $slug ) {
				$keep[ $slug ] = $slug;
			}
		}

		return $keep;
	}

	/**
	 * @param list<string> $registered
	 * @return list<string>
	 */
	public static function visible_menu_slugs( array $registered ): array {
		if ( ! self::is_simple() ) {
			return array_values( array_unique( array_map( array( self::class, 'sanitize_tool_slug' ), $registered ) ) );
		}
		$keep = self::keep_slugs();
		$out  = array();
		foreach ( $registered as $slug ) {
			$slug = self::sanitize_tool_slug( (string) $slug );
			if ( isset( $keep[ $slug ] ) ) {
				$out[] = $slug;
			}
		}

		return $out;
	}

	public static function register_menu(): void {
		if ( ! class_exists( Caps::class, false ) || ! Caps::user_can_view() ) {
			return;
		}
		if ( ! function_exists( 'add_submenu_page' ) || ! class_exists( Admin::class, false ) ) {
			return;
		}
		add_submenu_page(
			Admin::MENU_SLUG,
			__( 'More tools', 'handl-ai-connector-access-control' ),
			__( 'More tools', 'handl-ai-connector-access-control' ),
			Caps::VIEW,
			self::PAGE_SLUG,
			array( self::class, 'render_page' )
		);
	}

	public static function apply_simple_menu(): void {
		if ( ! self::is_simple() ) {
			return;
		}
		$parent = class_exists( Admin::class, false ) ? Admin::MENU_SLUG : 'handl-aicac';
		if ( ! isset( $GLOBALS['submenu'][ $parent ] ) || ! is_array( $GLOBALS['submenu'][ $parent ] ) ) {
			return;
		}
		$keep = self::keep_slugs();
		$kept = array();
		foreach ( $GLOBALS['submenu'][ $parent ] as $item ) {
			if ( ! is_array( $item ) ) {
				continue;
			}
			$slug = self::sanitize_tool_slug( (string) ( $item[2] ?? '' ) );
			if ( isset( $keep[ $slug ] ) ) {
				$kept[] = $item;
			}
		}
		$GLOBALS['submenu'][ $parent ] = $kept;
	}

	public static function maybe_handle_post(): void {
		if ( self::$posted ) {
			return;
		}
		$action = isset( $_POST['action'] ) ? sanitize_key( (string) wp_unslash( $_POST['action'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing
		if ( ! in_array( $action, array( self::ACTION_MODE, self::ACTION_PIN, self::ACTION_UNPIN ), true ) ) {
			return;
		}
		self::$posted = true;
		$nonce        = isset( $_POST['_wpnonce'] ) ? (string) wp_unslash( $_POST['_wpnonce'] ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing
		if ( '' === $nonce || ! function_exists( 'wp_verify_nonce' ) || ! wp_verify_nonce( $nonce, $action ) ) {
			return;
		}
		if ( ! class_exists( Caps::class, false ) || ! Caps::user_can_manage() ) {
			return;
		}
		if ( self::ACTION_MODE === $action ) {
			$mode = isset( $_POST['handl_aicac_ui_mode'] ) ? sanitize_key( (string) wp_unslash( $_POST['handl_aicac_ui_mode'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing
			self::set_mode( $mode );
			return;
		}
		$slug = isset( $_POST['handl_aicac_foyer_slug'] ) ? (string) wp_unslash( $_POST['handl_aicac_foyer_slug'] ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing
		if ( self::ACTION_PIN === $action ) {
			self::pin( $slug );
			return;
		}
		self::unpin( $slug );
	}

	public static function maybe_record_visit(): void {
		$page = isset( $_GET['page'] ) ? sanitize_key( (string) wp_unslash( $_GET['page'] ) ) : '';
		if ( 0 !== strpos( $page, 'handl-aicac' ) ) {
			return;
		}
		if ( ! class_exists( Caps::class, false ) || ! Caps::user_can_view() ) {
			return;
		}
		self::record_visit( $page );
	}

	public static function maybe_render_mode_toggle(): void {
		$page = isset( $_GET['page'] ) ? sanitize_key( (string) wp_unslash( $_GET['page'] ) ) : '';
		if ( 'handl-aicac-alerts' !== $page ) {
			return;
		}
		if ( ! class_exists( Caps::class, false ) || ! Caps::user_can_manage() ) {
			return;
		}
		self::render_mode_form();
	}

	public static function render_page(): void {
		if ( ! class_exists( Caps::class, false ) || ! Caps::user_can_view() ) {
			return;
		}
		$query = isset( $_GET[ self::SEARCH_ARG ] ) ? (string) wp_unslash( $_GET[ self::SEARCH_ARG ] ) : '';
		$query = function_exists( 'sanitize_text_field' ) ? sanitize_text_field( $query ) : trim( $query );
		$cards = self::cards( self::tool_items(), $query );

		echo '<div class="wrap handl-aicac-foyer">';
		echo '<h1>' . esc_html__( 'More tools', 'handl-ai-connector-access-control' ) . '</h1>';
		echo '<p class="description">' . esc_html__( 'Extra screens stay available here. Pin a tool to put it back in the menu.', 'handl-ai-connector-access-control' ) . '</p>';

		echo '<form method="get" action="' . esc_url( admin_url( 'admin.php' ) ) . '" class="handl-aicac-foyer-search">';
		echo '<input type="hidden" name="page" value="' . esc_attr( self::PAGE_SLUG ) . '" />';
		echo '<p><label for="handl-aicac-foyer-q">' . esc_html__( 'Search tools', 'handl-ai-connector-access-control' ) . '</label></p>';
		echo '<p><input type="search" id="handl-aicac-foyer-q" name="' . esc_attr( self::SEARCH_ARG ) . '" value="' . esc_attr( $query ) . '" class="regular-text" /></p>';
		if ( function_exists( 'submit_button' ) ) {
			submit_button( __( 'Search', 'handl-ai-connector-access-control' ), 'secondary', 'submit', false );
		} else {
			echo '<p><button type="submit" class="button">' . esc_html__( 'Search', 'handl-ai-connector-access-control' ) . '</button></p>';
		}
		echo '</form>';

		if ( array() === $cards ) {
			echo '<p>' . esc_html__( 'No tools match this search.', 'handl-ai-connector-access-control' ) . '</p>';
			echo '</div>';
			return;
		}

		$grouped = array();
		foreach ( $cards as $card ) {
			$grouped[ $card['group'] ][] = $card;
		}
		foreach ( self::group_labels() as $group => $label ) {
			if ( empty( $grouped[ $group ] ) ) {
				continue;
			}
			echo '<h2>' . esc_html( $label ) . '</h2>';
			echo '<div class="handl-aicac-foyer-cards">';
			foreach ( $grouped[ $group ] as $card ) {
				self::render_card( $card );
			}
			echo '</div>';
		}
		echo '</div>';
	}

	/**
	 * @param list<array{0:string,1:string,2:string,3?:string}> $items
	 * @return list<array{slug:string,title:string,description:string,group:string,url:string,pinned:bool,visited:int,haystack:string}>
	 */
	public static function cards( array $items, string $query = '' ): array {
		$visits = self::visits();
		$out    = array();
		foreach ( $items as $item ) {
			if ( ! is_array( $item ) ) {
				continue;
			}
			$slug = self::sanitize_tool_slug( (string) ( $item[2] ?? '' ) );
			if ( '' === $slug || self::is_reserved_slug( $slug ) ) {
				continue;
			}
			$title = trim( (string) ( $item[0] ?? '' ) );
			if ( '' === $title ) {
				$title = trim( (string) ( $item[3] ?? $slug ) );
			}
			$meta        = self::catalog_entry( $slug );
			$description = $meta['description'];
			if ( '' === $description ) {
				$description = $title;
			}
			$haystack = strtolower( trim( $title . ' ' . $description . ' ' . $meta['group'] . ' ' . $slug ) );
			if ( class_exists( Settings_Search::class, false ) && method_exists( Settings_Search::class, 'registered' ) ) {
				foreach ( Settings_Search::registered() as $entry ) {
					if ( ! is_array( $entry ) ) {
						continue;
					}
					$label = strtolower( (string) ( $entry['label'] ?? '' ) );
					if ( '' !== $label && false !== strpos( $haystack, $label ) ) {
						$haystack .= ' ' . implode( ' ', is_array( $entry['keywords'] ?? null ) ? $entry['keywords'] : array() );
					}
				}
			}
			$out[] = array(
				'slug'        => $slug,
				'title'       => $title,
				'description' => $description,
				'group'       => $meta['group'],
				'url'         => admin_url( 'admin.php?page=' . $slug ),
				'pinned'      => self::is_pinned( $slug ),
				'visited'     => (int) ( $visits[ $slug ] ?? 0 ),
				'haystack'    => preg_replace( '/\s+/', ' ', $haystack ),
			);
		}

		$q = strtolower( trim( $query ) );
		if ( '' !== $q ) {
			$out = array_values(
				array_filter(
					$out,
					static function ( array $card ) use ( $q ) {
						return false !== strpos( (string) $card['haystack'], $q );
					}
				)
			);
		}

		usort(
			$out,
			static function ( array $a, array $b ) {
				$ga = array_search( $a['group'], array_keys( self::group_labels() ), true );
				$gb = array_search( $b['group'], array_keys( self::group_labels() ), true );
				$ga = false === $ga ? 99 : $ga;
				$gb = false === $gb ? 99 : $gb;
				if ( $ga !== $gb ) {
					return $ga <=> $gb;
				}
				if ( (int) $a['visited'] !== (int) $b['visited'] ) {
					return (int) $b['visited'] <=> (int) $a['visited'];
				}

				return strcasecmp( (string) $a['title'], (string) $b['title'] );
			}
		);

		return $out;
	}

	/**
	 * @return array<string,string>
	 */
	public static function group_labels(): array {
		return array(
			self::GROUP_COST         => __( 'Cost', 'handl-ai-connector-access-control' ),
			self::GROUP_PRIVACY      => __( 'Privacy & exposure', 'handl-ai-connector-access-control' ),
			self::GROUP_RELIABILITY  => __( 'Reliability', 'handl-ai-connector-access-control' ),
			self::GROUP_COMPLIANCE   => __( 'Compliance', 'handl-ai-connector-access-control' ),
			self::GROUP_HYGIENE      => __( 'Hygiene', 'handl-ai-connector-access-control' ),
		);
	}

	private static function render_mode_form(): void {
		$mode = self::mode();
		echo '<div class="notice notice-info handl-aicac-foyer-mode" style="padding:12px 16px;">';
		echo '<form method="post" action="">';
		echo '<input type="hidden" name="action" value="' . esc_attr( self::ACTION_MODE ) . '" />';
		if ( function_exists( 'wp_nonce_field' ) ) {
			wp_nonce_field( self::ACTION_MODE );
		}
		echo '<p>' . esc_html__( 'Simple mode keeps the seven main screens in the menu and moves extra tools to More tools.', 'handl-ai-connector-access-control' ) . '</p>';
		echo '<p><label for="handl-aicac-ui-mode">' . esc_html__( 'Menu mode', 'handl-ai-connector-access-control' ) . '</label> ';
		echo '<select id="handl-aicac-ui-mode" name="handl_aicac_ui_mode">';
		echo '<option value="' . esc_attr( self::MODE_SIMPLE ) . '"' . ( self::MODE_SIMPLE === $mode ? ' selected="selected"' : '' ) . '>' . esc_html__( 'Simple', 'handl-ai-connector-access-control' ) . '</option>';
		echo '<option value="' . esc_attr( self::MODE_FULL ) . '"' . ( self::MODE_FULL === $mode ? ' selected="selected"' : '' ) . '>' . esc_html__( 'Full menu', 'handl-ai-connector-access-control' ) . '</option>';
		echo '</select> ';
		if ( function_exists( 'submit_button' ) ) {
			submit_button( __( 'Save menu mode', 'handl-ai-connector-access-control' ), 'secondary', 'submit', false );
		} else {
			echo '<button type="submit" class="button">' . esc_html__( 'Save menu mode', 'handl-ai-connector-access-control' ) . '</button>';
		}
		echo '</p></form></div>';
	}

	/**
	 * @param array{slug:string,title:string,description:string,url:string,pinned:bool} $card
	 */
	private static function render_card( array $card ): void {
		echo '<div class="handl-aicac-foyer-card" style="max-width:52em;margin:0 0 1em;padding:12px 16px;border:1px solid #c3c4c7;background:#fff;">';
		echo '<h3 style="margin:0 0 0.35em;"><a href="' . esc_url( (string) $card['url'] ) . '">' . esc_html( (string) $card['title'] ) . '</a></h3>';
		echo '<p class="description" style="margin:0 0 0.75em;">' . esc_html( (string) $card['description'] ) . '</p>';
		if ( ! empty( $card['pinned'] ) ) {
			echo '<p><span class="dashicons dashicons-star-filled" aria-hidden="true"></span> ' . esc_html__( 'Pinned', 'handl-ai-connector-access-control' ) . '</p>';
		}
		if ( class_exists( Caps::class, false ) && Caps::user_can_manage() ) {
			$action = ! empty( $card['pinned'] ) ? self::ACTION_UNPIN : self::ACTION_PIN;
			$label  = ! empty( $card['pinned'] )
				? __( 'Unpin', 'handl-ai-connector-access-control' )
				: __( 'Pin to menu', 'handl-ai-connector-access-control' );
			echo '<form method="post" action="" style="display:inline;">';
			echo '<input type="hidden" name="action" value="' . esc_attr( $action ) . '" />';
			echo '<input type="hidden" name="handl_aicac_foyer_slug" value="' . esc_attr( (string) $card['slug'] ) . '" />';
			if ( function_exists( 'wp_nonce_field' ) ) {
				wp_nonce_field( $action );
			}
			echo '<button type="submit" class="button">' . esc_html( $label ) . '</button>';
			echo '</form>';
		}
		echo '</div>';
	}

	/**
	 * Full registered submenu captured before Simple mode hides entries.
	 *
	 * @return list<array{0:string,1:string,2:string,3?:string}>
	 */
	private static function tool_items(): array {
		if ( null !== self::$catalog_items ) {
			return self::$catalog_items;
		}

		return self::submenu_items_from_global();
	}

	/**
	 * @return list<array{0:string,1:string,2:string,3?:string}>
	 */
	private static function submenu_items_from_global(): array {
		$parent = class_exists( Admin::class, false ) ? Admin::MENU_SLUG : 'handl-aicac';
		$rows   = $GLOBALS['submenu'][ $parent ] ?? array();

		return is_array( $rows ) ? $rows : array();
	}

	/**
	 * @return array{group:string,description:string}
	 */
	private static function catalog_entry( string $slug ): array {
		$map = self::catalog();
		if ( isset( $map[ $slug ] ) ) {
			return $map[ $slug ];
		}

		return array(
			'group'       => self::GROUP_HYGIENE,
			'description' => '',
		);
	}

	/**
	 * @return array<string,array{group:string,description:string}>
	 */
	private static function catalog(): array {
		$cost        = self::GROUP_COST;
		$privacy     = self::GROUP_PRIVACY;
		$reliability = self::GROUP_RELIABILITY;
		$compliance  = self::GROUP_COMPLIANCE;
		$hygiene     = self::GROUP_HYGIENE;

		return array(
			'handl-aicac-chargeback'     => array( 'group' => $cost, 'description' => __( 'A statement of recorded AI spend.', 'handl-ai-connector-access-control' ) ),
			'handl-aicac-carbon'         => array( 'group' => $cost, 'description' => __( 'Estimated energy use for recorded AI calls.', 'handl-ai-connector-access-control' ) ),
			'handl-aicac-volume'         => array( 'group' => $cost, 'description' => __( 'How much AI this site is using.', 'handl-ai-connector-access-control' ) ),
			'handl-aicac-dividend'       => array( 'group' => $cost, 'description' => __( 'Human visits attributed to AI referrals.', 'handl-ai-connector-access-control' ) ),
			'handl-aicac-rate-shock'     => array( 'group' => $cost, 'description' => __( 'Alerts when provider rates change.', 'handl-ai-connector-access-control' ) ),
			'handl-aicac-concentration'  => array( 'group' => $cost, 'description' => __( 'Whether spend is concentrated on a few plugins.', 'handl-ai-connector-access-control' ) ),
			'handl-aicac-reconcile'      => array( 'group' => $cost, 'description' => __( 'Match invoices to recorded usage.', 'handl-ai-connector-access-control' ) ),
			'handl-aicac-neighbors'      => array( 'group' => $cost, 'description' => __( 'Compare recorded usage to example ranges.', 'handl-ai-connector-access-control' ) ),
			'handl-aicac-taint'          => array( 'group' => $privacy, 'description' => __( 'Screen prompts for possible injection patterns.', 'handl-ai-connector-access-control' ) ),
			'handl-aicac-lookback'       => array( 'group' => $privacy, 'description' => __( 'Review saved Activity for one provider and window.', 'handl-ai-connector-access-control' ) ),
			'handl-aicac-luggage'        => array( 'group' => $privacy, 'description' => __( 'Recorded outbound media in AI requests.', 'handl-ai-connector-access-control' ) ),
			'handl-aicac-train-exposure' => array( 'group' => $privacy, 'description' => __( 'Where recorded content may be used for training.', 'handl-ai-connector-access-control' ) ),
			'handl-aicac-footprint'      => array( 'group' => $privacy, 'description' => __( 'Where AI shows up across this site.', 'handl-ai-connector-access-control' ) ),
			'handl-aicac-touched'        => array( 'group' => $privacy, 'description' => __( 'Content that AI has already touched.', 'handl-ai-connector-access-control' ) ),
			'handl-aicac-roommates'      => array( 'group' => $privacy, 'description' => __( 'Plugins that appear to share an API key.', 'handl-ai-connector-access-control' ) ),
			'handl-aicac-key-age'        => array( 'group' => $privacy, 'description' => __( 'How old stored AI keys look.', 'handl-ai-connector-access-control' ) ),
			'handl-aicac-key-custody'    => array( 'group' => $privacy, 'description' => __( 'Who holds stored AI keys.', 'handl-ai-connector-access-control' ) ),
			'handl-aicac-visitor'        => array( 'group' => $privacy, 'description' => __( 'Caps for visitor-facing AI.', 'handl-ai-connector-access-control' ) ),
			'handl-aicac-postcard'       => array( 'group' => $privacy, 'description' => __( 'A shareable snapshot of AI use.', 'handl-ai-connector-access-control' ) ),
			'handl-aicac-embargo'        => array( 'group' => $privacy, 'description' => __( 'Hold AI content before it publishes.', 'handl-ai-connector-access-control' ) ),
			'handl-aicac-legal-hold'     => array( 'group' => $compliance, 'description' => __( 'Keep Activity when a legal hold is on.', 'handl-ai-connector-access-control' ) ),
			'handl-aicac-waiting-room'   => array( 'group' => $reliability, 'description' => __( 'Queue and delay for busy AI providers.', 'handl-ai-connector-access-control' ) ),
			'handl-aicac-sleepwalker'    => array( 'group' => $reliability, 'description' => __( 'AI calls that run with nobody at the keyboard.', 'handl-ai-connector-access-control' ) ),
			'handl-aicac-witness'        => array( 'group' => $reliability, 'description' => __( 'Gaps in the Activity log.', 'handl-ai-connector-access-control' ) ),
			'handl-aicac-cron-pulse'     => array( 'group' => $reliability, 'description' => __( 'Whether scheduled AI jobs are still firing.', 'handl-ai-connector-access-control' ) ),
			'handl-aicac-sundial'        => array( 'group' => $reliability, 'description' => __( 'Clock skew that can throw off schedules.', 'handl-ai-connector-access-control' ) ),
			'handl-aicac-unattended'     => array( 'group' => $reliability, 'description' => __( 'Warn when no admin has signed in for a while.', 'handl-ai-connector-access-control' ) ),
			'handl-aicac-noise'          => array( 'group' => $reliability, 'description' => __( 'Alert volume that has turned into wallpaper.', 'handl-ai-connector-access-control' ) ),
			'handl-aicac-handshake'      => array( 'group' => $reliability, 'description' => __( 'TLS and transport hygiene for AI endpoints.', 'handl-ai-connector-access-control' ) ),
			'handl-aicac-wallflower'     => array( 'group' => $reliability, 'description' => __( 'Allowed plugins that never actually call AI.', 'handl-ai-connector-access-control' ) ),
			'handl-aicac-chatterbox'     => array( 'group' => $reliability, 'description' => __( 'Plugins that talk more than the rest.', 'handl-ai-connector-access-control' ) ),
			'handl-aicac-rush-hour'      => array( 'group' => $reliability, 'description' => __( 'When this site’s AI calls usually happen.', 'handl-ai-connector-access-control' ) ),
			'handl-aicac-weather'        => array( 'group' => $reliability, 'description' => __( 'Provider weather for recorded calls.', 'handl-ai-connector-access-control' ) ),
			'handl-aicac-manners'        => array( 'group' => $reliability, 'description' => __( 'How often plugins retry after a deny.', 'handl-ai-connector-access-control' ) ),
			'handl-aicac-welcome-back'   => array( 'group' => $reliability, 'description' => __( 'What changed while you were away.', 'handl-ai-connector-access-control' ) ),
			'handl-aicac-drill'          => array( 'group' => $reliability, 'description' => __( 'Practice an incident without changing policy.', 'handl-ai-connector-access-control' ) ),
			'handl-aicac-rollback'       => array( 'group' => $reliability, 'description' => __( 'Detect a plugin version rollback.', 'handl-ai-connector-access-control' ) ),
			'handl-aicac-spot-check'     => array( 'group' => $reliability, 'description' => __( 'Sample live calls for a human look.', 'handl-ai-connector-access-control' ) ),
			'handl-aicac-crosscheck'     => array( 'group' => $reliability, 'description' => __( 'Settings that disagree with each other.', 'handl-ai-connector-access-control' ) ),
			'handl-aicac-doppelganger'   => array( 'group' => $reliability, 'description' => __( 'Two plugins that look like the same AI path.', 'handl-ai-connector-access-control' ) ),
			'handl-aicac-gatekeeper'     => array( 'group' => $reliability, 'description' => __( 'Who is allowed to change AI access.', 'handl-ai-connector-access-control' ) ),
			'handl-aicac-deputy'         => array( 'group' => $reliability, 'description' => __( 'A backup approver when access requests sit.', 'handl-ai-connector-access-control' ) ),
			'handl-aicac-deny-receipt'   => array( 'group' => $reliability, 'description' => __( 'A receipt for a denied AI call.', 'handl-ai-connector-access-control' ) ),
			'handl-aicac-understudy'     => array( 'group' => $reliability, 'description' => __( 'Sample a cheaper model beside the live one.', 'handl-ai-connector-access-control' ) ),
			'handl-aicac-limbo'          => array( 'group' => $reliability, 'description' => __( 'Requests that never reached a decision.', 'handl-ai-connector-access-control' ) ),
			'handl-aicac-friction'       => array( 'group' => $reliability, 'description' => __( 'How often people retry after a deny.', 'handl-ai-connector-access-control' ) ),
			'handl-aicac-coach'          => array( 'group' => $reliability, 'description' => __( 'Coaching prompts for plugin authors.', 'handl-ai-connector-access-control' ) ),
			'handl-aicac-model-eol'      => array( 'group' => $reliability, 'description' => __( 'Models that are near retirement.', 'handl-ai-connector-access-control' ) ),
			'handl-aicac-env-policy'     => array( 'group' => $reliability, 'description' => __( 'Policy that follows the environment.', 'handl-ai-connector-access-control' ) ),
			'handl-aicac-ai-act'         => array( 'group' => $compliance, 'description' => __( 'EU AI Act readiness notes for this site.', 'handl-ai-connector-access-control' ) ),
			'handl-aicac-aup'            => array( 'group' => $compliance, 'description' => __( 'Acceptable-use text for AI features.', 'handl-ai-connector-access-control' ) ),
			'handl-aicac-register'       => array( 'group' => $compliance, 'description' => __( 'A register of AI processors this site uses.', 'handl-ai-connector-access-control' ) ),
			'handl-aicac-recert'         => array( 'group' => $compliance, 'description' => __( 'Re-approve who may use AI.', 'handl-ai-connector-access-control' ) ),
			'handl-aicac-chameleon'      => array( 'group' => $compliance, 'description' => __( 'Review access after a role change.', 'handl-ai-connector-access-control' ) ),
			'handl-aicac-fineprint'      => array( 'group' => $compliance, 'description' => __( 'Provider terms that affect this site.', 'handl-ai-connector-access-control' ) ),
			'handl-aicac-dossier'        => array( 'group' => $compliance, 'description' => __( 'One file of a user’s AI activity.', 'handl-ai-connector-access-control' ) ),
			'handl-aicac-botwatch'       => array( 'group' => $compliance, 'description' => __( 'Bots and crawlers hitting AI endpoints.', 'handl-ai-connector-access-control' ) ),
			'handl-aicac-coldcase'       => array( 'group' => $hygiene, 'description' => __( 'Old Activity that never got a follow-up.', 'handl-ai-connector-access-control' ) ),
			'handl-aicac-dejavu'         => array( 'group' => $hygiene, 'description' => __( 'The same AI ask, again.', 'handl-ai-connector-access-control' ) ),
			'handl-aicac-stowaway'       => array( 'group' => $hygiene, 'description' => __( 'Data left behind by a removed plugin.', 'handl-ai-connector-access-control' ) ),
			'handl-aicac-relic'          => array( 'group' => $hygiene, 'description' => __( 'Legacy AI content still sitting on the site.', 'handl-ai-connector-access-control' ) ),
			'handl-aicac-tombstone'      => array( 'group' => $hygiene, 'description' => __( 'Plugins that used to call AI and are gone.', 'handl-ai-connector-access-control' ) ),
			'handl-aicac-snowflake'      => array( 'group' => $hygiene, 'description' => __( 'One-off plugins that do not match the rest.', 'handl-ai-connector-access-control' ) ),
			'handl-aicac-succession'     => array( 'group' => $hygiene, 'description' => __( 'Who gets alerts if the usual admin is gone.', 'handl-ai-connector-access-control' ) ),
		);
	}

	/**
	 * @return array{pins:list<string>,visits:array<string,int>}
	 */
	private static function state(): array {
		$raw = get_option( self::STATE_OPTION, array() );
		if ( ! is_array( $raw ) ) {
			$raw = array();
		}
		$pins = array();
		foreach ( (array) ( $raw['pins'] ?? array() ) as $slug ) {
			$slug = self::sanitize_tool_slug( (string) $slug );
			if ( '' !== $slug ) {
				$pins[] = $slug;
			}
		}
		$visits = array();
		foreach ( (array) ( $raw['visits'] ?? array() ) as $slug => $ts ) {
			$slug = self::sanitize_tool_slug( (string) $slug );
			if ( '' !== $slug ) {
				$visits[ $slug ] = (int) $ts;
			}
		}

		return array(
			'pins'   => array_values( array_unique( $pins ) ),
			'visits' => $visits,
		);
	}

	/**
	 * @param array{pins?:list<string>,visits?:array<string,int>} $state
	 */
	private static function save_state( array $state ): void {
		update_option(
			self::STATE_OPTION,
			array(
				'pins'   => array_values( array_unique( array_map( 'strval', (array) ( $state['pins'] ?? array() ) ) ) ),
				'visits' => is_array( $state['visits'] ?? null ) ? $state['visits'] : array(),
			),
			false
		);
	}

	private static function sanitize_tool_slug( string $slug ): string {
		$slug = sanitize_key( $slug );
		if ( '' === $slug ) {
			return '';
		}
		if ( 0 !== strpos( $slug, 'handl-aicac' ) ) {
			return '';
		}

		return $slug;
	}
}
