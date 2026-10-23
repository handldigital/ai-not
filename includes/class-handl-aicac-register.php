<?php
/**
 * AICAC-REGISTER (#375): AI processor register for compliance (GDPR Art. 30-shaped).
 *
 * Auto-populated per-provider rows from the activity log + Provider_Map / Keyscan
 * public surfaces. Admin-maintained DPA/review fields in own option. Print + CSV
 * + WP-CLI. Staleness nudge on this screen only. Prohibited status is
 * informational in v1 — this class stays read-only against the gate.
 * OFF by default. No admin.php/policy.php/cost.php/logger edits.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * AI processor / vendor register.
 */
final class Register {

	public const SETTINGS_OPTION = 'handl_aicac_register';

	public const FIELDS_OPTION = 'handl_aicac_register_fields';

	public const PAGE_SLUG = 'handl-aicac-register';

	public const STATUS_APPROVED = 'approved';

	public const STATUS_UNDER_REVIEW = 'under_review';

	public const STATUS_PROHIBITED = 'prohibited';

	public const POST_PRESENT = 'handl_aicac_register_present';

	public const POST_ENABLED = 'handl_aicac_register_enabled';

	public const POST_FIELDS = 'handl_aicac_register_fields';

	public const ACTION_SAVE = 'handl_aicac_register_save';

	/** @var bool */
	private static $registered = false;

	public static function init(): void {
		if ( self::$registered ) {
			return;
		}
		self::$registered = true;

		add_action( 'admin_menu', array( self::class, 'register_menu' ), 20 );
		add_action( 'admin_init', array( self::class, 'maybe_handle_csv' ), 5 );
		add_action( 'admin_init', array( self::class, 'maybe_handle_print' ), 5 );
		add_action( 'admin_post_' . self::ACTION_SAVE, array( self::class, 'handle_save' ) );
		if ( function_exists( 'is_admin' ) && is_admin() ) {
			add_action( 'admin_notices', array( self::class, 'maybe_staleness_notice' ) );
		}
		self::register_cli();
	}

	public static function reset_for_tests(): void {
		self::$registered = false;
		delete_option( self::SETTINGS_OPTION );
		delete_option( self::FIELDS_OPTION );
	}

	/**
	 * @return array{enabled:bool}
	 */
	public static function defaults(): array {
		return array(
			'enabled' => false,
		);
	}

	/**
	 * @return array{enabled:bool}
	 */
	public static function get_settings(): array {
		return self::sanitize_settings( get_option( self::SETTINGS_OPTION, array() ) );
	}

	/**
	 * @param mixed $raw Raw settings.
	 * @return array{enabled:bool}
	 */
	public static function sanitize_settings( $raw ): array {
		$defaults = self::defaults();
		if ( ! is_array( $raw ) ) {
			return $defaults;
		}

		return array(
			'enabled' => ! empty( $raw['enabled'] ),
		);
	}

	/**
	 * @param array<string,mixed> $settings Settings.
	 */
	public static function save_settings( array $settings ): bool {
		$clean  = self::sanitize_settings( $settings );
		$before = self::get_settings();
		if ( $clean === $before ) {
			return false;
		}
		if ( $clean === self::defaults() ) {
			delete_option( self::SETTINGS_OPTION );

			return true;
		}
		update_option( self::SETTINGS_OPTION, $clean, false );

		return true;
	}

	public static function is_enabled(): bool {
		$settings = self::get_settings();

		return ! empty( $settings['enabled'] );
	}

	/**
	 * @return array{dpa_on_file:bool,dpa_date:string,dpa_url:string,purpose:string,residency:string,contact:string,review_date:string,status:string}
	 */
	public static function field_defaults(): array {
		return array(
			'dpa_on_file' => false,
			'dpa_date'    => '',
			'dpa_url'     => '',
			'purpose'     => '',
			'residency'   => '',
			'contact'     => '',
			'review_date' => '',
			'status'      => '',
		);
	}

	/**
	 * @return array<string,array{dpa_on_file:bool,dpa_date:string,dpa_url:string,purpose:string,residency:string,contact:string,review_date:string,status:string}>
	 */
	public static function get_fields(): array {
		return self::sanitize_fields( get_option( self::FIELDS_OPTION, array() ) );
	}

	/**
	 * @param mixed $raw Raw fields map.
	 * @return array<string,array{dpa_on_file:bool,dpa_date:string,dpa_url:string,purpose:string,residency:string,contact:string,review_date:string,status:string}>
	 */
	public static function sanitize_fields( $raw ): array {
		if ( ! is_array( $raw ) ) {
			return array();
		}
		$out = array();
		foreach ( $raw as $provider => $row ) {
			$id = Cost::normalize_provider_id( (string) $provider );
			if ( '' === $id || ! is_array( $row ) ) {
				continue;
			}
			$out[ $id ] = self::sanitize_field_row( $row );
		}
		ksort( $out );

		return $out;
	}

	/**
	 * @param array<string,mixed> $row Raw field row.
	 * @return array{dpa_on_file:bool,dpa_date:string,dpa_url:string,purpose:string,residency:string,contact:string,review_date:string,status:string}
	 */
	public static function sanitize_field_row( array $row ): array {
		$defaults = self::field_defaults();

		return array(
			'dpa_on_file' => ! empty( $row['dpa_on_file'] ),
			'dpa_date'    => self::sanitize_date( (string) ( $row['dpa_date'] ?? '' ) ),
			'dpa_url'     => self::sanitize_url( (string) ( $row['dpa_url'] ?? '' ) ),
			'purpose'     => self::sanitize_note( (string) ( $row['purpose'] ?? '' ) ),
			'residency'   => self::sanitize_note( (string) ( $row['residency'] ?? '' ) ),
			'contact'     => self::sanitize_note( (string) ( $row['contact'] ?? '' ), 500 ),
			'review_date' => self::sanitize_date( (string) ( $row['review_date'] ?? '' ) ),
			'status'      => self::sanitize_status( (string) ( $row['status'] ?? '' ) ),
		);
	}

	/**
	 * @param array<string,array<string,mixed>> $fields Fields map.
	 */
	public static function save_fields( array $fields ): bool {
		$clean  = self::sanitize_fields( $fields );
		$before = self::get_fields();
		if ( $clean === $before ) {
			return false;
		}
		if ( array() === $clean ) {
			delete_option( self::FIELDS_OPTION );

			return true;
		}
		update_option( self::FIELDS_OPTION, $clean, false );

		return true;
	}

	public static function sanitize_status( string $status ): string {
		$status = sanitize_key( $status );
		$allowed = array(
			self::STATUS_APPROVED,
			self::STATUS_UNDER_REVIEW,
			self::STATUS_PROHIBITED,
		);

		return in_array( $status, $allowed, true ) ? $status : '';
	}

	public static function sanitize_date( string $date ): string {
		$date = trim( $date );
		if ( '' === $date ) {
			return '';
		}
		if ( ! preg_match( '/^\d{4}-\d{2}-\d{2}$/', $date ) ) {
			return '';
		}
		$parts = explode( '-', $date );
		if ( 3 !== count( $parts ) ) {
			return '';
		}
		$y = (int) $parts[0];
		$m = (int) $parts[1];
		$d = (int) $parts[2];
		if ( $y < 1970 || $y > 2100 || ! checkdate( $m, $d, $y ) ) {
			return '';
		}

		return sprintf( '%04d-%02d-%02d', $y, $m, $d );
	}

	public static function sanitize_url( string $url ): string {
		$url = trim( $url );
		if ( '' === $url ) {
			return '';
		}
		if ( function_exists( 'esc_url_raw' ) ) {
			$url = (string) esc_url_raw( $url );
		}
		if ( strlen( $url ) > 2000 ) {
			$url = substr( $url, 0, 2000 );
		}

		return $url;
	}

	public static function sanitize_note( string $note, int $max = 2000 ): string {
		$note = trim( $note );
		if ( function_exists( 'sanitize_text_field' ) ) {
			$note = sanitize_text_field( $note );
		} else {
			$note = strip_tags( $note );
		}
		if ( strlen( $note ) > $max ) {
			$note = substr( $note, 0, $max );
		}

		return $note;
	}

	/**
	 * @return list<string>
	 */
	public static function status_choices(): array {
		return array(
			'',
			self::STATUS_APPROVED,
			self::STATUS_UNDER_REVIEW,
			self::STATUS_PROHIBITED,
		);
	}

	public static function status_label( string $status ): string {
		switch ( $status ) {
			case self::STATUS_APPROVED:
				return __( 'Approved', 'handl-ai-connector-access-control' );
			case self::STATUS_UNDER_REVIEW:
				return __( 'Under review', 'handl-ai-connector-access-control' );
			case self::STATUS_PROHIBITED:
				return __( 'Prohibited (informational)', 'handl-ai-connector-access-control' );
			default:
				return __( 'Unset', 'handl-ai-connector-access-control' );
		}
	}

	/**
	 * Build auto stats from retained activity log (+ optional Keyscan inventory).
	 *
	 * @param list<array<string,mixed>>|null $log  Optional log override.
	 * @param int|null                       $now  Clock override.
	 * @return array<string,array{
	 *   provider:string,
	 *   label:string,
	 *   first_seen:int,
	 *   last_seen:int,
	 *   calls:int,
	 *   denies:int,
	 *   plugins:list<string>,
	 *   families:list<string>,
	 *   pii_flagged:bool,
	 *   pii_types:list<string>,
	 *   sources:list<string>
	 * }>
	 */
	public static function compute_provider_stats( ?array $log = null, ?int $now = null ): array {
		unset( $now );
		if ( null === $log ) {
			$log = Policy::get_retained_log();
		}
		if ( class_exists( Demo_Mode::class, false ) ) {
			$log = Demo_Mode::without_demo( $log );
		}

		$stats = array();
		foreach ( $log as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			if ( class_exists( Selftest::class, false ) && Selftest::is_synthetic_row( $row ) ) {
				continue;
			}
			if ( class_exists( Usage_Trends::class, false ) && ! Usage_Trends::is_activity_row( $row ) ) {
				continue;
			}
			$provider = Cost::normalize_provider_id( (string) ( $row['provider'] ?? '' ) );
			if ( '' === $provider ) {
				continue;
			}
			if ( ! isset( $stats[ $provider ] ) ) {
				$stats[ $provider ] = self::empty_stat( $provider );
			}
			$ts    = isset( $row['ts'] ) ? (int) $row['ts'] : 0;
			$count = isset( $row['count'] ) ? max( 1, (int) $row['count'] ) : 1;
			if ( $ts > 0 ) {
				if ( 0 === $stats[ $provider ]['first_seen'] || $ts < $stats[ $provider ]['first_seen'] ) {
					$stats[ $provider ]['first_seen'] = $ts;
				}
				if ( $ts > $stats[ $provider ]['last_seen'] ) {
					$stats[ $provider ]['last_seen'] = $ts;
				}
			}
			$decision = (string) ( $row['decision'] ?? '' );
			if ( 'deny' === $decision ) {
				$stats[ $provider ]['denies'] += $count;
			} else {
				$stats[ $provider ]['calls'] += $count;
			}

			$plugin = isset( $row['plugin'] ) ? (string) $row['plugin'] : '';
			if ( '' !== $plugin ) {
				$stats[ $provider ]['plugins'][ $plugin ] = true;
			}

			$family = isset( $row['capability_family'] ) ? (string) $row['capability_family'] : '';
			$op     = isset( $row['operation'] ) ? (string) $row['operation'] : '';
			if ( '' === $family && '' !== $op && class_exists( Operations::class, false ) ) {
				$family = Operations::family_from_operation( $op );
			}
			if ( '' !== $family ) {
				$stats[ $provider ]['families'][ $family ] = true;
			}

			if ( isset( $row['pii_match'] ) && is_array( $row['pii_match'] ) ) {
				$stats[ $provider ]['pii_flagged'] = true;
				$types = isset( $row['pii_match']['types'] ) && is_array( $row['pii_match']['types'] )
					? $row['pii_match']['types']
					: array();
				foreach ( $types as $type => $n ) {
					$type_key = is_string( $type ) ? sanitize_key( $type ) : sanitize_key( (string) $n );
					if ( '' !== $type_key ) {
						$stats[ $provider ]['pii_types'][ $type_key ] = true;
					}
				}
			} elseif ( isset( $row['denial_reason'] ) && 'pii' === (string) $row['denial_reason'] ) {
				$stats[ $provider ]['pii_flagged'] = true;
			}

			$stats[ $provider ]['sources']['log'] = true;
		}

		if ( class_exists( Keyscan::class, false ) ) {
			foreach ( Keyscan::active_findings() as $finding ) {
				if ( ! is_array( $finding ) ) {
					continue;
				}
				$provider = Cost::normalize_provider_id( (string) ( $finding['provider'] ?? '' ) );
				if ( '' === $provider ) {
					continue;
				}
				if ( ! isset( $stats[ $provider ] ) ) {
					$stats[ $provider ] = self::empty_stat( $provider );
				}
				$first = isset( $finding['first_seen'] ) ? (int) $finding['first_seen'] : 0;
				$last  = isset( $finding['last_seen'] ) ? (int) $finding['last_seen'] : 0;
				if ( $first > 0 && ( 0 === $stats[ $provider ]['first_seen'] || $first < $stats[ $provider ]['first_seen'] ) ) {
					$stats[ $provider ]['first_seen'] = $first;
				}
				if ( $last > $stats[ $provider ]['last_seen'] ) {
					$stats[ $provider ]['last_seen'] = $last;
				}
				$plugin = isset( $finding['plugin'] ) ? (string) $finding['plugin'] : '';
				if ( '' !== $plugin ) {
					$stats[ $provider ]['plugins'][ $plugin ] = true;
				}
				$stats[ $provider ]['sources']['keyscan'] = true;
			}
		}

		$out = array();
		foreach ( $stats as $provider => $stat ) {
			$plugins = array_keys( $stat['plugins'] );
			sort( $plugins );
			$families = array_keys( $stat['families'] );
			sort( $families );
			$pii_types = array_keys( $stat['pii_types'] );
			sort( $pii_types );
			$sources = array_keys( $stat['sources'] );
			sort( $sources );
			$out[ $provider ] = array(
				'provider'   => $provider,
				'label'      => self::provider_label( $provider ),
				'first_seen' => (int) $stat['first_seen'],
				'last_seen'  => (int) $stat['last_seen'],
				'calls'      => (int) $stat['calls'],
				'denies'     => (int) $stat['denies'],
				'plugins'    => $plugins,
				'families'   => $families,
				'pii_flagged'=> ! empty( $stat['pii_flagged'] ),
				'pii_types'  => $pii_types,
				'sources'    => $sources,
			);
		}
		ksort( $out );

		return $out;
	}

	/**
	 * @return array{
	 *   provider:string,
	 *   label:string,
	 *   first_seen:int,
	 *   last_seen:int,
	 *   calls:int,
	 *   denies:int,
	 *   plugins:array<string,bool>,
	 *   families:array<string,bool>,
	 *   pii_flagged:bool,
	 *   pii_types:array<string,bool>,
	 *   sources:array<string,bool>
	 * }
	 */
	private static function empty_stat( string $provider ): array {
		return array(
			'provider'    => $provider,
			'label'       => self::provider_label( $provider ),
			'first_seen'  => 0,
			'last_seen'   => 0,
			'calls'       => 0,
			'denies'      => 0,
			'plugins'     => array(),
			'families'    => array(),
			'pii_flagged' => false,
			'pii_types'   => array(),
			'sources'     => array(),
		);
	}

	public static function provider_label( string $provider ): string {
		$provider = Cost::normalize_provider_id( $provider );
		if ( '' === $provider ) {
			return '';
		}
		if ( class_exists( Provider_Map::class, false ) ) {
			return Provider_Map::signature_label( $provider );
		}

		return $provider;
	}

	/**
	 * Merged register rows (auto stats + admin fields). Includes providers that
	 * only have admin fields (no traffic yet).
	 *
	 * @param list<array<string,mixed>>|null $log Optional log override.
	 * @param int|null                       $now Clock override.
	 * @return list<array<string,mixed>>
	 */
	public static function build_rows( ?array $log = null, ?int $now = null ): array {
		$stats  = self::compute_provider_stats( $log, $now );
		$fields = self::get_fields();
		$ids    = array_unique( array_merge( array_keys( $stats ), array_keys( $fields ) ) );
		sort( $ids );

		$rows = array();
		foreach ( $ids as $provider ) {
			$stat  = $stats[ $provider ] ?? self::empty_stat_public( $provider );
			$field = $fields[ $provider ] ?? self::field_defaults();
			$rows[] = array_merge(
				$stat,
				array(
					'dpa_on_file' => ! empty( $field['dpa_on_file'] ),
					'dpa_date'    => (string) $field['dpa_date'],
					'dpa_url'     => (string) $field['dpa_url'],
					'purpose'     => (string) $field['purpose'],
					'residency'   => (string) $field['residency'],
					'contact'     => (string) $field['contact'],
					'review_date' => (string) $field['review_date'],
					'status'      => (string) $field['status'],
					'stale'       => self::is_stale( (string) $field['review_date'], $now ),
				)
			);
		}

		return $rows;
	}

	/**
	 * @return array{
	 *   provider:string,
	 *   label:string,
	 *   first_seen:int,
	 *   last_seen:int,
	 *   calls:int,
	 *   denies:int,
	 *   plugins:list<string>,
	 *   families:list<string>,
	 *   pii_flagged:bool,
	 *   pii_types:list<string>,
	 *   sources:list<string>
	 * }
	 */
	private static function empty_stat_public( string $provider ): array {
		return array(
			'provider'    => $provider,
			'label'       => self::provider_label( $provider ),
			'first_seen'  => 0,
			'last_seen'   => 0,
			'calls'       => 0,
			'denies'      => 0,
			'plugins'     => array(),
			'families'    => array(),
			'pii_flagged' => false,
			'pii_types'   => array(),
			'sources'     => array(),
		);
	}

	/**
	 * @param int|null $now Clock override (unix). Used only for day comparison.
	 */
	public static function is_stale( string $review_date, ?int $now = null ): bool {
		$review_date = self::sanitize_date( $review_date );
		if ( '' === $review_date ) {
			return false;
		}
		$now       = null !== $now ? (int) $now : ( class_exists( Clock::class, false ) ? Clock::now() : time() );
		$today     = gmdate( 'Y-m-d', $now );
		return $review_date < $today;
	}

	/**
	 * @param int|null $now Clock override.
	 * @return list<array{provider:string,label:string,review_date:string}>
	 */
	public static function stale_rows( ?int $now = null ): array {
		$out = array();
		foreach ( self::build_rows( null, $now ) as $row ) {
			if ( empty( $row['stale'] ) ) {
				continue;
			}
			$out[] = array(
				'provider'    => (string) $row['provider'],
				'label'       => (string) $row['label'],
				'review_date' => (string) $row['review_date'],
			);
		}

		return $out;
	}

	public static function family_labels_csv( array $families ): string {
		$labels = class_exists( Operations::class, false ) ? Operations::family_labels() : array();
		$out    = array();
		foreach ( $families as $family ) {
			$family = (string) $family;
			if ( isset( $labels[ $family ] ) ) {
				$out[] = (string) $labels[ $family ];
			} elseif ( class_exists( Operations::class, false ) && Operations::FAMILY_UNKNOWN === $family ) {
				$out[] = __( 'Unknown', 'handl-ai-connector-access-control' );
			} else {
				$out[] = $family;
			}
		}

		return implode( '; ', $out );
	}

	public static function pii_types_csv( array $types ): string {
		$out = array();
		foreach ( $types as $type ) {
			$type = (string) $type;
			if ( class_exists( Pii_Warn::class, false ) ) {
				$out[] = Pii_Warn::pattern_label( $type );
			} else {
				$out[] = $type;
			}
		}

		return implode( '; ', $out );
	}

	/**
	 * @param list<array<string,mixed>>|null $rows Optional rows override.
	 */
	public static function csv_for_register( ?array $rows = null ): string {
		if ( null === $rows ) {
			$rows = self::build_rows();
		}
		$lines = array(
			self::csv_line(
				array(
					'provider',
					'label',
					'first_seen',
					'last_seen',
					'calls',
					'denies',
					'plugins',
					'families',
					'pii_flagged',
					'pii_types',
					'sources',
					'dpa_on_file',
					'dpa_date',
					'dpa_url',
					'purpose',
					'residency',
					'contact',
					'review_date',
					'status',
					'stale',
				)
			),
		);
		foreach ( $rows as $r ) {
			$lines[] = self::csv_line(
				array(
					(string) ( $r['provider'] ?? '' ),
					(string) ( $r['label'] ?? '' ),
					(string) (int) ( $r['first_seen'] ?? 0 ),
					(string) (int) ( $r['last_seen'] ?? 0 ),
					(string) (int) ( $r['calls'] ?? 0 ),
					(string) (int) ( $r['denies'] ?? 0 ),
					implode( '; ', is_array( $r['plugins'] ?? null ) ? $r['plugins'] : array() ),
					self::family_labels_csv( is_array( $r['families'] ?? null ) ? $r['families'] : array() ),
					! empty( $r['pii_flagged'] ) ? 'yes' : 'no',
					self::pii_types_csv( is_array( $r['pii_types'] ?? null ) ? $r['pii_types'] : array() ),
					implode( '; ', is_array( $r['sources'] ?? null ) ? $r['sources'] : array() ),
					! empty( $r['dpa_on_file'] ) ? 'yes' : 'no',
					(string) ( $r['dpa_date'] ?? '' ),
					(string) ( $r['dpa_url'] ?? '' ),
					(string) ( $r['purpose'] ?? '' ),
					(string) ( $r['residency'] ?? '' ),
					(string) ( $r['contact'] ?? '' ),
					(string) ( $r['review_date'] ?? '' ),
					(string) ( $r['status'] ?? '' ),
					! empty( $r['stale'] ) ? 'yes' : 'no',
				)
			);
		}

		return implode( "\n", $lines ) . "\n";
	}

	/**
	 * @param list<string> $fields Fields.
	 */
	private static function csv_line( array $fields ): string {
		$out = array();
		foreach ( $fields as $f ) {
			$f = str_replace( '"', '""', (string) $f );
			if ( preg_match( '/[",\n\r]/', $f ) ) {
				$out[] = '"' . $f . '"';
			} else {
				$out[] = $f;
			}
		}

		return implode( ',', $out );
	}

	public static function format_ts( int $ts ): string {
		if ( $ts <= 0 ) {
			return '—';
		}
		if ( function_exists( 'wp_date' ) ) {
			return (string) wp_date( 'Y-m-d H:i', $ts );
		}

		return gmdate( 'Y-m-d H:i', $ts ) . ' UTC';
	}

	public static function register_menu(): void {
		if ( ! Caps::user_can_view() ) {
			return;
		}
		if ( ! function_exists( 'add_submenu_page' ) ) {
			return;
		}
		add_submenu_page(
			Admin::MENU_SLUG,
			__( 'AI processor register', 'handl-ai-connector-access-control' ),
			__( 'Processor register', 'handl-ai-connector-access-control' ),
			Caps::VIEW,
			self::PAGE_SLUG,
			array( self::class, 'render_page' )
		);
	}

	public static function render_page(): void {
		if ( ! Caps::user_can_view() ) {
			return;
		}
		$settings   = self::get_settings();
		$can_manage = Caps::user_can_manage();
		$rows       = self::build_rows();
		$csv        = add_query_arg(
			array(
				'page'                     => self::PAGE_SLUG,
				'handl_aicac_register_csv' => '1',
				'_wpnonce'                 => function_exists( 'wp_create_nonce' ) ? wp_create_nonce( 'handl_aicac_register_csv' ) : '',
			),
			admin_url( 'admin.php' )
		);
		$print = add_query_arg(
			array(
				'page'                       => self::PAGE_SLUG,
				'handl_aicac_register_print' => '1',
				'_wpnonce'                   => function_exists( 'wp_create_nonce' ) ? wp_create_nonce( 'handl_aicac_register_print' ) : '',
			),
			admin_url( 'admin.php' )
		);

		echo '<div class="wrap">';
		echo '<h1>' . esc_html__( 'AI processor register', 'handl-ai-connector-access-control' ) . '</h1>';
		echo '<p class="description">' . esc_html__( 'Art. 30-shaped register of AI vendors that process site data. Rows auto-fill from observed traffic and key inventory; DPA and review fields are maintained here. Prohibited status is informational and does not deny calls. Off by default.', 'handl-ai-connector-access-control' ) . '</p>';

		if ( $can_manage ) {
			$action = admin_url( 'admin-post.php' );
			echo '<form method="post" action="' . esc_url( $action ) . '">';
			echo '<input type="hidden" name="action" value="' . esc_attr( self::ACTION_SAVE ) . '" />';
			if ( function_exists( 'wp_nonce_field' ) ) {
				wp_nonce_field( self::ACTION_SAVE );
			}
			echo '<input type="hidden" name="' . esc_attr( self::POST_PRESENT ) . '" value="1" />';
			echo '<table class="form-table" role="presentation"><tbody>';
			echo '<tr><th scope="row">' . esc_html__( 'Enable register', 'handl-ai-connector-access-control' ) . '</th><td>';
			echo '<label><input type="checkbox" name="' . esc_attr( self::POST_ENABLED ) . '" value="1" ' . checked( ! empty( $settings['enabled'] ), true, false ) . ' /> ';
			echo esc_html__( 'Track review dates and show staleness nudges on this screen', 'handl-ai-connector-access-control' );
			echo '</label></td></tr></tbody></table>';
		}

		echo '<p>';
		echo '<a class="button" href="' . esc_url( $csv ) . '">' . esc_html__( 'Download CSV', 'handl-ai-connector-access-control' ) . '</a> ';
		echo '<a class="button" href="' . esc_url( $print ) . '" target="_blank" rel="noopener noreferrer">' . esc_html__( 'Print / PDF view', 'handl-ai-connector-access-control' ) . '</a>';
		echo '</p>';

		if ( empty( $rows ) ) {
			echo '<p>' . esc_html__( 'No AI processors observed yet. Rows appear after governed AI traffic or keyscan findings.', 'handl-ai-connector-access-control' ) . '</p>';
			if ( $can_manage ) {
				submit_button( __( 'Save processor register', 'handl-ai-connector-access-control' ) );
				echo '</form>';
			}
			echo '</div>';
			return;
		}

		echo '<table class="widefat striped"><thead><tr>';
		echo '<th>' . esc_html__( 'Provider', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'First / last seen', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Calls / denies', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Plugins', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Families', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'PII signal', 'handl-ai-connector-access-control' ) . '</th>';
		if ( $can_manage ) {
			echo '<th>' . esc_html__( 'DPA / review', 'handl-ai-connector-access-control' ) . '</th>';
		} else {
			echo '<th>' . esc_html__( 'DPA / review', 'handl-ai-connector-access-control' ) . '</th>';
		}
		echo '</tr></thead><tbody>';

		foreach ( $rows as $r ) {
			$provider = (string) $r['provider'];
			$prefix   = self::POST_FIELDS . '[' . $provider . ']';
			echo '<tr>';
			echo '<td><strong>' . esc_html( (string) $r['label'] ) . '</strong>';
			echo '<br /><code>' . esc_html( $provider ) . '</code>';
			if ( self::STATUS_PROHIBITED === (string) $r['status'] ) {
				echo '<br /><span class="description">' . esc_html__( 'Prohibited — informational only; does not deny.', 'handl-ai-connector-access-control' ) . '</span>';
			}
			echo '</td>';
			echo '<td>' . esc_html( self::format_ts( (int) $r['first_seen'] ) ) . '<br />' . esc_html( self::format_ts( (int) $r['last_seen'] ) ) . '</td>';
			echo '<td class="num">' . esc_html( (string) (int) $r['calls'] ) . ' / ' . esc_html( (string) (int) $r['denies'] ) . '</td>';
			echo '<td>' . esc_html( implode( ', ', is_array( $r['plugins'] ) ? $r['plugins'] : array() ) ) . '</td>';
			echo '<td>' . esc_html( self::family_labels_csv( is_array( $r['families'] ) ? $r['families'] : array() ) ) . '</td>';
			if ( ! empty( $r['pii_flagged'] ) ) {
				echo '<td>' . esc_html__( 'Flagged', 'handl-ai-connector-access-control' );
				$pii = self::pii_types_csv( is_array( $r['pii_types'] ) ? $r['pii_types'] : array() );
				if ( '' !== $pii ) {
					echo '<br /><span class="description">' . esc_html( $pii ) . '</span>';
				}
				echo '</td>';
			} else {
				echo '<td>' . esc_html__( 'None', 'handl-ai-connector-access-control' ) . '</td>';
			}

			echo '<td>';
			if ( $can_manage ) {
				echo '<label><input type="checkbox" name="' . esc_attr( $prefix . '[dpa_on_file]' ) . '" value="1" ' . checked( ! empty( $r['dpa_on_file'] ), true, false ) . ' /> ';
				echo esc_html__( 'DPA on file', 'handl-ai-connector-access-control' ) . '</label><br />';
				echo '<label>' . esc_html__( 'DPA date', 'handl-ai-connector-access-control' ) . ' ';
				echo '<input type="date" name="' . esc_attr( $prefix . '[dpa_date]' ) . '" value="' . esc_attr( (string) $r['dpa_date'] ) . '" /></label><br />';
				echo '<label>' . esc_html__( 'DPA URL', 'handl-ai-connector-access-control' ) . ' ';
				echo '<input type="url" class="regular-text" name="' . esc_attr( $prefix . '[dpa_url]' ) . '" value="' . esc_attr( (string) $r['dpa_url'] ) . '" /></label><br />';
				echo '<label>' . esc_html__( 'Purpose', 'handl-ai-connector-access-control' ) . ' ';
				echo '<input type="text" class="regular-text" name="' . esc_attr( $prefix . '[purpose]' ) . '" value="' . esc_attr( (string) $r['purpose'] ) . '" /></label><br />';
				echo '<label>' . esc_html__( 'Data residency', 'handl-ai-connector-access-control' ) . ' ';
				echo '<input type="text" class="regular-text" name="' . esc_attr( $prefix . '[residency]' ) . '" value="' . esc_attr( (string) $r['residency'] ) . '" /></label><br />';
				echo '<label>' . esc_html__( 'Vendor contact', 'handl-ai-connector-access-control' ) . ' ';
				echo '<input type="text" class="regular-text" name="' . esc_attr( $prefix . '[contact]' ) . '" value="' . esc_attr( (string) $r['contact'] ) . '" /></label><br />';
				echo '<label>' . esc_html__( 'Review date', 'handl-ai-connector-access-control' ) . ' ';
				echo '<input type="date" name="' . esc_attr( $prefix . '[review_date]' ) . '" value="' . esc_attr( (string) $r['review_date'] ) . '" /></label><br />';
				echo '<label>' . esc_html__( 'Status', 'handl-ai-connector-access-control' ) . ' ';
				echo '<select name="' . esc_attr( $prefix . '[status]' ) . '">';
				foreach ( self::status_choices() as $choice ) {
					echo '<option value="' . esc_attr( $choice ) . '" ' . selected( (string) $r['status'], $choice, false ) . '>';
					echo esc_html( self::status_label( $choice ) );
					echo '</option>';
				}
				echo '</select></label>';
				if ( ! empty( $r['stale'] ) ) {
					echo '<p class="description" style="color:#b32d2e;">' . esc_html__( 'Review date has passed.', 'handl-ai-connector-access-control' ) . '</p>';
				}
			} else {
				echo esc_html(
					sprintf(
						/* translators: 1: yes/no, 2: date, 3: status label */
						__( 'DPA on file: %1$s (%2$s). Status: %3$s.', 'handl-ai-connector-access-control' ),
						! empty( $r['dpa_on_file'] ) ? __( 'yes', 'handl-ai-connector-access-control' ) : __( 'no', 'handl-ai-connector-access-control' ),
						'' !== (string) $r['dpa_date'] ? (string) $r['dpa_date'] : '—',
						self::status_label( (string) $r['status'] )
					)
				);
				if ( '' !== (string) $r['purpose'] ) {
					echo '<br /><span class="description">' . esc_html( (string) $r['purpose'] ) . '</span>';
				}
				if ( '' !== (string) $r['review_date'] ) {
					echo '<br /><span class="description">' . esc_html(
						sprintf(
							/* translators: %s: review date */
							__( 'Review by %s', 'handl-ai-connector-access-control' ),
							(string) $r['review_date']
						)
					) . '</span>';
				}
			}
			echo '</td>';
			echo '</tr>';
		}
		echo '</tbody></table>';

		if ( $can_manage ) {
			submit_button( __( 'Save processor register', 'handl-ai-connector-access-control' ) );
			echo '</form>';
		}
		echo '</div>';
	}

	public static function maybe_staleness_notice(): void {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$page = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( (string) $_GET['page'] ) ) : '';
		if ( self::PAGE_SLUG !== $page ) {
			return;
		}
		if ( ! self::is_enabled() ) {
			return;
		}
		if ( ! Caps::user_can_view() ) {
			return;
		}
		$stale = self::stale_rows();
		if ( empty( $stale ) ) {
			return;
		}
		$labels = array();
		foreach ( $stale as $row ) {
			$labels[] = (string) $row['label'];
		}
		echo '<div class="notice notice-warning"><p>';
		echo esc_html(
			sprintf(
				/* translators: %s: comma-separated provider labels */
				__( 'Processor register: review date has passed for: %s', 'handl-ai-connector-access-control' ),
				implode( ', ', $labels )
			)
		);
		echo '</p></div>';
	}

	public static function maybe_handle_csv(): void {
		if ( function_exists( 'is_admin' ) && ! is_admin() ) {
			return;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$page = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( (string) $_GET['page'] ) ) : '';
		if ( self::PAGE_SLUG !== $page ) {
			return;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$flag = isset( $_GET['handl_aicac_register_csv'] ) ? sanitize_key( wp_unslash( (string) $_GET['handl_aicac_register_csv'] ) ) : '';
		if ( '1' !== $flag ) {
			return;
		}
		if ( ! Caps::user_can_view() ) {
			if ( function_exists( 'wp_die' ) ) {
				wp_die( esc_html__( 'You do not have permission to export this register.', 'handl-ai-connector-access-control' ) );
			}
			return;
		}
		check_admin_referer( 'handl_aicac_register_csv' );
		$csv = self::csv_for_register();
		if ( function_exists( 'nocache_headers' ) ) {
			nocache_headers();
		}
		if ( function_exists( 'header' ) ) {
			header( 'Content-Type: text/csv; charset=utf-8' );
			header( 'Content-Disposition: attachment; filename="handl-aicac-processor-register.csv"' );
		}
		// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- raw CSV download body.
		echo $csv;
		exit;
	}

	public static function maybe_handle_print(): void {
		if ( function_exists( 'is_admin' ) && ! is_admin() ) {
			return;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$page = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( (string) $_GET['page'] ) ) : '';
		if ( self::PAGE_SLUG !== $page ) {
			return;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$flag = isset( $_GET['handl_aicac_register_print'] ) ? sanitize_key( wp_unslash( (string) $_GET['handl_aicac_register_print'] ) ) : '';
		if ( '1' !== $flag ) {
			return;
		}
		if ( ! Caps::user_can_view() ) {
			if ( function_exists( 'wp_die' ) ) {
				wp_die( esc_html__( 'You do not have permission to print this register.', 'handl-ai-connector-access-control' ) );
			}
			return;
		}
		check_admin_referer( 'handl_aicac_register_print' );
		$html = self::build_print_html( self::build_rows() );
		if ( function_exists( 'nocache_headers' ) ) {
			nocache_headers();
		}
		if ( function_exists( 'header' ) ) {
			header( 'Content-Type: text/html; charset=utf-8' );
			header( 'Content-Disposition: inline; filename="handl-aicac-processor-register.html"' );
		}
		// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- full HTML document built with escaping inside.
		echo $html;
		exit;
	}

	/**
	 * @param list<array<string,mixed>> $rows Register rows.
	 */
	public static function build_print_html( array $rows ): string {
		$site = function_exists( 'get_bloginfo' ) ? (string) get_bloginfo( 'name' ) : 'WordPress';
		$ver  = defined( 'HANDL_AICAC_VERSION' ) ? (string) HANDL_AICAC_VERSION : '';
		$now  = class_exists( Clock::class, false ) ? Clock::now() : time();
		$title = sprintf(
			/* translators: %s: site name */
			__( 'AI processor register: %s', 'handl-ai-connector-access-control' ),
			$site
		);

		ob_start();
		?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title><?php echo esc_html( $title ); ?></title>
<style>
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;font-size:12px;line-height:1.45;color:#1d2327;margin:24px;max-width:960px;}
h1{font-size:20px;margin:0 0 8px;}
h2{font-size:15px;margin:24px 0 8px;border-bottom:1px solid #c3c4c7;padding-bottom:4px;}
.meta{color:#50575e;margin-bottom:20px;}
table{border-collapse:collapse;width:100%;margin:8px 0 16px;}
th,td{border:1px solid #c3c4c7;padding:6px 8px;text-align:left;vertical-align:top;}
th{background:#f0f0f1;}
.muted{color:#646970;}
.num{text-align:right;font-variant-numeric:tabular-nums;}
@media print{body{margin:12mm;}.no-print{display:none !important;}}
</style>
</head>
<body>
<p class="no-print muted"><?php echo esc_html__( 'Use your browser’s Print dialog and choose Save as PDF. This page stays on your site. Nothing is sent elsewhere.', 'handl-ai-connector-access-control' ); ?></p>
<h1><?php echo esc_html__( 'AI processor register', 'handl-ai-connector-access-control' ); ?></h1>
<div class="meta">
<p><strong><?php echo esc_html__( 'Site', 'handl-ai-connector-access-control' ); ?>:</strong> <?php echo esc_html( $site ); ?></p>
<p><strong><?php echo esc_html__( 'Generated', 'handl-ai-connector-access-control' ); ?>:</strong> <?php echo esc_html( self::format_ts( $now ) ); ?></p>
<p><strong><?php echo esc_html__( 'Plugin version', 'handl-ai-connector-access-control' ); ?>:</strong> <?php echo esc_html( $ver ); ?></p>
<p class="muted"><?php echo esc_html__( 'Auto-filled from governed AI traffic and key inventory. DPA and review fields are site-maintained. Prohibited status is informational and does not deny AI calls.', 'handl-ai-connector-access-control' ); ?></p>
</div>
<h2><?php echo esc_html__( 'Processors', 'handl-ai-connector-access-control' ); ?></h2>
<?php if ( empty( $rows ) ) : ?>
<p class="muted"><?php echo esc_html__( 'No AI processors observed yet.', 'handl-ai-connector-access-control' ); ?></p>
<?php else : ?>
<table>
<thead>
<tr>
<th><?php echo esc_html__( 'Provider', 'handl-ai-connector-access-control' ); ?></th>
<th><?php echo esc_html__( 'First seen', 'handl-ai-connector-access-control' ); ?></th>
<th><?php echo esc_html__( 'Last seen', 'handl-ai-connector-access-control' ); ?></th>
<th class="num"><?php echo esc_html__( 'Calls', 'handl-ai-connector-access-control' ); ?></th>
<th class="num"><?php echo esc_html__( 'Denies', 'handl-ai-connector-access-control' ); ?></th>
<th><?php echo esc_html__( 'Plugins', 'handl-ai-connector-access-control' ); ?></th>
<th><?php echo esc_html__( 'Families', 'handl-ai-connector-access-control' ); ?></th>
<th><?php echo esc_html__( 'PII', 'handl-ai-connector-access-control' ); ?></th>
<th><?php echo esc_html__( 'DPA', 'handl-ai-connector-access-control' ); ?></th>
<th><?php echo esc_html__( 'Purpose', 'handl-ai-connector-access-control' ); ?></th>
<th><?php echo esc_html__( 'Residency', 'handl-ai-connector-access-control' ); ?></th>
<th><?php echo esc_html__( 'Contact', 'handl-ai-connector-access-control' ); ?></th>
<th><?php echo esc_html__( 'Review', 'handl-ai-connector-access-control' ); ?></th>
<th><?php echo esc_html__( 'Status', 'handl-ai-connector-access-control' ); ?></th>
</tr>
</thead>
<tbody>
<?php foreach ( $rows as $r ) : ?>
<tr>
<td><?php echo esc_html( (string) ( $r['label'] ?? '' ) ); ?><br /><span class="muted"><?php echo esc_html( (string) ( $r['provider'] ?? '' ) ); ?></span></td>
<td><?php echo esc_html( self::format_ts( (int) ( $r['first_seen'] ?? 0 ) ) ); ?></td>
<td><?php echo esc_html( self::format_ts( (int) ( $r['last_seen'] ?? 0 ) ) ); ?></td>
<td class="num"><?php echo esc_html( (string) (int) ( $r['calls'] ?? 0 ) ); ?></td>
<td class="num"><?php echo esc_html( (string) (int) ( $r['denies'] ?? 0 ) ); ?></td>
<td><?php echo esc_html( implode( ', ', is_array( $r['plugins'] ?? null ) ? $r['plugins'] : array() ) ); ?></td>
<td><?php echo esc_html( self::family_labels_csv( is_array( $r['families'] ?? null ) ? $r['families'] : array() ) ); ?></td>
<td><?php echo esc_html( ! empty( $r['pii_flagged'] ) ? self::pii_types_csv( is_array( $r['pii_types'] ?? null ) ? $r['pii_types'] : array() ) : '—' ); ?></td>
<td><?php echo esc_html( ! empty( $r['dpa_on_file'] ) ? ( '' !== (string) ( $r['dpa_date'] ?? '' ) ? (string) $r['dpa_date'] : __( 'yes', 'handl-ai-connector-access-control' ) ) : __( 'no', 'handl-ai-connector-access-control' ) ); ?></td>
<td><?php echo esc_html( (string) ( $r['purpose'] ?? '' ) ); ?></td>
<td><?php echo esc_html( (string) ( $r['residency'] ?? '' ) ); ?></td>
<td><?php echo esc_html( (string) ( $r['contact'] ?? '' ) ); ?></td>
<td><?php echo esc_html( '' !== (string) ( $r['review_date'] ?? '' ) ? (string) $r['review_date'] : '—' ); ?></td>
<td><?php echo esc_html( self::status_label( (string) ( $r['status'] ?? '' ) ) ); ?></td>
</tr>
<?php endforeach; ?>
</tbody>
</table>
<?php endif; ?>
</body>
</html>
		<?php
		return (string) ob_get_clean();
	}

	public static function handle_save(): void {
		if ( ! Caps::user_can_manage() ) {
			if ( function_exists( 'wp_die' ) ) {
				wp_die( esc_html__( 'You do not have permission to save this register.', 'handl-ai-connector-access-control' ) );
			}
			return;
		}
		check_admin_referer( self::ACTION_SAVE );

		$enabled = ! empty( $_POST[ self::POST_ENABLED ] ); // phpcs:ignore WordPress.Security.NonceVerification.Missing
		self::save_settings( array( 'enabled' => $enabled ) );

		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		$raw_fields = isset( $_POST[ self::POST_FIELDS ] ) && is_array( $_POST[ self::POST_FIELDS ] ) ? wp_unslash( $_POST[ self::POST_FIELDS ] ) : array();
		$merged     = self::get_fields();
		if ( is_array( $raw_fields ) ) {
			foreach ( $raw_fields as $provider => $row ) {
				$id = Cost::normalize_provider_id( (string) $provider );
				if ( '' === $id || ! is_array( $row ) ) {
					continue;
				}
				$merged[ $id ] = self::sanitize_field_row( $row );
			}
		}
		self::save_fields( $merged );

		$redirect = add_query_arg(
			array(
				'page'    => self::PAGE_SLUG,
				'updated' => '1',
			),
			admin_url( 'admin.php' )
		);
		if ( function_exists( 'wp_safe_redirect' ) ) {
			wp_safe_redirect( $redirect );
			exit;
		}
	}

	public static function register_cli(): void {
		if ( ! defined( 'WP_CLI' ) || ! WP_CLI ) {
			return;
		}
		if ( ! class_exists( '\WP_CLI' ) ) {
			return;
		}
		\WP_CLI::add_command( 'handl-aicac register', CLI_Register::class );
	}
}

/**
 * WP-CLI: wp handl-aicac register status|export
 */
final class CLI_Register {

	/**
	 * Show processor register status.
	 *
	 * ## OPTIONS
	 *
	 * @when after_wp_load
	 *
	 * @param list<string>             $args       Positional.
	 * @param array<string,string|int> $assoc_args Flags.
	 */
	public function status( $args, $assoc_args ): void {
		unset( $args, $assoc_args );
		$settings = Register::get_settings();
		$rows     = Register::build_rows();
		$stale    = Register::stale_rows();
		$pii      = 0;
		$prohib   = 0;
		foreach ( $rows as $r ) {
			if ( ! empty( $r['pii_flagged'] ) ) {
				++$pii;
			}
			if ( Register::STATUS_PROHIBITED === (string) ( $r['status'] ?? '' ) ) {
				++$prohib;
			}
		}
		\WP_CLI::log(
			sprintf(
				'enabled=%s providers=%d stale=%d pii_flagged=%d prohibited=%d',
				! empty( $settings['enabled'] ) ? 'yes' : 'no',
				count( $rows ),
				count( $stale ),
				$pii,
				$prohib
			)
		);
	}

	/**
	 * Export the processor register.
	 *
	 * ## OPTIONS
	 *
	 * [--format=<format>]
	 * : table, json, csv, or yaml. Default table.
	 *
	 * @when after_wp_load
	 *
	 * @param list<string>             $args       Positional.
	 * @param array<string,string|int> $assoc_args Flags.
	 */
	public function export( $args, $assoc_args ): void {
		unset( $args );
		$format = isset( $assoc_args['format'] ) ? (string) $assoc_args['format'] : 'table';
		$rows   = Register::build_rows();
		if ( 'csv' === $format ) {
			\WP_CLI::print_value( Register::csv_for_register( $rows ), array( 'format' => 'csv' ) );
			return;
		}
		$table = array();
		foreach ( $rows as $r ) {
			$table[] = array(
				'provider'    => (string) $r['provider'],
				'label'       => (string) $r['label'],
				'calls'       => (int) $r['calls'],
				'denies'      => (int) $r['denies'],
				'pii_flagged' => ! empty( $r['pii_flagged'] ) ? 'yes' : 'no',
				'dpa_on_file' => ! empty( $r['dpa_on_file'] ) ? 'yes' : 'no',
				'review_date' => (string) $r['review_date'],
				'status'      => (string) $r['status'],
				'stale'       => ! empty( $r['stale'] ) ? 'yes' : 'no',
			);
		}
		if ( empty( $table ) ) {
			\WP_CLI::log( 'No processors in the register.' );
			return;
		}
		\WP_CLI\Utils\format_items(
			$format,
			$table,
			array( 'provider', 'label', 'calls', 'denies', 'pii_flagged', 'dpa_on_file', 'review_date', 'status', 'stale' )
		);
	}
}
