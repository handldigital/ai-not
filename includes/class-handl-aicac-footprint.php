<?php
/**
 * AICAC-FOOTPRINT (#401): governance self-weigh-in (read-only).
 *
 * Inventories handl_aicac_* options (bytes + autoload), owned cron hooks, and a
 * static hot-path hook census. Configurable autoload-bytes budget with exactly
 * one re-arming [FOOTPRINT] alert. Capped growth history. Print + CSV + WP-CLI.
 * Informational only — never mutates foreign options, never times the gate.
 * OFF by default. Own two options.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Read-only option / cron / hot-path footprint of this plugin.
 */
final class Footprint {

	public const SETTINGS_OPTION = 'handl_aicac_footprint';

	public const STATE_OPTION = 'handl_aicac_footprint_state';

	public const PAGE_SLUG = 'handl-aicac-footprint';

	public const ALERT_KIND = 'footprint';

	public const FILTER_BUDGET = 'handl_aicac_footprint_budget_bytes';

	public const POST_PRESENT = 'handl_aicac_footprint_present';

	public const POST_ENABLED = 'handl_aicac_footprint_enabled';

	public const POST_BUDGET = 'handl_aicac_footprint_budget_bytes';

	public const ACTION_SAVE = 'handl_aicac_footprint_save';

	public const FRAMING = 'report_only_never_mutates';

	public const DEFAULT_BUDGET_BYTES = 524288;

	public const MIN_BUDGET_BYTES = 1024;

	public const MAX_BUDGET_BYTES = 104857600;

	public const HISTORY_CAP = 40;

	public const OPTION_PREFIX = 'handl_aicac_';

	public const CRON_PREFIX = 'handl_aicac_';

	/** @var bool */
	private static $registered = false;

	/** @var list<array<string,mixed>> */
	private static $test_mails = array();

	public static function init(): void {
		if ( self::$registered ) {
			return;
		}
		self::$registered = true;

		add_action( 'admin_menu', array( self::class, 'register_menu' ), 20 );
		add_action( 'admin_init', array( self::class, 'maybe_handle_csv' ), 5 );
		add_action( 'admin_init', array( self::class, 'maybe_handle_print' ), 5 );
		add_action( 'admin_post_' . self::ACTION_SAVE, array( self::class, 'handle_save' ) );

		if ( self::is_enabled() ) {
			add_action( 'init', array( self::class, 'maybe_fire_alerts' ), 30 );
		}

		self::register_cli();
	}

	public static function reset_for_tests(): void {
		self::$registered = false;
		self::$test_mails = array();
		delete_option( self::SETTINGS_OPTION );
		delete_option( self::STATE_OPTION );
		unset(
			$GLOBALS['handl_aicac_footprint_test_rows'],
			$GLOBALS['handl_aicac_footprint_test_site_autoload_bytes'],
			$GLOBALS['handl_aicac_footprint_test_cron']
		);
	}

	/**
	 * @return list<array<string,mixed>>
	 */
	public static function test_mails(): array {
		return self::$test_mails;
	}

	/**
	 * @return array{enabled:bool,budget_bytes:int}
	 */
	public static function defaults(): array {
		return array(
			'enabled'      => false,
			'budget_bytes' => self::DEFAULT_BUDGET_BYTES,
		);
	}

	/**
	 * @return array{enabled:bool,budget_bytes:int}
	 */
	public static function get_settings(): array {
		return self::sanitize_settings( get_option( self::SETTINGS_OPTION, array() ) );
	}

	/**
	 * @param mixed $raw Raw settings.
	 * @return array{enabled:bool,budget_bytes:int}
	 */
	public static function sanitize_settings( $raw ): array {
		$defaults = self::defaults();
		if ( ! is_array( $raw ) ) {
			return $defaults;
		}

		return array(
			'enabled'      => ! empty( $raw['enabled'] ),
			'budget_bytes' => self::sanitize_budget_bytes( $raw['budget_bytes'] ?? $defaults['budget_bytes'] ),
		);
	}

	/**
	 * @param mixed $raw Raw budget.
	 */
	public static function sanitize_budget_bytes( $raw ): int {
		if ( ! is_numeric( $raw ) ) {
			return self::DEFAULT_BUDGET_BYTES;
		}
		$v = (int) $raw;
		if ( $v < self::MIN_BUDGET_BYTES ) {
			$v = self::MIN_BUDGET_BYTES;
		}
		if ( $v > self::MAX_BUDGET_BYTES ) {
			$v = self::MAX_BUDGET_BYTES;
		}

		return $v;
	}

	/**
	 * Effective budget after filter.
	 */
	public static function budget_bytes(): int {
		$settings = self::get_settings();
		$base     = (int) $settings['budget_bytes'];
		if ( function_exists( 'apply_filters' ) ) {
			return self::sanitize_budget_bytes( apply_filters( self::FILTER_BUDGET, $base ) );
		}

		return $base;
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

	/* ---------------------------------------------------------------------
	 * State (alerted + history)
	 * ------------------------------------------------------------------ */

	/**
	 * @return array{alerted:bool,history:list<array<string,mixed>>}
	 */
	public static function defaults_state(): array {
		return array(
			'alerted' => false,
			'history' => array(),
		);
	}

	/**
	 * @return array{alerted:bool,history:list<array<string,mixed>>}
	 */
	public static function get_state(): array {
		return self::sanitize_state( get_option( self::STATE_OPTION, array() ) );
	}

	/**
	 * @param mixed $raw Raw state.
	 * @return array{alerted:bool,history:list<array<string,mixed>>}
	 */
	public static function sanitize_state( $raw ): array {
		$defaults = self::defaults_state();
		if ( ! is_array( $raw ) ) {
			return $defaults;
		}
		$history = array();
		if ( isset( $raw['history'] ) && is_array( $raw['history'] ) ) {
			foreach ( $raw['history'] as $entry ) {
				$clean = self::sanitize_history_entry( $entry );
				if ( null !== $clean ) {
					$history[] = $clean;
				}
			}
		}
		if ( count( $history ) > self::HISTORY_CAP ) {
			$history = array_slice( $history, -self::HISTORY_CAP );
		}

		return array(
			'alerted' => ! empty( $raw['alerted'] ),
			'history' => $history,
		);
	}

	/**
	 * @param mixed $raw Raw entry.
	 * @return array{ts:int,our_autoload_bytes:int,our_total_bytes:int,option_count:int,site_autoload_bytes:int}|null
	 */
	public static function sanitize_history_entry( $raw ): ?array {
		if ( ! is_array( $raw ) ) {
			return null;
		}
		$ts = isset( $raw['ts'] ) ? (int) $raw['ts'] : 0;
		if ( $ts <= 0 ) {
			return null;
		}

		return array(
			'ts'                  => $ts,
			'our_autoload_bytes'  => max( 0, (int) ( $raw['our_autoload_bytes'] ?? 0 ) ),
			'our_total_bytes'     => max( 0, (int) ( $raw['our_total_bytes'] ?? 0 ) ),
			'option_count'        => max( 0, (int) ( $raw['option_count'] ?? 0 ) ),
			'site_autoload_bytes' => max( 0, (int) ( $raw['site_autoload_bytes'] ?? 0 ) ),
		);
	}

	/**
	 * @param array{alerted:bool,history:list<array<string,mixed>>} $state State.
	 */
	public static function put_state( array $state ): void {
		$clean = self::sanitize_state( $state );
		if ( $clean === self::defaults_state() ) {
			delete_option( self::STATE_OPTION );

			return;
		}
		update_option( self::STATE_OPTION, $clean, false );
	}

	public static function is_alerted(): bool {
		return ! empty( self::get_state()['alerted'] );
	}

	public static function set_alerted( bool $alerted ): void {
		$state            = self::get_state();
		$state['alerted'] = $alerted;
		self::put_state( $state );
	}

	/* ---------------------------------------------------------------------
	 * Option inventory (read-only SELECT / injectable rows)
	 * ------------------------------------------------------------------ */

	/**
	 * Serialized byte length of an option value as stored.
	 *
	 * @param mixed $value Option value.
	 */
	public static function value_bytes( $value ): int {
		if ( is_string( $value ) ) {
			return strlen( $value );
		}
		if ( function_exists( 'maybe_serialize' ) ) {
			return strlen( (string) maybe_serialize( $value ) );
		}

		return strlen( (string) serialize( $value ) );
	}

	/**
	 * Whether an autoload flag counts as "yes" for our inventory.
	 *
	 * @param mixed $autoload Autoload column.
	 */
	public static function is_autoload_yes( $autoload ): bool {
		$v = strtolower( trim( (string) $autoload ) );

		return in_array( $v, array( 'yes', 'on', 'auto', 'true', '1' ), true );
	}

	/**
	 * @return list<array{option_name:string,option_value:mixed,autoload:string}>
	 */
	private static function fetch_option_rows(): array {
		if ( isset( $GLOBALS['handl_aicac_footprint_test_rows'] ) && is_array( $GLOBALS['handl_aicac_footprint_test_rows'] ) ) {
			$out = array();
			foreach ( $GLOBALS['handl_aicac_footprint_test_rows'] as $row ) {
				if ( ! is_array( $row ) ) {
					continue;
				}
				$name = (string) ( $row['option_name'] ?? '' );
				if ( '' === $name ) {
					continue;
				}
				$out[] = array(
					'option_name'  => $name,
					'option_value' => $row['option_value'] ?? '',
					'autoload'     => (string) ( $row['autoload'] ?? 'no' ),
				);
			}

			return $out;
		}

		global $wpdb;
		if ( ! isset( $wpdb ) || ! is_object( $wpdb ) || empty( $wpdb->options )
			|| ! method_exists( $wpdb, 'get_results' ) || ! method_exists( $wpdb, 'prepare' ) ) {
			return array();
		}

		$like = method_exists( $wpdb, 'esc_like' )
			? $wpdb->esc_like( self::OPTION_PREFIX ) . '%'
			: self::OPTION_PREFIX . '%';

		$output = defined( 'ARRAY_A' ) ? ARRAY_A : 'ARRAY_A';
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- read-only inventory SELECT.
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT option_name, option_value, autoload FROM {$wpdb->options} WHERE option_name LIKE %s",
				$like
			),
			$output
		);
		if ( ! is_array( $rows ) ) {
			return array();
		}
		$out = array();
		foreach ( $rows as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$out[] = array(
				'option_name'  => (string) ( $row['option_name'] ?? '' ),
				'option_value' => $row['option_value'] ?? '',
				'autoload'     => (string) ( $row['autoload'] ?? 'no' ),
			);
		}

		return $out;
	}

	/**
	 * Site-wide autoloaded options bytes (alloptions contribution).
	 */
	public static function site_autoload_bytes(): int {
		if ( isset( $GLOBALS['handl_aicac_footprint_test_site_autoload_bytes'] ) ) {
			return max( 0, (int) $GLOBALS['handl_aicac_footprint_test_site_autoload_bytes'] );
		}

		global $wpdb;
		if ( ! isset( $wpdb ) || ! is_object( $wpdb ) || empty( $wpdb->options )
			|| ! method_exists( $wpdb, 'get_var' ) || ! method_exists( $wpdb, 'prepare' ) ) {
			return 0;
		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- read-only SUM SELECT.
		$sum = $wpdb->get_var(
			"SELECT SUM(LENGTH(option_value)) FROM {$wpdb->options} WHERE autoload = 'yes'"
		);

		return max( 0, (int) $sum );
	}

	/**
	 * @return array{
	 *   options:list<array<string,mixed>>,
	 *   top10:list<array<string,mixed>>,
	 *   option_count:int,
	 *   our_total_bytes:int,
	 *   our_autoload_bytes:int,
	 *   site_autoload_bytes:int,
	 *   autoload_share:float
	 * }
	 */
	public static function option_inventory(): array {
		$rows               = self::fetch_option_rows();
		$options            = array();
		$our_total          = 0;
		$our_autoload       = 0;
		$site_autoload      = self::site_autoload_bytes();

		foreach ( $rows as $row ) {
			$name     = (string) $row['option_name'];
			$bytes    = self::value_bytes( $row['option_value'] );
			$autoload = (string) $row['autoload'];
			$is_auto  = self::is_autoload_yes( $autoload );
			$our_total += $bytes;
			if ( $is_auto ) {
				$our_autoload += $bytes;
			}
			$options[] = array(
				'option_name' => $name,
				'bytes'       => $bytes,
				'autoload'    => $is_auto ? 'yes' : 'no',
				'autoload_raw'=> $autoload,
			);
		}

		usort(
			$options,
			static function ( array $a, array $b ): int {
				if ( (int) $a['bytes'] === (int) $b['bytes'] ) {
					return strcmp( (string) $a['option_name'], (string) $b['option_name'] );
				}

				return ( (int) $b['bytes'] <=> (int) $a['bytes'] );
			}
		);

		$share = $site_autoload > 0 ? ( $our_autoload / $site_autoload ) : 0.0;

		return array(
			'options'             => $options,
			'top10'               => array_slice( $options, 0, 10 ),
			'option_count'        => count( $options ),
			'our_total_bytes'     => $our_total,
			'our_autoload_bytes'  => $our_autoload,
			'site_autoload_bytes' => $site_autoload,
			'autoload_share'      => $share,
		);
	}

	/* ---------------------------------------------------------------------
	 * Owned cron inventory
	 * ------------------------------------------------------------------ */

	/**
	 * @return list<array{hook:string,recurrence:string,next_run:int}>
	 */
	public static function cron_inventory(): array {
		$cron = null;
		if ( function_exists( '_get_cron_array' ) ) {
			$cron = _get_cron_array();
		} elseif ( isset( $GLOBALS['handl_aicac_footprint_test_cron'] ) ) {
			$cron = $GLOBALS['handl_aicac_footprint_test_cron'];
		}
		if ( ! is_array( $cron ) ) {
			return array();
		}

		// Flat map: hook => timestamp (or list of {hook,recurrence,next_run}).
		if ( self::is_flat_cron_map( $cron ) ) {
			return self::parse_flat_cron( $cron );
		}
		if ( self::is_list_cron( $cron ) ) {
			return self::parse_list_cron( $cron );
		}

		return self::parse_wp_cron_array( $cron );
	}

	/**
	 * @param array<mixed> $cron Cron structure.
	 */
	private static function is_flat_cron_map( array $cron ): bool {
		if ( empty( $cron ) ) {
			return false;
		}
		foreach ( $cron as $key => $value ) {
			if ( ! is_string( $key ) || ! str_starts_with( $key, self::CRON_PREFIX ) ) {
				return false;
			}
			if ( ! is_numeric( $value ) && ! is_array( $value ) ) {
				return false;
			}
			if ( is_array( $value ) && isset( $value['hook'] ) ) {
				return false;
			}
			// WP cron array keys are integer timestamps.
			if ( is_int( $key ) || ( is_string( $key ) && ctype_digit( $key ) ) ) {
				return false;
			}
		}

		return true;
	}

	/**
	 * @param array<mixed> $cron Cron structure.
	 */
	private static function is_list_cron( array $cron ): bool {
		if ( empty( $cron ) ) {
			return false;
		}
		$first = reset( $cron );
		return is_array( $first ) && isset( $first['hook'] );
	}

	/**
	 * @param array<string,mixed> $cron Flat hook => ts|meta.
	 * @return list<array{hook:string,recurrence:string,next_run:int}>
	 */
	private static function parse_flat_cron( array $cron ): array {
		$out = array();
		foreach ( $cron as $hook => $value ) {
			$hook = (string) $hook;
			if ( ! str_starts_with( $hook, self::CRON_PREFIX ) ) {
				continue;
			}
			$recurrence = 'unknown';
			$next       = 0;
			if ( is_array( $value ) ) {
				$next       = (int) ( $value['next_run'] ?? $value['timestamp'] ?? 0 );
				$recurrence = (string) ( $value['recurrence'] ?? $value['schedule'] ?? 'unknown' );
			} else {
				$next = (int) $value;
			}
			$out[] = array(
				'hook'       => $hook,
				'recurrence' => '' !== $recurrence ? $recurrence : 'unknown',
				'next_run'   => $next,
			);
		}
		usort(
			$out,
			static function ( array $a, array $b ): int {
				return strcmp( (string) $a['hook'], (string) $b['hook'] );
			}
		);

		return $out;
	}

	/**
	 * @param list<array<string,mixed>> $cron List rows.
	 * @return list<array{hook:string,recurrence:string,next_run:int}>
	 */
	private static function parse_list_cron( array $cron ): array {
		$out = array();
		foreach ( $cron as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$hook = (string) ( $row['hook'] ?? '' );
			if ( ! str_starts_with( $hook, self::CRON_PREFIX ) ) {
				continue;
			}
			$out[] = array(
				'hook'       => $hook,
				'recurrence' => (string) ( $row['recurrence'] ?? $row['schedule'] ?? 'unknown' ),
				'next_run'   => (int) ( $row['next_run'] ?? $row['timestamp'] ?? 0 ),
			);
		}
		usort(
			$out,
			static function ( array $a, array $b ): int {
				return strcmp( (string) $a['hook'], (string) $b['hook'] );
			}
		);

		return $out;
	}

	/**
	 * @param array<int|string,mixed> $cron WP `_get_cron_array()` shape.
	 * @return list<array{hook:string,recurrence:string,next_run:int}>
	 */
	private static function parse_wp_cron_array( array $cron ): array {
		$by_hook = array();
		foreach ( $cron as $timestamp => $hooks ) {
			if ( ! is_array( $hooks ) ) {
				continue;
			}
			$ts = (int) $timestamp;
			foreach ( $hooks as $hook => $events ) {
				$hook = (string) $hook;
				if ( ! str_starts_with( $hook, self::CRON_PREFIX ) || ! is_array( $events ) ) {
					continue;
				}
				foreach ( $events as $event ) {
					if ( ! is_array( $event ) ) {
						continue;
					}
					$schedule = isset( $event['schedule'] ) && false !== $event['schedule'] && null !== $event['schedule']
						? (string) $event['schedule']
						: 'once';
					if ( ! isset( $by_hook[ $hook ] ) || $ts < (int) $by_hook[ $hook ]['next_run'] || 0 === (int) $by_hook[ $hook ]['next_run'] ) {
						$by_hook[ $hook ] = array(
							'hook'       => $hook,
							'recurrence' => '' !== $schedule ? $schedule : 'once',
							'next_run'   => $ts,
						);
					}
				}
			}
		}
		$out = array_values( $by_hook );
		usort(
			$out,
			static function ( array $a, array $b ): int {
				return strcmp( (string) $a['hook'], (string) $b['hook'] );
			}
		);

		return $out;
	}

	/* ---------------------------------------------------------------------
	 * Hot-path census (static table — report only)
	 * ------------------------------------------------------------------ */

	/**
	 * @return list<array{class:string,hook:string,note:string}>
	 */
	public static function hot_path_table(): array {
		return array(
			array(
				'class' => 'Shadow_AI',
				'hook'  => 'pre_http_request',
				'note'  => 'Observes outbound AI HTTP without blocking.',
			),
			array(
				'class' => 'Mcp_Gate',
				'hook'  => 'pre_http_request',
				'note'  => 'Filters MCP connector HTTP on the request path.',
			),
			array(
				'class' => 'Soft_Deny',
				'hook'  => 'pre_http_request',
				'note'  => 'Stubs denied AI HTTP responses on the request path.',
			),
			array(
				'class' => 'Policy',
				'hook'  => 'wp_ai_client_prevent_prompt',
				'note'  => 'Primary AI Client gate decision filter.',
			),
			array(
				'class' => 'Latency',
				'hook'  => 'wp_ai_client_after_generate_result',
				'note'  => 'Records provider duration after generate (not a gate timer).',
			),
		);
	}

	/* ---------------------------------------------------------------------
	 * Snapshot + history
	 * ------------------------------------------------------------------ */

	public static function is_over_budget( ?array $inventory = null ): bool {
		$inv = null !== $inventory ? $inventory : self::option_inventory();

		return (int) ( $inv['our_autoload_bytes'] ?? 0 ) > self::budget_bytes();
	}

	/**
	 * Append a growth-history entry (capped). Optional same-minute identical-totals dedupe.
	 *
	 * @param array<string,mixed> $inventory Inventory totals.
	 * @return bool True when a new entry was appended.
	 */
	public static function record_history( array $inventory, ?int $now = null ): bool {
		$now   = null !== $now && $now > 0 ? $now : ( class_exists( Clock::class, false ) ? Clock::now() : time() );
		$entry = array(
			'ts'                  => $now,
			'our_autoload_bytes'  => (int) ( $inventory['our_autoload_bytes'] ?? 0 ),
			'our_total_bytes'     => (int) ( $inventory['our_total_bytes'] ?? 0 ),
			'option_count'        => (int) ( $inventory['option_count'] ?? 0 ),
			'site_autoload_bytes' => (int) ( $inventory['site_autoload_bytes'] ?? 0 ),
		);
		$state   = self::get_state();
		$history = $state['history'];
		if ( ! empty( $history ) ) {
			$last = $history[ count( $history ) - 1 ];
			$same_minute = (int) floor( (int) $last['ts'] / 60 ) === (int) floor( $now / 60 );
			$same_totals = (int) $last['our_autoload_bytes'] === (int) $entry['our_autoload_bytes']
				&& (int) $last['our_total_bytes'] === (int) $entry['our_total_bytes']
				&& (int) $last['option_count'] === (int) $entry['option_count']
				&& (int) $last['site_autoload_bytes'] === (int) $entry['site_autoload_bytes'];
			if ( $same_minute && $same_totals ) {
				return false;
			}
		}
		$history[]         = $entry;
		$state['history']  = array_slice( $history, -self::HISTORY_CAP );
		self::put_state( $state );

		return true;
	}

	/**
	 * Full snapshot for UI / CLI / CSV.
	 *
	 * @return array<string,mixed>
	 */
	public static function snapshot( ?int $now = null ): array {
		$inventory = self::option_inventory();
		$crons     = self::cron_inventory();
		$hot_path  = self::hot_path_table();
		$budget    = self::budget_bytes();
		$over      = (int) $inventory['our_autoload_bytes'] > $budget;

		if ( self::is_enabled() ) {
			self::record_history( $inventory, $now );
		}

		return array(
			'enabled'             => self::is_enabled(),
			'budget_bytes'        => $budget,
			'over_budget'         => $over,
			'options'             => $inventory['options'],
			'top10'               => $inventory['top10'],
			'option_count'        => $inventory['option_count'],
			'our_total_bytes'     => $inventory['our_total_bytes'],
			'our_autoload_bytes'  => $inventory['our_autoload_bytes'],
			'site_autoload_bytes' => $inventory['site_autoload_bytes'],
			'autoload_share'      => $inventory['autoload_share'],
			'crons'               => $crons,
			'hot_path'            => $hot_path,
			'history'             => self::get_state()['history'],
			'alerted'             => self::is_alerted(),
			'framing'             => self::FRAMING,
		);
	}

	public static function format_bytes( int $bytes ): string {
		if ( $bytes < 1024 ) {
			return (string) $bytes . ' B';
		}
		if ( $bytes < 1048576 ) {
			return rtrim( rtrim( sprintf( '%.1f', $bytes / 1024 ), '0' ), '.' ) . ' KiB';
		}

		return rtrim( rtrim( sprintf( '%.2f', $bytes / 1048576 ), '0' ), '.' ) . ' MiB';
	}

	public static function format_share( float $share ): string {
		return sprintf( '%.1f%%', $share * 100.0 );
	}

	/* ---------------------------------------------------------------------
	 * Alerts
	 * ------------------------------------------------------------------ */

	/**
	 * Fire at most one [FOOTPRINT] alert while over budget; re-arm when under.
	 *
	 * @return bool True when a new alert was sent.
	 */
	public static function maybe_fire_alerts( ?array $inventory = null ): bool {
		if ( ! self::is_enabled() ) {
			return false;
		}
		$inv = null !== $inventory ? $inventory : self::option_inventory();
		$over = self::is_over_budget( $inv );

		if ( ! $over ) {
			if ( self::is_alerted() ) {
				self::set_alerted( false );
			}

			return false;
		}

		if ( self::is_alerted() ) {
			return false;
		}

		$now     = class_exists( Clock::class, false ) ? Clock::now() : time();
		$payload = array(
			'our_autoload_bytes'  => (int) $inv['our_autoload_bytes'],
			'budget_bytes'        => self::budget_bytes(),
			'autoload_share'      => (float) $inv['autoload_share'],
			'site_autoload_bytes' => (int) $inv['site_autoload_bytes'],
			'option_count'        => (int) $inv['option_count'],
		);
		if ( ! self::fire_alert( $payload, $now ) ) {
			return false;
		}
		self::set_alerted( true );

		return true;
	}

	/**
	 * @param array<string,mixed> $payload Payload.
	 */
	private static function fire_alert( array $payload, int $now ): bool {
		$policy = class_exists( Policy::class, false ) ? Policy::get_policy() : array();
		if ( ! is_array( $policy ) ) {
			$policy = array();
		}
		$email = '';
		if ( class_exists( Alerts::class, false ) && method_exists( Alerts::class, 'resolve_email' ) ) {
			$email = (string) Alerts::resolve_email( $policy );
		}
		if ( '' === $email ) {
			return false;
		}

		$subject = self::build_subject( $payload );
		$body    = self::build_body( $payload );
		$ok      = false;
		if ( class_exists( Alerts::class, false ) && method_exists( Alerts::class, 'safe_wp_mail' ) ) {
			$ok = (bool) Alerts::safe_wp_mail( $email, $subject, $body );
		} elseif ( function_exists( 'wp_mail' ) ) {
			$ok = (bool) wp_mail( $email, $subject, $body );
		}
		self::$test_mails[] = array(
			'to'      => $email,
			'subject' => $subject,
			'body'     => $body,
		);

		if ( $ok && class_exists( Alerts::class, false ) && method_exists( Alerts::class, 'resolve_webhook' ) ) {
			$hook_url = (string) Alerts::resolve_webhook( $policy );
			if ( '' !== $hook_url && method_exists( Alerts::class, 'safe_wp_remote_post' ) ) {
				Alerts::safe_wp_remote_post(
					$hook_url,
					array(
						'type'               => 'handl_aicac_footprint',
						'our_autoload_bytes' => (int) ( $payload['our_autoload_bytes'] ?? 0 ),
						'budget_bytes'       => (int) ( $payload['budget_bytes'] ?? 0 ),
						'autoload_share'     => (float) ( $payload['autoload_share'] ?? 0 ),
						'site'               => function_exists( 'home_url' ) ? home_url( '/' ) : '',
						'ts'                 => $now,
					)
				);
			}
		}

		return $ok;
	}

	/**
	 * @param array<string,mixed> $payload Payload.
	 */
	public static function build_subject( array $payload ): string {
		unset( $payload );
		$site = function_exists( 'get_bloginfo' )
			? wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES )
			: 'WordPress';

		return sprintf(
			/* translators: %s: site name */
			__( '[%s] [FOOTPRINT] AI Connector autoload footprint over budget', 'handl-ai-connector-access-control' ),
			$site
		);
	}

	/**
	 * @param array<string,mixed> $payload Payload.
	 */
	public static function build_body( array $payload ): string {
		$lines   = array();
		$lines[] = __( 'This plugin\'s autoloaded options exceed the configured footprint budget.', 'handl-ai-connector-access-control' );
		$lines[] = '';
		$lines[] = sprintf(
			/* translators: 1: our autoload bytes formatted, 2: budget formatted */
			__( 'Our autoload bytes: %1$s — budget: %2$s', 'handl-ai-connector-access-control' ),
			self::format_bytes( (int) ( $payload['our_autoload_bytes'] ?? 0 ) ),
			self::format_bytes( (int) ( $payload['budget_bytes'] ?? self::DEFAULT_BUDGET_BYTES ) )
		);
		$lines[] = sprintf(
			/* translators: %s: share of site autoload */
			__( 'Share of site autoload: %s', 'handl-ai-connector-access-control' ),
			self::format_share( (float) ( $payload['autoload_share'] ?? 0 ) )
		);
		$lines[] = '';
		$lines[] = __( 'Report only — never changes options.', 'handl-ai-connector-access-control' );
		$url     = self::admin_url();
		if ( '' !== $url ) {
			$lines[] = '';
			$lines[] = sprintf(
				/* translators: %s: admin URL */
				__( 'Open footprint inventory: %s', 'handl-ai-connector-access-control' ),
				$url
			);
		}

		return implode( "\n", $lines );
	}

	public static function admin_url(): string {
		if ( ! function_exists( 'admin_url' ) ) {
			return '';
		}

		return (string) add_query_arg( 'page', self::PAGE_SLUG, admin_url( 'admin.php' ) );
	}

	/* ---------------------------------------------------------------------
	 * CSV + print
	 * ------------------------------------------------------------------ */

	/**
	 * @param list<array<string,mixed>>|null $options Optional inventory options (heaviest first).
	 */
	public static function csv_for_inventory( ?array $options = null ): string {
		if ( null === $options ) {
			$options = self::option_inventory()['options'];
		}
		$lines   = array();
		$lines[] = self::csv_line(
			array(
				'option_name',
				'bytes',
				'autoload',
				'framing',
			)
		);
		foreach ( $options as $row ) {
			$lines[] = self::csv_line(
				array(
					(string) ( $row['option_name'] ?? '' ),
					(string) (int) ( $row['bytes'] ?? 0 ),
					(string) ( $row['autoload'] ?? 'no' ),
					self::FRAMING,
				)
			);
		}

		return implode( "\n", $lines ) . "\n";
	}

	/**
	 * @param list<string> $cols Columns.
	 */
	public static function csv_line( array $cols ): string {
		$out = array();
		foreach ( $cols as $col ) {
			$col   = (string) $col;
			$needs = str_contains( $col, ',' ) || str_contains( $col, '"' ) || str_contains( $col, "\n" );
			$col   = str_replace( '"', '""', $col );
			$out[] = $needs ? '"' . $col . '"' : $col;
		}

		return implode( ',', $out );
	}

	/**
	 * @param list<array<string,mixed>> $options Option rows.
	 * @param list<array<string,mixed>> $crons   Cron rows.
	 * @param list<array<string,mixed>> $hot     Hot-path rows.
	 */
	public static function build_print_html( array $options, array $crons = array(), array $hot = array() ): string {
		$html  = '<!DOCTYPE html><html><head><meta charset="utf-8"><title>';
		$html .= esc_html__( 'AI Connector footprint', 'handl-ai-connector-access-control' );
		$html .= '</title><style>body{font-family:sans-serif;margin:24px}table{border-collapse:collapse;width:100%;margin-bottom:24px}th,td{border:1px solid #ccc;padding:6px 8px;text-align:left}th{background:#f6f7f7}</style></head><body>';
		$html .= '<h1>' . esc_html__( 'AI Connector footprint', 'handl-ai-connector-access-control' ) . '</h1>';
		$html .= '<p>' . esc_html__( 'Report only — never changes options. No gate timing.', 'handl-ai-connector-access-control' ) . '</p>';
		$html .= '<h2>' . esc_html__( 'Option inventory (heaviest first)', 'handl-ai-connector-access-control' ) . '</h2>';
		$html .= '<table><thead><tr>';
		$html .= '<th>' . esc_html__( 'Option', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '<th>' . esc_html__( 'Bytes', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '<th>' . esc_html__( 'Autoload', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '</tr></thead><tbody>';
		foreach ( $options as $row ) {
			$html .= '<tr>';
			$html .= '<td>' . esc_html( (string) ( $row['option_name'] ?? '' ) ) . '</td>';
			$html .= '<td>' . esc_html( (string) (int) ( $row['bytes'] ?? 0 ) ) . '</td>';
			$html .= '<td>' . esc_html( (string) ( $row['autoload'] ?? 'no' ) ) . '</td>';
			$html .= '</tr>';
		}
		$html .= '</tbody></table>';
		$html .= '<h2>' . esc_html__( 'Owned cron hooks', 'handl-ai-connector-access-control' ) . '</h2>';
		if ( empty( $crons ) ) {
			$html .= '<p>' . esc_html__( 'No handl_aicac_* cron hooks scheduled.', 'handl-ai-connector-access-control' ) . '</p>';
		} else {
			$html .= '<table><thead><tr>';
			$html .= '<th>' . esc_html__( 'Hook', 'handl-ai-connector-access-control' ) . '</th>';
			$html .= '<th>' . esc_html__( 'Recurrence', 'handl-ai-connector-access-control' ) . '</th>';
			$html .= '<th>' . esc_html__( 'Next run', 'handl-ai-connector-access-control' ) . '</th>';
			$html .= '</tr></thead><tbody>';
			foreach ( $crons as $row ) {
				$next = (int) ( $row['next_run'] ?? 0 );
				$html .= '<tr>';
				$html .= '<td>' . esc_html( (string) ( $row['hook'] ?? '' ) ) . '</td>';
				$html .= '<td>' . esc_html( (string) ( $row['recurrence'] ?? '' ) ) . '</td>';
				$html .= '<td>' . esc_html( $next > 0 ? gmdate( 'Y-m-d H:i:s', $next ) . ' UTC' : '—' ) . '</td>';
				$html .= '</tr>';
			}
			$html .= '</tbody></table>';
		}
		$html .= '<h2>' . esc_html__( 'Hot-path hook census', 'handl-ai-connector-access-control' ) . '</h2>';
		$html .= '<table><thead><tr>';
		$html .= '<th>' . esc_html__( 'Class', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '<th>' . esc_html__( 'Hook', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '<th>' . esc_html__( 'Note', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '</tr></thead><tbody>';
		foreach ( $hot as $row ) {
			$html .= '<tr>';
			$html .= '<td>' . esc_html( (string) ( $row['class'] ?? '' ) ) . '</td>';
			$html .= '<td>' . esc_html( (string) ( $row['hook'] ?? '' ) ) . '</td>';
			$html .= '<td>' . esc_html( (string) ( $row['note'] ?? '' ) ) . '</td>';
			$html .= '</tr>';
		}
		$html .= '</tbody></table></body></html>';

		return $html;
	}

	/* ---------------------------------------------------------------------
	 * Admin UI
	 * ------------------------------------------------------------------ */

	public static function register_menu(): void {
		if ( ! Caps::user_can_view() ) {
			return;
		}
		if ( ! function_exists( 'add_submenu_page' ) ) {
			return;
		}
		add_submenu_page(
			Admin::MENU_SLUG,
			__( 'AI footprint', 'handl-ai-connector-access-control' ),
			__( 'Footprint', 'handl-ai-connector-access-control' ),
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
		$enabled    = self::is_enabled();
		$snap       = $enabled ? self::snapshot() : null;
		$csv        = add_query_arg(
			array(
				'page'                       => self::PAGE_SLUG,
				'handl_aicac_footprint_csv'  => '1',
				'_wpnonce'                   => function_exists( 'wp_create_nonce' ) ? wp_create_nonce( 'handl_aicac_footprint_csv' ) : '',
			),
			admin_url( 'admin.php' )
		);
		$print = add_query_arg(
			array(
				'page'                        => self::PAGE_SLUG,
				'handl_aicac_footprint_print' => '1',
				'_wpnonce'                    => function_exists( 'wp_create_nonce' ) ? wp_create_nonce( 'handl_aicac_footprint_print' ) : '',
			),
			admin_url( 'admin.php' )
		);

		echo '<div class="wrap">';
		echo '<h1>' . esc_html__( 'AI footprint', 'handl-ai-connector-access-control' ) . '</h1>';
		echo '<p class="description">' . esc_html__( 'Weigh this plugin\'s options, cron hooks, and hot-path filters. Report only — never changes options. Off by default.', 'handl-ai-connector-access-control' ) . '</p>';

		if ( $can_manage ) {
			$action = admin_url( 'admin-post.php' );
			echo '<form method="post" action="' . esc_url( $action ) . '">';
			echo '<input type="hidden" name="action" value="' . esc_attr( self::ACTION_SAVE ) . '" />';
			if ( function_exists( 'wp_nonce_field' ) ) {
				wp_nonce_field( self::ACTION_SAVE );
			}
			echo '<input type="hidden" name="' . esc_attr( self::POST_PRESENT ) . '" value="1" />';
			echo '<table class="form-table" role="presentation"><tbody>';
			echo '<tr><th scope="row">' . esc_html__( 'Enable footprint watch', 'handl-ai-connector-access-control' ) . '</th><td>';
			echo '<label><input type="checkbox" name="' . esc_attr( self::POST_ENABLED ) . '" value="1" ' . checked( ! empty( $settings['enabled'] ), true, false ) . ' /> ';
			echo esc_html__( 'Inventory options/crons/hot-path and alert when autoload bytes exceed the budget', 'handl-ai-connector-access-control' );
			echo '</label></td></tr>';
			echo '<tr><th scope="row"><label for="handl-aicac-footprint-budget">' . esc_html__( 'Autoload budget (bytes)', 'handl-ai-connector-access-control' ) . '</label></th><td>';
			echo '<input name="' . esc_attr( self::POST_BUDGET ) . '" id="handl-aicac-footprint-budget" type="number" min="' . esc_attr( (string) self::MIN_BUDGET_BYTES ) . '" max="' . esc_attr( (string) self::MAX_BUDGET_BYTES ) . '" step="1" value="' . esc_attr( (string) (int) $settings['budget_bytes'] ) . '" class="regular-text" />';
			echo '<p class="description">' . esc_html__( 'Default 524288 (512 KiB). Alert once when our autoloaded options exceed this size.', 'handl-ai-connector-access-control' ) . '</p>';
			echo '</td></tr></tbody></table>';
			submit_button( __( 'Save footprint settings', 'handl-ai-connector-access-control' ) );
			echo '</form>';
		}

		if ( ! $enabled || ! is_array( $snap ) ) {
			echo '<p>' . esc_html__( 'Footprint watch is off. Enable it to inventory handl_aicac_* options, owned cron hooks, and the hot-path census.', 'handl-ai-connector-access-control' ) . '</p>';
			echo '</div>';

			return;
		}

		echo '<p><strong>' . esc_html__( 'Report only — never changes options.', 'handl-ai-connector-access-control' ) . '</strong> ';
		echo esc_html__( 'No timing instrumentation of the gate.', 'handl-ai-connector-access-control' ) . '</p>';

		echo '<ul>';
		echo '<li>' . esc_html(
			sprintf(
				/* translators: 1: option count, 2: total bytes, 3: autoload bytes */
				__( 'Options: %1$d — total %2$s — autoload %3$s', 'handl-ai-connector-access-control' ),
				(int) $snap['option_count'],
				self::format_bytes( (int) $snap['our_total_bytes'] ),
				self::format_bytes( (int) $snap['our_autoload_bytes'] )
			)
		) . '</li>';
		echo '<li>' . esc_html(
			sprintf(
				/* translators: 1: share percent, 2: site autoload bytes, 3: budget */
				__( 'Share of site autoload: %1$s of %2$s — budget %3$s', 'handl-ai-connector-access-control' ),
				self::format_share( (float) $snap['autoload_share'] ),
				self::format_bytes( (int) $snap['site_autoload_bytes'] ),
				self::format_bytes( (int) $snap['budget_bytes'] )
			)
		) . '</li>';
		if ( ! empty( $snap['over_budget'] ) ) {
			echo '<li><strong>' . esc_html__( 'Over autoload budget.', 'handl-ai-connector-access-control' ) . '</strong></li>';
		}
		echo '</ul>';

		echo '<p>';
		echo '<a class="button" href="' . esc_url( $csv ) . '">' . esc_html__( 'Download CSV', 'handl-ai-connector-access-control' ) . '</a> ';
		echo '<a class="button" href="' . esc_url( $print ) . '" target="_blank" rel="noopener noreferrer">' . esc_html__( 'Print / PDF view', 'handl-ai-connector-access-control' ) . '</a>';
		echo '</p>';

		echo '<h2>' . esc_html__( 'Top options (heaviest first)', 'handl-ai-connector-access-control' ) . '</h2>';
		if ( empty( $snap['options'] ) ) {
			echo '<p>' . esc_html__( 'No handl_aicac_* options found.', 'handl-ai-connector-access-control' ) . '</p>';
		} else {
			echo '<table class="widefat striped"><thead><tr>';
			echo '<th>' . esc_html__( 'Option', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Bytes', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Autoload', 'handl-ai-connector-access-control' ) . '</th>';
			echo '</tr></thead><tbody>';
			foreach ( $snap['top10'] as $row ) {
				echo '<tr>';
				echo '<td><code>' . esc_html( (string) $row['option_name'] ) . '</code></td>';
				echo '<td>' . esc_html( self::format_bytes( (int) $row['bytes'] ) ) . '</td>';
				echo '<td>' . esc_html( (string) $row['autoload'] ) . '</td>';
				echo '</tr>';
			}
			echo '</tbody></table>';
		}

		echo '<h2>' . esc_html__( 'Owned cron hooks', 'handl-ai-connector-access-control' ) . '</h2>';
		if ( empty( $snap['crons'] ) ) {
			echo '<p>' . esc_html__( 'No handl_aicac_* cron hooks scheduled.', 'handl-ai-connector-access-control' ) . '</p>';
		} else {
			echo '<table class="widefat striped"><thead><tr>';
			echo '<th>' . esc_html__( 'Hook', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Recurrence', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Next run', 'handl-ai-connector-access-control' ) . '</th>';
			echo '</tr></thead><tbody>';
			foreach ( $snap['crons'] as $row ) {
				$next = (int) $row['next_run'];
				echo '<tr>';
				echo '<td><code>' . esc_html( (string) $row['hook'] ) . '</code></td>';
				echo '<td>' . esc_html( (string) $row['recurrence'] ) . '</td>';
				echo '<td>' . esc_html( $next > 0 ? gmdate( 'Y-m-d H:i:s', $next ) . ' UTC' : '—' ) . '</td>';
				echo '</tr>';
			}
			echo '</tbody></table>';
		}

		echo '<h2>' . esc_html__( 'Hot-path hook census', 'handl-ai-connector-access-control' ) . '</h2>';
		echo '<table class="widefat striped"><thead><tr>';
		echo '<th>' . esc_html__( 'Class', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Hook', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Note', 'handl-ai-connector-access-control' ) . '</th>';
		echo '</tr></thead><tbody>';
		foreach ( $snap['hot_path'] as $row ) {
			echo '<tr>';
			echo '<td><code>' . esc_html( (string) $row['class'] ) . '</code></td>';
			echo '<td><code>' . esc_html( (string) $row['hook'] ) . '</code></td>';
			echo '<td>' . esc_html( (string) $row['note'] ) . '</td>';
			echo '</tr>';
		}
		echo '</tbody></table>';

		echo '</div>';
	}

	public static function maybe_handle_csv(): void {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( empty( $_GET['handl_aicac_footprint_csv'] ) ) {
			return;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$page = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( (string) $_GET['page'] ) ) : '';
		if ( self::PAGE_SLUG !== $page ) {
			return;
		}
		if ( ! Caps::user_can_view() || ! self::is_enabled() ) {
			return;
		}
		check_admin_referer( 'handl_aicac_footprint_csv' );
		$csv = self::csv_for_inventory();
		if ( function_exists( 'nocache_headers' ) ) {
			nocache_headers();
		}
		if ( ! headers_sent() ) {
			header( 'Content-Type: text/csv; charset=utf-8' );
			header( 'Content-Disposition: attachment; filename=handl-aicac-footprint.csv' );
		}
		echo $csv; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- CSV download.
		exit;
	}

	public static function maybe_handle_print(): void {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( empty( $_GET['handl_aicac_footprint_print'] ) ) {
			return;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$page = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( (string) $_GET['page'] ) ) : '';
		if ( self::PAGE_SLUG !== $page ) {
			return;
		}
		if ( ! Caps::user_can_view() || ! self::is_enabled() ) {
			return;
		}
		check_admin_referer( 'handl_aicac_footprint_print' );
		$snap = self::snapshot();
		if ( function_exists( 'nocache_headers' ) ) {
			nocache_headers();
		}
		if ( ! headers_sent() ) {
			header( 'Content-Type: text/html; charset=utf-8' );
		}
		echo self::build_print_html( // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped inside builder.
			(array) $snap['options'],
			(array) $snap['crons'],
			(array) $snap['hot_path']
		);
		exit;
	}

	public static function handle_save(): void {
		if ( ! Caps::user_can_manage() ) {
			wp_die( esc_html__( 'You do not have permission to save footprint settings.', 'handl-ai-connector-access-control' ) );
		}
		check_admin_referer( self::ACTION_SAVE );
		if ( empty( $_POST[ self::POST_PRESENT ] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing
			wp_die( esc_html__( 'Invalid form', 'handl-ai-connector-access-control' ) );
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		$budget_raw = isset( $_POST[ self::POST_BUDGET ] ) ? wp_unslash( (string) $_POST[ self::POST_BUDGET ] ) : '';
		self::save_settings(
			array(
				'enabled'      => ! empty( $_POST[ self::POST_ENABLED ] ), // phpcs:ignore WordPress.Security.NonceVerification.Missing
				'budget_bytes' => self::sanitize_budget_bytes( '' !== $budget_raw ? $budget_raw : self::DEFAULT_BUDGET_BYTES ),
			)
		);
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
		\WP_CLI::add_command( 'handl-aicac footprint', CLI_Footprint::class );
	}
}

/**
 * WP-CLI: wp handl-aicac footprint status|export
 */
final class CLI_Footprint {

	/**
	 * Show footprint status. Exits non-zero when over budget.
	 *
	 * ## OPTIONS
	 *
	 * [--format=<format>]
	 * : table or json. Default table.
	 *
	 * @when after_wp_load
	 *
	 * @param array<int,string>    $args       Positional.
	 * @param array<string,string> $assoc_args Flags.
	 */
	public function status( $args, $assoc_args ): void {
		unset( $args );
		$settings = Footprint::get_settings();
		$format   = isset( $assoc_args['format'] ) ? (string) $assoc_args['format'] : 'table';

		if ( ! Footprint::is_enabled() ) {
			\WP_CLI::log(
				sprintf(
					'enabled=no budget_bytes=%d framing=%s',
					(int) $settings['budget_bytes'],
					Footprint::FRAMING
				)
			);
			\WP_CLI::log( 'Footprint watch is disabled.' );

			return;
		}

		$snap = Footprint::snapshot();
		$over = ! empty( $snap['over_budget'] );

		\WP_CLI::log(
			sprintf(
				'enabled=yes budget_bytes=%d our_autoload_bytes=%d our_total_bytes=%d option_count=%d share=%s over_budget=%s framing=%s',
				(int) $snap['budget_bytes'],
				(int) $snap['our_autoload_bytes'],
				(int) $snap['our_total_bytes'],
				(int) $snap['option_count'],
				Footprint::format_share( (float) $snap['autoload_share'] ),
				$over ? 'yes' : 'no',
				Footprint::FRAMING
			)
		);

		$display = array();
		foreach ( (array) $snap['top10'] as $row ) {
			$display[] = array(
				'option_name' => (string) $row['option_name'],
				'bytes'       => (int) $row['bytes'],
				'autoload'    => (string) $row['autoload'],
			);
		}
		if ( ! empty( $display ) ) {
			if ( 'json' === $format ) {
				\WP_CLI::print_value( $display, array( 'format' => 'json' ) );
			} elseif ( class_exists( '\WP_CLI\Utils' ) ) {
				\WP_CLI\Utils\format_items( 'table', $display, array( 'option_name', 'bytes', 'autoload' ) );
			} else {
				foreach ( $display as $row ) {
					\WP_CLI::log( implode( "\t", $row ) );
				}
			}
		}

		if ( $over ) {
			\WP_CLI::error( 'Over autoload footprint budget.', false );
		}
	}

	/**
	 * Export the option inventory as CSV.
	 *
	 * ## OPTIONS
	 *
	 * [--porcelain]
	 * : Print CSV only.
	 *
	 * @when after_wp_load
	 *
	 * @param array<int,string>    $args       Positional.
	 * @param array<string,string> $assoc_args Flags.
	 */
	public function export( $args, $assoc_args ): void {
		unset( $args );
		$csv = Footprint::csv_for_inventory();
		if ( ! empty( $assoc_args['porcelain'] ) ) {
			echo $csv; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- CLI CSV.
			return;
		}
		\WP_CLI::print_value( $csv, array( 'format' => 'csv' ) );
	}
}
