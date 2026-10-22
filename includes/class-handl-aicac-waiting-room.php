<?php
/**
 * AICAC-WAITING-ROOM (#464): visitor-blocking AI call census.
 *
 * Times AI Client generations with own hooks on the same interval Latency
 * uses (prevent_prompt start → after_generate_result end). Stamps each
 * sample with request surface (front / admin / rest / cron / cli). Grades
 * plugins by front-surface p95. Observability only — never blocks or delays.
 *
 * README-FREE. Own options only (handl_aicac_waiting_room_*). Own admin screen.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Visitor-blocking AI call census.
 */
final class Waiting_Room {

	public const SETTINGS_OPTION = 'handl_aicac_waiting_room';

	public const STATS_OPTION = 'handl_aicac_waiting_room_stats';

	public const ALERTED_OPTION = 'handl_aicac_waiting_room_alerted';

	public const PAGE_SLUG = 'handl-aicac-waiting-room';

	public const ACTION_SAVE = 'handl_aicac_waiting_room_save';

	public const POST_PRESENT = 'handl_aicac_waiting_room_present';

	public const POST_ENABLED = 'handl_aicac_waiting_room_enabled';

	public const ALERT_KIND = 'waiting_room_blocking';

	public const SURFACE_FRONT = 'front';
	public const SURFACE_ADMIN = 'admin';
	public const SURFACE_REST  = 'rest';
	public const SURFACE_CRON  = 'cron';
	public const SURFACE_CLI   = 'cli';

	public const GRADE_INVISIBLE   = 'INVISIBLE';
	public const GRADE_POLITE      = 'POLITE';
	public const GRADE_NOTICEABLE  = 'NOTICEABLE';
	public const GRADE_BLOCKING    = 'BLOCKING';

	/** Front p95 under this → POLITE. */
	public const THRESHOLD_POLITE_MS = 300;

	/** Front p95 under this → NOTICEABLE; at/above → BLOCKING. */
	public const THRESHOLD_BLOCKING_MS = 2000;

	/** Cap per-(plugin, surface) sample buffer. */
	public const SAMPLE_CAP = 64;

	/** Cap plugins retained in the stats map. */
	public const PLUGIN_CAP = 200;

	/** @var bool */
	private static $registered = false;

	/** @var bool */
	private static $hooks_on = false;

	/** @var list<array{plugin:string,surface:string,start_ns:int}> */
	private static $pending = array();

	/** @var list<array{to:string,subject:string,body:string}> */
	private static $test_mails = array();

	/** @var string|null Forced surface for tests. */
	private static $test_surface = null;

	/**
	 * @var array{doing_cron?:bool,rest?:bool,is_admin?:bool,doing_cli?:bool}|null
	 */
	private static $test_flags = null;

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
			self::register_timing_hooks();
		}
	}

	public static function register_timing_hooks(): void {
		if ( self::$hooks_on ) {
			return;
		}
		self::$hooks_on = true;
		// Priority 2: after Policy (1) so $prevent already reflects allow/deny.
		add_filter( 'wp_ai_client_prevent_prompt', array( self::class, 'on_prevent_prompt' ), 2, 2 );
		// Priority 12: after Latency (11) so we share the same generation window.
		add_action( 'wp_ai_client_after_generate_result', array( self::class, 'on_after_generate' ), 12, 1 );
	}

	public static function reset_for_tests(): void {
		self::$registered   = false;
		self::$hooks_on     = false;
		self::$pending      = array();
		self::$test_mails   = array();
		self::$test_surface = null;
		self::$test_flags   = null;
		delete_option( self::SETTINGS_OPTION );
		delete_option( self::STATS_OPTION );
		delete_option( self::ALERTED_OPTION );
	}

	/**
	 * @return list<array{to:string,subject:string,body:string}>
	 */
	public static function test_mails(): array {
		return self::$test_mails;
	}

	public static function set_test_surface( ?string $surface ): void {
		self::$test_surface = ( null !== $surface && '' !== $surface ) ? self::normalize_surface( $surface ) : null;
	}

	/**
	 * @param array{doing_cron?:bool,rest?:bool,is_admin?:bool,doing_cli?:bool}|null $flags
	 */
	public static function set_test_flags( ?array $flags ): void {
		self::$test_flags = $flags;
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
		if ( ! is_array( $raw ) ) {
			return self::defaults();
		}

		return array(
			'enabled' => ! empty( $raw['enabled'] ),
		);
	}

	/**
	 * @param array{enabled?:bool} $settings Settings.
	 * @return bool True when the stored option changed.
	 */
	public static function save_settings( array $settings ): bool {
		$clean    = self::sanitize_settings( $settings );
		$previous = get_option( self::SETTINGS_OPTION, null );
		if ( self::defaults() === $clean ) {
			if ( false === $previous || null === $previous ) {
				return false;
			}
			delete_option( self::SETTINGS_OPTION );

			return true;
		}
		$serialized_prev = is_array( $previous ) ? serialize( self::sanitize_settings( $previous ) ) : null;
		if ( null !== $serialized_prev && serialize( $clean ) === $serialized_prev ) {
			return false;
		}
		update_option( self::SETTINGS_OPTION, $clean, false );

		return true;
	}

	public static function is_enabled(): bool {
		$settings = self::get_settings();

		return ! empty( $settings['enabled'] );
	}

	/**
	 * @return list<string>
	 */
	public static function surfaces(): array {
		return array(
			self::SURFACE_FRONT,
			self::SURFACE_ADMIN,
			self::SURFACE_REST,
			self::SURFACE_CRON,
			self::SURFACE_CLI,
		);
	}

	/**
	 * Classify the current request surface.
	 *
	 * Priority: cron → cli → rest → admin → front.
	 *
	 * @param array{doing_cron?:bool,rest?:bool,is_admin?:bool,doing_cli?:bool}|null $flags
	 */
	public static function detect_surface( ?array $flags = null ): string {
		if ( null !== self::$test_surface ) {
			return self::$test_surface;
		}
		if ( null === $flags ) {
			if ( null !== self::$test_flags ) {
				$flags = self::$test_flags;
			} else {
				$flags = array(
					'doing_cron' => ( function_exists( 'wp_doing_cron' ) && wp_doing_cron() )
						|| ( defined( 'DOING_CRON' ) && DOING_CRON ),
					'rest'       => defined( 'REST_REQUEST' ) && REST_REQUEST,
					'is_admin'   => function_exists( 'is_admin' ) && is_admin(),
					'doing_cli'  => defined( 'WP_CLI' ) && WP_CLI,
				);
			}
		}
		if ( ! empty( $flags['doing_cron'] ) ) {
			return self::SURFACE_CRON;
		}
		if ( ! empty( $flags['doing_cli'] ) ) {
			return self::SURFACE_CLI;
		}
		if ( ! empty( $flags['rest'] ) ) {
			return self::SURFACE_REST;
		}
		if ( ! empty( $flags['is_admin'] ) ) {
			return self::SURFACE_ADMIN;
		}

		return self::SURFACE_FRONT;
	}

	/**
	 * @param mixed $raw Surface token.
	 */
	public static function normalize_surface( $raw ): string {
		$s = is_string( $raw ) ? sanitize_key( $raw ) : '';
		if ( 'frontend' === $s ) {
			$s = self::SURFACE_FRONT;
		}
		if ( in_array( $s, self::surfaces(), true ) ) {
			return $s;
		}

		return self::SURFACE_FRONT;
	}

	/**
	 * Start timer when Policy allowed the prompt through (own hook; Latency untouched).
	 *
	 * @param bool  $prevent Whether the call is blocked.
	 * @param mixed $builder Prompt builder (unused).
	 */
	public static function on_prevent_prompt( bool $prevent, $builder ): bool {
		unset( $builder );
		if ( ! self::is_enabled() || $prevent ) {
			return $prevent;
		}
		$plugin = self::current_plugin();
		if ( '' === $plugin ) {
			return $prevent;
		}
		self::$pending[] = array(
			'plugin'   => $plugin,
			'surface'  => self::detect_surface(),
			'start_ns' => self::now_ns(),
		);

		return $prevent;
	}

	/**
	 * Complete a timed sample. Skips when no measured interval is pending.
	 *
	 * @param mixed $event AfterGenerateResultEvent (unused).
	 */
	public static function on_after_generate( $event ): void {
		unset( $event );
		if ( ! self::is_enabled() || empty( self::$pending ) ) {
			return;
		}
		$entry = array_pop( self::$pending );
		if ( ! is_array( $entry ) ) {
			return;
		}
		$start_ns = isset( $entry['start_ns'] ) ? (int) $entry['start_ns'] : 0;
		if ( $start_ns <= 0 ) {
			return;
		}
		$elapsed_ns = self::now_ns() - $start_ns;
		if ( $elapsed_ns < 0 ) {
			return;
		}
		$duration_ms = (int) round( $elapsed_ns / 1e6 );
		if ( $duration_ms < 0 ) {
			return;
		}
		$plugin  = isset( $entry['plugin'] ) ? (string) $entry['plugin'] : '';
		$surface = isset( $entry['surface'] ) ? self::normalize_surface( $entry['surface'] ) : self::SURFACE_FRONT;
		self::record_sample( $plugin, $surface, $duration_ms );
	}

	public static function current_plugin(): string {
		if ( class_exists( Attribution::class, false ) && method_exists( Attribution::class, 'resolve_from_backtrace' ) ) {
			$resolved = Attribution::resolve_from_backtrace();
			if ( is_array( $resolved ) && ! empty( $resolved['plugin'] ) && is_string( $resolved['plugin'] ) ) {
				return sanitize_text_field( $resolved['plugin'] );
			}
		}

		return '';
	}

	/**
	 * Record one measured sample. No-op when feature off or inputs empty.
	 *
	 * @return array{count:int,total_ms:int,max_ms:int,samples:list<int>}|null
	 */
	public static function record_sample( string $plugin, string $surface, int $duration_ms, ?int $now = null ) {
		if ( ! self::is_enabled() ) {
			return null;
		}
		$plugin = sanitize_text_field( $plugin );
		$surface = self::normalize_surface( $surface );
		if ( '' === $plugin || $duration_ms < 0 ) {
			return null;
		}
		$stats = self::get_stats();
		if ( ! isset( $stats['plugins'][ $plugin ] ) ) {
			if ( count( $stats['plugins'] ) >= self::PLUGIN_CAP ) {
				return null;
			}
			$stats['plugins'][ $plugin ] = array();
		}
		$cell = isset( $stats['plugins'][ $plugin ][ $surface ] ) && is_array( $stats['plugins'][ $plugin ][ $surface ] )
			? self::sanitize_cell( $stats['plugins'][ $plugin ][ $surface ] )
			: self::empty_cell();
		$cell['count']     = (int) $cell['count'] + 1;
		$cell['total_ms']  = (int) $cell['total_ms'] + $duration_ms;
		$cell['max_ms']    = max( (int) $cell['max_ms'], $duration_ms );
		$samples           = array_values( (array) $cell['samples'] );
		$samples[]         = $duration_ms;
		if ( count( $samples ) > self::SAMPLE_CAP ) {
			$samples = array_slice( $samples, -1 * self::SAMPLE_CAP );
		}
		$cell['samples'] = $samples;
		$stats['plugins'][ $plugin ][ $surface ] = $cell;
		self::put_stats( $stats );

		$now = null !== $now && $now > 0 ? $now : ( class_exists( Clock::class, false ) ? (int) Clock::now() : time() );
		if ( self::SURFACE_FRONT === $surface && self::GRADE_BLOCKING === self::grade_for_cell( $cell ) ) {
			self::maybe_alert_blocking( $plugin, $cell, $now );
		}

		return $cell;
	}

	/**
	 * @return array{plugins:array<string,array<string,array{count:int,total_ms:int,max_ms:int,samples:list<int>}>>}
	 */
	public static function get_stats(): array {
		return self::sanitize_stats( get_option( self::STATS_OPTION, array() ) );
	}

	/**
	 * @param mixed $raw Stats blob.
	 * @return array{plugins:array<string,array<string,array{count:int,total_ms:int,max_ms:int,samples:list<int>}>>}
	 */
	public static function sanitize_stats( $raw ): array {
		$out = array( 'plugins' => array() );
		if ( ! is_array( $raw ) || empty( $raw['plugins'] ) || ! is_array( $raw['plugins'] ) ) {
			return $out;
		}
		$n = 0;
		foreach ( $raw['plugins'] as $plugin => $surfaces ) {
			if ( $n >= self::PLUGIN_CAP ) {
				break;
			}
			$plugin = sanitize_text_field( (string) $plugin );
			if ( '' === $plugin || ! is_array( $surfaces ) ) {
				continue;
			}
			$clean = array();
			foreach ( $surfaces as $surface => $cell ) {
				$surface = self::normalize_surface( $surface );
				if ( ! is_array( $cell ) ) {
					continue;
				}
				$clean[ $surface ] = self::sanitize_cell( $cell );
			}
			if ( empty( $clean ) ) {
				continue;
			}
			$out['plugins'][ $plugin ] = $clean;
			++$n;
		}

		return $out;
	}

	/**
	 * @param array{plugins:array<string,array<string,array{count:int,total_ms:int,max_ms:int,samples:list<int>}>>} $stats
	 */
	public static function put_stats( array $stats ): void {
		$clean = self::sanitize_stats( $stats );
		if ( empty( $clean['plugins'] ) ) {
			delete_option( self::STATS_OPTION );

			return;
		}
		update_option( self::STATS_OPTION, $clean, false );
	}

	/**
	 * @return array{count:int,total_ms:int,max_ms:int,samples:list<int>}
	 */
	public static function empty_cell(): array {
		return array(
			'count'    => 0,
			'total_ms' => 0,
			'max_ms'   => 0,
			'samples'  => array(),
		);
	}

	/**
	 * @param array<string,mixed> $cell Cell.
	 * @return array{count:int,total_ms:int,max_ms:int,samples:list<int>}
	 */
	public static function sanitize_cell( array $cell ): array {
		$samples = array();
		if ( isset( $cell['samples'] ) && is_array( $cell['samples'] ) ) {
			foreach ( $cell['samples'] as $ms ) {
				if ( is_numeric( $ms ) ) {
					$samples[] = max( 0, (int) $ms );
				}
				if ( count( $samples ) >= self::SAMPLE_CAP ) {
					break;
				}
			}
		}

		return array(
			'count'    => max( 0, (int) ( $cell['count'] ?? 0 ) ),
			'total_ms' => max( 0, (int) ( $cell['total_ms'] ?? 0 ) ),
			'max_ms'   => max( 0, (int) ( $cell['max_ms'] ?? 0 ) ),
			'samples'  => $samples,
		);
	}

	/**
	 * @param list<int> $samples Durations ms.
	 */
	public static function p95_ms( array $samples ): int {
		$n = count( $samples );
		if ( $n <= 0 ) {
			return 0;
		}
		sort( $samples, SORT_NUMERIC );
		if ( class_exists( Latency::class, false ) && method_exists( Latency::class, 'percentile_ms' ) ) {
			return (int) Latency::percentile_ms( $samples, 95 );
		}
		$rank = (int) ceil( 0.95 * $n ) - 1;
		if ( $rank < 0 ) {
			$rank = 0;
		}
		if ( $rank >= $n ) {
			$rank = $n - 1;
		}

		return (int) $samples[ $rank ];
	}

	/**
	 * @param array{count?:int,total_ms?:int,max_ms?:int,samples?:list<int>} $cell Cell.
	 */
	public static function grade_for_cell( array $cell ): string {
		$count = (int) ( $cell['count'] ?? 0 );
		if ( $count <= 0 ) {
			return self::GRADE_INVISIBLE;
		}
		$p95 = self::p95_ms( array_values( (array) ( $cell['samples'] ?? array() ) ) );
		if ( $p95 < self::THRESHOLD_POLITE_MS ) {
			return self::GRADE_POLITE;
		}
		if ( $p95 < self::THRESHOLD_BLOCKING_MS ) {
			return self::GRADE_NOTICEABLE;
		}

		return self::GRADE_BLOCKING;
	}

	/**
	 * Front-surface grade for a plugin (INVISIBLE when no front samples).
	 */
	public static function grade_plugin( string $plugin, ?array $stats = null ): string {
		$stats = is_array( $stats ) ? $stats : self::get_stats();
		$plugin = sanitize_text_field( $plugin );
		$cell   = $stats['plugins'][ $plugin ][ self::SURFACE_FRONT ] ?? null;
		if ( ! is_array( $cell ) || (int) ( $cell['count'] ?? 0 ) <= 0 ) {
			return self::GRADE_INVISIBLE;
		}

		return self::grade_for_cell( $cell );
	}

	/**
	 * Primary roster: one row per plugin, graded by front-surface impact.
	 *
	 * @return list<array{
	 *   plugin:string,
	 *   grade:string,
	 *   front_calls:int,
	 *   visitor_seconds:float,
	 *   p95_ms:int,
	 *   max_ms:int,
	 *   admin_ms:int,
	 *   rest_ms:int,
	 *   cron_ms:int,
	 *   cli_ms:int
	 * }>
	 */
	public static function roster( ?array $stats = null ): array {
		$stats = is_array( $stats ) ? self::sanitize_stats( $stats ) : self::get_stats();
		$rows  = array();
		foreach ( $stats['plugins'] as $plugin => $surfaces ) {
			$front = isset( $surfaces[ self::SURFACE_FRONT ] ) ? self::sanitize_cell( $surfaces[ self::SURFACE_FRONT ] ) : self::empty_cell();
			$grade = ( (int) $front['count'] > 0 ) ? self::grade_for_cell( $front ) : self::GRADE_INVISIBLE;
			$p95   = ( (int) $front['count'] > 0 ) ? self::p95_ms( $front['samples'] ) : 0;
			$rows[] = array(
				'plugin'          => (string) $plugin,
				'grade'           => $grade,
				'front_calls'     => (int) $front['count'],
				'visitor_seconds' => round( ( (int) $front['total_ms'] ) / 1000.0, 3 ),
				'p95_ms'          => $p95,
				'max_ms'          => (int) $front['max_ms'],
				'admin_ms'        => (int) ( $surfaces[ self::SURFACE_ADMIN ]['total_ms'] ?? 0 ),
				'rest_ms'         => (int) ( $surfaces[ self::SURFACE_REST ]['total_ms'] ?? 0 ),
				'cron_ms'         => (int) ( $surfaces[ self::SURFACE_CRON ]['total_ms'] ?? 0 ),
				'cli_ms'          => (int) ( $surfaces[ self::SURFACE_CLI ]['total_ms'] ?? 0 ),
			);
		}
		usort(
			$rows,
			static function ( array $a, array $b ): int {
				$rank = array(
					self::GRADE_BLOCKING   => 0,
					self::GRADE_NOTICEABLE => 1,
					self::GRADE_POLITE     => 2,
					self::GRADE_INVISIBLE  => 3,
				);
				$ra = $rank[ $a['grade'] ] ?? 9;
				$rb = $rank[ $b['grade'] ] ?? 9;
				if ( $ra !== $rb ) {
					return $ra <=> $rb;
				}
				if ( (int) $a['p95_ms'] !== (int) $b['p95_ms'] ) {
					return (int) $b['p95_ms'] <=> (int) $a['p95_ms'];
				}

				return strcmp( (string) $a['plugin'], (string) $b['plugin'] );
			}
		);

		return $rows;
	}

	/**
	 * Secondary totals by surface (admin / rest / cron / cli).
	 *
	 * @return list<array{surface:string,calls:int,total_ms:int,max_ms:int}>
	 */
	public static function surface_totals( ?array $stats = null ): array {
		$stats = is_array( $stats ) ? self::sanitize_stats( $stats ) : self::get_stats();
		$out   = array();
		foreach ( array( self::SURFACE_ADMIN, self::SURFACE_REST, self::SURFACE_CRON, self::SURFACE_CLI ) as $surface ) {
			$calls = 0;
			$total = 0;
			$max   = 0;
			foreach ( $stats['plugins'] as $surfaces ) {
				if ( ! isset( $surfaces[ $surface ] ) || ! is_array( $surfaces[ $surface ] ) ) {
					continue;
				}
				$cell   = self::sanitize_cell( $surfaces[ $surface ] );
				$calls += (int) $cell['count'];
				$total += (int) $cell['total_ms'];
				$max    = max( $max, (int) $cell['max_ms'] );
			}
			$out[] = array(
				'surface'  => $surface,
				'calls'    => $calls,
				'total_ms' => $total,
				'max_ms'   => $max,
			);
		}

		return $out;
	}

	/**
	 * @return array<string,bool>
	 */
	public static function get_alerted(): array {
		$raw = get_option( self::ALERTED_OPTION, array() );
		if ( ! is_array( $raw ) ) {
			return array();
		}
		$out = array();
		foreach ( $raw as $fp => $flag ) {
			$fp = sanitize_text_field( (string) $fp );
			if ( '' === $fp ) {
				continue;
			}
			$out[ $fp ] = ! empty( $flag );
		}

		return $out;
	}

	/**
	 * @param array<string,bool> $alerted Fingerprints.
	 */
	public static function put_alerted( array $alerted ): void {
		$clean = array();
		foreach ( $alerted as $fp => $flag ) {
			$fp = sanitize_text_field( (string) $fp );
			if ( '' === $fp || empty( $flag ) ) {
				continue;
			}
			$clean[ $fp ] = true;
		}
		if ( empty( $clean ) ) {
			delete_option( self::ALERTED_OPTION );

			return;
		}
		update_option( self::ALERTED_OPTION, $clean, false );
	}

	public static function day_key( ?int $ts = null ): string {
		$ts = null !== $ts && $ts > 0 ? $ts : ( class_exists( Clock::class, false ) ? (int) Clock::now() : time() );

		return gmdate( 'Y-m-d', $ts );
	}

	public static function alert_fingerprint( string $plugin, string $day ): string {
		return sanitize_text_field( $plugin ) . '|' . sanitize_text_field( $day );
	}

	/**
	 * @param array{count?:int,total_ms?:int,max_ms?:int,samples?:list<int>} $cell Front cell.
	 */
	public static function maybe_alert_blocking( string $plugin, array $cell, ?int $now = null ): bool {
		if ( ! self::is_enabled() ) {
			return false;
		}
		$plugin = sanitize_text_field( $plugin );
		if ( '' === $plugin ) {
			return false;
		}
		if ( self::GRADE_BLOCKING !== self::grade_for_cell( $cell ) ) {
			return false;
		}
		$now = null !== $now && $now > 0 ? $now : ( class_exists( Clock::class, false ) ? (int) Clock::now() : time() );
		$day = self::day_key( $now );
		$fp  = self::alert_fingerprint( $plugin, $day );
		$alerted = self::get_alerted();
		if ( isset( $alerted[ $fp ] ) ) {
			return false;
		}
		if ( class_exists( Alert_Snooze::class, false )
			&& method_exists( Alert_Snooze::class, 'should_suppress' )
			&& Alert_Snooze::should_suppress( $plugin, self::ALERT_KIND, $now ) ) {
			return false;
		}
		$p95 = self::p95_ms( array_values( (array) ( $cell['samples'] ?? array() ) ) );
		$payload = array(
			'plugin' => $plugin,
			'day'    => $day,
			'p95_ms' => $p95,
			'max_ms' => (int) ( $cell['max_ms'] ?? 0 ),
			'count'  => (int) ( $cell['count'] ?? 0 ),
		);
		if ( ! self::fire_alert( $payload, $now ) ) {
			return false;
		}
		$alerted[ $fp ] = true;
		self::put_alerted( $alerted );

		return true;
	}

	/**
	 * @param array<string,mixed> $payload Alert payload.
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
		$plugin  = (string) ( $payload['plugin'] ?? '' );
		$p95     = (int) ( $payload['p95_ms'] ?? 0 );
		$subject = sprintf(
			/* translators: 1: plugin basename, 2: p95 ms */
			__( '[AICAC] Waiting room BLOCKING: %1$s (front p95 %2$dms)', 'handl-ai-connector-access-control' ),
			$plugin,
			$p95
		);
		$body  = __( 'A plugin’s front-surface AI calls crossed the BLOCKING threshold (visitor p95 ≥ 2s). This alert is informational and does not block calls.', 'handl-ai-connector-access-control' ) . "\n\n";
		$body .= 'plugin: ' . $plugin . "\n";
		$body .= 'front_p95_ms: ' . $p95 . "\n";
		$body .= 'front_max_ms: ' . (int) ( $payload['max_ms'] ?? 0 ) . "\n";
		$body .= 'front_calls: ' . (int) ( $payload['count'] ?? 0 ) . "\n";
		$body .= 'day: ' . (string) ( $payload['day'] ?? '' ) . "\n";
		$body .= 'screen: ' . self::admin_url_for_page() . "\n";

		$ok = false;
		if ( class_exists( Alerts::class, false ) && method_exists( Alerts::class, 'safe_wp_mail' ) ) {
			$ok = (bool) Alerts::safe_wp_mail( $email, $subject, $body );
		} elseif ( function_exists( 'wp_mail' ) ) {
			$ok = (bool) wp_mail( $email, $subject, $body );
		}
		self::$test_mails[] = array(
			'to'      => $email,
			'subject' => $subject,
			'body'    => $body,
		);
		if ( class_exists( Alerts::class, false ) && method_exists( Alerts::class, 'resolve_webhook' ) ) {
			$hook_url = (string) Alerts::resolve_webhook( $policy );
			if ( '' !== $hook_url && method_exists( Alerts::class, 'safe_wp_remote_post' ) ) {
				Alerts::safe_wp_remote_post(
					$hook_url,
					array(
						'type'     => 'handl_aicac_waiting_room_blocking',
						'plugin'   => $plugin,
						'p95_ms'   => $p95,
						'max_ms'   => (int) ( $payload['max_ms'] ?? 0 ),
						'count'    => (int) ( $payload['count'] ?? 0 ),
						'day'      => (string) ( $payload['day'] ?? '' ),
						'site'     => function_exists( 'home_url' ) ? home_url( '/' ) : '',
						'ts'       => $now,
					)
				);
			}
		}

		return $ok || ! empty( self::$test_mails );
	}

	public static function admin_url_for_page(): string {
		if ( function_exists( 'admin_url' ) ) {
			return (string) admin_url( 'admin.php?page=' . self::PAGE_SLUG );
		}

		return 'admin.php?page=' . self::PAGE_SLUG;
	}

	/**
	 * @param list<array<string,mixed>>|null $rows Roster.
	 */
	public static function csv_for_roster( ?array $rows = null ): string {
		$rows  = is_array( $rows ) ? $rows : self::roster();
		$lines = array();
		$lines[] = self::csv_line(
			array(
				'plugin',
				'grade',
				'front_calls',
				'visitor_seconds',
				'p95_ms',
				'max_ms',
				'admin_ms',
				'rest_ms',
				'cron_ms',
				'cli_ms',
			)
		);
		foreach ( $rows as $row ) {
			$lines[] = self::csv_line(
				array(
					(string) ( $row['plugin'] ?? '' ),
					(string) ( $row['grade'] ?? '' ),
					(string) (int) ( $row['front_calls'] ?? 0 ),
					(string) (float) ( $row['visitor_seconds'] ?? 0 ),
					(string) (int) ( $row['p95_ms'] ?? 0 ),
					(string) (int) ( $row['max_ms'] ?? 0 ),
					(string) (int) ( $row['admin_ms'] ?? 0 ),
					(string) (int) ( $row['rest_ms'] ?? 0 ),
					(string) (int) ( $row['cron_ms'] ?? 0 ),
					(string) (int) ( $row['cli_ms'] ?? 0 ),
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
			$col = (string) $col;
			if ( false !== strpos( $col, '"' ) || false !== strpos( $col, ',' ) || false !== strpos( $col, "\n" ) ) {
				$col = '"' . str_replace( '"', '""', $col ) . '"';
			}
			$out[] = $col;
		}

		return implode( ',', $out );
	}

	/**
	 * @param list<array<string,mixed>> $rows Roster.
	 */
	public static function build_print_html( array $rows ): string {
		$html  = '<!DOCTYPE html><html><head><meta charset="utf-8"><title>';
		$html .= esc_html__( 'Waiting room roster', 'handl-ai-connector-access-control' );
		$html .= '</title><style>body{font-family:sans-serif;margin:24px}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ccc;padding:6px 8px;text-align:left}th{background:#f6f7f7}</style></head><body>';
		$html .= '<h1>' . esc_html__( 'Waiting room roster', 'handl-ai-connector-access-control' ) . '</h1>';
		$html .= '<p>' . esc_html__( 'Front-surface visitor waits graded by p95. Informational — never denies.', 'handl-ai-connector-access-control' ) . '</p>';
		$html .= '<table><thead><tr>';
		$html .= '<th>' . esc_html__( 'Plugin', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '<th>' . esc_html__( 'Grade', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '<th>' . esc_html__( 'Front calls', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '<th>' . esc_html__( 'Visitor-seconds', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '<th>' . esc_html__( 'p95 (ms)', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '<th>' . esc_html__( 'Worst (ms)', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '</tr></thead><tbody>';
		foreach ( $rows as $row ) {
			$html .= '<tr>';
			$html .= '<td>' . esc_html( (string) ( $row['plugin'] ?? '' ) ) . '</td>';
			$html .= '<td>' . esc_html( (string) ( $row['grade'] ?? '' ) ) . '</td>';
			$html .= '<td>' . esc_html( (string) (int) ( $row['front_calls'] ?? 0 ) ) . '</td>';
			$html .= '<td>' . esc_html( (string) (float) ( $row['visitor_seconds'] ?? 0 ) ) . '</td>';
			$html .= '<td>' . esc_html( (string) (int) ( $row['p95_ms'] ?? 0 ) ) . '</td>';
			$html .= '<td>' . esc_html( (string) (int) ( $row['max_ms'] ?? 0 ) ) . '</td>';
			$html .= '</tr>';
		}
		$html .= '</tbody></table></body></html>';

		return $html;
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
			__( 'Waiting room', 'handl-ai-connector-access-control' ),
			__( 'Waiting room', 'handl-ai-connector-access-control' ),
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
		$enabled    = ! empty( $settings['enabled'] );
		$rows       = $enabled ? self::roster() : array();
		$totals     = $enabled ? self::surface_totals() : array();
		$csv        = add_query_arg(
			array(
				'page'                         => self::PAGE_SLUG,
				'handl_aicac_waiting_room_csv' => '1',
				'_wpnonce'                     => function_exists( 'wp_create_nonce' ) ? wp_create_nonce( 'handl_aicac_waiting_room_csv' ) : '',
			),
			admin_url( 'admin.php' )
		);
		$print = add_query_arg(
			array(
				'page'                           => self::PAGE_SLUG,
				'handl_aicac_waiting_room_print' => '1',
				'_wpnonce'                       => function_exists( 'wp_create_nonce' ) ? wp_create_nonce( 'handl_aicac_waiting_room_print' ) : '',
			),
			admin_url( 'admin.php' )
		);

		echo '<div class="wrap">';
		echo '<h1>' . esc_html__( 'Waiting room', 'handl-ai-connector-access-control' ) . '</h1>';
		echo '<p class="description">' . esc_html__( 'Who makes visitors wait on AI — front vs admin vs cron — graded by front-surface p95. Timing only; never blocks or delays a call. Off by default.', 'handl-ai-connector-access-control' ) . '</p>';

		if ( $can_manage ) {
			$action = admin_url( 'admin-post.php' );
			echo '<form method="post" action="' . esc_url( $action ) . '">';
			echo '<input type="hidden" name="action" value="' . esc_attr( self::ACTION_SAVE ) . '" />';
			if ( function_exists( 'wp_nonce_field' ) ) {
				wp_nonce_field( self::ACTION_SAVE );
			}
			echo '<input type="hidden" name="' . esc_attr( self::POST_PRESENT ) . '" value="1" />';
			echo '<table class="form-table" role="presentation"><tbody>';
			echo '<tr><th scope="row">' . esc_html__( 'Enable waiting room', 'handl-ai-connector-access-control' ) . '</th><td>';
			echo '<label><input type="checkbox" name="' . esc_attr( self::POST_ENABLED ) . '" value="1" ' . checked( $enabled, true, false ) . ' /> ';
			echo esc_html__( 'Time AI Client calls by request surface and grade front-end visitor waits', 'handl-ai-connector-access-control' );
			echo '</label></td></tr></tbody></table>';
			submit_button( __( 'Save waiting room settings', 'handl-ai-connector-access-control' ) );
			echo '</form>';
		}

		if ( ! $enabled ) {
			echo '<p>' . esc_html__( 'Waiting room is off. Enable it to census who waits on AI and how long visitors stare at a spinner.', 'handl-ai-connector-access-control' ) . '</p>';
			echo '</div>';

			return;
		}

		echo '<p class="description">' . esc_html__( 'Grades (front surface p95): INVISIBLE = no front samples · POLITE &lt; 300ms · NOTICEABLE &lt; 2s · BLOCKING ≥ 2s.', 'handl-ai-connector-access-control' ) . '</p>';

		echo '<h2>' . esc_html__( 'By plugin (front impact)', 'handl-ai-connector-access-control' ) . '</h2>';
		echo '<p>';
		echo '<a class="button" href="' . esc_url( $csv ) . '">' . esc_html__( 'Download CSV', 'handl-ai-connector-access-control' ) . '</a> ';
		echo '<a class="button" href="' . esc_url( $print ) . '" target="_blank" rel="noopener noreferrer">' . esc_html__( 'Print / PDF view', 'handl-ai-connector-access-control' ) . '</a>';
		echo '</p>';

		if ( empty( $rows ) ) {
			echo '<p>' . esc_html__( 'No timed samples yet. Enable the census and wait for AI Client generations.', 'handl-ai-connector-access-control' ) . '</p>';
		} else {
			echo '<table class="widefat striped"><thead><tr>';
			echo '<th>' . esc_html__( 'Plugin', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Grade', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Front calls', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Visitor-seconds', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'p95 (ms)', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Worst wait (ms)', 'handl-ai-connector-access-control' ) . '</th>';
			echo '</tr></thead><tbody>';
			foreach ( $rows as $row ) {
				echo '<tr>';
				echo '<td><code>' . esc_html( (string) $row['plugin'] ) . '</code></td>';
				echo '<td>' . esc_html( (string) $row['grade'] ) . '</td>';
				echo '<td>' . esc_html( (string) (int) $row['front_calls'] ) . '</td>';
				echo '<td>' . esc_html( (string) (float) $row['visitor_seconds'] ) . '</td>';
				echo '<td>' . esc_html( (string) (int) $row['p95_ms'] ) . '</td>';
				echo '<td>' . esc_html( (string) (int) $row['max_ms'] ) . '</td>';
				echo '</tr>';
			}
			echo '</tbody></table>';
		}

		echo '<h2>' . esc_html__( 'Other surfaces (totals)', 'handl-ai-connector-access-control' ) . '</h2>';
		echo '<table class="widefat striped"><thead><tr>';
		echo '<th>' . esc_html__( 'Surface', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Calls', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Total ms', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Max ms', 'handl-ai-connector-access-control' ) . '</th>';
		echo '</tr></thead><tbody>';
		foreach ( $totals as $row ) {
			echo '<tr>';
			echo '<td>' . esc_html( (string) $row['surface'] ) . '</td>';
			echo '<td>' . esc_html( (string) (int) $row['calls'] ) . '</td>';
			echo '<td>' . esc_html( (string) (int) $row['total_ms'] ) . '</td>';
			echo '<td>' . esc_html( (string) (int) $row['max_ms'] ) . '</td>';
			echo '</tr>';
		}
		echo '</tbody></table>';
		echo '</div>';
	}

	public static function handle_save(): void {
		if ( ! Caps::user_can_manage() ) {
			wp_die( esc_html__( 'You cannot manage waiting room settings.', 'handl-ai-connector-access-control' ) );
		}
		check_admin_referer( self::ACTION_SAVE );
		$enabled = ! empty( $_POST[ self::POST_ENABLED ] ); // phpcs:ignore WordPress.Security.NonceVerification.Missing
		self::save_settings( array( 'enabled' => $enabled ) );
		if ( self::is_enabled() ) {
			self::register_timing_hooks();
		}
		wp_safe_redirect( self::admin_url_for_page() );
		exit;
	}

	public static function maybe_handle_csv(): void {
		if ( empty( $_GET['handl_aicac_waiting_room_csv'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			return;
		}
		$page = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( (string) $_GET['page'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( self::PAGE_SLUG !== $page ) {
			return;
		}
		if ( ! Caps::user_can_view() ) {
			wp_die( esc_html__( 'You cannot export waiting room CSV.', 'handl-ai-connector-access-control' ) );
		}
		check_admin_referer( 'handl_aicac_waiting_room_csv' );
		$csv = self::csv_for_roster();
		nocache_headers();
		header( 'Content-Type: text/csv; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename=aicac-waiting-room.csv' );
		echo $csv; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		exit;
	}

	public static function maybe_handle_print(): void {
		if ( empty( $_GET['handl_aicac_waiting_room_print'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			return;
		}
		$page = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( (string) $_GET['page'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( self::PAGE_SLUG !== $page ) {
			return;
		}
		if ( ! Caps::user_can_view() ) {
			wp_die( esc_html__( 'You cannot print waiting room.', 'handl-ai-connector-access-control' ) );
		}
		check_admin_referer( 'handl_aicac_waiting_room_print' );
		nocache_headers();
		header( 'Content-Type: text/html; charset=utf-8' );
		echo self::build_print_html( self::roster() ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		exit;
	}

	private static function now_ns(): int {
		if ( function_exists( 'hrtime' ) ) {
			$t = hrtime( true );
			if ( is_int( $t ) ) {
				return $t;
			}
		}

		return (int) round( microtime( true ) * 1e9 );
	}
}
