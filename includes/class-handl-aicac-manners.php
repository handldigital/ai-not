<?php
/**
 * AICAC-MANNERS (#451): post-deny retry etiquette census.
 *
 * Soft-reads deny history and grades each connector (>=2 denies in lookback)
 * as HAMMER / PERSISTENT / BACKOFF / WENT-QUIET. Read-only trust signal —
 * never writes policy, alerts, or the activity log. Hourly transient cache.
 *
 * README-FREE. Distinct from Retry_Storm (suppression) and COLDCASE (single deny).
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Per-connector post-deny manners grades.
 */
final class Manners {

	public const PAGE_SLUG = 'handl-aicac-manners';

	public const TRANSIENT_KEY = 'handl_aicac_manners_cache';

	public const CACHE_TTL = 3600;

	public const LOOKBACK_DAYS = 14;

	public const HAMMER_MEDIAN_SECONDS = 10;

	public const BACKOFF_RATIO = 2.0;

	public const QUIET_SECONDS = 3600;

	public const GRADE_HAMMER     = 'HAMMER';
	public const GRADE_PERSISTENT = 'PERSISTENT';
	public const GRADE_BACKOFF    = 'BACKOFF';
	public const GRADE_WENT_QUIET = 'WENT-QUIET';

	/** @var bool */
	private static $registered = false;

	/** @var int|null */
	private static $test_now = null;

	/** @var list<array<string,mixed>>|null */
	private static $test_log = null;

	/** @var bool */
	private static $skip_cache = false;

	public static function init(): void {
		if ( self::$registered ) {
			return;
		}
		self::$registered = true;
		add_action( 'admin_menu', array( self::class, 'register_menu' ), 20 );
	}

	public static function reset_for_tests(): void {
		self::$registered = false;
		self::$test_now   = null;
		self::$test_log   = null;
		self::$skip_cache = false;
		delete_transient( self::TRANSIENT_KEY );
	}

	public static function set_test_now( ?int $now ): void {
		self::$test_now = $now;
	}

	/**
	 * @param list<array<string,mixed>>|null $log Injected activity rows.
	 */
	public static function set_test_log( ?array $log ): void {
		self::$test_log = $log;
	}

	public static function set_skip_cache( bool $skip ): void {
		self::$skip_cache = $skip;
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

	/**
	 * Pure classifier. $deny_ts must be sorted ascending, length >= 2.
	 *
	 * @param list<int> $deny_ts Deny timestamps for one connector.
	 */
	public static function classify( array $deny_ts, int $now ): string {
		$ts = array();
		foreach ( $deny_ts as $t ) {
			$t = (int) $t;
			if ( $t > 0 ) {
				$ts[] = $t;
			}
		}
		sort( $ts, SORT_NUMERIC );
		if ( count( $ts ) < 2 ) {
			return self::GRADE_PERSISTENT;
		}

		$gaps = array();
		$n    = count( $ts );
		for ( $i = 1; $i < $n; $i++ ) {
			$gaps[] = max( 0, $ts[ $i ] - $ts[ $i - 1 ] );
		}

		$last    = $ts[ $n - 1 ];
		$silence = max( 0, $now - $last );
		if ( $silence >= self::QUIET_SECONDS ) {
			return self::GRADE_WENT_QUIET;
		}

		$median = self::median( $gaps );
		if ( $median < self::HAMMER_MEDIAN_SECONDS ) {
			return self::GRADE_HAMMER;
		}

		$first_gap = $gaps[0];
		$last_gap  = $gaps[ count( $gaps ) - 1 ];
		if ( $first_gap > 0 && ( $last_gap / $first_gap ) >= self::BACKOFF_RATIO ) {
			return self::GRADE_BACKOFF;
		}

		return self::GRADE_PERSISTENT;
	}

	/**
	 * @param list<int|float> $values Values.
	 */
	public static function median( array $values ): float {
		$n = count( $values );
		if ( 0 === $n ) {
			return 0.0;
		}
		$sorted = array_values( $values );
		sort( $sorted, SORT_NUMERIC );
		$mid = (int) floor( $n / 2 );
		if ( 0 === $n % 2 ) {
			return ( (float) $sorted[ $mid - 1 ] + (float) $sorted[ $mid ] ) / 2.0;
		}

		return (float) $sorted[ $mid ];
	}

	/**
	 * Cadence trend label from gaps.
	 *
	 * @param list<int> $gaps Inter-deny gaps.
	 */
	public static function cadence_trend( array $gaps ): string {
		if ( count( $gaps ) < 1 ) {
			return 'n/a';
		}
		if ( count( $gaps ) < 2 ) {
			return 'flat';
		}
		$first = (float) $gaps[0];
		$last  = (float) $gaps[ count( $gaps ) - 1 ];
		if ( $first <= 0 ) {
			return 'flat';
		}
		$ratio = $last / $first;
		if ( $ratio >= self::BACKOFF_RATIO ) {
			return 'growing';
		}
		if ( $ratio <= ( 1.0 / self::BACKOFF_RATIO ) ) {
			return 'shrinking';
		}

		return 'flat';
	}

	/**
	 * Guarded activity-log soft-read.
	 *
	 * @return array{rows:list<array<string,mixed>>,available:bool}
	 */
	public static function read_activity_log(): array {
		if ( null !== self::$test_log ) {
			return array(
				'rows'      => array_values( self::$test_log ),
				'available' => true,
			);
		}
		$key = class_exists( Plugin::class, false ) ? Plugin::LOG_OPTION_KEY : 'handl_aicac_recent_calls';
		$raw = get_option( $key, null );
		if ( null === $raw || false === $raw || ! is_array( $raw ) ) {
			return array(
				'rows'      => array(),
				'available' => false,
			);
		}
		$rows = array();
		foreach ( $raw as $row ) {
			if ( is_array( $row ) ) {
				$rows[] = $row;
			}
		}

		return array(
			'rows'      => $rows,
			'available' => true,
		);
	}

	/**
	 * @param array<string,mixed> $row Activity row.
	 */
	public static function connector_key( array $row ): string {
		$plugin = isset( $row['plugin'] ) ? trim( (string) $row['plugin'] ) : '';
		$plugin = strtolower( $plugin );
		if ( '' !== $plugin ) {
			return $plugin;
		}
		$reason = isset( $row['denial_reason'] ) ? sanitize_key( (string) $row['denial_reason'] ) : '';

		return '' !== $reason ? 'reason:' . $reason : 'unknown';
	}

	/**
	 * Build graded rows from soft-read history (no cache write).
	 *
	 * @return list<array{
	 *   connector:string,
	 *   deny_count:int,
	 *   median_gap:float,
	 *   cadence:string,
	 *   grade:string,
	 *   last_seen:int
	 * }>
	 */
	public static function grade_connectors( ?int $now = null ): array {
		$now      = null !== $now && $now > 0 ? $now : self::now();
		$day      = defined( 'DAY_IN_SECONDS' ) ? DAY_IN_SECONDS : 86400;
		$cutoff   = $now - ( self::LOOKBACK_DAYS * $day );
		$pack     = self::read_activity_log();
		/** @var array<string,list<int>> $by */
		$by = array();

		foreach ( $pack['rows'] as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			if ( 'deny' !== (string) ( $row['decision'] ?? '' ) ) {
				continue;
			}
			$ts = isset( $row['ts'] ) ? (int) $row['ts'] : 0;
			if ( $ts < $cutoff || $ts > $now ) {
				continue;
			}
			$key = self::connector_key( $row );
			$by[ $key ][] = $ts;
		}

		$out = array();
		foreach ( $by as $connector => $timestamps ) {
			sort( $timestamps, SORT_NUMERIC );
			// Dedupe identical timestamps so a single second doesn't invent a 0-gap hammer.
			$uniq = array();
			$prev = null;
			foreach ( $timestamps as $t ) {
				if ( $prev === $t ) {
					continue;
				}
				$uniq[] = $t;
				$prev   = $t;
			}
			if ( count( $uniq ) < 2 ) {
				continue;
			}

			$gaps = array();
			for ( $i = 1, $n = count( $uniq ); $i < $n; $i++ ) {
				$gaps[] = $uniq[ $i ] - $uniq[ $i - 1 ];
			}
			$grade  = self::classify( $uniq, $now );
			$out[]  = array(
				'connector'  => $connector,
				'deny_count' => count( $uniq ),
				'median_gap' => self::median( $gaps ),
				'cadence'    => self::cadence_trend( $gaps ),
				'grade'      => $grade,
				'last_seen'  => (int) $uniq[ count( $uniq ) - 1 ],
			);
		}

		usort(
			$out,
			static function ( array $a, array $b ): int {
				$order = array(
					self::GRADE_HAMMER     => 0,
					self::GRADE_PERSISTENT => 1,
					self::GRADE_BACKOFF    => 2,
					self::GRADE_WENT_QUIET => 3,
				);
				$ga = $order[ $a['grade'] ] ?? 9;
				$gb = $order[ $b['grade'] ] ?? 9;
				if ( $ga !== $gb ) {
					return $ga <=> $gb;
				}
				if ( $a['deny_count'] !== $b['deny_count'] ) {
					return $b['deny_count'] <=> $a['deny_count'];
				}

				return strcmp( (string) $a['connector'], (string) $b['connector'] );
			}
		);

		return $out;
	}

	/**
	 * Snapshot with hourly transient cache (skipped in tests when set_skip_cache).
	 *
	 * @return array{
	 *   as_of:int,
	 *   lookback_days:int,
	 *   rows:list<array<string,mixed>>,
	 *   log_available:bool,
	 *   cached:bool
	 * }
	 */
	public static function snapshot( ?int $now = null ): array {
		$now = null !== $now && $now > 0 ? $now : self::now();

		if ( ! self::$skip_cache ) {
			$cached = get_transient( self::TRANSIENT_KEY );
			if ( is_array( $cached ) && isset( $cached['as_of'], $cached['rows'] ) && is_array( $cached['rows'] ) ) {
				return array(
					'as_of'          => (int) $cached['as_of'],
					'lookback_days'  => self::LOOKBACK_DAYS,
					'rows'           => $cached['rows'],
					'log_available'  => ! empty( $cached['log_available'] ),
					'cached'         => true,
				);
			}
		}

		$pack = self::read_activity_log();
		$rows = self::grade_connectors( $now );
		$snap = array(
			'as_of'         => $now,
			'lookback_days' => self::LOOKBACK_DAYS,
			'rows'          => $rows,
			'log_available' => ! empty( $pack['available'] ),
			'cached'        => false,
		);

		if ( ! self::$skip_cache ) {
			set_transient(
				self::TRANSIENT_KEY,
				array(
					'as_of'         => $now,
					'rows'          => $rows,
					'log_available' => ! empty( $pack['available'] ),
				),
				self::CACHE_TTL
			);
		}

		return $snap;
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
			__( 'Manners', 'handl-ai-connector-access-control' ),
			__( 'Manners', 'handl-ai-connector-access-control' ),
			Caps::VIEW,
			self::PAGE_SLUG,
			array( self::class, 'render_page' )
		);
	}

	public static function render_page(): void {
		if ( ! class_exists( Caps::class, false ) || ! Caps::user_can_view() ) {
			return;
		}
		$snap = self::snapshot();

		echo '<div class="wrap">';
		echo '<h1>' . esc_html__( 'Manners', 'handl-ai-connector-access-control' ) . '</h1>';
		echo '<p class="description">' . esc_html__( 'How each AI connector takes “no” after a deny — hammer, grind, back off, or go quiet. Read-only census; never changes allow/deny rules.', 'handl-ai-connector-access-control' ) . '</p>';

		echo '<ul class="ul-disc">';
		echo '<li><strong>' . esc_html__( 'HAMMER', 'handl-ai-connector-access-control' ) . '</strong> — ' . esc_html__( 'Median retry gap under 10 seconds.', 'handl-ai-connector-access-control' ) . '</li>';
		echo '<li><strong>' . esc_html__( 'PERSISTENT', 'handl-ai-connector-access-control' ) . '</strong> — ' . esc_html__( 'Steady cadence with no clear backoff.', 'handl-ai-connector-access-control' ) . '</li>';
		echo '<li><strong>' . esc_html__( 'BACKOFF', 'handl-ai-connector-access-control' ) . '</strong> — ' . esc_html__( 'Gaps grow about 2× or more (polite).', 'handl-ai-connector-access-control' ) . '</li>';
		echo '<li><strong>' . esc_html__( 'WENT-QUIET', 'handl-ai-connector-access-control' ) . '</strong> — ' . esc_html__( 'At least two denies, then stopped retrying for an hour or more.', 'handl-ai-connector-access-control' ) . '</li>';
		echo '</ul>';

		if ( empty( $snap['rows'] ) ) {
			echo '<p>' . esc_html__( 'No connectors with two or more denies in the lookback window yet. Grades appear once retry patterns show up in the activity log.', 'handl-ai-connector-access-control' ) . '</p>';
			echo '</div>';

			return;
		}

		echo '<table class="widefat striped"><thead><tr>';
		echo '<th>' . esc_html__( 'Connector', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Denies', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Median gap', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Cadence', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Grade', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Last seen', 'handl-ai-connector-access-control' ) . '</th>';
		echo '</tr></thead><tbody>';

		foreach ( $snap['rows'] as $row ) {
			$gap = (float) $row['median_gap'];
			$gap_label = $gap < 60
				? sprintf( '%ds', (int) round( $gap ) )
				: sprintf( '%dm', (int) round( $gap / 60 ) );
			$when = function_exists( 'wp_date' )
				? wp_date( 'Y-m-d H:i', (int) $row['last_seen'] )
				: gmdate( 'Y-m-d H:i', (int) $row['last_seen'] );

			echo '<tr>';
			echo '<td>' . esc_html( (string) $row['connector'] ) . '</td>';
			echo '<td>' . esc_html( (string) (int) $row['deny_count'] ) . '</td>';
			echo '<td>' . esc_html( $gap_label ) . '</td>';
			echo '<td>' . esc_html( (string) $row['cadence'] ) . '</td>';
			echo '<td>' . esc_html( (string) $row['grade'] ) . '</td>';
			echo '<td>' . esc_html( (string) $when ) . '</td>';
			echo '</tr>';
		}
		echo '</tbody></table>';
		echo '</div>';
	}
}
