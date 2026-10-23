<?php
/**
 * AICAC-CHATTERBOX (#472): per-request AI fan-out census.
 *
 * Soft-reads recent-calls and clusters same-plugin calls into bursts
 * (inter-call gap <= GAP_SECONDS). Grades SOLO / TALKATIVE / CHATTERBOX /
 * INSUFFICIENT-DATA. Distinguishes multi-endpoint fan-out from same-endpoint
 * hammering (Retry-storm note only — never re-implements retry detection).
 *
 * README-FREE. Zero option writes. Own admin screen.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Burst-amplification census (report-only).
 */
final class Chatterbox {

	public const PAGE_SLUG = 'handl-aicac-chatterbox';

	/** Max seconds between consecutive same-plugin calls to stay in one burst. */
	public const GAP_SECONDS = 5;

	public const GRADE_SOLO         = 'SOLO';
	public const GRADE_TALKATIVE    = 'TALKATIVE';
	public const GRADE_CHATTERBOX   = 'CHATTERBOX';
	public const GRADE_INSUFFICIENT = 'INSUFFICIENT-DATA';

	/** Minimum logged calls before a plugin earns a burst grade (else INSUFFICIENT-DATA). */
	public const MIN_CALLS = 2;

	public const MAX_ROWS = 200;

	/** @var bool */
	private static $registered = false;

	/** @var int|null */
	private static $test_now = null;

	/** @var list<array<string,mixed>>|null */
	private static $test_log = null;

	/** @var bool|null Force log-available flag in tests; null = derive. */
	private static $test_log_available = null;

	public static function init(): void {
		if ( self::$registered ) {
			return;
		}
		self::$registered = true;
		add_action( 'admin_menu', array( self::class, 'register_menu' ), 20 );
	}

	public static function reset_for_tests(): void {
		self::$registered         = false;
		self::$test_now           = null;
		self::$test_log           = null;
		self::$test_log_available = null;
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

	public static function set_test_log_available( ?bool $available ): void {
		self::$test_log_available = $available;
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
	 * Soft-read of activity log. Never writes.
	 *
	 * @return array{rows:list<array<string,mixed>>,available:bool}
	 */
	public static function read_activity_log(): array {
		if ( null !== self::$test_log ) {
			$available = null === self::$test_log_available ? true : (bool) self::$test_log_available;

			return array(
				'rows'      => array_values( self::$test_log ),
				'available' => $available,
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
	 * Endpoint identity for fan-out vs same-endpoint hammering.
	 * Prefer host; else provider|operation|model (no plugin — compared inside a plugin).
	 *
	 * @param array<string,mixed> $row Activity row.
	 */
	public static function endpoint_key( array $row ): string {
		$host = strtolower( trim( (string) ( $row['host'] ?? '' ) ) );
		if ( '' !== $host ) {
			return $host;
		}
		$provider = strtolower( trim( (string) ( $row['provider'] ?? '' ) ) );
		$op       = sanitize_key( (string) ( $row['operation'] ?? '' ) );
		if ( '' === $op ) {
			$op = sanitize_key( (string) ( $row['capability'] ?? '' ) );
		}
		$model = strtolower( trim( (string) ( $row['model'] ?? '' ) ) );
		$parts = array( $provider, $op, $model );
		$joined = implode( '|', $parts );

		return '' !== trim( $joined, '|' ) ? $joined : 'unknown';
	}

	public static function sanitize_plugin( string $basename ): string {
		if ( class_exists( Plugin_Profile::class, false ) && method_exists( Plugin_Profile::class, 'sanitize_plugin' ) ) {
			return Plugin_Profile::sanitize_plugin( $basename );
		}
		$basename = str_replace( '\\', '/', $basename );
		$basename = ltrim( $basename, '/' );

		return sanitize_text_field( $basename );
	}

	/**
	 * @param list<int> $sizes Burst sizes (>=1 each).
	 */
	public static function median_int( array $sizes ): int {
		$sizes = array_values( array_filter( array_map( 'intval', $sizes ), static function ( int $n ): bool {
			return $n > 0;
		} ) );
		$count = count( $sizes );
		if ( 0 === $count ) {
			return 0;
		}
		sort( $sizes, SORT_NUMERIC );
		$mid = (int) floor( ( $count - 1 ) / 2 );
		if ( 0 === $count % 2 ) {
			return (int) floor( ( $sizes[ $mid ] + $sizes[ $mid + 1 ] ) / 2 );
		}

		return (int) $sizes[ $mid ];
	}

	/**
	 * Pure grade from max burst size + call count.
	 */
	public static function classify( int $calls, int $max_burst ): string {
		if ( $calls < self::MIN_CALLS ) {
			return self::GRADE_INSUFFICIENT;
		}
		if ( $max_burst >= 5 ) {
			return self::GRADE_CHATTERBOX;
		}
		if ( $max_burst >= 2 ) {
			return self::GRADE_TALKATIVE;
		}

		return self::GRADE_SOLO;
	}

	/**
	 * Cluster chronological same-plugin calls into bursts.
	 *
	 * @param list<array{ts:int,endpoint:string}> $calls Sorted by ts ascending.
	 * @return list<array{size:int,endpoints:list<string>,start:int,end:int}>
	 */
	public static function cluster_bursts( array $calls, int $gap_seconds = self::GAP_SECONDS ): array {
		$gap_seconds = max( 0, $gap_seconds );
		$bursts      = array();
		$current     = null;

		foreach ( $calls as $call ) {
			$ts  = (int) ( $call['ts'] ?? 0 );
			$ep  = (string) ( $call['endpoint'] ?? 'unknown' );
			if ( $ts <= 0 ) {
				continue;
			}
			if ( null === $current ) {
				$current = array(
					'size'      => 1,
					'endpoints' => array( $ep ),
					'start'     => $ts,
					'end'       => $ts,
				);
				continue;
			}
			if ( ( $ts - (int) $current['end'] ) <= $gap_seconds ) {
				++$current['size'];
				$current['endpoints'][] = $ep;
				$current['end']         = $ts;
				continue;
			}
			$bursts[] = $current;
			$current  = array(
				'size'      => 1,
				'endpoints' => array( $ep ),
				'start'     => $ts,
				'end'       => $ts,
			);
		}
		if ( null !== $current ) {
			$bursts[] = $current;
		}

		return $bursts;
	}

	/**
	 * @return array{available:bool,rows:list<array<string,mixed>>}
	 */
	public static function census(): array {
		$pack = self::read_activity_log();
		if ( ! $pack['available'] ) {
			return array(
				'available' => false,
				'rows'      => array(),
			);
		}

		/** @var array<string,list<array{ts:int,endpoint:string}>> $by_plugin */
		$by_plugin = array();
		foreach ( $pack['rows'] as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$plugin = self::sanitize_plugin( (string) ( $row['plugin'] ?? '' ) );
			if ( '' === $plugin ) {
				continue;
			}
			$ts = isset( $row['ts'] ) ? (int) $row['ts'] : 0;
			if ( $ts <= 0 ) {
				continue;
			}
			if ( ! isset( $by_plugin[ $plugin ] ) ) {
				$by_plugin[ $plugin ] = array();
			}
			$by_plugin[ $plugin ][] = array(
				'ts'       => $ts,
				'endpoint' => self::endpoint_key( $row ),
			);
		}

		$rows = array();
		foreach ( $by_plugin as $plugin => $calls ) {
			usort(
				$calls,
				static function ( array $a, array $b ): int {
					return $a['ts'] <=> $b['ts'];
				}
			);
			$bursts = self::cluster_bursts( $calls, self::GAP_SECONDS );
			$sizes  = array();
			foreach ( $bursts as $burst ) {
				$sizes[] = (int) $burst['size'];
			}
			$max_burst = array() === $sizes ? 0 : max( $sizes );
			$median    = self::median_int( $sizes );
			$calls_n   = count( $calls );
			$grade     = self::classify( $calls_n, $max_burst );

			$largest           = null;
			$largest_distinct  = 0;
			foreach ( $bursts as $burst ) {
				if ( null === $largest || (int) $burst['size'] > (int) $largest['size'] ) {
					$largest = $burst;
				}
			}
			if ( null !== $largest ) {
				$largest_distinct = count( array_unique( $largest['endpoints'] ) );
			}

			$fan_out     = $largest_distinct >= 2;
			$same_endpoint = ( null !== $largest && (int) $largest['size'] >= 2 && $largest_distinct < 2 );
			$note        = '';
			if ( $same_endpoint ) {
				$note = __( 'Same endpoint in burst — see Retry-storm for failure/repeat storms.', 'handl-ai-connector-access-control' );
			} elseif ( $fan_out ) {
				$note = __( 'Multi-endpoint fan-out inside the largest burst.', 'handl-ai-connector-access-control' );
			}

			$rows[] = array(
				'plugin'            => $plugin,
				'calls'             => $calls_n,
				'bursts'            => count( $bursts ),
				'max_burst'         => $max_burst,
				'median_burst'      => $median,
				'largest_endpoints' => $largest_distinct,
				'fan_out'           => $fan_out,
				'same_endpoint'     => $same_endpoint,
				'grade'             => $grade,
				'note'              => $note,
			);
			if ( count( $rows ) >= self::MAX_ROWS ) {
				break;
			}
		}

		usort(
			$rows,
			static function ( array $a, array $b ): int {
				$order = array(
					self::GRADE_CHATTERBOX   => 0,
					self::GRADE_TALKATIVE    => 1,
					self::GRADE_SOLO         => 2,
					self::GRADE_INSUFFICIENT => 3,
				);
				$ga = $order[ $a['grade'] ] ?? 9;
				$gb = $order[ $b['grade'] ] ?? 9;
				if ( $ga !== $gb ) {
					return $ga <=> $gb;
				}
				if ( (int) $a['max_burst'] !== (int) $b['max_burst'] ) {
					return (int) $b['max_burst'] <=> (int) $a['max_burst'];
				}

				return strcmp( (string) $a['plugin'], (string) $b['plugin'] );
			}
		);

		return array(
			'available' => true,
			'rows'      => $rows,
		);
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
			__( 'Chatterbox', 'handl-ai-connector-access-control' ),
			__( 'Chatterbox', 'handl-ai-connector-access-control' ),
			Caps::VIEW,
			self::PAGE_SLUG,
			array( self::class, 'render_page' )
		);
	}

	public static function render_page(): void {
		if ( ! class_exists( Caps::class, false ) || ! Caps::user_can_view() ) {
			return;
		}
		$data = self::census();

		echo '<div class="wrap">';
		echo '<h1>' . esc_html__( 'Chatterbox', 'handl-ai-connector-access-control' ) . '</h1>';
		echo '<p class="description">' . esc_html__( 'How many AI calls one burst costs. Report only — this screen never changes policy or the activity log.', 'handl-ai-connector-access-control' ) . '</p>';

		echo '<ul class="ul-disc">';
		echo '<li><strong>' . esc_html__( 'SOLO', 'handl-ai-connector-access-control' ) . '</strong> — ' . esc_html__( 'Largest burst is a single call.', 'handl-ai-connector-access-control' ) . '</li>';
		echo '<li><strong>' . esc_html__( 'TALKATIVE', 'handl-ai-connector-access-control' ) . '</strong> — ' . esc_html__( 'Largest burst is 2–4 calls.', 'handl-ai-connector-access-control' ) . '</li>';
		echo '<li><strong>' . esc_html__( 'CHATTERBOX', 'handl-ai-connector-access-control' ) . '</strong> — ' . esc_html__( 'Largest burst is 5 or more calls.', 'handl-ai-connector-access-control' ) . '</li>';
		echo '<li><strong>' . esc_html__( 'INSUFFICIENT-DATA', 'handl-ai-connector-access-control' ) . '</strong> — ' . esc_html__( 'Too few logged calls to grade amplification.', 'handl-ai-connector-access-control' ) . '</li>';
		echo '</ul>';

		if ( ! $data['available'] ) {
			echo '<p><strong>' . esc_html__( 'INSUFFICIENT-DATA', 'handl-ai-connector-access-control' ) . '</strong> — ';
			echo esc_html__( 'Activity log is unavailable. Enable logging and generate AI traffic first.', 'handl-ai-connector-access-control' );
			echo '</p></div>';

			return;
		}

		if ( array() === $data['rows'] ) {
			echo '<p>' . esc_html__( 'No AI calls logged yet. Bursts appear here after plugins make calls.', 'handl-ai-connector-access-control' ) . '</p>';
			echo '</div>';

			return;
		}

		echo '<table class="widefat striped"><thead><tr>';
		echo '<th>' . esc_html__( 'Plugin', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Calls', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Bursts', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Max burst', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Median burst', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Endpoints in largest burst', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Grade', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Note', 'handl-ai-connector-access-control' ) . '</th>';
		echo '</tr></thead><tbody>';

		foreach ( $data['rows'] as $row ) {
			echo '<tr>';
			echo '<td>' . esc_html( (string) $row['plugin'] ) . '</td>';
			echo '<td>' . esc_html( (string) (int) $row['calls'] ) . '</td>';
			echo '<td>' . esc_html( (string) (int) $row['bursts'] ) . '</td>';
			echo '<td>' . esc_html( (string) (int) $row['max_burst'] ) . '</td>';
			echo '<td>' . esc_html( (string) (int) $row['median_burst'] ) . '</td>';
			echo '<td>' . esc_html( (string) (int) $row['largest_endpoints'] ) . '</td>';
			echo '<td><strong>' . esc_html( (string) $row['grade'] ) . '</strong></td>';
			echo '<td>' . esc_html( (string) $row['note'] ) . '</td>';
			echo '</tr>';
		}

		echo '</tbody></table>';
		echo '</div>';
	}
}
