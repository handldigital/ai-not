<?php
/**
 * AICAC-DEJA-VU (#453): duplicate-call waste census (ALLOWED calls only).
 *
 * Soft-reads recent-calls history and grades connectors by how often they
 * repeat the same ask: ECHO-CHAMBER / RERUN-HEAVY / VARIED. Never writes
 * policy, alerts, log, or cost options. Hourly transient cache.
 *
 * README-FREE. Distinct from Retry_Storm / MANNERS (deny side).
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Allowed-call duplicate census.
 */
final class Dejavu {

	public const PAGE_SLUG = 'handl-aicac-dejavu';

	public const TRANSIENT_KEY = 'handl_aicac_dejavu_cache';

	public const CACHE_TTL = 3600;

	public const LOOKBACK_DAYS = 14;

	public const GRADE_ECHO     = 'ECHO-CHAMBER';
	public const GRADE_RERUN    = 'RERUN-HEAVY';
	public const GRADE_VARIED   = 'VARIED';

	public const THRESHOLD_ECHO  = 0.70;
	public const THRESHOLD_RERUN = 0.40;

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
	 * @param list<array<string,mixed>>|null $log Injected rows.
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
	 * Pure grade from totals. $total_allowed >= 1; $distinct >= 1.
	 */
	public static function classify( int $total_allowed, int $distinct ): string {
		$total_allowed = max( 0, $total_allowed );
		$distinct      = max( 0, $distinct );
		if ( $total_allowed < 1 || $distinct < 1 ) {
			return self::GRADE_VARIED;
		}
		// repeat_ratio = share of calls that are not the first occurrence of their fingerprint.
		$unique_share = min( 1.0, $distinct / $total_allowed );
		$repeat_ratio = 1.0 - $unique_share;
		if ( $repeat_ratio >= self::THRESHOLD_ECHO ) {
			return self::GRADE_ECHO;
		}
		if ( $repeat_ratio >= self::THRESHOLD_RERUN ) {
			return self::GRADE_RERUN;
		}

		return self::GRADE_VARIED;
	}

	/**
	 * Fingerprint an ALLOWED activity row from stable fields already present.
	 *
	 * @param array<string,mixed> $row Activity row.
	 */
	public static function fingerprint( array $row ): string {
		$plugin = strtolower( trim( (string) ( $row['plugin'] ?? '' ) ) );
		$op     = sanitize_key( (string) ( $row['operation'] ?? '' ) );
		if ( '' === $op ) {
			$op = sanitize_key( (string) ( $row['capability'] ?? '' ) );
		}
		$provider = strtolower( trim( (string) ( $row['provider'] ?? '' ) ) );
		$model    = strtolower( trim( (string) ( $row['model'] ?? '' ) ) );
		$parts    = array( $plugin, $op, $provider, $model );
		// AICAC-CARPOOL (#486): when a prompt hash is present, fold it in so
		// census + carpool share one ask key. Legacy rows without a hash keep
		// the four-field fingerprint (grades stay stable for history).
		$prompt_hash = strtolower( trim( (string) ( $row['prompt_hash'] ?? '' ) ) );
		if ( '' !== $prompt_hash && 1 === preg_match( '/^[a-f0-9]{64}$/', $prompt_hash ) ) {
			$parts[] = $prompt_hash;
		}
		$joined = implode( '|', $parts );

		return '' !== $joined ? $joined : 'unknown';
	}

	/**
	 * Human-readable label for a composite fingerprint key.
	 */
	public static function format_fingerprint_label( string $fingerprint ): string {
		$parts = explode( '|', $fingerprint );
		if ( count( $parts ) < 4 ) {
			return $fingerprint;
		}
		$plugin   = (string) $parts[0];
		$op       = (string) $parts[1];
		$provider = (string) $parts[2];
		$model    = (string) $parts[3];
		$ask      = '' !== $op ? $op : __( 'unknown ask', 'handl-ai-connector-access-control' );
		$model_bit = '' !== $model ? $provider . '/' . $model : $provider;
		if ( '' === $model_bit ) {
			$model_bit = __( 'unknown model', 'handl-ai-connector-access-control' );
		}

		return $plugin . ' · ' . $ask . ' · ' . $model_bit;
	}

	/**
	 * @param array<string,mixed> $row Activity row.
	 */
	public static function connector_key( array $row ): string {
		$plugin = strtolower( trim( (string) ( $row['plugin'] ?? '' ) ) );

		return '' !== $plugin ? $plugin : 'unknown';
	}

	/**
	 * Guarded soft-read of activity log.
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
	 * Build census rows (no cache).
	 *
	 * @return list<array{
	 *   connector:string,
	 *   calls:int,
	 *   distinct:int,
	 *   repeat_ratio:float,
	 *   top_fingerprint:string,
	 *   top_count:int,
	 *   grade:string
	 * }>
	 */
	public static function grade_connectors( ?int $now = null ): array {
		$now    = null !== $now && $now > 0 ? $now : self::now();
		$day    = defined( 'DAY_IN_SECONDS' ) ? DAY_IN_SECONDS : 86400;
		$cutoff = $now - ( self::LOOKBACK_DAYS * $day );
		$pack   = self::read_activity_log();

		/** @var array<string,array{total:int,fps:array<string,int>}> $by */
		$by = array();

		foreach ( $pack['rows'] as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$decision = strtolower( (string) ( $row['decision'] ?? '' ) );
			if ( 'allow' !== $decision && 'allowed' !== $decision ) {
				continue;
			}
			$ts = isset( $row['ts'] ) ? (int) $row['ts'] : 0;
			if ( $ts < $cutoff || $ts > $now ) {
				continue;
			}
			$connector = self::connector_key( $row );
			$fp        = self::fingerprint( $row );
			if ( ! isset( $by[ $connector ] ) ) {
				$by[ $connector ] = array(
					'total' => 0,
					'fps'   => array(),
				);
			}
			++$by[ $connector ]['total'];
			if ( ! isset( $by[ $connector ]['fps'][ $fp ] ) ) {
				$by[ $connector ]['fps'][ $fp ] = 0;
			}
			++$by[ $connector ]['fps'][ $fp ];
		}

		$out = array();
		foreach ( $by as $connector => $bucket ) {
			$total    = (int) $bucket['total'];
			$distinct = count( $bucket['fps'] );
			if ( $total < 1 || $distinct < 1 ) {
				continue;
			}
			$unique_share = min( 1.0, $distinct / $total );
			$repeat_ratio = 1.0 - $unique_share;
			$top_fp       = '';
			$top_count    = 0;
			foreach ( $bucket['fps'] as $fp => $count ) {
				if ( $count > $top_count || ( $count === $top_count && ( $top_fp === '' || strcmp( $fp, $top_fp ) < 0 ) ) ) {
					$top_fp    = $fp;
					$top_count = $count;
				}
			}
			$out[] = array(
				'connector'       => $connector,
				'calls'           => $total,
				'distinct'        => $distinct,
				'repeat_ratio'    => $repeat_ratio,
				'top_fingerprint' => $top_fp,
				'top_count'       => $top_count,
				'grade'           => self::classify( $total, $distinct ),
			);
		}

		usort(
			$out,
			static function ( array $a, array $b ): int {
				$order = array(
					self::GRADE_ECHO   => 0,
					self::GRADE_RERUN  => 1,
					self::GRADE_VARIED => 2,
				);
				$ga = $order[ $a['grade'] ] ?? 9;
				$gb = $order[ $b['grade'] ] ?? 9;
				if ( $ga !== $gb ) {
					return $ga <=> $gb;
				}
				if ( $a['repeat_ratio'] !== $b['repeat_ratio'] ) {
					return $b['repeat_ratio'] <=> $a['repeat_ratio'];
				}

				return strcmp( (string) $a['connector'], (string) $b['connector'] );
			}
		);

		return $out;
	}

	/**
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
					'as_of'         => (int) $cached['as_of'],
					'lookback_days' => self::LOOKBACK_DAYS,
					'rows'          => $cached['rows'],
					'log_available' => ! empty( $cached['log_available'] ),
					'cached'        => true,
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
			__( 'Déjà vu', 'handl-ai-connector-access-control' ),
			__( 'Déjà vu', 'handl-ai-connector-access-control' ),
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
		echo '<h1>' . esc_html__( 'Déjà vu', 'handl-ai-connector-access-control' ) . '</h1>';
		echo '<p class="description">' . esc_html__( 'Connectors that keep asking the same allowed question — a caching opportunity table. Denied calls are out of scope.', 'handl-ai-connector-access-control' ) . '</p>';

		echo '<ul class="ul-disc">';
		echo '<li><strong>' . esc_html__( 'ECHO-CHAMBER', 'handl-ai-connector-access-control' ) . '</strong> — ' . esc_html__( 'Repeat share 70% or higher.', 'handl-ai-connector-access-control' ) . '</li>';
		echo '<li><strong>' . esc_html__( 'RERUN-HEAVY', 'handl-ai-connector-access-control' ) . '</strong> — ' . esc_html__( 'Repeat share 40% or higher.', 'handl-ai-connector-access-control' ) . '</li>';
		echo '<li><strong>' . esc_html__( 'VARIED', 'handl-ai-connector-access-control' ) . '</strong> — ' . esc_html__( 'Mostly distinct asks.', 'handl-ai-connector-access-control' ) . '</li>';
		echo '</ul>';

		// AICAC-CARPOOL (#486): acting half — opt-in + savings on this screen.
		if ( class_exists( Carpool::class, false ) ) {
			Carpool::render_dejavu_panel( is_array( $snap['rows'] ) ? $snap['rows'] : array() );
		}

		if ( empty( $snap['rows'] ) ) {
			echo '<p>' . esc_html__( 'No repeated allowed calls in the lookback window yet. Grades appear once connectors reuse the same ask.', 'handl-ai-connector-access-control' ) . '</p>';
			echo '</div>';

			return;
		}

		echo '<table class="widefat striped"><thead><tr>';
		echo '<th>' . esc_html__( 'Connector', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Calls', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Distinct asks', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Repeat share', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Top repeated ask', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Grade', 'handl-ai-connector-access-control' ) . '</th>';
		echo '</tr></thead><tbody>';

		foreach ( $snap['rows'] as $row ) {
			$pct = (int) round( 100.0 * (float) $row['repeat_ratio'] );
			$top = self::format_fingerprint_label( (string) $row['top_fingerprint'] ) . ' ×' . (int) $row['top_count'];
			echo '<tr>';
			echo '<td>' . esc_html( (string) $row['connector'] ) . '</td>';
			echo '<td>' . esc_html( (string) (int) $row['calls'] ) . '</td>';
			echo '<td>' . esc_html( (string) (int) $row['distinct'] ) . '</td>';
			echo '<td>' . esc_html( (string) $pct . '%' ) . '</td>';
			echo '<td>' . esc_html( $top ) . '</td>';
			echo '<td>' . esc_html( (string) $row['grade'] ) . '</td>';
			echo '</tr>';
		}
		echo '</tbody></table>';
		echo '</div>';
	}
}
