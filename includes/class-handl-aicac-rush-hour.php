<?php
/**
 * AICAC-RUSH-HOUR (#458): call-timing census.
 *
 * Soft-reads recent-calls (allow + deny) and grades actors by when they
 * run: BUSINESS-HOURS / AFTER-HOURS / NIGHT-SHIFT / WEEKENDER. Quiet Hours
 * still owns enforcement; this page never writes policy or the activity log.
 *
 * README-FREE. Own options only (handl_aicac_rush_hour_*). Own admin screen.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Observed call-timing census.
 */
final class Rush_Hour {

	public const PAGE_SLUG = 'handl-aicac-rush-hour';

	public const CENSUS_OPTION = 'handl_aicac_rush_hour_census';

	public const GENERATED_OPTION = 'handl_aicac_rush_hour_generated_at';

	public const GRADE_BUSINESS     = 'BUSINESS-HOURS';
	public const GRADE_AFTER        = 'AFTER-HOURS';
	public const GRADE_NIGHT        = 'NIGHT-SHIFT';
	public const GRADE_WEEKEND      = 'WEEKENDER';
	public const GRADE_INSUFFICIENT = 'INSUFFICIENT-DATA';

	public const KIND_USER     = 'user';
	public const KIND_ROLE     = 'role';
	public const KIND_PROVIDER = 'provider';

	/** @var bool */
	private static $registered = false;

	/** @var int|null */
	private static $test_now = null;

	/** @var string|null */
	private static $test_timezone = null;

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
		self::$registered     = false;
		self::$test_now       = null;
		self::$test_timezone  = null;
		self::$test_log       = null;
		self::$skip_cache     = false;
		delete_option( self::CENSUS_OPTION );
		delete_option( self::GENERATED_OPTION );
	}

	public static function set_test_now( ?int $now ): void {
		self::$test_now = $now;
	}

	public static function set_test_timezone( ?string $timezone ): void {
		self::$test_timezone = $timezone;
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
	 * Site timezone. Tests inject America/Chicago because wp_timezone() is UTC.
	 */
	public static function timezone(): \DateTimeZone {
		if ( is_string( self::$test_timezone ) && '' !== self::$test_timezone ) {
			try {
				return new \DateTimeZone( self::$test_timezone );
			} catch ( \Exception $e ) {
				unset( $e );
			}
		}
		if ( function_exists( 'wp_timezone' ) ) {
			$tz = wp_timezone();
			if ( $tz instanceof \DateTimeZone ) {
				return $tz;
			}
		}

		return new \DateTimeZone( 'UTC' );
	}

	/**
	 * Filterable classifier thresholds.
	 *
	 * @return array{
	 *   min_calls:int,
	 *   business_hours_share:float,
	 *   after_hours_min:float,
	 *   after_hours_max:float,
	 *   night_share:float,
	 *   weekend_share:float,
	 *   business_start_hour:int,
	 *   business_end_hour:int,
	 *   night_end_hour:int
	 * }
	 */
	public static function thresholds(): array {
		$defaults = array(
			'min_calls'             => 5,
			'business_hours_share'  => 0.80,
			'after_hours_min'       => 0.20,
			'after_hours_max'       => 0.50,
			'night_share'           => 0.50,
			'weekend_share'         => 0.50,
			'business_start_hour'   => 8,
			'business_end_hour'     => 18,
			'night_end_hour'        => 6,
		);
		$filtered = apply_filters( 'handl_aicac_rush_hour_thresholds', $defaults );
		if ( ! is_array( $filtered ) ) {
			return $defaults;
		}
		$out = $defaults;
		foreach ( array( 'min_calls', 'business_start_hour', 'business_end_hour', 'night_end_hour' ) as $int_key ) {
			if ( isset( $filtered[ $int_key ] ) ) {
				$out[ $int_key ] = (int) $filtered[ $int_key ];
			}
		}
		foreach ( array( 'business_hours_share', 'after_hours_min', 'after_hours_max', 'night_share', 'weekend_share' ) as $float_key ) {
			if ( isset( $filtered[ $float_key ] ) ) {
				$out[ $float_key ] = (float) $filtered[ $float_key ];
			}
		}
		if ( $out['min_calls'] < 1 ) {
			$out['min_calls'] = 1;
		}
		if ( $out['business_start_hour'] < 0 ) {
			$out['business_start_hour'] = 0;
		}
		if ( $out['business_end_hour'] > 24 ) {
			$out['business_end_hour'] = 24;
		}
		if ( $out['night_end_hour'] < 1 ) {
			$out['night_end_hour'] = 1;
		}

		return $out;
	}

	/**
	 * Pure classifier. Night, then weekend, then business, then after-hours.
	 */
	public static function classify( int $total, int $business, int $night, int $weekend ): string {
		$th = self::thresholds();
		if ( $total < (int) $th['min_calls'] ) {
			return self::GRADE_INSUFFICIENT;
		}
		$night_share    = $night / $total;
		$weekend_share  = $weekend / $total;
		$business_share = $business / $total;
		$outside_share  = 1.0 - $business_share;

		if ( $night_share >= (float) $th['night_share'] ) {
			return self::GRADE_NIGHT;
		}
		if ( $weekend_share >= (float) $th['weekend_share'] ) {
			return self::GRADE_WEEKEND;
		}
		if ( $business_share >= (float) $th['business_hours_share'] ) {
			return self::GRADE_BUSINESS;
		}
		if ( $outside_share >= (float) $th['after_hours_min'] ) {
			return self::GRADE_AFTER;
		}

		return self::GRADE_BUSINESS;
	}

	/**
	 * Local hour / weekday flags for one unix timestamp.
	 *
	 * @return array{hour:int,dow:int,weekend:bool,night:bool,business:bool}|null
	 */
	public static function local_flags( int $ts, ?\DateTimeZone $tz = null ): ?array {
		if ( $ts <= 0 ) {
			return null;
		}
		$tz = $tz instanceof \DateTimeZone ? $tz : self::timezone();
		try {
			$dt = ( new \DateTimeImmutable( '@' . $ts ) )->setTimezone( $tz );
		} catch ( \Exception $e ) {
			return null;
		}
		$hour = (int) $dt->format( 'G' );
		$dow  = (int) $dt->format( 'N' ); // 1=Mon … 7=Sun.
		$th   = self::thresholds();
		$weekend  = $dow >= 6;
		$night    = $hour < (int) $th['night_end_hour'];
		$business = ! $weekend && $hour >= (int) $th['business_start_hour'] && $hour < (int) $th['business_end_hour'];

		return array(
			'hour'     => $hour,
			'dow'      => $dow,
			'weekend'  => $weekend,
			'night'    => $night,
			'business' => $business,
		);
	}

	/**
	 * Allow + deny only.
	 *
	 * @param array<string,mixed> $row Activity row.
	 */
	public static function is_call_row( array $row ): bool {
		$decision = strtolower( (string) ( $row['decision'] ?? '' ) );

		return in_array( $decision, array( 'allow', 'allowed', 'deny', 'denied' ), true );
	}

	/**
	 * Guarded soft-read of the activity log. Never writes it.
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
	 * @return array{
	 *   hours:list<array{hour:int,count:int}>,
	 *   actors:list<array<string,mixed>>,
	 *   call_count:int,
	 *   log_available:bool
	 * }
	 */
	public static function census( ?int $now = null ): array {
		unset( $now );
		$pack = self::read_activity_log();
		$tz   = self::timezone();
		$hours = array();
		for ( $h = 0; $h < 24; $h++ ) {
			$hours[ $h ] = 0;
		}

		/** @var array<string,array{kind:string,id:string,label:string,total:int,business:int,night:int,weekend:int}> $actors */
		$actors     = array();
		$call_count = 0;

		foreach ( $pack['rows'] as $row ) {
			if ( ! is_array( $row ) || ! self::is_call_row( $row ) ) {
				continue;
			}
			$ts    = isset( $row['ts'] ) ? (int) $row['ts'] : 0;
			$flags = self::local_flags( $ts, $tz );
			if ( null === $flags ) {
				continue;
			}
			++$call_count;
			++$hours[ $flags['hour'] ];

			foreach ( self::actor_keys( $row ) as $actor ) {
				$key = $actor['kind'] . ':' . $actor['id'];
				if ( ! isset( $actors[ $key ] ) ) {
					$actors[ $key ] = array(
						'kind'     => $actor['kind'],
						'id'       => $actor['id'],
						'label'    => $actor['label'],
						'total'    => 0,
						'business' => 0,
						'night'    => 0,
						'weekend'  => 0,
					);
				}
				++$actors[ $key ]['total'];
				if ( $flags['business'] ) {
					++$actors[ $key ]['business'];
				}
				if ( $flags['night'] ) {
					++$actors[ $key ]['night'];
				}
				if ( $flags['weekend'] ) {
					++$actors[ $key ]['weekend'];
				}
			}
		}

		$hour_rows = array();
		for ( $h = 0; $h < 24; $h++ ) {
			$hour_rows[] = array(
				'hour'  => $h,
				'count' => (int) $hours[ $h ],
			);
		}

		$graded = array();
		foreach ( $actors as $actor ) {
			$grade = self::classify(
				(int) $actor['total'],
				(int) $actor['business'],
				(int) $actor['night'],
				(int) $actor['weekend']
			);
			if ( self::GRADE_INSUFFICIENT === $grade ) {
				continue;
			}
			$graded[] = array(
				'kind'     => $actor['kind'],
				'id'       => $actor['id'],
				'label'    => $actor['label'],
				'calls'    => (int) $actor['total'],
				'business' => (int) $actor['business'],
				'night'    => (int) $actor['night'],
				'weekend'  => (int) $actor['weekend'],
				'grade'    => $grade,
			);
		}

		usort(
			$graded,
			static function ( array $a, array $b ): int {
				$order = array(
					self::GRADE_NIGHT    => 0,
					self::GRADE_WEEKEND  => 1,
					self::GRADE_AFTER    => 2,
					self::GRADE_BUSINESS => 3,
				);
				$ga = $order[ $a['grade'] ] ?? 9;
				$gb = $order[ $b['grade'] ] ?? 9;
				if ( $ga !== $gb ) {
					return $ga <=> $gb;
				}
				if ( $a['kind'] !== $b['kind'] ) {
					return strcmp( (string) $a['kind'], (string) $b['kind'] );
				}

				return strcmp( (string) $a['id'], (string) $b['id'] );
			}
		);

		return array(
			'hours'         => $hour_rows,
			'actors'        => $graded,
			'call_count'    => $call_count,
			'log_available' => ! empty( $pack['available'] ),
		);
	}

	/**
	 * @param array<string,mixed> $row Activity row.
	 * @return list<array{kind:string,id:string,label:string}>
	 */
	public static function actor_keys( array $row ): array {
		$out = array();

		$user_id = isset( $row['user_id'] ) ? (int) $row['user_id'] : 0;
		if ( $user_id > 0 ) {
			$out[] = array(
				'kind'  => self::KIND_USER,
				'id'    => (string) $user_id,
				'label' => sprintf(
					/* translators: %d: user id */
					__( 'User #%d', 'handl-ai-connector-access-control' ),
					$user_id
				),
			);
		}

		$role = strtolower( trim( (string) ( $row['user_role'] ?? '' ) ) );
		if ( '' === $role ) {
			$role = 'unknown';
		}
		$out[] = array(
			'kind'  => self::KIND_ROLE,
			'id'    => sanitize_key( $role ),
			'label' => $role,
		);

		$provider = strtolower( trim( (string) ( $row['provider'] ?? '' ) ) );
		if ( '' === $provider ) {
			$provider = 'unknown';
		}
		$out[] = array(
			'kind'  => self::KIND_PROVIDER,
			'id'    => sanitize_key( $provider ),
			'label' => $provider,
		);

		return $out;
	}

	/**
	 * @return array{
	 *   as_of:int,
	 *   hours:list<array{hour:int,count:int}>,
	 *   actors:list<array<string,mixed>>,
	 *   call_count:int,
	 *   log_available:bool,
	 *   cached:bool
	 * }
	 */
	public static function snapshot( ?int $now = null ): array {
		$now = null !== $now && $now > 0 ? $now : self::now();

		if ( ! self::$skip_cache ) {
			$cached = get_option( self::CENSUS_OPTION, null );
			$as_of  = (int) get_option( self::GENERATED_OPTION, 0 );
			if ( is_array( $cached ) && isset( $cached['hours'], $cached['actors'] ) && $as_of > 0 ) {
				return array(
					'as_of'         => $as_of,
					'hours'         => is_array( $cached['hours'] ) ? $cached['hours'] : array(),
					'actors'        => is_array( $cached['actors'] ) ? $cached['actors'] : array(),
					'call_count'    => isset( $cached['call_count'] ) ? (int) $cached['call_count'] : 0,
					'log_available' => ! empty( $cached['log_available'] ),
					'cached'        => true,
				);
			}
		}

		$data = self::census( $now );
		$snap = array(
			'as_of'         => $now,
			'hours'         => $data['hours'],
			'actors'        => $data['actors'],
			'call_count'    => $data['call_count'],
			'log_available' => $data['log_available'],
			'cached'        => false,
		);

		if ( ! self::$skip_cache ) {
			update_option(
				self::CENSUS_OPTION,
				array(
					'hours'         => $data['hours'],
					'actors'        => $data['actors'],
					'call_count'    => $data['call_count'],
					'log_available' => $data['log_available'],
				),
				false
			);
			update_option( self::GENERATED_OPTION, $now, false );
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
			__( 'Rush hour', 'handl-ai-connector-access-control' ),
			__( 'Rush hour', 'handl-ai-connector-access-control' ),
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
		echo '<h1>' . esc_html__( 'Rush hour', 'handl-ai-connector-access-control' ) . '</h1>';
		echo '<p class="description">' . esc_html__( 'When AI calls actually happen on this site, in the site timezone. Read-only census. Quiet Hours still owns any enforcement.', 'handl-ai-connector-access-control' ) . '</p>';

		echo '<ul class="ul-disc">';
		echo '<li><strong>' . esc_html__( 'BUSINESS-HOURS', 'handl-ai-connector-access-control' ) . '</strong> — ' . esc_html__( '80% or more of calls fall Mon-Fri 08:00-18:00.', 'handl-ai-connector-access-control' ) . '</li>';
		echo '<li><strong>' . esc_html__( 'AFTER-HOURS', 'handl-ai-connector-access-control' ) . '</strong> — ' . esc_html__( '20% or more of calls fall outside business hours.', 'handl-ai-connector-access-control' ) . '</li>';
		echo '<li><strong>' . esc_html__( 'NIGHT-SHIFT', 'handl-ai-connector-access-control' ) . '</strong> — ' . esc_html__( '50% or more of calls fall 00:00-06:00.', 'handl-ai-connector-access-control' ) . '</li>';
		echo '<li><strong>' . esc_html__( 'WEEKENDER', 'handl-ai-connector-access-control' ) . '</strong> — ' . esc_html__( '50% or more of calls fall Saturday or Sunday.', 'handl-ai-connector-access-control' ) . '</li>';
		echo '</ul>';

		if ( $snap['call_count'] < 1 ) {
			echo '<p>' . esc_html__( 'No AI calls in the activity log yet. Timing grades appear once calls are recorded.', 'handl-ai-connector-access-control' ) . '</p>';
			echo '</div>';

			return;
		}

		$max = 1;
		foreach ( $snap['hours'] as $row ) {
			if ( (int) $row['count'] > $max ) {
				$max = (int) $row['count'];
			}
		}

		echo '<h2>' . esc_html__( 'Hour of day', 'handl-ai-connector-access-control' ) . '</h2>';
		echo '<table class="widefat striped"><thead><tr>';
		echo '<th>' . esc_html__( 'Hour', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Calls', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Share', 'handl-ai-connector-access-control' ) . '</th>';
		echo '</tr></thead><tbody>';
		foreach ( $snap['hours'] as $row ) {
			$count = (int) $row['count'];
			$pct   = (int) round( 100.0 * $count / $max );
			$label = sprintf( '%02d:00', (int) $row['hour'] );
			echo '<tr>';
			echo '<td>' . esc_html( $label ) . '</td>';
			echo '<td>' . esc_html( (string) $count ) . '</td>';
			echo '<td><span style="display:inline-block;height:10px;background:#2271b1;width:' . esc_attr( (string) $pct ) . '%"></span></td>';
			echo '</tr>';
		}
		echo '</tbody></table>';

		echo '<h2>' . esc_html__( 'Actor grades', 'handl-ai-connector-access-control' ) . '</h2>';
		if ( empty( $snap['actors'] ) ) {
			echo '<p>' . esc_html__( 'Not enough calls per actor to grade yet. Actors with fewer than five calls stay ungraded.', 'handl-ai-connector-access-control' ) . '</p>';
			echo '</div>';

			return;
		}

		echo '<table class="widefat striped"><thead><tr>';
		echo '<th>' . esc_html__( 'Actor', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Kind', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Calls', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Grade', 'handl-ai-connector-access-control' ) . '</th>';
		echo '</tr></thead><tbody>';
		foreach ( $snap['actors'] as $actor ) {
			echo '<tr>';
			echo '<td>' . esc_html( (string) $actor['label'] ) . '</td>';
			echo '<td>' . esc_html( (string) $actor['kind'] ) . '</td>';
			echo '<td>' . esc_html( (string) (int) $actor['calls'] ) . '</td>';
			echo '<td>' . esc_html( (string) $actor['grade'] ) . '</td>';
			echo '</tr>';
		}
		echo '</tbody></table>';
		echo '</div>';
	}
}
