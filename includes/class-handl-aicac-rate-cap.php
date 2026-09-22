<?php
/**
 * AICAC-RATE-CAP (#275): per-plugin call-count ceilings (hour + day).
 *
 * Empty / 0 caps = unlimited. Soft-warn once per window at >=80%; hard deny
 * at 100% with denial_reason `rate_cap`. Counts live in a durable option
 * (independent of Activity logging / ring-buffer eviction) so hard limits
 * remain enforceable.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Call-volume ceilings + durable counters + soft-warn / hard-deny helpers.
 */
final class Rate_Cap {

	public const REASON = 'rate_cap';

	public const CHANNEL_WARN = 'rate_warn';

	public const SOFT_WARN_RATIO = 0.8;

	/** Fired soft-warns: "{plugin}|hour|{YmdH}" / "{plugin}|day|{Ymd}" => meta. */
	public const WARNED_OPTION_KEY = 'handl_aicac_rate_cap_warned';

	/**
	 * Durable attempt counters: "{plugin}|hour|{YmdH}" / "{plugin}|day|{Ymd}" => int.
	 * Survives Activity log off, TTL prune, and ring-buffer eviction.
	 */
	public const COUNTS_OPTION_KEY = 'handl_aicac_rate_cap_counts';

	public const MAX_CAP = 1000000;

	public const WINDOW_HOUR = 'hour';
	public const WINDOW_DAY  = 'day';

	/**
	 * Empty / non-positive → unlimited (omit). Positive int capped.
	 *
	 * @param mixed $raw
	 */
	public static function sanitize_cap( $raw ): ?int {
		if ( null === $raw || false === $raw ) {
			return null;
		}
		if ( is_string( $raw ) ) {
			$raw = trim( $raw );
			if ( '' === $raw ) {
				return null;
			}
		}
		if ( ! is_numeric( $raw ) ) {
			return null;
		}
		$v = (int) $raw;
		if ( $v <= 0 ) {
			return null;
		}
		if ( $v > self::MAX_CAP ) {
			$v = self::MAX_CAP;
		}

		return $v;
	}

	/**
	 * @param mixed $raw basename => cap map
	 * @return array<string,int>
	 */
	public static function sanitize_plugin_caps( $raw ): array {
		if ( ! is_array( $raw ) ) {
			return array();
		}
		$out = array();
		foreach ( $raw as $basename => $cap ) {
			$basename = Plugin_Profile::sanitize_plugin( (string) $basename );
			if ( '' === $basename ) {
				continue;
			}
			$clean = self::sanitize_cap( $cap );
			if ( null === $clean ) {
				continue;
			}
			$out[ $basename ] = $clean;
		}

		return $out;
	}

	/**
	 * @param array<string,mixed> $policy
	 */
	public static function get_hour_cap( array $policy, string $plugin ): ?int {
		$plugin = Plugin_Profile::sanitize_plugin( $plugin );
		if ( '' === $plugin ) {
			return null;
		}
		$map = self::sanitize_plugin_caps( $policy['plugin_rate_caps_hour'] ?? array() );

		return $map[ $plugin ] ?? null;
	}

	/**
	 * @param array<string,mixed> $policy
	 */
	public static function get_day_cap( array $policy, string $plugin ): ?int {
		$plugin = Plugin_Profile::sanitize_plugin( $plugin );
		if ( '' === $plugin ) {
			return null;
		}
		$map = self::sanitize_plugin_caps( $policy['plugin_rate_caps_day'] ?? array() );

		return $map[ $plugin ] ?? null;
	}

	/**
	 * Soft-warn threshold count for a positive limit (ceil of 80%).
	 */
	public static function soft_warn_threshold( int $limit ): int {
		if ( $limit <= 0 ) {
			return 0;
		}

		return (int) max( 1, (int) ceil( $limit * self::SOFT_WARN_RATIO ) );
	}

	/**
	 * Local hour / day window bounds in site timezone: [start, end).
	 *
	 * @return array{start:int,end:int,key:string}
	 */
	public static function window_bounds( string $window, ?int $now = null, ?\DateTimeZone $tz = null ): array {
		$window = self::WINDOW_DAY === $window ? self::WINDOW_DAY : self::WINDOW_HOUR;
		$now    = null !== $now ? (int) $now : Clock::now();
		if ( $now <= 0 ) {
			$now = Clock::now();
		}
		$tz = Quiet_Hours::timezone( $tz );
		$dt = ( new \DateTimeImmutable( '@' . $now ) )->setTimezone( $tz );

		if ( self::WINDOW_DAY === $window ) {
			$start = $dt->setTime( 0, 0, 0 );
			$end   = $start->modify( '+1 day' );
			$key   = $start->format( 'Ymd' );
		} else {
			$start = $dt->setTime( (int) $dt->format( 'H' ), 0, 0 );
			$end   = $start->modify( '+1 hour' );
			$key   = $start->format( 'YmdH' );
		}

		return array(
			'start' => $start->getTimestamp(),
			'end'   => $end->getTimestamp(),
			'key'   => $key,
		);
	}

	/**
	 * Durable counter storage key for one plugin + window.
	 */
	public static function count_key( string $plugin, string $window, string $window_key ): string {
		$plugin = Plugin_Profile::sanitize_plugin( $plugin );
		$window = self::WINDOW_DAY === $window ? self::WINDOW_DAY : self::WINDOW_HOUR;

		return $plugin . '|' . $window . '|' . sanitize_text_field( $window_key );
	}

	/**
	 * @return array<string,int>
	 */
	public static function get_counts_map(): array {
		return self::sanitize_counts_map( get_option( self::COUNTS_OPTION_KEY, array() ) );
	}

	/**
	 * @param mixed $raw
	 * @return array<string,int>
	 */
	public static function sanitize_counts_map( $raw ): array {
		if ( ! is_array( $raw ) ) {
			return array();
		}
		$out = array();
		foreach ( $raw as $key => $n ) {
			$key = sanitize_text_field( (string) $key );
			if ( '' === $key || ! is_numeric( $n ) ) {
				continue;
			}
			$v = (int) $n;
			if ( $v < 0 ) {
				$v = 0;
			}
			$out[ $key ] = $v;
		}

		return $out;
	}

	/**
	 * @param array<string,int> $map
	 */
	public static function save_counts_map( array $map ): void {
		$map = self::sanitize_counts_map( $map );
		$map = self::prune_counts_map( $map );
		if ( empty( $map ) ) {
			delete_option( self::COUNTS_OPTION_KEY );
			return;
		}
		update_option( self::COUNTS_OPTION_KEY, $map, false );
	}

	/**
	 * Drop stale window keys when the map grows large.
	 *
	 * @param array<string,int> $map
	 * @return array<string,int>
	 */
	public static function prune_counts_map( array $map, ?int $now = null, ?\DateTimeZone $tz = null ): array {
		if ( count( $map ) <= 500 ) {
			return $map;
		}
		$now  = null !== $now ? (int) $now : Clock::now();
		$tz   = Quiet_Hours::timezone( $tz );
		$hour = self::window_bounds( self::WINDOW_HOUR, $now, $tz );
		$day  = self::window_bounds( self::WINDOW_DAY, $now, $tz );
		$keep = array();
		foreach ( $map as $key => $n ) {
			$parts = explode( '|', $key );
			if ( count( $parts ) < 3 ) {
				continue;
			}
			$window = $parts[ count( $parts ) - 2 ];
			$suffix = $parts[ count( $parts ) - 1 ];
			if ( self::WINDOW_HOUR === $window && $suffix === $hour['key'] ) {
				$keep[ $key ] = $n;
				continue;
			}
			if ( self::WINDOW_DAY === $window && $suffix === $day['key'] ) {
				$keep[ $key ] = $n;
			}
		}

		return $keep;
	}

	public static function get_window_count( string $plugin, string $window, string $window_key ): int {
		$key = self::count_key( $plugin, $window, $window_key );
		$map = self::get_counts_map();

		return isset( $map[ $key ] ) ? (int) $map[ $key ] : 0;
	}

	/**
	 * Increment durable hour + day counters for one allowed AI Client attempt.
	 *
	 * @return array{hour:int,day:int}
	 */
	public static function record_attempt( string $plugin, ?int $now = null, ?\DateTimeZone $tz = null ): array {
		$plugin = Plugin_Profile::sanitize_plugin( $plugin );
		if ( '' === $plugin ) {
			return array(
				'hour' => 0,
				'day'  => 0,
			);
		}
		$now  = null !== $now ? (int) $now : Clock::now();
		$tz   = Quiet_Hours::timezone( $tz );
		$hour = self::window_bounds( self::WINDOW_HOUR, $now, $tz );
		$day  = self::window_bounds( self::WINDOW_DAY, $now, $tz );
		$map  = self::get_counts_map();

		$hour_key         = self::count_key( $plugin, self::WINDOW_HOUR, $hour['key'] );
		$day_key          = self::count_key( $plugin, self::WINDOW_DAY, $day['key'] );
		$map[ $hour_key ] = ( isset( $map[ $hour_key ] ) ? (int) $map[ $hour_key ] : 0 ) + 1;
		$map[ $day_key ]  = ( isset( $map[ $day_key ] ) ? (int) $map[ $day_key ] : 0 ) + 1;
		self::save_counts_map( $map );

		return array(
			'hour' => (int) $map[ $hour_key ],
			'day'  => (int) $map[ $day_key ],
		);
	}

	/**
	 * Test helper: set an absolute window count.
	 */
	public static function set_window_count( string $plugin, string $window, string $window_key, int $count ): void {
		$plugin = Plugin_Profile::sanitize_plugin( $plugin );
		if ( '' === $plugin ) {
			return;
		}
		$map = self::get_counts_map();
		$key = self::count_key( $plugin, $window, $window_key );
		if ( $count <= 0 ) {
			unset( $map[ $key ] );
		} else {
			$map[ $key ] = $count;
		}
		self::save_counts_map( $map );
	}

	public static function clear_counts(): void {
		delete_option( self::COUNTS_OPTION_KEY );
	}

	/**
	 * Administrative Activity channels that are never AI Client attempts.
	 *
	 * @return list<string>
	 */
	public static function administrative_channels(): array {
		return array(
			'policy_restore',
			'access_request',
			'policy_checks',
			'policy_save',
			'policy_import',
			'email',
			'temp_allow',
			'went_ai',
			'canary',
			'tamper',
			'hardened_guard',
			'share',
			self::CHANNEL_WARN,
		);
	}

	/**
	 * Saved Activity rows that represent real AI Client attempts (profile stats).
	 *
	 * @param array<string,mixed> $row
	 */
	public static function is_counted_attempt_row( array $row, string $plugin = '' ): bool {
		if ( class_exists( Selftest::class ) && Selftest::is_synthetic_row( $row ) ) {
			return false;
		}
		if ( '' !== $plugin ) {
			$row_plugin = isset( $row['plugin'] ) ? Plugin_Profile::sanitize_plugin( (string) $row['plugin'] ) : '';
			if ( $row_plugin !== Plugin_Profile::sanitize_plugin( $plugin ) ) {
				return false;
			}
		}
		$channel = isset( $row['channel'] ) ? (string) $row['channel'] : '';
		if ( in_array( $channel, self::administrative_channels(), true ) ) {
			return false;
		}
		if ( class_exists( Usage_Trends::class ) && ! Usage_Trends::is_activity_row( $row ) ) {
			return false;
		}
		$decision = isset( $row['decision'] ) ? (string) $row['decision'] : '';

		return 'allow' === $decision || 'deny' === $decision;
	}

	/**
	 * Grouped deny clusters store the attempt total in `count`.
	 *
	 * @param array<string,mixed> $row
	 */
	public static function attempt_count( array $row ): int {
		$n = isset( $row['count'] ) ? (int) $row['count'] : 1;

		return $n > 0 ? $n : 1;
	}

	/**
	 * Reconstruct countable attempts from a log slice (tests / diagnostics).
	 *
	 * @param array<int,mixed> $log
	 */
	public static function count_plugin_calls_in_window( array $log, string $plugin, int $start_ts, int $end_ts ): int {
		$plugin = Plugin_Profile::sanitize_plugin( $plugin );
		if ( '' === $plugin || $end_ts <= $start_ts ) {
			return 0;
		}

		$n = 0;
		foreach ( $log as $row ) {
			if ( ! is_array( $row ) || ! self::is_countable_row( $row, $plugin ) ) {
				continue;
			}
			$ts = isset( $row['ts'] ) ? (int) $row['ts'] : 0;
			if ( $ts < $start_ts || $ts >= $end_ts ) {
				continue;
			}
			$n += self::attempt_count( $row );
		}

		return $n;
	}

	/**
	 * @param array<string,mixed> $row
	 */
	public static function is_countable_row( array $row, string $plugin ): bool {
		if ( ! self::is_counted_attempt_row( $row, $plugin ) ) {
			return false;
		}
		if ( self::REASON === (string) ( $row['denial_reason'] ?? '' ) ) {
			return false;
		}

		return true;
	}

	/**
	 * Evaluate hour + day caps for a plugin against durable counters.
	 *
	 * @param array<string,mixed>   $policy
	 * @param array<int,mixed>|null $log Unused; kept so call sites stay stable.
	 * @return array{
	 *   prevent:bool,
	 *   reason:string,
	 *   window:string,
	 *   limit:?int,
	 *   count:int,
	 *   soft_warn:bool,
	 *   soft_window:string,
	 *   soft_limit:?int,
	 *   soft_count:int,
	 *   hour:array{limit:?int,count:int,key:string,start:int,end:int},
	 *   day:array{limit:?int,count:int,key:string,start:int,end:int}
	 * }
	 */
	public static function evaluate( array $policy, string $plugin, ?array $log = null, ?int $now = null, ?\DateTimeZone $tz = null ): array {
		unset( $log );
		$plugin = Plugin_Profile::sanitize_plugin( $plugin );
		$now    = null !== $now ? (int) $now : Clock::now();
		$tz     = Quiet_Hours::timezone( $tz );

		$hour_bounds = self::window_bounds( self::WINDOW_HOUR, $now, $tz );
		$day_bounds  = self::window_bounds( self::WINDOW_DAY, $now, $tz );

		$hour_limit = self::get_hour_cap( $policy, $plugin );
		$day_limit  = self::get_day_cap( $policy, $plugin );

		$hour_count = '' !== $plugin
			? self::get_window_count( $plugin, self::WINDOW_HOUR, $hour_bounds['key'] )
			: 0;
		$day_count  = '' !== $plugin
			? self::get_window_count( $plugin, self::WINDOW_DAY, $day_bounds['key'] )
			: 0;

		$hour = array(
			'limit' => $hour_limit,
			'count' => $hour_count,
			'key'   => $hour_bounds['key'],
			'start' => $hour_bounds['start'],
			'end'   => $hour_bounds['end'],
		);
		$day  = array(
			'limit' => $day_limit,
			'count' => $day_count,
			'key'   => $day_bounds['key'],
			'start' => $day_bounds['start'],
			'end'   => $day_bounds['end'],
		);

		$out = array(
			'prevent'     => false,
			'reason'      => '',
			'window'      => '',
			'limit'       => null,
			'count'       => 0,
			'soft_warn'   => false,
			'soft_window' => '',
			'soft_limit'  => null,
			'soft_count'  => 0,
			'hour'        => $hour,
			'day'         => $day,
		);

		if ( '' === $plugin ) {
			return $out;
		}

		foreach ( array( self::WINDOW_HOUR => $hour, self::WINDOW_DAY => $day ) as $window => $snap ) {
			$limit = $snap['limit'];
			if ( null === $limit ) {
				continue;
			}
			$count = (int) $snap['count'];
			if ( $count >= $limit ) {
				$out['prevent'] = true;
				$out['reason']  = self::REASON;
				$out['window']  = $window;
				$out['limit']   = $limit;
				$out['count']   = $count;
				return $out;
			}
		}

		foreach ( array( self::WINDOW_HOUR => $hour, self::WINDOW_DAY => $day ) as $window => $snap ) {
			$limit = $snap['limit'];
			if ( null === $limit ) {
				continue;
			}
			$count = (int) $snap['count'];
			$soft  = self::soft_warn_threshold( $limit );
			if ( $count >= $soft ) {
				$out['soft_warn']   = true;
				$out['soft_window'] = $window;
				$out['soft_limit']  = $limit;
				$out['soft_count']  = $count;
				break;
			}
		}

		return $out;
	}

	/**
	 * Tag an Activity event; report whether to block. Soft-warn fires once per window.
	 * Allowed attempts increment durable counters (even when Activity logging is off).
	 *
	 * @param array<string,mixed>      $event
	 * @param array<string,mixed>|null $policy
	 * @param array<int,mixed>|null    $log Unused.
	 * @return array{active:bool,prevent:bool,reason:string,window:string,soft_warn:bool}
	 */
	public static function apply_to_event( array &$event, $policy = null, ?array $log = null, ?int $now = null ): array {
		unset( $log );
		$policy = is_array( $policy ) ? $policy : Policy::get_policy();
		$plugin = isset( $event['plugin'] ) ? Plugin_Profile::sanitize_plugin( (string) $event['plugin'] ) : '';
		$now    = null !== $now ? (int) $now : ( isset( $event['ts'] ) ? (int) $event['ts'] : Clock::now() );

		$hour_cap = self::get_hour_cap( $policy, $plugin );
		$day_cap  = self::get_day_cap( $policy, $plugin );
		if ( null === $hour_cap && null === $day_cap ) {
			return array(
				'active'    => false,
				'prevent'   => false,
				'reason'    => '',
				'window'    => '',
				'soft_warn' => false,
			);
		}

		$eval = self::evaluate( $policy, $plugin, null, $now );

		$event['rate_cap_hour_limit'] = $eval['hour']['limit'];
		$event['rate_cap_hour_count'] = $eval['hour']['count'];
		$event['rate_cap_day_limit']  = $eval['day']['limit'];
		$event['rate_cap_day_count']  = $eval['day']['count'];

		if ( ! empty( $eval['prevent'] ) ) {
			$event['rate_cap_window'] = $eval['window'];
			$event['rate_cap_limit']  = $eval['limit'];
			$event['rate_cap_count']  = $eval['count'];
			$event['rate_capped']     = true;

			return array(
				'active'    => true,
				'prevent'   => true,
				'reason'    => self::REASON,
				'window'    => (string) $eval['window'],
				'soft_warn' => false,
			);
		}

		$after                        = self::record_attempt( $plugin, $now );
		$event['rate_cap_hour_count'] = $after['hour'];
		$event['rate_cap_day_count']  = $after['day'];

		$soft       = false;
		$eval_after = self::evaluate( $policy, $plugin, null, $now );
		if ( ! empty( $eval_after['soft_warn'] ) ) {
			$soft = self::maybe_fire_soft_warn( $policy, $plugin, $eval_after, $now );
			if ( $soft ) {
				$event['rate_warn']        = true;
				$event['rate_warn_window'] = $eval_after['soft_window'];
				$event['rate_warn_limit']  = $eval_after['soft_limit'];
				$event['rate_warn_count']  = $eval_after['soft_count'];
			}
		}

		return array(
			'active'    => true,
			'prevent'   => false,
			'reason'    => '',
			'window'    => '',
			'soft_warn' => $soft,
		);
	}

	/**
	 * Fire soft-warn once per plugin+window key: audit row + alert email.
	 *
	 * @param array<string,mixed> $policy
	 * @param array<string,mixed> $eval evaluate() result
	 */
	public static function maybe_fire_soft_warn( array $policy, string $plugin, array $eval, ?int $now = null ): bool {
		$plugin = Plugin_Profile::sanitize_plugin( $plugin );
		$window = (string) ( $eval['soft_window'] ?? '' );
		$limit  = isset( $eval['soft_limit'] ) ? (int) $eval['soft_limit'] : 0;
		$count  = isset( $eval['soft_count'] ) ? (int) $eval['soft_count'] : 0;
		if ( '' === $plugin || ( self::WINDOW_HOUR !== $window && self::WINDOW_DAY !== $window ) || $limit <= 0 ) {
			return false;
		}

		$key_suffix = self::WINDOW_HOUR === $window
			? (string) ( $eval['hour']['key'] ?? '' )
			: (string) ( $eval['day']['key'] ?? '' );
		if ( '' === $key_suffix ) {
			return false;
		}

		$fired_key = $plugin . '|' . $window . '|' . $key_suffix;
		if ( self::already_warned( $fired_key ) ) {
			return false;
		}

		$now = null !== $now ? (int) $now : Clock::now();
		self::record_warning( $fired_key, $limit, $count, $now );
		self::append_warn_audit_row( $plugin, $window, $limit, $count, $now );
		self::maybe_notify_soft_warn( $policy, $plugin, $window, $limit, $count );

		return true;
	}

	/**
	 * @return array<string,array<string,mixed>>
	 */
	public static function get_warned_map(): array {
		return self::sanitize_warned_map( get_option( self::WARNED_OPTION_KEY, array() ) );
	}

	/**
	 * @param mixed $raw
	 * @return array<string,array<string,mixed>>
	 */
	public static function sanitize_warned_map( $raw ): array {
		if ( ! is_array( $raw ) ) {
			return array();
		}
		$out = array();
		foreach ( $raw as $key => $meta ) {
			$key = sanitize_text_field( (string) $key );
			if ( '' === $key || ! is_array( $meta ) ) {
				continue;
			}
			$out[ $key ] = array(
				'at'    => isset( $meta['at'] ) ? (int) $meta['at'] : 0,
				'limit' => isset( $meta['limit'] ) ? (int) $meta['limit'] : 0,
				'count' => isset( $meta['count'] ) ? (int) $meta['count'] : 0,
			);
		}

		return $out;
	}

	public static function already_warned( string $fired_key ): bool {
		$map = self::get_warned_map();

		return isset( $map[ $fired_key ] );
	}

	public static function record_warning( string $fired_key, int $limit, int $count, int $now ): void {
		$map                = self::get_warned_map();
		$map[ $fired_key ] = array(
			'at'    => $now,
			'limit' => $limit,
			'count' => $count,
		);
		if ( count( $map ) > 200 ) {
			uasort(
				$map,
				static function ( array $a, array $b ): int {
					return ( (int) ( $b['at'] ?? 0 ) ) <=> ( (int) ( $a['at'] ?? 0 ) );
				}
			);
			$map = array_slice( $map, 0, 200, true );
		}
		update_option( self::WARNED_OPTION_KEY, $map, false );
	}

	public static function clear_warned(): void {
		delete_option( self::WARNED_OPTION_KEY );
	}

	/**
	 * @param array<string,mixed> $policy
	 */
	private static function maybe_notify_soft_warn( array $policy, string $plugin, string $window, int $limit, int $count ): void {
		if ( empty( $policy['alert_on_deny'] ) ) {
			return;
		}
		$email = Alerts::resolve_email( $policy );
		if ( '' === $email ) {
			return;
		}

		$site  = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
		$label = self::plugin_label( $plugin );
		$win   = self::WINDOW_HOUR === $window
			? __( 'this hour', 'handl-ai-connector-access-control' )
			: __( 'today', 'handl-ai-connector-access-control' );

		$subject = sprintf(
			/* translators: 1: site name, 2: plugin label */
			__( '[%1$s] HandL call-cap warning: %2$s', 'handl-ai-connector-access-control' ),
			$site,
			$label
		);

		$footer = ! empty( $policy['audit_only'] )
			? __( 'Observe mode is on. Calls will continue even if the cap is reached.', 'handl-ai-connector-access-control' )
			: __( 'New calls will be blocked when the cap is reached.', 'handl-ai-connector-access-control' );

		$body = implode(
			"\n",
			array(
				__( 'AI call limit warning', 'handl-ai-connector-access-control' ),
				'',
				sprintf(
					/* translators: %s: plugin label */
					__( 'Plugin: %s', 'handl-ai-connector-access-control' ),
					$label
				),
				sprintf(
					/* translators: 1: call count, 2: cap, 3: window label */
					__( 'Usage: %1$d of %2$d calls %3$s.', 'handl-ai-connector-access-control' ),
					$count,
					$limit,
					$win
				),
				'',
				$footer,
			)
		);

		if ( isset( $GLOBALS['handl_aicac_wp_mail'] ) && is_callable( $GLOBALS['handl_aicac_wp_mail'] ) ) {
			call_user_func( $GLOBALS['handl_aicac_wp_mail'], $email, $subject, $body );
			return;
		}
		if ( function_exists( 'wp_mail' ) ) {
			wp_mail( $email, $subject, $body );
		}
	}

	private static function append_warn_audit_row( string $plugin, string $window, int $limit, int $count, int $now ): void {
		$policy = Policy::get_policy();
		if ( empty( $policy['log_enabled'] ) && empty( $policy['audit_only'] ) ) {
			return;
		}

		$row = array(
			'ts'            => $now,
			'decision'      => self::CHANNEL_WARN,
			'channel'       => self::CHANNEL_WARN,
			'plugin'        => $plugin,
			'operation'     => '',
			'provider'      => '',
			'model'         => '',
			'rate_window'   => $window,
			'rate_limit'    => $limit,
			'rate_count'    => $count,
			'denial_reason' => '',
		);

		$log = get_option( Plugin::LOG_OPTION_KEY, array() );
		if ( ! is_array( $log ) ) {
			$log = array();
		}
		$log[]      = $row;
		$limit_rows = isset( $policy['log_limit'] ) ? (int) $policy['log_limit'] : 200;
		if ( $limit_rows > 0 && count( $log ) > $limit_rows ) {
			$log = array_slice( $log, -$limit_rows );
		}
		update_option( Plugin::LOG_OPTION_KEY, array_values( $log ), false );
	}

	public static function plugin_label( string $plugin ): string {
		$plugin = Plugin_Profile::sanitize_plugin( $plugin );
		if ( '' === $plugin ) {
			return __( '(unknown plugin)', 'handl-ai-connector-access-control' );
		}
		if ( function_exists( 'get_plugins' ) ) {
			$all = get_plugins();
			if ( isset( $all[ $plugin ]['Name'] ) && '' !== (string) $all[ $plugin ]['Name'] ) {
				return (string) $all[ $plugin ]['Name'];
			}
		}

		return $plugin;
	}

	/**
	 * Profile / UI snapshot for one plugin.
	 *
	 * @param array<string,mixed> $policy
	 * @param array<int,mixed>    $log
	 * @return array{
	 *   hour_limit:?int,
	 *   day_limit:?int,
	 *   hour_count:int,
	 *   day_count:int,
	 *   warn_count:int,
	 *   capped_count:int
	 * }
	 */
	public static function profile_counts( array $policy, string $plugin, array $log, ?int $now = null ): array {
		$eval   = self::evaluate( $policy, $plugin, null, $now );
		$warn   = 0;
		$cap    = 0;
		$plugin = Plugin_Profile::sanitize_plugin( $plugin );
		foreach ( $log as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$row_plugin = isset( $row['plugin'] ) ? Plugin_Profile::sanitize_plugin( (string) $row['plugin'] ) : '';
			if ( $row_plugin !== $plugin ) {
				continue;
			}
			if ( self::CHANNEL_WARN === (string) ( $row['channel'] ?? '' ) ) {
				$warn += self::attempt_count( $row );
				continue;
			}
			if ( 'deny' === (string) ( $row['decision'] ?? '' )
				&& self::REASON === (string) ( $row['denial_reason'] ?? '' ) ) {
				$cap += self::attempt_count( $row );
			}
		}

		return array(
			'hour_limit'   => $eval['hour']['limit'],
			'day_limit'    => $eval['day']['limit'],
			'hour_count'   => (int) $eval['hour']['count'],
			'day_count'    => (int) $eval['day']['count'],
			'warn_count'   => $warn,
			'capped_count' => $cap,
		);
	}

	/**
	 * Plugins currently at soft-warn or hard-capped for dashboard banner.
	 *
	 * @param array<string,mixed> $policy
	 * @return list<array{plugin:string,state:string,window:string,count:int,limit:int}>
	 */
	public static function active_pressure_list( array $policy, ?array $log = null, ?int $now = null ): array {
		unset( $log );
		$hour_map = self::sanitize_plugin_caps( $policy['plugin_rate_caps_hour'] ?? array() );
		$day_map  = self::sanitize_plugin_caps( $policy['plugin_rate_caps_day'] ?? array() );
		$plugins  = array_unique( array_merge( array_keys( $hour_map ), array_keys( $day_map ) ) );
		if ( empty( $plugins ) ) {
			return array();
		}

		$out = array();
		foreach ( $plugins as $plugin ) {
			$eval = self::evaluate( $policy, $plugin, null, $now );
			if ( ! empty( $eval['prevent'] ) ) {
				$out[] = array(
					'plugin' => $plugin,
					'state'  => 'capped',
					'window' => (string) $eval['window'],
					'count'  => (int) $eval['count'],
					'limit'  => (int) $eval['limit'],
				);
				continue;
			}
			if ( ! empty( $eval['soft_warn'] ) ) {
				$out[] = array(
					'plugin' => $plugin,
					'state'  => 'warn',
					'window' => (string) $eval['soft_window'],
					'count'  => (int) $eval['soft_count'],
					'limit'  => (int) $eval['soft_limit'],
				);
			}
		}

		return $out;
	}
}
