<?php
/**
 * AICAC-RATE-CAP (#275): per-plugin call-count ceilings (hour + day).
 *
 * Empty caps = unlimited (current behavior). Soft-warn once per window at
 * >=80%; hard deny at 100% with denial_reason `rate_cap`. Counters come from
 * the retained recent-calls log in the site timezone.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Call-volume ceilings + soft-warn / hard-deny helpers.
 */
final class Rate_Cap {

	public const REASON = 'rate_cap';

	public const CHANNEL_WARN = 'rate_warn';

	public const SOFT_WARN_RATIO = 0.8;

	/** Fired soft-warns: "{plugin}|hour|{YmdH}" / "{plugin}|day|{Ymd}" => meta. */
	public const WARNED_OPTION_KEY = 'handl_aicac_rate_cap_warned';

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
	 * Count retained Activity rows for one plugin in [start, end).
	 * Excludes soft-warn audit rows and sticky rate_cap denials.
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
			++$n;
		}

		return $n;
	}

	/**
	 * @param array<string,mixed> $row
	 */
	public static function is_countable_row( array $row, string $plugin ): bool {
		$row_plugin = isset( $row['plugin'] ) ? Plugin_Profile::sanitize_plugin( (string) $row['plugin'] ) : '';
		if ( $row_plugin !== $plugin ) {
			return false;
		}
		if ( ! Usage_Trends::is_activity_row( $row ) ) {
			return false;
		}
		$channel = isset( $row['channel'] ) ? (string) $row['channel'] : '';
		if ( self::CHANNEL_WARN === $channel ) {
			return false;
		}
		// Sticky rate-cap denials must not inflate the ceiling.
		if ( self::REASON === (string) ( $row['denial_reason'] ?? '' ) ) {
			return false;
		}

		return true;
	}

	/**
	 * Evaluate hour + day caps for a plugin against the retained log.
	 *
	 * @param array<string,mixed> $policy
	 * @param array<int,mixed>|null $log
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
		$plugin = Plugin_Profile::sanitize_plugin( $plugin );
		$now    = null !== $now ? (int) $now : Clock::now();
		$tz     = Quiet_Hours::timezone( $tz );

		$hour_bounds = self::window_bounds( self::WINDOW_HOUR, $now, $tz );
		$day_bounds  = self::window_bounds( self::WINDOW_DAY, $now, $tz );

		$hour_limit = self::get_hour_cap( $policy, $plugin );
		$day_limit  = self::get_day_cap( $policy, $plugin );

		if ( null === $log ) {
			$log = Policy::get_retained_log( $now );
		}

		$hour_count = '' !== $plugin
			? self::count_plugin_calls_in_window( $log, $plugin, $hour_bounds['start'], $hour_bounds['end'] )
			: 0;
		$day_count = '' !== $plugin
			? self::count_plugin_calls_in_window( $log, $plugin, $day_bounds['start'], $day_bounds['end'] )
			: 0;

		$hour = array(
			'limit' => $hour_limit,
			'count' => $hour_count,
			'key'   => $hour_bounds['key'],
			'start' => $hour_bounds['start'],
			'end'   => $hour_bounds['end'],
		);
		$day = array(
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

		// Hard deny: hour first, then day (either trips the gate).
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

		// Soft warn: first window that has reached >=80% (hour preferred).
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
	 *
	 * @param array<string,mixed>      $event
	 * @param array<string,mixed>|null $policy
	 * @param array<int,mixed>|null    $log
	 * @return array{active:bool,prevent:bool,reason:string,window:string,soft_warn:bool}
	 */
	public static function apply_to_event( array &$event, $policy = null, ?array $log = null, ?int $now = null ): array {
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

		$eval = self::evaluate( $policy, $plugin, $log, $now );

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

		$soft = false;
		if ( ! empty( $eval['soft_warn'] ) ) {
			$soft = self::maybe_fire_soft_warn( $policy, $plugin, $eval, $now );
			if ( $soft ) {
				$event['rate_warn']         = true;
				$event['rate_warn_window']  = $eval['soft_window'];
				$event['rate_warn_limit']   = $eval['soft_limit'];
				$event['rate_warn_count']   = $eval['soft_count'];
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
	 * Fire soft-warn once per plugin+window key: audit row + denied-alert pipeline channel.
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
		$map = self::get_warned_map();
		$map[ $fired_key ] = array(
			'at'    => $now,
			'limit' => $limit,
			'count' => $count,
		);
		// Prune stale keys (keep newest 200).
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

	/**
	 * Clear fired state (tests / CLI).
	 */
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
		$body = implode(
			"\n",
			array(
				__( 'HandL AI Connector Access Control call-cap soft warning', 'handl-ai-connector-access-control' ),
				'',
				sprintf(
					/* translators: %s: plugin label */
					__( 'Plugin: %s', 'handl-ai-connector-access-control' ),
					$label
				),
				sprintf(
					/* translators: 1: call count, 2: cap, 3: window label */
					__( 'Usage: %1$d of %2$d calls %3$s (80%% warning).', 'handl-ai-connector-access-control' ),
					$count,
					$limit,
					$win
				),
				'',
				__( 'New calls will be blocked when the cap is reached.', 'handl-ai-connector-access-control' ),
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
			'ts'           => $now,
			'decision'     => self::CHANNEL_WARN,
			'channel'      => self::CHANNEL_WARN,
			'plugin'       => $plugin,
			'operation'    => '',
			'provider'     => '',
			'model'        => '',
			'rate_window'  => $window,
			'rate_limit'   => $limit,
			'rate_count'   => $count,
			'denial_reason'=> '',
		);

		$log = get_option( Plugin::LOG_OPTION_KEY, array() );
		if ( ! is_array( $log ) ) {
			$log = array();
		}
		$log[] = $row;
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
		$eval = self::evaluate( $policy, $plugin, $log, $now );
		$warn = 0;
		$cap  = 0;
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
				++$warn;
			}
			if ( self::REASON === (string) ( $row['denial_reason'] ?? '' ) ) {
				++$cap;
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
		$hour_map = self::sanitize_plugin_caps( $policy['plugin_rate_caps_hour'] ?? array() );
		$day_map  = self::sanitize_plugin_caps( $policy['plugin_rate_caps_day'] ?? array() );
		$plugins  = array_unique( array_merge( array_keys( $hour_map ), array_keys( $day_map ) ) );
		if ( empty( $plugins ) ) {
			return array();
		}
		if ( null === $log ) {
			$log = Policy::get_retained_log( $now );
		}

		$out = array();
		foreach ( $plugins as $plugin ) {
			$eval = self::evaluate( $policy, $plugin, $log, $now );
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
