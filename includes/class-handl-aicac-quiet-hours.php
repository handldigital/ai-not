<?php
/**
 * AICAC-HOURS: Scheduled quiet hours / maintenance windows (#132).
 *
 * Site-wide schedule evaluated in the same decision layer as Emergency stop
 * (after kill_switch, before role/plugin rules). Deny windows block; Observe
 * windows never block but tag activity rows.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Quiet-hours schedule storage + evaluation.
 */
final class Quiet_Hours {

	public const MAX_WINDOWS = 3;

	public const MODE_DENY    = 'deny';
	public const MODE_OBSERVE = 'observe';

	/**
	 * @param mixed $raw
	 * @return list<array{id:string,name:string,days:list<int>,start:string,end:string,mode:string}>
	 */
	public static function sanitize_windows( $raw ): array {
		if ( ! is_array( $raw ) ) {
			return array();
		}

		$out = array();
		foreach ( $raw as $row ) {
			if ( count( $out ) >= self::MAX_WINDOWS ) {
				break;
			}
			if ( ! is_array( $row ) ) {
				continue;
			}

			$name = isset( $row['name'] ) ? sanitize_text_field( (string) $row['name'] ) : '';
			$start = self::sanitize_hhmm( $row['start'] ?? '' );
			$end   = self::sanitize_hhmm( $row['end'] ?? '' );
			$mode  = self::sanitize_mode( $row['mode'] ?? self::MODE_DENY );
			$days  = self::sanitize_days( $row['days'] ?? array() );

			// Incomplete rows are dropped (no silent partial schedules).
			if ( '' === $name || null === $start || null === $end || empty( $days ) ) {
				continue;
			}

			$id = isset( $row['id'] ) ? sanitize_key( (string) $row['id'] ) : '';
			if ( '' === $id ) {
				$id = substr( md5( $name . '|' . $start . '|' . $end . '|' . implode( ',', $days ) . '|' . $mode ), 0, 12 );
			}

			$out[] = array(
				'id'    => $id,
				'name'  => $name,
				'days'  => $days,
				'start' => $start,
				'end'   => $end,
				'mode'  => $mode,
			);
		}

		return $out;
	}

	/**
	 * @param mixed $raw
	 */
	public static function sanitize_mode( $raw ): string {
		$mode = sanitize_key( (string) $raw );
		return self::MODE_OBSERVE === $mode ? self::MODE_OBSERVE : self::MODE_DENY;
	}

	/**
	 * @param mixed $raw
	 * @return list<int> 0=Sunday … 6=Saturday (PHP date('w')).
	 */
	public static function sanitize_days( $raw ): array {
		if ( ! is_array( $raw ) ) {
			return array();
		}
		$out = array();
		foreach ( $raw as $day ) {
			$d = (int) $day;
			if ( $d >= 0 && $d <= 6 ) {
				$out[] = $d;
			}
		}
		$out = array_values( array_unique( $out ) );
		sort( $out, SORT_NUMERIC );
		return $out;
	}

	/**
	 * @param mixed $raw
	 */
	public static function sanitize_hhmm( $raw ): ?string {
		$s = trim( (string) $raw );
		if ( ! preg_match( '/^([01]?\d|2[0-3]):([0-5]\d)$/', $s, $m ) ) {
			return null;
		}
		return sprintf( '%02d:%02d', (int) $m[1], (int) $m[2] );
	}

	/**
	 * Site timezone (wp_timezone when available).
	 */
	public static function timezone( ?\DateTimeZone $tz = null ): \DateTimeZone {
		if ( $tz instanceof \DateTimeZone ) {
			return $tz;
		}
		if ( function_exists( 'wp_timezone' ) ) {
			$wp = wp_timezone();
			if ( $wp instanceof \DateTimeZone ) {
				return $wp;
			}
		}
		return new \DateTimeZone( 'UTC' );
	}

	/**
	 * Active window at $now, or null when none configured / none matching.
	 *
	 * When multiple windows match, Deny wins over Observe; otherwise first match.
	 *
	 * @param array<string,mixed> $policy
	 * @return array{id:string,name:string,days:list<int>,start:string,end:string,mode:string,ends_at:int,ends_label:string}|null
	 */
	public static function active_window( array $policy, ?int $now = null, ?\DateTimeZone $tz = null ): ?array {
		$windows = self::sanitize_windows( $policy['quiet_hours'] ?? array() );
		if ( empty( $windows ) ) {
			return null;
		}

		$now = null !== $now ? $now : time();
		if ( $now <= 0 ) {
			$now = time();
		}
		$tz = self::timezone( $tz );

		$deny    = null;
		$observe = null;
		foreach ( $windows as $win ) {
			$match = self::match_window( $win, $now, $tz );
			if ( null === $match ) {
				continue;
			}
			if ( self::MODE_DENY === $match['mode'] ) {
				$deny = $match;
				break;
			}
			if ( null === $observe ) {
				$observe = $match;
			}
		}

		return $deny ?? $observe;
	}

	/**
	 * Decision-path gate: Deny window → prevent; Observe / none → null (no prevent).
	 *
	 * @param array<string,mixed> $policy
	 * @return array{prevent:bool,reason:string,window:array}|null
	 */
	public static function evaluate_gate( array $policy, ?int $now = null, ?\DateTimeZone $tz = null ): ?array {
		$active = self::active_window( $policy, $now, $tz );
		if ( null === $active ) {
			return null;
		}
		if ( self::MODE_DENY !== $active['mode'] ) {
			return null;
		}
		return array(
			'prevent' => true,
			'reason'  => 'quiet_hours',
			'window'  => $active,
		);
	}

	/**
	 * Dashboard / notice line when a window is live.
	 *
	 * @param array<string,mixed> $policy
	 */
	public static function active_banner_text( array $policy, ?int $now = null, ?\DateTimeZone $tz = null ): ?string {
		$active = self::active_window( $policy, $now, $tz );
		if ( null === $active ) {
			return null;
		}
		$until = (string) ( $active['ends_label'] ?? '' );
		$name  = (string) ( $active['name'] ?? '' );
		if ( self::MODE_OBSERVE === $active['mode'] ) {
			return sprintf(
				/* translators: 1: window name, 2: local end time HH:MM */
				__( 'Quiet hours (“%1$s”) are active until %2$s. Normal access rules are still in effect.', 'handl-ai-connector-access-control' ),
				$name,
				$until
			);
		}
		return sprintf(
			/* translators: 1: window name, 2: local end time HH:MM */
			__( 'Quiet hours (“%1$s”) are active. AI Client calls are blocked until %2$s.', 'handl-ai-connector-access-control' ),
			$name,
			$until
		);
	}

	/**
	 * @param array{id:string,name:string,days:list<int>,start:string,end:string,mode:string} $win
	 * @return array{id:string,name:string,days:list<int>,start:string,end:string,mode:string,ends_at:int,ends_label:string}|null
	 */
	public static function match_window( array $win, int $now, \DateTimeZone $tz ): ?array {
		try {
			$dt = ( new \DateTimeImmutable( '@' . $now ) )->setTimezone( $tz );
		} catch ( \Exception $e ) {
			return null;
		}

		$dow      = (int) $dt->format( 'w' ); // 0=Sun … 6=Sat
		$minutes  = ( (int) $dt->format( 'G' ) ) * 60 + (int) $dt->format( 'i' );
		$start_m  = self::hhmm_to_minutes( (string) $win['start'] );
		$end_m    = self::hhmm_to_minutes( (string) $win['end'] );
		$days     = $win['days'];
		$prev_dow = ( $dow + 6 ) % 7;

		$active  = false;
		$ends_at = null;

		if ( $start_m === $end_m ) {
			// Full-day window on selected days (identical start/end = all day).
			if ( in_array( $dow, $days, true ) ) {
				$active  = true;
				$ends_at = $dt->modify( '+1 day' )->setTime( 0, 0, 0 )->getTimestamp();
			}
		} elseif ( $start_m < $end_m ) {
			// Same calendar day.
			if ( in_array( $dow, $days, true ) && $minutes >= $start_m && $minutes < $end_m ) {
				$active  = true;
				$ends_at = self::local_clock_timestamp( $dt, $end_m );
			}
		} else {
			// Spans midnight: [start, 24:00) on selected day, [00:00, end) next morning.
			if ( in_array( $dow, $days, true ) && $minutes >= $start_m ) {
				$active  = true;
				$ends_at = self::local_clock_timestamp( $dt->modify( '+1 day' ), $end_m );
			} elseif ( in_array( $prev_dow, $days, true ) && $minutes < $end_m ) {
				$active  = true;
				$ends_at = self::local_clock_timestamp( $dt, $end_m );
			}
		}

		if ( ! $active || null === $ends_at ) {
			return null;
		}

		return array_merge(
			$win,
			array(
				'ends_at'    => $ends_at,
				'ends_label' => ( new \DateTimeImmutable( '@' . $ends_at ) )->setTimezone( $tz )->format( 'H:i' ),
			)
		);
	}

	/**
	 * Unix timestamp for HH:MM on the same local calendar day as $dt.
	 */
	private static function local_clock_timestamp( \DateTimeImmutable $dt, int $minutes_of_day ): int {
		$minutes_of_day = max( 0, min( ( 24 * 60 ) - 1, $minutes_of_day ) );
		$h              = intdiv( $minutes_of_day, 60 );
		$i              = $minutes_of_day % 60;
		return $dt->setTime( $h, $i, 0 )->getTimestamp();
	}

	private static function hhmm_to_minutes( string $hhmm ): int {
		$parts = explode( ':', $hhmm );
		return ( (int) $parts[0] ) * 60 + (int) ( $parts[1] ?? 0 );
	}

	/**
	 * Weekday labels for settings UI (Sunday-first to match date('w')).
	 *
	 * @return array<int,string>
	 */
	public static function day_labels(): array {
		return array(
			0 => __( 'Sun', 'handl-ai-connector-access-control' ),
			1 => __( 'Mon', 'handl-ai-connector-access-control' ),
			2 => __( 'Tue', 'handl-ai-connector-access-control' ),
			3 => __( 'Wed', 'handl-ai-connector-access-control' ),
			4 => __( 'Thu', 'handl-ai-connector-access-control' ),
			5 => __( 'Fri', 'handl-ai-connector-access-control' ),
			6 => __( 'Sat', 'handl-ai-connector-access-control' ),
		);
	}
}
