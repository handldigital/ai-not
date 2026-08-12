<?php
/**
 * AICAC-SNOOZE: per-plugin temporary mute for alert delivery (#149).
 *
 * Suppresses denial, shadow-AI, spend, anomaly, and drift ALERTS for one plugin.
 * Enforcement and logging continue unchanged. Separate option storage so
 * export/import policy surface is untouched.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Time-boxed per-plugin alert suppression + would-have-alerted counters.
 */
final class Alert_Snooze {

	public const OPTION_KEY = 'handl_aicac_alert_snoozes';

	/**
	 * Preset key => duration seconds.
	 *
	 * @var array<string,int>
	 */
	public const PRESETS = array(
		'1h'  => HOUR_IN_SECONDS,
		'8h'  => 8 * HOUR_IN_SECONDS,
		'24h' => DAY_IN_SECONDS,
		'7d'  => WEEK_IN_SECONDS,
	);

	/**
	 * @param mixed $raw
	 * @return array<string,array{until:int,started:int,suppressed:int,by_kind:array<string,int>}>
	 */
	public static function sanitize_map( $raw ): array {
		if ( ! is_array( $raw ) ) {
			return array();
		}
		$out = array();
		foreach ( $raw as $basename => $row ) {
			$basename = Plugin_Profile::sanitize_plugin( $basename );
			if ( '' === $basename || ! is_array( $row ) ) {
				continue;
			}
			$until   = isset( $row['until'] ) ? (int) $row['until'] : 0;
			$started = isset( $row['started'] ) ? (int) $row['started'] : 0;
			if ( $until <= 0 ) {
				continue;
			}
			if ( $started <= 0 ) {
				$started = $until;
			}
			$suppressed = isset( $row['suppressed'] ) ? max( 0, (int) $row['suppressed'] ) : 0;
			$by_kind    = array();
			if ( isset( $row['by_kind'] ) && is_array( $row['by_kind'] ) ) {
				foreach ( $row['by_kind'] as $kind => $n ) {
					$kind = sanitize_key( (string) $kind );
					if ( '' === $kind ) {
						continue;
					}
					$by_kind[ $kind ] = max( 0, (int) $n );
				}
			}
			$out[ $basename ] = array(
				'until'      => $until,
				'started'    => $started,
				'suppressed' => $suppressed,
				'by_kind'    => $by_kind,
			);
		}

		return $out;
	}

	/**
	 * @return array<string,array{until:int,started:int,suppressed:int,by_kind:array<string,int>}>
	 */
	public static function get_map(): array {
		return self::sanitize_map( get_option( self::OPTION_KEY, array() ) );
	}

	/**
	 * @param array<string,array{until:int,started:int,suppressed:int,by_kind:array<string,int>}> $map
	 */
	public static function save_map( array $map ): void {
		$map = self::sanitize_map( $map );
		if ( empty( $map ) ) {
			delete_option( self::OPTION_KEY );
			return;
		}
		update_option( self::OPTION_KEY, $map, false );
	}

	/**
	 * @param mixed $raw
	 */
	public static function sanitize_preset( $raw ): string {
		$key = sanitize_key( (string) $raw );
		return isset( self::PRESETS[ $key ] ) ? $key : '';
	}

	/**
	 * Whether alerts for this plugin are currently muted.
	 * Side effect: expires stale rows and writes end-of-snooze summary once.
	 */
	public static function is_snoozed( ?string $plugin, ?int $now = null ): bool {
		$plugin = Plugin_Profile::sanitize_plugin( (string) $plugin );
		if ( '' === $plugin ) {
			return false;
		}
		$now = null !== $now ? (int) $now : time();
		self::purge_expired( $now );

		$map = self::get_map();
		if ( ! isset( $map[ $plugin ] ) ) {
			return false;
		}

		return (int) $map[ $plugin ]['until'] > $now;
	}

	/**
	 * Unix end time when active; null when not snoozed.
	 */
	public static function until( ?string $plugin, ?int $now = null ): ?int {
		$plugin = Plugin_Profile::sanitize_plugin( (string) $plugin );
		if ( '' === $plugin ) {
			return null;
		}
		$now = null !== $now ? (int) $now : time();
		self::purge_expired( $now );
		$map = self::get_map();
		if ( ! isset( $map[ $plugin ] ) ) {
			return null;
		}
		$until = (int) $map[ $plugin ]['until'];
		return $until > $now ? $until : null;
	}

	/**
	 * Start or extend a snooze. Writes an audit row.
	 *
	 * @param string $preset One of PRESETS keys.
	 */
	public static function set( string $plugin, string $preset, ?int $now = null ): bool {
		$plugin = Plugin_Profile::sanitize_plugin( $plugin );
		$preset = self::sanitize_preset( $preset );
		if ( '' === $plugin || '' === $preset ) {
			return false;
		}
		$now      = null !== $now ? (int) $now : time();
		$duration = self::PRESETS[ $preset ];
		$until    = $now + $duration;

		$map = self::get_map();
		// Extending keeps prior suppressed count so the end summary is cumulative.
		$prev_suppressed = isset( $map[ $plugin ]['suppressed'] ) ? (int) $map[ $plugin ]['suppressed'] : 0;
		$prev_by_kind    = isset( $map[ $plugin ]['by_kind'] ) && is_array( $map[ $plugin ]['by_kind'] )
			? $map[ $plugin ]['by_kind']
			: array();

		$map[ $plugin ] = array(
			'until'      => $until,
			'started'    => $now,
			'suppressed' => $prev_suppressed,
			'by_kind'    => $prev_by_kind,
		);
		self::save_map( $map );

		self::append_audit(
			$plugin,
			'alert_snooze_start',
			array(
				'preset' => $preset,
				'until'  => $until,
			)
		);

		return true;
	}

	/**
	 * Cancel an active snooze. Writes summary audit when any events were suppressed.
	 *
	 * @return array{cancelled:bool,suppressed:int,by_kind:array<string,int>}
	 */
	public static function cancel( string $plugin, ?int $now = null ): array {
		$plugin = Plugin_Profile::sanitize_plugin( $plugin );
		$empty  = array(
			'cancelled'  => false,
			'suppressed' => 0,
			'by_kind'    => array(),
		);
		if ( '' === $plugin ) {
			return $empty;
		}
		$now = null !== $now ? (int) $now : time();
		$map = self::get_map();
		if ( ! isset( $map[ $plugin ] ) ) {
			return $empty;
		}

		$row = $map[ $plugin ];
		unset( $map[ $plugin ] );
		self::save_map( $map );

		$suppressed = (int) ( $row['suppressed'] ?? 0 );
		$by_kind    = isset( $row['by_kind'] ) && is_array( $row['by_kind'] ) ? $row['by_kind'] : array();

		self::append_audit(
			$plugin,
			'alert_snooze_cancel',
			array(
				'suppressed' => $suppressed,
				'by_kind'    => $by_kind,
				'until'      => (int) ( $row['until'] ?? 0 ),
			)
		);

		if ( $suppressed > 0 ) {
			self::append_audit(
				$plugin,
				'alert_snooze_summary',
				array(
					'suppressed' => $suppressed,
					'by_kind'    => $by_kind,
					'reason'     => 'cancel',
				)
			);
		}

		return array(
			'cancelled'  => true,
			'suppressed' => $suppressed,
			'by_kind'    => $by_kind,
		);
	}

	/**
	 * If snoozed, increment would-have-alerted counter and return true (caller must not send).
	 */
	public static function should_suppress( ?string $plugin, string $kind = 'denial', ?int $now = null ): bool {
		$plugin = Plugin_Profile::sanitize_plugin( (string) $plugin );
		$kind   = sanitize_key( $kind );
		if ( '' === $kind ) {
			$kind = 'denial';
		}
		if ( '' === $plugin || ! self::is_snoozed( $plugin, $now ) ) {
			return false;
		}

		$map = self::get_map();
		if ( ! isset( $map[ $plugin ] ) ) {
			return false;
		}
		$map[ $plugin ]['suppressed'] = (int) $map[ $plugin ]['suppressed'] + 1;
		if ( ! isset( $map[ $plugin ]['by_kind'][ $kind ] ) ) {
			$map[ $plugin ]['by_kind'][ $kind ] = 0;
		}
		$map[ $plugin ]['by_kind'][ $kind ] = (int) $map[ $plugin ]['by_kind'][ $kind ] + 1;
		self::save_map( $map );

		return true;
	}

	/**
	 * Active snoozes for Dashboard (sorted by until ascending).
	 *
	 * @return list<array{plugin:string,until:int,suppressed:int}>
	 */
	public static function active_list( ?int $now = null ): array {
		$now = null !== $now ? (int) $now : time();
		self::purge_expired( $now );
		$list = array();
		foreach ( self::get_map() as $plugin => $row ) {
			$until = (int) $row['until'];
			if ( $until <= $now ) {
				continue;
			}
			$list[] = array(
				'plugin'     => $plugin,
				'until'      => $until,
				'suppressed' => (int) $row['suppressed'],
			);
		}
		usort(
			$list,
			static function ( $a, $b ) {
				return $a['until'] <=> $b['until'];
			}
		);

		return $list;
	}

	/**
	 * Drop expired entries and write end summaries once.
	 *
	 * @return list<array{plugin:string,suppressed:int}>
	 */
	public static function purge_expired( ?int $now = null ): array {
		$now     = null !== $now ? (int) $now : time();
		$map     = self::get_map();
		$changed = false;
		$ended   = array();

		foreach ( $map as $plugin => $row ) {
			if ( (int) $row['until'] > $now ) {
				continue;
			}
			$suppressed = (int) $row['suppressed'];
			$by_kind    = isset( $row['by_kind'] ) && is_array( $row['by_kind'] ) ? $row['by_kind'] : array();
			unset( $map[ $plugin ] );
			$changed = true;
			$ended[] = array(
				'plugin'     => $plugin,
				'suppressed' => $suppressed,
			);
			self::append_audit(
				$plugin,
				'alert_snooze_summary',
				array(
					'suppressed' => $suppressed,
					'by_kind'    => $by_kind,
					'reason'     => 'expired',
				)
			);
		}

		if ( $changed ) {
			self::save_map( $map );
		}

		return $ended;
	}

	/**
	 * Human remaining / end time for UI.
	 */
	public static function remaining_label( string $plugin, ?int $now = null ): string {
		$until = self::until( $plugin, $now );
		if ( null === $until ) {
			return '';
		}
		$now  = null !== $now ? (int) $now : time();
		$left = max( 0, $until - $now );

		if ( $left < HOUR_IN_SECONDS ) {
			$mins = max( 1, (int) ceil( $left / MINUTE_IN_SECONDS ) );
			return sprintf(
				/* translators: %d: minutes remaining */
				_n( 'Alerts muted for %d minute', 'Alerts muted for %d minutes', $mins, 'handl-ai-connector-access-control' ),
				$mins
			);
		}
		if ( $left < DAY_IN_SECONDS ) {
			$hours = max( 1, (int) ceil( $left / HOUR_IN_SECONDS ) );
			return sprintf(
				/* translators: %d: hours remaining */
				_n( 'Alerts muted for %d hour', 'Alerts muted for %d hours', $hours, 'handl-ai-connector-access-control' ),
				$hours
			);
		}
		$days = max( 1, (int) ceil( $left / DAY_IN_SECONDS ) );
		return sprintf(
			/* translators: %d: days remaining */
			_n( 'Alerts muted for %d day', 'Alerts muted for %d days', $days, 'handl-ai-connector-access-control' ),
			$days
		);
	}

	/**
	 * Local time string for Dashboard “until HH:MM”.
	 */
	public static function until_time_label( int $until ): string {
		if ( $until <= 0 ) {
			return '';
		}
		if ( function_exists( 'wp_date' ) ) {
			return (string) wp_date( 'Y-m-d H:i', $until );
		}

		return gmdate( 'Y-m-d H:i', $until ) . ' UTC';
	}

	/**
	 * @param array<string,mixed> $extra
	 */
	private static function append_audit( string $plugin, string $decision, array $extra = array() ): void {
		$event = array_merge(
			array(
				'ts'       => time(),
				'plugin'   => $plugin,
				'decision' => $decision,
				'channel'  => 'alert_snooze',
				'operation'=> '',
				'provider' => '',
			),
			$extra
		);
		Policy::append_log_event( $event );
	}
}
