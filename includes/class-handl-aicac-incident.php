<?php
/**
 * AICAC-INCIDENT-TIMELINE (#276): group related Activity rows into incidents.
 *
 * Read-only. No enforcement. Timeline UI is a follow-up.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Correlation keys, incident ids, query API, and export hook.
 */
final class Incident {

	public const DEFAULT_WINDOW_SECONDS = 3600;

	public const MIN_WINDOW_SECONDS = 60;

	public const MAX_WINDOW_SECONDS = 86400;

	public const DEFAULT_DENY_BURST_THRESHOLD = 5;

	public const MIN_DENY_BURST_THRESHOLD = 2;

	public const MAX_DENY_BURST_THRESHOLD = 100;

	public const FILTER_EXPORT = 'handl_aicac_incident_export';

	/** @var array<string,string> */
	private const REASON_LABELS = array(
		'freeze_started' => 'Panic freeze started',
		'retry_storm'    => 'Retry storm',
		'deny_burst'     => 'Deny burst',
		'policy_save'    => 'Policy saved',
	);

	/** @var array<string,string> */
	private const EVENT_LABELS = array(
		'freeze_started' => 'Panic freeze started',
		'freeze_ended'   => 'Panic freeze ended',
		'retry_storm'    => 'Retry storm',
		'policy_save'    => 'Policy saved',
		'deny'           => 'Deny',
		'allow'          => 'Allow',
		'observe'        => 'Watch',
	);

	/**
	 * @param mixed $raw
	 */
	public static function sanitize_window_seconds( $raw ): int {
		if ( ! is_numeric( $raw ) ) {
			return self::DEFAULT_WINDOW_SECONDS;
		}
		$n = (int) $raw;
		if ( $n < self::MIN_WINDOW_SECONDS ) {
			return self::MIN_WINDOW_SECONDS;
		}
		if ( $n > self::MAX_WINDOW_SECONDS ) {
			return self::MAX_WINDOW_SECONDS;
		}

		return $n;
	}

	/**
	 * @param mixed $raw
	 */
	public static function sanitize_deny_burst_threshold( $raw ): int {
		if ( ! is_numeric( $raw ) ) {
			return self::DEFAULT_DENY_BURST_THRESHOLD;
		}
		$n = (int) $raw;
		if ( $n < self::MIN_DENY_BURST_THRESHOLD ) {
			return self::MIN_DENY_BURST_THRESHOLD;
		}
		if ( $n > self::MAX_DENY_BURST_THRESHOLD ) {
			return self::MAX_DENY_BURST_THRESHOLD;
		}

		return $n;
	}

	/**
	 * @param array<string,mixed> $policy
	 */
	public static function window_seconds( array $policy ): int {
		return self::sanitize_window_seconds( $policy['incident_window_seconds'] ?? self::DEFAULT_WINDOW_SECONDS );
	}

	/**
	 * @param array<string,mixed> $policy
	 */
	public static function deny_burst_threshold( array $policy ): int {
		return self::sanitize_deny_burst_threshold( $policy['incident_deny_burst_threshold'] ?? self::DEFAULT_DENY_BURST_THRESHOLD );
	}

	/**
	 * @param array<int,mixed>|null $log
	 * @param array<string,mixed>   $policy
	 * @return list<array<string,mixed>>
	 */
	public static function list( ?array $log = null, array $policy = array() ): array {
		if ( null === $log ) {
			$log = self::retained_log();
		}

		return self::group( $log, $policy );
	}

	/**
	 * @param array<int,mixed>|null $log
	 * @param array<string,mixed>   $policy
	 * @return array<string,mixed>|null
	 */
	public static function get( string $id, ?array $log = null, array $policy = array() ): ?array {
		$id = sanitize_key( $id );
		if ( '' === $id ) {
			return null;
		}
		foreach ( self::list( $log, $policy ) as $incident ) {
			if ( (string) ( $incident['id'] ?? '' ) === $id ) {
				return $incident;
			}
		}

		return null;
	}

	/**
	 * @param array<int,mixed>    $log
	 * @param array<string,mixed> $policy
	 * @return list<array<string,mixed>>
	 */
	public static function group( array $log, array $policy = array() ): array {
		$window    = self::window_seconds( $policy );
		$threshold = self::deny_burst_threshold( $policy );
		$rows      = self::normalized_rows( $log );
		if ( empty( $rows ) ) {
			return array();
		}

		$seeds = array_merge( self::explicit_seeds( $rows ), self::deny_burst_seeds( $rows, $window, $threshold ) );
		if ( empty( $seeds ) ) {
			return array();
		}

		$clusters = self::cluster_seeds( $seeds, $window );
		$out      = array();
		foreach ( $clusters as $cluster ) {
			$incident = self::build_incident( $cluster, $rows, $window );
			if ( null !== $incident ) {
				$out[] = $incident;
			}
		}

		usort(
			$out,
			static function ( array $a, array $b ): int {
				$end = (int) ( $b['ended_ts'] ?? 0 ) <=> (int) ( $a['ended_ts'] ?? 0 );
				if ( 0 !== $end ) {
					return $end;
				}

				return strcmp( (string) ( $a['id'] ?? '' ), (string) ( $b['id'] ?? '' ) );
			}
		);

		return array_values( $out );
	}

	/**
	 * @param array<string,mixed> $incident
	 */
	public static function export( array $incident, string $format = 'json' ): string {
		$format  = 'text' === $format ? 'text' : 'json';
		$payload = 'text' === $format ? self::to_text( $incident ) : self::to_json( $incident );
		if ( function_exists( 'apply_filters' ) ) {
			$filtered = apply_filters( self::FILTER_EXPORT, $payload, $incident, $format );
			if ( is_string( $filtered ) ) {
				return $filtered;
			}
		}

		return $payload;
	}

	/**
	 * @param array<string,mixed> $incident
	 */
	public static function to_json( array $incident ): string {
		$flags = JSON_UNESCAPED_SLASHES;
		if ( defined( 'JSON_INVALID_UTF8_SUBSTITUTE' ) ) {
			$flags |= JSON_INVALID_UTF8_SUBSTITUTE;
		}
		$encoded = wp_json_encode(
			array(
				'id'         => (string) ( $incident['id'] ?? '' ),
				'started_ts' => (int) ( $incident['started_ts'] ?? 0 ),
				'ended_ts'   => (int) ( $incident['ended_ts'] ?? 0 ),
				'plugins'    => isset( $incident['plugins'] ) && is_array( $incident['plugins'] ) ? $incident['plugins'] : array(),
				'reasons'    => isset( $incident['reasons'] ) && is_array( $incident['reasons'] ) ? $incident['reasons'] : array(),
				'events'     => isset( $incident['events'] ) && is_array( $incident['events'] ) ? $incident['events'] : array(),
			),
			$flags
		);

		return is_string( $encoded ) ? $encoded : '{}';
	}

	/**
	 * @param array<string,mixed> $incident
	 */
	public static function to_text( array $incident ): string {
		$id      = (string) ( $incident['id'] ?? '' );
		$started = (int) ( $incident['started_ts'] ?? 0 );
		$ended   = (int) ( $incident['ended_ts'] ?? 0 );
		$plugins = isset( $incident['plugins'] ) && is_array( $incident['plugins'] )
			? implode( ', ', array_map( 'strval', $incident['plugins'] ) )
			: '';
		$reasons = isset( $incident['reasons'] ) && is_array( $incident['reasons'] )
			? $incident['reasons']
			: array();
		$labels  = array();
		foreach ( $reasons as $reason ) {
			$reason = (string) $reason;
			$labels[] = self::REASON_LABELS[ $reason ] ?? $reason;
		}

		$lines   = array();
		$lines[] = 'Incident ' . $id;
		$lines[] = 'Started: ' . self::format_ts( $started );
		$lines[] = 'Ended: ' . self::format_ts( $ended );
		$lines[] = 'Plugins: ' . ( '' !== $plugins ? $plugins : '(none)' );
		$lines[] = 'Detection: ' . ( empty( $labels ) ? '(none)' : implode( '; ', $labels ) );
		$lines[] = '';
		$lines[] = 'Timeline:';
		$events  = isset( $incident['events'] ) && is_array( $incident['events'] ) ? $incident['events'] : array();
		foreach ( $events as $event ) {
			if ( ! is_array( $event ) ) {
				continue;
			}
			$type    = self::event_type( $event );
			$label   = self::EVENT_LABELS[ $type ] ?? $type;
			$plugin  = self::row_plugin( $event );
			$lines[] = self::format_ts( (int) ( $event['ts'] ?? 0 ) ) . ' ' . $label . ( '' !== $plugin ? ' ' . $plugin : '' );
		}

		return implode( "\n", $lines ) . "\n";
	}

	/**
	 * @param array<int,mixed> $log
	 * @return list<array<string,mixed>>
	 */
	private static function normalized_rows( array $log ): array {
		$out = array();
		foreach ( $log as $i => $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$ts = isset( $row['ts'] ) ? (int) $row['ts'] : 0;
			if ( $ts <= 0 ) {
				continue;
			}
			$row['_idx'] = (int) $i;
			$out[]       = $row;
		}
		usort(
			$out,
			static function ( array $a, array $b ): int {
				$cmp = (int) ( $a['ts'] ?? 0 ) <=> (int) ( $b['ts'] ?? 0 );
				if ( 0 !== $cmp ) {
					return $cmp;
				}

				return (int) ( $a['_idx'] ?? 0 ) <=> (int) ( $b['_idx'] ?? 0 );
			}
		);

		return $out;
	}

	/**
	 * @param list<array<string,mixed>> $rows
	 * @return list<array{kind:string,ts:int,plugin:string,idx:int}>
	 */
	private static function explicit_seeds( array $rows ): array {
		$seeds = array();
		foreach ( $rows as $row ) {
			$kind = self::seed_kind( $row );
			if ( '' === $kind ) {
				continue;
			}
			$seeds[] = array(
				'kind'   => $kind,
				'ts'     => (int) $row['ts'],
				'plugin' => self::row_plugin( $row ),
				'idx'    => (int) ( $row['_idx'] ?? 0 ),
			);
		}

		return $seeds;
	}

	/**
	 * @param list<array<string,mixed>> $rows
	 * @return list<array{kind:string,ts:int,plugin:string,idx:int}>
	 */
	private static function deny_burst_seeds( array $rows, int $window, int $threshold ): array {
		$by_plugin = array();
		foreach ( $rows as $row ) {
			if ( 'deny' !== (string) ( $row['decision'] ?? '' ) ) {
				continue;
			}
			$plugin = self::row_plugin( $row );
			if ( '' === $plugin ) {
				continue;
			}
			$by_plugin[ $plugin ][] = $row;
		}

		$seeds = array();
		foreach ( $by_plugin as $plugin => $denies ) {
			$n = count( $denies );
			$i = 0;
			while ( $i <= $n - $threshold ) {
				$first = (int) $denies[ $i ]['ts'];
				$hit   = (int) $denies[ $i + $threshold - 1 ]['ts'];
				if ( ( $hit - $first ) <= $window ) {
					$seeds[] = array(
						'kind'   => 'deny_burst',
						'ts'     => $hit,
						'plugin' => $plugin,
						'idx'    => (int) ( $denies[ $i + $threshold - 1 ]['_idx'] ?? 0 ),
					);
					$end = $first + $window;
					while ( $i < $n && (int) $denies[ $i ]['ts'] <= $end ) {
						++$i;
					}
					continue;
				}
				++$i;
			}
		}

		return $seeds;
	}

	/**
	 * @param array<string,mixed> $row
	 */
	private static function seed_kind( array $row ): string {
		$channel  = isset( $row['channel'] ) ? (string) $row['channel'] : '';
		$decision = isset( $row['decision'] ) ? (string) $row['decision'] : '';
		if ( 'freeze' === $channel && 'freeze_started' === $decision ) {
			return 'freeze_started';
		}
		if ( ! empty( $row['retry_storm'] ) || ! empty( $row['retry_storm_collapsed'] ) ) {
			return 'retry_storm';
		}
		if ( 'policy_restore' === $channel || 'policy' === $channel || 'policy_saved' === $decision || 'policy_restored' === $decision ) {
			return 'policy_save';
		}

		return '';
	}

	/**
	 * @param list<array{kind:string,ts:int,plugin:string,idx:int}> $seeds
	 * @return list<list<array{kind:string,ts:int,plugin:string,idx:int}>>
	 */
	private static function cluster_seeds( array $seeds, int $window ): array {
		$n = count( $seeds );
		if ( 0 === $n ) {
			return array();
		}
		$parent = range( 0, $n - 1 );
		$find   = static function ( int $i ) use ( &$parent ): int {
			while ( $parent[ $i ] !== $i ) {
				$parent[ $i ] = $parent[ $parent[ $i ] ];
				$i            = $parent[ $i ];
			}

			return $i;
		};
		for ( $i = 0; $i < $n; $i++ ) {
			for ( $j = $i + 1; $j < $n; $j++ ) {
				if ( abs( $seeds[ $i ]['ts'] - $seeds[ $j ]['ts'] ) > $window ) {
					continue;
				}
				$a = $seeds[ $i ]['plugin'];
				$b = $seeds[ $j ]['plugin'];
				if ( '' !== $a && '' !== $b && $a !== $b ) {
					continue;
				}
				$pi = $find( $i );
				$pj = $find( $j );
				if ( $pi !== $pj ) {
					$parent[ $pj ] = $pi;
				}
			}
		}

		$groups = array();
		for ( $i = 0; $i < $n; $i++ ) {
			$groups[ $find( $i ) ][] = $seeds[ $i ];
		}

		return array_values( $groups );
	}

	/**
	 * @param list<array{kind:string,ts:int,plugin:string,idx:int}> $cluster
	 * @param list<array<string,mixed>>                             $rows
	 * @return array<string,mixed>|null
	 */
	private static function build_incident( array $cluster, array $rows, int $window ): ?array {
		if ( empty( $cluster ) ) {
			return null;
		}
		$seed_ts = array();
		$plugins = array();
		$reasons = array();
		$parts   = array();
		foreach ( $cluster as $seed ) {
			$seed_ts[] = $seed['ts'];
			if ( '' !== $seed['plugin'] ) {
				$plugins[ $seed['plugin'] ] = true;
			}
			$reasons[ $seed['kind'] ] = true;
			$parts[]                  = $seed['kind'] . ':' . $seed['plugin'] . ':' . $seed['ts'];
		}
		sort( $parts );
		$min_seed = min( $seed_ts );
		$max_seed = max( $seed_ts );
		$from     = $min_seed - $window;
		$to       = $max_seed + $window;
		$scoped   = array_keys( $plugins );

		$events = array();
		foreach ( $rows as $row ) {
			$ts = (int) $row['ts'];
			if ( $ts < $from || $ts > $to ) {
				continue;
			}
			$plugin = self::row_plugin( $row );
			if ( ! empty( $scoped ) && '' !== $plugin && ! isset( $plugins[ $plugin ] ) ) {
				continue;
			}
			$event               = $row;
			$event['event_type'] = self::event_type( $row );
			unset( $event['_idx'] );
			$events[] = $event;
		}
		if ( empty( $events ) ) {
			return null;
		}

		$started = (int) $events[0]['ts'];
		$ended   = (int) $events[ count( $events ) - 1 ]['ts'];
		$seen    = array();
		foreach ( $events as $event ) {
			$plugin = self::row_plugin( $event );
			if ( '' !== $plugin ) {
				$seen[ $plugin ] = true;
			}
		}
		$plugin_list = array_keys( $seen );
		sort( $plugin_list );
		$reason_list = array_keys( $reasons );
		sort( $reason_list );

		return array(
			'id'         => 'inc_' . substr( sha1( implode( '|', $parts ) ), 0, 12 ),
			'started_ts' => $started,
			'ended_ts'   => $ended,
			'plugins'    => $plugin_list,
			'reasons'    => $reason_list,
			'events'     => $events,
		);
	}

	/**
	 * @param array<string,mixed> $row
	 */
	public static function event_type( array $row ): string {
		$channel  = isset( $row['channel'] ) ? (string) $row['channel'] : '';
		$decision = isset( $row['decision'] ) ? (string) $row['decision'] : '';
		if ( 'freeze' === $channel && 'freeze_started' === $decision ) {
			return 'freeze_started';
		}
		if ( 'freeze' === $channel && 'freeze_ended' === $decision ) {
			return 'freeze_ended';
		}
		if ( ! empty( $row['retry_storm'] ) || ! empty( $row['retry_storm_collapsed'] ) ) {
			return 'retry_storm';
		}
		if ( 'policy_restore' === $channel || 'policy' === $channel || 'policy_saved' === $decision || 'policy_restored' === $decision ) {
			return 'policy_save';
		}
		if ( isset( self::EVENT_LABELS[ $decision ] ) ) {
			return $decision;
		}

		return '' !== $decision ? $decision : ( '' !== $channel ? $channel : 'event' );
	}

	/**
	 * @param array<string,mixed> $row
	 */
	public static function row_plugin( array $row ): string {
		if ( ! isset( $row['plugin'] ) || ! is_string( $row['plugin'] ) ) {
			return '';
		}
		if ( class_exists( Plugin_Profile::class ) ) {
			return Plugin_Profile::sanitize_plugin( $row['plugin'] );
		}

		return $row['plugin'];
	}

	/**
	 * @return array<int,mixed>
	 */
	private static function retained_log(): array {
		$log = get_option( Plugin::LOG_OPTION_KEY );
		if ( ! is_array( $log ) ) {
			return array();
		}

		return $log;
	}

	private static function format_ts( int $ts ): string {
		if ( $ts <= 0 ) {
			return '0';
		}

		return gmdate( 'Y-m-d\TH:i:s\Z', $ts );
	}
}
