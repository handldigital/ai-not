<?php
/**
 * AICAC-DEAD-RULES (#290): flag Allow rules with zero matches in N days.
 *
 * Usage axis (distinct from review-due calendar staleness and version-watch).
 * Stamps last_matched at decision time so flags survive Activity log retention.
 * Retire archives via Policy_Snapshots (human action only — never auto-retire).
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Dead Allow detection, retire/undo, and WP-CLI list.
 */
final class Dead_Rules {

	/** plugin basename => unix ts of last Allow match. */
	public const MATCHED_OPTION_KEY = 'handl_aicac_dead_rules_last_matched';

	/** plugin basename => unix ts when the Allow rule was created/changed. */
	public const ALLOW_SINCE_OPTION_KEY = 'handl_aicac_dead_rules_allow_since';

	public const DEFAULT_DAYS = 60;

	/** @var list<int> */
	public const DAY_OPTIONS = array( 30, 60, 90, 0 );

	public const SCAN_TRANSIENT_KEY = 'handl_aicac_dead_rules_scanned';

	public const SCAN_INTERVAL = 300;

	/**
	 * @param mixed $raw
	 */
	public static function sanitize_days( $raw ): int {
		$days = is_numeric( $raw ) ? (int) $raw : self::DEFAULT_DAYS;
		if ( ! in_array( $days, self::DAY_OPTIONS, true ) ) {
			return self::DEFAULT_DAYS;
		}

		return $days;
	}

	/**
	 * @param array<string,mixed> $policy
	 */
	public static function window_days( array $policy ): int {
		return self::sanitize_days( $policy['dead_rules_days'] ?? self::DEFAULT_DAYS );
	}

	/**
	 * @param mixed $raw
	 * @return array<string,int>
	 */
	public static function sanitize_stamps( $raw ): array {
		if ( ! is_array( $raw ) ) {
			return array();
		}
		$out = array();
		foreach ( $raw as $basename => $ts ) {
			$basename = Plugin_Profile::sanitize_plugin( (string) $basename );
			if ( '' === $basename ) {
				continue;
			}
			$ts = (int) $ts;
			if ( $ts <= 0 ) {
				continue;
			}
			$out[ $basename ] = $ts;
		}

		return $out;
	}

	/**
	 * @return array<string,int>
	 */
	public static function get_matched(): array {
		return self::sanitize_stamps( get_option( self::MATCHED_OPTION_KEY, array() ) );
	}

	/**
	 * @param array<string,int> $map
	 */
	public static function put_matched( array $map ): void {
		$map = self::sanitize_stamps( $map );
		if ( empty( $map ) ) {
			delete_option( self::MATCHED_OPTION_KEY );
			return;
		}
		update_option( self::MATCHED_OPTION_KEY, $map, false );
	}

	/**
	 * @return array<string,int>
	 */
	public static function get_allow_since(): array {
		return self::sanitize_stamps( get_option( self::ALLOW_SINCE_OPTION_KEY, array() ) );
	}

	/**
	 * @param array<string,int> $map
	 */
	public static function put_allow_since( array $map ): void {
		$map = self::sanitize_stamps( $map );
		if ( empty( $map ) ) {
			delete_option( self::ALLOW_SINCE_OPTION_KEY );
			return;
		}
		update_option( self::ALLOW_SINCE_OPTION_KEY, $map, false );
	}

	/**
	 * Keep stamps only for explicit Allow rules.
	 *
	 * @param array<string,mixed> $policy
	 * @param array<string,int>   $stamps
	 * @return array<string,int>
	 */
	public static function normalize_allow_only( array $policy, array $stamps ): array {
		$plugins = isset( $policy['plugins'] ) && is_array( $policy['plugins'] )
			? $policy['plugins']
			: array();
		$stamps = self::sanitize_stamps( $stamps );
		$kept   = array();
		foreach ( $stamps as $basename => $ts ) {
			$rule = isset( $plugins[ $basename ] ) ? (string) $plugins[ $basename ] : '';
			if ( 'allow' !== $rule ) {
				continue;
			}
			$kept[ $basename ] = $ts;
		}

		return $kept;
	}

	public static function init(): void {
		add_action( 'init', array( self::class, 'lazy_scan' ), 32 );
		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			self::register_cli();
		}
	}

	/**
	 * Register WP-CLI read command when WP-CLI is available.
	 */
	public static function register_cli(): void {
		if ( ! defined( 'WP_CLI' ) || ! WP_CLI ) {
			return;
		}
		if ( ! class_exists( '\WP_CLI' ) ) {
			return;
		}
		\WP_CLI::add_command( 'handl-aicac dead-rules list', array( self::class, 'cmd_list' ) );
	}

	/**
	 * Stamp allow_since when an Allow rule is created or changed to allow.
	 * Clears stamps when Allow is removed. Deny rules are never stamped.
	 *
	 * @param array<string,mixed> $incoming
	 * @param array<string,mixed> $previous
	 * @param int|null            $now
	 */
	public static function stamp_on_rule_changes( array $incoming, array $previous, ?int $now = null ): void {
		$now    = null !== $now && $now > 0 ? $now : time();
		$before = isset( $previous['plugins'] ) && is_array( $previous['plugins'] )
			? $previous['plugins']
			: array();
		$after = isset( $incoming['plugins'] ) && is_array( $incoming['plugins'] )
			? $incoming['plugins']
			: array();

		$matched = self::get_matched();
		$since   = self::get_allow_since();

		foreach ( $after as $basename => $rule ) {
			$basename = Plugin_Profile::sanitize_plugin( (string) $basename );
			$rule     = (string) $rule;
			if ( '' === $basename || 'allow' !== $rule ) {
				continue;
			}
			$prev = isset( $before[ $basename ] ) ? (string) $before[ $basename ] : '';
			if ( $prev === $rule ) {
				continue;
			}
			// New or changed-to-Allow: start the unused clock; clear stale match.
			$since[ $basename ] = $now;
			unset( $matched[ $basename ] );
		}

		// Drop stamps for plugins no longer Allow (including Deny).
		foreach ( array_keys( $matched + $since ) as $basename ) {
			$rule = isset( $after[ $basename ] ) ? (string) $after[ $basename ] : '';
			if ( 'allow' !== $rule ) {
				unset( $matched[ $basename ], $since[ $basename ] );
			}
		}

		self::put_matched( self::normalize_allow_only( $incoming, $matched ) );
		self::put_allow_since( self::normalize_allow_only( $incoming, $since ) );
	}

	/**
	 * Decision-time stamp: last_matched for the matched Allow rule only.
	 *
	 * @param array<string,mixed> $event
	 * @param array<string,mixed> $policy
	 * @return array{stamped:bool,reason:string}
	 */
	public static function observe( array $event, array $policy ): array {
		$empty = array(
			'stamped' => false,
			'reason'  => '',
		);

		$channel = isset( $event['channel'] ) ? (string) $event['channel'] : '';
		if ( in_array(
			$channel,
			array(
				'direct_http',
				'anomaly',
				'spend_threshold',
				'drift',
				'alert_snooze',
				'budget',
				'went_ai',
				'temp_allow',
				'policy_restore',
				'selftest',
				'pii',
			),
			true
		) ) {
			$empty['reason'] = 'skip_channel';
			return $empty;
		}

		$decision = isset( $event['decision'] ) ? (string) $event['decision'] : '';
		if ( 'allow' !== $decision ) {
			$empty['reason'] = 'not_allow';
			return $empty;
		}

		$plugin = isset( $event['plugin'] ) ? Plugin_Profile::sanitize_plugin( (string) $event['plugin'] ) : '';
		if ( '' === $plugin || ( class_exists( Analytics::class ) && Analytics::UNKNOWN_KEY === $plugin ) ) {
			$empty['reason'] = 'no_plugin';
			return $empty;
		}

		$plugins = isset( $policy['plugins'] ) && is_array( $policy['plugins'] )
			? $policy['plugins']
			: array();
		$rule = isset( $plugins[ $plugin ] ) ? (string) $plugins[ $plugin ] : '';
		if ( 'allow' !== $rule ) {
			$empty['reason'] = 'no_allow_rule';
			return $empty;
		}

		$ts = isset( $event['ts'] ) ? (int) $event['ts'] : 0;
		if ( $ts <= 0 ) {
			$ts = time();
		}

		$matched = self::get_matched();
		$prior   = isset( $matched[ $plugin ] ) ? (int) $matched[ $plugin ] : 0;
		if ( $ts <= $prior ) {
			$empty['reason'] = 'stale_ts';
			return $empty;
		}

		$matched[ $plugin ] = $ts;
		self::put_matched( self::normalize_allow_only( $policy, $matched ) );

		// Ensure allow_since exists so absent-stamp aging has an anchor.
		$since = self::get_allow_since();
		if ( ! isset( $since[ $plugin ] ) ) {
			$since[ $plugin ] = $ts;
			self::put_allow_since( self::normalize_allow_only( $policy, $since ) );
		}

		return array(
			'stamped' => true,
			'reason'  => 'matched',
		);
	}

	/**
	 * Seed / refresh last_matched from retained Activity (Ralph scan path).
	 * Incremental observe stamps still win when newer.
	 *
	 * @param array<int,mixed>|null $log
	 * @param array<string,mixed>   $policy
	 * @param int|null              $now
	 * @return array{updated:int}
	 */
	public static function scan_activity( ?array $log = null, array $policy = array(), ?int $now = null ): array {
		unset( $now );
		if ( null === $log ) {
			$raw = get_option( Plugin::LOG_OPTION_KEY );
			$log = is_array( $raw ) ? $raw : array();
		}
		if ( empty( $policy ) ) {
			$policy = Policy::get_policy();
		}

		$plugins = isset( $policy['plugins'] ) && is_array( $policy['plugins'] )
			? $policy['plugins']
			: array();
		$matched = self::get_matched();
		$updated = 0;

		foreach ( $log as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			if ( 'allow' !== (string) ( $row['decision'] ?? '' ) ) {
				continue;
			}
			$plugin = Plugin_Profile::sanitize_plugin( (string) ( $row['plugin'] ?? '' ) );
			if ( '' === $plugin ) {
				continue;
			}
			$rule = isset( $plugins[ $plugin ] ) ? (string) $plugins[ $plugin ] : '';
			if ( 'allow' !== $rule ) {
				continue;
			}
			$ts = isset( $row['ts'] ) ? (int) $row['ts'] : 0;
			if ( $ts <= 0 ) {
				continue;
			}
			$prior = isset( $matched[ $plugin ] ) ? (int) $matched[ $plugin ] : 0;
			if ( $ts <= $prior ) {
				continue;
			}
			$matched[ $plugin ] = $ts;
			++$updated;
		}

		if ( $updated > 0 ) {
			self::put_matched( self::normalize_allow_only( $policy, $matched ) );
		}

		return array( 'updated' => $updated );
	}

	/**
	 * Throttled Activity seed + allow_since backfill.
	 */
	public static function lazy_scan(): void {
		if ( get_transient( self::SCAN_TRANSIENT_KEY ) ) {
			return;
		}
		set_transient( self::SCAN_TRANSIENT_KEY, 1, self::SCAN_INTERVAL );

		$policy = Policy::get_policy();
		self::scan_activity( null, $policy );
		self::ensure_allow_since( $policy );
	}

	/**
	 * Backfill allow_since for Allow rules missing a stamp (Review_Due proxy, else now).
	 *
	 * @param array<string,mixed> $policy
	 * @param int|null            $now
	 */
	public static function ensure_allow_since( array $policy, ?int $now = null ): void {
		$now     = null !== $now && $now > 0 ? $now : time();
		$plugins = isset( $policy['plugins'] ) && is_array( $policy['plugins'] )
			? $policy['plugins']
			: array();
		$since   = self::get_allow_since();
		$reviews = class_exists( Review_Due::class, false ) ? Review_Due::get_stamps() : array();
		$changed = false;

		foreach ( $plugins as $basename => $rule ) {
			$basename = Plugin_Profile::sanitize_plugin( (string) $basename );
			if ( '' === $basename || 'allow' !== (string) $rule ) {
				continue;
			}
			if ( isset( $since[ $basename ] ) ) {
				continue;
			}
			if ( isset( $reviews[ $basename ] ) && (int) $reviews[ $basename ] > 0 ) {
				$since[ $basename ] = (int) $reviews[ $basename ];
			} else {
				$since[ $basename ] = $now;
			}
			$changed = true;
		}

		if ( $changed ) {
			self::put_allow_since( self::normalize_allow_only( $policy, $since ) );
		}
	}

	/**
	 * Whether an Allow rule is flagged as unused in the window.
	 *
	 * @param array<string,mixed> $policy
	 * @param int|null            $now
	 */
	public static function is_flagged( string $basename, array $policy, ?int $now = null ): bool {
		$basename = Plugin_Profile::sanitize_plugin( $basename );
		if ( '' === $basename ) {
			return false;
		}
		$snap = self::snapshot( $policy, $now );
		foreach ( $snap['rows'] as $row ) {
			if ( (string) $row['basename'] === $basename ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Flagged Allow rows (Deny never appears).
	 *
	 * @param array<string,mixed> $policy
	 * @param int|null            $now
	 * @return array{total:int,flagged:int,days:int,rows:list<array{basename:string,last_matched:int,allow_since:int,age_days:int}>}
	 */
	public static function snapshot( array $policy, ?int $now = null ): array {
		$now  = null !== $now && $now > 0 ? $now : time();
		$days = self::window_days( $policy );
		$out  = array(
			'total'   => 0,
			'flagged' => 0,
			'days'    => $days,
			'rows'    => array(),
		);

		if ( $days <= 0 ) {
			return $out;
		}

		self::ensure_allow_since( $policy, $now );

		$plugins = isset( $policy['plugins'] ) && is_array( $policy['plugins'] )
			? $policy['plugins']
			: array();
		$matched = self::get_matched();
		$since   = self::get_allow_since();
		$window  = $days * DAY_IN_SECONDS;
		$total   = 0;

		foreach ( $plugins as $basename => $rule ) {
			$basename = Plugin_Profile::sanitize_plugin( (string) $basename );
			if ( '' === $basename || 'allow' !== (string) $rule ) {
				continue;
			}
			++$total;

			$last = isset( $matched[ $basename ] ) ? (int) $matched[ $basename ] : 0;
			$born = isset( $since[ $basename ] ) ? (int) $since[ $basename ] : 0;
			if ( $born <= 0 ) {
				$born = $now;
			}

			// Matched recently → live. Absent match → age from allow_since.
			$anchor = $last > 0 ? $last : $born;
			if ( ( $now - $anchor ) < $window ) {
				continue;
			}

			$age_days = (int) floor( ( $now - $anchor ) / DAY_IN_SECONDS );
			$out['rows'][] = array(
				'basename'     => $basename,
				'last_matched' => $last,
				'allow_since'  => $born,
				'age_days'     => $age_days,
			);
		}

		$out['total']   = $total;
		$out['flagged'] = count( $out['rows'] );

		return $out;
	}

	/**
	 * @param array<string,mixed> $policy
	 * @param int|null            $now
	 * @return list<string>
	 */
	public static function flagged_basenames( array $policy, ?int $now = null ): array {
		$out = array();
		foreach ( self::snapshot( $policy, $now )['rows'] as $row ) {
			$out[] = (string) $row['basename'];
		}

		return $out;
	}

	/**
	 * @param array{total?:int,flagged?:int,days?:int,rows?:list<array<string,mixed>>} $snapshot
	 */
	public static function inbox_count( array $snapshot ): int {
		return isset( $snapshot['flagged'] ) ? (int) $snapshot['flagged'] : 0;
	}

	/**
	 * Chip/status helper for a future Rules UI (no admin render this PR).
	 *
	 * @param array<string,mixed> $policy
	 * @param int|null            $now
	 * @return array{flagged:bool,label:string,last_matched:int,allow_since:int}
	 */
	public static function status_for( string $basename, array $policy, ?int $now = null ): array {
		$basename = Plugin_Profile::sanitize_plugin( $basename );
		$days     = self::window_days( $policy );
		$matched  = self::get_matched();
		$since    = self::get_allow_since();
		$last     = isset( $matched[ $basename ] ) ? (int) $matched[ $basename ] : 0;
		$born     = isset( $since[ $basename ] ) ? (int) $since[ $basename ] : 0;
		$flagged  = self::is_flagged( $basename, $policy, $now );
		$label    = '';
		if ( $flagged && $days > 0 ) {
			$label = sprintf(
				/* translators: %d: unused window in days */
				__( 'No matches in %dd', 'handl-ai-connector-access-control' ),
				$days
			);
		}

		return array(
			'flagged'      => $flagged,
			'label'        => $label,
			'last_matched' => $last,
			'allow_since'  => $born,
		);
	}

	/**
	 * Retire an Allow rule: snapshot-then-clear via Policy::set_plugin_rule.
	 * Never automatic — caller must invoke. Deny rules rejected.
	 *
	 * @return array{ok:bool,status:string,error?:string,basename?:string}
	 */
	public static function retire( string $basename ): array {
		$basename = Plugin_Profile::sanitize_plugin( $basename );
		if ( '' === $basename ) {
			return array(
				'ok'     => false,
				'status' => 'error',
				'error'  => 'empty',
			);
		}

		$policy  = Policy::get_policy();
		$plugins = isset( $policy['plugins'] ) && is_array( $policy['plugins'] )
			? $policy['plugins']
			: array();
		$rule = isset( $plugins[ $basename ] ) ? (string) $plugins[ $basename ] : '';
		if ( 'allow' !== $rule ) {
			return array(
				'ok'     => false,
				'status' => 'error',
				'error'  => 'not_allow',
			);
		}

		// save_policy → Policy_Snapshots::capture_before_save (restorable undo).
		$ok = Policy::set_plugin_rule( $basename, '' );
		if ( ! $ok ) {
			return array(
				'ok'     => false,
				'status' => 'error',
				'error'  => 'save_failed',
			);
		}

		$matched = self::get_matched();
		$since   = self::get_allow_since();
		unset( $matched[ $basename ], $since[ $basename ] );
		self::put_matched( $matched );
		self::put_allow_since( $since );

		Policy_Snapshots::append_history(
			array(
				'ts'      => time(),
				'actor'   => Policy_Snapshots::detect_actor(),
				'changes' => array(
					sprintf(
						/* translators: %s: plugin basename */
						__( 'Retired unused Allow (%s)', 'handl-ai-connector-access-control' ),
						$basename
					),
				),
				'summary' => sprintf( 'Retired unused Allow (%s)', $basename ),
			)
		);

		return array(
			'ok'       => true,
			'status'   => 'retired',
			'basename' => $basename,
		);
	}

	/**
	 * Undo latest retire via Policy_Snapshots restore (byte-identical rule return).
	 *
	 * @return array{ok:bool,status:string,error?:string,ts?:int}
	 */
	public static function undo_retire(): array {
		return Policy_Snapshots::restore_latest();
	}

	/**
	 * WP-CLI: list flagged dead Allow rules.
	 *
	 * ## OPTIONS
	 *
	 * [--format=<format>]
	 * : table or json.
	 * ---
	 * default: table
	 * options:
	 *   - table
	 *   - json
	 * ---
	 *
	 * ## EXAMPLES
	 *
	 *     wp handl-aicac dead-rules list
	 *     wp handl-aicac dead-rules list --format=json
	 *
	 * @param array<int,string>    $args
	 * @param array<string,string> $assoc_args
	 */
	public static function cmd_list( $args, $assoc_args ): void {
		unset( $args );
		$format = isset( $assoc_args['format'] ) ? (string) $assoc_args['format'] : 'table';
		if ( 'json' !== $format ) {
			$format = 'table';
		}

		$snap = self::snapshot( Policy::get_policy() );
		$rows = array();
		foreach ( $snap['rows'] as $row ) {
			$rows[] = array(
				'plugin'       => (string) $row['basename'],
				'last_matched' => (int) $row['last_matched'] > 0
					? (string) (int) $row['last_matched']
					: 'never',
				'allow_since'  => (string) (int) $row['allow_since'],
				'age_days'     => (string) (int) $row['age_days'],
			);
		}

		if ( 'json' === $format ) {
			\WP_CLI::print_value(
				array(
					'days'    => $snap['days'],
					'flagged' => $snap['flagged'],
					'total'   => $snap['total'],
					'rows'    => $rows,
				),
				array( 'format' => 'json' )
			);
			return;
		}

		if ( empty( $rows ) ) {
			\WP_CLI::log( sprintf( 'No Allow rules unused for %d days.', (int) $snap['days'] ) );
			return;
		}

		\WP_CLI\Utils\format_items( 'table', $rows, array( 'plugin', 'last_matched', 'allow_since', 'age_days' ) );
	}
}
