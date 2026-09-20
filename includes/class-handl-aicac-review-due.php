<?php
/**
 * AICAC-REVIEW-DUE (#203): last-confirmed stamp and review-due inbox.
 *
 * Staleness never mutates allow/deny. Confirm only writes a stamp + history.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Review_Due {

	public const OPTION_KEY = 'handl_aicac_plugin_last_reviewed';

	public const DEFAULT_DAYS = 90;

	/** Default postpone for review-due snooze (days). */
	public const SNOOZE_DAYS = 7;

	/** @var list<int> */
	public const DAY_OPTIONS = array( 30, 90, 180, 0 );

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
	public static function get_stamps(): array {
		return self::sanitize_stamps( get_option( self::OPTION_KEY, array() ) );
	}

	/**
	 * @param array<string,int> $stamps
	 */
	public static function put_stamps( array $stamps ): void {
		update_option( self::OPTION_KEY, self::sanitize_stamps( $stamps ), false );
	}

	/**
	 * Keep stamps only for explicit Allow/Deny rules.
	 *
	 * @param array<string,mixed> $policy
	 * @param array<string,int>   $stamps
	 * @return array<string,int>
	 */
	public static function normalize_stamps( array $policy, array $stamps ): array {
		$plugins = isset( $policy['plugins'] ) && is_array( $policy['plugins'] )
			? $policy['plugins']
			: array();
		$stamps = self::sanitize_stamps( $stamps );
		$kept   = array();
		foreach ( $stamps as $basename => $ts ) {
			$rule = isset( $plugins[ $basename ] ) ? (string) $plugins[ $basename ] : '';
			if ( 'allow' !== $rule && 'deny' !== $rule ) {
				continue;
			}
			$kept[ $basename ] = $ts;
		}

		return $kept;
	}

	/**
	 * Stamp last_reviewed on create/change of an explicit rule. Does not
	 * restamp unchanged rules. Never changes allow/deny.
	 *
	 * @param array<string,mixed> $incoming Policy just saved.
	 * @param array<string,mixed> $previous Previously stored option (may be empty).
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
		$stamps = self::get_stamps();

		foreach ( $after as $basename => $rule ) {
			$basename = Plugin_Profile::sanitize_plugin( (string) $basename );
			$rule     = (string) $rule;
			if ( '' === $basename || ( 'allow' !== $rule && 'deny' !== $rule ) ) {
				continue;
			}
			$prev = isset( $before[ $basename ] ) ? (string) $before[ $basename ] : '';
			if ( $prev === $rule ) {
				continue;
			}
			$stamps[ $basename ] = $now;
		}

		self::put_stamps( self::normalize_stamps( $incoming, $stamps ) );
	}

	/**
	 * Confirm selected rules still correct. Policy allow/deny unchanged.
	 *
	 * @param array<string,mixed> $policy
	 * @param list<string>        $basenames
	 * @param int|null            $now
	 * @return int Number confirmed.
	 */
	public static function confirm( array $policy, array $basenames, ?int $now = null ): int {
		$now     = null !== $now && $now > 0 ? $now : time();
		$stamps  = self::get_stamps();
		$plugins = isset( $policy['plugins'] ) && is_array( $policy['plugins'] )
			? $policy['plugins']
			: array();
		$changes = array();
		foreach ( $basenames as $basename ) {
			$basename = Plugin_Profile::sanitize_plugin( (string) $basename );
			if ( '' === $basename ) {
				continue;
			}
			$rule = isset( $plugins[ $basename ] ) ? (string) $plugins[ $basename ] : '';
			if ( 'allow' !== $rule && 'deny' !== $rule ) {
				continue;
			}
			$stamps[ $basename ] = $now;
			$changes[]           = sprintf(
				/* translators: %s: plugin basename */
				__( 'Still correct (%s)', 'handl-ai-connector-access-control' ),
				$basename
			);
		}
		self::put_stamps( self::normalize_stamps( $policy, $stamps ) );
		if ( ! empty( $changes ) ) {
			Policy_Snapshots::append_history(
				array(
					'ts'      => $now,
					'actor'   => Policy_Snapshots::detect_actor(),
					'changes' => $changes,
					'summary' => implode( '; ', $changes ),
				)
			);
		}

		return count( $changes );
	}

	/**
	 * Basenames that are stale (due) and still installed — not orphans.
	 *
	 * @param array<string,mixed>               $policy
	 * @param array<string,array<string,mixed>> $installed
	 * @return list<string>
	 */
	public static function due_basenames( array $policy, array $installed, ?int $now = null ): array {
		$snap = self::snapshot( $policy, $installed, $now );
		$out  = array();
		foreach ( $snap['rows'] as $row ) {
			if ( ! empty( $row['orphaned'] ) ) {
				continue;
			}
			$out[] = (string) $row['basename'];
		}

		return $out;
	}

	/**
	 * Postpone review without claiming the rule is still correct.
	 * Stamps last_reviewed so the row is due again after $days.
	 * Does not change Allow or Deny.
	 *
	 * @param array<string,mixed> $policy
	 * @param list<string>        $basenames
	 * @return int Number snoozed.
	 */
	public static function snooze( array $policy, array $basenames, int $days = self::SNOOZE_DAYS, ?int $now = null ): int {
		$now    = null !== $now && $now > 0 ? $now : time();
		$window = self::sanitize_days( $policy['review_due_days'] ?? self::DEFAULT_DAYS );
		$days   = $days > 0 ? $days : self::SNOOZE_DAYS;
		if ( $window <= 0 ) {
			return 0;
		}

		$stamp   = $now - ( $window * DAY_IN_SECONDS ) + ( $days * DAY_IN_SECONDS );
		if ( $stamp > $now ) {
			$stamp = $now;
		}

		$stamps  = self::get_stamps();
		$plugins = isset( $policy['plugins'] ) && is_array( $policy['plugins'] )
			? $policy['plugins']
			: array();
		$changes = array();
		foreach ( $basenames as $basename ) {
			$basename = Plugin_Profile::sanitize_plugin( (string) $basename );
			if ( '' === $basename ) {
				continue;
			}
			$rule = isset( $plugins[ $basename ] ) ? (string) $plugins[ $basename ] : '';
			if ( 'allow' !== $rule && 'deny' !== $rule ) {
				continue;
			}
			$stamps[ $basename ] = $stamp;
			$changes[]           = sprintf(
				/* translators: 1: plugin basename, 2: number of days */
				__( 'Remind later in %2$d days (%1$s)', 'handl-ai-connector-access-control' ),
				$basename,
				$days
			);
		}
		self::put_stamps( self::normalize_stamps( $policy, $stamps ) );
		if ( ! empty( $changes ) ) {
			Policy_Snapshots::append_history(
				array(
					'ts'      => $now,
					'actor'   => Policy_Snapshots::detect_actor(),
					'changes' => $changes,
					'summary' => implode( '; ', $changes ),
				)
			);
		}

		return count( $changes );
	}

	/**
	 * @param array<string,mixed>               $policy
	 * @param array<string,array<string,mixed>> $installed get_plugins()-shaped.
	 * @param int|null                          $now
	 * @return array{days:int,total:int,confirmed:int,due:int,orphaned:int,rows:list<array{basename:string,rule:string,last_reviewed:int,orphaned:bool,stale:bool}>}
	 */
	public static function snapshot( array $policy, array $installed, ?int $now = null ): array {
		$now  = null !== $now && $now > 0 ? $now : time();
		$days = self::sanitize_days( $policy['review_due_days'] ?? self::DEFAULT_DAYS );
		$plugins = isset( $policy['plugins'] ) && is_array( $policy['plugins'] )
			? $policy['plugins']
			: array();
		$stamps = self::get_stamps();

		$rows      = array();
		$confirmed = 0;
		$due       = 0;
		$orphaned  = 0;
		$total     = 0;
		$window    = $days > 0 ? $days * DAY_IN_SECONDS : 0;

		foreach ( $plugins as $basename => $rule ) {
			$basename = Plugin_Profile::sanitize_plugin( (string) $basename );
			$rule     = (string) $rule;
			if ( '' === $basename || ( 'allow' !== $rule && 'deny' !== $rule ) ) {
				continue;
			}
			++$total;
			$ts       = isset( $stamps[ $basename ] ) ? (int) $stamps[ $basename ] : 0;
			$is_orphan = ! isset( $installed[ $basename ] );
			$is_stale  = false;
			if ( $window > 0 ) {
				$is_stale = $ts <= 0 || ( $now - $ts ) >= $window;
			}
			if ( $is_orphan ) {
				++$orphaned;
			} elseif ( $is_stale ) {
				++$due;
			} elseif ( $ts > 0 ) {
				++$confirmed;
			}

			if ( $is_orphan || $is_stale ) {
				$rows[] = array(
					'basename'      => $basename,
					'rule'          => $rule,
					'last_reviewed' => $ts,
					'orphaned'      => $is_orphan,
					'stale'         => $is_stale,
				);
			}
		}

		return array(
			'days'      => $days,
			'total'     => $total,
			'confirmed' => $confirmed,
			'due'       => $due,
			'orphaned'  => $orphaned,
			'rows'      => $rows,
		);
	}

	/**
	 * @param array<string,mixed> $snapshot From snapshot().
	 */
	public static function evidence_line( array $snapshot ): string {
		$days = (int) ( $snapshot['days'] ?? self::DEFAULT_DAYS );
		if ( $days <= 0 ) {
			return __( 'Rule review window: off.', 'handl-ai-connector-access-control' );
		}
		$confirmed = (int) ( $snapshot['confirmed'] ?? 0 );
		$total     = (int) ( $snapshot['total'] ?? 0 );

		return sprintf(
			/* translators: 1: confirmed count, 2: total explicit rules, 3: window days */
			__( '%1$d of %2$d rules reviewed within %3$d days.', 'handl-ai-connector-access-control' ),
			$confirmed,
			$total,
			$days
		);
	}

	/**
	 * Inbox count for Dashboard (stale + orphaned).
	 *
	 * @param array<string,mixed> $snapshot
	 */
	public static function inbox_count( array $snapshot ): int {
		return (int) ( $snapshot['due'] ?? 0 ) + (int) ( $snapshot['orphaned'] ?? 0 );
	}
}
