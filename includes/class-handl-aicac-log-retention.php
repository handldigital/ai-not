<?php
/**
 * AICAC-RETENTION (#174): scheduled activity-log prune + export-before-first-prune.
 *
 * Builds on Policy::log_max_age_days (TTL #57). Default forever (null) keeps
 * prior behavior. When a finite period is first enabled (or tightened), cron
 * waits until the admin downloads a CSV of rows about to be removed — or skips.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Log_Retention {

	public const CRON_HOOK = 'handl_aicac_prune_activity_log';

	/** Meta option: last prune + export-before-prune gate. */
	public const META_OPTION = 'handl_aicac_log_retention_meta';

	/** Max expired rows removed per cron tick (batched). */
	public const BATCH_SIZE = 100;

	/**
	 * Discrete period choices (days). null = forever.
	 *
	 * @var list<int>
	 */
	public const PERIOD_DAYS = array( 30, 90, 180, 365 );

	private static ?Log_Retention $instance = null;

	public static function instance(): Log_Retention {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	public function init(): void {
		add_action( self::CRON_HOOK, array( $this, 'cron_prune' ) );
		add_action( 'init', array( $this, 'maybe_self_heal_schedule' ), 24 );
	}

	public function maybe_self_heal_schedule(): void {
		self::maybe_schedule( Policy::get_policy() );
	}

	public function cron_prune(): void {
		self::run_prune_batch( null, Clock::now() );
	}

	/**
	 * @param array<string,mixed> $policy
	 */
	public static function maybe_schedule( array $policy ): void {
		$want = null !== Policy::sanitize_log_max_age_days( $policy['log_max_age_days'] ?? null );

		if ( $want ) {
			if ( function_exists( 'wp_next_scheduled' ) && function_exists( 'wp_schedule_event' ) ) {
				if ( ! wp_next_scheduled( self::CRON_HOOK ) ) {
					$delay = defined( 'DAY_IN_SECONDS' ) ? (int) DAY_IN_SECONDS : 86400;
					wp_schedule_event( Clock::now() + $delay, 'daily', self::CRON_HOOK );
				}
			}
			return;
		}

		if ( function_exists( 'wp_next_scheduled' ) && function_exists( 'wp_unschedule_event' ) ) {
			$ts = wp_next_scheduled( self::CRON_HOOK );
			if ( $ts ) {
				wp_unschedule_event( $ts, self::CRON_HOOK );
			}
		}
	}

	/**
	 * @return array{last_prune_ts:int,export_pending:bool,export_period_days:?int}
	 */
	public static function meta(): array {
		$raw = get_option( self::META_OPTION );
		if ( ! is_array( $raw ) ) {
			$raw = array();
		}
		$days = isset( $raw['export_period_days'] ) ? Policy::sanitize_log_max_age_days( $raw['export_period_days'] ) : null;

		return array(
			'last_prune_ts'       => isset( $raw['last_prune_ts'] ) ? max( 0, (int) $raw['last_prune_ts'] ) : 0,
			'export_pending'      => ! empty( $raw['export_pending'] ),
			'export_period_days'  => $days,
		);
	}

	/**
	 * @param array{last_prune_ts?:int,export_pending?:bool,export_period_days?:?int} $meta
	 */
	public static function save_meta( array $meta ): void {
		$current = self::meta();
		$out     = array(
			'last_prune_ts'      => isset( $meta['last_prune_ts'] ) ? max( 0, (int) $meta['last_prune_ts'] ) : $current['last_prune_ts'],
			'export_pending'     => array_key_exists( 'export_pending', $meta ) ? ! empty( $meta['export_pending'] ) : $current['export_pending'],
			'export_period_days' => array_key_exists( 'export_period_days', $meta )
				? Policy::sanitize_log_max_age_days( $meta['export_period_days'] )
				: $current['export_period_days'],
		);
		update_option( self::META_OPTION, $out, false );
	}

	public static function is_export_pending(): bool {
		return ! empty( self::meta()['export_pending'] );
	}

	/**
	 * After Activity settings save: schedule cron; gate first prune behind CSV export
	 * when the new period would remove rows.
	 *
	 * @param array<string,mixed> $previous
	 * @param array<string,mixed> $saved
	 */
	public static function after_settings_saved( array $previous, array $saved, ?int $now = null ): void {
		$now = null !== $now ? $now : Clock::now();
		self::maybe_schedule( $saved );

		$prev_days = Policy::sanitize_log_max_age_days( $previous['log_max_age_days'] ?? null );
		$new_days  = Policy::sanitize_log_max_age_days( $saved['log_max_age_days'] ?? null );

		if ( null === $new_days ) {
			self::save_meta(
				array(
					'export_pending'     => false,
					'export_period_days' => null,
				)
			);
			return;
		}

		$became_stricter = ( null === $prev_days ) || ( $new_days < $prev_days );
		if ( ! $became_stricter ) {
			return;
		}

		$log   = get_option( Plugin::LOG_OPTION_KEY );
		$log   = is_array( $log ) ? $log : array();
		$doomed = self::rows_past_retention( $log, $new_days, $now );
		if ( empty( $doomed ) ) {
			self::save_meta(
				array(
					'export_pending'     => false,
					'export_period_days' => $new_days,
				)
			);
			return;
		}

		self::save_meta(
			array(
				'export_pending'     => true,
				'export_period_days' => $new_days,
			)
		);
	}

	/**
	 * Rows older than the retention window (boundary: ts == cutoff is kept).
	 *
	 * @param array<int,mixed> $log
	 * @return list<array<string,mixed>>
	 */
	public static function rows_past_retention( array $log, int $max_age_days, ?int $now = null ): array {
		$now = null !== $now ? $now : Clock::now();
		if ( $now <= 0 ) {
			$now = Clock::now();
		}
		$max_age_days = (int) $max_age_days;
		if ( $max_age_days < 1 ) {
			return array();
		}

		$cutoff = $now - ( $max_age_days * Policy::day_in_seconds() );
		$out    = array();
		foreach ( $log as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$ts = isset( $row['ts'] ) ? (int) $row['ts'] : 0;
			if ( $ts > 0 && $ts < $cutoff ) {
				$out[] = $row;
			}
		}

		return $out;
	}

	/**
	 * Run one batched prune when export gate is clear.
	 *
	 * @return array{ok:bool,status:string,removed:int,remaining:int}
	 */
	public static function run_prune_batch( ?array $policy = null, ?int $now = null ): array {
		$now    = null !== $now ? $now : Clock::now();
		$policy = null !== $policy ? $policy : Policy::get_policy();
		$days   = Policy::sanitize_log_max_age_days( $policy['log_max_age_days'] ?? null );

		if ( null === $days ) {
			self::maybe_schedule( $policy );
			return array(
				'ok'        => true,
				'status'    => 'disabled',
				'removed'   => 0,
				'remaining' => 0,
			);
		}

		if ( self::is_export_pending() ) {
			return array(
				'ok'        => true,
				'status'    => 'waiting_export',
				'removed'   => 0,
				'remaining' => count( self::rows_past_retention( self::raw_log(), $days, $now ) ),
			);
		}

		$log     = self::raw_log();
		$doomed  = self::rows_past_retention( $log, $days, $now );
		$remove_n = min( self::BATCH_SIZE, count( $doomed ) );
		if ( $remove_n < 1 ) {
			self::save_meta( array( 'last_prune_ts' => $now ) );
			self::maybe_schedule( $policy );
			return array(
				'ok'        => true,
				'status'    => 'noop',
				'removed'   => 0,
				'remaining' => 0,
			);
		}

		// Remove the oldest expired rows first (stable by ts).
		usort(
			$doomed,
			static function ( $a, $b ): int {
				$ta = isset( $a['ts'] ) ? (int) $a['ts'] : 0;
				$tb = isset( $b['ts'] ) ? (int) $b['ts'] : 0;
				return $ta <=> $tb;
			}
		);
		$drop = array_slice( $doomed, 0, $remove_n );
		$drop_keys = array();
		foreach ( $drop as $row ) {
			$drop_keys[ self::row_identity( $row ) ] = true;
		}

		$kept = array();
		$removed = 0;
		foreach ( $log as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$id = self::row_identity( $row );
			if ( isset( $drop_keys[ $id ] ) && $removed < $remove_n ) {
				++$removed;
				unset( $drop_keys[ $id ] );
				continue;
			}
			$kept[] = $row;
		}

		// Also apply entry-count cap after time prune.
		$kept = Policy::apply_log_retention( $kept, $policy, $now );
		update_option( Plugin::LOG_OPTION_KEY, $kept, false );
		self::save_meta( array( 'last_prune_ts' => $now ) );
		self::maybe_schedule( $policy );

		$remaining = count( self::rows_past_retention( $kept, $days, $now ) );

		return array(
			'ok'        => true,
			'status'    => 'pruned',
			'removed'   => $removed,
			'remaining' => $remaining,
		);
	}

	/**
	 * Mark export complete so cron may prune.
	 */
	public static function mark_export_completed(): void {
		self::save_meta(
			array(
				'export_pending' => false,
			)
		);
	}

	/**
	 * Skip CSV and allow prune (still gated behind an explicit admin action).
	 */
	public static function skip_export(): void {
		self::mark_export_completed();
	}

	/**
	 * Whether TTL pruning should be deferred (export gate open).
	 */
	public static function should_defer_ttl_prune(): bool {
		return self::is_export_pending();
	}

	/**
	 * Human label for Site Health / settings.
	 */
	public static function period_label( ?int $days ): string {
		if ( null === $days ) {
			return __( 'Keep forever', 'handl-ai-connector-access-control' );
		}
		return sprintf(
			/* translators: %d: number of days */
			_n( '%d day', '%d days', $days, 'handl-ai-connector-access-control' ),
			$days
		);
	}

	/**
	 * Select options for Activity settings (includes current custom value if any).
	 *
	 * @return array<string,string> value => label (value '' = forever)
	 */
	public static function period_choices( ?int $current ): array {
		$choices = array(
			'' => __( 'Keep forever (default)', 'handl-ai-connector-access-control' ),
		);
		foreach ( self::PERIOD_DAYS as $days ) {
			$choices[ (string) $days ] = self::period_label( $days );
		}
		if ( null !== $current && ! isset( $choices[ (string) $current ] ) ) {
			$choices[ (string) $current ] = sprintf(
				/* translators: %d: custom retention days already saved */
				__( '%d days (current)', 'handl-ai-connector-access-control' ),
				$current
			);
		}
		return $choices;
	}

	/**
	 * @return array<int,mixed>
	 */
	private static function raw_log(): array {
		$log = get_option( Plugin::LOG_OPTION_KEY );
		return is_array( $log ) ? $log : array();
	}

	/**
	 * @param array<string,mixed> $row
	 */
	private static function row_identity( array $row ): string {
		$ts = isset( $row['ts'] ) ? (int) $row['ts'] : 0;
		$plugin = isset( $row['plugin'] ) ? (string) $row['plugin'] : '';
		$decision = isset( $row['decision'] ) ? (string) $row['decision'] : '';
		$op = isset( $row['operation'] ) ? (string) $row['operation'] : '';
		return $ts . '|' . $plugin . '|' . $decision . '|' . $op . '|' . md5( (string) wp_json_encode( $row ) );
	}
}
