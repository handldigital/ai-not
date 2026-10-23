<?php
/**
 * AICAC-RECONCILE (#413): provider invoice reconciliation (report-only).
 *
 * The site owner types in what a provider actually billed for a calendar month
 * (manual invoice ledger). This control compares each row with the estimated
 * spend the plugin derived from its own activity log for the same provider and
 * month and flags variances over a configurable percentage (default 10%).
 *
 * - Estimate far BELOW the bill → unmetered usage / possible out-of-gate calls.
 * - Estimate far ABOVE the bill → stale rate table.
 *
 * Reads the activity log and policy; never writes them. Exactly one re-arming
 * [RECONCILE] alert. Print + CSV + WP-CLI. OFF by default. Own two options
 * only. Report only — never changes cost estimates, rates, budgets, or policy.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Invoice-vs-estimate reconciler.
 */
final class Reconcile {

	public const SETTINGS_OPTION = 'handl_aicac_reconcile';

	public const STATE_OPTION = 'handl_aicac_reconcile_state';

	public const PAGE_SLUG = 'handl-aicac-reconcile';

	public const ALERT_KIND = 'reconcile';

	public const FRAMING = 'report_only_never_mutates_cost';

	public const FILTER_THRESHOLD_PCT = 'handl_aicac_reconcile_threshold_pct';

	public const POST_PRESENT = 'handl_aicac_reconcile_present';

	public const POST_ENABLED = 'handl_aicac_reconcile_enabled';

	public const POST_THRESHOLD_PCT = 'handl_aicac_reconcile_threshold_pct';

	public const POST_REMOVE = 'handl_aicac_reconcile_remove';

	public const POST_NEW_PROVIDER = 'handl_aicac_reconcile_new_provider';

	public const POST_NEW_MONTH = 'handl_aicac_reconcile_new_month';

	public const POST_NEW_AMOUNT = 'handl_aicac_reconcile_new_amount';

	public const POST_NEW_NOTE = 'handl_aicac_reconcile_new_note';

	public const ACTION_SAVE = 'handl_aicac_reconcile_save';

	public const DEFAULT_THRESHOLD_PCT = 10.0;

	public const MIN_THRESHOLD_PCT = 0.1;

	public const MAX_THRESHOLD_PCT = 1000.0;

	public const INVOICE_CAP = 100;

	public const NOTE_MAX_LENGTH = 200;

	public const HISTORY_CAP = 40;

	public const DIRECTION_BELOW = 'below_bill';

	public const DIRECTION_ABOVE = 'above_bill';

	public const DIRECTION_WITHIN = 'within';

	/** @var bool */
	private static $registered = false;

	/** @var list<array<string,mixed>> */
	private static $test_mails = array();

	/** @var list<array<string,mixed>>|null */
	private static $test_log = null;

	/** @var array<string,mixed>|null */
	private static $test_policy = null;

	public static function init(): void {
		if ( self::$registered ) {
			return;
		}
		self::$registered = true;

		add_action( 'admin_menu', array( self::class, 'register_menu' ), 20 );
		add_action( 'admin_init', array( self::class, 'maybe_handle_csv' ), 5 );
		add_action( 'admin_init', array( self::class, 'maybe_handle_print' ), 5 );
		add_action( 'admin_post_' . self::ACTION_SAVE, array( self::class, 'handle_save' ) );

		if ( self::is_enabled() ) {
			add_action( 'init', array( self::class, 'maybe_fire_alerts' ), 30 );
		}

		self::register_cli();
	}

	public static function reset_for_tests(): void {
		self::$registered  = false;
		self::$test_mails  = array();
		self::$test_log    = null;
		self::$test_policy = null;
		delete_option( self::SETTINGS_OPTION );
		delete_option( self::STATE_OPTION );
	}

	/**
	 * @return list<array<string,mixed>>
	 */
	public static function test_mails(): array {
		return self::$test_mails;
	}

	/**
	 * Inject activity-log rows for unit tests (bypasses the log option).
	 *
	 * @param list<array<string,mixed>>|null $rows Rows or null to clear.
	 */
	public static function set_test_log( ?array $rows ): void {
		self::$test_log = $rows;
	}

	/**
	 * Inject a policy for unit tests (bypasses Policy::get_policy).
	 *
	 * @param array<string,mixed>|null $policy Policy or null to clear.
	 */
	public static function set_test_policy( ?array $policy ): void {
		self::$test_policy = $policy;
	}

	/* ---------------------------------------------------------------------
	 * Settings
	 * ------------------------------------------------------------------ */

	/**
	 * @return array{enabled:bool,threshold_pct:float,invoices:list<array<string,mixed>>}
	 */
	public static function defaults(): array {
		return array(
			'enabled'       => false,
			'threshold_pct' => self::DEFAULT_THRESHOLD_PCT,
			'invoices'      => array(),
		);
	}

	/**
	 * @return array{enabled:bool,threshold_pct:float,invoices:list<array<string,mixed>>}
	 */
	public static function get_settings(): array {
		return self::sanitize_settings( get_option( self::SETTINGS_OPTION, array() ) );
	}

	/**
	 * @param mixed $raw Raw settings.
	 * @return array{enabled:bool,threshold_pct:float,invoices:list<array<string,mixed>>}
	 */
	public static function sanitize_settings( $raw ): array {
		$defaults = self::defaults();
		if ( ! is_array( $raw ) ) {
			return $defaults;
		}

		return array(
			'enabled'       => ! empty( $raw['enabled'] ),
			'threshold_pct' => self::sanitize_threshold_pct( $raw['threshold_pct'] ?? $defaults['threshold_pct'] ),
			'invoices'      => self::sanitize_invoices( $raw['invoices'] ?? array() ),
		);
	}

	/**
	 * @param mixed $raw Raw percent.
	 */
	public static function sanitize_threshold_pct( $raw ): float {
		if ( ! is_numeric( $raw ) ) {
			return self::DEFAULT_THRESHOLD_PCT;
		}
		$v = (float) $raw;
		if ( ! is_finite( $v ) ) {
			return self::DEFAULT_THRESHOLD_PCT;
		}
		if ( $v < self::MIN_THRESHOLD_PCT ) {
			$v = self::MIN_THRESHOLD_PCT;
		}
		if ( $v > self::MAX_THRESHOLD_PCT ) {
			$v = self::MAX_THRESHOLD_PCT;
		}

		return round( $v, 2 );
	}

	/**
	 * Effective threshold percent after filter.
	 */
	public static function threshold_pct(): float {
		$settings = self::get_settings();
		$base     = (float) $settings['threshold_pct'];
		if ( function_exists( 'apply_filters' ) ) {
			return self::sanitize_threshold_pct( apply_filters( self::FILTER_THRESHOLD_PCT, $base ) );
		}

		return $base;
	}

	/**
	 * @param array<string,mixed> $settings Settings.
	 */
	public static function save_settings( array $settings ): bool {
		$clean  = self::sanitize_settings( $settings );
		$before = self::get_settings();
		if ( $clean === $before ) {
			return false;
		}
		if ( $clean === self::defaults() ) {
			delete_option( self::SETTINGS_OPTION );

			return true;
		}
		update_option( self::SETTINGS_OPTION, $clean, false );

		return true;
	}

	public static function is_enabled(): bool {
		$settings = self::get_settings();

		return ! empty( $settings['enabled'] );
	}

	/* ---------------------------------------------------------------------
	 * Manual invoice ledger (lives inside the settings option)
	 * ------------------------------------------------------------------ */

	/**
	 * Normalize a provider id (Cost helper when available).
	 */
	public static function sanitize_provider( string $provider ): string {
		if ( class_exists( Cost::class, false ) && method_exists( Cost::class, 'normalize_provider_id' ) ) {
			return (string) Cost::normalize_provider_id( $provider );
		}

		return preg_replace( '/[^a-z0-9_-]/', '', strtolower( trim( $provider ) ) ) ?? '';
	}

	/**
	 * Valid `Y-m` month or empty string.
	 *
	 * @param mixed $raw Raw month.
	 */
	public static function sanitize_month( $raw ): string {
		$month = is_scalar( $raw ) ? trim( (string) $raw ) : '';
		if ( 1 !== preg_match( '/^\d{4}-\d{2}$/', $month ) ) {
			return '';
		}
		$mm = (int) substr( $month, 5, 2 );
		if ( $mm < 1 || $mm > 12 ) {
			return '';
		}

		return $month;
	}

	/**
	 * Non-negative float amount or null when invalid.
	 *
	 * @param mixed $raw Raw amount.
	 */
	public static function sanitize_amount( $raw ): ?float {
		if ( is_string( $raw ) ) {
			$raw = str_replace( array( '$', ',', ' ' ), '', $raw );
		}
		if ( ! is_numeric( $raw ) ) {
			return null;
		}
		$v = (float) $raw;
		if ( ! is_finite( $v ) || $v < 0.0 ) {
			return null;
		}
		if ( $v > 1000000000.0 ) {
			$v = 1000000000.0;
		}

		return round( $v, 4 );
	}

	/**
	 * @param mixed $raw Raw note.
	 */
	public static function sanitize_note( $raw ): string {
		if ( ! is_scalar( $raw ) ) {
			return '';
		}
		$note = function_exists( 'sanitize_text_field' )
			? (string) sanitize_text_field( (string) $raw )
			: trim( strip_tags( (string) $raw ) );
		if ( strlen( $note ) > self::NOTE_MAX_LENGTH ) {
			$note = substr( $note, 0, self::NOTE_MAX_LENGTH );
		}

		return $note;
	}

	public static function sanitize_invoice_id( string $id ): string {
		return substr( strtolower( preg_replace( '/[^a-z0-9_-]/i', '', $id ) ?? '' ), 0, 40 );
	}

	/**
	 * Deterministic id from the row contents.
	 */
	public static function invoice_id( string $provider, string $month, float $amount, string $note = '' ): string {
		return substr( md5( $provider . '|' . $month . '|' . number_format( $amount, 4, '.', '' ) . '|' . $note ), 0, 12 );
	}

	/**
	 * @param mixed $row Raw invoice row.
	 * @return array{id:string,provider:string,month:string,amount:float,note:string}|null
	 */
	public static function sanitize_invoice( $row ): ?array {
		if ( ! is_array( $row ) ) {
			return null;
		}
		$provider = self::sanitize_provider( (string) ( $row['provider'] ?? '' ) );
		$month    = self::sanitize_month( $row['month'] ?? '' );
		$amount   = self::sanitize_amount( $row['amount'] ?? null );
		if ( '' === $provider || '' === $month || null === $amount ) {
			return null;
		}
		$note = self::sanitize_note( $row['note'] ?? '' );
		$id   = self::sanitize_invoice_id( (string) ( $row['id'] ?? '' ) );
		if ( '' === $id ) {
			$id = self::invoice_id( $provider, $month, $amount, $note );
		}

		return array(
			'id'       => $id,
			'provider' => $provider,
			'month'    => $month,
			'amount'   => $amount,
			'note'     => $note,
		);
	}

	/**
	 * Sanitize the ledger: drop invalid rows, dedupe by id, keep newest cap.
	 *
	 * @param mixed $raw Raw list.
	 * @return list<array{id:string,provider:string,month:string,amount:float,note:string}>
	 */
	public static function sanitize_invoices( $raw ): array {
		if ( ! is_array( $raw ) ) {
			return array();
		}
		$out  = array();
		$seen = array();
		foreach ( $raw as $row ) {
			$clean = self::sanitize_invoice( $row );
			if ( null === $clean || isset( $seen[ $clean['id'] ] ) ) {
				continue;
			}
			$seen[ $clean['id'] ] = true;
			$out[]                = $clean;
		}
		if ( count( $out ) > self::INVOICE_CAP ) {
			$out = array_slice( $out, -self::INVOICE_CAP );
		}

		return $out;
	}

	/**
	 * @return list<array{id:string,provider:string,month:string,amount:float,note:string}>
	 */
	public static function get_invoices(): array {
		$settings = self::get_settings();

		return $settings['invoices'];
	}

	/**
	 * Build the next settings array from a POST-shaped array (already unslashed).
	 *
	 * @param array<string,mixed> $post    Form values.
	 * @param array<string,mixed> $current Current settings.
	 * @return array{enabled:bool,threshold_pct:float,invoices:list<array<string,mixed>>}
	 */
	public static function settings_from_form( array $post, array $current ): array {
		$current  = self::sanitize_settings( $current );
		$invoices = $current['invoices'];

		$remove = array();
		if ( isset( $post[ self::POST_REMOVE ] ) && is_array( $post[ self::POST_REMOVE ] ) ) {
			foreach ( $post[ self::POST_REMOVE ] as $id ) {
				if ( is_scalar( $id ) ) {
					$remove[ self::sanitize_invoice_id( (string) $id ) ] = true;
				}
			}
		}
		if ( ! empty( $remove ) ) {
			$invoices = array_values(
				array_filter(
					$invoices,
					static function ( array $row ) use ( $remove ): bool {
						return ! isset( $remove[ (string) $row['id'] ] );
					}
				)
			);
		}

		$new = self::sanitize_invoice(
			array(
				'provider' => isset( $post[ self::POST_NEW_PROVIDER ] ) && is_scalar( $post[ self::POST_NEW_PROVIDER ] ) ? (string) $post[ self::POST_NEW_PROVIDER ] : '',
				'month'    => $post[ self::POST_NEW_MONTH ] ?? '',
				'amount'   => $post[ self::POST_NEW_AMOUNT ] ?? null,
				'note'     => $post[ self::POST_NEW_NOTE ] ?? '',
			)
		);
		if ( null !== $new ) {
			$invoices[] = $new;
		}

		$threshold_raw = isset( $post[ self::POST_THRESHOLD_PCT ] ) && is_scalar( $post[ self::POST_THRESHOLD_PCT ] )
			? (string) $post[ self::POST_THRESHOLD_PCT ]
			: '';

		return array(
			'enabled'       => ! empty( $post[ self::POST_ENABLED ] ),
			'threshold_pct' => self::sanitize_threshold_pct( '' !== $threshold_raw ? $threshold_raw : self::DEFAULT_THRESHOLD_PCT ),
			'invoices'      => self::sanitize_invoices( $invoices ),
		);
	}

	/* ---------------------------------------------------------------------
	 * State
	 * ------------------------------------------------------------------ */

	/**
	 * @return array{alerted:bool,history:list<array<string,mixed>>}
	 */
	public static function defaults_state(): array {
		return array(
			'alerted' => false,
			'history' => array(),
		);
	}

	/**
	 * @return array{alerted:bool,history:list<array<string,mixed>>}
	 */
	public static function get_state(): array {
		return self::sanitize_state( get_option( self::STATE_OPTION, array() ) );
	}

	/**
	 * @param mixed $raw Raw state.
	 * @return array{alerted:bool,history:list<array<string,mixed>>}
	 */
	public static function sanitize_state( $raw ): array {
		$defaults = self::defaults_state();
		if ( ! is_array( $raw ) ) {
			return $defaults;
		}
		$history = array();
		if ( isset( $raw['history'] ) && is_array( $raw['history'] ) ) {
			foreach ( $raw['history'] as $row ) {
				$clean = self::sanitize_history_entry( $row );
				if ( null !== $clean ) {
					$history[] = $clean;
				}
			}
		}
		if ( count( $history ) > self::HISTORY_CAP ) {
			$history = array_slice( $history, -self::HISTORY_CAP );
		}

		return array(
			'alerted' => ! empty( $raw['alerted'] ),
			'history' => $history,
		);
	}

	/**
	 * @param mixed $row Raw history row.
	 * @return array{ts:int,over_count:int,worst_id:string,worst_provider:string,worst_month:string,worst_delta_usd:float}|null
	 */
	public static function sanitize_history_entry( $row ): ?array {
		if ( ! is_array( $row ) ) {
			return null;
		}
		$ts = isset( $row['ts'] ) ? (int) $row['ts'] : 0;
		if ( $ts <= 0 ) {
			return null;
		}

		return array(
			'ts'              => $ts,
			'over_count'      => max( 0, (int) ( $row['over_count'] ?? 0 ) ),
			'worst_id'        => self::sanitize_invoice_id( (string) ( $row['worst_id'] ?? '' ) ),
			'worst_provider'  => self::sanitize_provider( (string) ( $row['worst_provider'] ?? '' ) ),
			'worst_month'     => self::sanitize_month( $row['worst_month'] ?? '' ),
			'worst_delta_usd' => is_numeric( $row['worst_delta_usd'] ?? null ) ? round( (float) $row['worst_delta_usd'], 4 ) : 0.0,
		);
	}

	/**
	 * @param array<string,mixed> $state State.
	 */
	public static function put_state( array $state ): void {
		$clean = self::sanitize_state( $state );
		if ( $clean === self::defaults_state() ) {
			delete_option( self::STATE_OPTION );

			return;
		}
		update_option( self::STATE_OPTION, $clean, false );
	}

	public static function is_alerted(): bool {
		$state = self::get_state();

		return ! empty( $state['alerted'] );
	}

	public static function set_alerted( bool $alerted ): void {
		$state            = self::get_state();
		$state['alerted'] = $alerted;
		self::put_state( $state );
	}

	/* ---------------------------------------------------------------------
	 * Estimated spend (read-only from the activity log)
	 * ------------------------------------------------------------------ */

	public static function log_option_key(): string {
		if ( class_exists( Plugin::class, false ) && defined( Plugin::class . '::LOG_OPTION_KEY' ) ) {
			return (string) Plugin::LOG_OPTION_KEY;
		}

		return 'handl_aicac_recent_calls';
	}

	/**
	 * Read-only activity log rows. Never writes.
	 *
	 * @return list<array<string,mixed>>
	 */
	public static function load_log(): array {
		if ( null !== self::$test_log ) {
			return self::$test_log;
		}
		$raw = get_option( self::log_option_key(), array() );
		if ( ! is_array( $raw ) ) {
			return array();
		}
		$out = array();
		foreach ( $raw as $row ) {
			if ( is_array( $row ) ) {
				$out[] = $row;
			}
		}

		return $out;
	}

	/**
	 * Read-only policy (rates). Never writes.
	 *
	 * @return array<string,mixed>
	 */
	public static function load_policy(): array {
		if ( null !== self::$test_policy ) {
			return self::$test_policy;
		}
		if ( class_exists( Policy::class, false ) && method_exists( Policy::class, 'get_policy' ) ) {
			$policy = Policy::get_policy();

			return is_array( $policy ) ? $policy : array();
		}

		return array();
	}

	/**
	 * Calendar-month [start, end) unix bounds in the site timezone (UTC fallback).
	 *
	 * @return array{start:int,end:int}|null
	 */
	public static function month_bounds( string $month ): ?array {
		$month = self::sanitize_month( $month );
		if ( '' === $month ) {
			return null;
		}
		$tz = null;
		if ( function_exists( 'wp_timezone' ) ) {
			$maybe = wp_timezone();
			if ( $maybe instanceof \DateTimeZone ) {
				$tz = $maybe;
			}
		}
		if ( null === $tz ) {
			$tz = new \DateTimeZone( 'UTC' );
		}
		$start = \DateTimeImmutable::createFromFormat( '!Y-m-d', $month . '-01', $tz );
		if ( false === $start ) {
			return null;
		}
		$end = $start->modify( '+1 month' );

		return array(
			'start' => $start->getTimestamp(),
			'end'   => $end->getTimestamp(),
		);
	}

	/**
	 * Is this log row call/spend activity (guarded Usage_Trends rule)?
	 *
	 * @param array<string,mixed> $row Log row.
	 */
	public static function is_activity_row( array $row ): bool {
		if ( class_exists( Usage_Trends::class, false ) && method_exists( Usage_Trends::class, 'is_activity_row' ) ) {
			return (bool) Usage_Trends::is_activity_row( $row );
		}

		return true;
	}

	/**
	 * Estimated USD for a single row (guarded; never writes).
	 *
	 * @param array<string,mixed> $row    Log row.
	 * @param array<string,mixed> $policy Policy.
	 */
	public static function row_spend_usd( array $row, array $policy ): ?float {
		if ( class_exists( Budget::class, false ) && method_exists( Budget::class, 'estimate_row_usd' ) ) {
			$usd = Budget::estimate_row_usd( $row, $policy );
			if ( null !== $usd ) {
				return (float) $usd;
			}
		}

		if ( class_exists( Cost::class, false ) && method_exists( Cost::class, 'rates_from_policy' ) && method_exists( Cost::class, 'estimate_usd' ) ) {
			$in    = array_key_exists( 'input_tokens', $row ) ? (int) $row['input_tokens'] : null;
			$out   = array_key_exists( 'output_tokens', $row ) ? (int) $row['output_tokens'] : null;
			$rates = Cost::rates_from_policy( $policy, isset( $row['provider'] ) ? (string) $row['provider'] : null );
			$usd   = Cost::estimate_usd( $in, $out, $rates );
			if ( null !== $usd ) {
				return (float) $usd;
			}
		}

		if ( class_exists( Cost_Receipt::class, false ) && method_exists( Cost_Receipt::class, 'row_spend_usd' ) ) {
			$method = new \ReflectionMethod( Cost_Receipt::class, 'row_spend_usd' );
			if ( $method->isPublic() && $method->isStatic() ) {
				$usd = Cost_Receipt::row_spend_usd( $row, $policy );
				if ( null !== $usd ) {
					return (float) $usd;
				}
			}
		}

		return null;
	}

	/**
	 * Estimated USD for provider + calendar month from the activity log.
	 *
	 * @param list<array<string,mixed>>|null $log    Optional log rows.
	 * @param array<string,mixed>|null       $policy Optional policy.
	 */
	public static function estimated_spend( string $provider, string $month, ?array $log = null, ?array $policy = null ): float {
		$provider = self::sanitize_provider( $provider );
		$bounds   = self::month_bounds( $month );
		if ( '' === $provider || null === $bounds ) {
			return 0.0;
		}
		$log    = null !== $log ? $log : self::load_log();
		$policy = null !== $policy ? $policy : self::load_policy();
		$total  = 0.0;

		foreach ( $log as $row ) {
			if ( ! is_array( $row ) || ! self::is_activity_row( $row ) ) {
				continue;
			}
			$ts = isset( $row['ts'] ) ? (int) $row['ts'] : 0;
			if ( $ts < $bounds['start'] || $ts >= $bounds['end'] ) {
				continue;
			}
			if ( self::sanitize_provider( (string) ( $row['provider'] ?? '' ) ) !== $provider ) {
				continue;
			}
			$usd = self::row_spend_usd( $row, $policy );
			if ( null !== $usd ) {
				$total += $usd;
			}
		}

		return round( $total, 4 );
	}

	/* ---------------------------------------------------------------------
	 * Variance roster
	 * ------------------------------------------------------------------ */

	/**
	 * Compare one invoice with its estimate.
	 *
	 * @param array<string,mixed> $invoice       Sanitized invoice row.
	 * @param float               $estimated     Estimated USD for provider+month.
	 * @param float               $threshold_pct Threshold percent.
	 * @return array<string,mixed>
	 */
	public static function compute_variance( array $invoice, float $estimated, float $threshold_pct ): array {
		$invoiced  = round( (float) ( $invoice['amount'] ?? 0.0 ), 4 );
		$estimated = round( $estimated, 4 );
		$delta_abs = round( $estimated - $invoiced, 4 );
		$delta_pct = null;
		$over      = false;

		if ( $invoiced > 0.0 ) {
			$pct       = ( $delta_abs / $invoiced ) * 100.0;
			$delta_pct = round( $pct, 2 );
			$over      = abs( round( $pct, 4 ) ) >= $threshold_pct;
		} else {
			// Nothing billed: any estimated usage is over; both zero is fine.
			$over = $estimated > 0.0;
		}

		$direction = self::DIRECTION_WITHIN;
		if ( $over ) {
			$direction = $estimated < $invoiced ? self::DIRECTION_BELOW : self::DIRECTION_ABOVE;
		}

		return array(
			'id'             => (string) ( $invoice['id'] ?? '' ),
			'provider'       => (string) ( $invoice['provider'] ?? '' ),
			'month'          => (string) ( $invoice['month'] ?? '' ),
			'note'           => (string) ( $invoice['note'] ?? '' ),
			'estimated'      => $estimated,
			'invoiced'       => $invoiced,
			'delta_abs'      => $delta_abs,
			'delta_pct'      => $delta_pct,
			'over'           => $over,
			'direction'      => $direction,
			'direction_text' => self::direction_text( $direction ),
		);
	}

	/**
	 * Plain-language reading of the variance direction.
	 */
	public static function direction_text( string $direction ): string {
		if ( self::DIRECTION_BELOW === $direction ) {
			return __( 'Estimate is far below the bill: likely unmetered usage or calls outside the gate.', 'handl-ai-connector-access-control' );
		}
		if ( self::DIRECTION_ABOVE === $direction ) {
			return __( 'Estimate is far above the bill: likely a stale rate table.', 'handl-ai-connector-access-control' );
		}

		return __( 'OK: within tolerance.', 'handl-ai-connector-access-control' );
	}

	/**
	 * Variance rows for the whole ledger. Over-threshold first (largest USD gap
	 * first), then within-tolerance rows newest month first.
	 *
	 * @param list<array<string,mixed>>|null $log    Optional log rows.
	 * @param array<string,mixed>|null       $policy Optional policy.
	 * @return list<array<string,mixed>>
	 */
	public static function variances( ?array $log = null, ?array $policy = null ): array {
		$log       = null !== $log ? $log : self::load_log();
		$policy    = null !== $policy ? $policy : self::load_policy();
		$threshold = self::threshold_pct();
		$out       = array();
		$cache     = array();

		foreach ( self::get_invoices() as $invoice ) {
			$key = $invoice['provider'] . '|' . $invoice['month'];
			if ( ! isset( $cache[ $key ] ) ) {
				$cache[ $key ] = self::estimated_spend( $invoice['provider'], $invoice['month'], $log, $policy );
			}
			$out[] = self::compute_variance( $invoice, $cache[ $key ], $threshold );
		}

		usort(
			$out,
			static function ( array $a, array $b ): int {
				$cmp = (int) ! empty( $b['over'] ) <=> (int) ! empty( $a['over'] );
				if ( 0 !== $cmp ) {
					return $cmp;
				}
				if ( ! empty( $a['over'] ) ) {
					$cmp = abs( (float) $b['delta_abs'] ) <=> abs( (float) $a['delta_abs'] );
					if ( 0 !== $cmp ) {
						return $cmp;
					}
				}
				$cmp = strcmp( (string) $b['month'], (string) $a['month'] );
				if ( 0 !== $cmp ) {
					return $cmp;
				}

				return strcmp( (string) $a['id'], (string) $b['id'] );
			}
		);

		return $out;
	}

	/**
	 * @param list<array<string,mixed>>|null $log    Optional log rows.
	 * @param array<string,mixed>|null       $policy Optional policy.
	 * @return array<string,mixed>
	 */
	public static function snapshot( ?array $log = null, ?array $policy = null, ?int $now = null ): array {
		$now      = null !== $now && $now > 0
			? $now
			: ( class_exists( Clock::class, false ) ? Clock::now() : time() );
		$roster   = self::variances( $log, $policy );
		$over     = array();
		foreach ( $roster as $row ) {
			if ( ! empty( $row['over'] ) ) {
				$over[] = $row;
			}
		}
		$state    = self::get_state();
		$settings = self::get_settings();

		return array(
			'enabled'       => ! empty( $settings['enabled'] ),
			'threshold_pct' => self::threshold_pct(),
			'invoices'      => $settings['invoices'],
			'roster'        => $roster,
			'over'          => $over,
			'over_count'    => count( $over ),
			'worst'         => ! empty( $over ) ? $over[0] : null,
			'alerted'       => ! empty( $state['alerted'] ),
			'history'       => $state['history'],
			'framing'       => self::FRAMING,
			'now'           => $now,
		);
	}

	/* ---------------------------------------------------------------------
	 * Alerts
	 * ------------------------------------------------------------------ */

	/**
	 * @return bool True when a new alert was sent.
	 */
	public static function maybe_fire_alerts( ?int $now = null ): bool {
		if ( ! self::is_enabled() ) {
			return false;
		}
		$now        = null !== $now && $now > 0
			? $now
			: ( class_exists( Clock::class, false ) ? Clock::now() : time() );
		$snap       = self::snapshot( null, null, $now );
		$over_count = (int) $snap['over_count'];

		if ( $over_count <= 0 ) {
			if ( self::is_alerted() ) {
				self::set_alerted( false );
			}

			return false;
		}

		if ( self::is_alerted() ) {
			return false;
		}

		if ( ! self::fire_alert( $snap, $now ) ) {
			return false;
		}

		$worst = is_array( $snap['worst'] ?? null ) ? (array) $snap['worst'] : array();
		$state = self::get_state();

		$state['alerted']   = true;
		$state['history']   = $state['history'] ?? array();
		$state['history'][] = array(
			'ts'              => $now,
			'over_count'      => $over_count,
			'worst_id'        => (string) ( $worst['id'] ?? '' ),
			'worst_provider'  => (string) ( $worst['provider'] ?? '' ),
			'worst_month'     => (string) ( $worst['month'] ?? '' ),
			'worst_delta_usd' => (float) ( $worst['delta_abs'] ?? 0.0 ),
		);
		self::put_state( $state );

		return true;
	}

	/**
	 * @param array<string,mixed> $snap Snapshot.
	 */
	private static function fire_alert( array $snap, int $now ): bool {
		$policy = self::load_policy();

		$email = '';
		if ( class_exists( Alerts::class, false ) && method_exists( Alerts::class, 'resolve_email' ) ) {
			$email = (string) Alerts::resolve_email( $policy );
		}
		if ( '' === $email ) {
			$email = function_exists( 'sanitize_email' )
				? sanitize_email( (string) get_option( 'admin_email' ) )
				: (string) get_option( 'admin_email' );
		}
		if ( '' === $email ) {
			return false;
		}

		$subject = self::build_subject( $snap );
		$body    = self::build_body( $snap );
		$ok      = false;
		if ( class_exists( Alerts::class, false ) && method_exists( Alerts::class, 'safe_wp_mail' ) ) {
			$ok = (bool) Alerts::safe_wp_mail( $email, $subject, $body );
		} elseif ( function_exists( 'wp_mail' ) ) {
			$ok = (bool) wp_mail( $email, $subject, $body );
		}
		self::$test_mails[] = array(
			'to'      => $email,
			'subject' => $subject,
			'body'    => $body,
		);

		if ( $ok && class_exists( Alerts::class, false ) && method_exists( Alerts::class, 'resolve_webhook' ) ) {
			$hook_url = (string) Alerts::resolve_webhook( $policy );
			if ( '' !== $hook_url && method_exists( Alerts::class, 'safe_wp_remote_post' ) ) {
				$worst = is_array( $snap['worst'] ?? null ) ? (array) $snap['worst'] : array();
				Alerts::safe_wp_remote_post(
					$hook_url,
					array(
						'type'          => 'handl_aicac_reconcile',
						'over_count'    => (int) ( $snap['over_count'] ?? 0 ),
						'worst_id'      => (string) ( $worst['id'] ?? '' ),
						'worst_provider' => (string) ( $worst['provider'] ?? '' ),
						'worst_month'   => (string) ( $worst['month'] ?? '' ),
						'worst_delta_usd' => (float) ( $worst['delta_abs'] ?? 0.0 ),
						'direction'     => (string) ( $worst['direction'] ?? '' ),
						'threshold_pct' => (float) ( $snap['threshold_pct'] ?? self::DEFAULT_THRESHOLD_PCT ),
						'site'          => function_exists( 'home_url' ) ? home_url( '/' ) : '',
						'ts'            => $now,
					)
				);
			}
		}

		return $ok;
	}

	/**
	 * @param array<string,mixed> $snap Snapshot.
	 */
	public static function build_subject( array $snap ): string {
		$site  = function_exists( 'get_bloginfo' )
			? wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES )
			: 'WordPress';
		$worst = is_array( $snap['worst'] ?? null ) ? (array) $snap['worst'] : array();

		return sprintf(
			/* translators: 1: site name, 2: variance count, 3: provider, 4: month */
			__( '[%1$s] [RECONCILE] %2$d provider invoice(s) differ from logged estimate (largest: %3$s %4$s)', 'handl-ai-connector-access-control' ),
			$site,
			(int) ( $snap['over_count'] ?? 0 ),
			(string) ( $worst['provider'] ?? '' ),
			(string) ( $worst['month'] ?? '' )
		);
	}

	/**
	 * @param array<string,mixed> $snap Snapshot.
	 */
	public static function build_body( array $snap ): string {
		$lines   = array();
		$worst   = is_array( $snap['worst'] ?? null ) ? (array) $snap['worst'] : array();
		$lines[] = __( 'One or more manually entered provider invoices differ from the spend estimated from this site\'s activity log by more than the configured tolerance.', 'handl-ai-connector-access-control' );
		$lines[] = '';
		$lines[] = sprintf(
			/* translators: 1: variance count, 2: threshold percent */
			__( 'Over-threshold variances: %1$d (tolerance %2$s%%)', 'handl-ai-connector-access-control' ),
			(int) ( $snap['over_count'] ?? 0 ),
			self::format_number( (float) ( $snap['threshold_pct'] ?? self::DEFAULT_THRESHOLD_PCT ) )
		);
		if ( ! empty( $worst ) ) {
			$lines[] = sprintf(
				/* translators: 1: provider, 2: month, 3: estimated, 4: invoiced, 5: delta */
				__( 'Largest: %1$s %2$s — estimated %3$s vs invoiced %4$s (delta %5$s)', 'handl-ai-connector-access-control' ),
				(string) ( $worst['provider'] ?? '' ),
				(string) ( $worst['month'] ?? '' ),
				self::format_usd( (float) ( $worst['estimated'] ?? 0.0 ) ),
				self::format_usd( (float) ( $worst['invoiced'] ?? 0.0 ) ),
				self::format_signed_usd( (float) ( $worst['delta_abs'] ?? 0.0 ) )
			);
			$lines[] = (string) ( $worst['direction_text'] ?? '' );
		}
		$lines[] = '';
		$lines[] = __( 'Report only — never changes cost estimates, rates, budgets, or policy.', 'handl-ai-connector-access-control' );
		$url     = self::admin_url();
		if ( '' !== $url ) {
			$lines[] = '';
			$lines[] = sprintf(
				/* translators: %s: admin URL */
				__( 'Open reconciliation: %s', 'handl-ai-connector-access-control' ),
				$url
			);
		}

		return implode( "\n", $lines );
	}

	public static function admin_url(): string {
		if ( ! function_exists( 'admin_url' ) ) {
			return '';
		}

		return (string) add_query_arg( 'page', self::PAGE_SLUG, admin_url( 'admin.php' ) );
	}

	/* ---------------------------------------------------------------------
	 * Formatting helpers
	 * ------------------------------------------------------------------ */

	public static function format_number( float $v ): string {
		$s = number_format( $v, 2, '.', '' );
		if ( str_contains( $s, '.' ) ) {
			$s = rtrim( rtrim( $s, '0' ), '.' );
		}

		return '' === $s ? '0' : $s;
	}

	public static function format_usd( float $amount ): string {
		$decimals = ( $amount > 0.0 && $amount < 0.01 ) ? 4 : 2;

		return '$' . number_format( $amount, $decimals, '.', ',' );
	}

	public static function format_signed_usd( float $amount ): string {
		return ( $amount < 0.0 ? '-' : '+' ) . self::format_usd( abs( $amount ) );
	}

	/**
	 * @param float|null $pct Percent or null.
	 */
	public static function format_pct( ?float $pct ): string {
		if ( null === $pct ) {
			return 'n/a';
		}

		return ( $pct < 0.0 ? '-' : '+' ) . self::format_number( abs( $pct ) ) . '%';
	}

	/* ---------------------------------------------------------------------
	 * CSV + print
	 * ------------------------------------------------------------------ */

	/**
	 * @param array<string,mixed>|null $snap Optional snapshot.
	 */
	public static function csv_for_snapshot( ?array $snap = null ): string {
		if ( null === $snap ) {
			$snap = self::snapshot();
		}
		$lines   = array();
		$lines[] = self::csv_line(
			array(
				'section',
				'id',
				'provider',
				'month',
				'estimated_usd',
				'invoiced_usd',
				'delta_usd',
				'delta_pct',
				'over_threshold',
				'direction',
				'note',
				'framing',
			)
		);

		$lines[] = self::csv_line(
			array(
				'summary',
				'',
				'',
				'',
				'',
				'',
				'',
				self::format_number( (float) ( $snap['threshold_pct'] ?? self::DEFAULT_THRESHOLD_PCT ) ),
				(string) (int) ( $snap['over_count'] ?? 0 ),
				'',
				'',
				self::FRAMING,
			)
		);

		foreach ( (array) ( $snap['roster'] ?? array() ) as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$lines[] = self::csv_line(
				array(
					'variance',
					(string) ( $row['id'] ?? '' ),
					(string) ( $row['provider'] ?? '' ),
					(string) ( $row['month'] ?? '' ),
					number_format( (float) ( $row['estimated'] ?? 0.0 ), 4, '.', '' ),
					number_format( (float) ( $row['invoiced'] ?? 0.0 ), 4, '.', '' ),
					number_format( (float) ( $row['delta_abs'] ?? 0.0 ), 4, '.', '' ),
					null !== ( $row['delta_pct'] ?? null ) ? number_format( (float) $row['delta_pct'], 2, '.', '' ) : '',
					! empty( $row['over'] ) ? 'yes' : 'no',
					(string) ( $row['direction'] ?? '' ),
					self::csv_text( (string) ( $row['note'] ?? '' ) ),
					self::FRAMING,
				)
			);
		}

		return implode( "\n", $lines ) . "\n";
	}

	/**
	 * Neutralize spreadsheet formula injection for free-text cells.
	 */
	public static function csv_text( string $text ): string {
		if ( '' !== $text && in_array( $text[0], array( '=', '+', '-', '@', "\t", "\r" ), true ) ) {
			return "'" . $text;
		}

		return $text;
	}

	/**
	 * @param list<string> $cols Columns.
	 */
	public static function csv_line( array $cols ): string {
		$out = array();
		foreach ( $cols as $col ) {
			$col   = (string) $col;
			$needs = str_contains( $col, ',' ) || str_contains( $col, '"' ) || str_contains( $col, "\n" );
			$col   = str_replace( '"', '""', $col );
			$out[] = $needs ? '"' . $col . '"' : $col;
		}

		return implode( ',', $out );
	}

	/**
	 * @param array<string,mixed> $snap Snapshot.
	 */
	public static function build_print_html( array $snap ): string {
		$html  = '<!DOCTYPE html><html><head><meta charset="utf-8"><title>';
		$html .= esc_html__( 'AI Connector invoice reconciliation', 'handl-ai-connector-access-control' );
		$html .= '</title><style>body{font-family:sans-serif;margin:24px}table{border-collapse:collapse;width:100%;margin-bottom:24px}th,td{border:1px solid #ccc;padding:6px 8px;text-align:left}th{background:#f6f7f7}</style></head><body>';
		$html .= '<h1>' . esc_html__( 'AI Connector invoice reconciliation', 'handl-ai-connector-access-control' ) . '</h1>';
		$html .= '<p>' . esc_html__( 'Report only — never changes cost estimates, rates, budgets, or policy.', 'handl-ai-connector-access-control' ) . '</p>';
		$html .= '<ul><li>' . esc_html(
			sprintf(
				/* translators: 1: over count, 2: invoice count, 3: threshold percent */
				__( 'Over tolerance: %1$d of %2$d invoice(s) (tolerance %3$s%%)', 'handl-ai-connector-access-control' ),
				(int) ( $snap['over_count'] ?? 0 ),
				count( (array) ( $snap['roster'] ?? array() ) ),
				self::format_number( (float) ( $snap['threshold_pct'] ?? self::DEFAULT_THRESHOLD_PCT ) )
			)
		) . '</li></ul>';

		$html .= '<h2>' . esc_html__( 'Variance roster', 'handl-ai-connector-access-control' ) . '</h2>';
		$html .= '<table><thead><tr>';
		foreach ( array( 'Provider', 'Month', 'Estimated', 'Invoiced', 'Delta', 'Delta %', 'Reading' ) as $label ) {
			$html .= '<th>' . esc_html( $label ) . '</th>';
		}
		$html .= '</tr></thead><tbody>';
		$roster = (array) ( $snap['roster'] ?? array() );
		if ( empty( $roster ) ) {
			$html .= '<tr><td colspan="7">' . esc_html__( 'No invoices entered.', 'handl-ai-connector-access-control' ) . '</td></tr>';
		} else {
			foreach ( $roster as $row ) {
				if ( ! is_array( $row ) ) {
					continue;
				}
				$html .= '<tr>';
				$html .= '<td>' . esc_html( (string) ( $row['provider'] ?? '' ) ) . '</td>';
				$html .= '<td>' . esc_html( (string) ( $row['month'] ?? '' ) ) . '</td>';
				$html .= '<td>' . esc_html( self::format_usd( (float) ( $row['estimated'] ?? 0.0 ) ) ) . '</td>';
				$html .= '<td>' . esc_html( self::format_usd( (float) ( $row['invoiced'] ?? 0.0 ) ) ) . '</td>';
				$html .= '<td>' . esc_html( self::format_signed_usd( (float) ( $row['delta_abs'] ?? 0.0 ) ) ) . '</td>';
				$html .= '<td>' . esc_html( self::format_pct( isset( $row['delta_pct'] ) ? (float) $row['delta_pct'] : null ) ) . '</td>';
				$html .= '<td>' . esc_html( (string) ( $row['direction_text'] ?? '' ) ) . '</td>';
				$html .= '</tr>';
			}
		}
		$html .= '</tbody></table></body></html>';

		return $html;
	}

	/* ---------------------------------------------------------------------
	 * Admin UI
	 * ------------------------------------------------------------------ */

	public static function register_menu(): void {
		if ( ! Caps::user_can_view() ) {
			return;
		}
		if ( ! function_exists( 'add_submenu_page' ) ) {
			return;
		}
		add_submenu_page(
			Admin::MENU_SLUG,
			__( 'Invoice reconciliation', 'handl-ai-connector-access-control' ),
			__( 'Reconcile', 'handl-ai-connector-access-control' ),
			Caps::VIEW,
			self::PAGE_SLUG,
			array( self::class, 'render_page' )
		);
	}

	public static function render_page(): void {
		if ( ! Caps::user_can_view() ) {
			return;
		}
		$settings   = self::get_settings();
		$can_manage = Caps::user_can_manage();
		$enabled    = self::is_enabled();
		$snap       = $enabled ? self::snapshot() : null;
		$csv        = add_query_arg(
			array(
				'page'                      => self::PAGE_SLUG,
				'handl_aicac_reconcile_csv' => '1',
				'_wpnonce'                  => function_exists( 'wp_create_nonce' ) ? wp_create_nonce( 'handl_aicac_reconcile_csv' ) : '',
			),
			admin_url( 'admin.php' )
		);
		$print      = add_query_arg(
			array(
				'page'                        => self::PAGE_SLUG,
				'handl_aicac_reconcile_print' => '1',
				'_wpnonce'                    => function_exists( 'wp_create_nonce' ) ? wp_create_nonce( 'handl_aicac_reconcile_print' ) : '',
			),
			admin_url( 'admin.php' )
		);

		echo '<div class="wrap">';
		echo '<h1>' . esc_html__( 'Invoice reconciliation', 'handl-ai-connector-access-control' ) . '</h1>';
		echo '<p class="description">' . esc_html__( 'Compare what a provider actually billed with the spend this plugin estimated from its own activity log. Report only — never changes cost estimates, rates, budgets, or policy. Off by default.', 'handl-ai-connector-access-control' ) . '</p>';

		if ( $can_manage ) {
			$action = admin_url( 'admin-post.php' );
			echo '<form method="post" action="' . esc_url( $action ) . '">';
			echo '<input type="hidden" name="action" value="' . esc_attr( self::ACTION_SAVE ) . '" />';
			if ( function_exists( 'wp_nonce_field' ) ) {
				wp_nonce_field( self::ACTION_SAVE );
			}
			echo '<input type="hidden" name="' . esc_attr( self::POST_PRESENT ) . '" value="1" />';
			echo '<table class="form-table" role="presentation"><tbody>';
			echo '<tr><th scope="row">' . esc_html__( 'Enable reconciliation', 'handl-ai-connector-access-control' ) . '</th><td>';
			echo '<label><input type="checkbox" name="' . esc_attr( self::POST_ENABLED ) . '" value="1" ' . checked( ! empty( $settings['enabled'] ), true, false ) . ' /> ';
			echo esc_html__( 'Compare invoices with logged estimates and alert once when a variance exceeds the tolerance', 'handl-ai-connector-access-control' );
			echo '</label></td></tr>';
			echo '<tr><th scope="row"><label for="handl-aicac-reconcile-threshold">' . esc_html__( 'Tolerance (%)', 'handl-ai-connector-access-control' ) . '</label></th><td>';
			echo '<input name="' . esc_attr( self::POST_THRESHOLD_PCT ) . '" id="handl-aicac-reconcile-threshold" type="number" min="' . esc_attr( (string) self::MIN_THRESHOLD_PCT ) . '" max="' . esc_attr( (string) self::MAX_THRESHOLD_PCT ) . '" step="0.1" value="' . esc_attr( self::format_number( (float) $settings['threshold_pct'] ) ) . '" class="small-text" />';
			echo '<p class="description">' . esc_html__( 'Default 10. Variances at or beyond this percentage of the invoiced amount are flagged.', 'handl-ai-connector-access-control' ) . '</p>';
			echo '</td></tr>';
			echo '<tr><th scope="row">' . esc_html__( 'Add invoice', 'handl-ai-connector-access-control' ) . '</th><td>';
			$providers = ( class_exists( Cost::class, false ) && defined( Cost::class . '::KNOWN_PROVIDERS' ) ) ? (array) Cost::KNOWN_PROVIDERS : array();
			echo '<datalist id="handl-aicac-reconcile-providers">';
			foreach ( $providers as $pid ) {
				echo '<option value="' . esc_attr( (string) $pid ) . '"></option>';
			}
			echo '</datalist>';
			echo '<input name="' . esc_attr( self::POST_NEW_PROVIDER ) . '" type="text" list="handl-aicac-reconcile-providers" placeholder="' . esc_attr__( 'provider (e.g. openai)', 'handl-ai-connector-access-control' ) . '" class="regular-text" aria-label="' . esc_attr__( 'Provider', 'handl-ai-connector-access-control' ) . '" /> ';
			echo '<input name="' . esc_attr( self::POST_NEW_MONTH ) . '" type="month" placeholder="YYYY-MM" aria-label="' . esc_attr__( 'Billing month', 'handl-ai-connector-access-control' ) . '" /> ';
			echo '<input name="' . esc_attr( self::POST_NEW_AMOUNT ) . '" type="number" min="0" step="0.01" placeholder="' . esc_attr__( 'USD billed', 'handl-ai-connector-access-control' ) . '" class="small-text" aria-label="' . esc_attr__( 'Invoiced amount in USD', 'handl-ai-connector-access-control' ) . '" /> ';
			echo '<input name="' . esc_attr( self::POST_NEW_NOTE ) . '" type="text" maxlength="' . esc_attr( (string) self::NOTE_MAX_LENGTH ) . '" placeholder="' . esc_attr__( 'note (optional)', 'handl-ai-connector-access-control' ) . '" class="regular-text" aria-label="' . esc_attr__( 'Note', 'handl-ai-connector-access-control' ) . '" />';
			echo '<p class="description">' . esc_html__( 'Enter what the provider billed for one calendar month (site timezone). Up to 100 invoices are kept.', 'handl-ai-connector-access-control' ) . '</p>';
			echo '</td></tr></tbody></table>';

			if ( ! empty( $settings['invoices'] ) ) {
				echo '<h2>' . esc_html__( 'Invoice ledger', 'handl-ai-connector-access-control' ) . '</h2>';
				echo '<table class="widefat striped"><thead><tr>';
				echo '<th>' . esc_html__( 'Remove', 'handl-ai-connector-access-control' ) . '</th>';
				echo '<th>' . esc_html__( 'Provider', 'handl-ai-connector-access-control' ) . '</th>';
				echo '<th>' . esc_html__( 'Month', 'handl-ai-connector-access-control' ) . '</th>';
				echo '<th>' . esc_html__( 'Invoiced', 'handl-ai-connector-access-control' ) . '</th>';
				echo '<th>' . esc_html__( 'Note', 'handl-ai-connector-access-control' ) . '</th>';
				echo '</tr></thead><tbody>';
				foreach ( $settings['invoices'] as $inv ) {
					echo '<tr>';
					echo '<td><input type="checkbox" name="' . esc_attr( self::POST_REMOVE ) . '[]" value="' . esc_attr( (string) $inv['id'] ) . '" aria-label="' . esc_attr__( 'Remove this invoice', 'handl-ai-connector-access-control' ) . '" /></td>';
					echo '<td><code>' . esc_html( (string) $inv['provider'] ) . '</code></td>';
					echo '<td>' . esc_html( (string) $inv['month'] ) . '</td>';
					echo '<td>' . esc_html( self::format_usd( (float) $inv['amount'] ) ) . '</td>';
					echo '<td>' . esc_html( (string) $inv['note'] ) . '</td>';
					echo '</tr>';
				}
				echo '</tbody></table>';
			}
			submit_button( __( 'Save reconciliation settings', 'handl-ai-connector-access-control' ) );
			echo '</form>';
		}

		if ( ! $enabled || ! is_array( $snap ) ) {
			echo '<p>' . esc_html__( 'Reconciliation is off. Enable it to compare provider invoices with logged estimates.', 'handl-ai-connector-access-control' ) . '</p>';
			echo '</div>';

			return;
		}

		echo '<p><strong>' . esc_html__( 'Report only — never changes cost estimates, rates, budgets, or policy.', 'handl-ai-connector-access-control' ) . '</strong></p>';
		echo '<ul><li>' . esc_html(
			sprintf(
				/* translators: 1: over count, 2: invoice count, 3: threshold */
				__( 'Over tolerance: %1$d of %2$d invoice(s) (tolerance %3$s%%)', 'handl-ai-connector-access-control' ),
				(int) $snap['over_count'],
				count( (array) $snap['roster'] ),
				self::format_number( (float) $snap['threshold_pct'] )
			)
		) . '</li></ul>';

		echo '<p>';
		echo '<a class="button" href="' . esc_url( $csv ) . '">' . esc_html__( 'Download CSV', 'handl-ai-connector-access-control' ) . '</a> ';
		echo '<a class="button" href="' . esc_url( $print ) . '" target="_blank" rel="noopener noreferrer">' . esc_html__( 'Print / PDF view', 'handl-ai-connector-access-control' ) . '</a>';
		echo '</p>';

		echo '<h2>' . esc_html__( 'Variance roster', 'handl-ai-connector-access-control' ) . '</h2>';
		if ( empty( $snap['roster'] ) ) {
			echo '<p>' . esc_html__( 'No invoices entered yet.', 'handl-ai-connector-access-control' ) . '</p>';
		} else {
			echo '<table class="widefat striped"><thead><tr>';
			foreach ( array( 'Provider', 'Month', 'Estimated', 'Invoiced', 'Delta', 'Delta %', 'Reading' ) as $label ) {
				echo '<th>' . esc_html( $label ) . '</th>';
			}
			echo '</tr></thead><tbody>';
			foreach ( $snap['roster'] as $row ) {
				echo '<tr>';
				echo '<td><code>' . esc_html( (string) $row['provider'] ) . '</code></td>';
				echo '<td>' . esc_html( (string) $row['month'] ) . '</td>';
				echo '<td>' . esc_html( self::format_usd( (float) $row['estimated'] ) ) . '</td>';
				echo '<td>' . esc_html( self::format_usd( (float) $row['invoiced'] ) ) . '</td>';
				echo '<td>' . esc_html( self::format_signed_usd( (float) $row['delta_abs'] ) ) . '</td>';
				echo '<td>' . esc_html( self::format_pct( null === $row['delta_pct'] ? null : (float) $row['delta_pct'] ) ) . '</td>';
				echo '<td>';
				if ( ! empty( $row['over'] ) ) {
					echo '<strong>' . esc_html( (string) $row['direction_text'] ) . '</strong>';
				} else {
					echo esc_html( (string) $row['direction_text'] );
				}
				echo '</td>';
				echo '</tr>';
			}
			echo '</tbody></table>';
		}

		echo '</div>';
	}

	public static function maybe_handle_csv(): void {
		if ( empty( $_GET['handl_aicac_reconcile_csv'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			return;
		}
		$page = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( (string) $_GET['page'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( self::PAGE_SLUG !== $page ) {
			return;
		}
		if ( ! Caps::user_can_view() || ! self::is_enabled() ) {
			return;
		}
		$nonce = isset( $_GET['_wpnonce'] ) ? (string) wp_unslash( $_GET['_wpnonce'] ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( ! function_exists( 'wp_verify_nonce' ) || ! wp_verify_nonce( $nonce, 'handl_aicac_reconcile_csv' ) ) {
			return;
		}
		$csv = self::csv_for_snapshot();
		if ( function_exists( 'nocache_headers' ) ) {
			nocache_headers();
		}
		header( 'Content-Type: text/csv; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename=handl-aicac-reconcile.csv' );
		echo $csv; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- CSV download.
		exit;
	}

	public static function maybe_handle_print(): void {
		if ( empty( $_GET['handl_aicac_reconcile_print'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			return;
		}
		$page = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( (string) $_GET['page'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( self::PAGE_SLUG !== $page ) {
			return;
		}
		if ( ! Caps::user_can_view() || ! self::is_enabled() ) {
			return;
		}
		$nonce = isset( $_GET['_wpnonce'] ) ? (string) wp_unslash( $_GET['_wpnonce'] ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( ! function_exists( 'wp_verify_nonce' ) || ! wp_verify_nonce( $nonce, 'handl_aicac_reconcile_print' ) ) {
			return;
		}
		if ( function_exists( 'nocache_headers' ) ) {
			nocache_headers();
		}
		echo self::build_print_html( self::snapshot() ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped in builder.
		exit;
	}

	public static function handle_save(): void {
		if ( ! Caps::user_can_manage() ) {
			wp_die( esc_html__( 'You do not have permission to save reconciliation settings.', 'handl-ai-connector-access-control' ) );
		}
		check_admin_referer( self::ACTION_SAVE );
		if ( empty( $_POST[ self::POST_PRESENT ] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing
			wp_die( esc_html__( 'Security check failed. Go back, reload the page, and try again.', 'handl-ai-connector-access-control' ) );
		}
		$post = array();
		foreach ( array( self::POST_ENABLED, self::POST_THRESHOLD_PCT, self::POST_REMOVE, self::POST_NEW_PROVIDER, self::POST_NEW_MONTH, self::POST_NEW_AMOUNT, self::POST_NEW_NOTE ) as $key ) {
			if ( isset( $_POST[ $key ] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing
				$post[ $key ] = wp_unslash( $_POST[ $key ] ); // phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- sanitized in settings_from_form().
			}
		}
		self::save_settings( self::settings_from_form( $post, self::get_settings() ) );
		$redirect = self::admin_url();
		if ( '' === $redirect && function_exists( 'admin_url' ) ) {
			$redirect = admin_url( 'admin.php?page=' . self::PAGE_SLUG );
		}
		wp_safe_redirect( $redirect );
		exit;
	}

	public static function register_cli(): void {
		if ( ! defined( 'WP_CLI' ) || ! WP_CLI ) {
			return;
		}
		if ( ! class_exists( '\\WP_CLI' ) ) {
			return;
		}
		\WP_CLI::add_command( 'handl-aicac reconcile', CLI_Reconcile::class );
	}
}

/**
 * WP-CLI: wp handl-aicac reconcile status|export
 */
final class CLI_Reconcile {

	/**
	 * Show reconciliation status. Exits non-zero on any over-threshold variance.
	 *
	 * ## OPTIONS
	 *
	 * [--format=<format>]
	 * : table or json. Default table.
	 *
	 * @when after_wp_load
	 *
	 * @param array<int,string>    $args       Positional.
	 * @param array<string,string> $assoc_args Flags.
	 */
	public function status( $args, $assoc_args ): void {
		unset( $args );
		$format = isset( $assoc_args['format'] ) ? (string) $assoc_args['format'] : 'table';

		if ( ! Reconcile::is_enabled() ) {
			\WP_CLI::log(
				sprintf(
					'enabled=no threshold_pct=%s framing=%s',
					Reconcile::format_number( (float) Reconcile::get_settings()['threshold_pct'] ),
					Reconcile::FRAMING
				)
			);
			\WP_CLI::log( 'Invoice reconciliation is disabled.' );

			return;
		}

		$snap = Reconcile::snapshot();
		\WP_CLI::log(
			sprintf(
				'enabled=yes threshold_pct=%s invoices=%d over=%d alerted=%s framing=%s',
				Reconcile::format_number( (float) $snap['threshold_pct'] ),
				count( (array) $snap['roster'] ),
				(int) $snap['over_count'],
				! empty( $snap['alerted'] ) ? 'yes' : 'no',
				Reconcile::FRAMING
			)
		);

		$display = array();
		foreach ( (array) $snap['roster'] as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$display[] = array(
				'provider'  => (string) ( $row['provider'] ?? '' ),
				'month'     => (string) ( $row['month'] ?? '' ),
				'estimated' => number_format( (float) ( $row['estimated'] ?? 0.0 ), 4, '.', '' ),
				'invoiced'  => number_format( (float) ( $row['invoiced'] ?? 0.0 ), 4, '.', '' ),
				'delta_pct' => null !== ( $row['delta_pct'] ?? null ) ? number_format( (float) $row['delta_pct'], 2, '.', '' ) : 'n/a',
				'over'      => ! empty( $row['over'] ) ? 'yes' : 'no',
				'direction' => (string) ( $row['direction'] ?? '' ),
			);
		}
		if ( ! empty( $display ) ) {
			if ( 'json' === $format ) {
				\WP_CLI::print_value( $display, array( 'format' => 'json' ) );
			} elseif ( class_exists( '\\WP_CLI\\Utils' ) ) {
				\WP_CLI\Utils\format_items( 'table', $display, array( 'provider', 'month', 'estimated', 'invoiced', 'delta_pct', 'over', 'direction' ) );
			} else {
				foreach ( $display as $row ) {
					\WP_CLI::log( implode( "\t", $row ) );
				}
			}
		}

		if ( (int) $snap['over_count'] > 0 ) {
			// Default exit=true: non-zero exit status.
			\WP_CLI::error( 'Over-threshold invoice variances present.' );
		}
	}

	/**
	 * Export the reconciliation report as CSV.
	 *
	 * ## OPTIONS
	 *
	 * [--porcelain]
	 * : Print CSV only.
	 *
	 * @when after_wp_load
	 *
	 * @param array<int,string>    $args       Positional.
	 * @param array<string,string> $assoc_args Flags.
	 */
	public function export( $args, $assoc_args ): void {
		unset( $args );
		$csv = Reconcile::csv_for_snapshot();
		if ( ! empty( $assoc_args['porcelain'] ) ) {
			echo $csv; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- CLI CSV.
			return;
		}
		\WP_CLI::print_value( $csv, array( 'format' => 'csv' ) );
	}
}
