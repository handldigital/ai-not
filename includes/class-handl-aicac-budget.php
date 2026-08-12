<?php
/**
 * AICAC-BUDGET: per-plugin estimated-spend ceiling (A accounting, B enforce, C UI/alerts).
 *
 * Accumulates estimated USD (rate table) keyed by period id (Y-m) in the site
 * timezone. Period key is authoritative — a mid-month timezone change cannot
 * double-count already-recorded spend.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Spend accumulator + budget storage + enforcement + UI/alert helpers (AICAC-BUDGET-A/B/C).
 */
final class Budget {

	/** period_id => [ plugin_basename => estimated_usd ]. */
	public const SPEND_OPTION_KEY = 'handl_aicac_budget_spend';

	/** Fired-state for budget-hit emails: plugin:basename => { period, at, budget }. */
	public const FIRED_OPTION_KEY = 'handl_aicac_budget_fired';

	/** Keep a few past months so B/C can report; drop older keys on write. */
	public const RETAIN_PERIODS = 6;

	public const MODE_DENY    = 'deny';
	public const MODE_OBSERVE = 'observe';

	/** Soft-warning fraction of budget when no explicit spend threshold is set. */
	public const SOFT_WARN_RATIO = 0.8;

	/**
	 * Calendar-month period id in site timezone (e.g. 2026-08).
	 */
	public static function period_id( ?int $ts = null, ?\DateTimeZone $tz = null ): string {
		$ts = null !== $ts ? (int) $ts : time();
		if ( $ts <= 0 ) {
			$ts = time();
		}
		$tz = Quiet_Hours::timezone( $tz );
		return ( new \DateTimeImmutable( '@' . $ts ) )->setTimezone( $tz )->format( 'Y-m' );
	}

	/**
	 * @param mixed $raw
	 */
	public static function sanitize_period_id( $raw ): string {
		$key = (string) $raw;
		if ( ! preg_match( '/^\d{4}-(0[1-9]|1[0-2])$/', $key ) ) {
			return '';
		}
		return $key;
	}

	/**
	 * Empty / non-positive → unlimited (omit). Positive USD capped.
	 *
	 * @param mixed $raw
	 */
	public static function sanitize_budget_amount( $raw ): ?float {
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
		$v = (float) $raw;
		if ( $v <= 0 ) {
			return null;
		}
		if ( $v > 1000000 ) {
			$v = 1000000.0;
		}

		return round( $v, 4 );
	}

	/**
	 * @param mixed $raw basename => amount map
	 * @return array<string,float>
	 */
	public static function sanitize_plugin_budgets( $raw ): array {
		if ( ! is_array( $raw ) ) {
			return array();
		}
		$out = array();
		foreach ( $raw as $basename => $amount ) {
			$basename = Plugin_Profile::sanitize_plugin( (string) $basename );
			if ( '' === $basename ) {
				continue;
			}
			$budget = self::sanitize_budget_amount( $amount );
			if ( null === $budget ) {
				continue;
			}
			$out[ $basename ] = $budget;
		}

		return $out;
	}

	/**
	 * Configured budget for a plugin, or null when unlimited.
	 *
	 * @param array<string,mixed> $policy
	 */
	public static function get_budget( array $policy, string $plugin ): ?float {
		$plugin = Plugin_Profile::sanitize_plugin( $plugin );
		if ( '' === $plugin ) {
			return null;
		}
		$map = self::sanitize_plugin_budgets( $policy['plugin_budgets'] ?? array() );

		return $map[ $plugin ] ?? null;
	}

	/**
	 * @return array<string,array<string,float>>
	 */
	public static function get_spend_map(): array {
		return self::sanitize_spend_map( get_option( self::SPEND_OPTION_KEY, array() ) );
	}

	/**
	 * @param mixed $raw
	 * @return array<string,array<string,float>>
	 */
	public static function sanitize_spend_map( $raw ): array {
		if ( ! is_array( $raw ) ) {
			return array();
		}
		$out = array();
		foreach ( $raw as $period => $plugins ) {
			$period = self::sanitize_period_id( $period );
			if ( '' === $period || ! is_array( $plugins ) ) {
				continue;
			}
			$clean = array();
			foreach ( $plugins as $plugin => $usd ) {
				$plugin = Plugin_Profile::sanitize_plugin( (string) $plugin );
				if ( '' === $plugin || ! is_numeric( $usd ) ) {
					continue;
				}
				$amount = round( (float) $usd, 6 );
				if ( $amount < 0 ) {
					$amount = 0.0;
				}
				$clean[ $plugin ] = $amount;
			}
			if ( ! empty( $clean ) ) {
				$out[ $period ] = $clean;
			}
		}

		return $out;
	}

	/**
	 * @param array<string,array<string,float>> $map
	 */
	public static function save_spend_map( array $map ): void {
		$map = self::sanitize_spend_map( $map );
		$map = self::prune_old_periods( $map );
		if ( empty( $map ) ) {
			delete_option( self::SPEND_OPTION_KEY );
			return;
		}
		update_option( self::SPEND_OPTION_KEY, $map, false );
	}

	/**
	 * Drop periods older than RETAIN_PERIODS (by Y-m string order).
	 *
	 * @param array<string,array<string,float>> $map
	 * @return array<string,array<string,float>>
	 */
	public static function prune_old_periods( array $map, ?string $current_period = null ): array {
		if ( count( $map ) <= self::RETAIN_PERIODS ) {
			return $map;
		}
		$keys = array_keys( $map );
		rsort( $keys, SORT_STRING );
		$keep = array_slice( $keys, 0, self::RETAIN_PERIODS );
		$out  = array();
		foreach ( $keep as $k ) {
			$out[ $k ] = $map[ $k ];
		}
		// Prefer retaining the current period even if somehow outside the newest N.
		if ( null !== $current_period && isset( $map[ $current_period ] ) && ! isset( $out[ $current_period ] ) ) {
			$out[ $current_period ] = $map[ $current_period ];
		}

		return $out;
	}

	/**
	 * Add estimated USD to the period bucket for $plugin.
	 * Period id is taken from $ts in $tz (defaults: now / site timezone).
	 */
	public static function add_estimated_spend( string $plugin, float $usd, ?int $ts = null, ?\DateTimeZone $tz = null ): void {
		$plugin = Plugin_Profile::sanitize_plugin( $plugin );
		if ( '' === $plugin || $usd <= 0.0 ) {
			return;
		}
		$period = self::period_id( $ts, $tz );
		$map    = self::get_spend_map();
		if ( ! isset( $map[ $period ] ) ) {
			$map[ $period ] = array();
		}
		$prior = isset( $map[ $period ][ $plugin ] ) ? (float) $map[ $period ][ $plugin ] : 0.0;
		$map[ $period ][ $plugin ] = round( $prior + $usd, 6 );
		self::save_spend_map( self::prune_old_periods( $map, $period ) );
	}

	/**
	 * Estimated spend for a plugin in a period (0 when none).
	 */
	public static function period_spend( string $plugin, string $period ): float {
		$plugin = Plugin_Profile::sanitize_plugin( $plugin );
		$period = self::sanitize_period_id( $period );
		if ( '' === $plugin || '' === $period ) {
			return 0.0;
		}
		$map = self::get_spend_map();

		return isset( $map[ $period ][ $plugin ] ) ? (float) $map[ $period ][ $plugin ] : 0.0;
	}

	/**
	 * Current-period spend for a plugin.
	 */
	public static function current_period_spend( string $plugin, ?int $now = null, ?\DateTimeZone $tz = null ): float {
		return self::period_spend( $plugin, self::period_id( $now, $tz ) );
	}

	/**
	 * Read API for parts B and C.
	 *
	 * @param array<string,mixed> $policy
	 * @return array{
	 *   plugin:string,
	 *   period:string,
	 *   spend:float,
	 *   budget:float|null,
	 *   percent_used:float|null,
	 *   unlimited:bool
	 * }
	 */
	public static function status( array $policy, string $plugin, ?int $now = null, ?\DateTimeZone $tz = null ): array {
		$plugin = Plugin_Profile::sanitize_plugin( $plugin );
		$period = self::period_id( $now, $tz );
		$spend  = self::period_spend( $plugin, $period );
		$budget = self::get_budget( $policy, $plugin );
		$unlimited = null === $budget;
		$percent   = null;
		if ( ! $unlimited && $budget > 0.0 ) {
			$percent = round( 100.0 * ( $spend / $budget ), 2 );
			if ( $percent > 9999.99 ) {
				$percent = 9999.99;
			}
		}

		return array(
			'plugin'       => $plugin,
			'period'       => $period,
			'spend'        => $spend,
			'budget'       => $budget,
			'percent_used' => $percent,
			'unlimited'    => $unlimited,
		);
	}

	/**
	 * Per-plugin enforcement mode. Default hard-deny. Only meaningful when a budget is set.
	 *
	 * @param mixed $raw
	 * @return 'deny'|'observe'
	 */
	public static function sanitize_mode( $raw ): string {
		$key = sanitize_key( (string) $raw );
		return self::MODE_OBSERVE === $key ? self::MODE_OBSERVE : self::MODE_DENY;
	}

	/**
	 * @param mixed $raw basename => mode map
	 * @return array<string,string>
	 */
	public static function sanitize_plugin_budget_modes( $raw ): array {
		if ( ! is_array( $raw ) ) {
			return array();
		}
		$out = array();
		foreach ( $raw as $basename => $mode ) {
			$basename = Plugin_Profile::sanitize_plugin( (string) $basename );
			if ( '' === $basename ) {
				continue;
			}
			$out[ $basename ] = self::sanitize_mode( $mode );
		}

		return $out;
	}

	/**
	 * @param array<string,mixed> $policy
	 * @return 'deny'|'observe'
	 */
	public static function get_mode( array $policy, string $plugin ): string {
		$plugin = Plugin_Profile::sanitize_plugin( $plugin );
		if ( '' === $plugin ) {
			return self::MODE_DENY;
		}
		$map = self::sanitize_plugin_budget_modes( $policy['plugin_budget_modes'] ?? array() );

		return $map[ $plugin ] ?? self::MODE_DENY;
	}

	/**
	 * True when the plugin has a finite budget and current-period estimated spend has reached it.
	 *
	 * @param array<string,mixed> $policy
	 */
	public static function is_over_budget( array $policy, string $plugin, ?int $now = null, ?\DateTimeZone $tz = null ): bool {
		$status = self::status( $policy, $plugin, $now, $tz );
		if ( $status['unlimited'] || null === $status['budget'] ) {
			return false;
		}

		return (float) $status['spend'] >= (float) $status['budget'];
	}

	/**
	 * Decision-path gate. Temp-allow / plugin Allow cannot pierce this.
	 *
	 * @param array<string,mixed> $policy
	 * @return array{prevent:bool,mode:string,reason:string}|null Null when no budget or under budget.
	 */
	public static function evaluate_gate( array $policy, ?string $plugin, ?int $now = null, ?\DateTimeZone $tz = null ): ?array {
		$plugin = Plugin_Profile::sanitize_plugin( (string) $plugin );
		if ( '' === $plugin || ! self::is_over_budget( $policy, $plugin, $now, $tz ) ) {
			return null;
		}
		$mode = self::get_mode( $policy, $plugin );
		if ( self::MODE_OBSERVE === $mode ) {
			return array(
				'prevent' => false,
				'mode'    => self::MODE_OBSERVE,
				'reason'  => 'budget',
			);
		}

		return array(
			'prevent' => true,
			'mode'    => self::MODE_DENY,
			'reason'  => 'budget',
		);
	}

	/**
	 * Auto 80% soft-warning thresholds for plugins that have a budget but no explicit spend threshold.
	 *
	 * @param array<string,mixed> $policy
	 * @return array<string,float>
	 */
	public static function soft_warn_thresholds( array $policy ): array {
		$explicit = Spend_Threshold::sanitize_plugin_thresholds( $policy['spend_threshold_plugins'] ?? array() );
		$budgets  = self::sanitize_plugin_budgets( $policy['plugin_budgets'] ?? array() );
		$out      = array();
		foreach ( $budgets as $plugin => $budget ) {
			if ( isset( $explicit[ $plugin ] ) ) {
				continue;
			}
			$soft = round( (float) $budget * self::SOFT_WARN_RATIO, 4 );
			if ( $soft > 0 ) {
				$out[ $plugin ] = $soft;
			}
		}

		return $out;
	}

	/**
	 * Plugins that currently have a finite budget and estimated spend at/over it.
	 *
	 * @param array<string,mixed> $policy
	 * @return list<array{
	 *   plugin:string,
	 *   period:string,
	 *   spend:float,
	 *   budget:float,
	 *   percent_used:float,
	 *   mode:string
	 * }>
	 */
	public static function over_budget_list( array $policy, ?int $now = null, ?\DateTimeZone $tz = null ): array {
		$budgets = self::sanitize_plugin_budgets( $policy['plugin_budgets'] ?? array() );
		$out     = array();
		foreach ( array_keys( $budgets ) as $plugin ) {
			if ( ! self::is_over_budget( $policy, $plugin, $now, $tz ) ) {
				continue;
			}
			$status = self::status( $policy, $plugin, $now, $tz );
			$out[]  = array(
				'plugin'       => $plugin,
				'period'       => (string) $status['period'],
				'spend'        => (float) $status['spend'],
				'budget'       => (float) $status['budget'],
				'percent_used' => null !== $status['percent_used'] ? (float) $status['percent_used'] : 100.0,
				'mode'         => self::get_mode( $policy, $plugin ),
			);
		}
		usort(
			$out,
			static function ( $a, $b ) {
				return $b['percent_used'] <=> $a['percent_used'];
			}
		);

		return $out;
	}

	/**
	 * Bar fill 0–100 for progress UI (caps display; label may show higher %).
	 *
	 * @param array<string,mixed> $status From status().
	 */
	public static function progress_fill_percent( array $status ): int {
		if ( ! empty( $status['unlimited'] ) || null === ( $status['percent_used'] ?? null ) ) {
			return 0;
		}
		$pct = (float) $status['percent_used'];
		if ( $pct <= 0 ) {
			return 0;
		}
		if ( $pct >= 100 ) {
			return 100;
		}

		return (int) max( 1, (int) round( $pct ) );
	}

	/**
	 * Evaluate budgets and send a one-shot estimated-budget-reached email per plugin/period.
	 *
	 * @param array<string,mixed>|null $policy
	 */
	public static function maybe_evaluate_alerts( ?array $policy = null ): void {
		$policy = is_array( $policy ) ? $policy : Policy::get_policy();
		$budgets = self::sanitize_plugin_budgets( $policy['plugin_budgets'] ?? array() );
		if ( empty( $budgets ) ) {
			return;
		}

		$to = Alerts::resolve_email( $policy );
		if ( '' === $to ) {
			return;
		}

		foreach ( array_keys( $budgets ) as $plugin ) {
			if ( ! self::is_over_budget( $policy, $plugin ) ) {
				self::clear_fire_key( $plugin );
				continue;
			}
			self::maybe_fire_hit( $policy, $to, $plugin );
		}
	}

	/**
	 * @param array<string,mixed> $policy
	 */
	private static function maybe_fire_hit( array $policy, string $to, string $plugin ): void {
		if ( Alert_Snooze::should_suppress( $plugin, 'budget' ) ) {
			return;
		}

		$status = self::status( $policy, $plugin );
		$budget = (float) ( $status['budget'] ?? 0.0 );
		$period = (string) ( $status['period'] ?? '' );
		$spend  = (float) ( $status['spend'] ?? 0.0 );
		$mode   = self::get_mode( $policy, $plugin );

		if ( $budget <= 0.0 || '' === $period ) {
			return;
		}
		if ( self::is_deduped( $plugin, $period, $budget ) ) {
			return;
		}

		$subject = self::build_hit_subject( $plugin );
		$body    = self::build_hit_body( $plugin, $spend, $budget, $period, $mode );
		$ok      = Alerts::safe_wp_mail( $to, $subject, $body );
		if ( ! $ok ) {
			return;
		}

		self::record_fire( $plugin, $period, $budget );
		self::append_audit_row( $plugin, $spend, $budget, $period, $mode );
	}

	public static function build_hit_subject( string $plugin ): string {
		$site  = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
		$label = self::plugin_label( $plugin );

		return sprintf(
			/* translators: 1: site name, 2: plugin name */
			__( '[%1$s] HandL estimated budget reached: %2$s', 'handl-ai-connector-access-control' ),
			$site,
			$label
		);
	}

	public static function build_hit_body(
		string $plugin,
		float $spend,
		float $budget,
		string $period,
		string $mode
	): string {
		$lines   = array();
		$lines[] = __( 'HandL AI Connector Access Control estimated budget alert', 'handl-ai-connector-access-control' );
		$lines[] = '';
		$lines[] = sprintf(
			/* translators: %s: plugin display name or basename */
			__( 'Plugin: %s', 'handl-ai-connector-access-control' ),
			self::plugin_label( $plugin )
		);
		$lines[] = sprintf(
			/* translators: %s: budget USD amount */
			__( 'Estimated budget: $%s', 'handl-ai-connector-access-control' ),
			self::format_amount( $budget )
		);
		$lines[] = sprintf(
			/* translators: %s: current estimated spend USD */
			__( 'Current estimated spend: $%s', 'handl-ai-connector-access-control' ),
			self::format_amount( $spend )
		);
		$lines[] = sprintf(
			/* translators: %s: period id Y-m */
			__( 'Budget period: %s (calendar month)', 'handl-ai-connector-access-control' ),
			$period
		);
		if ( self::MODE_OBSERVE === $mode ) {
			$lines[] = __( 'Mode: Observe-only. New AI Client calls still run, and each is logged as estimated budget reached.', 'handl-ai-connector-access-control' );
		} else {
			$lines[] = __( 'Mode: Block. New AI Client calls from this plugin are blocked for the rest of the period.', 'handl-ai-connector-access-control' );
		}
		$lines[] = '';
		$lines[] = __( 'Amounts are estimates from logged token usage and your rates. They are not a bill.', 'handl-ai-connector-access-control' );
		$lines[] = '';
		$lines[] = __( 'Manage estimated budgets:', 'handl-ai-connector-access-control' );
		$lines[] = admin_url( 'options-general.php?page=handl-ai-connector-access-control&handl_aicac_tab=rules' );

		return implode( "\n", $lines ) . "\n";
	}

	public static function format_amount( float $amount ): string {
		if ( $amount > 0 && $amount < 0.01 ) {
			return '0.01';
		}

		return function_exists( 'number_format_i18n' )
			? number_format_i18n( $amount, 2 )
			: number_format( $amount, 2, '.', '' );
	}

	private static function plugin_label( string $basename ): string {
		if ( '' === $basename ) {
			return __( '(unknown plugin)', 'handl-ai-connector-access-control' );
		}
		if ( ! function_exists( 'get_plugins' ) ) {
			$plugin_php = ABSPATH . 'wp-admin/includes/plugin.php';
			if ( is_string( $plugin_php ) && is_readable( $plugin_php ) ) {
				require_once $plugin_php;
			}
		}
		if ( function_exists( 'get_plugins' ) ) {
			$plugins = get_plugins();
			if ( isset( $plugins[ $basename ]['Name'] ) && is_string( $plugins[ $basename ]['Name'] ) ) {
				return (string) $plugins[ $basename ]['Name'];
			}
		}

		return $basename;
	}

	private static function is_deduped( string $plugin, string $period, float $budget ): bool {
		$state = get_option( self::FIRED_OPTION_KEY, array() );
		if ( ! is_array( $state ) || ! isset( $state[ $plugin ] ) || ! is_array( $state[ $plugin ] ) ) {
			return false;
		}
		$row = $state[ $plugin ];
		$p   = isset( $row['period'] ) ? (string) $row['period'] : '';
		$th  = isset( $row['budget'] ) ? (float) $row['budget'] : 0.0;
		if ( $p !== $period ) {
			return false;
		}
		if ( abs( $th - $budget ) >= 0.0001 ) {
			return false;
		}

		return true;
	}

	private static function record_fire( string $plugin, string $period, float $budget ): void {
		$state = get_option( self::FIRED_OPTION_KEY, array() );
		if ( ! is_array( $state ) ) {
			$state = array();
		}
		$state[ $plugin ] = array(
			'period' => $period,
			'budget' => $budget,
			'at'     => time(),
		);
		update_option( self::FIRED_OPTION_KEY, $state, false );
	}

	private static function clear_fire_key( string $plugin ): void {
		$state = get_option( self::FIRED_OPTION_KEY, array() );
		if ( ! is_array( $state ) || ! isset( $state[ $plugin ] ) ) {
			return;
		}
		unset( $state[ $plugin ] );
		update_option( self::FIRED_OPTION_KEY, $state, false );
	}

	/**
	 * @param 'deny'|'observe' $mode
	 */
	private static function append_audit_row(
		string $plugin,
		float $spend,
		float $budget,
		string $period,
		string $mode
	): void {
		Policy::append_log_event(
			array(
				'ts'       => time(),
				'decision' => 'budget_alert',
				'channel'  => 'budget',
				'plugin'   => $plugin,
				'est_usd'  => $spend,
				'budget'   => $budget,
				'period'   => $period,
				'mode'     => $mode,
			)
		);
	}

	/**
	 * Record estimated-spend delta when a log row gains or increases tokens.
	 *
	 * @param array<string,mixed> $before Row before patch (may lack tokens).
	 * @param array<string,mixed> $after  Row after patch.
	 * @param array<string,mixed> $policy
	 */
	public static function maybe_record_from_row( array $before, array $after, array $policy ): void {
		$channel = isset( $after['channel'] ) ? (string) $after['channel'] : '';
		if ( in_array( $channel, array( 'direct_http', 'anomaly', 'spend_threshold', 'drift', 'alert_snooze', 'budget' ), true ) ) {
			return;
		}
		$plugin = isset( $after['plugin'] ) ? Plugin_Profile::sanitize_plugin( (string) $after['plugin'] ) : '';
		if ( '' === $plugin ) {
			return;
		}

		$before_usd = self::estimate_row_usd( $before, $policy );
		$after_usd  = self::estimate_row_usd( $after, $policy );
		if ( null === $after_usd ) {
			return;
		}
		$prior = null !== $before_usd ? $before_usd : 0.0;
		$delta = $after_usd - $prior;
		if ( $delta <= 0.0 ) {
			return;
		}

		$ts = isset( $after['ts'] ) ? (int) $after['ts'] : time();
		self::add_estimated_spend( $plugin, $delta, $ts );
	}

	/**
	 * @param array<string,mixed> $row
	 * @param array<string,mixed> $policy
	 */
	public static function estimate_row_usd( array $row, array $policy ): ?float {
		$has_in  = array_key_exists( 'input_tokens', $row );
		$has_out = array_key_exists( 'output_tokens', $row );
		if ( ! $has_in && ! $has_out ) {
			return null;
		}
		$in  = $has_in ? (int) $row['input_tokens'] : null;
		$out = $has_out ? (int) $row['output_tokens'] : null;
		$rates = Cost::rates_from_policy( $policy, isset( $row['provider'] ) ? (string) $row['provider'] : null );

		return Cost::estimate_usd( $in, $out, $rates );
	}
}
