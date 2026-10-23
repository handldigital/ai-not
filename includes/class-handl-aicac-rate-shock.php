<?php
/**
 * AICAC-RATE-SHOCK (#345): personal cost impact when rates-feed prices change.
 *
 * Observability only — never changes Allow/Deny or rewrites cost.php. Hooks the
 * rates-feed apply event, replays last-30-day usage at old vs new rates, and
 * delivers one Alerts email + admin notice when the site-specific delta clears
 * the materiality gate. Unused / sub-threshold changes still get an audit row.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Rates-feed personal impact alerts.
 */
final class Rate_Shock {

	public const SETTINGS_OPTION = 'handl_aicac_rate_shock';

	public const NOTICE_OPTION = 'handl_aicac_rate_shock_notice';

	public const PAGE_SLUG = 'handl-aicac-rate-shock';

	public const ACTION_SAVE = 'handl_aicac_rate_shock_save';

	public const POST_PRESENT = 'handl_aicac_rate_shock_present';

	public const POST_THRESHOLD_USD = 'handl_aicac_rate_shock_threshold_usd';

	public const POST_THRESHOLD_PCT = 'handl_aicac_rate_shock_threshold_pct';

	public const ACTION_DISMISS = 'handl_aicac_rate_shock_dismiss';

	/** Replay window in seconds (30 days). */
	public const WINDOW_SECONDS = 2592000;

	public const DEFAULT_THRESHOLD_USD = 1.0;

	public const DEFAULT_THRESHOLD_PCT = 5.0;

	/** @var bool */
	private static $registered = false;

	/** @var int|null */
	private static $test_now = null;

	/** @var list<array{to:string,subject:string,body:string}> */
	private static $test_mails = array();

	/** @var list<array<string,mixed>>|null Injected activity log for tests. */
	private static $test_log = null;

	public static function init(): void {
		if ( self::$registered ) {
			return;
		}
		self::$registered = true;

		add_action( Rates_Feed::ACTION_APPLIED, array( self::class, 'on_rates_applied' ), 10, 3 );
		add_action( 'admin_menu', array( self::class, 'register_menu' ), 20 );
		add_action( 'admin_post_' . self::ACTION_SAVE, array( self::class, 'handle_save' ) );
		add_action( 'admin_post_' . self::ACTION_DISMISS, array( self::class, 'handle_dismiss' ) );
		if ( function_exists( 'is_admin' ) && is_admin() ) {
			add_action( 'admin_notices', array( self::class, 'maybe_render_notice' ) );
		}
	}

	public static function reset_for_tests(): void {
		self::$registered = false;
		self::$test_now   = null;
		self::$test_mails = array();
		self::$test_log   = null;
		delete_option( self::SETTINGS_OPTION );
		delete_option( self::NOTICE_OPTION );
	}

	public static function set_test_now( ?int $now ): void {
		self::$test_now = $now;
	}

	/**
	 * @param list<array<string,mixed>>|null $log
	 */
	public static function set_test_log( ?array $log ): void {
		self::$test_log = $log;
	}

	/**
	 * @return list<array{to:string,subject:string,body:string}>
	 */
	public static function test_mails(): array {
		return self::$test_mails;
	}

	public static function now(): int {
		if ( null !== self::$test_now ) {
			return self::$test_now;
		}
		if ( class_exists( Clock::class, false ) ) {
			return Clock::now();
		}

		return time();
	}

	/**
	 * @return array{threshold_usd:float,threshold_pct:float}
	 */
	public static function defaults(): array {
		return array(
			'threshold_usd' => self::DEFAULT_THRESHOLD_USD,
			'threshold_pct' => self::DEFAULT_THRESHOLD_PCT,
		);
	}

	/**
	 * @return array{threshold_usd:float,threshold_pct:float}
	 */
	public static function get_settings(): array {
		return self::sanitize_settings( get_option( self::SETTINGS_OPTION, array() ) );
	}

	/**
	 * @param mixed $raw
	 * @return array{threshold_usd:float,threshold_pct:float}
	 */
	public static function sanitize_settings( $raw ): array {
		$defaults = self::defaults();
		if ( ! is_array( $raw ) ) {
			return $defaults;
		}
		$usd = isset( $raw['threshold_usd'] ) ? (float) $raw['threshold_usd'] : $defaults['threshold_usd'];
		$pct = isset( $raw['threshold_pct'] ) ? (float) $raw['threshold_pct'] : $defaults['threshold_pct'];
		if ( $usd < 0 ) {
			$usd = 0.0;
		}
		if ( $usd > 1000000 ) {
			$usd = 1000000.0;
		}
		if ( $pct < 0 ) {
			$pct = 0.0;
		}
		if ( $pct > 1000 ) {
			$pct = 1000.0;
		}

		return array(
			'threshold_usd' => round( $usd, 4 ),
			'threshold_pct' => round( $pct, 4 ),
		);
	}

	/**
	 * @param array<string,mixed> $settings
	 */
	public static function save_settings( array $settings ): bool {
		$clean  = self::sanitize_settings( $settings );
		$before = self::get_settings();
		if ( $clean === $before ) {
			return true;
		}
		if ( $clean === self::defaults() ) {
			delete_option( self::SETTINGS_OPTION );
		} else {
			update_option( self::SETTINGS_OPTION, $clean, false );
		}

		return true;
	}

	/**
	 * Rates-feed apply handler.
	 *
	 * @param array{version?:string,updated_at?:int,providers?:array<string,array{input_per_m:float,output_per_m:float}>} $before
	 * @param array{version?:string,updated_at?:int,providers?:array<string,array{input_per_m:float,output_per_m:float}>} $after
	 */
	public static function on_rates_applied( array $before, array $after, int $now ): void {
		$impact = self::compute_impact( $before, $after, $now );
		self::append_audit_row( $impact, $now );

		$material = array();
		foreach ( $impact['changes'] as $row ) {
			if ( ! empty( $row['material'] ) ) {
				$material[] = $row;
			}
		}

		if ( array() === $material ) {
			return;
		}

		$impact['changes'] = $material;
		self::deliver_alert( $impact, $now );
		self::store_notice( $impact, $now );
	}

	/**
	 * @param array{version?:string,updated_at?:int,providers?:array<string,array{input_per_m:float,output_per_m:float}>} $before
	 * @param array{version?:string,updated_at?:int,providers?:array<string,array{input_per_m:float,output_per_m:float}>} $after
	 * @return array{
	 *   version:string,
	 *   window_start:int,
	 *   window_end:int,
	 *   total_old:float,
	 *   total_new:float,
	 *   total_delta:float,
	 *   framing:string,
	 *   changes:list<array<string,mixed>>,
	 *   budget_warnings:list<array<string,mixed>>,
	 *   settings:array{threshold_usd:float,threshold_pct:float}
	 * }
	 */
	public static function compute_impact( array $before, array $after, ?int $now = null ): array {
		$now      = null !== $now ? $now : self::now();
		$settings = self::get_settings();
		$start    = max( 0, $now - self::WINDOW_SECONDS );
		$old_map  = isset( $before['providers'] ) && is_array( $before['providers'] )
			? Cost::sanitize_provider_rates( $before['providers'] )
			: array();
		$new_map  = isset( $after['providers'] ) && is_array( $after['providers'] )
			? Cost::sanitize_provider_rates( $after['providers'] )
			: array();
		$usage    = self::usage_by_provider( $start, $now );
		$ids      = array_unique( array_merge( array_keys( $old_map ), array_keys( $new_map ) ) );
		sort( $ids );

		$changes    = array();
		$total_old  = 0.0;
		$total_new  = 0.0;
		foreach ( $ids as $id ) {
			$old_rates = $old_map[ $id ] ?? null;
			$new_rates = $new_map[ $id ] ?? null;
			if ( null === $old_rates && null === $new_rates ) {
				continue;
			}
			$same = (
				null !== $old_rates
				&& null !== $new_rates
				&& abs( (float) $old_rates['input_per_m'] - (float) $new_rates['input_per_m'] ) < 0.00001
				&& abs( (float) $old_rates['output_per_m'] - (float) $new_rates['output_per_m'] ) < 0.00001
			);
			if ( $same ) {
				continue;
			}

			$vol     = $usage[ $id ] ?? array( 'input_tokens' => 0, 'output_tokens' => 0 );
			$in      = (int) $vol['input_tokens'];
			$out     = (int) $vol['output_tokens'];
			$used    = ( $in > 0 || $out > 0 );
			$cost_old = null !== $old_rates ? (float) ( Cost::estimate_usd( $in, $out, $old_rates ) ?? 0.0 ) : 0.0;
			$cost_new = null !== $new_rates ? (float) ( Cost::estimate_usd( $in, $out, $new_rates ) ?? 0.0 ) : 0.0;
			$delta    = $cost_new - $cost_old;
			$total_old += $cost_old;
			$total_new += $cost_new;

			$material = $used && self::is_material( $delta, $cost_old, $settings );

			$changes[] = array(
				'provider'      => $id,
				'old_input'     => null !== $old_rates ? (float) $old_rates['input_per_m'] : null,
				'old_output'    => null !== $old_rates ? (float) $old_rates['output_per_m'] : null,
				'new_input'     => null !== $new_rates ? (float) $new_rates['input_per_m'] : null,
				'new_output'    => null !== $new_rates ? (float) $new_rates['output_per_m'] : null,
				'input_tokens'  => $in,
				'output_tokens' => $out,
				'used'          => $used,
				'cost_old'      => $cost_old,
				'cost_new'      => $cost_new,
				'delta'         => $delta,
				'material'      => $material,
			);
		}

		$total_delta = $total_new - $total_old;
		$framing     = $total_delta < -0.00001 ? 'decrease' : ( $total_delta > 0.00001 ? 'increase' : 'flat' );

		return array(
			'version'         => sanitize_text_field( (string) ( $after['version'] ?? '' ) ),
			'window_start'    => $start,
			'window_end'      => $now,
			'total_old'       => $total_old,
			'total_new'       => $total_new,
			'total_delta'     => $total_delta,
			'framing'         => $framing,
			'changes'         => $changes,
			'budget_warnings' => self::budget_warnings( $new_map, $now ),
			'settings'        => $settings,
		);
	}

	/**
	 * @param array{threshold_usd:float,threshold_pct:float} $settings
	 */
	public static function is_material( float $delta, float $cost_old, array $settings ): bool {
		$abs = abs( $delta );
		if ( $abs < 0.0000001 ) {
			return false;
		}
		$usd = (float) $settings['threshold_usd'];
		$pct = (float) $settings['threshold_pct'];
		if ( $abs + 0.0000001 >= $usd ) {
			return true;
		}
		$base = abs( $cost_old );
		if ( $base < 0.0000001 ) {
			return false;
		}

		return ( ( $abs / $base ) * 100.0 ) + 0.0000001 >= $pct;
	}

	/**
	 * @return array<string,array{input_tokens:int,output_tokens:int}>
	 */
	public static function usage_by_provider( int $start_ts, int $end_ts ): array {
		$log = null !== self::$test_log ? self::$test_log : Policy::get_retained_log();
		$out = array();
		foreach ( $log as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$channel = isset( $row['channel'] ) ? (string) $row['channel'] : '';
			if ( in_array( $channel, array( 'direct_http', 'spend_threshold', 'drift', 'budget', 'rate_shock' ), true ) ) {
				continue;
			}
			$ts = isset( $row['ts'] ) ? (int) $row['ts'] : 0;
			if ( $ts < $start_ts || $ts >= $end_ts ) {
				continue;
			}
			$in  = array_key_exists( 'input_tokens', $row ) ? (int) $row['input_tokens'] : null;
			$tok = array_key_exists( 'output_tokens', $row ) ? (int) $row['output_tokens'] : null;
			if ( null === $in && null === $tok ) {
				continue;
			}
			$id = Cost::normalize_provider_id( (string) ( $row['provider'] ?? '' ) );
			if ( '' === $id || ! Cost::is_known_provider( $id ) ) {
				continue;
			}
			if ( ! isset( $out[ $id ] ) ) {
				$out[ $id ] = array(
					'input_tokens'  => 0,
					'output_tokens' => 0,
				);
			}
			$out[ $id ]['input_tokens']  += max( 0, (int) ( $in ?? 0 ) );
			$out[ $id ]['output_tokens'] += max( 0, (int) ( $tok ?? 0 ) );
		}

		return $out;
	}

	/**
	 * Projected-over-cap warnings for plugins with a budget when current-period
	 * activity replayed at the new feed rates would cross the cap.
	 *
	 * @param array<string,array{input_per_m:float,output_per_m:float}> $new_map
	 * @return list<array{plugin:string,budget:float,projected:float,period:string}>
	 */
	public static function budget_warnings( array $new_map, ?int $now = null ): array {
		if ( ! class_exists( Budget::class, false ) ) {
			return array();
		}
		$now    = null !== $now ? $now : self::now();
		$policy = Policy::get_policy();
		$budgets = Budget::sanitize_plugin_budgets( $policy['plugin_budgets'] ?? array() );
		if ( empty( $budgets ) ) {
			return array();
		}

		$period = Budget::period_id( $now );
		// Calendar month start ≈ first day 00:00 UTC of period id Y-m.
		$month_start = (int) strtotime( $period . '-01 00:00:00 UTC' );
		if ( $month_start <= 0 ) {
			$month_start = max( 0, $now - self::WINDOW_SECONDS );
		}

		$log      = null !== self::$test_log ? self::$test_log : Policy::get_retained_log();
		$by_plugin = array();
		foreach ( $log as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$ts = isset( $row['ts'] ) ? (int) $row['ts'] : 0;
			if ( $ts < $month_start || $ts > $now ) {
				continue;
			}
			$plugin = isset( $row['plugin'] ) ? (string) $row['plugin'] : '';
			if ( '' === $plugin || ! isset( $budgets[ $plugin ] ) ) {
				continue;
			}
			$in  = array_key_exists( 'input_tokens', $row ) ? (int) $row['input_tokens'] : null;
			$tok = array_key_exists( 'output_tokens', $row ) ? (int) $row['output_tokens'] : null;
			if ( null === $in && null === $tok ) {
				continue;
			}
			$id    = Cost::normalize_provider_id( (string) ( $row['provider'] ?? '' ) );
			$rates = isset( $new_map[ $id ] ) ? $new_map[ $id ] : Cost::rates_from_policy( $policy, $id );
			$usd   = Cost::estimate_usd( $in, $tok, $rates );
			if ( null === $usd ) {
				continue;
			}
			if ( ! isset( $by_plugin[ $plugin ] ) ) {
				$by_plugin[ $plugin ] = 0.0;
			}
			$by_plugin[ $plugin ] += (float) $usd;
		}

		$warnings = array();
		foreach ( $budgets as $plugin => $budget ) {
			$projected = (float) ( $by_plugin[ $plugin ] ?? 0.0 );
			$current   = Budget::period_spend( $plugin, $period );
			// Cap exists and new-rate projection crosses it; skip if already over under prior spend
			// and the new projection did not increase the overrun.
			if ( $projected + 0.00001 < (float) $budget ) {
				continue;
			}
			if ( $current + 0.00001 >= (float) $budget && $projected <= $current + 0.00001 ) {
				continue;
			}
			$warnings[] = array(
				'plugin'    => $plugin,
				'budget'    => (float) $budget,
				'projected' => $projected,
				'period'    => $period,
			);
		}

		return $warnings;
	}

	/**
	 * @param array<string,mixed> $impact
	 */
	public static function append_audit_row( array $impact, ?int $now = null ): void {
		$now   = null !== $now ? $now : self::now();
		$event = array(
			'ts'             => $now,
			'decision'       => 'rate_shock',
			'channel'        => 'rate_shock',
			'feed_version'   => (string) ( $impact['version'] ?? '' ),
			'total_old'      => (float) ( $impact['total_old'] ?? 0.0 ),
			'total_new'      => (float) ( $impact['total_new'] ?? 0.0 ),
			'total_delta'    => (float) ( $impact['total_delta'] ?? 0.0 ),
			'framing'        => (string) ( $impact['framing'] ?? 'flat' ),
			'change_count'   => is_array( $impact['changes'] ?? null ) ? count( $impact['changes'] ) : 0,
			'material_count' => 0,
		);
		if ( is_array( $impact['changes'] ?? null ) ) {
			$n = 0;
			foreach ( $impact['changes'] as $row ) {
				if ( ! empty( $row['material'] ) ) {
					++$n;
				}
			}
			$event['material_count'] = $n;
		}
		Policy::append_log_event( $event );
	}

	/**
	 * @param array<string,mixed> $impact
	 */
	public static function deliver_alert( array $impact, ?int $now = null ): void {
		unset( $now );
		$policy = Policy::get_policy();
		$to     = Alerts::resolve_email( $policy );
		if ( '' === $to ) {
			return;
		}
		$subject = self::build_subject( $impact );
		$body    = self::build_body( $impact );
		$ok      = Alerts::safe_wp_mail( $to, $subject, $body );
		self::$test_mails[] = array(
			'to'      => $to,
			'subject' => $subject,
			'body'    => $body,
			'ok'      => $ok,
		);
	}

	/**
	 * @param array<string,mixed> $impact
	 */
	public static function build_subject( array $impact ): string {
		$site    = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
		$delta   = (float) ( $impact['total_delta'] ?? 0.0 );
		$framing = (string) ( $impact['framing'] ?? 'flat' );
		if ( 'decrease' === $framing ) {
			return sprintf(
				/* translators: 1: site name, 2: absolute USD savings */
				__( '[%1$s] Provider rates dropped — about $%2$s/mo cheaper for your recent AI use', 'handl-ai-connector-access-control' ),
				$site,
				self::format_amount( abs( $delta ) )
			);
		}

		return sprintf(
			/* translators: 1: site name, 2: absolute USD increase */
			__( '[%1$s] Provider rates changed — about $%2$s/mo more for your recent AI use', 'handl-ai-connector-access-control' ),
			$site,
			self::format_amount( abs( $delta ) )
		);
	}

	/**
	 * @param array<string,mixed> $impact
	 */
	public static function build_body( array $impact ): string {
		$lines   = array();
		$framing = (string) ( $impact['framing'] ?? 'flat' );
		if ( 'decrease' === $framing ) {
			$lines[] = __( 'Good news: a signed rates-feed update lowered prices for models you actually used.', 'handl-ai-connector-access-control' );
		} else {
			$lines[] = __( 'A signed rates-feed update changed prices for models you used in the last 30 days.', 'handl-ai-connector-access-control' );
		}
		$lines[] = '';
		$lines[] = sprintf(
			/* translators: %s: feed version */
			__( 'Feed version: %s', 'handl-ai-connector-access-control' ),
			(string) ( $impact['version'] ?? '' )
		);
		$lines[] = sprintf(
			/* translators: 1: old USD total, 2: new USD total, 3: signed delta */
			__( 'Your last-30-day usage at old rates $%1$s → new rates $%2$s (delta $%3$s).', 'handl-ai-connector-access-control' ),
			self::format_amount( (float) ( $impact['total_old'] ?? 0.0 ) ),
			self::format_amount( (float) ( $impact['total_new'] ?? 0.0 ) ),
			self::format_signed( (float) ( $impact['total_delta'] ?? 0.0 ) )
		);
		$lines[] = '';
		$lines[] = __( 'Per-provider changes:', 'handl-ai-connector-access-control' );
		foreach ( (array) ( $impact['changes'] ?? array() ) as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$lines[] = sprintf(
				/* translators: 1: provider id, 2: old in/out, 3: new in/out, 4: delta USD */
				__( '- %1$s: $%2$s/$%3$s per 1M in/out → $%4$s/$%5$s (your delta $%6$s)', 'handl-ai-connector-access-control' ),
				(string) ( $row['provider'] ?? '' ),
				self::format_amount( (float) ( $row['old_input'] ?? 0.0 ) ),
				self::format_amount( (float) ( $row['old_output'] ?? 0.0 ) ),
				self::format_amount( (float) ( $row['new_input'] ?? 0.0 ) ),
				self::format_amount( (float) ( $row['new_output'] ?? 0.0 ) ),
				self::format_signed( (float) ( $row['delta'] ?? 0.0 ) )
			);
		}

		$warnings = (array) ( $impact['budget_warnings'] ?? array() );
		if ( array() !== $warnings ) {
			$lines[] = '';
			$lines[] = __( 'Budget early warning — projected spend at the new rates crosses a configured cap:', 'handl-ai-connector-access-control' );
			foreach ( $warnings as $w ) {
				if ( ! is_array( $w ) ) {
					continue;
				}
				$lines[] = sprintf(
					/* translators: 1: plugin, 2: projected USD, 3: budget USD, 4: period */
					__( '- %1$s: projected $%2$s vs budget $%3$s (period %4$s)', 'handl-ai-connector-access-control' ),
					(string) ( $w['plugin'] ?? '' ),
					self::format_amount( (float) ( $w['projected'] ?? 0.0 ) ),
					self::format_amount( (float) ( $w['budget'] ?? 0.0 ) ),
					(string) ( $w['period'] ?? '' )
				);
			}
		}

		$lines[] = '';
		$lines[] = __( 'Estimates only — not a bill. Allow/Deny rules are unchanged.', 'handl-ai-connector-access-control' );
		if ( class_exists( Admin::class, false ) ) {
			$lines[] = '';
			$lines[] = __( 'Activity:', 'handl-ai-connector-access-control' );
			$lines[] = Admin::screen_url( 'activity' );
		}

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

	public static function format_signed( float $amount ): string {
		$sign = $amount < -0.00001 ? '-' : ( $amount > 0.00001 ? '+' : '' );

		return $sign . self::format_amount( abs( $amount ) );
	}

	/**
	 * @param array<string,mixed> $impact
	 */
	public static function store_notice( array $impact, ?int $now = null ): void {
		$now = null !== $now ? $now : self::now();
		update_option(
			self::NOTICE_OPTION,
			array(
				'ts'      => $now,
				'version' => (string) ( $impact['version'] ?? '' ),
				'framing' => (string) ( $impact['framing'] ?? 'flat' ),
				'delta'   => (float) ( $impact['total_delta'] ?? 0.0 ),
				'subject' => self::build_subject( $impact ),
			),
			false
		);
	}

	public static function maybe_render_notice(): void {
		if ( ! Caps::user_can_view() ) {
			return;
		}
		$notice = get_option( self::NOTICE_OPTION, null );
		if ( ! is_array( $notice ) || empty( $notice['subject'] ) ) {
			return;
		}
		$framing = (string) ( $notice['framing'] ?? 'flat' );
		$class   = 'decrease' === $framing ? 'notice notice-success' : 'notice notice-warning';
		$url     = wp_nonce_url(
			admin_url( 'admin-post.php?action=' . self::ACTION_DISMISS ),
			self::ACTION_DISMISS
		);
		echo '<div class="' . esc_attr( $class ) . ' is-dismissible"><p>';
		echo esc_html( (string) $notice['subject'] );
		echo ' <a href="' . esc_url( $url ) . '">' . esc_html__( 'Dismiss', 'handl-ai-connector-access-control' ) . '</a>';
		echo '</p></div>';
	}

	public static function handle_dismiss(): void {
		if ( ! Caps::user_can_view() ) {
			wp_die( esc_html__( 'You do not have permission to dismiss this notice.', 'handl-ai-connector-access-control' ) );
		}
		check_admin_referer( self::ACTION_DISMISS );
		delete_option( self::NOTICE_OPTION );
		wp_safe_redirect( admin_url( 'admin.php?page=' . self::PAGE_SLUG ) );
		exit;
	}

	public static function register_menu(): void {
		if ( ! Caps::user_can_view() ) {
			return;
		}
		if ( ! function_exists( 'add_submenu_page' ) || ! class_exists( Admin::class, false ) ) {
			return;
		}
		add_submenu_page(
			Admin::MENU_SLUG,
			__( 'Rate shock', 'handl-ai-connector-access-control' ),
			__( 'Rate shock', 'handl-ai-connector-access-control' ),
			Caps::VIEW,
			self::PAGE_SLUG,
			array( self::class, 'render_page' )
		);
	}

	public static function handle_save(): void {
		if ( ! Caps::user_can_manage() ) {
			wp_die( esc_html__( 'You do not have permission to save rate-shock settings.', 'handl-ai-connector-access-control' ) );
		}
		check_admin_referer( self::ACTION_SAVE );
		if ( empty( $_POST[ self::POST_PRESENT ] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing
			wp_die( esc_html__( 'Invalid form', 'handl-ai-connector-access-control' ) );
		}
		self::save_settings(
			array(
				'threshold_usd' => isset( $_POST[ self::POST_THRESHOLD_USD ] ) ? wp_unslash( (string) $_POST[ self::POST_THRESHOLD_USD ] ) : self::DEFAULT_THRESHOLD_USD, // phpcs:ignore WordPress.Security.NonceVerification.Missing,WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
				'threshold_pct' => isset( $_POST[ self::POST_THRESHOLD_PCT ] ) ? wp_unslash( (string) $_POST[ self::POST_THRESHOLD_PCT ] ) : self::DEFAULT_THRESHOLD_PCT, // phpcs:ignore WordPress.Security.NonceVerification.Missing,WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
			)
		);
		wp_safe_redirect( admin_url( 'admin.php?page=' . self::PAGE_SLUG ) );
		exit;
	}

	public static function render_page(): void {
		if ( ! Caps::user_can_view() ) {
			return;
		}
		$settings   = self::get_settings();
		$can_manage = Caps::user_can_manage();

		echo '<div class="wrap">';
		echo '<h1>' . esc_html__( 'Rate shock', 'handl-ai-connector-access-control' ) . '</h1>';
		echo '<p>' . esc_html__( 'When a signed rates-feed update changes prices for models this site used in the last 30 days, AI Not emails the personal cost impact. Unused models and tiny deltas still get an Activity row, but no alert.', 'handl-ai-connector-access-control' ) . '</p>';

		if ( $can_manage ) {
			echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
			echo '<input type="hidden" name="action" value="' . esc_attr( self::ACTION_SAVE ) . '" />';
			echo '<input type="hidden" name="' . esc_attr( self::POST_PRESENT ) . '" value="1" />';
			wp_nonce_field( self::ACTION_SAVE );
			echo '<table class="form-table" role="presentation"><tbody>';
			echo '<tr><th scope="row"><label for="' . esc_attr( self::POST_THRESHOLD_USD ) . '">' . esc_html__( 'Dollar threshold', 'handl-ai-connector-access-control' ) . '</label></th><td>';
			echo '<input name="' . esc_attr( self::POST_THRESHOLD_USD ) . '" id="' . esc_attr( self::POST_THRESHOLD_USD ) . '" type="number" min="0" step="0.01" value="' . esc_attr( (string) $settings['threshold_usd'] ) . '" class="small-text" />';
			echo '<p class="description">' . esc_html__( 'Alert when the absolute monthly impact is at least this many dollars (default 1).', 'handl-ai-connector-access-control' ) . '</p>';
			echo '</td></tr>';
			echo '<tr><th scope="row"><label for="' . esc_attr( self::POST_THRESHOLD_PCT ) . '">' . esc_html__( 'Percent threshold', 'handl-ai-connector-access-control' ) . '</label></th><td>';
			echo '<input name="' . esc_attr( self::POST_THRESHOLD_PCT ) . '" id="' . esc_attr( self::POST_THRESHOLD_PCT ) . '" type="number" min="0" step="0.1" value="' . esc_attr( (string) $settings['threshold_pct'] ) . '" class="small-text" />';
			echo '<p class="description">' . esc_html__( 'Or when the absolute impact is at least this percent of the prior estimate (default 5).', 'handl-ai-connector-access-control' ) . '</p>';
			echo '</td></tr></tbody></table>';
			submit_button( __( 'Save changes', 'handl-ai-connector-access-control' ) );
			echo '</form>';
		}

		echo '</div>';
	}
}
