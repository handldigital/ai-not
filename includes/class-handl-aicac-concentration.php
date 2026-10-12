<?php
/**
 * AICAC-CONCENTRATION (#393): provider concentration risk.
 *
 * Per-provider share of 30/90-day calls and estimated spend, read-only from the
 * activity log (Cost helpers class_exists-guarded). HHI-style index, divorce
 * roster (plugins with no observed alternate provider), one alert per
 * provider+window on the 80% share crossing (own _alerted ledger). Print + CSV
 * + WP-CLI concentration status|export (status non-zero above threshold).
 * Informational only — never denies. OFF by default. Own two options. No
 * admin.php/policy.php/cost.php/logger/rates-feed/register edits.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Provider concentration risk from logged traffic.
 */
final class Concentration {

	public const SETTINGS_OPTION = 'handl_aicac_concentration';

	public const ALERTED_OPTION = 'handl_aicac_concentration_alerted';

	public const PAGE_SLUG = 'handl-aicac-concentration';

	public const FILTER_THRESHOLD = 'handl_aicac_concentration_threshold';

	public const ALERT_KIND = 'concentration';

	public const DEFAULT_THRESHOLD = 0.80;

	/** @var list<int> */
	public const WINDOWS = array( 30, 90 );

	public const UNKNOWN_PLUGIN = '(unknown)';

	public const UNKNOWN_PROVIDER = '(unknown)';

	public const POST_PRESENT = 'handl_aicac_concentration_present';

	public const POST_ENABLED = 'handl_aicac_concentration_enabled';

	public const POST_THRESHOLD = 'handl_aicac_concentration_threshold_pct';

	public const ACTION_SAVE = 'handl_aicac_concentration_save';

	/** @var bool */
	private static $registered = false;

	/** @var list<array<string,mixed>> */
	private static $test_mails = array();

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
		self::$registered = false;
		self::$test_mails = array();
		delete_option( self::SETTINGS_OPTION );
		delete_option( self::ALERTED_OPTION );
	}

	/**
	 * @return list<array<string,mixed>>
	 */
	public static function test_mails(): array {
		return self::$test_mails;
	}

	/**
	 * @return array{enabled:bool,threshold:float}
	 */
	public static function defaults(): array {
		return array(
			'enabled'   => false,
			'threshold' => self::DEFAULT_THRESHOLD,
		);
	}

	/**
	 * @return array{enabled:bool,threshold:float}
	 */
	public static function get_settings(): array {
		return self::sanitize_settings( get_option( self::SETTINGS_OPTION, array() ) );
	}

	/**
	 * @param mixed $raw Raw settings.
	 * @return array{enabled:bool,threshold:float}
	 */
	public static function sanitize_settings( $raw ): array {
		$defaults = self::defaults();
		if ( ! is_array( $raw ) ) {
			return $defaults;
		}

		return array(
			'enabled'   => ! empty( $raw['enabled'] ),
			'threshold' => self::sanitize_threshold( $raw['threshold'] ?? $defaults['threshold'] ),
		);
	}

	/**
	 * @param mixed $raw Raw threshold (0–1 fraction or 1–100 percent).
	 */
	public static function sanitize_threshold( $raw ): float {
		if ( ! is_numeric( $raw ) ) {
			return self::DEFAULT_THRESHOLD;
		}
		$v = (float) $raw;
		if ( ! is_finite( $v ) ) {
			return self::DEFAULT_THRESHOLD;
		}
		// Accept whole-percent form (e.g. 80) from the settings UI.
		if ( $v > 1.0 ) {
			$v = $v / 100.0;
		}
		if ( $v < 0.01 ) {
			$v = 0.01;
		}
		if ( $v > 0.99 ) {
			$v = 0.99;
		}

		return round( $v, 4 );
	}

	/**
	 * Effective threshold after filter.
	 */
	public static function threshold(): float {
		$settings = self::get_settings();
		$base     = (float) $settings['threshold'];
		if ( function_exists( 'apply_filters' ) ) {
			$filtered = apply_filters( self::FILTER_THRESHOLD, $base );
			return self::sanitize_threshold( $filtered );
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

	public static function sanitize_plugin( string $raw ): string {
		$raw = trim( $raw );
		if ( '' === $raw ) {
			return self::UNKNOWN_PLUGIN;
		}
		$raw = preg_replace( '/[\r\n\t]+/', ' ', $raw ) ?? $raw;
		if ( function_exists( 'mb_substr' ) ) {
			$raw = mb_substr( $raw, 0, 190 );
		} else {
			$raw = substr( $raw, 0, 190 );
		}

		return '' !== $raw ? $raw : self::UNKNOWN_PLUGIN;
	}

	public static function sanitize_provider( string $raw ): string {
		if ( class_exists( Cost::class, false ) ) {
			$id = Cost::normalize_provider_id( $raw );
			if ( '' !== $id ) {
				return $id;
			}
		}
		$raw = strtolower( trim( $raw ) );
		$raw = preg_replace( '/[^a-z0-9_-]/', '', $raw ) ?? '';

		return '' !== $raw ? $raw : self::UNKNOWN_PROVIDER;
	}

	/**
	 * @return list<array<string,mixed>>
	 */
	public static function load_log( ?array $log = null ): array {
		if ( null === $log ) {
			$log = class_exists( Policy::class, false ) ? Policy::get_retained_log() : array();
		}
		if ( ! is_array( $log ) ) {
			return array();
		}
		if ( class_exists( Demo_Mode::class, false ) ) {
			$log = Demo_Mode::without_demo( $log );
		}
		$out = array();
		foreach ( $log as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			if ( class_exists( Selftest::class, false ) && Selftest::is_synthetic_row( $row ) ) {
				continue;
			}
			if ( class_exists( Usage_Trends::class, false ) && ! Usage_Trends::is_activity_row( $row ) ) {
				continue;
			}
			$out[] = $row;
		}

		return $out;
	}

	/**
	 * Estimated USD for a log row when Cost is available; otherwise 0.
	 *
	 * @param array<string,mixed> $row    Log row.
	 * @param array<string,mixed> $policy Policy (for rates).
	 */
	public static function row_spend_usd( array $row, array $policy ): float {
		if ( ! class_exists( Cost::class, false ) ) {
			return 0.0;
		}
		$has_in  = array_key_exists( 'input_tokens', $row );
		$has_out = array_key_exists( 'output_tokens', $row );
		if ( ! $has_in && ! $has_out ) {
			return 0.0;
		}
		$in    = $has_in ? max( 0, (int) $row['input_tokens'] ) : null;
		$out   = $has_out ? max( 0, (int) $row['output_tokens'] ) : null;
		$count = isset( $row['count'] ) ? max( 1, (int) $row['count'] ) : 1;
		$rates = Cost::rates_from_policy( $policy, isset( $row['provider'] ) ? (string) $row['provider'] : null );
		$usd   = Cost::estimate_usd( $in, $out, $rates );
		if ( null === $usd ) {
			return 0.0;
		}

		return (float) $usd * $count;
	}

	/**
	 * Aggregate one window from the live log.
	 *
	 * @param list<array<string,mixed>>|null $log Optional log.
	 * @return array{
	 *   window:int,
	 *   total_calls:int,
	 *   total_spend:float,
	 *   top_provider:string,
	 *   top_calls_share:float,
	 *   top_spend_share:float,
	 *   hhi_calls:float,
	 *   hhi_spend:float,
	 *   above_threshold:bool,
	 *   providers:list<array<string,mixed>>,
	 *   divorce:list<array<string,mixed>>,
	 *   framing:string
	 * }
	 */
	public static function analyze_window( int $window_days, ?array $log = null, ?int $now = null, ?array $policy = null ): array {
		$window_days = in_array( $window_days, self::WINDOWS, true ) ? $window_days : 30;
		$now         = null !== $now && $now > 0 ? $now : ( class_exists( Clock::class, false ) ? Clock::now() : time() );
		$day         = defined( 'DAY_IN_SECONDS' ) ? (int) DAY_IN_SECONDS : 86400;
		$cut         = $now - ( ( $window_days - 1 ) * $day );
		$log         = self::load_log( $log );
		if ( null === $policy ) {
			$policy = class_exists( Policy::class, false ) ? Policy::get_policy() : array();
		}
		if ( ! is_array( $policy ) ) {
			$policy = array();
		}

		$by_provider = array();
		$by_plugin   = array();

		foreach ( $log as $row ) {
			$ts = isset( $row['ts'] ) ? (int) $row['ts'] : 0;
			if ( $ts <= 0 ) {
				$ts = $now;
			}
			if ( $ts < $cut ) {
				continue;
			}
			$provider = self::sanitize_provider( (string) ( $row['provider'] ?? '' ) );
			$plugin   = self::sanitize_plugin( (string) ( $row['plugin'] ?? '' ) );
			$count    = isset( $row['count'] ) ? max( 1, (int) $row['count'] ) : 1;
			$spend    = self::row_spend_usd( $row, $policy );

			if ( ! isset( $by_provider[ $provider ] ) ) {
				$by_provider[ $provider ] = array(
					'provider' => $provider,
					'calls'    => 0,
					'spend'    => 0.0,
				);
			}
			$by_provider[ $provider ]['calls'] += $count;
			$by_provider[ $provider ]['spend'] += $spend;

			if ( ! isset( $by_plugin[ $plugin ] ) ) {
				$by_plugin[ $plugin ] = array();
			}
			if ( ! isset( $by_plugin[ $plugin ][ $provider ] ) ) {
				$by_plugin[ $plugin ][ $provider ] = 0;
			}
			$by_plugin[ $plugin ][ $provider ] += $count;
		}

		$total_calls = 0;
		$total_spend = 0.0;
		foreach ( $by_provider as $cell ) {
			$total_calls += (int) $cell['calls'];
			$total_spend += (float) $cell['spend'];
		}

		$providers = array();
		$hhi_calls = 0.0;
		$hhi_spend = 0.0;
		foreach ( $by_provider as $cell ) {
			$calls_share = $total_calls > 0 ? ( (int) $cell['calls'] / $total_calls ) : 0.0;
			$spend_share = $total_spend > 0.0 ? ( (float) $cell['spend'] / $total_spend ) : 0.0;
			$hhi_calls  += $calls_share * $calls_share;
			$hhi_spend  += $spend_share * $spend_share;
			$providers[] = array(
				'provider'    => (string) $cell['provider'],
				'calls'       => (int) $cell['calls'],
				'spend'       => (float) $cell['spend'],
				'calls_share' => $calls_share,
				'spend_share' => $spend_share,
			);
		}
		usort(
			$providers,
			static function ( array $a, array $b ): int {
				if ( (int) $a['calls'] === (int) $b['calls'] ) {
					return ( (float) $b['spend'] <=> (float) $a['spend'] );
				}

				return ( (int) $b['calls'] <=> (int) $a['calls'] );
			}
		);

		$top_provider    = ! empty( $providers ) ? (string) $providers[0]['provider'] : '';
		$top_calls_share = ! empty( $providers ) ? (float) $providers[0]['calls_share'] : 0.0;
		$top_spend_share = ! empty( $providers ) ? (float) $providers[0]['spend_share'] : 0.0;
		$threshold       = self::threshold();
		$above           = $top_calls_share >= $threshold || $top_spend_share >= $threshold;

		$divorce = array();
		foreach ( $by_plugin as $plugin => $prov_map ) {
			$observed = array_keys( $prov_map );
			if ( count( $observed ) !== 1 ) {
				continue;
			}
			$only = (string) $observed[0];
			$divorce[] = array(
				'plugin'   => (string) $plugin,
				'provider' => $only,
				'calls'    => (int) $prov_map[ $only ],
			);
		}
		usort(
			$divorce,
			static function ( array $a, array $b ): int {
				if ( (int) $a['calls'] === (int) $b['calls'] ) {
					return strcmp( (string) $a['plugin'], (string) $b['plugin'] );
				}

				return ( (int) $b['calls'] <=> (int) $a['calls'] );
			}
		);

		return array(
			'window'          => $window_days,
			'total_calls'     => $total_calls,
			'total_spend'     => $total_spend,
			'top_provider'    => $top_provider,
			'top_calls_share' => $top_calls_share,
			'top_spend_share' => $top_spend_share,
			'hhi_calls'       => $hhi_calls,
			'hhi_spend'       => $hhi_spend,
			'above_threshold' => $above,
			'providers'       => $providers,
			'divorce'         => $divorce,
			'framing'         => 'estimate_from_logged_traffic_not_a_bill',
		);
	}

	/**
	 * Full snapshot for 30d + 90d.
	 *
	 * @param list<array<string,mixed>>|null $log Optional log.
	 * @return array{windows:array<int,array<string,mixed>>,threshold:float,framing:string}
	 */
	public static function snapshot( ?array $log = null, ?int $now = null, ?array $policy = null ): array {
		$log = self::load_log( $log );
		if ( null === $policy ) {
			$policy = class_exists( Policy::class, false ) ? Policy::get_policy() : array();
		}
		$windows = array();
		foreach ( self::WINDOWS as $days ) {
			$windows[ $days ] = self::analyze_window( $days, $log, $now, $policy );
		}

		return array(
			'windows'   => $windows,
			'threshold' => self::threshold(),
			'framing'   => 'estimate_from_logged_traffic_not_a_bill',
		);
	}

	/**
	 * Flattened provider roster rows (one per provider per window) for CSV/UI.
	 *
	 * @return list<array<string,mixed>>
	 */
	public static function provider_roster( ?array $log = null, ?int $now = null ): array {
		$snap = self::snapshot( $log, $now );
		$rows = array();
		foreach ( $snap['windows'] as $window => $analysis ) {
			foreach ( (array) ( $analysis['providers'] ?? array() ) as $cell ) {
				$rows[] = array(
					'window'          => (int) $window,
					'provider'        => (string) ( $cell['provider'] ?? '' ),
					'calls'           => (int) ( $cell['calls'] ?? 0 ),
					'spend'           => (float) ( $cell['spend'] ?? 0 ),
					'calls_share'     => (float) ( $cell['calls_share'] ?? 0 ),
					'spend_share'     => (float) ( $cell['spend_share'] ?? 0 ),
					'top_provider'    => (string) ( $analysis['top_provider'] ?? '' ),
					'top_calls_share' => (float) ( $analysis['top_calls_share'] ?? 0 ),
					'top_spend_share' => (float) ( $analysis['top_spend_share'] ?? 0 ),
					'hhi_calls'       => (float) ( $analysis['hhi_calls'] ?? 0 ),
					'hhi_spend'       => (float) ( $analysis['hhi_spend'] ?? 0 ),
					'above_threshold' => ! empty( $analysis['above_threshold'] ),
					'framing'         => 'estimate_from_logged_traffic_not_a_bill',
				);
			}
		}

		return $rows;
	}

	/**
	 * Plugins with exactly one observed provider in the 30-day window (default).
	 *
	 * @return list<array<string,mixed>>
	 */
	public static function divorce_roster( int $window_days = 30, ?array $log = null, ?int $now = null ): array {
		$analysis = self::analyze_window( $window_days, $log, $now );

		return array_values( (array) ( $analysis['divorce'] ?? array() ) );
	}

	public static function format_share( float $share ): string {
		return sprintf( '%.1f%%', $share * 100.0 );
	}

	public static function format_usd( float $amount ): string {
		if ( class_exists( Cost::class, false ) && method_exists( Cost::class, 'format_usd' ) ) {
			return Cost::format_usd( $amount );
		}
		if ( $amount > 0 && $amount < 0.01 ) {
			return '<$0.01';
		}

		return '$' . number_format( $amount, 2, '.', ',' );
	}

	public static function format_hhi( float $hhi ): string {
		return number_format( $hhi * 10000.0, 0, '.', ',' );
	}

	/**
	 * @return array<string,bool>
	 */
	public static function get_alerted(): array {
		$raw = get_option( self::ALERTED_OPTION, array() );
		if ( ! is_array( $raw ) ) {
			return array();
		}
		$out = array();
		foreach ( $raw as $fp => $flag ) {
			$fp = self::sanitize_fingerprint( (string) $fp );
			if ( '' === $fp || empty( $flag ) ) {
				continue;
			}
			$out[ $fp ] = true;
		}

		return $out;
	}

	/**
	 * @param array<string,bool> $alerted Fingerprints.
	 */
	public static function put_alerted( array $alerted ): void {
		$clean = array();
		foreach ( $alerted as $fp => $flag ) {
			$fp = self::sanitize_fingerprint( (string) $fp );
			if ( '' === $fp || empty( $flag ) ) {
				continue;
			}
			$clean[ $fp ] = true;
		}
		if ( empty( $clean ) ) {
			delete_option( self::ALERTED_OPTION );

			return;
		}
		update_option( self::ALERTED_OPTION, $clean, false );
	}

	public static function sanitize_fingerprint( string $raw ): string {
		$raw = strtolower( trim( $raw ) );
		$raw = preg_replace( '/[^a-z0-9_|-]/', '', $raw ) ?? '';

		return substr( $raw, 0, 120 );
	}

	public static function alert_fingerprint( string $provider, int $window ): string {
		return self::sanitize_fingerprint( self::sanitize_provider( $provider ) . '|' . (string) (int) $window );
	}

	/**
	 * Fire at most one alert per provider+window when share crosses threshold.
	 *
	 * @param list<array<string,mixed>>|null $log Optional log.
	 * @return list<string> Fingerprints newly alerted.
	 */
	public static function maybe_fire_alerts( ?array $log = null, ?array $policy = null, ?int $now = null ): array {
		if ( ! self::is_enabled() ) {
			return array();
		}
		$now       = null !== $now && $now > 0 ? $now : ( class_exists( Clock::class, false ) ? Clock::now() : time() );
		$threshold = self::threshold();
		$snap      = self::snapshot( $log, $now, $policy );
		$alerted   = self::get_alerted();
		$fired     = array();

		foreach ( $snap['windows'] as $window => $analysis ) {
			foreach ( (array) ( $analysis['providers'] ?? array() ) as $cell ) {
				$calls_share = (float) ( $cell['calls_share'] ?? 0 );
				$spend_share = (float) ( $cell['spend_share'] ?? 0 );
				if ( $calls_share < $threshold && $spend_share < $threshold ) {
					continue;
				}
				$provider = (string) ( $cell['provider'] ?? '' );
				$fp       = self::alert_fingerprint( $provider, (int) $window );
				if ( isset( $alerted[ $fp ] ) ) {
					continue;
				}
				$payload = array(
					'provider'    => $provider,
					'window'      => (int) $window,
					'calls_share' => $calls_share,
					'spend_share' => $spend_share,
					'calls'       => (int) ( $cell['calls'] ?? 0 ),
					'spend'       => (float) ( $cell['spend'] ?? 0 ),
					'threshold'   => $threshold,
					'hhi_calls'   => (float) ( $analysis['hhi_calls'] ?? 0 ),
				);
				if ( ! self::fire_alert( $payload, $now ) ) {
					continue;
				}
				$alerted[ $fp ] = true;
				$fired[]        = $fp;
			}
		}
		if ( ! empty( $fired ) ) {
			self::put_alerted( $alerted );
		}

		return $fired;
	}

	/**
	 * @param array<string,mixed> $payload Payload.
	 */
	private static function fire_alert( array $payload, int $now ): bool {
		$policy = class_exists( Policy::class, false ) ? Policy::get_policy() : array();
		if ( ! is_array( $policy ) ) {
			$policy = array();
		}
		$email = '';
		if ( class_exists( Alerts::class, false ) && method_exists( Alerts::class, 'resolve_email' ) ) {
			$email = (string) Alerts::resolve_email( $policy );
		}
		if ( '' === $email ) {
			return false;
		}

		$subject = self::build_subject( $payload );
		$body    = self::build_body( $payload );
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

		if ( class_exists( Alerts::class, false ) && method_exists( Alerts::class, 'resolve_webhook' ) ) {
			$hook_url = (string) Alerts::resolve_webhook( $policy );
			if ( '' !== $hook_url && method_exists( Alerts::class, 'safe_wp_remote_post' ) ) {
				Alerts::safe_wp_remote_post(
					$hook_url,
					array(
						'type'        => 'handl_aicac_concentration',
						'provider'    => (string) ( $payload['provider'] ?? '' ),
						'window'      => (int) ( $payload['window'] ?? 0 ),
						'calls_share' => (float) ( $payload['calls_share'] ?? 0 ),
						'spend_share' => (float) ( $payload['spend_share'] ?? 0 ),
						'threshold'   => (float) ( $payload['threshold'] ?? 0 ),
						'site'        => function_exists( 'home_url' ) ? home_url( '/' ) : '',
						'ts'          => $now,
					)
				);
			}
		}

		return $ok;
	}

	/**
	 * @param array<string,mixed> $payload Payload.
	 */
	public static function build_subject( array $payload ): string {
		$site = function_exists( 'get_bloginfo' )
			? wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES )
			: 'WordPress';

		return sprintf(
			/* translators: 1: site name, 2: provider, 3: window days */
			__( '[%1$s] AI provider concentration: %2$s over %3$dd', 'handl-ai-connector-access-control' ),
			$site,
			(string) ( $payload['provider'] ?? '' ),
			(int) ( $payload['window'] ?? 0 )
		);
	}

	/**
	 * @param array<string,mixed> $payload Payload.
	 */
	public static function build_body( array $payload ): string {
		$lines   = array();
		$lines[] = __( 'A single AI provider crossed the concentration threshold on logged traffic.', 'handl-ai-connector-access-control' );
		$lines[] = '';
		$lines[] = sprintf(
			/* translators: %s: provider id */
			__( 'Provider: %s', 'handl-ai-connector-access-control' ),
			(string) ( $payload['provider'] ?? '' )
		);
		$lines[] = sprintf(
			/* translators: %d: trailing window days */
			__( 'Window: %d days', 'handl-ai-connector-access-control' ),
			(int) ( $payload['window'] ?? 0 )
		);
		$lines[] = sprintf(
			/* translators: 1: call share percent, 2: spend share percent, 3: threshold percent */
			__( 'Call share: %1$s — spend share (est.): %2$s — threshold: %3$s', 'handl-ai-connector-access-control' ),
			self::format_share( (float) ( $payload['calls_share'] ?? 0 ) ),
			self::format_share( (float) ( $payload['spend_share'] ?? 0 ) ),
			self::format_share( (float) ( $payload['threshold'] ?? self::DEFAULT_THRESHOLD ) )
		);
		$lines[] = '';
		$lines[] = __( 'Estimate from logged traffic, not a bill. Informational only — this alert never denies AI calls.', 'handl-ai-connector-access-control' );
		$url     = self::admin_url();
		if ( '' !== $url ) {
			$lines[] = '';
			$lines[] = sprintf(
				/* translators: %s: admin URL */
				__( 'Open concentration roster: %s', 'handl-ai-connector-access-control' ),
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

	/**
	 * @param list<array<string,mixed>>|null $rows Optional roster.
	 */
	public static function csv_for_roster( ?array $rows = null ): string {
		if ( null === $rows ) {
			$rows = self::provider_roster();
		}
		$lines   = array();
		$lines[] = self::csv_line(
			array(
				'window_days',
				'provider',
				'calls',
				'spend_est_usd',
				'calls_share',
				'spend_share',
				'top_provider',
				'top_calls_share',
				'top_spend_share',
				'hhi_calls_10000',
				'hhi_spend_10000',
				'above_threshold',
				'framing',
			)
		);
		foreach ( $rows as $row ) {
			$lines[] = self::csv_line(
				array(
					(string) (int) ( $row['window'] ?? 0 ),
					(string) ( $row['provider'] ?? '' ),
					(string) (int) ( $row['calls'] ?? 0 ),
					self::csv_float( (float) ( $row['spend'] ?? 0 ) ),
					self::csv_float( (float) ( $row['calls_share'] ?? 0 ) ),
					self::csv_float( (float) ( $row['spend_share'] ?? 0 ) ),
					(string) ( $row['top_provider'] ?? '' ),
					self::csv_float( (float) ( $row['top_calls_share'] ?? 0 ) ),
					self::csv_float( (float) ( $row['top_spend_share'] ?? 0 ) ),
					self::csv_float( (float) ( $row['hhi_calls'] ?? 0 ) * 10000.0 ),
					self::csv_float( (float) ( $row['hhi_spend'] ?? 0 ) * 10000.0 ),
					! empty( $row['above_threshold'] ) ? 'yes' : 'no',
					'estimate_from_logged_traffic_not_a_bill',
				)
			);
		}

		return implode( "\n", $lines ) . "\n";
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

	public static function csv_float( float $n ): string {
		if ( ! is_finite( $n ) ) {
			return '0';
		}

		return rtrim( rtrim( sprintf( '%.6f', $n ), '0' ), '.' );
	}

	/**
	 * @param list<array<string,mixed>> $rows Provider roster.
	 * @param list<array<string,mixed>> $divorce Divorce roster.
	 */
	public static function build_print_html( array $rows, array $divorce = array() ): string {
		$html  = '<!DOCTYPE html><html><head><meta charset="utf-8"><title>';
		$html .= esc_html__( 'AI provider concentration', 'handl-ai-connector-access-control' );
		$html .= '</title><style>body{font-family:sans-serif;margin:24px}table{border-collapse:collapse;width:100%;margin-bottom:24px}th,td{border:1px solid #ccc;padding:6px 8px;text-align:left}th{background:#f6f7f7}</style></head><body>';
		$html .= '<h1>' . esc_html__( 'AI provider concentration', 'handl-ai-connector-access-control' ) . '</h1>';
		$html .= '<p>' . esc_html__( 'Estimate from logged traffic, not a bill. Informational — never denies.', 'handl-ai-connector-access-control' ) . '</p>';
		$html .= '<table><thead><tr>';
		$html .= '<th>' . esc_html__( 'Window', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '<th>' . esc_html__( 'Provider', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '<th>' . esc_html__( 'Calls', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '<th>' . esc_html__( 'Call share', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '<th>' . esc_html__( 'Spend (est.)', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '<th>' . esc_html__( 'Spend share', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '<th>' . esc_html__( 'HHI (calls)', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '</tr></thead><tbody>';
		foreach ( $rows as $row ) {
			$html .= '<tr>';
			$html .= '<td>' . esc_html( (string) (int) ( $row['window'] ?? 0 ) ) . '</td>';
			$html .= '<td>' . esc_html( (string) ( $row['provider'] ?? '' ) ) . '</td>';
			$html .= '<td>' . esc_html( (string) (int) ( $row['calls'] ?? 0 ) ) . '</td>';
			$html .= '<td>' . esc_html( self::format_share( (float) ( $row['calls_share'] ?? 0 ) ) ) . '</td>';
			$html .= '<td>' . esc_html( self::format_usd( (float) ( $row['spend'] ?? 0 ) ) ) . '</td>';
			$html .= '<td>' . esc_html( self::format_share( (float) ( $row['spend_share'] ?? 0 ) ) ) . '</td>';
			$html .= '<td>' . esc_html( self::format_hhi( (float) ( $row['hhi_calls'] ?? 0 ) ) ) . '</td>';
			$html .= '</tr>';
		}
		$html .= '</tbody></table>';
		$html .= '<h2>' . esc_html__( 'Divorce roster (no observed alternate)', 'handl-ai-connector-access-control' ) . '</h2>';
		if ( empty( $divorce ) ) {
			$html .= '<p>' . esc_html__( 'No single-provider plugins in the 30-day window.', 'handl-ai-connector-access-control' ) . '</p>';
		} else {
			$html .= '<table><thead><tr>';
			$html .= '<th>' . esc_html__( 'Plugin', 'handl-ai-connector-access-control' ) . '</th>';
			$html .= '<th>' . esc_html__( 'Only provider', 'handl-ai-connector-access-control' ) . '</th>';
			$html .= '<th>' . esc_html__( 'Calls', 'handl-ai-connector-access-control' ) . '</th>';
			$html .= '</tr></thead><tbody>';
			foreach ( $divorce as $row ) {
				$html .= '<tr>';
				$html .= '<td>' . esc_html( (string) ( $row['plugin'] ?? '' ) ) . '</td>';
				$html .= '<td>' . esc_html( (string) ( $row['provider'] ?? '' ) ) . '</td>';
				$html .= '<td>' . esc_html( (string) (int) ( $row['calls'] ?? 0 ) ) . '</td>';
				$html .= '</tr>';
			}
			$html .= '</tbody></table>';
		}
		$html .= '</body></html>';

		return $html;
	}

	public static function register_menu(): void {
		if ( ! Caps::user_can_view() ) {
			return;
		}
		if ( ! function_exists( 'add_submenu_page' ) ) {
			return;
		}
		add_submenu_page(
			Admin::MENU_SLUG,
			__( 'AI concentration', 'handl-ai-connector-access-control' ),
			__( 'Concentration', 'handl-ai-connector-access-control' ),
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
		$rows       = $enabled ? self::provider_roster() : array();
		$divorce    = $enabled ? self::divorce_roster( 30 ) : array();
		$snap       = $enabled ? self::snapshot() : null;
		$csv        = add_query_arg(
			array(
				'page'                          => self::PAGE_SLUG,
				'handl_aicac_concentration_csv' => '1',
				'_wpnonce'                      => function_exists( 'wp_create_nonce' ) ? wp_create_nonce( 'handl_aicac_concentration_csv' ) : '',
			),
			admin_url( 'admin.php' )
		);
		$print = add_query_arg(
			array(
				'page'                            => self::PAGE_SLUG,
				'handl_aicac_concentration_print' => '1',
				'_wpnonce'                        => function_exists( 'wp_create_nonce' ) ? wp_create_nonce( 'handl_aicac_concentration_print' ) : '',
			),
			admin_url( 'admin.php' )
		);

		echo '<div class="wrap">';
		echo '<h1>' . esc_html__( 'AI concentration', 'handl-ai-connector-access-control' ) . '</h1>';
		echo '<p class="description">' . esc_html__( 'See when one provider quietly becomes most of your AI traffic. Circuit-breaker watches outages; this watches monopoly risk. Estimate from logged traffic, not a bill. Informational; off by default.', 'handl-ai-connector-access-control' ) . '</p>';

		if ( $can_manage ) {
			$action = admin_url( 'admin-post.php' );
			echo '<form method="post" action="' . esc_url( $action ) . '">';
			echo '<input type="hidden" name="action" value="' . esc_attr( self::ACTION_SAVE ) . '" />';
			if ( function_exists( 'wp_nonce_field' ) ) {
				wp_nonce_field( self::ACTION_SAVE );
			}
			echo '<input type="hidden" name="' . esc_attr( self::POST_PRESENT ) . '" value="1" />';
			echo '<table class="form-table" role="presentation"><tbody>';
			echo '<tr><th scope="row">' . esc_html__( 'Enable concentration watch', 'handl-ai-connector-access-control' ) . '</th><td>';
			echo '<label><input type="checkbox" name="' . esc_attr( self::POST_ENABLED ) . '" value="1" ' . checked( ! empty( $settings['enabled'] ), true, false ) . ' /> ';
			echo esc_html__( 'Compute provider shares and alert on concentration crossings', 'handl-ai-connector-access-control' );
			echo '</label></td></tr>';
			$pct = (float) $settings['threshold'] * 100.0;
			echo '<tr><th scope="row"><label for="handl-aicac-concentration-threshold">' . esc_html__( 'Alert threshold (%)', 'handl-ai-connector-access-control' ) . '</label></th><td>';
			echo '<input name="' . esc_attr( self::POST_THRESHOLD ) . '" id="handl-aicac-concentration-threshold" type="number" min="1" max="99" step="1" value="' . esc_attr( (string) (int) round( $pct ) ) . '" class="small-text" />';
			echo '<p class="description">' . esc_html__( 'Alert once per provider+window when call share or estimated spend share reaches this percent. Default 80.', 'handl-ai-connector-access-control' ) . '</p>';
			echo '</td></tr></tbody></table>';
			submit_button( __( 'Save concentration settings', 'handl-ai-connector-access-control' ) );
			echo '</form>';
		}

		if ( ! $enabled ) {
			echo '<p>' . esc_html__( 'Concentration watch is off. Enable it to build the provider-share roster and divorce list from logged traffic.', 'handl-ai-connector-access-control' ) . '</p>';
			echo '</div>';

			return;
		}

		echo '<p><strong>' . esc_html__( 'Estimate from logged traffic, not a bill.', 'handl-ai-connector-access-control' ) . '</strong> ';
		echo esc_html__( 'Shares and the HHI-style index are computed from the activity log. Spend uses the same directional USD estimates as Cost — not an invoice.', 'handl-ai-connector-access-control' ) . '</p>';

		if ( is_array( $snap ) ) {
			foreach ( array( 30, 90 ) as $window ) {
				$w = $snap['windows'][ $window ] ?? null;
				if ( ! is_array( $w ) ) {
					continue;
				}
				echo '<h2>' . esc_html(
					sprintf(
						/* translators: %d: window days */
						__( '%d-day summary', 'handl-ai-connector-access-control' ),
						$window
					)
				) . '</h2>';
				echo '<ul>';
				echo '<li>' . esc_html(
					sprintf(
						/* translators: 1: provider, 2: call share, 3: spend share */
						__( 'Top provider: %1$s — calls %2$s — spend (est.) %3$s', 'handl-ai-connector-access-control' ),
						(string) ( $w['top_provider'] ?? '—' ),
						self::format_share( (float) ( $w['top_calls_share'] ?? 0 ) ),
						self::format_share( (float) ( $w['top_spend_share'] ?? 0 ) )
					)
				) . '</li>';
				echo '<li>' . esc_html(
					sprintf(
						/* translators: 1: HHI calls, 2: HHI spend */
						__( 'HHI (0–10,000): calls %1$s — spend %2$s', 'handl-ai-connector-access-control' ),
						self::format_hhi( (float) ( $w['hhi_calls'] ?? 0 ) ),
						self::format_hhi( (float) ( $w['hhi_spend'] ?? 0 ) )
					)
				) . '</li>';
				if ( ! empty( $w['above_threshold'] ) ) {
					echo '<li><strong>' . esc_html__( 'Above alert threshold.', 'handl-ai-connector-access-control' ) . '</strong></li>';
				}
				echo '</ul>';
			}
		}

		echo '<p>';
		echo '<a class="button" href="' . esc_url( $csv ) . '">' . esc_html__( 'Download CSV', 'handl-ai-connector-access-control' ) . '</a> ';
		echo '<a class="button" href="' . esc_url( $print ) . '" target="_blank" rel="noopener noreferrer">' . esc_html__( 'Print / PDF view', 'handl-ai-connector-access-control' ) . '</a>';
		echo '</p>';

		echo '<h2>' . esc_html__( 'Provider shares', 'handl-ai-connector-access-control' ) . '</h2>';
		if ( empty( $rows ) ) {
			echo '<p>' . esc_html__( 'No logged AI traffic in the 30/90-day windows yet.', 'handl-ai-connector-access-control' ) . '</p>';
		} else {
			echo '<table class="widefat striped"><thead><tr>';
			echo '<th>' . esc_html__( 'Window', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Provider', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Calls', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Call share', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Spend (est.)', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Spend share', 'handl-ai-connector-access-control' ) . '</th>';
			echo '</tr></thead><tbody>';
			foreach ( $rows as $row ) {
				echo '<tr>';
				echo '<td>' . esc_html( (string) (int) $row['window'] ) . '</td>';
				echo '<td><code>' . esc_html( (string) $row['provider'] ) . '</code></td>';
				echo '<td>' . esc_html( (string) (int) $row['calls'] ) . '</td>';
				echo '<td>' . esc_html( self::format_share( (float) $row['calls_share'] ) ) . '</td>';
				echo '<td>' . esc_html( self::format_usd( (float) $row['spend'] ) ) . '</td>';
				echo '<td>' . esc_html( self::format_share( (float) $row['spend_share'] ) ) . '</td>';
				echo '</tr>';
			}
			echo '</tbody></table>';
		}

		echo '<h2>' . esc_html__( 'Divorce roster (30d — no observed alternate)', 'handl-ai-connector-access-control' ) . '</h2>';
		echo '<p class="description">' . esc_html__( 'Plugins that talked to only one provider in the window — what actually breaks in a divorce.', 'handl-ai-connector-access-control' ) . '</p>';
		if ( empty( $divorce ) ) {
			echo '<p>' . esc_html__( 'No single-provider plugins in the 30-day window.', 'handl-ai-connector-access-control' ) . '</p>';
		} else {
			echo '<table class="widefat striped"><thead><tr>';
			echo '<th>' . esc_html__( 'Plugin', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Only provider', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Calls', 'handl-ai-connector-access-control' ) . '</th>';
			echo '</tr></thead><tbody>';
			foreach ( $divorce as $row ) {
				echo '<tr>';
				echo '<td><code>' . esc_html( (string) $row['plugin'] ) . '</code></td>';
				echo '<td>' . esc_html( (string) $row['provider'] ) . '</td>';
				echo '<td>' . esc_html( (string) (int) $row['calls'] ) . '</td>';
				echo '</tr>';
			}
			echo '</tbody></table>';
		}

		echo '</div>';
	}

	public static function maybe_handle_csv(): void {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( empty( $_GET['handl_aicac_concentration_csv'] ) ) {
			return;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$page = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( (string) $_GET['page'] ) ) : '';
		if ( self::PAGE_SLUG !== $page ) {
			return;
		}
		if ( ! Caps::user_can_view() || ! self::is_enabled() ) {
			return;
		}
		check_admin_referer( 'handl_aicac_concentration_csv' );
		$csv = self::csv_for_roster();
		if ( function_exists( 'nocache_headers' ) ) {
			nocache_headers();
		}
		if ( ! headers_sent() ) {
			header( 'Content-Type: text/csv; charset=utf-8' );
			header( 'Content-Disposition: attachment; filename=handl-aicac-concentration.csv' );
		}
		echo $csv; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- CSV download.
		exit;
	}

	public static function maybe_handle_print(): void {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( empty( $_GET['handl_aicac_concentration_print'] ) ) {
			return;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$page = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( (string) $_GET['page'] ) ) : '';
		if ( self::PAGE_SLUG !== $page ) {
			return;
		}
		if ( ! Caps::user_can_view() || ! self::is_enabled() ) {
			return;
		}
		check_admin_referer( 'handl_aicac_concentration_print' );
		$rows    = self::provider_roster();
		$divorce = self::divorce_roster( 30 );
		if ( function_exists( 'nocache_headers' ) ) {
			nocache_headers();
		}
		if ( ! headers_sent() ) {
			header( 'Content-Type: text/html; charset=utf-8' );
		}
		echo self::build_print_html( $rows, $divorce ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped inside builder.
		exit;
	}

	public static function handle_save(): void {
		if ( ! Caps::user_can_manage() ) {
			wp_die( esc_html__( 'You do not have permission to save concentration settings.', 'handl-ai-connector-access-control' ) );
		}
		check_admin_referer( self::ACTION_SAVE );
		if ( empty( $_POST[ self::POST_PRESENT ] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing
			wp_die( esc_html__( 'Invalid form', 'handl-ai-connector-access-control' ) );
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		$threshold_raw = isset( $_POST[ self::POST_THRESHOLD ] ) ? wp_unslash( (string) $_POST[ self::POST_THRESHOLD ] ) : '';
		self::save_settings(
			array(
				'enabled'   => ! empty( $_POST[ self::POST_ENABLED ] ), // phpcs:ignore WordPress.Security.NonceVerification.Missing
				'threshold' => self::sanitize_threshold( '' !== $threshold_raw ? $threshold_raw : self::DEFAULT_THRESHOLD ),
			)
		);
		$redirect = add_query_arg(
			array(
				'page'    => self::PAGE_SLUG,
				'updated' => '1',
			),
			admin_url( 'admin.php' )
		);
		if ( function_exists( 'wp_safe_redirect' ) ) {
			wp_safe_redirect( $redirect );
			exit;
		}
	}

	public static function register_cli(): void {
		if ( ! defined( 'WP_CLI' ) || ! WP_CLI ) {
			return;
		}
		if ( ! class_exists( '\WP_CLI' ) ) {
			return;
		}
		\WP_CLI::add_command( 'handl-aicac concentration', CLI_Concentration::class );
	}

	/**
	 * Whether any window is currently above threshold.
	 */
	public static function is_above_threshold( ?array $log = null, ?int $now = null ): bool {
		$snap = self::snapshot( $log, $now );
		foreach ( $snap['windows'] as $analysis ) {
			if ( ! empty( $analysis['above_threshold'] ) ) {
				return true;
			}
		}

		return false;
	}
}

/**
 * WP-CLI: wp handl-aicac concentration status|export
 */
final class CLI_Concentration {

	/**
	 * Show concentration status.
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
		$settings = Concentration::get_settings();
		$snap     = Concentration::is_enabled() ? Concentration::snapshot() : null;
		$format   = isset( $assoc_args['format'] ) ? (string) $assoc_args['format'] : 'table';
		$above    = is_array( $snap ) ? Concentration::is_above_threshold() : false;

		\WP_CLI::log(
			sprintf(
				'enabled=%s threshold=%s framing=estimate_from_logged_traffic_not_a_bill above_threshold=%s',
				! empty( $settings['enabled'] ) ? 'yes' : 'no',
				Concentration::format_share( Concentration::threshold() ),
				$above ? 'yes' : 'no'
			)
		);

		$rows = Concentration::is_enabled() ? Concentration::provider_roster() : array();
		if ( empty( $rows ) ) {
			\WP_CLI::log( 'No concentration rows.' );
			if ( $above ) {
				\WP_CLI::error( 'Above concentration threshold.', false );
			}
			return;
		}

		$display = array();
		foreach ( $rows as $row ) {
			$display[] = array(
				'window'      => (int) $row['window'],
				'provider'    => (string) $row['provider'],
				'calls'       => (int) $row['calls'],
				'calls_share' => Concentration::format_share( (float) $row['calls_share'] ),
				'spend'       => Concentration::csv_float( (float) $row['spend'] ),
				'spend_share' => Concentration::format_share( (float) $row['spend_share'] ),
				'hhi_calls'   => Concentration::format_hhi( (float) $row['hhi_calls'] ),
			);
		}
		if ( 'json' === $format ) {
			\WP_CLI::print_value( $display, array( 'format' => 'json' ) );
		} elseif ( class_exists( '\WP_CLI\Utils' ) ) {
			\WP_CLI\Utils\format_items(
				'table',
				$display,
				array( 'window', 'provider', 'calls', 'calls_share', 'spend', 'spend_share', 'hhi_calls' )
			);
		} else {
			foreach ( $display as $row ) {
				\WP_CLI::log( implode( "\t", $row ) );
			}
		}

		if ( $above ) {
			\WP_CLI::error( 'Above concentration threshold.', false );
		}
	}

	/**
	 * Export the concentration roster as CSV.
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
		$csv = Concentration::csv_for_roster();
		if ( ! empty( $assoc_args['porcelain'] ) ) {
			echo $csv; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- CLI CSV.
			return;
		}
		\WP_CLI::print_value( $csv, array( 'format' => 'csv' ) );
	}
}
