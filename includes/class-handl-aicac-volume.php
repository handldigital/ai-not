<?php
/**
 * AICAC-VOLUME (#385): outbound AI payload volume watch (exfil-shaped spikes).
 *
 * Own http_api_debug hook measures request + response body sizes for AI-destined
 * HTTP calls — byte counts only, never content. Per-plugin / per-provider daily
 * counters in the class's own option (30-day rolling window). Trailing-median
 * baseline; one alert per plugin+day on a configurable spike multiple (default
 * 10x) or absolute daily ceiling. Top-senders roster + CSV + WP-CLI. Informational
 * only — never denies. OFF by default. No admin.php/policy.php/cost.php/logger/
 * rate-cap edits.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Byte-volume egress watch for AI connector traffic.
 */
final class Volume {

	public const SETTINGS_OPTION = 'handl_aicac_volume';

	public const COUNTERS_OPTION = 'handl_aicac_volume_counters';

	public const ALERTED_OPTION = 'handl_aicac_volume_alerted';

	public const PAGE_SLUG = 'handl-aicac-volume';

	public const ALERT_KIND = 'volume';

	public const WINDOW_DAYS = 30;

	public const DEFAULT_SPIKE_MULTIPLE = 10.0;

	public const DEFAULT_DAILY_CEILING = 0;

	public const UNKNOWN_PLUGIN = '(unknown)';

	public const POST_PRESENT = 'handl_aicac_volume_present';

	public const POST_ENABLED = 'handl_aicac_volume_enabled';

	public const POST_SPIKE = 'handl_aicac_volume_spike_multiple';

	public const POST_CEILING = 'handl_aicac_volume_daily_ceiling_mb';

	public const ACTION_SAVE = 'handl_aicac_volume_save';

	/** @var bool */
	private static $registered = false;

	/** @var bool */
	private static $http_hooked = false;

	/** @var list<array{to:string,subject:string,body:string}> */
	private static $test_mails = array();

	/** @var string|null Forced provider id for tests (bypass host map). */
	private static $test_provider = null;

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
			self::register_http_hook();
		}
		self::register_cli();
	}

	public static function register_http_hook(): void {
		if ( self::$http_hooked ) {
			return;
		}
		self::$http_hooked = true;
		add_action( 'http_api_debug', array( self::class, 'on_http_api_debug' ), 10, 5 );
	}

	public static function reset_for_tests(): void {
		self::$registered    = false;
		self::$http_hooked   = false;
		self::$test_mails    = array();
		self::$test_provider = null;
		delete_option( self::SETTINGS_OPTION );
		delete_option( self::COUNTERS_OPTION );
		delete_option( self::ALERTED_OPTION );
	}

	/**
	 * @return list<array{to:string,subject:string,body:string}>
	 */
	public static function test_mails(): array {
		return self::$test_mails;
	}

	/**
	 * @internal Tests only.
	 */
	public static function set_test_provider( ?string $provider ): void {
		self::$test_provider = ( null !== $provider && '' !== $provider ) ? sanitize_key( $provider ) : null;
	}

	/**
	 * @return array{enabled:bool,spike_multiple:float,daily_ceiling_bytes:int}
	 */
	public static function defaults(): array {
		return array(
			'enabled'             => false,
			'spike_multiple'      => self::DEFAULT_SPIKE_MULTIPLE,
			'daily_ceiling_bytes' => self::DEFAULT_DAILY_CEILING,
		);
	}

	/**
	 * @return array{enabled:bool,spike_multiple:float,daily_ceiling_bytes:int}
	 */
	public static function get_settings(): array {
		return self::sanitize_settings( get_option( self::SETTINGS_OPTION, array() ) );
	}

	/**
	 * @param mixed $raw Raw settings.
	 * @return array{enabled:bool,spike_multiple:float,daily_ceiling_bytes:int}
	 */
	public static function sanitize_settings( $raw ): array {
		$defaults = self::defaults();
		if ( ! is_array( $raw ) ) {
			return $defaults;
		}

		return array(
			'enabled'             => ! empty( $raw['enabled'] ),
			'spike_multiple'      => self::sanitize_spike_multiple( $raw['spike_multiple'] ?? $defaults['spike_multiple'] ),
			'daily_ceiling_bytes' => self::sanitize_daily_ceiling( $raw['daily_ceiling_bytes'] ?? $defaults['daily_ceiling_bytes'] ),
		);
	}

	/**
	 * @param mixed $raw Spike multiple.
	 */
	public static function sanitize_spike_multiple( $raw ): float {
		$n = is_numeric( $raw ) ? (float) $raw : self::DEFAULT_SPIKE_MULTIPLE;
		if ( $n < 1.0 ) {
			$n = 1.0;
		}
		if ( $n > 1000.0 ) {
			$n = 1000.0;
		}

		return round( $n, 2 );
	}

	/**
	 * @param mixed $raw Absolute daily ceiling in bytes (0 = off).
	 */
	public static function sanitize_daily_ceiling( $raw ): int {
		if ( is_string( $raw ) ) {
			$raw = trim( $raw );
			if ( '' === $raw ) {
				return 0;
			}
		}
		$n = is_numeric( $raw ) ? (int) $raw : 0;
		if ( $n < 0 ) {
			$n = 0;
		}
		// Cap at 10 GiB/day to avoid absurd option values.
		if ( $n > 10737418240 ) {
			$n = 10737418240;
		}

		return $n;
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

	public static function day_key( ?int $ts = null ): string {
		$ts = null !== $ts && $ts > 0 ? $ts : Clock::now();
		if ( function_exists( 'wp_date' ) ) {
			return (string) wp_date( 'Y-m-d', $ts );
		}

		return gmdate( 'Y-m-d', $ts );
	}

	/**
	 * Measure body size without retaining content.
	 *
	 * @param mixed $body Request or response body.
	 */
	public static function body_bytes( $body ): int {
		if ( null === $body || false === $body ) {
			return 0;
		}
		if ( is_string( $body ) ) {
			return strlen( $body );
		}
		if ( is_array( $body ) ) {
			$total = 0;
			foreach ( $body as $part ) {
				if ( is_string( $part ) ) {
					$total += strlen( $part );
					continue;
				}
				if ( is_array( $part ) ) {
					if ( isset( $part['bits'] ) && is_string( $part['bits'] ) ) {
						$total += strlen( $part['bits'] );
					} elseif ( isset( $part['file'] ) && is_string( $part['file'] ) && is_readable( $part['file'] ) ) {
						$size = @filesize( $part['file'] ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- best-effort size only.
						if ( false !== $size ) {
							$total += (int) $size;
						}
					}
				}
			}

			return $total;
		}

		return 0;
	}

	/**
	 * @param mixed                $response Response or WP_Error.
	 * @param string               $context  Hook context.
	 * @param string               $class    Transport class.
	 * @param array<string,mixed>  $args     Request args.
	 * @param string               $url      Request URL.
	 */
	public static function on_http_api_debug( $response, $context, $class, $args, $url ): void {
		unset( $class );
		if ( 'response' !== (string) $context ) {
			return;
		}
		if ( ! self::is_enabled() ) {
			return;
		}
		if ( ! is_array( $args ) ) {
			$args = array();
		}
		$url = is_string( $url ) ? $url : '';
		self::record_from_http( $response, $args, $url, null );
	}

	/**
	 * @param mixed               $response Response or WP_Error.
	 * @param array<string,mixed> $args     Request args.
	 * @param string              $url      URL.
	 * @param int|null            $now      Optional clock.
	 * @return array<string,mixed>|null Updated day cell or null when ignored.
	 */
	public static function record_from_http( $response, array $args, string $url, ?int $now = null ): ?array {
		if ( ! self::is_enabled() ) {
			return null;
		}

		$provider = self::provider_for_url( $url );
		if ( null === $provider || '' === $provider ) {
			return null;
		}

		$plugin = self::caller_plugin();
		$bytes_out = self::body_bytes( $args['body'] ?? null );
		$bytes_in  = 0;
		if ( is_array( $response ) ) {
			$bytes_in = self::body_bytes( $response['body'] ?? null );
		}

		return self::record_bytes( $plugin, $provider, $bytes_out, $bytes_in, $now );
	}

	public static function provider_for_url( string $url ): ?string {
		if ( null !== self::$test_provider && '' !== self::$test_provider ) {
			return self::$test_provider;
		}
		$host = self::host_from_url( $url );
		if ( '' === $host ) {
			return null;
		}
		if ( class_exists( Shadow_AI::class, false ) && method_exists( Shadow_AI::class, 'match_provider' ) ) {
			$matched = Shadow_AI::match_provider( $host );

			return null !== $matched ? sanitize_key( (string) $matched ) : null;
		}

		return null;
	}

	public static function host_from_url( string $url ): string {
		$url = trim( $url );
		if ( '' === $url ) {
			return '';
		}
		$parts = function_exists( 'wp_parse_url' ) ? wp_parse_url( $url ) : parse_url( $url );
		if ( ! is_array( $parts ) || empty( $parts['host'] ) ) {
			return '';
		}

		return strtolower( rtrim( (string) $parts['host'], '.' ) );
	}

	public static function caller_plugin(): string {
		if ( class_exists( Attribution::class, false ) && method_exists( Attribution::class, 'resolve_from_backtrace' ) ) {
			$resolved = Attribution::resolve_from_backtrace();
			if ( is_array( $resolved ) && ! empty( $resolved['plugin'] ) && is_string( $resolved['plugin'] ) ) {
				return sanitize_text_field( $resolved['plugin'] );
			}
		}

		return self::UNKNOWN_PLUGIN;
	}

	/**
	 * @return array{days:array<string,array<string,array<string,mixed>>>}
	 */
	public static function get_counters(): array {
		return self::sanitize_counters( get_option( self::COUNTERS_OPTION, array() ) );
	}

	/**
	 * @param mixed $raw Raw counters.
	 * @return array{days:array<string,array<string,array<string,mixed>>>}
	 */
	public static function sanitize_counters( $raw ): array {
		$out = array( 'days' => array() );
		if ( ! is_array( $raw ) ) {
			return $out;
		}
		$days = isset( $raw['days'] ) && is_array( $raw['days'] ) ? $raw['days'] : array();
		foreach ( $days as $day => $cells ) {
			$day_key = self::sanitize_day_key( $day );
			if ( '' === $day_key || ! is_array( $cells ) ) {
				continue;
			}
			$clean_cells = array();
			foreach ( $cells as $cell_key => $cell ) {
				$clean = self::sanitize_cell( $cell );
				if ( null === $clean ) {
					continue;
				}
				$clean_cells[ self::cell_key( $clean['plugin'], $clean['provider'] ) ] = $clean;
			}
			if ( ! empty( $clean_cells ) ) {
				$out['days'][ $day_key ] = $clean_cells;
			}
		}
		ksort( $out['days'] );

		return $out;
	}

	/**
	 * @param mixed $raw Day key.
	 */
	public static function sanitize_day_key( $raw ): string {
		$day = is_string( $raw ) ? trim( $raw ) : '';
		if ( ! preg_match( '/^\d{4}-\d{2}-\d{2}$/', $day ) ) {
			return '';
		}

		return $day;
	}

	/**
	 * @param mixed $raw Cell.
	 * @return array{plugin:string,provider:string,bytes_out:int,bytes_in:int,calls:int,max_request:int}|null
	 */
	public static function sanitize_cell( $raw ): ?array {
		if ( ! is_array( $raw ) ) {
			return null;
		}
		$plugin = isset( $raw['plugin'] ) ? sanitize_text_field( (string) $raw['plugin'] ) : '';
		if ( '' === $plugin ) {
			$plugin = self::UNKNOWN_PLUGIN;
		}
		$provider = isset( $raw['provider'] ) ? sanitize_key( (string) $raw['provider'] ) : '';
		if ( '' === $provider ) {
			return null;
		}

		return array(
			'plugin'      => $plugin,
			'provider'    => $provider,
			'bytes_out'   => max( 0, (int) ( $raw['bytes_out'] ?? 0 ) ),
			'bytes_in'    => max( 0, (int) ( $raw['bytes_in'] ?? 0 ) ),
			'calls'       => max( 0, (int) ( $raw['calls'] ?? 0 ) ),
			'max_request' => max( 0, (int) ( $raw['max_request'] ?? 0 ) ),
		);
	}

	public static function cell_key( string $plugin, string $provider ): string {
		return $plugin . '|' . $provider;
	}

	/**
	 * @param array{days:array<string,array<string,array<string,mixed>>>} $counters Counters.
	 */
	public static function put_counters( array $counters ): void {
		$clean = self::sanitize_counters( $counters );
		$clean = self::evict_old_days( $clean );
		if ( empty( $clean['days'] ) ) {
			delete_option( self::COUNTERS_OPTION );

			return;
		}
		update_option( self::COUNTERS_OPTION, $clean, false );
	}

	/**
	 * @param array{days:array<string,array<string,array<string,mixed>>>} $counters Counters.
	 * @return array{days:array<string,array<string,array<string,mixed>>>}
	 */
	public static function evict_old_days( array $counters ): array {
		$days = array_keys( $counters['days'] ?? array() );
		sort( $days );
		while ( count( $days ) > self::WINDOW_DAYS ) {
			$oldest = array_shift( $days );
			unset( $counters['days'][ $oldest ] );
		}

		return $counters;
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
			$fp = sanitize_text_field( (string) $fp );
			if ( '' === $fp ) {
				continue;
			}
			if ( ! empty( $flag ) ) {
				$out[ $fp ] = true;
			}
		}

		return $out;
	}

	/**
	 * @param array<string,bool> $alerted Fingerprints.
	 */
	public static function put_alerted( array $alerted ): void {
		$clean = array();
		foreach ( $alerted as $fp => $flag ) {
			$fp = sanitize_text_field( (string) $fp );
			if ( '' === $fp || empty( $flag ) ) {
				continue;
			}
			$clean[ $fp ] = true;
		}
		// Bound growth: keep fingerprints that still fall inside the counter window.
		$days = array_keys( self::get_counters()['days'] );
		if ( ! empty( $days ) ) {
			$min_day = min( $days );
			foreach ( array_keys( $clean ) as $fp ) {
				$parts = explode( '|', $fp, 2 );
				$day   = $parts[1] ?? '';
				if ( '' !== $day && $day < $min_day ) {
					unset( $clean[ $fp ] );
				}
			}
		}
		if ( empty( $clean ) ) {
			delete_option( self::ALERTED_OPTION );

			return;
		}
		update_option( self::ALERTED_OPTION, $clean, false );
	}

	public static function alert_fingerprint( string $plugin, string $day ): string {
		return sanitize_text_field( $plugin ) . '|' . self::sanitize_day_key( $day );
	}

	/**
	 * @return array<string,mixed>|null Updated cell.
	 */
	public static function record_bytes( string $plugin, string $provider, int $bytes_out, int $bytes_in, ?int $now = null ): ?array {
		if ( ! self::is_enabled() ) {
			return null;
		}
		$plugin   = '' !== $plugin ? sanitize_text_field( $plugin ) : self::UNKNOWN_PLUGIN;
		$provider = sanitize_key( $provider );
		if ( '' === $provider ) {
			return null;
		}
		$bytes_out = max( 0, $bytes_out );
		$bytes_in  = max( 0, $bytes_in );
		if ( 0 === $bytes_out && 0 === $bytes_in ) {
			return null;
		}

		$now     = null !== $now && $now > 0 ? $now : Clock::now();
		$day     = self::day_key( $now );
		$key     = self::cell_key( $plugin, $provider );
		$store   = self::get_counters();
		$cell    = $store['days'][ $day ][ $key ] ?? array(
			'plugin'      => $plugin,
			'provider'    => $provider,
			'bytes_out'   => 0,
			'bytes_in'    => 0,
			'calls'       => 0,
			'max_request' => 0,
		);
		$cell['plugin']      = $plugin;
		$cell['provider']    = $provider;
		$cell['bytes_out']   = (int) $cell['bytes_out'] + $bytes_out;
		$cell['bytes_in']    = (int) $cell['bytes_in'] + $bytes_in;
		$cell['calls']       = (int) $cell['calls'] + 1;
		$cell['max_request'] = max( (int) $cell['max_request'], $bytes_out );
		$store['days'][ $day ][ $key ] = $cell;
		self::put_counters( $store );
		self::maybe_alert_plugin_day( $plugin, $day, $now );

		return $cell;
	}

	/**
	 * Daily outbound bytes for a plugin across providers.
	 *
	 * @return array<string,int> day => bytes_out
	 */
	public static function plugin_daily_totals( string $plugin, ?array $counters = null ): array {
		$plugin    = sanitize_text_field( $plugin );
		$counters  = is_array( $counters ) ? self::sanitize_counters( $counters ) : self::get_counters();
		$totals    = array();
		foreach ( $counters['days'] as $day => $cells ) {
			$sum = 0;
			foreach ( $cells as $cell ) {
				if ( (string) $cell['plugin'] === $plugin ) {
					$sum += (int) $cell['bytes_out'];
				}
			}
			$totals[ $day ] = $sum;
		}
		ksort( $totals );

		return $totals;
	}

	/**
	 * Trailing median of prior days (excludes $day).
	 *
	 * @param array<string,int> $daily day => bytes.
	 */
	public static function trailing_median( array $daily, string $day ): ?float {
		$values = array();
		foreach ( $daily as $d => $bytes ) {
			if ( (string) $d === $day ) {
				continue;
			}
			$values[] = (int) $bytes;
		}
		if ( empty( $values ) ) {
			return null;
		}
		sort( $values, SORT_NUMERIC );
		$n = count( $values );
		$mid = (int) floor( ( $n - 1 ) / 2 );
		if ( 0 === $n % 2 ) {
			return ( (float) $values[ $mid ] + (float) $values[ $mid + 1 ] ) / 2.0;
		}

		return (float) $values[ $mid ];
	}

	public static function maybe_alert_plugin_day( string $plugin, string $day, ?int $now = null ): bool {
		if ( ! self::is_enabled() ) {
			return false;
		}
		$plugin = sanitize_text_field( $plugin );
		$day    = self::sanitize_day_key( $day );
		if ( '' === $plugin || '' === $day ) {
			return false;
		}
		$fp = self::alert_fingerprint( $plugin, $day );
		$alerted = self::get_alerted();
		if ( isset( $alerted[ $fp ] ) ) {
			return false;
		}

		$settings = self::get_settings();
		$daily    = self::plugin_daily_totals( $plugin );
		$today    = (int) ( $daily[ $day ] ?? 0 );
		if ( $today <= 0 ) {
			return false;
		}

		$reasons = array();
		$median  = self::trailing_median( $daily, $day );
		$mult    = (float) $settings['spike_multiple'];
		if ( null !== $median && $median > 0 && $today >= ( $median * $mult ) ) {
			$reasons[] = 'spike';
		}
		$ceiling = (int) $settings['daily_ceiling_bytes'];
		if ( $ceiling > 0 && $today >= $ceiling ) {
			$reasons[] = 'ceiling';
		}
		if ( empty( $reasons ) ) {
			return false;
		}

		$now = null !== $now && $now > 0 ? $now : Clock::now();
		if ( class_exists( Alert_Snooze::class, false )
			&& method_exists( Alert_Snooze::class, 'should_suppress' )
			&& Alert_Snooze::should_suppress( $plugin, self::ALERT_KIND, $now ) ) {
			return false;
		}

		$payload = array(
			'plugin'         => $plugin,
			'day'            => $day,
			'bytes_out'      => $today,
			'baseline'       => $median,
			'spike_multiple' => $mult,
			'ceiling'        => $ceiling,
			'reasons'        => $reasons,
		);
		if ( ! self::fire_alert( $payload, $now ) ) {
			return false;
		}
		$alerted[ $fp ] = true;
		self::put_alerted( $alerted );

		return true;
	}

	/**
	 * @param array<string,mixed> $payload Alert payload.
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

		$ok = false;
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
						'type'           => 'handl_aicac_volume_spike',
						'plugin'         => (string) ( $payload['plugin'] ?? '' ),
						'day'            => (string) ( $payload['day'] ?? '' ),
						'bytes_out'      => (int) ( $payload['bytes_out'] ?? 0 ),
						'baseline'       => $payload['baseline'] ?? null,
						'spike_multiple' => (float) ( $payload['spike_multiple'] ?? 0 ),
						'ceiling'        => (int) ( $payload['ceiling'] ?? 0 ),
						'reasons'        => array_values( (array) ( $payload['reasons'] ?? array() ) ),
						'site'           => function_exists( 'home_url' ) ? home_url( '/' ) : '',
						'ts'             => $now,
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
			/* translators: 1: site name, 2: plugin basename */
			__( '[%1$s] AI volume spike: %2$s', 'handl-ai-connector-access-control' ),
			$site,
			'' !== (string) ( $payload['plugin'] ?? '' ) ? (string) $payload['plugin'] : __( '(unknown plugin)', 'handl-ai-connector-access-control' )
		);
	}

	/**
	 * @param array<string,mixed> $payload Payload.
	 */
	public static function build_body( array $payload ): string {
		$lines   = array();
		$lines[] = __( 'HandL AI Connector Access Control — outbound AI volume spike (informational; no deny).', 'handl-ai-connector-access-control' );
		$lines[] = '';
		$lines[] = sprintf(
			/* translators: %s: plugin */
			__( 'Plugin: %s', 'handl-ai-connector-access-control' ),
			(string) ( $payload['plugin'] ?? '' )
		);
		$lines[] = sprintf(
			/* translators: %s: day */
			__( 'Day: %s', 'handl-ai-connector-access-control' ),
			(string) ( $payload['day'] ?? '' )
		);
		$lines[] = sprintf(
			/* translators: %s: formatted bytes */
			__( 'Outbound bytes today: %s', 'handl-ai-connector-access-control' ),
			self::format_bytes( (int) ( $payload['bytes_out'] ?? 0 ) )
		);
		if ( null !== ( $payload['baseline'] ?? null ) ) {
			$lines[] = sprintf(
				/* translators: 1: baseline bytes, 2: multiple */
				__( 'Trailing-median baseline: %1$s (alert at %2$sx)', 'handl-ai-connector-access-control' ),
				self::format_bytes( (int) round( (float) $payload['baseline'] ) ),
				(string) (float) ( $payload['spike_multiple'] ?? self::DEFAULT_SPIKE_MULTIPLE )
			);
		}
		if ( (int) ( $payload['ceiling'] ?? 0 ) > 0 ) {
			$lines[] = sprintf(
				/* translators: %s: ceiling */
				__( 'Absolute daily ceiling: %s', 'handl-ai-connector-access-control' ),
				self::format_bytes( (int) $payload['ceiling'] )
			);
		}
		$reasons = array_values( (array) ( $payload['reasons'] ?? array() ) );
		if ( ! empty( $reasons ) ) {
			$lines[] = sprintf(
				/* translators: %s: reason list */
				__( 'Triggered by: %s', 'handl-ai-connector-access-control' ),
				implode( ', ', $reasons )
			);
		}
		$lines[] = '';
		$lines[] = __( 'Byte counts only — no request content is stored or emailed.', 'handl-ai-connector-access-control' );
		$lines[] = __( 'Review the volume roster:', 'handl-ai-connector-access-control' );
		$lines[] = self::admin_url();

		return implode( "\n", $lines );
	}

	public static function format_bytes( int $bytes ): string {
		$bytes = max( 0, $bytes );
		if ( $bytes < 1024 ) {
			return (string) $bytes . ' B';
		}
		if ( $bytes < 1048576 ) {
			return round( $bytes / 1024, 1 ) . ' KB';
		}
		if ( $bytes < 1073741824 ) {
			return round( $bytes / 1048576, 2 ) . ' MB';
		}

		return round( $bytes / 1073741824, 2 ) . ' GB';
	}

	public static function admin_url(): string {
		if ( function_exists( 'admin_url' ) ) {
			return (string) admin_url( 'admin.php?page=' . self::PAGE_SLUG );
		}

		return 'admin.php?page=' . self::PAGE_SLUG;
	}

	/**
	 * Top senders roster rows.
	 *
	 * @return list<array<string,mixed>>
	 */
	public static function roster( ?string $as_of_day = null, ?array $counters = null ): array {
		$counters = is_array( $counters ) ? self::sanitize_counters( $counters ) : self::get_counters();
		$as_of    = self::sanitize_day_key( $as_of_day ?? '' );
		if ( '' === $as_of ) {
			$as_of = self::day_key();
		}
		$as_ts = strtotime( $as_of . ' UTC' );
		if ( false === $as_ts ) {
			$as_ts = Clock::now();
		}
		$week_start  = gmdate( 'Y-m-d', $as_ts - ( 6 * DAY_IN_SECONDS ) );
		$month_start = gmdate( 'Y-m-d', $as_ts - ( 29 * DAY_IN_SECONDS ) );

		$by_plugin = array();
		foreach ( $counters['days'] as $day => $cells ) {
			foreach ( $cells as $cell ) {
				$plugin = (string) $cell['plugin'];
				if ( ! isset( $by_plugin[ $plugin ] ) ) {
					$by_plugin[ $plugin ] = array(
						'plugin'      => $plugin,
						'today'       => 0,
						'week'        => 0,
						'month'       => 0,
						'max_request' => 0,
						'providers'   => array(),
						'trend'       => array(),
					);
				}
				$out = (int) $cell['bytes_out'];
				if ( $day === $as_of ) {
					$by_plugin[ $plugin ]['today'] += $out;
				}
				if ( $day >= $week_start && $day <= $as_of ) {
					$by_plugin[ $plugin ]['week'] += $out;
				}
				if ( $day >= $month_start && $day <= $as_of ) {
					$by_plugin[ $plugin ]['month'] += $out;
				}
				$by_plugin[ $plugin ]['max_request'] = max(
					(int) $by_plugin[ $plugin ]['max_request'],
					(int) $cell['max_request']
				);
				$prov = (string) $cell['provider'];
				if ( ! isset( $by_plugin[ $plugin ]['providers'][ $prov ] ) ) {
					$by_plugin[ $plugin ]['providers'][ $prov ] = 0;
				}
				$by_plugin[ $plugin ]['providers'][ $prov ] += $out;
				if ( ! isset( $by_plugin[ $plugin ]['trend'][ $day ] ) ) {
					$by_plugin[ $plugin ]['trend'][ $day ] = 0;
				}
				$by_plugin[ $plugin ]['trend'][ $day ] += $out;
			}
		}

		$rows = array_values( $by_plugin );
		usort(
			$rows,
			static function ( array $a, array $b ): int {
				if ( (int) $a['today'] !== (int) $b['today'] ) {
					return (int) $b['today'] <=> (int) $a['today'];
				}
				if ( (int) $a['week'] !== (int) $b['week'] ) {
					return (int) $b['week'] <=> (int) $a['week'];
				}

				return (int) $b['month'] <=> (int) $a['month'];
			}
		);

		foreach ( $rows as &$row ) {
			arsort( $row['providers'] );
			$row['top_provider'] = (string) ( array_key_first( $row['providers'] ) ?? '' );
			ksort( $row['trend'] );
			$row['trend_7'] = self::sparkline_values( $row['trend'], $as_of, 7 );
			unset( $row['providers'], $row['trend'] );
		}
		unset( $row );

		return $rows;
	}

	/**
	 * @param array<string,int> $trend day => bytes.
	 * @return list<int>
	 */
	public static function sparkline_values( array $trend, string $as_of, int $days ): array {
		$as_ts = strtotime( $as_of . ' UTC' );
		if ( false === $as_ts ) {
			$as_ts = Clock::now();
		}
		$out = array();
		for ( $i = $days - 1; $i >= 0; $i-- ) {
			$d     = gmdate( 'Y-m-d', $as_ts - ( $i * DAY_IN_SECONDS ) );
			$out[] = (int) ( $trend[ $d ] ?? 0 );
		}

		return $out;
	}

	/**
	 * @param list<int> $values Sparkline values.
	 */
	public static function format_sparkline( array $values ): string {
		if ( empty( $values ) ) {
			return '—';
		}
		$max = max( $values );
		if ( $max <= 0 ) {
			return str_repeat( '▁', count( $values ) );
		}
		$blocks = array( '▁', '▂', '▃', '▄', '▅', '▆', '▇', '█' );
		$out    = '';
		foreach ( $values as $v ) {
			$idx = (int) floor( ( (float) $v / (float) $max ) * 7 );
			if ( $idx < 0 ) {
				$idx = 0;
			}
			if ( $idx > 7 ) {
				$idx = 7;
			}
			$out .= $blocks[ $idx ];
		}

		return $out;
	}

	/**
	 * @param list<array<string,mixed>>|null $rows Roster rows.
	 */
	public static function csv_for_roster( ?array $rows = null ): string {
		$rows = is_array( $rows ) ? $rows : self::roster();
		$lines = array();
		$lines[] = self::csv_line(
			array(
				'plugin',
				'top_provider',
				'bytes_today',
				'bytes_7d',
				'bytes_30d',
				'max_request',
				'trend_7',
			)
		);
		foreach ( $rows as $row ) {
			$lines[] = self::csv_line(
				array(
					(string) ( $row['plugin'] ?? '' ),
					(string) ( $row['top_provider'] ?? '' ),
					(string) (int) ( $row['today'] ?? 0 ),
					(string) (int) ( $row['week'] ?? 0 ),
					(string) (int) ( $row['month'] ?? 0 ),
					(string) (int) ( $row['max_request'] ?? 0 ),
					self::format_sparkline( array_values( (array) ( $row['trend_7'] ?? array() ) ) ),
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
			$col = (string) $col;
			if ( false !== strpos( $col, '"' ) || false !== strpos( $col, ',' ) || false !== strpos( $col, "\n" ) ) {
				$col = '"' . str_replace( '"', '""', $col ) . '"';
			}
			$out[] = $col;
		}

		return implode( ',', $out );
	}

	/**
	 * @param list<array<string,mixed>> $rows Roster.
	 */
	public static function build_print_html( array $rows ): string {
		$html  = '<!DOCTYPE html><html><head><meta charset="utf-8"><title>';
		$html .= esc_html__( 'AI volume roster', 'handl-ai-connector-access-control' );
		$html .= '</title><style>body{font-family:sans-serif;margin:24px}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ccc;padding:6px 8px;text-align:left}th{background:#f6f7f7}</style></head><body>';
		$html .= '<h1>' . esc_html__( 'AI volume roster', 'handl-ai-connector-access-control' ) . '</h1>';
		$html .= '<p>' . esc_html__( 'Byte counts only. Informational — never denies.', 'handl-ai-connector-access-control' ) . '</p>';
		$html .= '<table><thead><tr>';
		$html .= '<th>' . esc_html__( 'Plugin', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '<th>' . esc_html__( 'Top provider', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '<th>' . esc_html__( 'Today', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '<th>' . esc_html__( '7d', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '<th>' . esc_html__( '30d', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '<th>' . esc_html__( 'Biggest request', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '<th>' . esc_html__( '7d trend', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '</tr></thead><tbody>';
		foreach ( $rows as $row ) {
			$html .= '<tr>';
			$html .= '<td>' . esc_html( (string) ( $row['plugin'] ?? '' ) ) . '</td>';
			$html .= '<td>' . esc_html( (string) ( $row['top_provider'] ?? '' ) ) . '</td>';
			$html .= '<td>' . esc_html( self::format_bytes( (int) ( $row['today'] ?? 0 ) ) ) . '</td>';
			$html .= '<td>' . esc_html( self::format_bytes( (int) ( $row['week'] ?? 0 ) ) ) . '</td>';
			$html .= '<td>' . esc_html( self::format_bytes( (int) ( $row['month'] ?? 0 ) ) ) . '</td>';
			$html .= '<td>' . esc_html( self::format_bytes( (int) ( $row['max_request'] ?? 0 ) ) ) . '</td>';
			$html .= '<td>' . esc_html( self::format_sparkline( array_values( (array) ( $row['trend_7'] ?? array() ) ) ) ) . '</td>';
			$html .= '</tr>';
		}
		$html .= '</tbody></table></body></html>';

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
			__( 'AI volume', 'handl-ai-connector-access-control' ),
			__( 'Volume', 'handl-ai-connector-access-control' ),
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
		$rows       = self::roster();
		$csv        = add_query_arg(
			array(
				'page'                   => self::PAGE_SLUG,
				'handl_aicac_volume_csv' => '1',
				'_wpnonce'               => function_exists( 'wp_create_nonce' ) ? wp_create_nonce( 'handl_aicac_volume_csv' ) : '',
			),
			admin_url( 'admin.php' )
		);
		$print = add_query_arg(
			array(
				'page'                     => self::PAGE_SLUG,
				'handl_aicac_volume_print' => '1',
				'_wpnonce'                 => function_exists( 'wp_create_nonce' ) ? wp_create_nonce( 'handl_aicac_volume_print' ) : '',
			),
			admin_url( 'admin.php' )
		);

		echo '<div class="wrap">';
		echo '<h1>' . esc_html__( 'AI volume', 'handl-ai-connector-access-control' ) . '</h1>';
		echo '<p class="description">' . esc_html__( 'Watch how many bytes leave for AI providers. Spikes can look like a data leak even when call-rate caps stay quiet. Byte counts only — never content. Informational; off by default.', 'handl-ai-connector-access-control' ) . '</p>';

		if ( $can_manage ) {
			$action = admin_url( 'admin-post.php' );
			echo '<form method="post" action="' . esc_url( $action ) . '">';
			echo '<input type="hidden" name="action" value="' . esc_attr( self::ACTION_SAVE ) . '" />';
			if ( function_exists( 'wp_nonce_field' ) ) {
				wp_nonce_field( self::ACTION_SAVE );
			}
			echo '<input type="hidden" name="' . esc_attr( self::POST_PRESENT ) . '" value="1" />';
			echo '<table class="form-table" role="presentation"><tbody>';
			echo '<tr><th scope="row">' . esc_html__( 'Enable volume watch', 'handl-ai-connector-access-control' ) . '</th><td>';
			echo '<label><input type="checkbox" name="' . esc_attr( self::POST_ENABLED ) . '" value="1" ' . checked( ! empty( $settings['enabled'] ), true, false ) . ' /> ';
			echo esc_html__( 'Measure outbound AI request sizes and alert on spikes', 'handl-ai-connector-access-control' );
			echo '</label></td></tr>';
			echo '<tr><th scope="row"><label for="handl-aicac-volume-spike">' . esc_html__( 'Spike multiple', 'handl-ai-connector-access-control' ) . '</label></th><td>';
			echo '<input name="' . esc_attr( self::POST_SPIKE ) . '" id="handl-aicac-volume-spike" type="number" min="1" max="1000" step="0.1" value="' . esc_attr( (string) $settings['spike_multiple'] ) . '" class="small-text" />';
			echo '<p class="description">' . esc_html__( 'Alert when today’s outbound bytes for a plugin reach this multiple of its trailing-day median. Default 10.', 'handl-ai-connector-access-control' ) . '</p>';
			echo '</td></tr>';
			$ceiling_mb = (int) $settings['daily_ceiling_bytes'] > 0
				? round( (int) $settings['daily_ceiling_bytes'] / 1048576, 2 )
				: 0;
			echo '<tr><th scope="row"><label for="handl-aicac-volume-ceiling">' . esc_html__( 'Daily ceiling (MB)', 'handl-ai-connector-access-control' ) . '</label></th><td>';
			echo '<input name="' . esc_attr( self::POST_CEILING ) . '" id="handl-aicac-volume-ceiling" type="number" min="0" max="10240" step="0.01" value="' . esc_attr( (string) $ceiling_mb ) . '" class="small-text" />';
			echo '<p class="description">' . esc_html__( 'Optional absolute outbound-bytes ceiling per plugin per day. 0 disables the ceiling (spike multiple still applies).', 'handl-ai-connector-access-control' ) . '</p>';
			echo '</td></tr></tbody></table>';
			submit_button( __( 'Save volume settings', 'handl-ai-connector-access-control' ) );
			echo '</form>';
		}

		echo '<h2>' . esc_html__( 'Top senders', 'handl-ai-connector-access-control' ) . '</h2>';
		echo '<p>';
		echo '<a class="button" href="' . esc_url( $csv ) . '">' . esc_html__( 'Download CSV', 'handl-ai-connector-access-control' ) . '</a> ';
		echo '<a class="button" href="' . esc_url( $print ) . '" target="_blank" rel="noopener noreferrer">' . esc_html__( 'Print / PDF view', 'handl-ai-connector-access-control' ) . '</a>';
		echo '</p>';

		if ( empty( $rows ) ) {
			echo '<p>' . esc_html__( 'No volume data yet. Enable the watch and wait for AI-destined HTTP traffic.', 'handl-ai-connector-access-control' ) . '</p>';
			echo '</div>';

			return;
		}

		echo '<table class="widefat striped"><thead><tr>';
		echo '<th>' . esc_html__( 'Plugin', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Top provider', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Today', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( '7d', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( '30d', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Biggest request', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( '7d trend', 'handl-ai-connector-access-control' ) . '</th>';
		echo '</tr></thead><tbody>';
		foreach ( $rows as $row ) {
			echo '<tr>';
			echo '<td><code>' . esc_html( (string) $row['plugin'] ) . '</code></td>';
			echo '<td>' . esc_html( (string) $row['top_provider'] ) . '</td>';
			echo '<td>' . esc_html( self::format_bytes( (int) $row['today'] ) ) . '</td>';
			echo '<td>' . esc_html( self::format_bytes( (int) $row['week'] ) ) . '</td>';
			echo '<td>' . esc_html( self::format_bytes( (int) $row['month'] ) ) . '</td>';
			echo '<td>' . esc_html( self::format_bytes( (int) $row['max_request'] ) ) . '</td>';
			echo '<td><span aria-hidden="true">' . esc_html( self::format_sparkline( array_values( (array) $row['trend_7'] ) ) ) . '</span></td>';
			echo '</tr>';
		}
		echo '</tbody></table></div>';
	}

	public static function maybe_handle_csv(): void {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( empty( $_GET['handl_aicac_volume_csv'] ) ) {
			return;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$page = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( (string) $_GET['page'] ) ) : '';
		if ( self::PAGE_SLUG !== $page ) {
			return;
		}
		if ( ! Caps::user_can_view() ) {
			return;
		}
		check_admin_referer( 'handl_aicac_volume_csv' );
		$csv = self::csv_for_roster();
		nocache_headers();
		header( 'Content-Type: text/csv; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename=handl-aicac-volume.csv' );
		echo $csv; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- CSV download.
		exit;
	}

	public static function maybe_handle_print(): void {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( empty( $_GET['handl_aicac_volume_print'] ) ) {
			return;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$page = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( (string) $_GET['page'] ) ) : '';
		if ( self::PAGE_SLUG !== $page ) {
			return;
		}
		if ( ! Caps::user_can_view() ) {
			return;
		}
		check_admin_referer( 'handl_aicac_volume_print' );
		$rows = self::roster();
		nocache_headers();
		header( 'Content-Type: text/html; charset=utf-8' );
		echo self::build_print_html( $rows ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped inside builder.
		exit;
	}

	public static function handle_save(): void {
		if ( ! Caps::user_can_manage() ) {
			if ( function_exists( 'wp_die' ) ) {
				wp_die( esc_html__( 'You do not have permission to save volume settings.', 'handl-ai-connector-access-control' ) );
			}
			return;
		}
		check_admin_referer( self::ACTION_SAVE );

		$enabled = ! empty( $_POST[ self::POST_ENABLED ] ); // phpcs:ignore WordPress.Security.NonceVerification.Missing
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		$spike_raw = isset( $_POST[ self::POST_SPIKE ] ) ? wp_unslash( (string) $_POST[ self::POST_SPIKE ] ) : '';
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		$ceiling_mb_raw = isset( $_POST[ self::POST_CEILING ] ) ? wp_unslash( (string) $_POST[ self::POST_CEILING ] ) : '';
		$ceiling_bytes  = 0;
		if ( is_numeric( $ceiling_mb_raw ) && (float) $ceiling_mb_raw > 0 ) {
			$ceiling_bytes = (int) round( (float) $ceiling_mb_raw * 1048576 );
		}

		self::save_settings(
			array(
				'enabled'             => $enabled,
				'spike_multiple'      => self::sanitize_spike_multiple( '' !== $spike_raw ? $spike_raw : self::DEFAULT_SPIKE_MULTIPLE ),
				'daily_ceiling_bytes' => self::sanitize_daily_ceiling( $ceiling_bytes ),
			)
		);
		if ( self::is_enabled() ) {
			self::register_http_hook();
		}

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
		\WP_CLI::add_command( 'handl-aicac volume', CLI_Volume::class );
	}
}

/**
 * WP-CLI: wp handl-aicac volume status|export
 */
final class CLI_Volume {

	/**
	 * Show volume watch status and top senders.
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
		$settings = Volume::get_settings();
		$rows     = Volume::roster();
		$format   = isset( $assoc_args['format'] ) ? (string) $assoc_args['format'] : 'table';

		\WP_CLI::log(
			sprintf(
				'enabled=%s spike_multiple=%s daily_ceiling_bytes=%d senders=%d',
				! empty( $settings['enabled'] ) ? 'yes' : 'no',
				(string) $settings['spike_multiple'],
				(int) $settings['daily_ceiling_bytes'],
				count( $rows )
			)
		);

		if ( empty( $rows ) ) {
			\WP_CLI::log( 'No volume rows.' );
			return;
		}

		$display = array();
		foreach ( $rows as $row ) {
			$display[] = array(
				'plugin'       => (string) $row['plugin'],
				'top_provider' => (string) $row['top_provider'],
				'today'        => (int) $row['today'],
				'week'         => (int) $row['week'],
				'month'        => (int) $row['month'],
				'max_request'  => (int) $row['max_request'],
			);
		}
		if ( 'json' === $format ) {
			\WP_CLI::print_value( $display, array( 'format' => 'json' ) );
			return;
		}
		\WP_CLI\Utils\format_items(
			'table',
			$display,
			array( 'plugin', 'top_provider', 'today', 'week', 'month', 'max_request' )
		);
	}

	/**
	 * Export the volume roster as CSV.
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
		$csv = Volume::csv_for_roster();
		if ( ! empty( $assoc_args['porcelain'] ) ) {
			echo $csv; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- CLI CSV.
			return;
		}
		\WP_CLI::print_value( $csv, array( 'format' => 'csv' ) );
	}
}
