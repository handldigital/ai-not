<?php
/**
 * AICAC-CARBON (#387): AI sustainability ledger (kWh / CO2e estimates).
 *
 * Reads the activity log + token counts read-only (Cost helpers class_exists-
 * guarded). Bundled kWh-per-1M-token factor table + grid-intensity default +
 * handl_aicac_carbon_factors filter; staleness-age nudge (model-eol pattern).
 * Daily/monthly rollups per plugin/provider in the class's own option. Roster
 * with explicit estimate framing + print + CSV. WP-CLI carbon status|export.
 * Informational only — never denies. OFF by default. No admin.php/policy.php/
 * cost.php/logger/rates-feed edits.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Directional AI energy / CO2e estimates from tokens we already log.
 */
final class Carbon {

	public const SETTINGS_OPTION = 'handl_aicac_carbon';

	public const ROLLUPS_OPTION = 'handl_aicac_carbon_rollups';

	public const PAGE_SLUG = 'handl-aicac-carbon';

	public const FILTER_FACTORS = 'handl_aicac_carbon_factors';

	/** Absolute ship date of the bundled factor table (Y-m-d). */
	public const BUNDLED_SHIPPED = '2026-10-01';

	/** Days after factor-table age before the on-screen staleness nudge. */
	public const STALE_AFTER_DAYS = 120;

	/** Rolling day window retained in the rollups option. */
	public const WINDOW_DAYS = 90;

	/** Default kWh per 1M tokens when no model family matches. */
	public const DEFAULT_KWH_PER_1M = 0.5;

	/** Default grid intensity kgCO2e / kWh (global-average directional). */
	public const DEFAULT_GRID_KG_PER_KWH = 0.475;

	public const UNKNOWN_PLUGIN = '(unknown)';

	public const UNKNOWN_PROVIDER = '(unknown)';

	public const POST_PRESENT = 'handl_aicac_carbon_present';

	public const POST_ENABLED = 'handl_aicac_carbon_enabled';

	public const ACTION_SAVE = 'handl_aicac_carbon_save';

	/** @var bool */
	private static $registered = false;

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
			add_action( 'init', array( self::class, 'maybe_rebuild_rollups' ), 30 );
			if ( function_exists( 'is_admin' ) && is_admin() ) {
				add_action( 'admin_notices', array( self::class, 'maybe_staleness_notice' ) );
			}
		}

		self::register_cli();
	}

	public static function reset_for_tests(): void {
		self::$registered = false;
		delete_option( self::SETTINGS_OPTION );
		delete_option( self::ROLLUPS_OPTION );
	}

	/**
	 * @return array{enabled:bool}
	 */
	public static function defaults(): array {
		return array(
			'enabled' => false,
		);
	}

	/**
	 * @return array{enabled:bool}
	 */
	public static function get_settings(): array {
		return self::sanitize_settings( get_option( self::SETTINGS_OPTION, array() ) );
	}

	/**
	 * @param mixed $raw Raw settings.
	 * @return array{enabled:bool}
	 */
	public static function sanitize_settings( $raw ): array {
		$defaults = self::defaults();
		if ( ! is_array( $raw ) ) {
			return $defaults;
		}

		return array(
			'enabled' => ! empty( $raw['enabled'] ),
		);
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

	/**
	 * Bundled energy factors. Directional research-shaped defaults — not
	 * compliance-grade. Override via {@see FILTER_FACTORS}.
	 *
	 * @return array{
	 *   shipped:string,
	 *   grid_kg_per_kwh:float,
	 *   default_kwh_per_1m:float,
	 *   models:array<string,float>
	 * }
	 */
	public static function bundled_factors(): array {
		return array(
			'shipped'            => self::BUNDLED_SHIPPED,
			'grid_kg_per_kwh'    => self::DEFAULT_GRID_KG_PER_KWH,
			'default_kwh_per_1m' => self::DEFAULT_KWH_PER_1M,
			// Longest matching model-id prefix wins (see kwh_per_1m_for_model).
			'models'             => array(
				'gpt-4o-mini'         => 0.15,
				'gpt-4o'              => 0.35,
				'gpt-4-turbo'         => 0.7,
				'gpt-4'               => 0.8,
				'gpt-3.5'             => 0.2,
				'o1-mini'             => 0.6,
				'o1'                  => 1.2,
				'claude-opus'         => 0.9,
				'claude-3-opus'       => 0.9,
				'claude-sonnet'       => 0.4,
				'claude-3-5-sonnet'   => 0.4,
				'claude-3-sonnet'     => 0.4,
				'claude-haiku'        => 0.15,
				'claude-3-haiku'      => 0.15,
				'claude-3-5-haiku'    => 0.15,
				'gemini-2.0-flash'    => 0.2,
				'gemini-1.5-flash'    => 0.2,
				'gemini-2.0-pro'      => 0.55,
				'gemini-1.5-pro'      => 0.5,
				'gemini'              => 0.4,
				'mistral-large'       => 0.55,
				'mistral-small'       => 0.25,
				'mistral'             => 0.3,
				'llama-3.1-405b'      => 1.0,
				'llama-3.1-70b'       => 0.55,
				'llama'               => 0.35,
				'deepseek'            => 0.25,
			),
		);
	}

	/**
	 * Effective factors after the public filter.
	 *
	 * @return array{
	 *   shipped:string,
	 *   grid_kg_per_kwh:float,
	 *   default_kwh_per_1m:float,
	 *   models:array<string,float>
	 * }
	 */
	public static function factors(): array {
		$bundled = self::bundled_factors();
		/**
		 * Filter the AI energy factor table (kWh per 1M tokens + grid intensity).
		 *
		 * @param array<string,mixed> $factors Factor table.
		 */
		$filtered = apply_filters( self::FILTER_FACTORS, $bundled );

		return self::sanitize_factors( $filtered, $bundled );
	}

	/**
	 * @param mixed               $raw      Filtered value.
	 * @param array<string,mixed> $fallback Bundled fallback.
	 * @return array{
	 *   shipped:string,
	 *   grid_kg_per_kwh:float,
	 *   default_kwh_per_1m:float,
	 *   models:array<string,float>
	 * }
	 */
	public static function sanitize_factors( $raw, ?array $fallback = null ): array {
		$fallback = is_array( $fallback ) ? $fallback : self::bundled_factors();
		if ( ! is_array( $raw ) ) {
			return $fallback;
		}

		$shipped = isset( $raw['shipped'] ) ? self::sanitize_day_key( (string) $raw['shipped'] ) : '';
		if ( '' === $shipped ) {
			$shipped = self::sanitize_day_key( (string) ( $fallback['shipped'] ?? self::BUNDLED_SHIPPED ) );
		}
		if ( '' === $shipped ) {
			$shipped = self::BUNDLED_SHIPPED;
		}

		$grid = isset( $raw['grid_kg_per_kwh'] ) && is_numeric( $raw['grid_kg_per_kwh'] )
			? (float) $raw['grid_kg_per_kwh']
			: (float) ( $fallback['grid_kg_per_kwh'] ?? self::DEFAULT_GRID_KG_PER_KWH );
		$grid = self::clamp_positive_float( $grid, self::DEFAULT_GRID_KG_PER_KWH, 0.0, 5.0 );

		$default = isset( $raw['default_kwh_per_1m'] ) && is_numeric( $raw['default_kwh_per_1m'] )
			? (float) $raw['default_kwh_per_1m']
			: (float) ( $fallback['default_kwh_per_1m'] ?? self::DEFAULT_KWH_PER_1M );
		$default = self::clamp_positive_float( $default, self::DEFAULT_KWH_PER_1M, 0.0, 100.0 );

		$models_raw = isset( $raw['models'] ) && is_array( $raw['models'] ) ? $raw['models'] : array();
		$models     = array();
		foreach ( $models_raw as $id => $kwh ) {
			$model = self::sanitize_model_id( (string) $id );
			if ( '' === $model || ! is_numeric( $kwh ) ) {
				continue;
			}
			$models[ $model ] = self::clamp_positive_float( (float) $kwh, $default, 0.0, 100.0 );
		}
		if ( empty( $models ) && isset( $fallback['models'] ) && is_array( $fallback['models'] ) ) {
			foreach ( $fallback['models'] as $id => $kwh ) {
				$model = self::sanitize_model_id( (string) $id );
				if ( '' === $model || ! is_numeric( $kwh ) ) {
					continue;
				}
				$models[ $model ] = self::clamp_positive_float( (float) $kwh, $default, 0.0, 100.0 );
			}
		}

		return array(
			'shipped'            => $shipped,
			'grid_kg_per_kwh'    => $grid,
			'default_kwh_per_1m' => $default,
			'models'             => $models,
		);
	}

	public static function sanitize_model_id( string $raw ): string {
		$raw = strtolower( trim( $raw ) );
		$raw = preg_replace( '/[^a-z0-9._*-]/', '', $raw ) ?? '';

		return $raw;
	}

	public static function sanitize_day_key( string $raw ): string {
		$raw = trim( $raw );
		if ( ! preg_match( '/^(\d{4})-(\d{2})-(\d{2})$/', $raw, $parts ) ) {
			return '';
		}
		$y = (int) $parts[1];
		$m = (int) $parts[2];
		$d = (int) $parts[3];
		if ( $y < 1970 || $y > 2100 || ! checkdate( $m, $d, $y ) ) {
			return '';
		}

		return sprintf( '%04d-%02d-%02d', $y, $m, $d );
	}

	public static function sanitize_month_key( string $raw ): string {
		$raw = trim( $raw );
		if ( ! preg_match( '/^(\d{4})-(\d{2})$/', $raw, $parts ) ) {
			return '';
		}
		$y = (int) $parts[1];
		$m = (int) $parts[2];
		if ( $y < 1970 || $y > 2100 || $m < 1 || $m > 12 ) {
			return '';
		}

		return sprintf( '%04d-%02d', $y, $m );
	}

	public static function day_key( ?int $ts = null ): string {
		$ts = null !== $ts && $ts > 0 ? $ts : ( class_exists( Clock::class, false ) ? Clock::now() : time() );

		return gmdate( 'Y-m-d', $ts );
	}

	public static function month_key( ?int $ts = null ): string {
		$ts = null !== $ts && $ts > 0 ? $ts : ( class_exists( Clock::class, false ) ? Clock::now() : time() );

		return gmdate( 'Y-m', $ts );
	}

	/**
	 * Longest matching model-id prefix wins; otherwise the default factor.
	 *
	 * @param array<string,mixed>|null $factors Optional factors override.
	 */
	public static function kwh_per_1m_for_model( string $model, ?array $factors = null ): float {
		$factors = is_array( $factors ) ? self::sanitize_factors( $factors ) : self::factors();
		$model   = self::sanitize_model_id( $model );
		$default = (float) $factors['default_kwh_per_1m'];
		if ( '' === $model ) {
			return $default;
		}

		$best_len = -1;
		$best     = $default;
		foreach ( $factors['models'] as $pattern => $kwh ) {
			$pattern = self::sanitize_model_id( (string) $pattern );
			if ( '' === $pattern ) {
				continue;
			}
			if ( ! self::model_matches( $pattern, $model ) ) {
				continue;
			}
			$len = strlen( rtrim( $pattern, '*' ) );
			if ( $len > $best_len ) {
				$best_len = $len;
				$best     = (float) $kwh;
			}
		}

		return $best;
	}

	public static function model_matches( string $pattern, string $model ): bool {
		$pattern = self::sanitize_model_id( $pattern );
		$model   = self::sanitize_model_id( $model );
		if ( '' === $pattern || '' === $model ) {
			return false;
		}
		if ( $pattern === $model ) {
			return true;
		}
		if ( str_ends_with( $pattern, '*' ) ) {
			$prefix = substr( $pattern, 0, -1 );

			return '' === $prefix || str_starts_with( $model, $prefix );
		}

		return str_starts_with( $model, $pattern );
	}

	/**
	 * @param array{kwh:float,kg_co2e:float} $energy Energy pair.
	 * @param array<string,mixed>|null       $factors Optional factors.
	 * @return array{kwh:float,kg_co2e:float}
	 */
	public static function energy_for_tokens( int $tokens, string $model = '', ?array $factors = null ): array {
		$factors = is_array( $factors ) ? self::sanitize_factors( $factors ) : self::factors();
		$tokens  = max( 0, $tokens );
		$kwh     = ( $tokens / 1_000_000 ) * self::kwh_per_1m_for_model( $model, $factors );
		$kg      = $kwh * (float) $factors['grid_kg_per_kwh'];

		return array(
			'kwh'     => $kwh,
			'kg_co2e' => $kg,
		);
	}

	/**
	 * Unix timestamp representing factor-table freshness.
	 */
	public static function factors_age_ts( ?int $now = null ): int {
		unset( $now );
		$factors = self::factors();
		$shipped = strtotime( (string) $factors['shipped'] . ' UTC' );

		return false !== $shipped ? (int) $shipped : 0;
	}

	public static function is_factors_stale( ?int $now = null ): bool {
		$now = null !== $now && $now > 0 ? $now : time();
		$age = self::factors_age_ts( $now );
		if ( $age <= 0 ) {
			return false;
		}
		$day = defined( 'DAY_IN_SECONDS' ) ? (int) DAY_IN_SECONDS : 86400;

		return ( $now - $age ) > ( self::STALE_AFTER_DAYS * $day );
	}

	/**
	 * @return array{
	 *   updated_at:int,
	 *   days:array<string,array<string,array<string,mixed>>>,
	 *   months:array<string,array<string,array<string,mixed>>>
	 * }
	 */
	public static function empty_rollups(): array {
		return array(
			'updated_at' => 0,
			'days'       => array(),
			'months'     => array(),
		);
	}

	/**
	 * @return array{
	 *   updated_at:int,
	 *   days:array<string,array<string,array<string,mixed>>>,
	 *   months:array<string,array<string,array<string,mixed>>>
	 * }
	 */
	public static function get_rollups(): array {
		return self::sanitize_rollups( get_option( self::ROLLUPS_OPTION, array() ) );
	}

	/**
	 * @param mixed $raw Raw rollups.
	 * @return array{
	 *   updated_at:int,
	 *   days:array<string,array<string,array<string,mixed>>>,
	 *   months:array<string,array<string,array<string,mixed>>>
	 * }
	 */
	public static function sanitize_rollups( $raw ): array {
		$empty = self::empty_rollups();
		if ( ! is_array( $raw ) ) {
			return $empty;
		}
		$out = array(
			'updated_at' => isset( $raw['updated_at'] ) ? max( 0, (int) $raw['updated_at'] ) : 0,
			'days'       => array(),
			'months'     => array(),
		);
		if ( isset( $raw['days'] ) && is_array( $raw['days'] ) ) {
			foreach ( $raw['days'] as $day => $cells ) {
				$day = self::sanitize_day_key( (string) $day );
				if ( '' === $day || ! is_array( $cells ) ) {
					continue;
				}
				foreach ( $cells as $cell ) {
					$clean = self::sanitize_cell( $cell );
					if ( null === $clean ) {
						continue;
					}
					$key = self::cell_key( $clean['plugin'], $clean['provider'] );
					$out['days'][ $day ][ $key ] = $clean;
				}
			}
		}
		if ( isset( $raw['months'] ) && is_array( $raw['months'] ) ) {
			foreach ( $raw['months'] as $month => $cells ) {
				$month = self::sanitize_month_key( (string) $month );
				if ( '' === $month || ! is_array( $cells ) ) {
					continue;
				}
				foreach ( $cells as $cell ) {
					$clean = self::sanitize_cell( $cell );
					if ( null === $clean ) {
						continue;
					}
					$key = self::cell_key( $clean['plugin'], $clean['provider'] );
					$out['months'][ $month ][ $key ] = $clean;
				}
			}
		}

		return $out;
	}

	/**
	 * @param mixed $cell Raw cell.
	 * @return array{plugin:string,provider:string,calls:int,tokens:int,kwh:float,kg_co2e:float}|null
	 */
	public static function sanitize_cell( $cell ): ?array {
		if ( ! is_array( $cell ) ) {
			return null;
		}
		$plugin   = self::sanitize_plugin( (string) ( $cell['plugin'] ?? '' ) );
		$provider = self::sanitize_provider( (string) ( $cell['provider'] ?? '' ) );

		return array(
			'plugin'   => $plugin,
			'provider' => $provider,
			'calls'    => max( 0, (int) ( $cell['calls'] ?? 0 ) ),
			'tokens'   => max( 0, (int) ( $cell['tokens'] ?? 0 ) ),
			'kwh'      => max( 0.0, (float) ( $cell['kwh'] ?? 0 ) ),
			'kg_co2e'  => max( 0.0, (float) ( $cell['kg_co2e'] ?? 0 ) ),
		);
	}

	public static function sanitize_plugin( string $raw ): string {
		$raw = trim( $raw );
		if ( '' === $raw ) {
			return self::UNKNOWN_PLUGIN;
		}
		if ( function_exists( 'sanitize_text_field' ) ) {
			$raw = sanitize_text_field( $raw );
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
		$id = strtolower( trim( $raw ) );
		$id = preg_replace( '/[^a-z0-9_-]/', '', $id ) ?? '';

		return '' !== $id ? $id : self::UNKNOWN_PROVIDER;
	}

	public static function cell_key( string $plugin, string $provider ): string {
		return self::sanitize_plugin( $plugin ) . "\0" . self::sanitize_provider( $provider );
	}

	/**
	 * Rebuild rollups from the retained activity log. No-op when the feature is off
	 * unless $force is true (tests / CLI).
	 *
	 * @param list<array<string,mixed>>|null $log Optional log override.
	 * @return array{
	 *   updated_at:int,
	 *   days:array<string,array<string,array<string,mixed>>>,
	 *   months:array<string,array<string,array<string,mixed>>>
	 * }
	 */
	public static function rebuild_rollups( ?array $log = null, ?int $now = null, bool $force = false ): array {
		if ( ! $force && ! self::is_enabled() ) {
			return self::empty_rollups();
		}
		$now     = null !== $now && $now > 0 ? $now : ( class_exists( Clock::class, false ) ? Clock::now() : time() );
		$factors = self::factors();
		if ( null === $log ) {
			$log = class_exists( Policy::class, false ) ? Policy::get_retained_log() : array();
		}
		if ( class_exists( Demo_Mode::class, false ) ) {
			$log = Demo_Mode::without_demo( $log );
		}

		$days   = array();
		$months = array();
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
			if ( isset( $row['channel'] ) && 'direct_http' === (string) $row['channel'] ) {
				// Token estimates live on AI Client rows; skip raw HTTP probes.
				continue;
			}

			$has_in  = array_key_exists( 'input_tokens', $row );
			$has_out = array_key_exists( 'output_tokens', $row );
			if ( ! $has_in && ! $has_out ) {
				continue;
			}
			$in     = $has_in ? max( 0, (int) $row['input_tokens'] ) : 0;
			$out    = $has_out ? max( 0, (int) $row['output_tokens'] ) : 0;
			$tokens = $in + $out;
			if ( $tokens <= 0 ) {
				continue;
			}

			$ts = isset( $row['ts'] ) ? (int) $row['ts'] : 0;
			if ( $ts <= 0 ) {
				$ts = $now;
			}
			$day   = self::day_key( $ts );
			$month = self::month_key( $ts );
			$plugin   = self::sanitize_plugin( (string) ( $row['plugin'] ?? '' ) );
			$provider = self::sanitize_provider( (string) ( $row['provider'] ?? '' ) );
			$model    = '';
			foreach ( array( 'model', 'pin_model', 'forced_model' ) as $field ) {
				$candidate = self::sanitize_model_id( (string) ( $row[ $field ] ?? '' ) );
				if ( '' !== $candidate ) {
					$model = $candidate;
					break;
				}
			}
			$count  = isset( $row['count'] ) ? max( 1, (int) $row['count'] ) : 1;
			$tokens = $tokens * $count;
			$energy = self::energy_for_tokens( $tokens, $model, $factors );
			$key    = self::cell_key( $plugin, $provider );

			if ( ! isset( $days[ $day ][ $key ] ) ) {
				$days[ $day ][ $key ] = array(
					'plugin'   => $plugin,
					'provider' => $provider,
					'calls'    => 0,
					'tokens'   => 0,
					'kwh'      => 0.0,
					'kg_co2e'  => 0.0,
				);
			}
			$days[ $day ][ $key ]['calls']   += $count;
			$days[ $day ][ $key ]['tokens']  += $tokens;
			$days[ $day ][ $key ]['kwh']     += $energy['kwh'];
			$days[ $day ][ $key ]['kg_co2e'] += $energy['kg_co2e'];

			if ( ! isset( $months[ $month ][ $key ] ) ) {
				$months[ $month ][ $key ] = array(
					'plugin'   => $plugin,
					'provider' => $provider,
					'calls'    => 0,
					'tokens'   => 0,
					'kwh'      => 0.0,
					'kg_co2e'  => 0.0,
				);
			}
			$months[ $month ][ $key ]['calls']   += $count;
			$months[ $month ][ $key ]['tokens']  += $tokens;
			$months[ $month ][ $key ]['kwh']     += $energy['kwh'];
			$months[ $month ][ $key ]['kg_co2e'] += $energy['kg_co2e'];
		}

		$days = self::evict_days( $days, $now );
		ksort( $months );

		$rollups = array(
			'updated_at' => $now,
			'days'       => $days,
			'months'     => $months,
		);
		$rollups = self::sanitize_rollups( $rollups );
		if ( empty( $rollups['days'] ) && empty( $rollups['months'] ) ) {
			delete_option( self::ROLLUPS_OPTION );
		} else {
			update_option( self::ROLLUPS_OPTION, $rollups, false );
		}

		return $rollups;
	}

	/**
	 * @param array<string,array<string,array<string,mixed>>> $days Day map.
	 * @return array<string,array<string,array<string,mixed>>>
	 */
	public static function evict_days( array $days, ?int $now = null ): array {
		$now = null !== $now && $now > 0 ? $now : time();
		$day = defined( 'DAY_IN_SECONDS' ) ? (int) DAY_IN_SECONDS : 86400;
		$cut = self::day_key( $now - ( ( self::WINDOW_DAYS - 1 ) * $day ) );
		foreach ( array_keys( $days ) as $key ) {
			if ( (string) $key < $cut ) {
				unset( $days[ $key ] );
			}
		}
		ksort( $days );
		while ( count( $days ) > self::WINDOW_DAYS ) {
			$first = array_key_first( $days );
			if ( null === $first ) {
				break;
			}
			unset( $days[ $first ] );
		}

		return $days;
	}

	/**
	 * Throttled rebuild (at most once per hour) when the feature is on.
	 */
	public static function maybe_rebuild_rollups( ?int $now = null ): void {
		if ( ! self::is_enabled() ) {
			return;
		}
		$now     = null !== $now && $now > 0 ? $now : time();
		$rollups = self::get_rollups();
		$hour = defined( 'HOUR_IN_SECONDS' ) ? (int) HOUR_IN_SECONDS : 3600;
		if ( (int) $rollups['updated_at'] > 0 && ( $now - (int) $rollups['updated_at'] ) < $hour ) {
			return;
		}
		self::rebuild_rollups( null, $now, true );
	}

	/**
	 * Plugin roster with estimate framing fields.
	 *
	 * @return list<array<string,mixed>>
	 */
	public static function roster( ?string $as_of_day = null, ?array $rollups = null, bool $rebuild = true ): array {
		if ( $rebuild && self::is_enabled() && null === $rollups ) {
			$rollups = self::rebuild_rollups( null, null, true );
		} else {
			$rollups = is_array( $rollups ) ? self::sanitize_rollups( $rollups ) : self::get_rollups();
		}
		$as_of = self::sanitize_day_key( $as_of_day ?? '' );
		if ( '' === $as_of ) {
			$as_of = self::day_key();
		}
		$as_ts = strtotime( $as_of . ' UTC' );
		if ( false === $as_ts ) {
			$as_ts = time();
		}
		$month = self::month_key( $as_ts );

		$by_plugin = array();
		$day_cells = $rollups['days'][ $as_of ] ?? array();
		foreach ( $day_cells as $cell ) {
			$plugin = (string) $cell['plugin'];
			if ( ! isset( $by_plugin[ $plugin ] ) ) {
				$by_plugin[ $plugin ] = self::empty_roster_row( $plugin );
			}
			$by_plugin[ $plugin ]['today_calls']  += (int) $cell['calls'];
			$by_plugin[ $plugin ]['today_tokens'] += (int) $cell['tokens'];
			$by_plugin[ $plugin ]['today_kwh']    += (float) $cell['kwh'];
			$by_plugin[ $plugin ]['today_kg']     += (float) $cell['kg_co2e'];
			$prov = (string) $cell['provider'];
			if ( ! isset( $by_plugin[ $plugin ]['providers'][ $prov ] ) ) {
				$by_plugin[ $plugin ]['providers'][ $prov ] = 0.0;
			}
			$by_plugin[ $plugin ]['providers'][ $prov ] += (float) $cell['kwh'];
		}

		$month_cells = $rollups['months'][ $month ] ?? array();
		foreach ( $month_cells as $cell ) {
			$plugin = (string) $cell['plugin'];
			if ( ! isset( $by_plugin[ $plugin ] ) ) {
				$by_plugin[ $plugin ] = self::empty_roster_row( $plugin );
			}
			$by_plugin[ $plugin ]['month_calls']  += (int) $cell['calls'];
			$by_plugin[ $plugin ]['month_tokens'] += (int) $cell['tokens'];
			$by_plugin[ $plugin ]['month_kwh']    += (float) $cell['kwh'];
			$by_plugin[ $plugin ]['month_kg']     += (float) $cell['kg_co2e'];
			$prov = (string) $cell['provider'];
			if ( ! isset( $by_plugin[ $plugin ]['providers'][ $prov ] ) ) {
				$by_plugin[ $plugin ]['providers'][ $prov ] = 0.0;
			}
			$by_plugin[ $plugin ]['providers'][ $prov ] += (float) $cell['kwh'];
		}

		$rows = array_values( $by_plugin );
		usort(
			$rows,
			static function ( array $a, array $b ): int {
				if ( (float) $a['month_kwh'] !== (float) $b['month_kwh'] ) {
					return (float) $b['month_kwh'] <=> (float) $a['month_kwh'];
				}

				return (float) $b['today_kwh'] <=> (float) $a['today_kwh'];
			}
		);

		foreach ( $rows as &$row ) {
			arsort( $row['providers'] );
			$row['top_provider'] = (string) ( array_key_first( $row['providers'] ) ?? '' );
			unset( $row['providers'] );
			$row['estimate'] = true;
		}
		unset( $row );

		return $rows;
	}

	/**
	 * @return array<string,mixed>
	 */
	private static function empty_roster_row( string $plugin ): array {
		return array(
			'plugin'       => $plugin,
			'today_calls'  => 0,
			'today_tokens' => 0,
			'today_kwh'    => 0.0,
			'today_kg'     => 0.0,
			'month_calls'  => 0,
			'month_tokens' => 0,
			'month_kwh'    => 0.0,
			'month_kg'     => 0.0,
			'providers'    => array(),
			'top_provider' => '',
			'estimate'     => true,
		);
	}

	/**
	 * Provider-level roster (same windows).
	 *
	 * @return list<array<string,mixed>>
	 */
	public static function provider_roster( ?string $as_of_day = null, ?array $rollups = null, bool $rebuild = true ): array {
		if ( $rebuild && self::is_enabled() && null === $rollups ) {
			$rollups = self::rebuild_rollups( null, null, true );
		} else {
			$rollups = is_array( $rollups ) ? self::sanitize_rollups( $rollups ) : self::get_rollups();
		}
		$as_of = self::sanitize_day_key( $as_of_day ?? '' );
		if ( '' === $as_of ) {
			$as_of = self::day_key();
		}
		$as_ts = strtotime( $as_of . ' UTC' );
		if ( false === $as_ts ) {
			$as_ts = time();
		}
		$month = self::month_key( $as_ts );

		$by = array();
		foreach ( ( $rollups['days'][ $as_of ] ?? array() ) as $cell ) {
			$provider = (string) $cell['provider'];
			if ( ! isset( $by[ $provider ] ) ) {
				$by[ $provider ] = array(
					'provider'     => $provider,
					'today_kwh'    => 0.0,
					'today_kg'     => 0.0,
					'today_tokens' => 0,
					'month_kwh'    => 0.0,
					'month_kg'     => 0.0,
					'month_tokens' => 0,
					'estimate'     => true,
				);
			}
			$by[ $provider ]['today_kwh']    += (float) $cell['kwh'];
			$by[ $provider ]['today_kg']     += (float) $cell['kg_co2e'];
			$by[ $provider ]['today_tokens'] += (int) $cell['tokens'];
		}
		foreach ( ( $rollups['months'][ $month ] ?? array() ) as $cell ) {
			$provider = (string) $cell['provider'];
			if ( ! isset( $by[ $provider ] ) ) {
				$by[ $provider ] = array(
					'provider'     => $provider,
					'today_kwh'    => 0.0,
					'today_kg'     => 0.0,
					'today_tokens' => 0,
					'month_kwh'    => 0.0,
					'month_kg'     => 0.0,
					'month_tokens' => 0,
					'estimate'     => true,
				);
			}
			$by[ $provider ]['month_kwh']    += (float) $cell['kwh'];
			$by[ $provider ]['month_kg']     += (float) $cell['kg_co2e'];
			$by[ $provider ]['month_tokens'] += (int) $cell['tokens'];
		}

		$rows = array_values( $by );
		usort(
			$rows,
			static function ( array $a, array $b ): int {
				return (float) $b['month_kwh'] <=> (float) $a['month_kwh'];
			}
		);

		return $rows;
	}

	public static function format_kwh( float $kwh ): string {
		if ( $kwh > 0 && $kwh < 0.0001 ) {
			return '<0.0001';
		}
		$decimals = $kwh >= 1 ? 3 : 4;

		return function_exists( 'number_format_i18n' )
			? number_format_i18n( $kwh, $decimals )
			: number_format( $kwh, $decimals, '.', ',' );
	}

	public static function format_kg( float $kg ): string {
		if ( $kg > 0 && $kg < 0.0001 ) {
			return '<0.0001';
		}
		$decimals = $kg >= 1 ? 3 : 4;

		return function_exists( 'number_format_i18n' )
			? number_format_i18n( $kg, $decimals )
			: number_format( $kg, $decimals, '.', ',' );
	}

	/**
	 * @param list<array<string,mixed>>|null $rows Plugin roster.
	 */
	public static function csv_for_roster( ?array $rows = null ): string {
		$rows  = is_array( $rows ) ? $rows : self::roster();
		$lines = array();
		$lines[] = self::csv_line(
			array(
				'estimate_framing',
				'plugin',
				'top_provider',
				'today_tokens',
				'today_kwh_est',
				'today_kg_co2e_est',
				'month_tokens',
				'month_kwh_est',
				'month_kg_co2e_est',
			)
		);
		foreach ( $rows as $row ) {
			$lines[] = self::csv_line(
				array(
					'directional_estimate_not_compliance_grade',
					(string) ( $row['plugin'] ?? '' ),
					(string) ( $row['top_provider'] ?? '' ),
					(string) (int) ( $row['today_tokens'] ?? 0 ),
					self::csv_float( (float) ( $row['today_kwh'] ?? 0 ) ),
					self::csv_float( (float) ( $row['today_kg'] ?? 0 ) ),
					(string) (int) ( $row['month_tokens'] ?? 0 ),
					self::csv_float( (float) ( $row['month_kwh'] ?? 0 ) ),
					self::csv_float( (float) ( $row['month_kg'] ?? 0 ) ),
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

	public static function csv_float( float $n ): string {
		return rtrim( rtrim( sprintf( '%.8F', $n ), '0' ), '.' );
	}

	/**
	 * @param list<array<string,mixed>> $rows Plugin roster.
	 */
	public static function build_print_html( array $rows ): string {
		$factors = self::factors();
		$html    = '<!DOCTYPE html><html><head><meta charset="utf-8"><title>';
		$html   .= esc_html__( 'AI sustainability ledger (estimates)', 'handl-ai-connector-access-control' );
		$html   .= '</title><style>body{font-family:sans-serif;margin:24px}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ccc;padding:6px 8px;text-align:left}th{background:#f6f7f7}.note{color:#646970;max-width:52rem}</style></head><body>';
		$html   .= '<h1>' . esc_html__( 'AI sustainability ledger', 'handl-ai-connector-access-control' ) . '</h1>';
		$html   .= '<p class="note"><strong>' . esc_html__( 'Estimate, directional — not compliance-grade.', 'handl-ai-connector-access-control' ) . '</strong> ';
		$html   .= esc_html__( 'kWh and CO2e are multiplied from logged token counts and a bundled factor table. Use for ESG binders as an internal estimate only.', 'handl-ai-connector-access-control' );
		$html   .= '</p>';
		$html   .= '<p class="note">' . esc_html(
			sprintf(
				/* translators: 1: grid intensity, 2: default kWh per 1M tokens */
				__( 'Grid intensity default: %1$s kgCO2e/kWh. Default model factor: %2$s kWh per 1M tokens.', 'handl-ai-connector-access-control' ),
				self::format_kg( (float) $factors['grid_kg_per_kwh'] ),
				self::format_kwh( (float) $factors['default_kwh_per_1m'] )
			)
		) . '</p>';
		$html .= '<table><thead><tr>';
		$html .= '<th>' . esc_html__( 'Plugin', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '<th>' . esc_html__( 'Top provider', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '<th>' . esc_html__( 'Today kWh (est.)', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '<th>' . esc_html__( 'Today kgCO2e (est.)', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '<th>' . esc_html__( 'Month kWh (est.)', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '<th>' . esc_html__( 'Month kgCO2e (est.)', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '</tr></thead><tbody>';
		foreach ( $rows as $row ) {
			$html .= '<tr>';
			$html .= '<td>' . esc_html( (string) ( $row['plugin'] ?? '' ) ) . '</td>';
			$html .= '<td>' . esc_html( (string) ( $row['top_provider'] ?? '' ) ) . '</td>';
			$html .= '<td>' . esc_html( self::format_kwh( (float) ( $row['today_kwh'] ?? 0 ) ) ) . '</td>';
			$html .= '<td>' . esc_html( self::format_kg( (float) ( $row['today_kg'] ?? 0 ) ) ) . '</td>';
			$html .= '<td>' . esc_html( self::format_kwh( (float) ( $row['month_kwh'] ?? 0 ) ) ) . '</td>';
			$html .= '<td>' . esc_html( self::format_kg( (float) ( $row['month_kg'] ?? 0 ) ) ) . '</td>';
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
			__( 'AI sustainability', 'handl-ai-connector-access-control' ),
			__( 'Sustainability', 'handl-ai-connector-access-control' ),
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
		$enabled    = ! empty( $settings['enabled'] );
		$rows       = $enabled ? self::roster() : array();
		$providers  = $enabled ? self::provider_roster( null, self::get_rollups(), false ) : array();
		$stale      = $enabled && self::is_factors_stale();
		$age_ts     = self::factors_age_ts();
		$factors    = self::factors();
		$csv        = add_query_arg(
			array(
				'page'                   => self::PAGE_SLUG,
				'handl_aicac_carbon_csv' => '1',
				'_wpnonce'               => function_exists( 'wp_create_nonce' ) ? wp_create_nonce( 'handl_aicac_carbon_csv' ) : '',
			),
			admin_url( 'admin.php' )
		);
		$print = add_query_arg(
			array(
				'page'                     => self::PAGE_SLUG,
				'handl_aicac_carbon_print' => '1',
				'_wpnonce'                 => function_exists( 'wp_create_nonce' ) ? wp_create_nonce( 'handl_aicac_carbon_print' ) : '',
			),
			admin_url( 'admin.php' )
		);

		echo '<div class="wrap">';
		echo '<h1>' . esc_html__( 'AI sustainability', 'handl-ai-connector-access-control' ) . '</h1>';
		echo '<p class="description">' . esc_html__( 'Directional kWh and CO2e estimates from logged AI token counts. For ESG binders — not compliance-grade claims. Informational only; off by default.', 'handl-ai-connector-access-control' ) . '</p>';

		if ( $can_manage ) {
			$action = admin_url( 'admin-post.php' );
			echo '<form method="post" action="' . esc_url( $action ) . '">';
			echo '<input type="hidden" name="action" value="' . esc_attr( self::ACTION_SAVE ) . '" />';
			if ( function_exists( 'wp_nonce_field' ) ) {
				wp_nonce_field( self::ACTION_SAVE );
			}
			echo '<input type="hidden" name="' . esc_attr( self::POST_PRESENT ) . '" value="1" />';
			echo '<table class="form-table" role="presentation"><tbody>';
			echo '<tr><th scope="row">' . esc_html__( 'Enable sustainability ledger', 'handl-ai-connector-access-control' ) . '</th><td>';
			echo '<label><input type="checkbox" name="' . esc_attr( self::POST_ENABLED ) . '" value="1" ' . checked( $enabled, true, false ) . ' /> ';
			echo esc_html__( 'Build kWh / CO2e estimates from AI token usage already logged on this site', 'handl-ai-connector-access-control' );
			echo '</label></td></tr></tbody></table>';
			submit_button( __( 'Save sustainability settings', 'handl-ai-connector-access-control' ) );
			echo '</form>';
		}

		if ( ! $enabled ) {
			echo '<p>' . esc_html__( 'Sustainability ledger is off. Enable it to build the estimate roster and export CSV for your ESG binder.', 'handl-ai-connector-access-control' ) . '</p>';
			echo '</div>';

			return;
		}

		echo '<div class="notice notice-info"><p><strong>' . esc_html__( 'Estimate, directional — not compliance-grade.', 'handl-ai-connector-access-control' ) . '</strong> ';
		echo esc_html__( 'These figures multiply logged tokens by a bundled energy-factor table and a default grid intensity. Override factors with the handl_aicac_carbon_factors filter when you have better data.', 'handl-ai-connector-access-control' );
		echo '</p></div>';

		echo '<p class="description">';
		echo esc_html(
			sprintf(
				/* translators: 1: Y-m-d date, 2: age label, 3: grid intensity, 4: default kWh factor */
				__( 'Factor table age: %1$s (%2$s). Grid: %3$s kgCO2e/kWh. Default: %4$s kWh per 1M tokens.', 'handl-ai-connector-access-control' ),
				$age_ts > 0 ? gmdate( 'Y-m-d', $age_ts ) : '—',
				$stale
					? __( 'stale — refresh or override recommended', 'handl-ai-connector-access-control' )
					: __( 'current', 'handl-ai-connector-access-control' ),
				self::format_kg( (float) $factors['grid_kg_per_kwh'] ),
				self::format_kwh( (float) $factors['default_kwh_per_1m'] )
			)
		);
		echo '</p>';

		if ( $stale ) {
			echo '<div class="notice notice-warning"><p>';
			echo esc_html__( 'The energy factor table is older than 120 days. Confirm factors against current research or override via handl_aicac_carbon_factors.', 'handl-ai-connector-access-control' );
			echo '</p></div>';
		}

		echo '<p>';
		echo '<a class="button" href="' . esc_url( $csv ) . '">' . esc_html__( 'Download CSV', 'handl-ai-connector-access-control' ) . '</a> ';
		echo '<a class="button" href="' . esc_url( $print ) . '" target="_blank" rel="noopener noreferrer">' . esc_html__( 'Print / PDF view', 'handl-ai-connector-access-control' ) . '</a>';
		echo '</p>';

		echo '<h2>' . esc_html__( 'By plugin (estimates)', 'handl-ai-connector-access-control' ) . '</h2>';
		if ( empty( $rows ) ) {
			echo '<p>' . esc_html__( 'No token-bearing AI Client rows in the retained log yet. Estimates appear after traffic that logs input/output tokens.', 'handl-ai-connector-access-control' ) . '</p>';
		} else {
			echo '<table class="widefat striped"><thead><tr>';
			echo '<th>' . esc_html__( 'Plugin', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Top provider', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Today kWh (est.)', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Today kgCO2e (est.)', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Month kWh (est.)', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Month kgCO2e (est.)', 'handl-ai-connector-access-control' ) . '</th>';
			echo '</tr></thead><tbody>';
			foreach ( $rows as $row ) {
				echo '<tr>';
				echo '<td><code>' . esc_html( (string) $row['plugin'] ) . '</code></td>';
				echo '<td>' . esc_html( (string) $row['top_provider'] ) . '</td>';
				echo '<td class="num">' . esc_html( self::format_kwh( (float) $row['today_kwh'] ) ) . '</td>';
				echo '<td class="num">' . esc_html( self::format_kg( (float) $row['today_kg'] ) ) . '</td>';
				echo '<td class="num">' . esc_html( self::format_kwh( (float) $row['month_kwh'] ) ) . '</td>';
				echo '<td class="num">' . esc_html( self::format_kg( (float) $row['month_kg'] ) ) . '</td>';
				echo '</tr>';
			}
			echo '</tbody></table>';
		}

		echo '<h2>' . esc_html__( 'By provider (estimates)', 'handl-ai-connector-access-control' ) . '</h2>';
		if ( empty( $providers ) ) {
			echo '<p>' . esc_html__( 'No provider rollups yet.', 'handl-ai-connector-access-control' ) . '</p>';
		} else {
			echo '<table class="widefat striped"><thead><tr>';
			echo '<th>' . esc_html__( 'Provider', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Today kWh (est.)', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Today kgCO2e (est.)', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Month kWh (est.)', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Month kgCO2e (est.)', 'handl-ai-connector-access-control' ) . '</th>';
			echo '</tr></thead><tbody>';
			foreach ( $providers as $row ) {
				echo '<tr>';
				echo '<td><code>' . esc_html( (string) $row['provider'] ) . '</code></td>';
				echo '<td class="num">' . esc_html( self::format_kwh( (float) $row['today_kwh'] ) ) . '</td>';
				echo '<td class="num">' . esc_html( self::format_kg( (float) $row['today_kg'] ) ) . '</td>';
				echo '<td class="num">' . esc_html( self::format_kwh( (float) $row['month_kwh'] ) ) . '</td>';
				echo '<td class="num">' . esc_html( self::format_kg( (float) $row['month_kg'] ) ) . '</td>';
				echo '</tr>';
			}
			echo '</tbody></table>';
		}

		echo '</div>';
	}

	public static function maybe_staleness_notice(): void {
		if ( ! self::is_enabled() || ! Caps::user_can_view() ) {
			return;
		}
		$page = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( (string) $_GET['page'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( self::PAGE_SLUG !== $page ) {
			return;
		}
		if ( ! self::is_factors_stale() ) {
			return;
		}
		echo '<div class="notice notice-warning"><p>';
		echo esc_html__( 'The AI energy factor table is older than 120 days. Verify factors against current research or override via handl_aicac_carbon_factors.', 'handl-ai-connector-access-control' );
		echo '</p></div>';
	}

	public static function maybe_handle_csv(): void {
		if ( empty( $_GET['handl_aicac_carbon_csv'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			return;
		}
		$page = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( (string) $_GET['page'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( self::PAGE_SLUG !== $page ) {
			return;
		}
		if ( ! Caps::user_can_view() || ! self::is_enabled() ) {
			return;
		}
		check_admin_referer( 'handl_aicac_carbon_csv' );
		$csv = self::csv_for_roster();
		if ( function_exists( 'nocache_headers' ) ) {
			nocache_headers();
		}
		if ( ! headers_sent() ) {
			header( 'Content-Type: text/csv; charset=utf-8' );
			header( 'Content-Disposition: attachment; filename=handl-aicac-carbon.csv' );
		}
		echo $csv; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- CSV download.
		exit;
	}

	public static function maybe_handle_print(): void {
		if ( empty( $_GET['handl_aicac_carbon_print'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			return;
		}
		$page = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( (string) $_GET['page'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( self::PAGE_SLUG !== $page ) {
			return;
		}
		if ( ! Caps::user_can_view() || ! self::is_enabled() ) {
			return;
		}
		check_admin_referer( 'handl_aicac_carbon_print' );
		$rows = self::roster();
		if ( function_exists( 'nocache_headers' ) ) {
			nocache_headers();
		}
		if ( ! headers_sent() ) {
			header( 'Content-Type: text/html; charset=utf-8' );
		}
		echo self::build_print_html( $rows ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped inside builder.
		exit;
	}

	public static function handle_save(): void {
		if ( ! Caps::user_can_manage() ) {
			wp_die( esc_html__( 'You do not have permission to save sustainability settings.', 'handl-ai-connector-access-control' ) );
		}
		check_admin_referer( self::ACTION_SAVE );
		if ( empty( $_POST[ self::POST_PRESENT ] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing
			wp_die( esc_html__( 'Invalid form', 'handl-ai-connector-access-control' ) );
		}
		self::save_settings(
			array(
				'enabled' => ! empty( $_POST[ self::POST_ENABLED ] ), // phpcs:ignore WordPress.Security.NonceVerification.Missing
			)
		);
		if ( self::is_enabled() ) {
			self::rebuild_rollups( null, null, true );
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
		\WP_CLI::add_command( 'handl-aicac carbon', CLI_Carbon::class );
	}

	private static function clamp_positive_float( float $v, float $default, float $min, float $max ): float {
		if ( ! is_finite( $v ) ) {
			return $default;
		}
		if ( $v < $min ) {
			$v = $min;
		}
		if ( $v > $max ) {
			$v = $max;
		}

		return $v;
	}
}

/**
 * WP-CLI: wp handl-aicac carbon status|export
 */
final class CLI_Carbon {

	/**
	 * Show sustainability ledger status.
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
		$settings = Carbon::get_settings();
		$rows     = Carbon::is_enabled() ? Carbon::roster() : array();
		$format   = isset( $assoc_args['format'] ) ? (string) $assoc_args['format'] : 'table';
		$age      = Carbon::factors_age_ts();

		\WP_CLI::log(
			sprintf(
				'enabled=%s plugins=%d factors_age=%s stale=%s framing=estimate_directional_not_compliance_grade',
				! empty( $settings['enabled'] ) ? 'yes' : 'no',
				count( $rows ),
				$age > 0 ? gmdate( 'Y-m-d', $age ) : '—',
				Carbon::is_factors_stale() ? 'yes' : 'no'
			)
		);

		if ( empty( $rows ) ) {
			\WP_CLI::log( 'No carbon rows.' );
			return;
		}

		$display = array();
		foreach ( $rows as $row ) {
			$display[] = array(
				'plugin'       => (string) $row['plugin'],
				'top_provider' => (string) $row['top_provider'],
				'today_kwh'    => Carbon::csv_float( (float) $row['today_kwh'] ),
				'today_kg'     => Carbon::csv_float( (float) $row['today_kg'] ),
				'month_kwh'    => Carbon::csv_float( (float) $row['month_kwh'] ),
				'month_kg'     => Carbon::csv_float( (float) $row['month_kg'] ),
			);
		}
		if ( 'json' === $format ) {
			\WP_CLI::print_value( $display, array( 'format' => 'json' ) );
			return;
		}
		if ( class_exists( '\WP_CLI\Utils' ) ) {
			\WP_CLI\Utils\format_items(
				'table',
				$display,
				array( 'plugin', 'top_provider', 'today_kwh', 'today_kg', 'month_kwh', 'month_kg' )
			);
		} else {
			foreach ( $display as $row ) {
				\WP_CLI::log( implode( "\t", $row ) );
			}
		}
	}

	/**
	 * Export the sustainability roster as CSV.
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
		$csv = Carbon::csv_for_roster();
		if ( ! empty( $assoc_args['porcelain'] ) ) {
			echo $csv; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- CLI CSV.
			return;
		}
		\WP_CLI::print_value( $csv, array( 'format' => 'csv' ) );
	}
}
