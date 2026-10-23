<?php
/**
 * AICAC-MODEL-EOL (#379): vendor model retirement calendar.
 *
 * Models-in-use inventory from the activity log + Model-Force pins
 * (class_exists-guarded, read-only). Bundled retirement calendar + filter;
 * optional refresh age from the rates-feed advisory channel when that class
 * is loaded. 60/14-day alerts once per model+threshold (snooze respected);
 * loud variant for fail-close pins. Staleness nudge on this screen only.
 * WP-CLI. Informational only — read-only against the gate. OFF by default.
 * No admin.php/policy.php/cost.php/logger/model-force/rates-feed edits.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Warn before a model the site depends on is switched off by the vendor.
 */
final class Model_Eol {

	public const SETTINGS_OPTION = 'handl_aicac_model_eol';

	public const REMOTE_OPTION = 'handl_aicac_model_eol_remote';

	public const ALERTED_OPTION = 'handl_aicac_model_eol_alerted';

	public const PAGE_SLUG = 'handl-aicac-model-eol';

	public const FILTER_CALENDAR = 'handl_aicac_model_eol_calendar';

	/** Absolute ship date of the bundled calendar (Y-m-d). */
	public const BUNDLED_SHIPPED = '2026-10-01';

	/** Days after calendar age before the on-screen staleness nudge. */
	public const STALE_AFTER_DAYS = 120;

	public const THRESHOLD_60 = 60;

	public const THRESHOLD_14 = 14;

	public const ALERT_KIND = 'model_eol';

	public const POST_PRESENT = 'handl_aicac_model_eol_present';

	public const POST_ENABLED = 'handl_aicac_model_eol_enabled';

	public const ACTION_SAVE = 'handl_aicac_model_eol_save';

	/** @var bool */
	private static $registered = false;

	/** @var list<array{to:string,subject:string,body:string}> */
	private static $test_mails = array();

	public static function init(): void {
		if ( self::$registered ) {
			return;
		}
		self::$registered = true;

		add_action( 'admin_menu', array( self::class, 'register_menu' ), 20 );
		add_action( 'admin_init', array( self::class, 'maybe_handle_csv' ), 5 );
		add_action( 'admin_post_' . self::ACTION_SAVE, array( self::class, 'handle_save' ) );

		if ( self::is_enabled() ) {
			add_action( 'init', array( self::class, 'maybe_refresh_from_feed' ), 25 );
			add_action( 'init', array( self::class, 'maybe_fire_alerts' ), 30 );
			if ( function_exists( 'is_admin' ) && is_admin() ) {
				add_action( 'admin_notices', array( self::class, 'maybe_staleness_notice' ) );
			}
		}

		self::register_cli();
	}

	public static function reset_for_tests(): void {
		self::$registered = false;
		self::$test_mails = array();
		delete_option( self::SETTINGS_OPTION );
		delete_option( self::REMOTE_OPTION );
		delete_option( self::ALERTED_OPTION );
	}

	/**
	 * @return list<array{to:string,subject:string,body:string}>
	 */
	public static function test_mails(): array {
		return self::$test_mails;
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
	 * Bundled announced retirement rows.
	 *
	 * @return list<array{provider:string,model:string,eol:string,replacement:string}>
	 */
	public static function bundled_calendar(): array {
		return array(
			array(
				'provider'    => 'openai',
				'model'       => 'gpt-4-turbo',
				'eol'         => '2025-12-17',
				'replacement' => 'gpt-4o',
			),
			array(
				'provider'    => 'openai',
				'model'       => 'gpt-4-0314',
				'eol'         => '2024-06-06',
				'replacement' => 'gpt-4o',
			),
			array(
				'provider'    => 'openai',
				'model'       => 'gpt-3.5-turbo-0613',
				'eol'         => '2024-09-13',
				'replacement' => 'gpt-4o-mini',
			),
			array(
				'provider'    => 'anthropic',
				'model'       => 'claude-2',
				'eol'         => '2025-07-21',
				'replacement' => 'claude-sonnet-4',
			),
			array(
				'provider'    => 'anthropic',
				'model'       => 'claude-2.1',
				'eol'         => '2025-07-21',
				'replacement' => 'claude-sonnet-4',
			),
			array(
				'provider'    => 'google',
				'model'       => 'gemini-1.0-pro',
				'eol'         => '2025-04-09',
				'replacement' => 'gemini-2.0-flash',
			),
			array(
				'provider'    => 'google',
				'model'       => 'gemini-1.5-pro-001',
				'eol'         => '2025-05-24',
				'replacement' => 'gemini-2.0-flash',
			),
			array(
				'provider'    => 'mistral',
				'model'       => 'mistral-tiny',
				'eol'         => '2025-06-30',
				'replacement' => 'mistral-small-latest',
			),
		);
	}

	/**
	 * @return array{updated_at:int,rows:list<array{provider:string,model:string,eol:string,replacement:string}>}
	 */
	public static function get_remote(): array {
		return self::sanitize_remote( get_option( self::REMOTE_OPTION, array() ) );
	}

	/**
	 * @param mixed $raw Raw remote payload.
	 * @return array{updated_at:int,rows:list<array{provider:string,model:string,eol:string,replacement:string}>}
	 */
	public static function sanitize_remote( $raw ): array {
		if ( ! is_array( $raw ) ) {
			return array(
				'updated_at' => 0,
				'rows'       => array(),
			);
		}
		$rows = array();
		$list = isset( $raw['rows'] ) && is_array( $raw['rows'] ) ? $raw['rows'] : array();
		foreach ( $list as $row ) {
			$clean = self::sanitize_calendar_row( $row );
			if ( null !== $clean ) {
				$rows[] = $clean;
			}
		}

		return array(
			'updated_at' => max( 0, (int) ( $raw['updated_at'] ?? 0 ) ),
			'rows'       => $rows,
		);
	}

	/**
	 * Persist feed-sourced calendar rows (public for future Threat_Feed wiring / tests).
	 *
	 * @param list<array<string,mixed>> $rows Calendar rows.
	 */
	public static function apply_remote_calendar( array $rows, ?int $now = null ): void {
		$now  = null !== $now && $now > 0 ? $now : time();
		$clean = array();
		foreach ( $rows as $row ) {
			$item = self::sanitize_calendar_row( $row );
			if ( null !== $item ) {
				$clean[] = $item;
			}
		}
		update_option(
			self::REMOTE_OPTION,
			array(
				'updated_at' => $now,
				'rows'       => $clean,
			),
			false
		);
	}

	/**
	 * When Rates_Feed is loaded, adopt its feed updated_at as calendar refresh age
	 * (and pull model_eol rows if a public method exposes them).
	 */
	public static function maybe_refresh_from_feed( ?int $now = null ): void {
		if ( ! self::is_enabled() ) {
			return;
		}
		$now = null !== $now && $now > 0 ? $now : time();
		if ( ! class_exists( Rates_Feed::class, false ) ) {
			return;
		}

		if ( method_exists( Rates_Feed::class, 'remote_model_eol' ) ) {
			$remote_rows = Rates_Feed::remote_model_eol();
			if ( is_array( $remote_rows ) && ! empty( $remote_rows ) ) {
				self::apply_remote_calendar( $remote_rows, $now );
				return;
			}
		}

		if ( ! method_exists( Rates_Feed::class, 'status' ) ) {
			return;
		}
		$status = Rates_Feed::status();
		if ( ! is_array( $status ) ) {
			return;
		}
		$updated = isset( $status['updated_at'] ) ? (int) $status['updated_at'] : 0;
		if ( $updated <= 0 || empty( $status['active'] ) ) {
			return;
		}
		$remote = self::get_remote();
		if ( $updated <= (int) $remote['updated_at'] ) {
			return;
		}
		update_option(
			self::REMOTE_OPTION,
			array(
				'updated_at' => $updated,
				'rows'       => $remote['rows'],
			),
			false
		);
	}

	/**
	 * Effective calendar: remote rows overlay bundled by provider+model key, then filter.
	 *
	 * @return list<array{provider:string,model:string,eol:string,replacement:string,source:string}>
	 */
	public static function calendar(): array {
		$map = array();
		foreach ( self::bundled_calendar() as $row ) {
			$key         = self::row_key( $row['provider'], $row['model'] );
			$map[ $key ] = array_merge( $row, array( 'source' => 'bundled' ) );
		}
		foreach ( self::get_remote()['rows'] as $row ) {
			$key         = self::row_key( $row['provider'], $row['model'] );
			$map[ $key ] = array_merge( $row, array( 'source' => 'feed' ) );
		}

		/**
		 * Filter the model retirement calendar.
		 *
		 * @param list<array{provider:string,model:string,eol:string,replacement:string,source?:string}> $rows Calendar rows.
		 */
		$filtered = apply_filters( self::FILTER_CALENDAR, array_values( $map ) );
		if ( ! is_array( $filtered ) ) {
			return array_values( $map );
		}

		$out = array();
		foreach ( $filtered as $row ) {
			$clean = self::sanitize_calendar_row( $row );
			if ( null === $clean ) {
				continue;
			}
			$source = isset( $row['source'] ) ? sanitize_key( (string) $row['source'] ) : 'filter';
			if ( ! in_array( $source, array( 'bundled', 'feed', 'filter' ), true ) ) {
				$source = 'filter';
			}
			$out[] = array_merge( $clean, array( 'source' => $source ) );
		}

		return $out;
	}

	/**
	 * @param mixed $row Raw row.
	 * @return array{provider:string,model:string,eol:string,replacement:string}|null
	 */
	public static function sanitize_calendar_row( $row ): ?array {
		if ( ! is_array( $row ) ) {
			return null;
		}
		$provider = Cost::normalize_provider_id( (string) ( $row['provider'] ?? '' ) );
		$model    = self::sanitize_model_id( (string) ( $row['model'] ?? $row['pattern'] ?? '' ) );
		$eol      = self::sanitize_date( (string) ( $row['eol'] ?? $row['retire'] ?? $row['retirement'] ?? '' ) );
		if ( '' === $provider || '' === $model || '' === $eol ) {
			return null;
		}
		$replacement = self::sanitize_model_id( (string) ( $row['replacement'] ?? $row['hint'] ?? '' ) );

		return array(
			'provider'    => $provider,
			'model'       => $model,
			'eol'         => $eol,
			'replacement' => $replacement,
		);
	}

	public static function sanitize_model_id( string $raw ): string {
		$raw = strtolower( trim( sanitize_text_field( $raw ) ) );
		$raw = preg_replace( '/[^a-z0-9._*:\/+-]+/', '', $raw ) ?? '';
		if ( strlen( $raw ) > 128 ) {
			$raw = substr( $raw, 0, 128 );
		}

		return $raw;
	}

	public static function sanitize_date( string $date ): string {
		$date = trim( $date );
		if ( '' === $date ) {
			return '';
		}
		if ( ! preg_match( '/^\d{4}-\d{2}-\d{2}$/', $date ) ) {
			return '';
		}
		$parts = explode( '-', $date );
		if ( 3 !== count( $parts ) ) {
			return '';
		}
		$y = (int) $parts[0];
		$m = (int) $parts[1];
		$d = (int) $parts[2];
		if ( $y < 1970 || $y > 2100 || ! checkdate( $m, $d, $y ) ) {
			return '';
		}

		return sprintf( '%04d-%02d-%02d', $y, $m, $d );
	}

	public static function row_key( string $provider, string $model ): string {
		return Cost::normalize_provider_id( $provider ) . "\0" . self::sanitize_model_id( $model );
	}

	/**
	 * Unix timestamp representing calendar freshness (bundled ship date or later feed refresh).
	 */
	public static function calendar_age_ts( ?int $now = null ): int {
		unset( $now );
		$shipped = strtotime( self::BUNDLED_SHIPPED . ' UTC' );
		$age     = false !== $shipped ? (int) $shipped : 0;
		$remote  = self::get_remote();
		if ( (int) $remote['updated_at'] > $age ) {
			$age = (int) $remote['updated_at'];
		}

		return $age;
	}

	public static function is_calendar_stale( ?int $now = null ): bool {
		$now = null !== $now && $now > 0 ? $now : time();
		$age = self::calendar_age_ts( $now );
		if ( $age <= 0 ) {
			return false;
		}

		$day = defined( 'DAY_IN_SECONDS' ) ? (int) DAY_IN_SECONDS : 86400;

		return ( $now - $age ) > ( self::STALE_AFTER_DAYS * $day );
	}

	/**
	 * Models observed in the retained activity log.
	 *
	 * @param list<array<string,mixed>>|null $log Optional log override.
	 * @return array<string,array{provider:string,model:string,last_seen:int,calls:int,plugins:list<string>}>
	 */
	public static function models_from_log( ?array $log = null ): array {
		if ( null === $log ) {
			$log = Policy::get_retained_log();
		}
		if ( class_exists( Demo_Mode::class, false ) ) {
			$log = Demo_Mode::without_demo( $log );
		}

		$stats = array();
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
			$provider = Cost::normalize_provider_id( (string) ( $row['provider'] ?? '' ) );
			$model    = '';
			foreach ( array( 'model', 'pin_model', 'forced_model' ) as $field ) {
				$candidate = self::sanitize_model_id( (string) ( $row[ $field ] ?? '' ) );
				if ( '' !== $candidate ) {
					$model = $candidate;
					break;
				}
			}
			if ( '' === $provider || '' === $model ) {
				continue;
			}
			$key = self::row_key( $provider, $model );
			if ( ! isset( $stats[ $key ] ) ) {
				$stats[ $key ] = array(
					'provider'  => $provider,
					'model'     => $model,
					'last_seen' => 0,
					'calls'     => 0,
					'plugins'   => array(),
				);
			}
			$ts    = isset( $row['ts'] ) ? (int) $row['ts'] : 0;
			$count = isset( $row['count'] ) ? max( 1, (int) $row['count'] ) : 1;
			if ( $ts > $stats[ $key ]['last_seen'] ) {
				$stats[ $key ]['last_seen'] = $ts;
			}
			$stats[ $key ]['calls'] += $count;
			$plugin = isset( $row['plugin'] ) ? (string) $row['plugin'] : '';
			if ( '' !== $plugin ) {
				$stats[ $key ]['plugins'][ $plugin ] = true;
			}
		}

		$out = array();
		foreach ( $stats as $key => $stat ) {
			$plugins = array_keys( $stat['plugins'] );
			sort( $plugins );
			$out[ $key ] = array(
				'provider'  => $stat['provider'],
				'model'     => $stat['model'],
				'last_seen' => (int) $stat['last_seen'],
				'calls'     => (int) $stat['calls'],
				'plugins'   => $plugins,
			);
		}

		return $out;
	}

	/**
	 * Model-Force pins (fail-close) keyed like inventory rows.
	 *
	 * @param array<string,mixed>|null $policy Optional policy override.
	 * @return array<string,array{provider:string,model:string,plugins:list<string>}>
	 */
	public static function pins_from_model_force( ?array $policy = null ): array {
		if ( ! class_exists( Model_Force::class, false ) ) {
			return array();
		}
		if ( null === $policy ) {
			$policy = Policy::get_policy();
		}
		if ( ! is_array( $policy ) ) {
			return array();
		}

		$pins = array();
		$map  = Model_Force::force_map( $policy );
		foreach ( $map as $basename => $route ) {
			if ( ! is_array( $route ) ) {
				continue;
			}
			$provider = Cost::normalize_provider_id( (string) ( $route['provider'] ?? '' ) );
			$model    = self::sanitize_model_id( (string) ( $route['model'] ?? '' ) );
			if ( '' === $provider || '' === $model ) {
				continue;
			}
			$key = self::row_key( $provider, $model );
			if ( ! isset( $pins[ $key ] ) ) {
				$pins[ $key ] = array(
					'provider' => $provider,
					'model'    => $model,
					'plugins'  => array(),
				);
			}
			$basename = sanitize_text_field( (string) $basename );
			if ( '' !== $basename ) {
				$pins[ $key ]['plugins'][ $basename ] = true;
			}
		}

		if ( method_exists( Model_Force::class, 'unattributed_route' ) ) {
			$route = Model_Force::unattributed_route( $policy );
			if ( is_array( $route ) ) {
				$provider = Cost::normalize_provider_id( (string) ( $route['provider'] ?? '' ) );
				$model    = self::sanitize_model_id( (string) ( $route['model'] ?? '' ) );
				if ( '' !== $provider && '' !== $model ) {
					$key = self::row_key( $provider, $model );
					if ( ! isset( $pins[ $key ] ) ) {
						$pins[ $key ] = array(
							'provider' => $provider,
							'model'    => $model,
							'plugins'  => array(),
						);
					}
					$pins[ $key ]['plugins']['(unattributed)'] = true;
				}
			}
		}

		$out = array();
		foreach ( $pins as $key => $pin ) {
			$plugins = array_keys( $pin['plugins'] );
			sort( $plugins );
			$out[ $key ] = array(
				'provider' => $pin['provider'],
				'model'    => $pin['model'],
				'plugins'  => $plugins,
			);
		}

		return $out;
	}

	/**
	 * Match a model id against a calendar pattern (exact or trailing * wildcard).
	 */
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

		return false;
	}

	/**
	 * Find the best calendar row for a provider+model (exact wins over wildcard).
	 *
	 * @param list<array{provider:string,model:string,eol:string,replacement:string,source?:string}>|null $calendar
	 * @return array{provider:string,model:string,eol:string,replacement:string,source:string}|null
	 */
	public static function match_calendar_row( string $provider, string $model, ?array $calendar = null ): ?array {
		$provider = Cost::normalize_provider_id( $provider );
		$model    = self::sanitize_model_id( $model );
		if ( '' === $provider || '' === $model ) {
			return null;
		}
		if ( null === $calendar ) {
			$calendar = self::calendar();
		}
		$exact = null;
		$wild  = null;
		foreach ( $calendar as $row ) {
			if ( $provider !== (string) ( $row['provider'] ?? '' ) ) {
				continue;
			}
			$pattern = (string) ( $row['model'] ?? '' );
			if ( ! self::model_matches( $pattern, $model ) ) {
				continue;
			}
			$enriched = array(
				'provider'    => (string) $row['provider'],
				'model'       => $pattern,
				'eol'         => (string) $row['eol'],
				'replacement' => (string) ( $row['replacement'] ?? '' ),
				'source'      => (string) ( $row['source'] ?? 'bundled' ),
			);
			if ( $pattern === $model ) {
				$exact = $enriched;
			} elseif ( null === $wild ) {
				$wild = $enriched;
			}
		}

		return $exact ?? $wild;
	}

	/**
	 * Days until EOL (negative when past). Null when date unparsable.
	 */
	public static function days_until_eol( string $eol, ?int $now = null ): ?int {
		$eol = self::sanitize_date( $eol );
		if ( '' === $eol ) {
			return null;
		}
		$now    = null !== $now && $now > 0 ? $now : time();
		$eol_ts = strtotime( $eol . ' 00:00:00 UTC' );
		if ( false === $eol_ts ) {
			return null;
		}
		$now_mid = gmmktime(
			0,
			0,
			0,
			(int) gmdate( 'n', $now ),
			(int) gmdate( 'j', $now ),
			(int) gmdate( 'Y', $now )
		);
		if ( false === $now_mid ) {
			return null;
		}
		$day = defined( 'DAY_IN_SECONDS' ) ? (int) DAY_IN_SECONDS : 86400;

		return (int) floor( ( (int) $eol_ts - (int) $now_mid ) / $day );
	}

	/**
	 * Roster rows for models in use (log + pins) that have a calendar match.
	 *
	 * @param list<array<string,mixed>>|null $log Optional log.
	 * @param array<string,mixed>|null       $policy Optional policy.
	 * @return list<array{
	 *   provider:string,
	 *   model:string,
	 *   eol:string,
	 *   days_left:int,
	 *   replacement:string,
	 *   source:string,
	 *   pinned:bool,
	 *   plugins:list<string>,
	 *   calls:int,
	 *   last_seen:int,
	 *   past:bool,
	 *   within_14:bool,
	 *   within_60:bool
	 * }>
	 */
	public static function build_rows( ?array $log = null, ?array $policy = null, ?int $now = null ): array {
		$now      = null !== $now && $now > 0 ? $now : time();
		$calendar = self::calendar();
		$from_log = self::models_from_log( $log );
		$pins     = self::pins_from_model_force( $policy );

		$keys = array_unique( array_merge( array_keys( $from_log ), array_keys( $pins ) ) );
		$rows = array();
		foreach ( $keys as $key ) {
			$provider = '';
			$model    = '';
			if ( isset( $from_log[ $key ] ) ) {
				$provider = $from_log[ $key ]['provider'];
				$model    = $from_log[ $key ]['model'];
			} elseif ( isset( $pins[ $key ] ) ) {
				$provider = $pins[ $key ]['provider'];
				$model    = $pins[ $key ]['model'];
			}
			$match = self::match_calendar_row( $provider, $model, $calendar );
			if ( null === $match ) {
				continue;
			}
			$days = self::days_until_eol( $match['eol'], $now );
			if ( null === $days ) {
				continue;
			}
			$plugins = array();
			if ( isset( $from_log[ $key ]['plugins'] ) ) {
				foreach ( $from_log[ $key ]['plugins'] as $p ) {
					$plugins[ $p ] = true;
				}
			}
			if ( isset( $pins[ $key ]['plugins'] ) ) {
				foreach ( $pins[ $key ]['plugins'] as $p ) {
					$plugins[ $p ] = true;
				}
			}
			$plugin_list = array_keys( $plugins );
			sort( $plugin_list );

			$rows[] = array(
				'provider'    => $provider,
				'model'       => $model,
				'eol'         => $match['eol'],
				'days_left'   => $days,
				'replacement' => $match['replacement'],
				'source'      => $match['source'],
				'pinned'      => isset( $pins[ $key ] ),
				'plugins'     => $plugin_list,
				'calls'       => isset( $from_log[ $key ] ) ? (int) $from_log[ $key ]['calls'] : 0,
				'last_seen'   => isset( $from_log[ $key ] ) ? (int) $from_log[ $key ]['last_seen'] : 0,
				'past'        => $days < 0,
				'within_14'   => $days <= self::THRESHOLD_14,
				'within_60'   => $days <= self::THRESHOLD_60,
			);
		}

		usort(
			$rows,
			static function ( array $a, array $b ): int {
				if ( $a['days_left'] === $b['days_left'] ) {
					return strcmp( $a['provider'] . '/' . $a['model'], $b['provider'] . '/' . $b['model'] );
				}

				return $a['days_left'] <=> $b['days_left'];
			}
		);

		return $rows;
	}

	/**
	 * Rows that should fail `model-eol check` (past or within 14 days).
	 *
	 * @return list<array<string,mixed>>
	 */
	public static function check_failures( ?array $log = null, ?array $policy = null, ?int $now = null ): array {
		$out = array();
		foreach ( self::build_rows( $log, $policy, $now ) as $row ) {
			if ( ! empty( $row['within_14'] ) ) {
				$out[] = $row;
			}
		}

		return $out;
	}

	/**
	 * @return array<string,bool> fingerprint => true
	 */
	public static function get_alerted(): array {
		$raw = get_option( self::ALERTED_OPTION, array() );
		if ( ! is_array( $raw ) ) {
			return array();
		}
		$out = array();
		foreach ( $raw as $fp => $flag ) {
			$fp = sanitize_text_field( (string) $fp );
			if ( '' === $fp || ! $flag ) {
				continue;
			}
			$out[ $fp ] = true;
		}

		return $out;
	}

	/**
	 * @param array<string,bool> $map Alerted fingerprints.
	 */
	public static function put_alerted( array $map ): void {
		$clean = array();
		foreach ( $map as $fp => $flag ) {
			$fp = sanitize_text_field( (string) $fp );
			if ( '' === $fp || ! $flag ) {
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

	public static function alert_fingerprint( string $provider, string $model, int $threshold ): string {
		return Cost::normalize_provider_id( $provider ) . '|' . self::sanitize_model_id( $model ) . '|' . (string) $threshold;
	}

	/**
	 * Fire 60/14-day alerts once per model+threshold.
	 *
	 * @return array{fired:int,skipped:int}
	 */
	public static function maybe_fire_alerts( ?array $log = null, ?array $policy = null, ?int $now = null ): array {
		$result = array(
			'fired'   => 0,
			'skipped' => 0,
		);
		if ( ! self::is_enabled() ) {
			return $result;
		}
		$now = null !== $now && $now > 0 ? $now : time();
		if ( null === $policy ) {
			$policy = Policy::get_policy();
		}
		if ( ! is_array( $policy ) ) {
			$policy = array();
		}

		$alerted = self::get_alerted();
		$rows    = self::build_rows( $log, $policy, $now );
		foreach ( $rows as $row ) {
			$thresholds = array();
			if ( ! empty( $row['within_60'] ) ) {
				$thresholds[] = self::THRESHOLD_60;
			}
			if ( ! empty( $row['within_14'] ) ) {
				$thresholds[] = self::THRESHOLD_14;
			}
			foreach ( $thresholds as $threshold ) {
				$fp = self::alert_fingerprint( (string) $row['provider'], (string) $row['model'], $threshold );
				if ( isset( $alerted[ $fp ] ) ) {
					++$result['skipped'];
					continue;
				}
				$plugin_for_snooze = ! empty( $row['plugins'][0] ) ? (string) $row['plugins'][0] : '';
				if ( '' !== $plugin_for_snooze
					&& class_exists( Alert_Snooze::class, false )
					&& Alert_Snooze::should_suppress( $plugin_for_snooze, self::ALERT_KIND, $now ) ) {
					++$result['skipped'];
					continue;
				}
				$ok = self::fire_alert( $row, $threshold, $policy, $now );
				if ( $ok ) {
					$alerted[ $fp ] = true;
					++$result['fired'];
				} else {
					++$result['skipped'];
				}
			}
		}
		self::put_alerted( $alerted );

		return $result;
	}

	/**
	 * @param array<string,mixed> $row Roster row.
	 * @param array<string,mixed> $policy Policy.
	 */
	private static function fire_alert( array $row, int $threshold, array $policy, int $now ): bool {
		$email = '';
		if ( class_exists( Alerts::class, false ) && method_exists( Alerts::class, 'resolve_email' ) ) {
			$email = (string) Alerts::resolve_email( $policy );
		}
		if ( '' === $email ) {
			return false;
		}

		$loud    = ! empty( $row['pinned'] );
		$subject = self::build_subject( $row, $threshold, $loud );
		$body    = self::build_body( $row, $threshold, $loud );

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
						'type'        => 'handl_aicac_model_eol_alert',
						'provider'    => (string) $row['provider'],
						'model'       => (string) $row['model'],
						'eol'         => (string) $row['eol'],
						'days_left'   => (int) $row['days_left'],
						'threshold'   => $threshold,
						'pinned'      => ! empty( $row['pinned'] ),
						'replacement' => (string) ( $row['replacement'] ?? '' ),
						'site'        => function_exists( 'home_url' ) ? home_url( '/' ) : '',
					)
				);
			}
		}

		if ( ! $ok ) {
			return false;
		}

		Policy::append_log_event(
			array(
				'ts'        => $now,
				'decision'  => 'model_eol_alert',
				'channel'   => 'model_eol',
				'provider'  => (string) $row['provider'],
				'model'     => (string) $row['model'],
				'eol'       => (string) $row['eol'],
				'days_left' => (int) $row['days_left'],
				'threshold' => $threshold,
				'pinned'    => ! empty( $row['pinned'] ),
			)
		);

		return true;
	}

	/**
	 * @param array<string,mixed> $row Roster row.
	 */
	public static function build_subject( array $row, int $threshold, bool $loud ): string {
		$site = function_exists( 'get_bloginfo' )
			? wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES )
			: 'WordPress';
		$model = (string) ( $row['model'] ?? '' );
		if ( $loud ) {
			return sprintf(
				/* translators: 1: site name, 2: model id */
				__( '[%1$s] HandL URGENT: fail-close pin on retiring model %2$s', 'handl-ai-connector-access-control' ),
				$site,
				$model
			);
		}

		return sprintf(
			/* translators: 1: site name, 2: model id, 3: day threshold */
			__( '[%1$s] HandL: model %2$s retires within %3$d days', 'handl-ai-connector-access-control' ),
			$site,
			$model,
			$threshold
		);
	}

	/**
	 * @param array<string,mixed> $row Roster row.
	 */
	public static function build_body( array $row, int $threshold, bool $loud ): string {
		$lines   = array();
		$lines[] = __( 'HandL AI Connector Access Control: vendor model retirement', 'handl-ai-connector-access-control' );
		$lines[] = '';
		$lines[] = sprintf(
			/* translators: 1: provider id, 2: model id */
			__( 'Model: %1$s / %2$s', 'handl-ai-connector-access-control' ),
			(string) ( $row['provider'] ?? '' ),
			(string) ( $row['model'] ?? '' )
		);
		$lines[] = sprintf(
			/* translators: %s: Y-m-d date */
			__( 'Retirement date: %s', 'handl-ai-connector-access-control' ),
			(string) ( $row['eol'] ?? '' )
		);
		$lines[] = sprintf(
			/* translators: %d: days remaining (may be negative) */
			__( 'Days remaining: %d', 'handl-ai-connector-access-control' ),
			(int) ( $row['days_left'] ?? 0 )
		);
		$lines[] = sprintf(
			/* translators: %d: alert threshold in days */
			__( 'Alert threshold: %d days', 'handl-ai-connector-access-control' ),
			$threshold
		);
		if ( ! empty( $row['replacement'] ) ) {
			$lines[] = sprintf(
				/* translators: %s: suggested replacement model */
				__( 'Suggested replacement: %s', 'handl-ai-connector-access-control' ),
				(string) $row['replacement']
			);
		}
		$plugins = isset( $row['plugins'] ) && is_array( $row['plugins'] ) ? $row['plugins'] : array();
		if ( ! empty( $plugins ) ) {
			$lines[] = sprintf(
				/* translators: %s: comma-separated plugin basenames */
				__( 'Calling plugins: %s', 'handl-ai-connector-access-control' ),
				implode( ', ', $plugins )
			);
		}
		$lines[] = '';
		if ( $loud ) {
			$lines[] = __( 'This model is pinned with Model-Force fail-close. On retirement day, pinned traffic will fail closed unless you change the pin.', 'handl-ai-connector-access-control' );
		} else {
			$lines[] = __( 'Informational only — access rules have not changed. Plan a model migration before the retirement date.', 'handl-ai-connector-access-control' );
		}
		$lines[] = '';
		$lines[] = __( 'Open the model retirement screen:', 'handl-ai-connector-access-control' );
		$lines[] = self::admin_url();

		return implode( "\n", $lines ) . "\n";
	}

	public static function admin_url(): string {
		if ( function_exists( 'admin_url' ) ) {
			return (string) admin_url( 'admin.php?page=' . self::PAGE_SLUG );
		}

		return '';
	}

	/**
	 * @param list<array<string,mixed>>|null $rows Optional rows.
	 */
	public static function csv_for_rows( ?array $rows = null ): string {
		if ( null === $rows ) {
			$rows = self::build_rows();
		}
		$lines   = array();
		$lines[] = self::csv_line(
			array(
				'provider',
				'model',
				'eol',
				'days_left',
				'replacement',
				'pinned',
				'plugins',
				'calls',
				'source',
			)
		);
		foreach ( $rows as $r ) {
			$lines[] = self::csv_line(
				array(
					(string) ( $r['provider'] ?? '' ),
					(string) ( $r['model'] ?? '' ),
					(string) ( $r['eol'] ?? '' ),
					(string) (int) ( $r['days_left'] ?? 0 ),
					(string) ( $r['replacement'] ?? '' ),
					! empty( $r['pinned'] ) ? 'yes' : 'no',
					implode( ';', is_array( $r['plugins'] ?? null ) ? $r['plugins'] : array() ),
					(string) (int) ( $r['calls'] ?? 0 ),
					(string) ( $r['source'] ?? '' ),
				)
			);
		}

		return implode( "\n", $lines ) . "\n";
	}

	/**
	 * @param list<string> $fields CSV fields.
	 */
	private static function csv_line( array $fields ): string {
		$out = array();
		foreach ( $fields as $field ) {
			$field = (string) $field;
			if ( strpbrk( $field, ",\"\n\r" ) !== false ) {
				$field = '"' . str_replace( '"', '""', $field ) . '"';
			}
			$out[] = $field;
		}

		return implode( ',', $out );
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
			__( 'Model retirement', 'handl-ai-connector-access-control' ),
			__( 'Model retirement', 'handl-ai-connector-access-control' ),
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
		$rows       = $enabled ? self::build_rows() : array();
		$stale      = $enabled && self::is_calendar_stale();
		$age_ts     = self::calendar_age_ts();
		$csv        = add_query_arg(
			array(
				'page'                      => self::PAGE_SLUG,
				'handl_aicac_model_eol_csv' => '1',
				'_wpnonce'                  => function_exists( 'wp_create_nonce' ) ? wp_create_nonce( 'handl_aicac_model_eol_csv' ) : '',
			),
			admin_url( 'admin.php' )
		);

		echo '<div class="wrap">';
		echo '<h1>' . esc_html__( 'Model retirement', 'handl-ai-connector-access-control' ) . '</h1>';
		echo '<p class="description">' . esc_html__( 'Warns when a model your site uses (or pins with Model-Force) has an announced vendor retirement date. Informational only — does not deny calls. Off by default.', 'handl-ai-connector-access-control' ) . '</p>';

		if ( $can_manage ) {
			$action = admin_url( 'admin-post.php' );
			echo '<form method="post" action="' . esc_url( $action ) . '">';
			echo '<input type="hidden" name="action" value="' . esc_attr( self::ACTION_SAVE ) . '" />';
			if ( function_exists( 'wp_nonce_field' ) ) {
				wp_nonce_field( self::ACTION_SAVE );
			}
			echo '<input type="hidden" name="' . esc_attr( self::POST_PRESENT ) . '" value="1" />';
			echo '<table class="form-table" role="presentation"><tbody>';
			echo '<tr><th scope="row">' . esc_html__( 'Enable model retirement watch', 'handl-ai-connector-access-control' ) . '</th><td>';
			echo '<label><input type="checkbox" name="' . esc_attr( self::POST_ENABLED ) . '" value="1" ' . checked( $enabled, true, false ) . ' /> ';
			echo esc_html__( 'Watch models in use and alert at 60 and 14 days before vendor retirement', 'handl-ai-connector-access-control' );
			echo '</label></td></tr></tbody></table>';
			submit_button( __( 'Save model retirement settings', 'handl-ai-connector-access-control' ) );
			echo '</form>';
		}

		if ( ! $enabled ) {
			echo '<p>' . esc_html__( 'Model retirement watch is off. Enable it to build the roster and send alerts.', 'handl-ai-connector-access-control' ) . '</p>';
			echo '</div>';
			return;
		}

		echo '<p class="description">';
		echo esc_html(
			sprintf(
				/* translators: 1: Y-m-d date, 2: age label */
				__( 'Calendar age: %1$s (%2$s).', 'handl-ai-connector-access-control' ),
				$age_ts > 0 ? gmdate( 'Y-m-d', $age_ts ) : '—',
				$stale
					? __( 'stale — refresh or override recommended', 'handl-ai-connector-access-control' )
					: __( 'current', 'handl-ai-connector-access-control' )
			)
		);
		echo '</p>';

		if ( $stale ) {
			echo '<div class="notice notice-warning"><p>';
			echo esc_html__( 'The retirement calendar is older than 120 days. Confirm dates against vendor docs or refresh from the advisory feed when available.', 'handl-ai-connector-access-control' );
			echo '</p></div>';
		}

		echo '<p><a class="button" href="' . esc_url( $csv ) . '">' . esc_html__( 'Download CSV', 'handl-ai-connector-access-control' ) . '</a></p>';

		if ( empty( $rows ) ) {
			echo '<p>' . esc_html__( 'No retiring models among observed traffic or Model-Force pins.', 'handl-ai-connector-access-control' ) . '</p>';
			echo '</div>';
			return;
		}

		echo '<table class="widefat striped"><thead><tr>';
		echo '<th>' . esc_html__( 'Provider / model', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Retires', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Days left', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Replacement', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Pin', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Plugins', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Calls', 'handl-ai-connector-access-control' ) . '</th>';
		echo '</tr></thead><tbody>';

		foreach ( $rows as $r ) {
			echo '<tr>';
			echo '<td><code>' . esc_html( (string) $r['provider'] ) . '</code><br /><strong>' . esc_html( (string) $r['model'] ) . '</strong>';
			if ( ! empty( $r['past'] ) ) {
				echo '<br /><span class="description">' . esc_html__( 'Past retirement date', 'handl-ai-connector-access-control' ) . '</span>';
			} elseif ( ! empty( $r['within_14'] ) ) {
				echo '<br /><span class="description">' . esc_html__( 'Within 14 days', 'handl-ai-connector-access-control' ) . '</span>';
			} elseif ( ! empty( $r['within_60'] ) ) {
				echo '<br /><span class="description">' . esc_html__( 'Within 60 days', 'handl-ai-connector-access-control' ) . '</span>';
			}
			echo '</td>';
			echo '<td>' . esc_html( (string) $r['eol'] ) . '</td>';
			echo '<td class="num">' . esc_html( (string) (int) $r['days_left'] ) . '</td>';
			echo '<td>' . esc_html( '' !== (string) $r['replacement'] ? (string) $r['replacement'] : '—' ) . '</td>';
			if ( ! empty( $r['pinned'] ) ) {
				echo '<td><strong>' . esc_html__( 'Fail-close pin', 'handl-ai-connector-access-control' ) . '</strong></td>';
			} else {
				echo '<td>' . esc_html__( 'No', 'handl-ai-connector-access-control' ) . '</td>';
			}
			echo '<td>' . esc_html( implode( ', ', is_array( $r['plugins'] ) ? $r['plugins'] : array() ) ) . '</td>';
			echo '<td class="num">' . esc_html( (string) (int) $r['calls'] ) . '</td>';
			echo '</tr>';
		}
		echo '</tbody></table></div>';
	}

	public static function maybe_staleness_notice(): void {
		if ( ! self::is_enabled() || ! Caps::user_can_view() ) {
			return;
		}
		$page = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( (string) $_GET['page'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( self::PAGE_SLUG !== $page ) {
			return;
		}
		if ( ! self::is_calendar_stale() ) {
			return;
		}
		echo '<div class="notice notice-warning"><p>';
		echo esc_html__( 'The model retirement calendar is older than 120 days. Verify dates against vendor announcements.', 'handl-ai-connector-access-control' );
		echo '</p></div>';
	}

	public static function maybe_handle_csv(): void {
		if ( empty( $_GET['handl_aicac_model_eol_csv'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			return;
		}
		if ( ! Caps::user_can_view() ) {
			return;
		}
		$page = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( (string) $_GET['page'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( self::PAGE_SLUG !== $page ) {
			return;
		}
		if ( ! self::is_enabled() ) {
			return;
		}
		$nonce = isset( $_GET['_wpnonce'] ) ? (string) wp_unslash( $_GET['_wpnonce'] ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( function_exists( 'wp_verify_nonce' ) && ! wp_verify_nonce( $nonce, 'handl_aicac_model_eol_csv' ) ) {
			return;
		}
		$csv = self::csv_for_rows();
		if ( ! headers_sent() ) {
			header( 'Content-Type: text/csv; charset=utf-8' );
			header( 'Content-Disposition: attachment; filename="handl-aicac-model-eol.csv"' );
		}
		echo $csv; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- CSV download.
		exit;
	}

	public static function handle_save(): void {
		if ( ! Caps::user_can_manage() ) {
			wp_die( esc_html__( 'Forbidden', 'handl-ai-connector-access-control' ) );
		}
		if ( function_exists( 'check_admin_referer' ) ) {
			check_admin_referer( self::ACTION_SAVE );
		}
		if ( empty( $_POST[ self::POST_PRESENT ] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing
			wp_die( esc_html__( 'Security check failed. Go back, reload the page, and try again.', 'handl-ai-connector-access-control' ) );
		}
		self::save_settings(
			array(
				'enabled' => ! empty( $_POST[ self::POST_ENABLED ] ), // phpcs:ignore WordPress.Security.NonceVerification.Missing
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
		\WP_CLI::add_command( 'handl-aicac model-eol', CLI_Model_Eol::class );
	}
}

/**
 * WP-CLI: wp handl-aicac model-eol status|check
 */
final class CLI_Model_Eol {

	/**
	 * Show model retirement status.
	 *
	 * ## OPTIONS
	 *
	 * @when after_wp_load
	 *
	 * @param list<string>             $args       Positional.
	 * @param array<string,string|int> $assoc_args Flags.
	 */
	public function status( $args, $assoc_args ): void {
		unset( $args, $assoc_args );
		$settings = Model_Eol::get_settings();
		$rows     = Model_Eol::is_enabled() ? Model_Eol::build_rows() : array();
		$within14 = 0;
		$within60 = 0;
		$pinned   = 0;
		foreach ( $rows as $r ) {
			if ( ! empty( $r['within_14'] ) ) {
				++$within14;
			} elseif ( ! empty( $r['within_60'] ) ) {
				++$within60;
			}
			if ( ! empty( $r['pinned'] ) ) {
				++$pinned;
			}
		}
		$age = Model_Eol::calendar_age_ts();
		\WP_CLI::log(
			sprintf(
				'enabled=%s models=%d within_14=%d within_60=%d pinned=%d calendar_age=%s stale=%s',
				! empty( $settings['enabled'] ) ? 'yes' : 'no',
				count( $rows ),
				$within14,
				$within60,
				$pinned,
				$age > 0 ? gmdate( 'Y-m-d', $age ) : '—',
				Model_Eol::is_calendar_stale() ? 'yes' : 'no'
			)
		);
	}

	/**
	 * Exit non-zero when a model in use is past or within 14 days of EOL.
	 *
	 * ## OPTIONS
	 *
	 * @when after_wp_load
	 *
	 * @param list<string>             $args       Positional.
	 * @param array<string,string|int> $assoc_args Flags.
	 */
	public function check( $args, $assoc_args ): void {
		unset( $args, $assoc_args );
		if ( ! Model_Eol::is_enabled() ) {
			\WP_CLI::success( 'Model retirement watch is off.' );
			return;
		}
		$failures = Model_Eol::check_failures();
		if ( empty( $failures ) ) {
			\WP_CLI::success( 'No models in use within 14 days of retirement.' );
			return;
		}
		foreach ( $failures as $r ) {
			\WP_CLI::log(
				sprintf(
					'%s/%s eol=%s days_left=%d pinned=%s',
					(string) $r['provider'],
					(string) $r['model'],
					(string) $r['eol'],
					(int) $r['days_left'],
					! empty( $r['pinned'] ) ? 'yes' : 'no'
				)
			);
		}
		\WP_CLI::error(
			sprintf(
				'%d model(s) past or within 14 days of retirement.',
				count( $failures )
			)
		);
	}
}
