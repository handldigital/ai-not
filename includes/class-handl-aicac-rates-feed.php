<?php
/**
 * AICAC-RATES-FEED (#334): signed cost-rate table updates between releases.
 *
 * Reuses the Threat_Feed / #318 signed-feed transport (same URL, Ed25519 key,
 * tamper rejection, and air-gap). Observability only — never changes Allow/Deny.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Versioned remote cost-rate table layered under admin overrides.
 */
final class Rates_Feed {

	public const OPTION_KEY = 'handl_aicac_rates_feed';

	public const VERSION_MAX = 64;

	/**
	 * @var bool
	 */
	private static $registered = false;

	public static function reset_for_tests(): void {
		self::$registered = false;
		delete_option( self::OPTION_KEY );
	}

	/**
	 * Stored payload. Empty map when air-gap is on (stored set is ignored, not deleted).
	 *
	 * @return array{
	 *   version:string,
	 *   updated_at:int,
	 *   providers:array<string,array{input_per_m:float,output_per_m:float}>
	 * }
	 */
	public static function remote_rates(): array {
		if ( class_exists( Threat_Feed::class, false ) && Threat_Feed::is_fetch_disabled() ) {
			return self::empty_state();
		}

		return self::stored_rates();
	}

	/**
	 * @return array{
	 *   version:string,
	 *   updated_at:int,
	 *   providers:array<string,array{input_per_m:float,output_per_m:float}>
	 * }
	 */
	public static function stored_rates(): array {
		return self::sanitize_state( get_option( self::OPTION_KEY, array() ) );
	}

	/**
	 * Active feed rates for estimates, or empty when air-gapped / unset.
	 *
	 * @return array<string,array{input_per_m:float,output_per_m:float}>
	 */
	public static function active_provider_rates(): array {
		$state = self::remote_rates();

		return $state['providers'];
	}

	/**
	 * Bundled Cost_Receipt provider table used when the feed is off or missing a row.
	 *
	 * @return array<string,array{input_per_m:float,output_per_m:float}>
	 */
	public static function bundled_provider_rates(): array {
		if ( class_exists( Cost_Receipt::class, false ) ) {
			$table = Cost_Receipt::bundled_table();
			if ( isset( $table['providers'] ) && is_array( $table['providers'] ) ) {
				return Cost::sanitize_provider_rates( $table['providers'] );
			}
		}

		return array();
	}

	/**
	 * Status lines for WP-CLI / admin (version + date).
	 *
	 * @return array{version:string,updated_at:int,provider_count:int,active:bool}
	 */
	public static function status(): array {
		$stored = self::stored_rates();
		$active = ! ( class_exists( Threat_Feed::class, false ) && Threat_Feed::is_fetch_disabled() );

		return array(
			'version'        => $stored['version'],
			'updated_at'     => $stored['updated_at'],
			'provider_count' => count( $stored['providers'] ),
			'active'         => $active && ( '' !== $stored['version'] || ! empty( $stored['providers'] ) ),
		);
	}

	/**
	 * @param mixed $raw
	 * @return array{
	 *   version:string,
	 *   updated_at:int,
	 *   providers:array<string,array{input_per_m:float,output_per_m:float}>
	 * }
	 */
	public static function sanitize_state( $raw ): array {
		if ( ! is_array( $raw ) ) {
			return self::empty_state();
		}
		$version = sanitize_text_field( (string) ( $raw['version'] ?? '' ) );
		if ( strlen( $version ) > self::VERSION_MAX ) {
			$version = substr( $version, 0, self::VERSION_MAX );
		}
		$providers_raw = $raw['providers'] ?? array();
		if ( isset( $raw['items'] ) && is_array( $raw['items'] ) && ! is_array( $providers_raw ) ) {
			$providers_raw = $raw['items'];
		}

		return array(
			'version'    => $version,
			'updated_at' => max( 0, (int) ( $raw['updated_at'] ?? 0 ) ),
			'providers'  => self::sanitize_rates_payload( $providers_raw ),
		);
	}

	/**
	 * @param mixed $raw Payload `rates` object (`version` + `providers`/`items`).
	 * @return array{version:string,providers:array<string,array{input_per_m:float,output_per_m:float}>}|null
	 */
	public static function sanitize_rates_block( $raw ): ?array {
		if ( ! is_array( $raw ) ) {
			return null;
		}
		$version = sanitize_text_field( (string) ( $raw['version'] ?? $raw['rates_version'] ?? '' ) );
		if ( strlen( $version ) > self::VERSION_MAX ) {
			$version = substr( $version, 0, self::VERSION_MAX );
		}
		if ( array_key_exists( 'providers', $raw ) ) {
			$providers_raw = $raw['providers'];
		} elseif ( array_key_exists( 'items', $raw ) ) {
			$providers_raw = $raw['items'];
		} else {
			$providers_raw = $raw;
			unset( $providers_raw['version'], $providers_raw['rates_version'], $providers_raw['generated_at'] );
		}

		return array(
			'version'   => $version,
			'providers' => self::sanitize_rates_payload( $providers_raw ),
		);
	}

	/**
	 * Accept map keyed by provider id or list of {id,input,output} rows.
	 *
	 * @param mixed $raw
	 * @return array<string,array{input_per_m:float,output_per_m:float}>
	 */
	public static function sanitize_rates_payload( $raw ): array {
		if ( ! is_array( $raw ) ) {
			return array();
		}
		$map = array();
		$is_list = array_keys( $raw ) === range( 0, count( $raw ) - 1 );
		if ( $is_list ) {
			foreach ( $raw as $row ) {
				if ( ! is_array( $row ) ) {
					continue;
				}
				$id = Cost::normalize_provider_id( (string) ( $row['id'] ?? $row['provider'] ?? '' ) );
				if ( '' === $id || ! Cost::is_known_provider( $id ) ) {
					continue;
				}
				$map[ $id ] = $row;
			}
		} else {
			$map = $raw;
		}

		return Cost::sanitize_provider_rates( $map );
	}

	/**
	 * Persist a verified rates block from the signed feed.
	 *
	 * @param array{version?:string,providers?:array<string,array{input_per_m:float,output_per_m:float}>} $block
	 */
	public static function apply_remote_rates( array $block, int $now ): void {
		$version = sanitize_text_field( (string) ( $block['version'] ?? '' ) );
		if ( strlen( $version ) > self::VERSION_MAX ) {
			$version = substr( $version, 0, self::VERSION_MAX );
		}
		$providers = isset( $block['providers'] ) && is_array( $block['providers'] )
			? Cost::sanitize_provider_rates( $block['providers'] )
			: array();

		update_option(
			self::OPTION_KEY,
			array(
				'version'    => $version,
				'updated_at' => max( 0, $now ),
				'providers'  => $providers,
			),
			false
		);
	}

	/**
	 * @return array{
	 *   version:string,
	 *   updated_at:int,
	 *   providers:array<string,array{input_per_m:float,output_per_m:float}>
	 * }
	 */
	private static function empty_state(): array {
		return array(
			'version'    => '',
			'updated_at' => 0,
			'providers'  => array(),
		);
	}
}
