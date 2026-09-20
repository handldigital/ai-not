<?php
/**
 * AICAC-RESIDENCY (#229): site-level provider region filter.
 *
 * Admin picks none / listed-for-EU / listed-for-US. A request whose provider
 * is not listed for that selection is denied with reason `residency`.
 * Unknown providers warn (allow + tag) unless fail-closed.
 *
 * Provider → region map is a saved list of public API endpoint regions —
 * no live geolocation, no outbound calls, no processing/storage check.
 * Site owners extend or correct it with the
 * `handl_aicac_residency_provider_map` filter or the settings map.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Residency {

	public const OPTION_KEY = 'handl_aicac_residency';

	public const REGION_NONE = 'none';
	public const REGION_EU   = 'eu';
	public const REGION_US   = 'us';

	public const REASON = 'residency';

	public const FILTER_MAP = 'handl_aicac_residency_provider_map';

	/**
	 * Tokens a provider row may list.
	 *
	 * @return list<string>
	 */
	public static function region_tokens(): array {
		return array( 'eu', 'us', 'uk', 'cn' );
	}

	/**
	 * Approved sets the admin can enforce.
	 *
	 * @return list<string>
	 */
	public static function approved_sets(): array {
		return array( self::REGION_NONE, self::REGION_EU, self::REGION_US );
	}

	/**
	 * Built-in public-API endpoint regions. Not enterprise/regional SKUs.
	 *
	 * @return array<string,list<string>>
	 */
	public static function default_provider_map(): array {
		return array(
			'openai'     => array( 'us' ),
			'anthropic'  => array( 'us' ),
			'google'     => array( 'us' ),
			'cohere'     => array( 'us' ),
			'mistral'    => array( 'eu' ),
			'groq'       => array( 'us' ),
			'together'   => array( 'us' ),
			'fireworks'  => array( 'us' ),
			'perplexity' => array( 'us' ),
			'xai'        => array( 'us' ),
			'deepseek'   => array( 'cn' ),
			'openrouter' => array( 'us' ),
		);
	}

	/**
	 * @param mixed $raw
	 */
	public static function sanitize_region( $raw ): string {
		$region = sanitize_key( (string) $raw );
		if ( self::REGION_EU === $region || self::REGION_US === $region ) {
			return $region;
		}

		return self::REGION_NONE;
	}

	/**
	 * @param mixed $raw
	 * @return list<string>
	 */
	public static function sanitize_region_list( $raw ): array {
		if ( is_string( $raw ) ) {
			$raw = preg_split( '/[\s,;]+/', $raw ) ?: array();
		}
		if ( ! is_array( $raw ) ) {
			return array();
		}
		$allowed = array_fill_keys( self::region_tokens(), true );
		$out     = array();
		foreach ( $raw as $token ) {
			$token = sanitize_key( (string) $token );
			if ( isset( $allowed[ $token ] ) ) {
				$out[] = $token;
			}
		}

		return array_values( array_unique( $out ) );
	}

	/**
	 * Empty region list is kept as an unmap marker (settings overrides only).
	 *
	 * @param mixed $raw
	 * @return array<string,list<string>>
	 */
	public static function sanitize_provider_map( $raw ): array {
		if ( ! is_array( $raw ) ) {
			return array();
		}
		$out = array();
		foreach ( $raw as $provider => $regions ) {
			$provider = Cost::normalize_provider_id( (string) $provider );
			if ( '' === $provider ) {
				continue;
			}
			$out[ $provider ] = self::sanitize_region_list( $regions );
		}

		return $out;
	}

	/**
	 * Parse settings/CLI text: one `provider=region,region` line.
	 * A line with an empty region list records an unmap sentinel.
	 *
	 * @return array<string,list<string>>
	 */
	public static function parse_map_text( string $text ): array {
		$out = array();
		foreach ( preg_split( '/\R/', $text ) ?: array() as $line ) {
			$line = trim( $line );
			if ( '' === $line || '#' === $line[0] ) {
				continue;
			}
			if ( false === strpos( $line, '=' ) ) {
				continue;
			}
			list( $provider, $regions ) = array_map( 'trim', explode( '=', $line, 2 ) );
			$provider = Cost::normalize_provider_id( $provider );
			if ( '' === $provider ) {
				continue;
			}
			$out[ $provider ] = self::sanitize_region_list( $regions );
		}

		return $out;
	}

	/**
	 * @param array<string,list<string>> $map
	 */
	public static function format_map_text( array $map ): string {
		$lines = array();
		foreach ( $map as $provider => $regions ) {
			$lines[] = $provider . '=' . implode( ',', $regions );
		}

		return implode( "\n", $lines );
	}

	/**
	 * @param mixed $raw
	 * @return array{region:string,strict_unknown:bool,map:array<string,list<string>>}
	 */
	public static function sanitize_settings( $raw ): array {
		if ( ! is_array( $raw ) ) {
			$raw = array();
		}

		return array(
			'region'         => self::sanitize_region( $raw['region'] ?? self::REGION_NONE ),
			'strict_unknown' => ! empty( $raw['strict_unknown'] ),
			'map'            => self::sanitize_provider_map( $raw['map'] ?? array() ),
		);
	}

	/**
	 * @return array{region:string,strict_unknown:bool,map:array<string,list<string>>}
	 */
	public static function get(): array {
		return self::sanitize_settings( get_option( self::OPTION_KEY, array() ) );
	}

	/**
	 * @param array<string,mixed> $settings
	 * @return array{region:string,strict_unknown:bool,map:array<string,list<string>>}
	 */
	public static function save( array $settings ): array {
		$clean = self::sanitize_settings( $settings );
		if ( self::REGION_NONE === $clean['region'] && empty( $clean['strict_unknown'] ) && empty( $clean['map'] ) ) {
			delete_option( self::OPTION_KEY );
			return $clean;
		}
		update_option( self::OPTION_KEY, $clean, false );

		return $clean;
	}

	public static function save_from_post(): void {
		$region = isset( $_POST['handl_aicac_residency_region'] )
			? wp_unslash( (string) $_POST['handl_aicac_residency_region'] )
			: self::REGION_NONE;
		$map_raw = isset( $_POST['handl_aicac_residency_map'] )
			? wp_unslash( (string) $_POST['handl_aicac_residency_map'] )
			: '';

		self::save(
			array(
				'region'         => $region,
				'strict_unknown' => ! empty( $_POST['handl_aicac_residency_strict_unknown'] ),
				'map'            => self::parse_map_text( (string) $map_raw ),
			)
		);
	}

	/**
	 * Filter + settings overrides on top of the built-in map.
	 * An override with an empty region list unmaps that provider.
	 *
	 * @return array<string,list<string>>
	 */
	public static function provider_map(): array {
		$map = self::default_provider_map();
		if ( function_exists( 'apply_filters' ) ) {
			$filtered = apply_filters( self::FILTER_MAP, $map );
			if ( is_array( $filtered ) ) {
				$map = self::sanitize_provider_map( $filtered );
			}
		}

		$overrides = self::get()['map'];
		foreach ( $overrides as $provider => $regions ) {
			if ( empty( $regions ) ) {
				unset( $map[ $provider ] );
				continue;
			}
			$map[ $provider ] = $regions;
		}

		return $map;
	}

	public static function normalize_provider( ?string $provider ): string {
		return Cost::normalize_provider_id( (string) $provider );
	}

	/**
	 * @return list<string>
	 */
	public static function regions_for_provider( string $provider ): array {
		$provider = self::normalize_provider( $provider );
		if ( '' === $provider ) {
			return array();
		}
		$map = self::provider_map();
		if ( ! isset( $map[ $provider ] ) ) {
			return array();
		}

		return $map[ $provider ];
	}

	/**
	 * @return list<string>
	 */
	public static function approved_tokens( string $region ): array {
		$region = self::sanitize_region( $region );
		if ( self::REGION_EU === $region ) {
			return array( 'eu' );
		}
		if ( self::REGION_US === $region ) {
			return array( 'us' );
		}

		return array();
	}

	public static function region_label( string $region ): string {
		$region = self::sanitize_region( $region );
		if ( self::REGION_EU === $region ) {
			return __( 'Listed for the European Union', 'handl-ai-connector-access-control' );
		}
		if ( self::REGION_US === $region ) {
			return __( 'Listed for the United States', 'handl-ai-connector-access-control' );
		}

		return __( 'No restriction', 'handl-ai-connector-access-control' );
	}

	/**
	 * WP-CLI `residency set` success line. Region none disables the filter,
	 * so the unknown-provider mode is not reported as active.
	 *
	 * @param array<string,mixed> $settings
	 */
	public static function cli_set_success_message( array $settings ): string {
		$settings = self::sanitize_settings( $settings );
		if ( self::REGION_NONE === $settings['region'] ) {
			return sprintf(
				'Provider region filter: %s. Unknown-provider check is inactive.',
				self::region_label( $settings['region'] )
			);
		}

		return sprintf(
			'Provider region filter: %s. Providers with no listed region: %s.',
			self::region_label( $settings['region'] ),
			! empty( $settings['strict_unknown'] ) ? 'block' : 'allow and warn'
		);
	}

	/**
	 * @return array{
	 *   active:bool,
	 *   prevent:bool,
	 *   unknown:bool,
	 *   provider:string,
	 *   regions:list<string>,
	 *   approved:list<string>,
	 *   rule:string,
	 *   reason:string
	 * }
	 */
	public static function evaluate( ?string $provider, ?array $settings = null ): array {
		$settings = null !== $settings ? self::sanitize_settings( $settings ) : self::get();
		$region   = $settings['region'];
		$empty    = array(
			'active'   => false,
			'prevent'  => false,
			'unknown'  => false,
			'provider' => self::normalize_provider( $provider ),
			'regions'  => array(),
			'approved' => array(),
			'rule'     => self::region_label( $region ),
			'reason'   => '',
		);

		if ( self::REGION_NONE === $region ) {
			return $empty;
		}

		$approved = self::approved_tokens( $region );
		$id       = self::normalize_provider( $provider );
		$regions  = '' === $id ? array() : self::regions_for_provider( $id );
		$unknown  = '' === $id || empty( $regions );
		$base     = array(
			'active'   => true,
			'prevent'  => false,
			'unknown'  => $unknown,
			'provider' => $id,
			'regions'  => $regions,
			'approved' => $approved,
			'rule'     => self::region_label( $region ),
			'reason'   => '',
		);

		if ( $unknown ) {
			if ( ! empty( $settings['strict_unknown'] ) ) {
				$base['prevent'] = true;
				$base['reason']  = self::REASON;
			}

			return $base;
		}

		$overlap = array_values( array_intersect( $regions, $approved ) );
		if ( empty( $overlap ) ) {
			$base['prevent'] = true;
			$base['reason']  = self::REASON;
		}

		return $base;
	}

	/**
	 * Tag an Activity event and report whether to block.
	 *
	 * @param array<string,mixed>      $event
	 * @param array<string,mixed>|null $policy Unused; kept so the call site matches other gates.
	 * @return array{active:bool,prevent:bool,unknown:bool,rule:string}
	 */
	public static function apply_to_event( array &$event, $policy = null, ?string $provider = null ): array {
		unset( $policy );
		if ( null === $provider ) {
			$provider = isset( $event['provider'] ) ? (string) $event['provider'] : '';
		}

		$eval = self::evaluate( $provider );
		if ( empty( $eval['active'] ) ) {
			return array(
				'active'  => false,
				'prevent' => false,
				'unknown' => false,
				'rule'    => $eval['rule'],
			);
		}

		$event['residency_region']   = self::get()['region'];
		$event['residency_provider'] = $eval['provider'];
		$event['residency_rule']     = $eval['rule'];
		if ( ! empty( $eval['unknown'] ) ) {
			$event['residency_unknown'] = true;
		}

		return array(
			'active'  => true,
			'prevent' => ! empty( $eval['prevent'] ),
			'unknown' => ! empty( $eval['unknown'] ),
			'rule'    => $eval['rule'],
		);
	}
}
