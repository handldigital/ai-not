<?php
/**
 * WP-CLI for AICAC-RESIDENCY (#229).
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * @when after_wp_load
 */
final class CLI_Residency {

	public static function register(): void {
		if ( ! defined( 'WP_CLI' ) || ! WP_CLI ) {
			return;
		}
		if ( ! class_exists( '\WP_CLI' ) ) {
			return;
		}
		\WP_CLI::add_command( 'handl-aicac residency', self::class );
	}

	/**
	 * Show the saved residency region, unknown-provider mode, and map overrides.
	 *
	 * ## OPTIONS
	 *
	 * [--format=<format>]
	 * : table or json.
	 * ---
	 * default: table
	 * options:
	 *   - table
	 *   - json
	 * ---
	 *
	 * ## EXAMPLES
	 *
	 *     wp handl-aicac residency get
	 *     wp handl-aicac residency get --format=json
	 *
	 * @subcommand get
	 *
	 * @param array<int,string>    $args
	 * @param array<string,string> $assoc_args
	 */
	public function get( $args, $assoc_args ): void {
		unset( $args );
		$format   = isset( $assoc_args['format'] ) ? (string) $assoc_args['format'] : 'table';
		$settings = Residency::get();
		$row      = array(
			'region'         => $settings['region'],
			'strict_unknown' => ! empty( $settings['strict_unknown'] ) ? 'on' : 'off',
			'rule'           => Residency::region_label( $settings['region'] ),
			'map_overrides'  => count( $settings['map'] ),
		);

		if ( 'json' === $format ) {
			\WP_CLI::print_value(
				array_merge(
					$settings,
					array(
						'rule' => $row['rule'],
					)
				),
				array( 'format' => 'json' )
			);
			return;
		}

		\WP_CLI\Utils\format_items( 'table', array( $row ), array( 'region', 'strict_unknown', 'rule', 'map_overrides' ) );
	}

	/**
	 * Set the approved region and unknown-provider mode.
	 *
	 * ## OPTIONS
	 *
	 * [--region=<region>]
	 * : none (default), eu, or us.
	 *
	 * [--strict-unknown=<on|off>]
	 * : Block unmapped providers (on) or allow and tag a warning (off).
	 *
	 * [--map=<text>]
	 * : Override lines, `provider=region,region`. Empty region unmaps.
	 *
	 * ## EXAMPLES
	 *
	 *     wp handl-aicac residency set --region=eu
	 *     wp handl-aicac residency set --region=us --strict-unknown=on
	 *     wp handl-aicac residency set --region=none
	 *     wp handl-aicac residency set --map='mistral=eu'
	 *
	 * @subcommand set
	 *
	 * @param array<int,string>    $args
	 * @param array<string,string> $assoc_args
	 */
	public function set( $args, $assoc_args ): void {
		unset( $args );
		$current = Residency::get();

		if ( isset( $assoc_args['region'] ) ) {
			$region = sanitize_key( (string) $assoc_args['region'] );
			if ( ! in_array( $region, Residency::approved_sets(), true ) ) {
				\WP_CLI::error( 'Region must be none, eu, or us.' );
			}
			$current['region'] = $region;
		}

		if ( isset( $assoc_args['strict-unknown'] ) ) {
			$raw = sanitize_key( (string) $assoc_args['strict-unknown'] );
			if ( ! in_array( $raw, array( 'on', 'off', '1', '0' ), true ) ) {
				\WP_CLI::error( 'strict-unknown must be on or off.' );
			}
			$current['strict_unknown'] = in_array( $raw, array( 'on', '1' ), true );
		}

		if ( isset( $assoc_args['map'] ) ) {
			$current['map'] = Residency::parse_map_text( (string) $assoc_args['map'] );
		}

		$saved = Residency::save( $current );
		\WP_CLI::success(
			sprintf(
				'Data residency: %s. Unknown providers: %s.',
				Residency::region_label( $saved['region'] ),
				! empty( $saved['strict_unknown'] ) ? 'block' : 'allow and warn'
			)
		);
	}
}
