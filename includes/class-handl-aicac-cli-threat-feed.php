<?php
/**
 * WP-CLI for AICAC-SIGNATURE-FEED (#318) / threat-feed status.
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
final class CLI_Threat_Feed {

	public static function register(): void {
		if ( ! defined( 'WP_CLI' ) || ! WP_CLI ) {
			return;
		}
		if ( ! class_exists( '\WP_CLI' ) ) {
			return;
		}
		\WP_CLI::add_command( 'handl-aicac threat-feed', self::class );
	}

	/**
	 * List active remote provider-map signatures from the threat feed.
	 *
	 * ## EXAMPLES
	 *
	 *     wp handl-aicac threat-feed status
	 *
	 * @subcommand status
	 *
	 * @param array<int,string>    $args
	 * @param array<string,string> $assoc_args
	 */
	public function status( $args, $assoc_args ): void {
		unset( $args, $assoc_args );
		if ( Threat_Feed::is_fetch_disabled() ) {
			\WP_CLI::log( __( 'Threat feed is turned off.', 'handl-ai-connector-access-control' ) );
			return;
		}
		$rows = Threat_Feed::remote_signatures();
		if ( empty( $rows ) ) {
			\WP_CLI::log( __( 'No remote signatures stored.', 'handl-ai-connector-access-control' ) );
			return;
		}
		\WP_CLI::log(
			sprintf(
				/* translators: %d: number of remote signature rows */
				__( 'Remote signatures: %d', 'handl-ai-connector-access-control' ),
				count( $rows )
			)
		);
		$items = array();
		foreach ( $rows as $id => $row ) {
			$items[] = array(
				'provider' => (string) $id,
				'label'    => (string) ( $row['label'] ?? $id ),
				'hosts'    => implode( ', ', (array) ( $row['hosts'] ?? array() ) ),
			);
		}
		if ( method_exists( '\WP_CLI', 'format_items' ) ) {
			\WP_CLI::format_items( 'table', $items, array( 'provider', 'label', 'hosts' ) );
			return;
		}
		foreach ( $items as $item ) {
			\WP_CLI::log( $item['provider'] . ' / ' . $item['label'] . ' / ' . $item['hosts'] );
		}
	}
}
