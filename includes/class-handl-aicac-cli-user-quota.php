<?php
/**
 * WP-CLI: `wp handl-aicac user-quota` for AICAC-USER-QUOTA (#339).
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
final class CLI_User_Quota {

	public static function register(): void {
		if ( ! defined( 'WP_CLI' ) || ! WP_CLI ) {
			return;
		}
		if ( ! class_exists( '\WP_CLI' ) ) {
			return;
		}
		\WP_CLI::add_command( 'handl-aicac user-quota', self::class );
	}

	/**
	 * Show rolling-24h usage and effective quota for one user.
	 *
	 * ## OPTIONS
	 *
	 * <user>
	 * : User ID or login.
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
	 *     wp handl-aicac user-quota get 12
	 *     wp handl-aicac user-quota get editor1 --format=json
	 *
	 * @subcommand get
	 *
	 * @param array<int,string>    $args
	 * @param array<string,string> $assoc_args
	 */
	public function get( $args, $assoc_args ): void {
		$raw = isset( $args[0] ) ? (string) $args[0] : '';
		$user_id = self::resolve_user_id( $raw );
		if ( $user_id <= 0 ) {
			\WP_CLI::error( 'Need a user ID or login.' );
		}

		$format = isset( $assoc_args['format'] ) ? (string) $assoc_args['format'] : 'table';
		$policy = Policy::get_policy();
		$eval   = User_Quota::evaluate( $policy, $user_id );

		$payload = array(
			'user_id'  => $user_id,
			'limit'    => $eval['limit'],
			'count'    => $eval['count'],
			'source'   => $eval['source'],
			'prevent'  => ! empty( $eval['prevent'] ),
			'override' => User_Quota::user_override( $user_id ),
			'roles'    => User_Quota::roles_for_user( $user_id ),
		);

		if ( 'json' === $format ) {
			\WP_CLI::print_value( $payload, array( 'format' => 'json' ) );
			return;
		}

		$rows = array(
			array(
				'field' => 'limit',
				'value' => null === $payload['limit'] ? 'unlimited' : (string) $payload['limit'],
			),
			array(
				'field' => 'count_24h',
				'value' => (string) $payload['count'],
			),
			array(
				'field' => 'source',
				'value' => '' !== $payload['source'] ? (string) $payload['source'] : 'none',
			),
			array(
				'field' => 'prevent',
				'value' => $payload['prevent'] ? 'yes' : 'no',
			),
		);
		\WP_CLI::log( 'User ID: ' . $user_id );
		\WP_CLI\Utils\format_items( 'table', $rows, array( 'field', 'value' ) );
	}

	/**
	 * List role default quotas from policy.
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
	 * @subcommand roles
	 *
	 * @param array<int,string>    $args
	 * @param array<string,string> $assoc_args
	 */
	public function roles( $args, $assoc_args ): void {
		unset( $args );
		$format = isset( $assoc_args['format'] ) ? (string) $assoc_args['format'] : 'table';
		$limits = User_Quota::role_limits( Policy::get_policy() );
		$rows   = array();
		foreach ( $limits as $role => $limit ) {
			$rows[] = array(
				'role'  => $role,
				'limit' => (string) (int) $limit,
			);
		}

		if ( 'json' === $format ) {
			\WP_CLI::print_value( $limits, array( 'format' => 'json' ) );
			return;
		}

		if ( empty( $rows ) ) {
			\WP_CLI::log( 'No role quotas configured.' );
			return;
		}
		\WP_CLI\Utils\format_items( 'table', $rows, array( 'role', 'limit' ) );
	}

	private static function resolve_user_id( string $raw ): int {
		$raw = trim( $raw );
		if ( '' === $raw ) {
			return 0;
		}
		if ( ctype_digit( $raw ) ) {
			return (int) $raw;
		}
		if ( function_exists( 'get_user_by' ) ) {
			$user = get_user_by( 'login', $raw );
			if ( $user && isset( $user->ID ) ) {
				return (int) $user->ID;
			}
		}

		return 0;
	}
}
