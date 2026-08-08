<?php
/**
 * WP-CLI commands for HandL AICAC rules.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Manage per-plugin capability-family allow/deny rules.
 *
 * ## EXAMPLES
 *
 *     # List family rules as a table
 *     $ wp aicac rule list
 *
 *     # List family rules as JSON
 *     $ wp aicac rule list --format=json
 *
 *     # Deny text generation for a plugin
 *     $ wp aicac rule set acme-plugin/acme-plugin.php text deny
 *
 *     # Clear a family rule (inherit plugin AI access)
 *     $ wp aicac rule set acme-plugin/acme-plugin.php image inherit
 *
 * @when after_wp_load
 */
final class CLI {

	/**
	 * Register WP-CLI commands when WP-CLI is available.
	 */
	public static function register(): void {
		if ( ! defined( 'WP_CLI' ) || ! WP_CLI ) {
			return;
		}
		if ( ! class_exists( '\WP_CLI' ) ) {
			return;
		}
		\WP_CLI::add_command( 'aicac rule', self::class );
	}

	/**
	 * List per-plugin capability-family rules.
	 *
	 * ## OPTIONS
	 *
	 * [--format=<format>]
	 * : Render format (table or json).
	 * ---
	 * default: table
	 * options:
	 *   - table
	 *   - json
	 * ---
	 *
	 * ## EXAMPLES
	 *
	 *     wp aicac rule list
	 *     wp aicac rule list --format=json
	 *
	 * @subcommand list
	 *
	 * @param array<int,string>    $args       Positional args (unused).
	 * @param array<string,string> $assoc_args Associative args.
	 */
	public function list_( $args, $assoc_args ): void {
		unset( $args );
		$format = isset( $assoc_args['format'] ) ? (string) $assoc_args['format'] : 'table';
		if ( 'json' !== $format ) {
			$format = 'table';
		}

		$rows = self::list_rows();
		if ( 'json' === $format ) {
			\WP_CLI::print_value( $rows, array( 'format' => 'json' ) );
			return;
		}

		$fields = array_merge(
			array( 'plugin', 'name', 'status' ),
			Operations::families()
		);
		\WP_CLI\Utils\format_items( 'table', $rows, $fields );
	}

	/**
	 * Set a single capability-family rule for one plugin.
	 *
	 * ## OPTIONS
	 *
	 * <plugin>
	 * : Plugin basename as shown on the Rules tab (e.g. acme-plugin/acme-plugin.php).
	 *
	 * <family>
	 * : Capability family: text, image, speech, tts, or video.
	 *
	 * <rule>
	 * : allow, deny, or inherit.
	 *
	 * ## EXAMPLES
	 *
	 *     wp aicac rule set acme-plugin/acme-plugin.php text deny
	 *
	 * @subcommand set
	 *
	 * @param array<int,string>    $args       plugin, family, rule.
	 * @param array<string,string> $assoc_args Unused.
	 */
	public function set( $args, $assoc_args ): void {
		unset( $assoc_args );

		// WP-CLI enforces required positionals before invoke; defensive guard for tests.
		if ( count( $args ) < 3 ) {
			\WP_CLI::error( 'Usage: wp aicac rule set <plugin> <family> <allow|deny|inherit>' );
		}

		$plugin = (string) $args[0];
		$family = (string) $args[1];
		$rule   = (string) $args[2];

		$error = self::validate_set_args( $plugin, $family, $rule, self::known_plugin_basenames() );
		if ( null !== $error ) {
			\WP_CLI::error( $error );
		}

		if ( ! Policy::set_family_rule( $plugin, $family, $rule ) ) {
			\WP_CLI::error( 'Failed to save family rule.' );
		}

		\WP_CLI::success( self::set_confirmation_message( $plugin, $family, $rule ) );
	}

	/**
	 * @return list<array<string,string>>
	 */
	public static function list_rows(): array {
		$plugins = self::installed_plugins();
		$active  = array();
		foreach ( array_keys( $plugins ) as $basename ) {
			if ( function_exists( 'is_plugin_active' ) && is_plugin_active( $basename ) ) {
				$active[ $basename ] = true;
			}
		}

		return Policy::family_rule_rows_for_plugins( $plugins, Policy::get_policy(), $active );
	}

	/**
	 * Plugins known to the Rules tab (installed; active and inactive).
	 *
	 * @return array<string,array<string,mixed>>
	 */
	public static function installed_plugins(): array {
		if ( ! function_exists( 'get_plugins' ) ) {
			return array();
		}
		$plugins = get_plugins();
		return is_array( $plugins ) ? $plugins : array();
	}

	/**
	 * @return list<string>
	 */
	public static function known_plugin_basenames(): array {
		return array_map( 'strval', array_keys( self::installed_plugins() ) );
	}

	/**
	 * Validate set arguments without writing.
	 *
	 * @param list<string> $known_basenames Installed plugin basenames.
	 * @return string|null Error message, or null when valid.
	 */
	public static function validate_set_args( string $plugin, string $family, string $rule, array $known_basenames ): ?string {
		$plugin = sanitize_text_field( $plugin );
		$family = sanitize_text_field( $family );
		$rule   = sanitize_text_field( $rule );

		if ( '' === $plugin || ! in_array( $plugin, $known_basenames, true ) ) {
			return sprintf(
				'Unrecognized plugin basename: %s. Use a basename from `wp aicac rule list` (installed plugins, including inactive).',
				$plugin
			);
		}

		if ( ! in_array( $family, Operations::families(), true ) ) {
			return sprintf(
				'Unrecognized capability family: %s. Expected one of: %s.',
				$family,
				implode( ', ', Operations::families() )
			);
		}

		if ( ! in_array( $rule, array( 'allow', 'deny', 'inherit' ), true ) ) {
			return sprintf(
				'Unrecognized rule: %s. Expected allow, deny, or inherit.',
				$rule
			);
		}

		return null;
	}

	/**
	 * Confirmation line after a successful set (exit 0 path).
	 */
	public static function set_confirmation_message( string $plugin, string $family, string $rule ): string {
		$rule = sanitize_text_field( $rule );
		if ( 'inherit' === $rule || '' === $rule ) {
			return sprintf( 'Cleared %s family rule for %s (inherit).', $family, $plugin );
		}
		return sprintf( 'Set %s family rule for %s to %s.', $family, $plugin, $rule );
	}
}
