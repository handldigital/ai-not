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
 *     # Show whether uninstall keeps or removes plugin data
 *     $ wp handl-aicac uninstall get
 *
 *     # Remove plugin data the next time the plugin is deleted
 *     $ wp handl-aicac uninstall set purge
 *
 * @when after_wp_load
 */
final class CLI {

	public const UNINSTALL_OPTION_KEY = 'handl_aicac_uninstall_policy';
	public const UNINSTALL_KEEP       = 'keep';
	public const UNINSTALL_PURGE      = 'purge';

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
		\WP_CLI::add_command( 'handl-aicac uninstall get', array( self::class, 'cmd_uninstall_get' ) );
		\WP_CLI::add_command( 'handl-aicac uninstall set', array( self::class, 'cmd_uninstall_set' ) );
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

	/**
	 * Stored uninstall policy for this site. Missing or unknown = keep.
	 *
	 * @return 'keep'|'purge'
	 */
	public static function get_uninstall_policy(): string {
		$raw = get_option( self::UNINSTALL_OPTION_KEY, self::UNINSTALL_KEEP );
		return ( self::UNINSTALL_PURGE === $raw ) ? self::UNINSTALL_PURGE : self::UNINSTALL_KEEP;
	}

	/**
	 * Persist keep or purge. Does not uninstall.
	 *
	 * @return string|null Error message, or null when saved.
	 */
	public static function set_uninstall_policy( string $mode ): ?string {
		$mode = sanitize_text_field( $mode );
		if ( ! in_array( $mode, array( self::UNINSTALL_KEEP, self::UNINSTALL_PURGE ), true ) ) {
			return 'Use keep or purge.';
		}
		update_option( self::UNINSTALL_OPTION_KEY, $mode, false );
		return null;
	}

	/**
	 * Plain status line for get/set.
	 */
	public static function uninstall_status_message( string $mode ): string {
		if ( self::UNINSTALL_PURGE === $mode ) {
			return 'Uninstall will remove all plugin data.';
		}
		return 'Uninstall will keep plugin data.';
	}

	/**
	 * Print the stored uninstall policy.
	 *
	 * ## EXAMPLES
	 *
	 *     wp handl-aicac uninstall get
	 *
	 * @param array<int,string>    $args
	 * @param array<string,string> $assoc_args
	 */
	public static function cmd_uninstall_get( $args, $assoc_args ): void {
		unset( $args, $assoc_args );
		$mode = self::get_uninstall_policy();
		\WP_CLI::log( $mode );
		\WP_CLI::success( self::uninstall_status_message( $mode ) );
	}

	/**
	 * Choose keep or purge for the next plugin delete.
	 *
	 * ## OPTIONS
	 *
	 * <policy>
	 * : keep (default) or purge.
	 *
	 * ## EXAMPLES
	 *
	 *     wp handl-aicac uninstall set keep
	 *     wp handl-aicac uninstall set purge
	 *
	 * @param array<int,string>    $args       keep or purge.
	 * @param array<string,string> $assoc_args Unused.
	 */
	public static function cmd_uninstall_set( $args, $assoc_args ): void {
		unset( $assoc_args );
		$mode  = isset( $args[0] ) ? (string) $args[0] : '';
		$error = self::set_uninstall_policy( $mode );
		if ( null !== $error ) {
			\WP_CLI::error( $error );
		}
		\WP_CLI::success( self::uninstall_status_message( self::get_uninstall_policy() ) );
	}
}
