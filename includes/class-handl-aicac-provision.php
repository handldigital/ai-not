<?php
/**
 * AICAC-PROVISION (#355): role-based day-one AI grants on user create/promotion.
 *
 * Admin defines per-role templates (allow → plugins via Temp_Allow/Policy;
 * request → no auto-grant). Hooks user_register / set_user_role / add_user_to_blog.
 * Grants only — never revokes — so it cannot fight OFFBOARD or DORMANT.
 * Ships with no templates (zero behavior until an admin creates one).
 *
 * Settings live in this class (own option + Protections hook), not admin.php.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Role → day-one grant templates.
 */
final class Provision {

	public const OPTION_KEY = 'handl_aicac_provision';

	public const MODE_ALLOW   = 'allow';
	public const MODE_REQUEST = 'request';

	public const CHANNEL = 'provision';

	public const POST_PRESENT = 'handl_aicac_provision_present';
	public const POST_ROLES   = 'handl_aicac_provision_roles';

	/** @var bool */
	private static $registered = false;

	public static function init(): void {
		if ( self::$registered ) {
			return;
		}
		self::$registered = true;

		add_action( 'user_register', array( self::class, 'on_user_register' ), 20, 1 );
		add_action( 'set_user_role', array( self::class, 'on_set_user_role' ), 20, 3 );
		add_action( 'add_user_to_blog', array( self::class, 'on_add_user_to_blog' ), 20, 3 );
		add_action( 'handl_aicac_protections_settings', array( self::class, 'render_settings' ) );
		add_filter( 'pre_update_option_' . Plugin::OPTION_KEY, array( self::class, 'capture_templates_on_policy_save' ), 10, 2 );
	}

	public static function reset_for_tests(): void {
		self::$registered = false;
		delete_option( self::OPTION_KEY );
	}

	/**
	 * @return array{templates:array<string,array{mode:string,plugins:list<string>}>}
	 */
	public static function get_settings(): array {
		return self::sanitize_settings( get_option( self::OPTION_KEY, array() ) );
	}

	/**
	 * @param mixed $raw
	 * @return array{templates:array<string,array{mode:string,plugins:list<string>}>}
	 */
	public static function sanitize_settings( $raw ): array {
		$out = array( 'templates' => array() );
		if ( ! is_array( $raw ) ) {
			return $out;
		}
		$src = isset( $raw['templates'] ) && is_array( $raw['templates'] )
			? $raw['templates']
			: $raw;
		foreach ( $src as $role => $row ) {
			$role = sanitize_key( (string) $role );
			if ( '' === $role || ! is_array( $row ) ) {
				continue;
			}
			$mode = sanitize_key( (string) ( $row['mode'] ?? self::MODE_REQUEST ) );
			if ( self::MODE_ALLOW !== $mode ) {
				$mode = self::MODE_REQUEST;
			}
			$plugins = array();
			$raw_plugins = $row['plugins'] ?? array();
			if ( is_string( $raw_plugins ) ) {
				$raw_plugins = preg_split( '/[\r\n,;]+/', $raw_plugins ) ?: array();
			}
			if ( is_array( $raw_plugins ) ) {
				foreach ( $raw_plugins as $plugin ) {
					$clean = Plugin_Profile::sanitize_plugin( (string) $plugin );
					if ( '' !== $clean ) {
						$plugins[] = $clean;
					}
				}
			}
			$plugins = array_values( array_unique( $plugins ) );
			// Drop empty request-only rows — they are the default (no template).
			if ( self::MODE_REQUEST === $mode && empty( $plugins ) ) {
				continue;
			}
			$out['templates'][ $role ] = array(
				'mode'    => $mode,
				'plugins' => $plugins,
			);
		}
		ksort( $out['templates'] );

		return $out;
	}

	/**
	 * Persist only when the sanitized payload differs from what is stored.
	 *
	 * @param array<string,mixed> $settings
	 * @return bool True when the option was written or deleted.
	 */
	public static function save_settings( array $settings ): bool {
		$clean  = self::sanitize_settings( $settings );
		$stored = get_option( self::OPTION_KEY, null );
		$prev   = self::sanitize_settings( is_array( $stored ) ? $stored : array() );

		if ( $clean === $prev ) {
			return false;
		}

		if ( empty( $clean['templates'] ) ) {
			if ( false === $stored || null === $stored ) {
				return false;
			}
			delete_option( self::OPTION_KEY );
			return true;
		}

		update_option( self::OPTION_KEY, $clean, false );
		return true;
	}

	/**
	 * @return array{mode:string,plugins:list<string>}|null
	 */
	public static function template_for_role( string $role ): ?array {
		$role = sanitize_key( $role );
		if ( '' === $role ) {
			return null;
		}
		$map = self::get_settings()['templates'];
		return isset( $map[ $role ] ) ? $map[ $role ] : null;
	}

	/**
	 * @param int $user_id
	 */
	public static function on_user_register( $user_id ): void {
		$user_id = (int) $user_id;
		if ( $user_id <= 0 ) {
			return;
		}
		$role = self::primary_role_for_user( $user_id );
		if ( '' === $role ) {
			return;
		}
		self::provision_user( $user_id, $role, 'register' );
	}

	/**
	 * @param int    $user_id
	 * @param string $role
	 * @param array  $old_roles Unused — grants only; demotion is OFFBOARD.
	 */
	public static function on_set_user_role( $user_id, $role, $old_roles ): void {
		unset( $old_roles );
		self::provision_user( (int) $user_id, sanitize_key( (string) $role ), 'role' );
	}

	/**
	 * @param int    $user_id
	 * @param string $role
	 * @param int    $blog_id Unused.
	 */
	public static function on_add_user_to_blog( $user_id, $role, $blog_id ): void {
		unset( $blog_id );
		self::provision_user( (int) $user_id, sanitize_key( (string) $role ), 'blog' );
	}

	/**
	 * Apply the role template. Grants only — never revokes.
	 *
	 * @return array{
	 *   applied:bool,
	 *   role:string,
	 *   mode:string,
	 *   plugins:list<string>,
	 *   role_added:bool,
	 *   summary:string
	 * }
	 */
	public static function provision_user( int $user_id, string $role, string $via = 'manual', ?int $now = null ): array {
		$empty = array(
			'applied'    => false,
			'role'       => '',
			'mode'       => '',
			'plugins'    => array(),
			'role_added' => false,
			'summary'    => '',
		);
		$user_id = (int) $user_id;
		$role    = sanitize_key( $role );
		if ( $user_id <= 0 || '' === $role ) {
			return $empty;
		}

		$template = self::template_for_role( $role );
		if ( null === $template ) {
			return $empty;
		}

		$mode = (string) $template['mode'];
		if ( self::MODE_ALLOW !== $mode ) {
			// request-only: documented template, no grant, no audit, no writes.
			return $empty;
		}

		$now     = null !== $now ? (int) $now : time();
		$via     = sanitize_key( $via );
		$plugins = is_array( $template['plugins'] ) ? $template['plugins'] : array();
		$granted = array();

		foreach ( $plugins as $plugin ) {
			$plugin = Plugin_Profile::sanitize_plugin( (string) $plugin );
			if ( '' === $plugin ) {
				continue;
			}
			if ( Inbox_Actions::apply_temp_allow_24h( $plugin, $now ) ) {
				$granted[] = $plugin;
			}
		}

		$role_added = self::ensure_role_allowed( $role );

		if ( empty( $granted ) && ! $role_added ) {
			// Template matched but nothing changed (already live) — still audit the provision event.
		}

		$who     = self::display_name_for( $user_id );
		$summary = self::build_summary( $who, $role, $granted, $role_added );
		self::append_audit( $user_id, $who, $role, $via, $granted, $role_added, $summary, $now );

		return array(
			'applied'    => true,
			'role'       => $role,
			'mode'       => self::MODE_ALLOW,
			'plugins'    => $granted,
			'role_added' => $role_added,
			'summary'    => $summary,
		);
	}

	/**
	 * Ensure the role can pass the role gate when the gate is on.
	 */
	public static function ensure_role_allowed( string $role ): bool {
		$role = sanitize_key( $role );
		if ( '' === $role ) {
			return false;
		}
		$policy = Policy::get_policy();
		if ( empty( $policy['role_gate_enabled'] ) ) {
			return false;
		}
		$allowed = Policy::sanitize_allowed_roles( $policy['allowed_roles'] ?? array() );
		if ( in_array( $role, $allowed, true ) ) {
			return false;
		}
		$allowed[]               = $role;
		$policy['allowed_roles'] = Policy::sanitize_allowed_roles( $allowed );
		Policy::save_policy( $policy );
		return true;
	}

	/**
	 * Capture template POST fields when the Protections form saves policy.
	 *
	 * @param mixed $value New policy value.
	 * @param mixed $old   Old policy value.
	 * @return mixed
	 */
	public static function capture_templates_on_policy_save( $value, $old ) {
		unset( $old );
		if ( ! isset( $_POST[ self::POST_PRESENT ] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Admin save already verified the form nonce.
			return $value;
		}
		$raw = isset( $_POST[ self::POST_ROLES ] ) ? wp_unslash( $_POST[ self::POST_ROLES ] ) : array(); // phpcs:ignore WordPress.Security.NonceVerification.Missing,WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		if ( ! is_array( $raw ) ) {
			$raw = array();
		}
		$templates = array();
		foreach ( $raw as $role => $row ) {
			$role = sanitize_key( (string) $role );
			if ( '' === $role || ! is_array( $row ) ) {
				continue;
			}
			$templates[ $role ] = array(
				'mode'    => isset( $row['mode'] ) ? (string) $row['mode'] : self::MODE_REQUEST,
				'plugins' => isset( $row['plugins'] ) ? (string) $row['plugins'] : '',
			);
		}
		self::save_settings( array( 'templates' => $templates ) );

		return $value;
	}

	/**
	 * @param array<string,mixed> $policy Unused.
	 */
	public static function render_settings( $policy ): void {
		unset( $policy );
		$settings  = self::get_settings();
		$available = Policy::available_roles_for_gate();
		if ( empty( $available ) ) {
			$available = array(
				'administrator' => 'Administrator',
				'editor'        => 'Editor',
				'author'        => 'Author',
				'contributor'   => 'Contributor',
				'subscriber'    => 'Subscriber',
			);
		}

		echo '<tr id="handl-aicac-provision">';
		echo '<th scope="row">' . esc_html__( 'Day-one AI grants', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<td>';
		echo '<input type="hidden" name="' . esc_attr( self::POST_PRESENT ) . '" value="1" />';
		echo '<p class="description">' . esc_html__( 'When a user is created or promoted into a role below, apply that role template. Allow grants temporary plugin access and adds the role to the role gate when the gate is on. Request leaves the user on the normal request flow. Leave every role on Request with no plugins to keep day-one grants off.', 'handl-ai-connector-access-control' ) . '</p>';
		echo '<table class="widefat striped" style="max-width:40rem;margin-top:0.5em;">';
		echo '<thead><tr>';
		echo '<th scope="col">' . esc_html__( 'Role', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th scope="col">' . esc_html__( 'Template', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th scope="col">' . esc_html__( 'Plugins (one per line)', 'handl-ai-connector-access-control' ) . '</th>';
		echo '</tr></thead><tbody>';

		foreach ( $available as $slug => $label ) {
			$row     = $settings['templates'][ $slug ] ?? array(
				'mode'    => self::MODE_REQUEST,
				'plugins' => array(),
			);
			$mode    = (string) ( $row['mode'] ?? self::MODE_REQUEST );
			$plugins = isset( $row['plugins'] ) && is_array( $row['plugins'] )
				? implode( "\n", $row['plugins'] )
				: '';
			$base    = self::POST_ROLES . '[' . $slug . ']';
			echo '<tr>';
			echo '<th scope="row">' . esc_html( (string) $label ) . '</th>';
			echo '<td><select name="' . esc_attr( $base . '[mode]' ) . '">';
			echo '<option value="' . esc_attr( self::MODE_REQUEST ) . '"' . selected( $mode, self::MODE_REQUEST, false ) . '>' . esc_html__( 'Request only', 'handl-ai-connector-access-control' ) . '</option>';
			echo '<option value="' . esc_attr( self::MODE_ALLOW ) . '"' . selected( $mode, self::MODE_ALLOW, false ) . '>' . esc_html__( 'Allow', 'handl-ai-connector-access-control' ) . '</option>';
			echo '</select></td>';
			echo '<td><textarea class="large-text code" rows="2" cols="40" name="' . esc_attr( $base . '[plugins]' ) . '">' . esc_textarea( $plugins ) . '</textarea></td>';
			echo '</tr>';
		}

		echo '</tbody></table>';
		echo '</td></tr>';
	}

	/**
	 * @return string
	 */
	private static function primary_role_for_user( int $user_id ): string {
		if ( array_key_exists( 'handl_aicac_test_users', $GLOBALS )
			&& isset( $GLOBALS['handl_aicac_test_users'][ $user_id ] )
			&& is_array( $GLOBALS['handl_aicac_test_users'][ $user_id ] )
		) {
			$roles = $GLOBALS['handl_aicac_test_users'][ $user_id ]['roles'] ?? array();
			if ( is_array( $roles ) && ! empty( $roles ) ) {
				return sanitize_key( (string) reset( $roles ) );
			}
			return '';
		}
		if ( ! function_exists( 'get_userdata' ) ) {
			return '';
		}
		$user = get_userdata( $user_id );
		if ( ! $user || empty( $user->roles ) || ! is_array( $user->roles ) ) {
			return '';
		}
		return sanitize_key( (string) reset( $user->roles ) );
	}

	private static function display_name_for( int $user_id ): string {
		if ( array_key_exists( 'handl_aicac_test_users', $GLOBALS )
			&& isset( $GLOBALS['handl_aicac_test_users'][ $user_id ] )
			&& is_array( $GLOBALS['handl_aicac_test_users'][ $user_id ] )
		) {
			$login = (string) ( $GLOBALS['handl_aicac_test_users'][ $user_id ]['user_login'] ?? '' );
			if ( '' !== $login ) {
				return sanitize_text_field( $login );
			}
		}
		if ( function_exists( 'get_userdata' ) ) {
			$user = get_userdata( $user_id );
			if ( $user && ! empty( $user->user_login ) ) {
				return sanitize_text_field( (string) $user->user_login );
			}
		}
		return 'user#' . (string) $user_id;
	}

	/**
	 * @param list<string> $plugins
	 */
	private static function build_summary( string $who, string $role, array $plugins, bool $role_added ): string {
		$parts = array();
		if ( ! empty( $plugins ) ) {
			$parts[] = sprintf(
				/* translators: 1: plugin count */
				_n( '%d plugin temp-allow', '%d plugin temp-allows', count( $plugins ), 'handl-ai-connector-access-control' ),
				count( $plugins )
			);
		}
		if ( $role_added ) {
			$parts[] = __( 'role gate', 'handl-ai-connector-access-control' );
		}
		if ( empty( $parts ) ) {
			$parts[] = __( 'already live', 'handl-ai-connector-access-control' );
		}

		return sprintf(
			/* translators: 1: user login, 2: role slug, 3: grant summary */
			__( '%1$s provisioned as %2$s: %3$s', 'handl-ai-connector-access-control' ),
			$who,
			$role,
			implode( ', ', $parts )
		);
	}

	/**
	 * @param list<string> $plugins
	 */
	private static function append_audit(
		int $user_id,
		string $who,
		string $role,
		string $via,
		array $plugins,
		bool $role_added,
		string $summary,
		int $now
	): void {
		Policy::append_log_event(
			array(
				'ts'               => $now,
				'plugin'           => ! empty( $plugins ) ? (string) $plugins[0] : '',
				'decision'         => 'provision',
				'channel'          => self::CHANNEL,
				'source'           => 'system',
				'user_id'          => $user_id,
				'user_login'       => $who,
				'provision_role'   => $role,
				'provision_via'    => $via,
				'provision_plugins'=> array_values( $plugins ),
				'provision_role_gate' => $role_added,
				'summary'          => $summary,
				'operation'        => '',
				'provider'         => '',
			)
		);
	}
}
