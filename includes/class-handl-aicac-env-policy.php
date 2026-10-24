<?php
/**
 * AICAC-ENV-POLICY (#363): per-environment policy overlays.
 *
 * Detects wp_get_environment_type() and, when enabled, may deny or relax
 * (allow-and-log) the normal evaluate result for that environment only.
 * Own options, OFF by default. Own admin page — no admin.php edits.
 * DOPPELGANGER (#423) is the identity watchdog; this class never calls it.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Environment-aware overlays on top of the single site policy.
 */
final class Env_Policy {

	public const SETTINGS_OPTION = 'handl_aicac_env_policy';

	public const PAGE_SLUG = 'handl-aicac-env-policy';

	public const FILTER_EVALUATE = 'handl_aicac_evaluate_result';

	public const REASON = 'env_policy';

	public const MODE_INHERIT = 'inherit';

	public const MODE_DENY = 'deny';

	public const MODE_OBSERVE = 'observe';

	public const ACTION_SAVE = 'handl_aicac_env_policy_save';

	public const POST_PRESENT = 'handl_aicac_env_policy_present';

	public const POST_ENABLED = 'handl_aicac_env_policy_enabled';

	public const POST_OVERLAYS = 'handl_aicac_env_policy_overlay';

	/** @var list<string> */
	public const ENVIRONMENTS = array( 'production', 'staging', 'development', 'local' );

	/** @var bool */
	private static $registered = false;

	public static function init(): void {
		if ( self::$registered ) {
			return;
		}
		self::$registered = true;

		add_action( 'admin_menu', array( self::class, 'register_menu' ), 20 );
		add_action( 'admin_post_' . self::ACTION_SAVE, array( self::class, 'handle_save' ) );
		add_filter( self::FILTER_EVALUATE, array( self::class, 'filter_evaluate_result' ), 10, 3 );

		if ( defined( 'HANDL_AICAC_PHPUNIT' ) && HANDL_AICAC_PHPUNIT ) {
			$GLOBALS['handl_aicac_test_filters'][ self::FILTER_EVALUATE ] = array( self::class, 'filter_evaluate_result' );
		}

		self::register_cli();
	}

	public static function reset_for_tests(): void {
		self::$registered = false;
		delete_option( self::SETTINGS_OPTION );
		unset( $GLOBALS['handl_aicac_test_environment_type'], $GLOBALS['handl_aicac_test_filters'][ self::FILTER_EVALUATE ] );
	}

	/**
	 * @return array{enabled:bool,overlays:array<string,string>}
	 */
	public static function defaults(): array {
		$overlays = array();
		foreach ( self::ENVIRONMENTS as $env ) {
			$overlays[ $env ] = self::MODE_INHERIT;
		}

		return array(
			'enabled'  => false,
			'overlays' => $overlays,
		);
	}

	/**
	 * @return array{enabled:bool,overlays:array<string,string>}
	 */
	public static function get_settings(): array {
		return self::sanitize_settings( get_option( self::SETTINGS_OPTION, array() ) );
	}

	/**
	 * @param mixed $raw Raw settings.
	 * @return array{enabled:bool,overlays:array<string,string>}
	 */
	public static function sanitize_settings( $raw ): array {
		$defaults = self::defaults();
		if ( ! is_array( $raw ) ) {
			return $defaults;
		}

		$overlays = $defaults['overlays'];
		$posted   = isset( $raw['overlays'] ) && is_array( $raw['overlays'] ) ? $raw['overlays'] : array();
		foreach ( self::ENVIRONMENTS as $env ) {
			if ( isset( $posted[ $env ] ) ) {
				$overlays[ $env ] = self::sanitize_mode( $posted[ $env ] );
			}
		}

		return array(
			'enabled'  => ! empty( $raw['enabled'] ),
			'overlays' => $overlays,
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
	 * @param mixed $raw Raw mode.
	 */
	public static function sanitize_mode( $raw ): string {
		$mode = sanitize_key( (string) $raw );
		if ( self::MODE_DENY === $mode || self::MODE_OBSERVE === $mode ) {
			return $mode;
		}

		return self::MODE_INHERIT;
	}

	/**
	 * @param mixed $raw Raw environment.
	 */
	public static function sanitize_environment( $raw ): string {
		$env = sanitize_key( (string) $raw );
		if ( in_array( $env, self::ENVIRONMENTS, true ) ) {
			return $env;
		}

		return 'production';
	}

	public static function environment_type(): string {
		if ( array_key_exists( 'handl_aicac_test_environment_type', $GLOBALS ) ) {
			return self::sanitize_environment( $GLOBALS['handl_aicac_test_environment_type'] );
		}
		if ( function_exists( 'wp_get_environment_type' ) ) {
			return self::sanitize_environment( wp_get_environment_type() );
		}

		return 'production';
	}

	public static function environment_label( string $env = '' ): string {
		$env = '' === $env ? self::environment_type() : self::sanitize_environment( $env );
		$labels = array(
			'production'  => __( 'production', 'handl-ai-connector-access-control' ),
			'staging'     => __( 'staging', 'handl-ai-connector-access-control' ),
			'development' => __( 'development', 'handl-ai-connector-access-control' ),
			'local'       => __( 'local', 'handl-ai-connector-access-control' ),
		);

		return $labels[ $env ];
	}

	/**
	 * Overlay mode for the current (or given) environment. inherit when off.
	 */
	public static function overlay_mode( string $env = '' ): string {
		if ( ! self::is_enabled() ) {
			return self::MODE_INHERIT;
		}
		$env      = '' === $env ? self::environment_type() : self::sanitize_environment( $env );
		$settings = self::get_settings();

		return self::sanitize_mode( $settings['overlays'][ $env ] ?? self::MODE_INHERIT );
	}

	/**
	 * Sanctioned Policy::evaluate filter. Identity when overlays are off or inherit.
	 *
	 * @param mixed                $result          Evaluate result.
	 * @param array<string,mixed>  $policy          Current policy (unused; overlay is own options).
	 * @param string|null          $plugin_basename Plugin file (unused).
	 * @return mixed
	 */
	public static function filter_evaluate_result( $result, $policy = array(), $plugin_basename = null ) {
		unset( $policy, $plugin_basename );
		if ( ! is_array( $result ) ) {
			return $result;
		}

		$mode = self::overlay_mode();
		if ( self::MODE_INHERIT === $mode ) {
			return $result;
		}

		$prevent = ! empty( $result['prevent'] );
		$env     = self::environment_type();

		if ( self::MODE_DENY === $mode && ! $prevent ) {
			$result['prevent']     = true;
			$result['reason']      = self::REASON;
			$result['env_overlay'] = $env . ':' . $mode;

			return $result;
		}

		if ( self::MODE_OBSERVE === $mode && $prevent ) {
			$result['prevent']     = false;
			$result['reason']      = self::REASON;
			$result['env_overlay'] = $env . ':' . $mode;

			return $result;
		}

		return $result;
	}

	/**
	 * Loose-settings notes for a production site. Empty on other environments.
	 *
	 * @param array<string,mixed>|null $policy Policy snapshot.
	 * @return list<string>
	 */
	public static function production_loose_findings( ?array $policy = null ): array {
		if ( 'production' !== self::environment_type() ) {
			return array();
		}
		if ( null === $policy ) {
			$policy = get_option( Plugin::OPTION_KEY, array() );
		}
		if ( ! is_array( $policy ) ) {
			$policy = array();
		}

		$findings = array();
		if ( ! empty( $policy['audit_only'] ) ) {
			$findings[] = __( 'Enforcement is off. AI calls are logged only.', 'handl-ai-connector-access-control' );
		}
		$default = isset( $policy['default'] ) ? (string) $policy['default'] : 'allow';
		if ( 'deny' !== $default ) {
			$findings[] = __( 'Unknown plugins are allowed.', 'handl-ai-connector-access-control' );
		}
		$email = isset( $policy['alert_email'] ) ? trim( (string) $policy['alert_email'] ) : '';
		if ( '' === $email ) {
			$findings[] = __( 'No alert email is set.', 'handl-ai-connector-access-control' );
		}

		return $findings;
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
			__( 'Environment policy', 'handl-ai-connector-access-control' ),
			__( 'Environment', 'handl-ai-connector-access-control' ),
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
		$env        = self::environment_type();
		$findings   = self::production_loose_findings();

		echo '<div class="wrap">';
		echo '<h1>' . esc_html__( 'Environment policy', 'handl-ai-connector-access-control' ) . '</h1>';
		echo '<p class="description">' . esc_html(
			sprintf(
				/* translators: %s: production, staging, development, or local */
				__( 'This site is %s. Extra rules for one environment are off by default. They do not copy the whole policy.', 'handl-ai-connector-access-control' ),
				self::environment_label( $env )
			)
		) . '</p>';

		echo '<p><strong>' . esc_html__( 'This site is', 'handl-ai-connector-access-control' ) . ' ' . esc_html( self::environment_label( $env ) ) . '.</strong></p>';

		if ( $can_manage ) {
			$action = admin_url( 'admin-post.php' );
			echo '<form method="post" action="' . esc_url( $action ) . '">';
			echo '<input type="hidden" name="action" value="' . esc_attr( self::ACTION_SAVE ) . '" />';
			if ( function_exists( 'wp_nonce_field' ) ) {
				wp_nonce_field( self::ACTION_SAVE );
			}
			echo '<input type="hidden" name="' . esc_attr( self::POST_PRESENT ) . '" value="1" />';
			echo '<table class="form-table" role="presentation"><tbody>';
			echo '<tr><th scope="row">' . esc_html__( 'Extra rules per environment', 'handl-ai-connector-access-control' ) . '</th><td>';
			echo '<label><input type="checkbox" name="' . esc_attr( self::POST_ENABLED ) . '" value="1" ' . checked( $enabled, true, false ) . ' /> ';
			echo esc_html__( 'Use extra rules per environment', 'handl-ai-connector-access-control' );
			echo '</label></td></tr>';
			foreach ( self::ENVIRONMENTS as $row_env ) {
				$current = self::sanitize_mode( $settings['overlays'][ $row_env ] ?? self::MODE_INHERIT );
				echo '<tr><th scope="row">' . esc_html( self::environment_heading( $row_env ) ) . '</th><td>';
				echo '<select name="' . esc_attr( self::POST_OVERLAYS . '[' . $row_env . ']' ) . '">';
				foreach ( self::mode_choices() as $mode => $label ) {
					echo '<option value="' . esc_attr( $mode ) . '"' . selected( $current, $mode, false ) . '>' . esc_html( $label ) . '</option>';
				}
				echo '</select></td></tr>';
			}
			echo '</tbody></table>';
			submit_button( __( 'Save environment policy', 'handl-ai-connector-access-control' ) );
			echo '</form>';
		}

		if ( ! $enabled ) {
			echo '<p>' . esc_html__( 'Extra environment rules are off. Decisions follow the site policy.', 'handl-ai-connector-access-control' ) . '</p>';
		}

		if ( ! empty( $findings ) ) {
			echo '<h2>' . esc_html__( 'Loose settings on production', 'handl-ai-connector-access-control' ) . '</h2>';
			echo '<ul>';
			foreach ( $findings as $finding ) {
				echo '<li>' . esc_html( $finding ) . '</li>';
			}
			echo '</ul>';
		}

		echo '</div>';
	}

	public static function handle_save(): void {
		if ( ! Caps::user_can_manage() ) {
			wp_die( esc_html__( 'You do not have permission to save environment policy.', 'handl-ai-connector-access-control' ) );
		}
		check_admin_referer( self::ACTION_SAVE );
		if ( empty( $_POST[ self::POST_PRESENT ] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing
			wp_die( esc_html__( 'Security check failed. Go back, reload the page, and try again.', 'handl-ai-connector-access-control' ) );
		}
		$overlays = array();
		if ( isset( $_POST[ self::POST_OVERLAYS ] ) && is_array( $_POST[ self::POST_OVERLAYS ] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing
			$overlays = wp_unslash( $_POST[ self::POST_OVERLAYS ] ); // phpcs:ignore WordPress.Security.NonceVerification.Missing,WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		}
		self::save_settings(
			array(
				'enabled'  => ! empty( $_POST[ self::POST_ENABLED ] ), // phpcs:ignore WordPress.Security.NonceVerification.Missing
				'overlays' => is_array( $overlays ) ? $overlays : array(),
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

	/**
	 * One-line status for WP-CLI / tests.
	 */
	public static function status_line(): string {
		$env  = self::environment_type();
		$mode = self::overlay_mode( $env );
		if ( ! self::is_enabled() ) {
			return sprintf(
				/* translators: %s: production, staging, development, or local */
				__( 'Environment rules are turned off. This site: %s.', 'handl-ai-connector-access-control' ),
				self::environment_label( $env )
			);
		}

		return sprintf(
			/* translators: 1: environment label, 2: rule label */
			__( 'This site: %1$s. Rule: %2$s.', 'handl-ai-connector-access-control' ),
			self::environment_label( $env ),
			self::mode_choices()[ $mode ]
		);
	}

	public static function register_cli(): void {
		if ( ! defined( 'WP_CLI' ) || ! WP_CLI ) {
			return;
		}
		if ( ! class_exists( '\WP_CLI' ) ) {
			return;
		}
		\WP_CLI::add_command( 'handl-aicac env-policy', CLI_Env_Policy::class );
	}

	/**
	 * @return array<string,string>
	 */
	public static function mode_choices(): array {
		return array(
			self::MODE_INHERIT => __( 'Use the site policy', 'handl-ai-connector-access-control' ),
			self::MODE_DENY    => __( 'Deny AI calls', 'handl-ai-connector-access-control' ),
			self::MODE_OBSERVE => __( 'Allow and log', 'handl-ai-connector-access-control' ),
		);
	}

	private static function environment_heading( string $env ): string {
		$headings = array(
			'production'  => __( 'Production', 'handl-ai-connector-access-control' ),
			'staging'     => __( 'Staging', 'handl-ai-connector-access-control' ),
			'development' => __( 'Development', 'handl-ai-connector-access-control' ),
			'local'       => __( 'Local', 'handl-ai-connector-access-control' ),
		);

		return $headings[ self::sanitize_environment( $env ) ];
	}
}

/**
 * WP-CLI: wp handl-aicac env-policy status
 */
final class CLI_Env_Policy {

	/**
	 * Show environment-policy status.
	 *
	 * ## OPTIONS
	 *
	 * @when after_wp_load
	 *
	 * @param array<int,string>    $args       Positional.
	 * @param array<string,string> $assoc_args Flags.
	 */
	public function status( $args, $assoc_args ): void {
		unset( $args, $assoc_args );
		\WP_CLI::log( Env_Policy::status_line() );
	}
}
