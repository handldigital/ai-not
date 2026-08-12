<?php
/**
 * AICAC-WHATS-NEW: One-time post-update What's-New notice + highlights panel.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Version-bump notice (once per user) and curated in-plugin highlights.
 */
final class Whats_New {

	/** Site option: last known plugin version on this site. */
	public const OPTION_KEY = 'handl_aicac_whats_new_seen_version';

	/** Site option: version currently being announced (empty when none). */
	public const ANNOUNCE_OPTION_KEY = 'handl_aicac_whats_new_announce';

	/** User meta: last version this user dismissed (or opened). */
	public const USER_META_KEY = 'handl_aicac_whats_new_dismissed';

	private static ?Whats_New $instance = null;

	public static function instance(): Whats_New {
		if ( null === self::$instance ) {
			self::$instance = new Whats_New();
		}
		return self::$instance;
	}

	public function init(): void {
		add_action( 'admin_init', array( $this, 'maybe_detect_version_bump' ), 5 );
		add_action( 'admin_init', array( $this, 'maybe_handle_dismiss' ), 6 );
		add_action( 'admin_notices', array( $this, 'maybe_render_notice' ) );
		add_action( 'network_admin_notices', array( $this, 'maybe_render_notice' ) );
	}

	/**
	 * Dismiss POST can land on any admin screen (notice form posts to current URL).
	 */
	public function maybe_handle_dismiss(): void {
		if ( ! isset( $_POST['handl_aicac_action'] ) ) {
			return;
		}
		$action = sanitize_key( wp_unslash( (string) $_POST['handl_aicac_action'] ) );
		if ( 'whats_new_dismiss' !== $action ) {
			return;
		}
		if ( ! self::user_can_see_notice() ) {
			return;
		}
		check_admin_referer( 'handl_aicac_whats_new_dismiss', 'handl_aicac_nonce' );
		$user_id = get_current_user_id();
		$version = isset( $_POST['handl_aicac_whats_new_version'] )
			? self::sanitize_version( wp_unslash( (string) $_POST['handl_aicac_whats_new_version'] ) )
			: self::current_version();
		self::dismiss_for_user( $user_id, $version );

		$redirect = wp_get_referer();
		if ( ! is_string( $redirect ) || '' === $redirect ) {
			$redirect = self::is_network_active() && is_network_admin()
				? network_admin_url()
				: admin_url();
		}
		wp_safe_redirect( $redirect );
		exit;
	}

	/**
	 * Curated highlights keyed by version. Missing key → empty panel (no error).
	 *
	 * @return array<string,list<string>>
	 */
	public static function highlights_catalog(): array {
		return array(
			'1.5.0' => array(
				__( 'Set per-plugin estimated monthly budgets on the Rules tab, with a Dashboard banner, budget-hit email, and Site Health notice when the ceiling is reached. Amounts are estimates, not bills.', 'handl-ai-connector-access-control' ),
				__( 'Turn on an optional weekly governance digest: last 7 days of AI Client calls, estimated spend vs the previous week, blocked calls, direct connections, and top plugins.', 'handl-ai-connector-access-control' ),
				__( 'Get one alert the first time a plugin uses a new AI provider (or model). The first recorded call sets a baseline and does not send an alert.', 'handl-ai-connector-access-control' ),
				__( 'See the last 20 webhook delivery attempts on Activity, send a test webhook next to the URL, and get one automatic retry after a server error or timeout.', 'handl-ai-connector-access-control' ),
				__( 'Inspect policy and activity from the command line with `wp handl-aicac policy list` and `wp handl-aicac log summary` (table or JSON).', 'handl-ai-connector-access-control' ),
			),
			'1.4.0' => array(
				__( 'Save policy checks on the Rules tab; the plugin warns before a preset, restore, or import would change an expected Allow or Deny result.', 'handl-ai-connector-access-control' ),
				__( 'Set weekly Quiet hours on the Activity tab to block AI Client calls or use Observe-only mode. Emergency stop still takes priority.', 'handl-ai-connector-access-control' ),
				__( 'Compare a previous rules export with your current policy and see every difference before you import.', 'handl-ai-connector-access-control' ),
				__( 'Mute alert emails and webhooks per plugin for 1 hour to 7 days without changing rules or activity logging.', 'handl-ai-connector-access-control' ),
				__( 'Open a read-only Plugin AI profile from Activity or Dashboard estimated spend to see usage, incidents, and rules in one place.', 'handl-ai-connector-access-control' ),
			),
			'1.3.0' => array(
				__( 'See 8 weeks of call and estimated-spend trends in Insights, including per-plugin sparklines and changes from the previous week.', 'handl-ai-connector-access-control' ),
				__( 'Restore a previous policy from the Rules tab. Review every rule and setting that will change before you confirm.', 'handl-ai-connector-access-control' ),
				__( 'Scan active plugins for possible embedded AI API keys. Only the last 4 characters appear on the Dashboard, and full keys are never stored.', 'handl-ai-connector-access-control' ),
				__( 'Turn on a monthly email with a short summary and printable HTML audit report. If no activity was retained, you still receive a no-activity note.', 'handl-ai-connector-access-control' ),
			),
			'1.2.2' => array(
				__( 'Start with a policy preset and preview every setting that will change before you apply it.', 'handl-ai-connector-access-control' ),
				__( 'Set temporary Allow rules that expire automatically, then renew an expired rule for 7 days when needed.', 'handl-ai-connector-access-control' ),
				__( 'See 24-hour AI activity and estimated spend at a glance on the WordPress Dashboard.', 'handl-ai-connector-access-control' ),
				__( 'Open a printable audit report with current rules, activity, and estimated-spend alerts, then save it as a PDF from your browser.', 'handl-ai-connector-access-control' ),
			),
		);
	}

	/**
	 * @return list<string>
	 */
	public static function highlights_for_version( string $version ): array {
		$version = self::sanitize_version( $version );
		$catalog = self::highlights_catalog();
		if ( '' === $version || ! isset( $catalog[ $version ] ) || ! is_array( $catalog[ $version ] ) ) {
			return array();
		}
		$out = array();
		foreach ( $catalog[ $version ] as $line ) {
			$line = is_string( $line ) ? trim( $line ) : '';
			if ( '' !== $line ) {
				$out[] = $line;
			}
		}
		return $out;
	}

	public static function current_version(): string {
		return defined( 'HANDL_AICAC_VERSION' ) ? self::sanitize_version( (string) HANDL_AICAC_VERSION ) : '';
	}

	public static function sanitize_version( string $version ): string {
		$version = trim( $version );
		if ( '' === $version ) {
			return '';
		}
		if ( ! preg_match( '/^\d+(\.\d+){0,3}([a-z0-9\-]+)?$/i', $version ) ) {
			return '';
		}
		return $version;
	}

	/**
	 * Activation helper: fresh installs record the current version with no announcement.
	 */
	public static function ensure_seen_version_seeded(): void {
		$current = self::current_version();
		if ( '' === $current ) {
			return;
		}
		$installed = get_option( self::OPTION_KEY, null );
		if ( null !== $installed && false !== $installed && '' !== (string) $installed ) {
			return;
		}
		if ( Onboarding::is_fresh_install() ) {
			update_option( self::OPTION_KEY, $current, false );
			delete_option( self::ANNOUNCE_OPTION_KEY );
		}
	}

	/**
	 * Detect version transitions and set the announce target.
	 */
	public function maybe_detect_version_bump(): void {
		self::detect_version_bump();
	}

	/**
	 * @return string Announcement version after detection (may be empty).
	 */
	public static function detect_version_bump( ?string $current = null, ?bool $fresh_install = null ): string {
		$current = null !== $current ? self::sanitize_version( $current ) : self::current_version();
		if ( '' === $current ) {
			return '';
		}
		$fresh     = null !== $fresh_install ? $fresh_install : Onboarding::is_fresh_install();
		$installed = get_option( self::OPTION_KEY, null );

		if ( null === $installed || false === $installed || '' === self::sanitize_version( (string) $installed ) ) {
			update_option( self::OPTION_KEY, $current, false );
			if ( $fresh ) {
				delete_option( self::ANNOUNCE_OPTION_KEY );
				return '';
			}
			// Existing site meeting this feature for the first time, or unknown prior version.
			update_option( self::ANNOUNCE_OPTION_KEY, $current, false );
			return $current;
		}

		$installed = self::sanitize_version( (string) $installed );
		if ( version_compare( $installed, $current, '<' ) ) {
			update_option( self::OPTION_KEY, $current, false );
			update_option( self::ANNOUNCE_OPTION_KEY, $current, false );
			return $current;
		}

		return self::get_announce_version();
	}

	public static function get_announce_version(): string {
		return self::sanitize_version( (string) get_option( self::ANNOUNCE_OPTION_KEY, '' ) );
	}

	public static function get_user_dismissed_version( int $user_id ): string {
		if ( $user_id <= 0 ) {
			return '';
		}
		return self::sanitize_version( (string) get_user_meta( $user_id, self::USER_META_KEY, true ) );
	}

	public static function dismiss_for_user( int $user_id, ?string $version = null ): void {
		$version = null !== $version ? self::sanitize_version( $version ) : self::current_version();
		if ( $user_id <= 0 || '' === $version ) {
			return;
		}
		update_user_meta( $user_id, self::USER_META_KEY, $version );
	}

	/**
	 * Whether this user should see the admin notice for the active announcement.
	 */
	public static function should_show_notice_for_user( int $user_id, ?string $announce = null ): bool {
		$announce = null !== $announce ? self::sanitize_version( $announce ) : self::get_announce_version();
		$current  = self::current_version();
		if ( '' === $announce || '' === $current || $user_id <= 0 ) {
			return false;
		}
		if ( $announce !== $current ) {
			return false;
		}
		$dismissed = self::get_user_dismissed_version( $user_id );
		if ( '' !== $dismissed && version_compare( $dismissed, $announce, '>=' ) ) {
			return false;
		}
		return true;
	}

	public static function is_network_active(): bool {
		if ( ! is_multisite() ) {
			return false;
		}
		if ( ! function_exists( 'is_plugin_active_for_network' ) ) {
			$plugin_php = ABSPATH . 'wp-admin/includes/plugin.php';
			if ( is_string( $plugin_php ) && is_readable( $plugin_php ) ) {
				require_once $plugin_php;
			}
		}
		if ( ! function_exists( 'is_plugin_active_for_network' ) || ! defined( 'HANDL_AICAC_FILE' ) ) {
			return false;
		}
		$basename = plugin_basename( HANDL_AICAC_FILE );
		return (bool) is_plugin_active_for_network( $basename );
	}

	public static function user_can_see_notice(): bool {
		if ( self::is_network_active() ) {
			return is_network_admin() && current_user_can( 'manage_network_options' );
		}
		return ! is_network_admin() && current_user_can( 'manage_options' );
	}

	public static function panel_url( ?string $version = null ): string {
		$version = null !== $version ? self::sanitize_version( $version ) : self::current_version();
		if ( self::is_network_active() && is_network_admin() ) {
			return add_query_arg(
				array(
					'page'                  => 'handl-aicac-network',
					'handl_aicac_whats_new' => '1',
					'handl_aicac_ver'       => $version,
				),
				network_admin_url( 'settings.php' )
			);
		}

		return add_query_arg(
			array(
				'page'            => 'handl-ai-connector-access-control',
				'handl_aicac_tab' => 'whats-new',
			),
			admin_url( 'options-general.php' )
		);
	}

	public function maybe_render_notice(): void {
		if ( ! self::user_can_see_notice() ) {
			return;
		}
		self::detect_version_bump();
		$user_id = get_current_user_id();
		if ( ! self::should_show_notice_for_user( $user_id ) ) {
			return;
		}

		$version = self::current_version();
		$url     = self::panel_url( $version );

		echo '<div class="notice notice-info"><p>';
		echo '<strong>';
		echo esc_html(
			sprintf(
				/* translators: %s: plugin version */
				__( 'HandL AI Access updated to %s', 'handl-ai-connector-access-control' ),
				$version
			)
		);
		echo '</strong>. ';
		echo '<a href="' . esc_url( $url ) . '">' . esc_html__( 'See what’s new', 'handl-ai-connector-access-control' ) . '</a>';
		echo '</p>';
		echo '<form method="post" style="margin:0 0 8px 0;">';
		wp_nonce_field( 'handl_aicac_whats_new_dismiss', 'handl_aicac_nonce' );
		echo '<input type="hidden" name="handl_aicac_action" value="whats_new_dismiss" />';
		echo '<input type="hidden" name="handl_aicac_whats_new_version" value="' . esc_attr( $version ) . '" />';
		submit_button( __( 'Dismiss', 'handl-ai-connector-access-control' ), 'link', 'submit', false );
		echo '</form>';
		echo '</div>';
	}

	/**
	 * Render the in-plugin highlights panel body (caller wraps layout).
	 */
	public static function render_panel( ?string $version = null ): void {
		$version    = null !== $version ? self::sanitize_version( $version ) : self::current_version();
		$highlights = self::highlights_for_version( $version );

		echo '<div class="handl-aicac-whats-new">';
		echo '<h2>' . esc_html__( 'What’s new', 'handl-ai-connector-access-control' ) . '</h2>';
		if ( '' !== $version ) {
			echo '<p class="description">' . esc_html(
				sprintf(
					/* translators: %s: plugin version */
					__( 'Highlights for version %s.', 'handl-ai-connector-access-control' ),
					$version
				)
			) . '</p>';
		}

		if ( empty( $highlights ) ) {
			echo '<p class="description">' . esc_html__( 'No highlights are listed for this version.', 'handl-ai-connector-access-control' ) . '</p>';
		} else {
			echo '<ul class="ul-disc">';
			foreach ( $highlights as $line ) {
				echo '<li>' . esc_html( $line ) . '</li>';
			}
			echo '</ul>';
		}

		$back = ( self::is_network_active() && is_network_admin() )
			? network_admin_url( 'settings.php?page=handl-aicac-network' )
			: admin_url( 'options-general.php?page=handl-ai-connector-access-control&handl_aicac_tab=dashboard' );
		$back_label = ( self::is_network_active() && is_network_admin() )
			? __( 'Back to network overview', 'handl-ai-connector-access-control' )
			: __( 'Back to Dashboard', 'handl-ai-connector-access-control' );

		echo '<p><a class="button" href="' . esc_url( $back ) . '">' . esc_html( $back_label ) . '</a></p>';
		echo '</div>';
	}
}
