<?php
/**
 * Main plugin bootstrap.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Plugin {
	private static ?Plugin $instance = null;

	public const OPTION_KEY = 'handl_aicac_policy';
	public const LOG_OPTION_KEY = 'handl_aicac_recent_calls';

	public static function instance(): Plugin {
		if ( null === self::$instance ) {
			self::$instance = new Plugin();
		}
		return self::$instance;
	}

	public function init(): void {
		self::migrate_legacy_options();

		require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-attribution.php';
		require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-prompt-snapshot.php';
		require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-operations.php';
		require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-cost.php';
		require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-spend-threshold.php';
		require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-forecast.php';
		require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-usage-trends.php';
		require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-log-storage.php';
		require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-anomaly.php';
		require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-alerts.php';
		require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-alert-health.php';
		require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-weekly-report.php';
		require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-monthly-report.php';
		require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-model-force.php';
		require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-shadow-ai.php';
		require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-keyscan.php';
		require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-temp-allow.php';
		require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-new-plugin.php';
		require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-policy.php';
		require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-policy-simulator.php';
		require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-onboarding.php';
		require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-leads.php';
		require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-policy-transfer.php';
		require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-presets.php';
		require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-policy-snapshots.php';
		require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-audit-export.php';
		require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-audit-evidence.php';
		require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-analytics.php';
		require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-plugin-profile.php';
require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-graduate.php';
		require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-differentiator-messaging.php';
		require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-admin.php';
		require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-whats-new.php';
		require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-network-admin.php';
		require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-site-health.php';
		require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-rest.php';
		require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-dashboard-widget.php';

		Policy::instance()->init();
		Temp_Allow::instance()->init();
		New_Plugin::instance()->init();
		Alerts::instance()->init();
		Weekly_Report::instance()->init();
		Monthly_Report::instance()->init();
		Model_Force::instance()->init();
		Shadow_AI::instance()->init();
		Keyscan::instance()->init();
		Admin::instance()->init();
		Whats_New::instance()->init();
		Network_Admin::instance()->init();
		Site_Health::instance()->init();
		Rest::instance()->init();
		Dashboard_Widget::instance()->init();

		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-cli.php';
			CLI::register();
		}
	}

	/**
	 * Copy options saved under previous plugin slugs when upgrading.
	 */
	private static function migrate_legacy_options(): void {
		// From previous rename: "HandL AI Gate".
		$legacy_policy = get_option( 'handl_aigate_policy', null );
		if ( is_array( $legacy_policy ) ) {
			$current = get_option( self::OPTION_KEY, null );
			if ( null === $current || false === $current ) {
				update_option( self::OPTION_KEY, $legacy_policy, false );
			}
			delete_option( 'handl_aigate_policy' );
		}

		$legacy_log = get_option( 'handl_aigate_recent_calls', null );
		if ( null !== $legacy_log ) {
			$current_log = get_option( self::LOG_OPTION_KEY, null );
			if ( null === $current_log || false === $current_log ) {
				update_option(
					self::LOG_OPTION_KEY,
					is_array( $legacy_log ) ? $legacy_log : array(),
					false
				);
			}
			delete_option( 'handl_aigate_recent_calls' );
		}

		// From original submission: "AI Not".
		$legacy_policy = get_option( 'ai_not_policy', null );
		if ( is_array( $legacy_policy ) ) {
			$current = get_option( self::OPTION_KEY, null );
			if ( null === $current || false === $current ) {
				update_option( self::OPTION_KEY, $legacy_policy, false );
			}
			delete_option( 'ai_not_policy' );
		}

		$legacy_log = get_option( 'ai_not_recent_calls', null );
		if ( null !== $legacy_log ) {
			$current_log = get_option( self::LOG_OPTION_KEY, null );
			if ( null === $current_log || false === $current_log ) {
				update_option(
					self::LOG_OPTION_KEY,
					is_array( $legacy_log ) ? $legacy_log : array(),
					false
				);
			}
			delete_option( 'ai_not_recent_calls' );
		}
	}
}
