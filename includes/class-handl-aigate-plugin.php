<?php
/**
 * Main plugin bootstrap.
 *
 * @package HandL_AIGate
 */

namespace HandL\AIGate;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Plugin {
	private static ?Plugin $instance = null;

	public const OPTION_KEY = 'handl_aigate_policy';
	public const LOG_OPTION_KEY = 'handl_aigate_recent_calls';

	public static function instance(): Plugin {
		if ( null === self::$instance ) {
			self::$instance = new Plugin();
		}
		return self::$instance;
	}

	public function init(): void {
		self::migrate_legacy_options();

		require_once HANDL_AIGATE_DIR . '/includes/class-handl-aigate-attribution.php';
		require_once HANDL_AIGATE_DIR . '/includes/class-handl-aigate-policy.php';
		require_once HANDL_AIGATE_DIR . '/includes/class-handl-aigate-admin.php';

		Policy::instance()->init();
		Admin::instance()->init();
	}

	/**
	 * Copy options saved under the previous plugin slug (ai-not) when upgrading.
	 */
	private static function migrate_legacy_options(): void {
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
