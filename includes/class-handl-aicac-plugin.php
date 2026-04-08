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
		require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-policy.php';
		require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-admin.php';

		Policy::instance()->init();
		Admin::instance()->init();
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
