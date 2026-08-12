<?php
/**
 * Plugin Name: HandL AI Connector Access Control
 * Description: See AI activity from WordPress plugins, decide what each plugin may do, and block unwanted prompts through the WordPress AI Client.
 * Version: 1.3.0
 * Author: Haktan Suren
 * Requires at least: 7.0
 * Requires PHP: 7.4
 * Author URI: https://www.handldigital.com/
 * License: GPLv2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: handl-ai-connector-access-control
 * Domain Path: /languages
 *
 * @package HandL_AICAC
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'HANDL_AICAC_VERSION', '1.3.0' );
define( 'HANDL_AICAC_FILE', __FILE__ );
define( 'HANDL_AICAC_DIR', __DIR__ );
define( 'HANDL_AICAC_URL', plugin_dir_url( __FILE__ ) );

require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-plugin.php';

register_activation_hook(
	__FILE__,
	static function (): void {
		require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-onboarding.php';
		require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-whats-new.php';
		\HandL\AICAC\Onboarding::ensure_initialized();
		\HandL\AICAC\Whats_New::ensure_seen_version_seeded();
	}
);

add_action(
	'plugins_loaded',
	static function (): void {
		\HandL\AICAC\Plugin::instance()->init();
	}
);
