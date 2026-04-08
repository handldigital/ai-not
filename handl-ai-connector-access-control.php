<?php
/**
 * Plugin Name: HandL AI Connector Access Control
 * Description: Lets administrators allow/deny which plugins may use the WordPress AI Client. Defaults to allow, with opt-in logging and best-effort attribution.
 * Version: 1.0.2
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

define( 'HANDL_AICAC_VERSION', '1.0.2' );
define( 'HANDL_AICAC_FILE', __FILE__ );
define( 'HANDL_AICAC_DIR', __DIR__ );

require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-plugin.php';

add_action(
	'plugins_loaded',
	static function (): void {
		\HandL\AICAC\Plugin::instance()->init();
	}
);
