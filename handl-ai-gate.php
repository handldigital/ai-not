<?php
/**
 * Plugin Name: HandL AI Gate
 * Description: Lets administrators allow/deny which plugins may use the WordPress AI Client. Defaults to allow, with opt-in logging and best-effort attribution.
 * Version: 1.0.1
 * Author: Haktan Suren
 * Requires at least: 7.0
 * Requires PHP: 7.4
 * Author URI: https://www.haktansuren.com/
 * License: GPLv2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: handl-ai-gate
 * Domain Path: /languages
 *
 * @package HandL_AIGate
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'HANDL_AIGATE_VERSION', '1.0.1' );
define( 'HANDL_AIGATE_FILE', __FILE__ );
define( 'HANDL_AIGATE_DIR', __DIR__ );

require_once HANDL_AIGATE_DIR . '/includes/class-handl-aigate-plugin.php';

add_action(
	'plugins_loaded',
	static function (): void {
		\HandL\AIGate\Plugin::instance()->init();
	}
);
