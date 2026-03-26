<?php
/**
 * Plugin Name: AI Not (AI Connector Governance)
 * Description: Lets administrators allow/deny which plugins may use the WordPress AI Client. Defaults to allow, with opt-in logging and best-effort attribution.
 * Version: 1.0.0
 * Author: Haktan Suren
 * Requires at least: 7.0
 * Requires PHP: 7.4
 * Author URI: https://www.haktansuren.com/
 * License: GPLv2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: ai-not
 * Domain Path: /languages
 *
 * @package AINot
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'AI_NOT_VERSION', '1.0.0' );
define( 'AI_NOT_FILE', __FILE__ );
define( 'AI_NOT_DIR', __DIR__ );

require_once AI_NOT_DIR . '/includes/class-ai-not-plugin.php';

add_action(
	'plugins_loaded',
	static function (): void {
		\AINot\Plugin::instance()->init();
	}
);

