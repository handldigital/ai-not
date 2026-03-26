<?php
/**
 * Main plugin bootstrap.
 *
 * @package AINot
 */

namespace AINot;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Plugin {
	private static ?Plugin $instance = null;

	public const OPTION_KEY = 'ai_not_policy';
	public const LOG_OPTION_KEY = 'ai_not_recent_calls';

	public static function instance(): Plugin {
		if ( null === self::$instance ) {
			self::$instance = new Plugin();
		}
		return self::$instance;
	}

	public function init(): void {
		require_once AI_NOT_DIR . '/includes/class-ai-not-attribution.php';
		require_once AI_NOT_DIR . '/includes/class-ai-not-policy.php';
		require_once AI_NOT_DIR . '/includes/class-ai-not-admin.php';

		Policy::instance()->init();
		Admin::instance()->init();
	}
}

