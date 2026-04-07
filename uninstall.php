<?php
/**
 * Uninstall handler for HandL AI Gate.
 *
 * @package HandL_AIGate
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

delete_option( 'handl_aigate_policy' );
delete_option( 'handl_aigate_recent_calls' );
delete_option( 'ai_not_policy' );
delete_option( 'ai_not_recent_calls' );
