<?php
/**
 * Uninstall handler for HandL AI Connector Access Control.
 *
 * @package HandL_AICAC
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

delete_option( 'handl_aicac_policy' );
delete_option( 'handl_aicac_recent_calls' );
delete_option( 'handl_aigate_policy' );
delete_option( 'handl_aigate_recent_calls' );
delete_option( 'ai_not_policy' );
delete_option( 'ai_not_recent_calls' );
