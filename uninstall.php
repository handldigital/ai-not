<?php
/**
 * Uninstall handler for AI Not.
 *
 * @package AINot
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

delete_option( 'ai_not_policy' );
delete_option( 'ai_not_recent_calls' );

