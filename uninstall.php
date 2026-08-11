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
delete_option( 'handl_aicac_policy_snapshots' );
delete_option( 'handl_aicac_onboard' );

// F3: denial alert metadata — must not survive uninstall (privacy).
delete_option( 'handl_aicac_denial_digest_queue' );
delete_option( 'handl_aicac_denial_email_rate' );
delete_option( 'handl_aicac_test_email_rate' );
delete_option( 'handl_aicac_alert_health' );
delete_option( 'handl_aicac_whats_new_seen_version' );
delete_option( 'handl_aicac_whats_new_announce' );
if ( function_exists( 'delete_metadata' ) ) {
	delete_metadata( 'user', 0, 'handl_aicac_whats_new_dismissed', '', true );
}
delete_option( 'handl_aicac_spend_threshold_fired' );
delete_option( 'handl_aicac_forecast_warned' );
delete_option( 'handl_aicac_anomaly_fired' );
if ( function_exists( 'wp_clear_scheduled_hook' ) ) {
	wp_clear_scheduled_hook( 'handl_aicac_send_denial_digest' );
	// F7: weekly report cron.
	wp_clear_scheduled_hook( 'handl_aicac_send_weekly_report' );
}

// F4: experimental model-force health state.
delete_option( 'handl_aicac_model_force_health' );

// Legacy option keys from prior renames.
delete_option( 'handl_aigate_policy' );
delete_option( 'handl_aigate_recent_calls' );
delete_option( 'ai_not_policy' );
delete_option( 'ai_not_recent_calls' );
