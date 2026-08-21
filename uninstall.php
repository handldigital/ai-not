<?php
/**
 * Uninstall handler for HandL AI Connector Access Control.
 *
 * Default is Keep (leave data for reinstall). Purge is opt-in via
 * `wp handl-aicac uninstall set purge`. That is an intentional change from
 * earlier releases, which always deleted plugin options on uninstall.
 *
 * @package HandL_AICAC
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) && ! defined( 'HANDL_AICAC_UNINSTALL_HELPERS' ) ) {
	exit;
}

/**
 * Per-site option storing keep vs purge.
 */
function handl_aicac_uninstall_option_key(): string {
	return 'handl_aicac_uninstall_policy';
}

/**
 * @return 'keep'|'purge'
 */
function handl_aicac_uninstall_policy(): string {
	$key = handl_aicac_uninstall_option_key();
	$raw = function_exists( 'get_option' ) ? get_option( $key, 'keep' ) : 'keep';
	return ( 'purge' === $raw ) ? 'purge' : 'keep';
}

/**
 * Cron hooks this plugin schedules. Cleared only on purge.
 *
 * @return list<string>
 */
function handl_aicac_uninstall_cron_hooks(): array {
	return array(
		'handl_aicac_send_denial_digest',
		'handl_aicac_send_weekly_report',
		'handl_aicac_keyscan_weekly',
		'handl_aicac_send_monthly_report',
		'handl_aicac_prune_activity_log',
		'handl_aicac_send_governance_digest',
		'handl_aicac_send_policy_backup',
	);
}

/**
 * Option keys from prior plugin slugs. Not `handl_aicac_`-prefixed.
 *
 * @return list<string>
 */
function handl_aicac_uninstall_legacy_option_keys(): array {
	return array(
		'handl_aigate_policy',
		'handl_aigate_recent_calls',
		'ai_not_policy',
		'ai_not_recent_calls',
	);
}

/**
 * Delete every plugin-prefixed option, transient, cron hook, and legacy key.
 */
function handl_aicac_uninstall_purge(): void {
	if ( isset( $GLOBALS['handl_aicac_test_options'] ) && is_array( $GLOBALS['handl_aicac_test_options'] ) ) {
		foreach ( array_keys( $GLOBALS['handl_aicac_test_options'] ) as $key ) {
			if ( 0 === strpos( (string) $key, 'handl_aicac_' ) ) {
				delete_option( (string) $key );
			}
		}
	}

	if ( isset( $GLOBALS['handl_aicac_test_transients'] ) && is_array( $GLOBALS['handl_aicac_test_transients'] ) ) {
		foreach ( array_keys( $GLOBALS['handl_aicac_test_transients'] ) as $key ) {
			if ( 0 === strpos( (string) $key, 'handl_aicac_' ) ) {
				delete_transient( (string) $key );
			}
		}
	}

	if ( isset( $GLOBALS['handl_aicac_test_cron'] ) && is_array( $GLOBALS['handl_aicac_test_cron'] ) ) {
		foreach ( array_keys( $GLOBALS['handl_aicac_test_cron'] ) as $hook ) {
			if ( 0 === strpos( (string) $hook, 'handl_aicac_' ) && function_exists( 'wp_clear_scheduled_hook' ) ) {
				wp_clear_scheduled_hook( (string) $hook );
			}
		}
	}

	global $wpdb;
	if ( isset( $wpdb ) && is_object( $wpdb ) && ! empty( $wpdb->options ) && method_exists( $wpdb, 'query' ) && method_exists( $wpdb, 'prepare' ) && method_exists( $wpdb, 'esc_like' ) ) {
		$like = $wpdb->esc_like( 'handl_aicac_' ) . '%';
		$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->options} WHERE option_name LIKE %s", $like ) );
		$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->options} WHERE option_name LIKE %s", $wpdb->esc_like( '_transient_handl_aicac_' ) . '%' ) );
		$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->options} WHERE option_name LIKE %s", $wpdb->esc_like( '_transient_timeout_handl_aicac_' ) . '%' ) );
		if ( isset( $wpdb->sitemeta ) && function_exists( 'is_multisite' ) && is_multisite() ) {
			$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->sitemeta} WHERE meta_key LIKE %s", $like ) );
		}
	}

	foreach ( handl_aicac_uninstall_legacy_option_keys() as $legacy ) {
		delete_option( $legacy );
	}

	if ( function_exists( 'wp_clear_scheduled_hook' ) ) {
		foreach ( handl_aicac_uninstall_cron_hooks() as $hook ) {
			wp_clear_scheduled_hook( $hook );
		}
	}

	if ( function_exists( 'delete_metadata' ) ) {
		delete_metadata( 'user', 0, 'handl_aicac_whats_new_dismissed', '', true );
	}
}

/**
 * Honor the stored policy for the current site. Missing option = keep.
 */
function handl_aicac_run_uninstall(): void {
	if ( 'purge' !== handl_aicac_uninstall_policy() ) {
		return;
	}
	handl_aicac_uninstall_purge();
}

/**
 * Run per site on network delete; otherwise once on the current site.
 *
 * @param callable $callback Callback with no arguments.
 */
function handl_aicac_uninstall_foreach_site( $callback ): void {
	if ( function_exists( 'is_multisite' ) && is_multisite() && function_exists( 'get_sites' ) && function_exists( 'switch_to_blog' ) && function_exists( 'restore_current_blog' ) ) {
		$sites = get_sites( array( 'fields' => 'ids', 'number' => 10000 ) );
		if ( is_array( $sites ) && array() !== $sites ) {
			foreach ( $sites as $site_id ) {
				switch_to_blog( (int) $site_id );
				call_user_func( $callback );
				restore_current_blog();
			}
			return;
		}
	}
	call_user_func( $callback );
}

if ( defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	handl_aicac_uninstall_foreach_site( 'handl_aicac_run_uninstall' );
}
