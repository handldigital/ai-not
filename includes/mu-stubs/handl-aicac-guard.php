<?php
/**
 * HandL AI Connector Access Control — hardened must-use guard.
 *
 * Installed by the main plugin when Hardened mode is enabled. Survives
 * deactivation of the main plugin. Do not edit by hand — toggle via
 * `wp handl-aicac hardened`.
 *
 * Stub version: 1
 *
 * @package HandL_AICAC
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( ! defined( 'HANDL_AICAC_GUARD_STUB_VERSION' ) ) {
	define( 'HANDL_AICAC_GUARD_STUB_VERSION', '1' );
}

/**
 * Main plugin owns enforcement when it is loaded.
 */
function handl_aicac_guard_main_loaded(): bool {
	return defined( 'HANDL_AICAC_VERSION' );
}

/**
 * @return 'fail_closed'|'watch'|''
 */
function handl_aicac_guard_mode(): string {
	$raw = get_option( 'handl_aicac_hardened_mode', '' );
	if ( 'fail_closed' === $raw || 'watch' === $raw ) {
		return $raw;
	}
	return '';
}

/**
 * Append one fallback row while the main plugin is inactive (watch mode).
 *
 * @param array<string,mixed> $row
 */
function handl_aicac_guard_append_fallback( array $row ): void {
	$key = 'handl_aicac_guard_fallback_log';
	$log = get_option( $key, array() );
	if ( ! is_array( $log ) ) {
		$log = array();
	}
	$log[] = $row;
	if ( count( $log ) > 50 ) {
		$log = array_slice( $log, -50 );
	}
	update_option( $key, $log, false );
}

/**
 * One watch-mode alert per deactivation stamp (shares Tamper option key).
 */
function handl_aicac_guard_maybe_alert( int $now ): void {
	$deactivated_at = (int) get_option( 'handl_aicac_deactivated_at', 0 );
	if ( $deactivated_at < 1 ) {
		$deactivated_at = $now;
	}

	$sent_for = (int) get_option( 'handl_aicac_guard_alert_for', 0 );
	if ( $sent_for === $deactivated_at ) {
		return;
	}

	$to = get_option( 'handl_aicac_policy', array() );
	$email = '';
	if ( is_array( $to ) && ! empty( $to['alert_email'] ) && is_string( $to['alert_email'] ) ) {
		$email = sanitize_email( $to['alert_email'] );
	}
	if ( '' === $email ) {
		$email = sanitize_email( (string) get_option( 'admin_email', '' ) );
	}
	if ( '' === $email || ! is_email( $email ) ) {
		return;
	}

	$subject = '[HandL AI Connector] Hardened watch: AI call while plugin inactive';
	$body    = "Hardened mode is set to Watch. The main plugin is inactive, so an AI Client call was allowed and logged to the fallback log.\n\n";
	$body   .= 'Time (UTC): ' . gmdate( 'c', $now ) . "\n";
	$body   .= "Mode: watch\n";
	$body   .= "This is observe-only; calls are not blocked while Watch is on.\n";

	// phpcs:ignore WordPress.WP.AlternativeFunctions.wp_mail -- stub has no Alerts class.
	$ok = wp_mail( $email, $subject, $body );
	if ( $ok ) {
		update_option( 'handl_aicac_guard_alert_for', $deactivated_at, false );
	}
}

/**
 * @param bool  $prevent
 * @param mixed $builder
 */
function handl_aicac_guard_maybe_prevent( $prevent, $builder ) {
	unset( $builder );

	if ( handl_aicac_guard_main_loaded() ) {
		return (bool) $prevent;
	}

	$mode = handl_aicac_guard_mode();
	if ( '' === $mode ) {
		return (bool) $prevent;
	}

	$now = time();

	if ( 'watch' === $mode ) {
		handl_aicac_guard_append_fallback(
			array(
				'ts'       => $now,
				'decision' => 'allow',
				'channel'  => 'hardened_guard',
				'mode'     => 'watch',
				'note'     => 'main_plugin_inactive',
			)
		);
		handl_aicac_guard_maybe_alert( $now );
		return (bool) $prevent;
	}

	// fail_closed
	handl_aicac_guard_append_fallback(
		array(
			'ts'       => $now,
			'decision' => 'deny',
			'channel'  => 'hardened_guard',
			'mode'     => 'fail_closed',
			'note'     => 'main_plugin_inactive',
		)
	);

	return true;
}

add_filter( 'wp_ai_client_prevent_prompt', 'handl_aicac_guard_maybe_prevent', 0, 2 );
