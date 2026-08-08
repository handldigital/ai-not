<?php
/**
 * PHPUnit bootstrap for HandL AICAC unit tests.
 *
 * Loads production classes without a full WordPress install by defining
 * ABSPATH and stubbing the few WP helpers the decision engine calls.
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

if ( ! defined( 'ABSPATH' ) ) {
	define( 'ABSPATH', __DIR__ . '/../' );
}

if ( ! defined( 'HANDL_AICAC_DIR' ) ) {
	define( 'HANDL_AICAC_DIR', dirname( __DIR__ ) );
}

if ( ! defined( 'HANDL_AICAC_VERSION' ) ) {
	define( 'HANDL_AICAC_VERSION', 'test' );
}

if ( ! function_exists( 'sanitize_text_field' ) ) {
	/**
	 * Minimal stand-in for WordPress sanitize_text_field().
	 *
	 * @param string $str Raw string.
	 */
	function sanitize_text_field( $str ): string {
		$str = (string) $str;
		$str = strip_tags( $str );
		$str = preg_replace( '/[\r\n\t]+/', ' ', $str ) ?? $str;
		return trim( $str );
	}
}

if ( ! function_exists( '__' ) ) {
	/**
	 * Identity stub for WordPress i18n.
	 *
	 * @param string $text   Text.
	 * @param string $domain Text domain (unused).
	 */
	function __( $text, $domain = 'default' ): string {
		unset( $domain );
		return (string) $text;
	}
}

require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-operations.php';
require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-model-force.php';
require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-policy.php';
require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-policy-transfer.php';
