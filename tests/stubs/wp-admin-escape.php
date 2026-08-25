<?php
/**
 * Minimal WP escape/checked stubs for Admin HTML unit tests.
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

if ( ! function_exists( 'esc_html' ) ) {
	/**
	 * @param string $text Text.
	 */
	function esc_html( $text ): string {
		return htmlspecialchars( (string) $text, ENT_QUOTES, 'UTF-8' );
	}
}

if ( ! function_exists( 'esc_html__' ) ) {
	/**
	 * @param string $text   Text.
	 * @param string $domain Domain.
	 */
	function esc_html__( $text, $domain = 'default' ): string {
		unset( $domain );
		return esc_html( (string) $text );
	}
}

if ( ! function_exists( 'esc_attr' ) ) {
	/**
	 * @param string $text Text.
	 */
	function esc_attr( $text ): string {
		return htmlspecialchars( (string) $text, ENT_QUOTES, 'UTF-8' );
	}
}

if ( ! function_exists( 'esc_attr__' ) ) {
	/**
	 * @param string $text   Text.
	 * @param string $domain Domain.
	 */
	function esc_attr__( $text, $domain = 'default' ): string {
		unset( $domain );
		return esc_attr( (string) $text );
	}
}

if ( ! function_exists( 'selected' ) ) {
	/**
	 * @param mixed $selected Current.
	 * @param mixed $current  Expected.
	 * @param bool  $display  Echo?
	 */
	function selected( $selected, $current = true, $display = true ) {
		$result = ( (string) $selected === (string) $current ) ? ' selected="selected"' : '';
		if ( $display ) {
			echo $result;
		}
		return $result;
	}
}

if ( ! function_exists( 'checked' ) ) {
	/**
	 * @param mixed $checked Current.
	 * @param mixed $current Expected.
	 * @param bool  $display Echo?
	 */
	function checked( $checked, $current = true, $display = true ) {
		$result = ( (string) $checked === (string) $current ) ? ' checked="checked"' : '';
		if ( $display ) {
			echo $result;
		}
		return $result;
	}
}
