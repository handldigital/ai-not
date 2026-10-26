<?php
/**
 * AICAC-HALT-HELPER (#483): shared terminal-page shapes for admin POST handlers.
 *
 * Three recurring copy-nit classes — nonce failure, permission denied, and
 * save-success dead-ends — live here so new screens stop reinventing them.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Terminal admin pages: security check failed / permission denied / saved.
 */
final class Halt {

	/** @var string */
	private static $last_kind = '';

	/** @var string */
	private static $last_message = '';

	/** @var string */
	private static $last_html = '';

	/** @var string */
	private static $last_back_url = '';

	public static function reset_for_tests(): void {
		self::$last_kind     = '';
		self::$last_message  = '';
		self::$last_html     = '';
		self::$last_back_url = '';
	}

	public static function last_kind(): string {
		return self::$last_kind;
	}

	public static function last_message(): string {
		return self::$last_message;
	}

	public static function last_html(): string {
		return self::$last_html;
	}

	public static function last_back_url(): string {
		return self::$last_back_url;
	}

	/**
	 * Admin screen URL for a page slug (empty when admin_url is unavailable).
	 */
	public static function admin_page_url( string $page_slug ): string {
		if ( '' === $page_slug || ! function_exists( 'admin_url' ) ) {
			return '';
		}
		$url = admin_url( 'admin.php' );
		if ( function_exists( 'add_query_arg' ) ) {
			return (string) add_query_arg( array( 'page' => $page_slug ), $url );
		}

		return $url . '?page=' . rawurlencode( $page_slug );
	}

	/**
	 * Nonce / present-flag failure: say what happened and how to recover.
	 */
	public static function security_check_failed( string $back_url = '' ): void {
		self::emit(
			'security',
			__( 'Security check failed. Go back, reload the page, and try again.', 'handl-ai-connector-access-control' ),
			$back_url,
			403
		);
	}

	/**
	 * Permission denial. Empty $what uses the house default (Deny receipts wording).
	 *
	 * @param string $what Full message, or empty for the default.
	 */
	public static function permission_denied( string $what = '', string $back_url = '' ): void {
		$message = '' !== $what
			? $what
			: __( 'You need permission to manage these settings.', 'handl-ai-connector-access-control' );
		self::emit( 'permission', $message, $back_url, 403 );
	}

	/**
	 * Save-success terminal page that always offers a back link when a URL is known.
	 */
	public static function saved( string $message, string $back_url = '' ): void {
		self::emit( 'saved', $message, $back_url, 200 );
	}

	/**
	 * @param 'security'|'permission'|'saved' $kind Terminal kind.
	 */
	private static function emit( string $kind, string $message, string $back_url, int $response ): void {
		$back_url = self::sanitize_back_url( $back_url );

		self::$last_kind     = $kind;
		self::$last_message  = $message;
		self::$last_back_url = $back_url;

		$html  = '<div class="wrap handl-aicac-halt">';
		$html .= '<p>' . esc_html( $message ) . '</p>';
		if ( '' !== $back_url ) {
			$html .= '<p><a class="button" href="' . esc_url( $back_url ) . '">';
			$html .= esc_html__( 'Back to settings', 'handl-ai-connector-access-control' );
			$html .= '</a></p>';
		}
		$html .= '</div>';

		self::$last_html = $html;

		if ( defined( 'HANDL_AICAC_PHPUNIT' ) && HANDL_AICAC_PHPUNIT ) {
			return;
		}

		if ( function_exists( 'wp_die' ) ) {
			wp_die( $html, '', array( 'response' => $response ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- HTML built with esc_html/esc_url above.
		}

		echo $html; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- HTML built with esc_html/esc_url above.
		exit;
	}

	private static function sanitize_back_url( string $back_url ): string {
		$back_url = trim( $back_url );
		if ( '' === $back_url ) {
			return '';
		}
		if ( function_exists( 'esc_url_raw' ) ) {
			$back_url = (string) esc_url_raw( $back_url );
		}
		if ( '' === $back_url ) {
			return '';
		}
		// Prefer same-origin admin URLs; reject obvious off-site schemes.
		if ( preg_match( '#^(javascript|data):#i', $back_url ) ) {
			return '';
		}

		return $back_url;
	}
}
