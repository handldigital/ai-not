<?php
/**
 * AICAC-EMAIL-BRAND (#154): shared chrome for plugin emails.
 *
 * Wraps existing per-type content blocks with a consistent header, intro,
 * and footer. Content blocks stay byte-identical. Always provides a plain-text
 * body and an HTML alternative. Never displays recipient email addresses.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Shared email layout helper.
 */
final class Email_Template {

	public const CONTENT_START = '=== HandL message ===';
	public const CONTENT_END   = '=== End HandL message ===';

	/**
	 * Site display name for the header.
	 */
	public static function site_name(): string {
		if ( function_exists( 'get_bloginfo' ) ) {
			$name = wp_specialchars_decode( (string) get_bloginfo( 'name' ), ENT_QUOTES );
			if ( '' !== $name ) {
				return $name;
			}
		}

		return 'WordPress';
	}

	/**
	 * Product name for the header (not translated — brand string).
	 */
	public static function product_name(): string {
		return 'HandL AI Connector Access Control';
	}

	/**
	 * Settings deep link (no recipient address).
	 */
	public static function settings_url(): string {
		return admin_url( 'options-general.php?page=handl-ai-connector-access-control' );
	}

	/**
	 * Default intro line (shared chrome — Krusty-gated).
	 */
	public static function default_intro(): string {
		return __( 'This message is from HandL AI Connector Access Control on your WordPress site.', 'handl-ai-connector-access-control' );
	}

	/**
	 * Standard footer lines (shared chrome — Krusty-gated). No email addresses.
	 *
	 * @return list<string>
	 */
	public static function footer_lines(): array {
		return array(
			__( 'You received this because alerts or reports are turned on for this site.', 'handl-ai-connector-access-control' ),
			__( 'Manage HandL AI Connector Access Control settings:', 'handl-ai-connector-access-control' ),
			self::settings_url(),
		);
	}

	/**
	 * @return array{text:string,html:string}
	 */
	public static function compose( string $content_block, ?string $intro = null ): array {
		$content_block = self::normalize_content( $content_block );
		$intro         = null !== $intro ? trim( (string) $intro ) : self::default_intro();
		$actions       = class_exists( Inbox_Actions::class ) ? Inbox_Actions::email_footer_lines() : array();
		$text          = self::build_text( $content_block, $intro, $actions );
		$html          = self::build_html( $content_block, $intro, $actions );

		return array(
			'text' => $text,
			'html' => $html,
		);
	}

	/**
	 * Pull the content block back out of a wrapped plain-text body (tests / AC).
	 */
	public static function extract_content( string $wrapped_text ): string {
		$start = strpos( $wrapped_text, self::CONTENT_START );
		$end   = strpos( $wrapped_text, self::CONTENT_END );
		if ( false === $start || false === $end || $end <= $start ) {
			return '';
		}
		$start += strlen( self::CONTENT_START );
		$chunk  = substr( $wrapped_text, $start, $end - $start );
		// Trim the single leading/trailing newlines we add around content.
		if ( 0 === strpos( $chunk, "\n" ) ) {
			$chunk = substr( $chunk, 1 );
		}
		if ( substr( $chunk, -1 ) === "\n" ) {
			$chunk = substr( $chunk, 0, -1 );
		}

		return $chunk;
	}

	/**
	 * True when the body already includes our content markers (avoid double-wrap).
	 */
	public static function is_wrapped( string $body ): bool {
		return false !== strpos( $body, self::CONTENT_START ) && false !== strpos( $body, self::CONTENT_END );
	}

	/**
	 * Build multipart/alternative headers + body for wp_mail.
	 *
	 * @param array{text:string,html:string} $parts
	 * @return array{headers:list<string>,body:string}
	 */
	public static function multipart_payload( array $parts ): array {
		$boundary = 'handl_aicac_' . md5( uniqid( (string) mt_rand(), true ) );
		$text     = (string) ( $parts['text'] ?? '' );
		$html     = (string) ( $parts['html'] ?? '' );

		$chunks   = array();
		$chunks[] = '--' . $boundary;
		$chunks[] = 'Content-Type: text/plain; charset=UTF-8';
		$chunks[] = 'Content-Transfer-Encoding: 8bit';
		$chunks[] = '';
		$chunks[] = $text;
		$chunks[] = '--' . $boundary;
		$chunks[] = 'Content-Type: text/html; charset=UTF-8';
		$chunks[] = 'Content-Transfer-Encoding: 8bit';
		$chunks[] = '';
		$chunks[] = $html;
		$chunks[] = '--' . $boundary . '--';
		$chunks[] = '';

		return array(
			'headers' => array(
				'MIME-Version: 1.0',
				'Content-Type: multipart/alternative; boundary="' . $boundary . '"',
			),
			'body'    => implode( "\r\n", $chunks ),
		);
	}

	private static function normalize_content( string $content ): string {
		$content = str_replace( array( "\r\n", "\r" ), "\n", $content );
		return $content;
	}

	/**
	 * @param list<string> $actions
	 */
	private static function build_text( string $content, string $intro, array $actions = array() ): string {
		$lines   = array();
		$lines[] = self::product_name();
		$lines[] = sprintf(
			/* translators: %s: site name */
			__( 'Site: %s', 'handl-ai-connector-access-control' ),
			self::site_name()
		);
		$lines[] = '';
		if ( '' !== $intro ) {
			$lines[] = $intro;
			$lines[] = '';
		}
		$lines[] = self::CONTENT_START;
		$lines[] = $content;
		if ( '' === $content || substr( $content, -1 ) !== "\n" ) {
			// CONTENT_END on its own line after content.
		}
		$lines[] = self::CONTENT_END;
		$lines[] = '';
		foreach ( self::footer_lines() as $footer_line ) {
			$lines[] = $footer_line;
		}
		if ( ! empty( $actions ) ) {
			$lines[] = '';
			foreach ( $actions as $action_line ) {
				$lines[] = $action_line;
			}
		}
		$lines[] = '';

		return implode( "\n", $lines );
	}

	/**
	 * @param list<string> $actions
	 */
	private static function build_html( string $content, string $intro, array $actions = array() ): string {
		$esc = static function ( string $s ): string {
			return htmlspecialchars( $s, ENT_QUOTES, 'UTF-8' );
		};

		$header = $esc( self::product_name() );
		$site   = $esc(
			sprintf(
				/* translators: %s: site name */
				__( 'Site: %s', 'handl-ai-connector-access-control' ),
				self::site_name()
			)
		);
		$intro_html = '' !== $intro ? '<p>' . $esc( $intro ) . '</p>' : '';
		// Preserve content newlines; content may already include plain URLs.
		$content_html = nl2br( $esc( rtrim( $content, "\n" ) ), false );
		$footer_bits  = array();
		foreach ( array_merge( self::footer_lines(), $actions ) as $line ) {
			if ( '' === $line ) {
				continue;
			}
			if ( 0 === strpos( $line, 'http://' ) || 0 === strpos( $line, 'https://' ) ) {
				$url           = $esc( $line );
				$footer_bits[] = '<p><a href="' . $url . '">' . $url . '</a></p>';
			} else {
				$footer_bits[] = '<p>' . $esc( $line ) . '</p>';
			}
		}

		return '<!DOCTYPE html><html><body style="font-family:sans-serif;font-size:14px;line-height:1.45;color:#111;">'
			. '<p><strong>' . $header . '</strong><br />' . $site . '</p>'
			. $intro_html
			. '<hr />'
			. '<div>' . $content_html . '</div>'
			. '<hr />'
			. implode( '', $footer_bits )
			. '</body></html>';
	}
}
