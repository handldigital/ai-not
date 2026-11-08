<?php
/**
 * AICAC-LITMUS (#506): injection-pattern test bench on the Injection screen.
 *
 * Paste sample text, see class matches and per-mode verdict. Strictly
 * ephemeral: never stores, logs, or sends the pasted text. Class-only
 * display via Taint::screen() — never echoes matched substrings.
 *
 * README-FREE. No submenu. One render call-site in taint.php.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Ephemeral pattern test bench. Does not change live screening.
 */
final class Litmus {

	public const ACTION = 'handl_aicac_litmus_test';

	public const FRAMING = 'test_only_never_persists';

	public const MAX_CHARS = 20000;

	public const FIELD_TEXT = 'handl_aicac_litmus_text';

	/** @var bool */
	private static $registered = false;

	public static function init(): void {
		if ( self::$registered ) {
			return;
		}
		self::$registered = true;
	}

	public static function reset_for_tests(): void {
		self::$registered = false;
	}

	/**
	 * Screen pasted text. Class counts only — never matched substrings.
	 *
	 * @return array{
	 *   matches: array<string,int>,
	 *   matched: bool,
	 *   verdicts: array{off:string,warn:string,deny:string},
	 *   none_would_flag: bool
	 * }
	 */
	public static function evaluate( string $text ): array {
		$matches = array();
		if ( class_exists( Taint::class, false ) && method_exists( Taint::class, 'screen' ) ) {
			$matches = Taint::screen( $text );
			if ( method_exists( Taint::class, 'sanitize_match_classes' ) ) {
				$matches = Taint::sanitize_match_classes( $matches );
			}
		}
		$matched = ! empty( $matches );

		return array(
			'matches'         => $matches,
			'matched'         => $matched,
			'verdicts'        => array(
				'off'  => __( 'Off: this check would be skipped', 'handl-ai-connector-access-control' ),
				'warn' => $matched
					? __( 'Warn: this check would flag a match without blocking it', 'handl-ai-connector-access-control' )
					: __( 'Warn: no match for this check', 'handl-ai-connector-access-control' ),
				'deny' => $matched
					? __( 'Deny: this check would block a match unless Learn mode is on', 'handl-ai-connector-access-control' )
					: __( 'Deny: no match for this check', 'handl-ai-connector-access-control' ),
			),
			'none_would_flag' => ! $matched,
		);
	}

	/**
	 * Section below the Injection screen mode table.
	 */
	public static function render_section(): void {
		if ( ! class_exists( Caps::class, false ) || ! Caps::user_can_view() ) {
			return;
		}

		$result = self::posted_result();

		echo '<div class="handl-aicac-litmus" style="max-width:52em;margin-top:2em;">';
		echo '<h2>' . esc_html__( 'Pattern test', 'handl-ai-connector-access-control' ) . '</h2>';
		echo '<p class="description">' . esc_html__( 'Paste plain text to test the current injection patterns. Results show pattern types and counts, not matching text. This test does not change settings or add Activity entries.', 'handl-ai-connector-access-control' ) . '</p>';
		echo '<p class="description">' . esc_html__( 'This tool does not save your sample or send it to an AI provider.', 'handl-ai-connector-access-control' ) . '</p>';

		echo '<form method="post" action="' . esc_url( admin_url( 'admin.php?page=' . Taint::PAGE_SLUG ) ) . '" class="handl-aicac-litmus-form">';
		echo '<input type="hidden" name="action" value="' . esc_attr( self::ACTION ) . '" />';
		if ( function_exists( 'wp_nonce_field' ) ) {
			wp_nonce_field( self::ACTION );
		}
		echo '<p><label for="handl-aicac-litmus-text">' . esc_html__( 'Sample text', 'handl-ai-connector-access-control' ) . '</label></p>';
		echo '<p><textarea id="handl-aicac-litmus-text" name="' . esc_attr( self::FIELD_TEXT ) . '" rows="6" cols="80" class="large-text"></textarea></p>';
		echo '<p class="description">' . esc_html__( 'HTML tags are removed. Only the first 20,000 bytes are tested; this may be fewer than 20,000 characters.', 'handl-ai-connector-access-control' ) . '</p>';
		if ( function_exists( 'submit_button' ) ) {
			submit_button( __( 'Test patterns', 'handl-ai-connector-access-control' ), 'secondary', 'submit', false );
		} else {
			echo '<p><button type="submit" class="button">' . esc_html__( 'Test patterns', 'handl-ai-connector-access-control' ) . '</button></p>';
		}
		echo '</form>';

		if ( is_array( $result ) ) {
			self::render_result( $result );
		}

		echo '</div>';
	}

	/**
	 * @param array{matches:array<string,int>,matched:bool,verdicts:array{off:string,warn:string,deny:string},none_would_flag:bool} $result
	 */
	private static function render_result( array $result ): void {
		echo '<div class="handl-aicac-litmus-result" style="margin-top:1.25em;">';
		echo '<h3>' . esc_html__( 'Pattern types', 'handl-ai-connector-access-control' ) . '</h3>';
		if ( empty( $result['matches'] ) ) {
			echo '<p>' . esc_html__( 'No current patterns matched the tested text.', 'handl-ai-connector-access-control' ) . '</p>';
		} else {
			$summary = class_exists( Taint::class, false ) && method_exists( Taint::class, 'receipt_summary' )
				? Taint::receipt_summary( $result['matches'] )
				: '';
			echo '<p>' . esc_html( $summary ) . '</p>';
		}

		echo '<h3>' . esc_html__( 'Mode preview', 'handl-ai-connector-access-control' ) . '</h3>';
		echo '<p class="description">' . esc_html__( 'Injection check only. Other rules still apply. Pattern checks can flag harmless text and miss attacks.', 'handl-ai-connector-access-control' ) . '</p>';
		echo '<ul class="ul-disc">';
		foreach ( array( 'off', 'warn', 'deny' ) as $mode ) {
			echo '<li>' . esc_html( (string) ( $result['verdicts'][ $mode ] ?? '' ) ) . '</li>';
		}
		echo '</ul>';
		echo '</div>';
	}

	/**
	 * Read a one-shot POST. Never writes options, transients, or Activity.
	 *
	 * @return array{matches:array<string,int>,matched:bool,verdicts:array{off:string,warn:string,deny:string},none_would_flag:bool}|null
	 */
	private static function posted_result(): ?array {
		$action = isset( $_POST['action'] ) ? sanitize_key( (string) wp_unslash( $_POST['action'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing
		if ( self::ACTION !== $action ) {
			return null;
		}
		$nonce = isset( $_POST['_wpnonce'] ) ? (string) wp_unslash( $_POST['_wpnonce'] ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing
		if ( '' === $nonce || ! function_exists( 'wp_verify_nonce' ) || ! wp_verify_nonce( $nonce, self::ACTION ) ) {
			return null;
		}
		if ( ! class_exists( Caps::class, false ) || ! Caps::user_can_view() ) {
			return null;
		}

		$raw = isset( $_POST[ self::FIELD_TEXT ] ) ? (string) wp_unslash( $_POST[ self::FIELD_TEXT ] ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing
		if ( function_exists( 'sanitize_textarea_field' ) ) {
			$raw = sanitize_textarea_field( $raw );
		}
		if ( strlen( $raw ) > self::MAX_CHARS ) {
			$raw = substr( $raw, 0, self::MAX_CHARS );
		}

		return self::evaluate( $raw );
	}
}
