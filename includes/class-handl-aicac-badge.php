<?php
/**
 * AICAC-BADGE (#317): public AI-transparency badge + copyable embed.
 *
 * Inline SVG only. Renders when the public disclosure page is on.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Small public badge that links to the published AI disclosure.
 */
final class Badge {

	public const SHORTCODE = 'handl_ai_badge';

	public const BLOCK_NAME = 'handl-aicac/badge';

	public const LABEL = 'AI disclosure';

	public const SETTINGS_SNIPPET = 'Copy this HTML to link to this site’s public AI disclosure. Remove pasted badges if you turn the disclosure off.';

	public const SETTINGS_TA_LABEL = 'Badge embed code';

	public const QUERY_VAR = 'handl_aicac_disclosure';

	public const PATH = '/ai-disclosure/';

	/** @var Badge|null */
	private static $instance = null;

	public static function instance(): Badge {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}

		return self::$instance;
	}

	public static function reset_for_tests(): void {
		self::$instance = null;
	}

	/**
	 * Hook only. No option reads — render is the first I/O.
	 */
	public function init(): void {
		if ( function_exists( 'add_shortcode' ) ) {
			add_shortcode( self::SHORTCODE, array( $this, 'render_shortcode' ) );
		}
		add_action( 'init', array( $this, 'register_block' ) );
		add_action( 'init', array( $this, 'register_rewrite' ) );
		add_filter( 'query_vars', array( $this, 'query_vars' ) );
		add_action( 'template_redirect', array( $this, 'maybe_serve' ), 0 );
		add_action( 'update_option_' . Plugin::OPTION_KEY, array( $this, 'maybe_flush_rewrites' ), 10, 2 );
	}

	public function register_rewrite(): void {
		if ( ! function_exists( 'add_rewrite_rule' ) ) {
			return;
		}
		add_rewrite_rule( '^ai-disclosure/?$', 'index.php?' . self::QUERY_VAR . '=1', 'top' );
	}

	/**
	 * @param mixed $vars Query vars.
	 * @return array<int|string,mixed>
	 */
	public function query_vars( $vars ) {
		if ( ! is_array( $vars ) ) {
			$vars = array();
		}
		$vars[] = self::QUERY_VAR;

		return $vars;
	}

	/**
	 * @param mixed $old Previous option.
	 * @param mixed $value New option.
	 */
	public function maybe_flush_rewrites( $old, $value ): void {
		$old_on = class_exists( Disclosure::class ) && Disclosure::is_privacy_enabled( is_array( $old ) ? $old : array() );
		$new_on = class_exists( Disclosure::class ) && Disclosure::is_privacy_enabled( is_array( $value ) ? $value : array() );
		if ( $old_on === $new_on ) {
			return;
		}
		if ( function_exists( 'flush_rewrite_rules' ) ) {
			flush_rewrite_rules( false );
		}
	}

	public function register_block(): void {
		if ( ! function_exists( 'register_block_type' ) ) {
			return;
		}

		register_block_type(
			self::BLOCK_NAME,
			array(
				'api_version'     => 3,
				'title'           => self::LABEL,
				'description'     => self::SETTINGS_SNIPPET,
				'category'        => 'widgets',
				'render_callback' => array( $this, 'render_block' ),
			)
		);
	}

	/**
	 * @param mixed $atts Shortcode attributes.
	 */
	public function render_shortcode( $atts = array() ): string {
		unset( $atts );

		return self::render();
	}

	/**
	 * @param array<string,mixed> $attributes Block attributes.
	 * @param string              $content    Inner content (unused).
	 */
	public function render_block( $attributes = array(), $content = '' ): string {
		unset( $attributes, $content );

		return self::render();
	}

	/**
	 * @param array<string,mixed>|null $policy
	 */
	public static function render( ?array $policy = null ): string {
		if ( null === $policy ) {
			$policy = class_exists( Policy::class ) ? Policy::get_policy() : array();
		}
		$policy = is_array( $policy ) ? $policy : array();
		if ( ! class_exists( Disclosure::class ) || ! Disclosure::is_privacy_enabled( $policy ) ) {
			return '';
		}

		$disclosure = self::disclosure_url();
		$json       = '';
		if ( Disclosure::is_json_enabled( $policy ) && class_exists( Ai_Json::class ) ) {
			$json = Ai_Json::public_url();
		}

		return self::markup( $disclosure, $json );
	}

	/**
	 * Same markup as the public badge (for the settings textarea).
	 *
	 * @param array<string,mixed>|null $policy
	 */
	public static function embed_snippet( ?array $policy = null ): string {
		return self::render( $policy );
	}

	/**
	 * Settings fields inside the Public AI disclosure row.
	 *
	 * @param array<string,mixed> $policy
	 */
	public static function render_settings( array $policy ): void {
		if ( ! class_exists( Disclosure::class ) || ! Disclosure::is_privacy_enabled( $policy ) ) {
			return;
		}
		$snippet = self::embed_snippet( $policy );
		echo '<p class="description">' . esc_html__( 'Copy this HTML to link to this site’s public AI disclosure. Remove pasted badges if you turn the disclosure off.', 'handl-ai-connector-access-control' ) . '</p>';
		echo '<p><label for="handl-aicac-badge-embed">' . esc_html__( 'Badge embed code', 'handl-ai-connector-access-control' ) . '</label></p>';
		echo '<textarea id="handl-aicac-badge-embed" class="large-text code" rows="6" readonly="readonly">';
		echo function_exists( 'esc_textarea' ) ? esc_textarea( $snippet ) : htmlspecialchars( $snippet, ENT_QUOTES, 'UTF-8' );
		echo '</textarea>';
	}

	public static function disclosure_url(): string {
		if ( function_exists( 'get_privacy_policy_url' ) ) {
			$url = (string) get_privacy_policy_url();
			if ( '' !== $url ) {
				return $url;
			}
		}

		return self::public_url();
	}

	public static function public_url(): string {
		if ( function_exists( 'home_url' ) ) {
			return home_url( self::PATH );
		}

		return self::PATH;
	}

	public static function is_requested(): bool {
		if ( isset( $_GET[ self::QUERY_VAR ] ) && '1' === (string) wp_unslash( (string) $_GET[ self::QUERY_VAR ] ) ) {
			return true;
		}
		if ( function_exists( 'get_query_var' ) && (string) get_query_var( self::QUERY_VAR ) === '1' ) {
			return true;
		}

		return false;
	}

	/**
	 * Public HTML disclosure when no privacy-policy page is set.
	 *
	 * @param array<string,mixed>|null $policy
	 * @return array{status:int,body:string}
	 */
	public static function respond( ?array $policy = null ): array {
		if ( null === $policy ) {
			$policy = class_exists( Policy::class ) ? Policy::get_policy() : array();
		}
		$policy = is_array( $policy ) ? $policy : array();
		if ( ! class_exists( Disclosure::class ) || ! Disclosure::is_privacy_enabled( $policy ) ) {
			return array(
				'status' => 404,
				'body'   => '',
			);
		}
		$inner = Disclosure::render( null, $policy, null, null );
		$title = class_exists( Disclosure::class ) ? Disclosure::HEADING : self::LABEL;
		$body  = '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>' . esc_html( $title ) . '</title></head><body>';
		$body .= $inner;
		$body .= '</body></html>';

		return array(
			'status' => 200,
			'body'   => $body,
		);
	}

	public function maybe_serve(): void {
		if ( ! self::is_requested() ) {
			return;
		}
		$out = self::respond();
		self::emit( $out );
	}

	/**
	 * @param array{status:int,body:string} $out
	 */
	public static function emit( array $out ): void {
		if ( function_exists( 'status_header' ) ) {
			status_header( (int) $out['status'] );
		}
		$phpunit = defined( 'HANDL_AICAC_PHPUNIT' ) && HANDL_AICAC_PHPUNIT;
		if ( $phpunit ) {
			$GLOBALS['handl_aicac_test_badge_emitted'] = $out;
			return;
		}
		if ( function_exists( 'header' ) ) {
			header( 'Content-Type: text/html; charset=UTF-8' );
		}
		echo (string) ( $out['body'] ?? '' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- assembled HTML.
		exit;
	}

	public static function svg(): string {
		$label = self::LABEL;

		return '<svg xmlns="http://www.w3.org/2000/svg" width="132" height="28" viewBox="0 0 132 28" role="img" aria-labelledby="handl-aicac-badge-title">'
			. '<title id="handl-aicac-badge-title">' . esc_html( $label ) . '</title>'
			. '<rect width="132" height="28" rx="4" fill="#111111"/>'
			. '<circle cx="14" cy="14" r="7" fill="none" stroke="#ffffff" stroke-width="1.6"/>'
			. '<circle cx="14" cy="10" r="1.15" fill="#ffffff"/>'
			. '<path d="M14 13.2 v7.2" fill="none" stroke="#ffffff" stroke-width="1.7" stroke-linecap="round"/>'
			. '<text x="26" y="18" fill="#ffffff" font-size="12" font-family="system-ui,sans-serif">' . esc_html( $label ) . '</text>'
			. '</svg>';
	}

	private static function markup( string $disclosure_url, string $json_url ): string {
		$html  = '<p class="handl-aicac-badge">';
		$html .= '<a class="handl-aicac-badge__link" href="' . esc_url( $disclosure_url ) . '">';
		$html .= self::svg();
		$html .= '</a>';
		if ( '' !== $json_url ) {
			$json_label = class_exists( Disclosure::class ) ? Disclosure::FOOTER_JSON : 'Machine-readable copy';
			$html      .= ' <a class="handl-aicac-badge__json" href="' . esc_url( $json_url ) . '">' . esc_html( $json_label ) . '</a>';
		}
		$html .= '</p>';

		return $html;
	}
}
