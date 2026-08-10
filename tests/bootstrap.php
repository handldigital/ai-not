<?php
/**
 * PHPUnit bootstrap for HandL AICAC unit tests.
 *
 * Loads production classes without a full WordPress install by defining
 * ABSPATH and stubbing the few WP helpers the decision engine / alerts call.
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

if ( ! defined( 'HOUR_IN_SECONDS' ) ) {
	define( 'HOUR_IN_SECONDS', 3600 );
}

if ( ! defined( 'ENT_QUOTES' ) ) {
	// PHP already defines ENT_QUOTES; keep guard for completeness.
}

if ( ! class_exists( 'WP_Error', false ) ) {
	/**
	 * Minimal WP_Error stand-in for HTTP failure paths.
	 */
	class WP_Error {
		/** @var string */
		public $code;
		/** @var string */
		public $message;

		public function __construct( string $code = '', string $message = '' ) {
			$this->code    = $code;
			$this->message = $message;
		}

		public function get_error_message(): string {
			return $this->message;
		}
	}
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

if ( ! function_exists( 'sanitize_key' ) ) {
	/**
	 * @param string $key Raw key.
	 */
	function sanitize_key( $key ): string {
		$key = strtolower( (string) $key );
		return (string) preg_replace( '/[^a-z0-9_\-]/', '', $key );
	}
}

if ( ! function_exists( 'sanitize_email' ) ) {
	/**
	 * @param string $email Raw email.
	 */
	function sanitize_email( $email ): string {
		$email = trim( (string) $email );
		$email = filter_var( $email, FILTER_SANITIZE_EMAIL );
		return is_string( $email ) ? $email : '';
	}
}

if ( ! function_exists( 'is_email' ) ) {
	/**
	 * @param string $email Candidate.
	 */
	function is_email( $email ) {
		return false !== filter_var( (string) $email, FILTER_VALIDATE_EMAIL ) ? (string) $email : false;
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

if ( ! function_exists( '_n' ) ) {
	/**
	 * @param string $single Singular.
	 * @param string $plural Plural.
	 * @param int    $number Count.
	 */
	function _n( $single, $plural, $number, $domain = 'default' ): string {
		unset( $domain );
		return 1 === (int) $number ? (string) $single : (string) $plural;
	}
}

if ( ! function_exists( 'esc_html' ) ) {
	/**
	 * @param string $text Text.
	 */
	function esc_html( $text ): string {
		return htmlspecialchars( (string) $text, ENT_QUOTES, 'UTF-8' );
	}
}

if ( ! function_exists( 'esc_url' ) ) {
	/**
	 * @param string $url URL.
	 */
	function esc_url( $url ): string {
		return (string) $url;
	}
}


if ( ! function_exists( 'is_multisite' ) ) {
	/**
	 * Default false so Network_Admin::init() is a no-op in unit tests (AC1).
	 * Tests may flip $GLOBALS['handl_aicac_test_is_multisite'].
	 */
	function is_multisite(): bool {
		return ! empty( $GLOBALS['handl_aicac_test_is_multisite'] );
	}
}

if ( ! function_exists( 'esc_url_raw' ) ) {
	/**
	 * Minimal esc_url_raw: keep http(s) URLs; drop others when allowlisted.
	 *
	 * @param string       $url       Raw URL.
	 * @param list<string>|null $protocols Allowed schemes.
	 */
	function esc_url_raw( $url, $protocols = null ): string {
		$url = trim( (string) $url );
		if ( '' === $url ) {
			return '';
		}
		$parts = wp_parse_url( $url );
		if ( ! is_array( $parts ) || empty( $parts['scheme'] ) || empty( $parts['host'] ) ) {
			return '';
		}
		$scheme = strtolower( (string) $parts['scheme'] );
		$allowed = is_array( $protocols ) ? $protocols : array( 'http', 'https' );
		$allowed = array_map( 'strtolower', $allowed );
		if ( ! in_array( $scheme, $allowed, true ) ) {
			return '';
		}
		return $url;
	}
}

if ( ! function_exists( 'wp_parse_url' ) ) {
	/**
	 * @param string $url URL.
	 * @param int    $component Component.
	 * @return mixed
	 */
	function wp_parse_url( $url, $component = -1 ) {
		return parse_url( (string) $url, $component );
	}
}

if ( ! function_exists( 'wp_json_encode' ) ) {
	/**
	 * @param mixed $data Data.
	 */
	function wp_json_encode( $data, $options = 0, $depth = 512 ) {
		return json_encode( $data, $options, $depth );
	}
}

if ( ! function_exists( 'wp_specialchars_decode' ) ) {
	/**
	 * @param string $text Text.
	 * @param int    $quote_style Quote style.
	 */
	function wp_specialchars_decode( $text, $quote_style = ENT_NOQUOTES ): string {
		return html_entity_decode( (string) $text, $quote_style, 'UTF-8' );
	}
}

if ( ! function_exists( 'wp_date' ) ) {
	/**
	 * @param string   $format Format.
	 * @param int|null $timestamp Timestamp.
	 */
	function wp_date( $format, $timestamp = null, $timezone = null ): string {
		unset( $timezone );
		return gmdate( (string) $format, null === $timestamp ? time() : (int) $timestamp );
	}
}

if ( ! function_exists( 'get_bloginfo' ) ) {
	/**
	 * @param string $show Field.
	 */
	function get_bloginfo( $show = '' ): string {
		unset( $show );
		return 'Test Site';
	}
}

if ( ! function_exists( 'home_url' ) ) {
	/**
	 * @param string $path Path.
	 */
	function home_url( $path = '' ): string {
		return 'https://example.test' . (string) $path;
	}
}

if ( ! function_exists( 'admin_url' ) ) {
	/**
	 * @param string $path Path.
	 */
	function admin_url( $path = '' ): string {
		return 'https://example.test/wp-admin/' . ltrim( (string) $path, '/' );
	}
}

if ( ! function_exists( 'get_option' ) ) {
	/**
	 * @param string $key Option key.
	 * @param mixed  $default Default.
	 * @return mixed
	 */
	function get_option( $key, $default = false ) {
		$store = $GLOBALS['handl_aicac_test_options'] ?? array();
		if ( array_key_exists( (string) $key, $store ) ) {
			return $store[ (string) $key ];
		}
		if ( 'admin_email' === $key ) {
			return 'admin@example.com';
		}
		return $default;
	}
}

if ( ! function_exists( 'update_option' ) ) {
	/**
	 * @param string $key Option key.
	 * @param mixed  $value Value.
	 */
	function update_option( $key, $value, $autoload = null ): bool {
		unset( $autoload );
		if ( ! isset( $GLOBALS['handl_aicac_test_options'] ) || ! is_array( $GLOBALS['handl_aicac_test_options'] ) ) {
			$GLOBALS['handl_aicac_test_options'] = array();
		}
		$GLOBALS['handl_aicac_test_options'][ (string) $key ] = $value;
		return true;
	}
}

if ( ! function_exists( 'delete_option' ) ) {
	/**
	 * @param string $key Option key.
	 */
	function delete_option( $key ): bool {
		if ( isset( $GLOBALS['handl_aicac_test_options'] ) && is_array( $GLOBALS['handl_aicac_test_options'] ) ) {
			unset( $GLOBALS['handl_aicac_test_options'][ (string) $key ] );
		}
		return true;
	}
}

if ( ! function_exists( 'add_action' ) ) {
	/**
	 * Capture hooks for Network_Admin init tests.
	 *
	 * @param string   $hook          Hook name.
	 * @param callable $callback      Callback.
	 * @param int      $priority      Priority.
	 * @param int      $accepted_args Accepted args.
	 */
	function add_action( $hook, $callback, $priority = 10, $accepted_args = 1 ): bool {
		unset( $callback, $priority, $accepted_args );
		if ( ! isset( $GLOBALS['handl_aicac_test_added_actions'] ) || ! is_array( $GLOBALS['handl_aicac_test_added_actions'] ) ) {
			$GLOBALS['handl_aicac_test_added_actions'] = array();
		}
		$GLOBALS['handl_aicac_test_added_actions'][] = (string) $hook;
		return true;
	}
}

if ( ! function_exists( 'wp_mail' ) ) {
	/**
	 * @param string|list<string> $to Recipients.
	 * @param string              $subject Subject.
	 * @param string              $message Body.
	 */
	function wp_mail( $to, $subject, $message, $headers = '', $attachments = array() ): bool {
		unset( $headers, $attachments );
		if ( isset( $GLOBALS['handl_aicac_wp_mail'] ) && is_callable( $GLOBALS['handl_aicac_wp_mail'] ) ) {
			return (bool) call_user_func( $GLOBALS['handl_aicac_wp_mail'], $to, $subject, $message );
		}
		return true;
	}
}

if ( ! function_exists( 'wp_supports_ai' ) ) {
	/**
	 * Stub: default true; tests may set $GLOBALS['handl_aicac_wp_supports_ai'] = false.
	 */
	function wp_supports_ai(): bool {
		if ( array_key_exists( 'handl_aicac_wp_supports_ai', $GLOBALS ) ) {
			return (bool) $GLOBALS['handl_aicac_wp_supports_ai'];
		}
		return true;
	}
}

if ( ! function_exists( 'wp_remote_post' ) ) {
	/**
	 * @param string               $url URL.
	 * @param array<string,mixed>  $args Args.
	 * @return array|WP_Error
	 */
	function wp_remote_post( $url, $args = array() ) {
		if ( isset( $GLOBALS['handl_aicac_wp_remote_post'] ) && is_callable( $GLOBALS['handl_aicac_wp_remote_post'] ) ) {
			return call_user_func( $GLOBALS['handl_aicac_wp_remote_post'], (string) $url, (array) $args );
		}
		return array(
			'response' => array( 'code' => 200 ),
			'body'     => 'ok',
		);
	}
}

if ( ! function_exists( 'is_wp_error' ) ) {
	/**
	 * @param mixed $thing Value.
	 */
	function is_wp_error( $thing ): bool {
		return $thing instanceof WP_Error;
	}
}

if ( ! function_exists( 'wp_remote_retrieve_response_code' ) ) {
	/**
	 * @param array|WP_Error $response Response.
	 */
	function wp_remote_retrieve_response_code( $response ): int {
		if ( is_wp_error( $response ) || ! is_array( $response ) ) {
			return 0;
		}
		return isset( $response['response']['code'] ) ? (int) $response['response']['code'] : 0;
	}
}

require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-operations.php';
require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-cost.php';
require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-model-force.php';
require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-cost.php';
require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-spend-threshold.php';
require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-analytics.php';
require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-alerts.php';
require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-weekly-report.php';
require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-policy.php';
require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-policy-transfer.php';
require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-audit-export.php';
require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-differentiator-messaging.php';
require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-plugin.php';
require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-network-admin.php';
require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-site-health.php';
