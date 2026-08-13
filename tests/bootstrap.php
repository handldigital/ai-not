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
	define( 'HANDL_AICAC_VERSION', '1.5.0' );
}

if ( ! defined( 'HOUR_IN_SECONDS' ) ) {
	define( 'HOUR_IN_SECONDS', 3600 );
}

if ( ! defined( 'DAY_IN_SECONDS' ) ) {
	define( 'DAY_IN_SECONDS', 86400 );
}

if ( ! defined( 'WEEK_IN_SECONDS' ) ) {
	define( 'WEEK_IN_SECONDS', 604800 );
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

if ( ! function_exists( 'esc_html__' ) ) {
	/**
	 * @param string $text Text.
	 * @param string $domain Domain.
	 */
	function esc_html__( $text, $domain = 'default' ): string {
		return esc_html( __( $text, $domain ) );
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

if ( ! function_exists( 'wp_timezone' ) ) {
	function wp_timezone(): \DateTimeZone {
		return new \DateTimeZone( 'UTC' );
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

if ( ! function_exists( 'add_query_arg' ) ) {
	/**
	 * Minimal add_query_arg stand-in for unit tests (uses http_build_query).
	 *
	 * @param array<string,mixed>|string $key
	 * @param mixed                      $value
	 * @param string|null                $url
	 */
	function add_query_arg( $key, $value = null, $url = null ): string {
		if ( is_array( $key ) ) {
			$params = $key;
			$url    = is_string( $value ) ? $value : (string) $url;
		} else {
			$params = array( (string) $key => $value );
			$url    = (string) $url;
		}
		if ( '' === $url ) {
			$url = 'https://example.test/wp-admin/options-general.php';
		}
		$sep = false !== strpos( $url, '?' ) ? '&' : '?';
		return $url . $sep . http_build_query( $params );
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

if ( ! function_exists( 'current_user_can' ) ) {
	/**
	 * Capability stub for REST permission_callback tests.
	 *
	 * @param string $capability Capability slug.
	 */
	function current_user_can( $capability ): bool {
		unset( $capability );
		if ( array_key_exists( 'handl_aicac_test_current_user_can', $GLOBALS ) ) {
			return (bool) $GLOBALS['handl_aicac_test_current_user_can'];
		}
		return true;
	}
}



if ( ! function_exists( 'get_transient' ) ) {
	function get_transient( $key ) {
		$store = $GLOBALS['handl_aicac_test_transients'] ?? array();
		return array_key_exists( (string) $key, $store ) ? $store[ (string) $key ] : false;
	}
}
if ( ! function_exists( 'set_transient' ) ) {
	function set_transient( $key, $value, $expiration = 0 ): bool {
		unset( $expiration );
		if ( ! isset( $GLOBALS['handl_aicac_test_transients'] ) || ! is_array( $GLOBALS['handl_aicac_test_transients'] ) ) {
			$GLOBALS['handl_aicac_test_transients'] = array();
		}
		$GLOBALS['handl_aicac_test_transients'][ (string) $key ] = $value;
		return true;
	}
}
if ( ! function_exists( 'delete_transient' ) ) {
	function delete_transient( $key ): bool {
		if ( isset( $GLOBALS['handl_aicac_test_transients'] ) && is_array( $GLOBALS['handl_aicac_test_transients'] ) ) {
			unset( $GLOBALS['handl_aicac_test_transients'][ (string) $key ] );
		}
		return true;
	}
}

if ( ! function_exists( 'number_format_i18n' ) ) {
	function number_format_i18n( $number, $decimals = 0 ) {
		return number_format( (float) $number, (int) $decimals, '.', ',' );
	}
}

if ( ! function_exists( 'esc_attr' ) ) {
	function esc_attr( $text ): string {
		return htmlspecialchars( (string) $text, ENT_QUOTES, 'UTF-8' );
	}
}

if ( ! function_exists( 'esc_html__' ) ) {
	function esc_html__( $text, $domain = 'default' ): string {
		unset( $domain );
		return htmlspecialchars( (string) $text, ENT_QUOTES, 'UTF-8' );
	}
}

if ( ! defined( 'WEEK_IN_SECONDS' ) ) {
	define( 'WEEK_IN_SECONDS', 604800 );
}

if ( ! function_exists( 'wp_next_scheduled' ) ) {
	/**
	 * @param string $hook Hook.
	 * @param array  $args Args.
	 * @return int|false
	 */
	function wp_next_scheduled( $hook, $args = array() ) {
		unset( $args );
		$cron = $GLOBALS['handl_aicac_test_cron'] ?? array();
		return isset( $cron[ (string) $hook ] ) ? (int) $cron[ (string) $hook ] : false;
	}
}

if ( ! function_exists( 'wp_schedule_event' ) ) {
	/**
	 * @param int    $timestamp Timestamp.
	 * @param string $recurrence Recurrence.
	 * @param string $hook Hook.
	 * @param array  $args Args.
	 */
	function wp_schedule_event( $timestamp, $recurrence, $hook, $args = array() ): bool {
		unset( $recurrence, $args );
		if ( ! isset( $GLOBALS['handl_aicac_test_cron'] ) || ! is_array( $GLOBALS['handl_aicac_test_cron'] ) ) {
			$GLOBALS['handl_aicac_test_cron'] = array();
		}
		$GLOBALS['handl_aicac_test_cron'][ (string) $hook ] = (int) $timestamp;
		return true;
	}
}

if ( ! function_exists( 'wp_unschedule_event' ) ) {
	/**
	 * @param int    $timestamp Timestamp.
	 * @param string $hook Hook.
	 * @param array  $args Args.
	 */
	function wp_unschedule_event( $timestamp, $hook, $args = array() ): bool {
		unset( $timestamp, $args );
		if ( isset( $GLOBALS['handl_aicac_test_cron'][ (string) $hook ] ) ) {
			unset( $GLOBALS['handl_aicac_test_cron'][ (string) $hook ] );
		}
		return true;
	}
}

if ( ! function_exists( 'wp_clear_scheduled_hook' ) ) {
	function wp_clear_scheduled_hook( $hook, $args = array() ) {
		unset( $hook, $args );
		return true;
	}
}

if ( ! function_exists( 'apply_filters' ) ) {
	/**
	 * @param string $hook Hook name.
	 * @param mixed  $value Value.
	 * @return mixed
	 */
	function apply_filters( $hook, $value ) {
		$args = func_get_args();
		if ( isset( $GLOBALS['handl_aicac_test_filters'][ (string) $args[0] ] ) && is_callable( $GLOBALS['handl_aicac_test_filters'][ (string) $args[0] ] ) ) {
			return call_user_func_array( $GLOBALS['handl_aicac_test_filters'][ (string) $args[0] ], array_slice( $args, 1 ) );
		}
		return $value;
	}
}

if ( ! function_exists( 'wp_mail' ) ) {
	/**
	 * @param string|list<string> $to Recipients.
	 * @param string              $subject Subject.
	 * @param string              $message Body.
	 */
	function wp_mail( $to, $subject, $message, $headers = '', $attachments = array() ): bool {
		if ( isset( $GLOBALS['handl_aicac_wp_mail'] ) && is_callable( $GLOBALS['handl_aicac_wp_mail'] ) ) {
			$cb = new \ReflectionFunction( \Closure::fromCallable( $GLOBALS['handl_aicac_wp_mail'] ) );
			$n  = $cb->getNumberOfParameters();
			if ( $n >= 5 ) {
				return (bool) call_user_func( $GLOBALS['handl_aicac_wp_mail'], $to, $subject, $message, $headers, $attachments );
			}
			unset( $headers, $attachments );
			return (bool) call_user_func( $GLOBALS['handl_aicac_wp_mail'], $to, $subject, $message );
		}
		unset( $headers, $attachments );
		return true;
	}
}

if ( ! function_exists( 'wp_next_scheduled' ) ) {
	/**
	 * @param string $hook Hook.
	 * @return int|false
	 */
	function wp_next_scheduled( $hook ) {
		$cron = $GLOBALS['handl_aicac_test_cron'] ?? array();
		return isset( $cron[ (string) $hook ] ) ? (int) $cron[ (string) $hook ] : false;
	}
}

if ( ! function_exists( 'wp_schedule_event' ) ) {
	/**
	 * @param int    $timestamp Timestamp.
	 * @param string $recurrence Recurrence.
	 * @param string $hook Hook.
	 */
	function wp_schedule_event( $timestamp, $recurrence, $hook ): bool {
		unset( $recurrence );
		if ( ! isset( $GLOBALS['handl_aicac_test_cron'] ) || ! is_array( $GLOBALS['handl_aicac_test_cron'] ) ) {
			$GLOBALS['handl_aicac_test_cron'] = array();
		}
		$GLOBALS['handl_aicac_test_cron'][ (string) $hook ] = (int) $timestamp;
		return true;
	}
}

if ( ! function_exists( 'wp_unschedule_event' ) ) {
	/**
	 * @param int    $timestamp Timestamp.
	 * @param string $hook Hook.
	 */
	function wp_unschedule_event( $timestamp, $hook ): bool {
		unset( $timestamp );
		if ( isset( $GLOBALS['handl_aicac_test_cron'][ (string) $hook ] ) ) {
			unset( $GLOBALS['handl_aicac_test_cron'][ (string) $hook ] );
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
require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-budget.php';
require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-forecast.php';
require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-usage-trends.php';
require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-log-storage.php';
require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-anomaly.php';
require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-drift.php';
require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-analytics.php';
require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-email-template.php';
require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-alert-health.php';
require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-webhook-delivery-log.php';
require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-alerts.php';
require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-alert-snooze.php';
require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-weekly-report.php';
require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-monthly-report.php';
require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-governance-digest.php';

if ( ! defined( 'HANDL_AICAC_FILE' ) ) {
	define( 'HANDL_AICAC_FILE', HANDL_AICAC_DIR . '/handl-ai-connector-access-control.php' );
}
if ( ! defined( 'WP_PLUGIN_DIR' ) ) {
	define( 'WP_PLUGIN_DIR', sys_get_temp_dir() . '/handl-aicac-plugins' );
}
if ( ! function_exists( 'wp_normalize_path' ) ) {
	/**
	 * @param string $path Path.
	 */
	function wp_normalize_path( $path ): string {
		$path = str_replace( '\\', '/', (string) $path );
		$path = preg_replace( '|/+|', '/', $path ) ?? $path;
		return $path;
	}
}
if ( ! function_exists( 'get_current_user_id' ) ) {
	function get_current_user_id(): int {
		return isset( $GLOBALS['handl_aicac_test_user_id'] ) ? (int) $GLOBALS['handl_aicac_test_user_id'] : 0;
	}
}
if ( ! function_exists( 'get_user_meta' ) ) {
	/**
	 * @param int    $user_id User id.
	 * @param string $key     Meta key.
	 * @param bool   $single  Single.
	 * @return mixed
	 */
	function get_user_meta( $user_id, $key = '', $single = false ) {
		$store = $GLOBALS['handl_aicac_test_user_meta'] ?? array();
		$uid   = (string) (int) $user_id;
		$k     = (string) $key;
		if ( ! isset( $store[ $uid ] ) || ! is_array( $store[ $uid ] ) || ! array_key_exists( $k, $store[ $uid ] ) ) {
			return $single ? '' : array();
		}
		return $single ? $store[ $uid ][ $k ] : array( $store[ $uid ][ $k ] );
	}
}
if ( ! function_exists( 'update_user_meta' ) ) {
	/**
	 * @param int    $user_id User id.
	 * @param string $key     Meta key.
	 * @param mixed  $value   Value.
	 */
	function update_user_meta( $user_id, $key, $value, $prev = '' ): bool {
		unset( $prev );
		if ( ! isset( $GLOBALS['handl_aicac_test_user_meta'] ) || ! is_array( $GLOBALS['handl_aicac_test_user_meta'] ) ) {
			$GLOBALS['handl_aicac_test_user_meta'] = array();
		}
		$uid = (string) (int) $user_id;
		if ( ! isset( $GLOBALS['handl_aicac_test_user_meta'][ $uid ] ) || ! is_array( $GLOBALS['handl_aicac_test_user_meta'][ $uid ] ) ) {
			$GLOBALS['handl_aicac_test_user_meta'][ $uid ] = array();
		}
		$GLOBALS['handl_aicac_test_user_meta'][ $uid ][ (string) $key ] = $value;
		return true;
	}
}
if ( ! function_exists( 'delete_user_meta' ) ) {
	function delete_user_meta( $user_id, $key, $meta_value = '' ): bool {
		unset( $meta_value );
		$uid = (string) (int) $user_id;
		$k   = (string) $key;
		if ( isset( $GLOBALS['handl_aicac_test_user_meta'][ $uid ] ) && is_array( $GLOBALS['handl_aicac_test_user_meta'][ $uid ] ) ) {
			unset( $GLOBALS['handl_aicac_test_user_meta'][ $uid ][ $k ] );
		}
		return true;
	}
}
if ( ! function_exists( 'get_plugins' ) ) {
	/**
	 * @return array<string,array<string,mixed>>
	 */
	function get_plugins(): array {
		return array();
	}
}

require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-attribution.php';
require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-shadow-ai.php';
require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-keyscan.php';
require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-temp-allow.php';
require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-new-plugin.php';
require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-quiet-hours.php';
require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-policy.php';
require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-policy-simulator.php';
require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-policy-checks.php';
require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-onboarding.php';
require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-whats-new.php';
require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-leads.php';
require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-policy-transfer.php';
require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-presets.php';
require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-policy-packs.php';
require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-policy-snapshots.php';
require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-audit-export.php';
require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-audit-evidence.php';
require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-plugin-profile.php';
require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-graduate.php';
require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-differentiator-messaging.php';
require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-plugin.php';
require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-network-admin.php';
require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-site-health.php';
require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-rest.php';
require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-dashboard-widget.php';
