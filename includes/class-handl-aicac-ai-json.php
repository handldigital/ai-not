<?php
/**
 * AICAC-AI-TXT (#309): opt-in /.well-known/ai.json rewrite.
 *
 * Serves the same redacted disclosure dataset as the public page.
 * Zero option writes on read.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Pretty-permalink front door for the machine-readable disclosure.
 */
final class Ai_Json {

	public const QUERY_VAR = 'handl_aicac_ai_json';

	public const PATH = '/.well-known/ai.json';

	public const CACHE_MAX_AGE = 3600;

	private static ?Ai_Json $instance = null;

	public static function instance(): Ai_Json {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}

		return self::$instance;
	}

	public static function reset_for_tests(): void {
		self::$instance = null;
	}

	public function init(): void {
		add_action( 'init', array( $this, 'register_rewrite' ) );
		add_filter( 'query_vars', array( $this, 'query_vars' ) );
		add_action( 'template_redirect', array( $this, 'maybe_serve' ), 0 );
		add_action( 'update_option_' . Plugin::OPTION_KEY, array( $this, 'maybe_flush_rewrites' ), 10, 2 );
	}

	public function register_rewrite(): void {
		if ( ! function_exists( 'add_rewrite_rule' ) ) {
			return;
		}
		add_rewrite_rule( '^\.well-known/ai\.json$', 'index.php?' . self::QUERY_VAR . '=1', 'top' );
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
		$old_on = Disclosure::is_json_enabled( is_array( $old ) ? $old : array() );
		$new_on = Disclosure::is_json_enabled( is_array( $value ) ? $value : array() );
		if ( $old_on === $new_on ) {
			return;
		}
		if ( function_exists( 'flush_rewrite_rules' ) ) {
			flush_rewrite_rules( false );
		}
	}

	public static function public_url(): string {
		if ( function_exists( 'home_url' ) ) {
			return home_url( self::PATH );
		}

		return self::PATH;
	}

	public static function rest_mirror_url(): string {
		$path = Rest::NAMESPACE . '/disclosure';
		if ( function_exists( 'rest_url' ) ) {
			return rest_url( $path );
		}

		return '/wp-json/' . $path;
	}

	/**
	 * @return array<string,string>
	 */
	public static function cache_headers(): array {
		return array(
			'Content-Type'  => 'application/json; charset=UTF-8',
			'Cache-Control' => 'public, max-age=' . self::CACHE_MAX_AGE,
		);
	}

	public static function is_requested(): bool {
		if ( function_exists( 'get_query_var' ) && (string) get_query_var( self::QUERY_VAR ) === '1' ) {
			return true;
		}

		return false;
	}

	/**
	 * @param array<string,mixed>|null $policy
	 * @param array<int,mixed>|null    $log
	 * @return array{status:int,body:string,headers:array<string,string>}
	 */
	public static function respond( ?array $policy = null, ?array $log = null, ?bool $freeze = null ): array {
		if ( null === $policy ) {
			$policy = class_exists( Policy::class ) ? Policy::get_policy() : array();
		}
		$policy = is_array( $policy ) ? $policy : array();
		if ( ! Disclosure::is_json_enabled( $policy ) ) {
			return array(
				'status'  => 404,
				'body'    => '',
				'headers' => array(
					'Cache-Control' => 'private, max-age=0',
				),
			);
		}
		if ( null === $log ) {
			$log = class_exists( Disclosure::class ) ? Disclosure::public_log_readonly() : array();
		}
		$log = is_array( $log ) ? $log : array();
		if ( null === $freeze ) {
			$freeze = class_exists( Freeze::class ) && Freeze::is_active();
		}

		$document = Disclosure::build_machine_document( $policy, $log, (bool) $freeze );

		return array(
			'status'  => 200,
			'body'    => Disclosure::encode_machine_document( $document ),
			'headers' => self::cache_headers(),
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
	 * @param array{status:int,body:string,headers:array<string,string>} $out
	 */
	public static function emit( array $out ): void {
		if ( function_exists( 'status_header' ) ) {
			status_header( (int) $out['status'] );
		}
		$phpunit = defined( 'HANDL_AICAC_PHPUNIT' ) && HANDL_AICAC_PHPUNIT;
		if ( ! $phpunit && isset( $out['headers'] ) && is_array( $out['headers'] ) ) {
			foreach ( $out['headers'] as $name => $value ) {
				header( $name . ': ' . $value );
			}
		}
		if ( $phpunit ) {
			$GLOBALS['handl_aicac_test_ai_json_emitted'] = $out;
			return;
		}
		echo (string) ( $out['body'] ?? '' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- application/json body.
		exit;
	}
}
