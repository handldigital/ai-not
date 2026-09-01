<?php
/**
 * Shadow-AI detector: observe (and optionally block) direct HTTP to known AI providers (F6 / AICAC-23).
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Flags plugins that call known AI provider hosts over WordPress HTTP
 * without going through the AI Client gate we control.
 *
 * Default is observation only. When `shadow_block_enabled` is on, non-excepted
 * curated-host calls short-circuit with WP_Error (never reach the network).
 * Fail-open: any internal error returns the original $preempt unchanged.
 *
 * STORAGE: writes via Policy::append_log_event into the SAME ring buffer as
 * AI Client rows. Chatty-host collapse lives in that append path. This class
 * tallies in-request HTTP calls and flushes once on shutdown so `count` means
 * *calls* (same unit as AI Client rows), not page loads.
 *
 * Exclusion: traffic whose stack already includes the core AI Client HTTP
 * path is not "shadow" — that path is governed by wp_ai_client_prevent_prompt.
 */
final class Shadow_AI {
	private static ?Shadow_AI $instance = null;

	/**
	 * In-request tally + first observation per collapse key.
	 * Avoids N update_option writes in one request; flushed once on shutdown.
	 *
	 * @var array<string,array{tally:int,event:array<string,mixed>}>
	 */
	private static array $pending = array();

	/** Whether shutdown flush is registered for this request. */
	private static bool $flush_registered = false;

	/** WP_Error code when a direct AI host call is blocked. */
	public const BLOCK_ERROR_CODE = 'handl_aicac_shadow_blocked';

	public static function instance(): Shadow_AI {
		if ( null === self::$instance ) {
			self::$instance = new Shadow_AI();
		}
		return self::$instance;
	}

	public function init(): void {
		add_filter( 'pre_http_request', array( $this, 'maybe_observe' ), 10, 3 );
	}

	/**
	 * @param false|array|\WP_Error $preempt Whether to short-circuit the request.
	 * @param array<string,mixed>   $args    Request arguments (unused for body/auth).
	 * @param string                $url     Request URL.
	 * @return false|array|\WP_Error
	 */
	public function maybe_observe( $preempt, $args, $url ) {
		// Fail open: never fatal site-wide HTTP because of this plugin.
		try {
			return self::handle_http_request( $preempt, $args, $url );
		} catch ( \Throwable $e ) { // phpcs:ignore Generic.CodeAnalysis.EmptyStatement.DetectedCatch -- fail open.
			return $preempt;
		}
	}

	/**
	 * Core path (throwable for tests / fail-open wrapper).
	 *
	 * @param false|array|\WP_Error $preempt
	 * @param array<string,mixed>   $args
	 * @param string                $url
	 * @return false|array|\WP_Error
	 */
	public static function handle_http_request( $preempt, $args, $url ) {
		if ( class_exists( Canary::class ) ) {
			$canary_args = is_array( $args ) ? $args : array();
			$canary_url  = is_string( $url ) ? $url : '';
			$tripped     = Canary::intercept( $canary_args, $canary_url );
			if ( null !== $tripped ) {
				return $tripped;
			}
		}

		unset( $args );

		if ( ! is_string( $url ) || '' === $url ) {
			return $preempt;
		}

		$parsed = wp_parse_url( $url );
		if ( ! is_array( $parsed ) || empty( $parsed['host'] ) ) {
			return $preempt;
		}

		$host = strtolower( (string) $parsed['host'] );
		$host = rtrim( $host, '.' );

		$provider = self::match_provider( $host );
		if ( null === $provider ) {
			return $preempt;
		}

		// AI Client / php-ai-client stack ⇒ already on the governed path. Not shadow.
		if ( self::stack_is_ai_client() ) {
			return $preempt;
		}

		$policy       = Policy::get_policy();
		$block_on     = ! empty( $policy['shadow_block_enabled'] );
		$logging_on   = ! empty( $policy['log_enabled'] ) || ! empty( $policy['audit_only'] );
		$attrib       = Attribution::resolve_from_backtrace();
		$plugin       = is_string( $attrib['plugin'] ?? null ) ? (string) $attrib['plugin'] : '';
		$file         = is_string( $attrib['file'] ?? null ) ? (string) $attrib['file'] : '';
		$is_exception = self::plugin_is_exception( $plugin, $policy );

		// Pure decision for unit tests and logging labels.
		$verdict = self::decide( $block_on, $is_exception );

		// Logging gate: observe/exception rows need logging or learn mode.
		// Denied rows also use the same gate (consistent with append_log_event).
		if ( $logging_on ) {
			self::queue_log_event(
				$policy,
				$attrib,
				$plugin,
				$host,
				$provider,
				$parsed,
				$verdict
			);
		}

		if ( 'deny' === $verdict['decision'] ) {
			return self::block_error();
		}

		return $preempt;
	}

	/**
	 * Pure verdict for a matched non-AI-Client curated-host call.
	 *
	 * @return array{decision:string,denial_reason:string,shadow_exception:bool}
	 */
	public static function decide( bool $block_enabled, bool $is_exception ): array {
		if ( ! $block_enabled ) {
			return array(
				'decision'         => 'observe',
				'denial_reason'    => '',
				'shadow_exception' => false,
			);
		}

		if ( $is_exception ) {
			return array(
				'decision'         => 'allow',
				'denial_reason'    => 'shadow_block_exception',
				'shadow_exception' => true,
			);
		}

		return array(
			'decision'         => 'deny',
			'denial_reason'    => 'shadow_block',
			'shadow_exception' => false,
		);
	}

	/**
	 * @param array<string,mixed> $policy
	 */
	public static function plugin_is_exception( string $plugin_basename, array $policy ): bool {
		if ( '' === $plugin_basename ) {
			return false;
		}
		$exceptions = self::get_block_exceptions( $policy );
		return in_array( $plugin_basename, $exceptions, true );
	}

	/**
	 * @param array<string,mixed> $policy
	 * @return list<string>
	 */
	public static function get_block_exceptions( array $policy ): array {
		$raw = $policy['shadow_block_exceptions'] ?? array();
		if ( ! is_array( $raw ) ) {
			return array();
		}
		$out = array();
		foreach ( $raw as $basename ) {
			$basename = sanitize_text_field( (string) $basename );
			if ( '' !== $basename ) {
				$out[] = $basename;
			}
		}
		return array_values( array_unique( $out ) );
	}

	/**
	 * @return \WP_Error
	 */
	public static function block_error() {
		$message = __(
			'HandL AI Connector Access Control blocked a direct connection to an AI provider outside the WordPress AI Client.',
			'handl-ai-connector-access-control'
		);
		if ( class_exists( 'WP_Error', false ) ) {
			return new \WP_Error( self::BLOCK_ERROR_CODE, $message );
		}
		// Unit-test bootstrap WP_Error.
		return new \WP_Error( self::BLOCK_ERROR_CODE, $message );
	}

	/**
	 * @param array<string,mixed>               $policy
	 * @param array<string,mixed>               $attrib
	 * @param array{decision:string,denial_reason:string,shadow_exception:bool} $verdict
	 * @param array<string,mixed>               $parsed
	 */
	private static function queue_log_event(
		array $policy,
		array $attrib,
		string $plugin,
		string $host,
		string $provider,
		array $parsed,
		array $verdict
	): void {
		$file       = is_string( $attrib['file'] ?? null ) ? (string) $attrib['file'] : '';
		$dedupe_key = self::collapse_key( $plugin, $host, $file ) . '|' . (string) $verdict['decision'];

		$path = isset( $parsed['path'] ) ? (string) $parsed['path'] : '/';
		$path = '' !== $path ? $path : '/';

		if ( isset( self::$pending[ $dedupe_key ] ) ) {
			self::$pending[ $dedupe_key ]['tally']++;
			return;
		}

		$event = array(
			'channel'         => 'direct_http',
			'ts'              => time(),
			'plugin'          => '' !== $plugin ? $plugin : null,
			'file'            => $attrib['file'] ?? null,
			'caller'          => $attrib['method'] ?? null,
			'host'            => $host,
			'shadow_provider' => $provider,
			'provider'        => $provider,
			'decision'        => $verdict['decision'],
			'operation'       => 'direct_http',
			'uri'             => $path,
			'user_id'         => function_exists( 'get_current_user_id' ) ? get_current_user_id() : 0,
			'count'           => 1,
		);

		if ( '' !== (string) $verdict['denial_reason'] ) {
			$event['denial_reason'] = (string) $verdict['denial_reason'];
		}
		if ( ! empty( $verdict['shadow_exception'] ) ) {
			$event['shadow_exception'] = true;
		}
		if ( ! empty( $policy['audit_only'] ) ) {
			$event['audit_only'] = true;
		}

		self::$pending[ $dedupe_key ] = array(
			'tally' => 1,
			'event' => $event,
		);

		if ( ! self::$flush_registered ) {
			self::$flush_registered = true;
			add_action( 'shutdown', array( self::class, 'flush_pending' ), 0 );
			register_shutdown_function( array( self::class, 'flush_pending' ) );
		}
	}

	/**
	 * Collapse / de-dupe key. Attributed: plugin|host. Unattributed: __unknown__|host|file.
	 */
	public static function collapse_key( string $plugin, string $host, string $file = '' ): string {
		if ( '' !== $plugin ) {
			return $plugin . '|' . $host;
		}
		return '__unknown__|' . $host . '|' . $file;
	}

	/**
	 * Write pending in-request tallies once. count = number of HTTP calls this request.
	 * Public for tests / emergency flush; normally hooked on shutdown.
	 */
	public static function flush_pending(): void {
		if ( empty( self::$pending ) ) {
			return;
		}

		$batch = self::$pending;
		self::$pending = array();

		foreach ( $batch as $item ) {
			$event          = $item['event'];
			$tally          = isset( $item['tally'] ) ? (int) $item['tally'] : 1;
			$event['count'] = $tally > 0 ? $tally : 1;
			if ( $tally > 1 ) {
				$first = isset( $event['ts'] ) ? (int) $event['ts'] : 0;
				if ( $first > 0 && ! isset( $event['first_ts'] ) ) {
					$event['first_ts'] = $first;
				}
			}
			if ( ! isset( $event['ts'] ) || (int) $event['ts'] <= 0 ) {
				$event['ts'] = time();
			}
			Policy::append_log_event( $event );
		}
	}

	/**
	 * Reset in-request state (unit tests).
	 */
	public static function reset_pending_for_tests(): void {
		self::$pending          = array();
		self::$flush_registered = false;
	}

	/**
	 * Curated host → provider id map. Extensible list, not an inventory of the internet.
	 *
	 * @return string|null Provider id or null if not a known AI host.
	 */
	public static function match_provider( string $host ): ?string {
		$host = strtolower( rtrim( $host, '.' ) );
		if ( '' === $host ) {
			return null;
		}

		$map = array(
			'api.openai.com'                    => 'openai',
			'api.anthropic.com'                 => 'anthropic',
			'generativelanguage.googleapis.com' => 'google',
			'api.cohere.ai'                     => 'cohere',
			'api.cohere.com'                    => 'cohere',
			'api.mistral.ai'                    => 'mistral',
			'api.groq.com'                      => 'groq',
			'api.together.xyz'                  => 'together',
			'api.fireworks.ai'                  => 'fireworks',
			'api.perplexity.ai'                 => 'perplexity',
			'api.x.ai'                          => 'xai',
			'api.deepseek.com'                  => 'deepseek',
			'openrouter.ai'                     => 'openrouter',
		);

		foreach ( $map as $base => $id ) {
			if ( $host === $base || self::host_ends_with( $host, '.' . $base ) ) {
				return $id;
			}
		}

		return null;
	}

	/**
	 * Whether the current PHP stack already includes the core AI Client HTTP path.
	 * Those requests are governed by our prevent-prompt filter — not shadow traffic.
	 */
	public static function stack_is_ai_client(): bool {
		$trace = ( new \Exception() )->getTrace();
		if ( count( $trace ) > 80 ) {
			$trace = array_slice( $trace, 0, 80 );
		}

		$ai_client_dir     = function_exists( 'wp_normalize_path' )
			? wp_normalize_path( ABSPATH . ( defined( 'WPINC' ) ? WPINC : 'wp-includes' ) . '/ai-client' )
			: ABSPATH . 'wp-includes/ai-client';
		$php_ai_client_dir = function_exists( 'wp_normalize_path' )
			? wp_normalize_path( ABSPATH . ( defined( 'WPINC' ) ? WPINC : 'wp-includes' ) . '/php-ai-client' )
			: ABSPATH . 'wp-includes/php-ai-client';

		foreach ( $trace as $frame ) {
			if ( empty( $frame['file'] ) ) {
				$class = isset( $frame['class'] ) ? (string) $frame['class'] : '';
				if ( self::class_is_ai_client( $class ) ) {
					return true;
				}
				continue;
			}

			$file = function_exists( 'wp_normalize_path' )
				? wp_normalize_path( (string) $frame['file'] )
				: (string) $frame['file'];

			if ( self::path_is_under( $file, $ai_client_dir ) || self::path_is_under( $file, $php_ai_client_dir ) ) {
				return true;
			}

			$class = isset( $frame['class'] ) ? (string) $frame['class'] : '';
			if ( self::class_is_ai_client( $class ) ) {
				return true;
			}
		}

		return false;
	}

	private static function class_is_ai_client( string $class ): bool {
		if ( '' === $class ) {
			return false;
		}
		if ( 0 === strpos( $class, 'WP_AI_Client' ) || 0 === strpos( $class, 'WP_Ai_Client' ) ) {
			return true;
		}
		if ( false !== strpos( $class, 'WP_AI_Client' ) ) {
			return true;
		}
		if ( 0 === strpos( $class, 'WordPress\\AiClient\\' ) || 0 === strpos( $class, 'WordPress\\AI_Client\\' ) ) {
			return true;
		}
		return false;
	}

	private static function path_is_under( string $file, string $dir ): bool {
		$dir = rtrim( $dir, '/' );
		return $file === $dir || 0 === strpos( $file, $dir . '/' );
	}

	private static function host_ends_with( string $host, string $suffix ): bool {
		$len = strlen( $suffix );
		if ( $len === 0 || strlen( $host ) < $len ) {
			return false;
		}
		return substr( $host, -$len ) === $suffix;
	}
}
