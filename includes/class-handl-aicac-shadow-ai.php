<?php
/**
 * Shadow-AI detector: observe direct HTTP to known AI providers (F6).
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
 * Observation only in v1 — never blocks, mutates, or reads request bodies /
 * Authorization headers. Retains host + path-only (query stripped) so the
 * coverage tile can later widen its denominator (F5) without a second %.
 *
 * STORAGE: writes via Policy::append_log_event into the SAME ring buffer as
 * AI Client rows (board 2026-07-31). Chatty-host collapse lives in that append
 * path. This class tallies in-request HTTP calls and flushes once on shutdown
 * so `count` means *calls* (same unit as AI Client rows), not page loads.
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

	public static function instance(): Shadow_AI {
		if ( null === self::$instance ) {
			self::$instance = new Shadow_AI();
		}
		return self::$instance;
	}

	public function init(): void {
		// Observe only. Always return $preempt unchanged.
		add_filter( 'pre_http_request', array( $this, 'maybe_observe' ), 10, 3 );
	}

	/**
	 * @param false|array|\WP_Error $preempt Whether to short-circuit the request.
	 * @param array<string,mixed>   $args    Request arguments (unused for body/auth).
	 * @param string                $url     Request URL.
	 * @return false|array|\WP_Error Unchanged $preempt.
	 */
	public function maybe_observe( $preempt, $args, $url ) {
		// Never alter the request path — observation only.
		unset( $args );

		$policy = Policy::get_policy();
		// Same observability gate as other retained rows: log_enabled OR learn mode.
		// Action gates ≠ observation gates — learn mode must still see outside traffic.
		if ( empty( $policy['log_enabled'] ) && empty( $policy['audit_only'] ) ) {
			return $preempt;
		}

		if ( ! is_string( $url ) || '' === $url ) {
			return $preempt;
		}

		$parsed = wp_parse_url( $url );
		if ( ! is_array( $parsed ) || empty( $parsed['host'] ) ) {
			return $preempt;
		}

		$host = strtolower( (string) $parsed['host'] );
		// Strip trailing dots / normalize.
		$host = rtrim( $host, '.' );

		$provider = self::match_provider( $host );
		if ( null === $provider ) {
			return $preempt;
		}

		// AI Client / php-ai-client stack ⇒ already on the governed path. Not shadow.
		if ( self::stack_is_ai_client() ) {
			return $preempt;
		}

		$attrib = Attribution::resolve_from_backtrace();
		$plugin = is_string( $attrib['plugin'] ?? null ) ? (string) $attrib['plugin'] : '';
		$file   = is_string( $attrib['file'] ?? null ) ? (string) $attrib['file'] : '';
		// Key matches Policy collapse: attributed → plugin|host; unattributed → file|host
		// so distinct unknown callers do not merge into one misleading row.
		$dedupe_key = self::collapse_key( $plugin, $host, $file );

		$path = isset( $parsed['path'] ) ? (string) $parsed['path'] : '/';
		// Privacy: path only, never query string (may carry keys / tokens in bad clients).
		$path = '' !== $path ? $path : '/';

		if ( isset( self::$pending[ $dedupe_key ] ) ) {
			// Same key again this request: tally another *call* (not a page load).
			self::$pending[ $dedupe_key ]['tally']++;
			return $preempt;
		}

		$event = array(
			'channel'         => 'direct_http',
			'ts'              => time(),
			'plugin'          => '' !== $plugin ? $plugin : null,
			'file'            => $attrib['file'] ?? null,
			'caller'          => $attrib['method'] ?? null,
			'host'            => $host,
			'shadow_provider' => $provider,
			// Also surface under provider for existing filters/UI columns.
			'provider'        => $provider,
			'decision'        => 'observe',
			// Stable operation label so Audit filters can select "direct HTTP" rows.
			'operation'       => 'direct_http',
			// Path-only (no query). Reuses the log column named uri without expanding retention.
			'uri'             => $path,
			'user_id'         => get_current_user_id(),
			// Unit: HTTP *calls* (Lisa gate-1 / board preference). Flushed tally may raise this.
			'count'           => 1,
		);

		if ( ! empty( $policy['audit_only'] ) ) {
			$event['audit_only'] = true;
		}

		self::$pending[ $dedupe_key ] = array(
			'tally' => 1,
			'event' => $event,
		);

		if ( ! self::$flush_registered ) {
			self::$flush_registered = true;
			// Priority 0: flush before other shutdown work that might exit early.
			add_action( 'shutdown', array( self::class, 'flush_pending' ), 0 );
			// Floor: catch calls observed *during* later shutdown hooks (priority > 0).
			// WP action order alone drops those — $flush_registered stays true so the
			// action is never re-added, and priority 0 has already run. PHP's
			// register_shutdown_function runs after every WP shutdown action;
			// flush_pending is idempotent on empty $pending (no double-write).
			register_shutdown_function( array( self::class, 'flush_pending' ) );
		}

		return $preempt;
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
		// Clear first so a re-entrant observe during write cannot double-count.
		self::$pending = array();

		foreach ( $batch as $item ) {
			$event          = $item['event'];
			$tally          = isset( $item['tally'] ) ? (int) $item['tally'] : 1;
			$event['count'] = $tally > 0 ? $tally : 1;
			// Multi-call first flush: first observation ts is already on the event;
			// copy to first_ts before overwriting so the row has a real span (Δ5).
			if ( $tally > 1 ) {
				$first = isset( $event['ts'] ) ? (int) $event['ts'] : 0;
				if ( $first > 0 && ! isset( $event['first_ts'] ) ) {
					$event['first_ts'] = $first;
				}
			}
			// ts is last call time in this request batch (first observation kept its fields).
			$event['ts'] = time();
			Policy::append_log_event( $event );
		}
	}

	/**
	 * Curated host → provider id map. Extensible list, not an inventory of the internet.
	 *
	 * Matching is suffix-safe on known API hostnames (host === base OR host ends with ".base").
	 *
	 * @return string|null Provider id or null if not a known AI host.
	 */
	public static function match_provider( string $host ): ?string {
		$host = strtolower( rtrim( $host, '.' ) );
		if ( '' === $host ) {
			return null;
		}

		// Host suffix (or exact) => provider id.
		// Prefer more-specific hosts first when two could match (none currently nest).
		$map = array(
			'api.openai.com'                   => 'openai',
			'api.anthropic.com'                => 'anthropic',
			'generativelanguage.googleapis.com'=> 'google',
			'api.cohere.ai'                    => 'cohere',
			'api.cohere.com'                   => 'cohere',
			'api.mistral.ai'                   => 'mistral',
			'api.groq.com'                     => 'groq',
			'api.together.xyz'                 => 'together',
			'api.fireworks.ai'                 => 'fireworks',
			'api.perplexity.ai'                => 'perplexity',
			'api.x.ai'                         => 'xai',
			'api.deepseek.com'                 => 'deepseek',
			'openrouter.ai'                    => 'openrouter',
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
		// Cap depth; HTTP wrappers can be deep.
		if ( count( $trace ) > 80 ) {
			$trace = array_slice( $trace, 0, 80 );
		}

		$ai_client_dir     = wp_normalize_path( ABSPATH . WPINC . '/ai-client' );
		$php_ai_client_dir = wp_normalize_path( ABSPATH . WPINC . '/php-ai-client' );

		foreach ( $trace as $frame ) {
			if ( empty( $frame['file'] ) ) {
				// Class-only frames (no file) — still check class name.
				$class = isset( $frame['class'] ) ? (string) $frame['class'] : '';
				if ( self::class_is_ai_client( $class ) ) {
					return true;
				}
				continue;
			}

			$file = wp_normalize_path( (string) $frame['file'] );

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
		// Core WP AI Client + WordPress\AiClient namespaces.
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
