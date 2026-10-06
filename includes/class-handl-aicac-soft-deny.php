<?php
/**
 * AICAC-SOFT-DENY (#279): per-plugin deny response mode.
 *
 * Default Hard block keeps today's WP_Error path. Soft block still records a
 * deny (storm / alerts / counters unchanged) but returns a parseable empty
 * success body on the AI Client wp_remote_* hop so callers degrade to "no AI
 * output" instead of fataling.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Soft-deny mode resolution + HTTP stub responses.
 */
final class Soft_Deny {

	public const MODE_HARD = 'hard';
	public const MODE_SOFT = 'soft';

	/** Activity outcome token when a soft stub was armed. */
	public const OUTCOME = 'soft-blocked';

	public const POLICY_KEY = 'plugin_deny_modes';

	/**
	 * Request-local arm: family + operation awaiting one stubbed HTTP response.
	 *
	 * @var array{family:string,operation:string}|null
	 */
	private static $armed = null;

	/** @var self|null */
	private static $instance = null;

	public static function instance(): self {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	public function init(): void {
		// Priority 8: before MCP (9) and Shadow (10) so an armed soft stub wins.
		add_filter( 'pre_http_request', array( $this, 'maybe_stub' ), 8, 3 );
	}

	/**
	 * @param mixed $raw
	 */
	public static function sanitize_mode( $raw ): string {
		$mode = sanitize_key( (string) $raw );
		if ( self::MODE_SOFT === $mode ) {
			return self::MODE_SOFT;
		}

		return self::MODE_HARD;
	}

	/**
	 * Per-plugin map. Hard (default) is omitted so untouched saves stay identical.
	 *
	 * @param mixed $raw
	 * @return array<string,string> plugin => soft
	 */
	public static function sanitize_plugin_modes( $raw ): array {
		if ( ! is_array( $raw ) ) {
			return array();
		}
		$out = array();
		foreach ( $raw as $plugin => $mode ) {
			$plugin = Plugin_Profile::sanitize_plugin( (string) $plugin );
			if ( '' === $plugin ) {
				continue;
			}
			if ( self::MODE_SOFT !== self::sanitize_mode( $mode ) ) {
				continue;
			}
			$out[ $plugin ] = self::MODE_SOFT;
		}

		return $out;
	}

	/**
	 * @param array<string,mixed> $policy
	 */
	public static function mode_for_plugin( array $policy, ?string $plugin ): string {
		$plugin = Plugin_Profile::sanitize_plugin( (string) $plugin );
		if ( '' === $plugin ) {
			return self::MODE_HARD;
		}
		$map = self::sanitize_plugin_modes( $policy[ self::POLICY_KEY ] ?? array() );

		return isset( $map[ $plugin ] ) ? self::MODE_SOFT : self::MODE_HARD;
	}

	/**
	 * @param array<string,mixed> $policy
	 */
	public static function is_soft( array $policy, ?string $plugin ): bool {
		return self::MODE_SOFT === self::mode_for_plugin( $policy, $plugin );
	}

	/**
	 * Soft stub only for generating ops — support checks already return false
	 * without WP_Error when prevent_prompt is true.
	 */
	public static function applies_to_operation( string $operation ): bool {
		if ( '' === $operation ) {
			return false;
		}

		return 0 === strpos( $operation, 'generate_' )
			|| 0 === strpos( $operation, 'convert_text_to_speech' );
	}

	/**
	 * Merge posted On-deny modes onto the stored map (keep unposted plugins).
	 *
	 * @param array<string,string>      $stored
	 * @param array<string,mixed>|null  $posted
	 * @return array<string,string>
	 */
	public static function merge_posted_modes( array $stored, $posted ): array {
		$base = self::sanitize_plugin_modes( $stored );
		if ( ! is_array( $posted ) ) {
			return $base;
		}
		foreach ( $posted as $basename => $raw ) {
			$basename = Plugin_Profile::sanitize_plugin( (string) $basename );
			if ( '' === $basename ) {
				continue;
			}
			if ( self::MODE_SOFT === self::sanitize_mode( $raw ) ) {
				$base[ $basename ] = self::MODE_SOFT;
			} else {
				unset( $base[ $basename ] );
			}
		}

		return $base;
	}

	/**
	 * When a deny would hard-block a generating call, optionally arm an HTTP stub
	 * and tag the Activity row. Returns true when the caller should NOT prevent.
	 *
	 * @param array<string,mixed> $event  Mutated with outcome when soft.
	 * @param array<string,mixed> $policy
	 */
	public static function maybe_arm_from_deny(
		bool $prevent,
		array &$event,
		array $policy,
		?string $plugin,
		string $operation,
		string $family
	): bool {
		if ( ! $prevent || ! empty( $policy['audit_only'] ) ) {
			return false;
		}
		if ( ! self::is_soft( $policy, $plugin ) ) {
			return false;
		}
		if ( ! self::applies_to_operation( $operation ) ) {
			return false;
		}

		$event['outcome']  = self::OUTCOME;
		$event['decision'] = 'deny';
		self::arm( $family, $operation );

		return true;
	}

	public static function arm( string $family, string $operation ): void {
		$resolved = sanitize_key( $family );
		if ( '' === $resolved || Operations::FAMILY_UNKNOWN === $resolved ) {
			$resolved = Operations::family_from_operation( $operation );
		}
		self::$armed = array(
			'family'    => $resolved,
			'operation' => $operation,
		);
	}

	public static function disarm(): void {
		self::$armed = null;
	}

	public static function is_armed(): bool {
		return null !== self::$armed;
	}

	/**
	 * @return array{family:string,operation:string}|null
	 */
	public static function armed_state(): ?array {
		return self::$armed;
	}

	/**
	 * Reset request-local arm (unit tests).
	 */
	public static function reset_for_tests(): void {
		self::$armed = null;
	}

	/**
	 * @param false|array|\WP_Error $preempt
	 * @param array<string,mixed>   $args
	 * @param string                $url
	 * @return false|array|\WP_Error
	 */
	public function maybe_stub( $preempt, $args, $url ) {
		unset( $args );
		if ( null === self::$armed ) {
			return $preempt;
		}
		$family    = (string) ( self::$armed['family'] ?? Operations::FAMILY_UNKNOWN );
		$operation = (string) ( self::$armed['operation'] ?? '' );
		self::disarm();

		return self::stub_http_response( $family, is_string( $url ) ? $url : '', $operation );
	}

	/**
	 * Well-formed empty success for wp_remote_* (AI Client provider parsers).
	 *
	 * @return array{headers:array<string,string>,body:string,response:array{code:int,message:string},cookies:array,filename:null}
	 */
	public static function stub_http_response( string $family, string $url = '', string $operation = '' ): array {
		$body = self::stub_body_for_family( $family, $url, $operation );

		return array(
			'headers'  => array(
				'content-type' => 'application/json; charset=utf-8',
			),
			'body'     => $body,
			'response' => array(
				'code'    => 200,
				'message' => 'OK',
			),
			'cookies'  => array(),
			'filename' => null,
		);
	}

	/**
	 * Empty / stub JSON shaped per capability family.
	 */
	public static function stub_body_for_family( string $family, string $url = '', string $operation = '' ): string {
		$family = sanitize_key( $family );
		$host   = '';
		if ( '' !== $url ) {
			$parsed = function_exists( 'wp_parse_url' ) ? wp_parse_url( $url ) : parse_url( $url );
			if ( is_array( $parsed ) && ! empty( $parsed['host'] ) ) {
				$host = strtolower( (string) $parsed['host'] );
			}
		}

		switch ( $family ) {
			case Operations::FAMILY_IMAGE:
				$payload = array(
					'created' => 0,
					'data'    => array(),
				);
				break;

			case Operations::FAMILY_SPEECH:
			case Operations::FAMILY_TTS:
				// OpenAI audio JSON envelope; binary audio endpoints still get JSON
				// so callers that json_decode do not notice.
				$payload = array(
					'text' => '',
				);
				break;

			case Operations::FAMILY_VIDEO:
				$payload = array(
					'data' => array(),
				);
				break;

			case Operations::FAMILY_TEXT:
			default:
				$payload = self::text_stub_payload( $host, $operation );
				break;
		}

		$json = wp_json_encode( $payload );
		if ( ! is_string( $json ) || '' === $json ) {
			return '{}';
		}

		return $json;
	}

	/**
	 * @return array<string,mixed>
	 */
	private static function text_stub_payload( string $host, string $operation ): array {
		unset( $operation );

		// Anthropic Messages API.
		if ( false !== strpos( $host, 'anthropic.com' ) ) {
			return array(
				'id'           => 'msg_handl_soft_deny',
				'type'         => 'message',
				'role'         => 'assistant',
				'content'      => array(),
				'model'        => 'handl-soft-deny',
				'stop_reason'  => 'end_turn',
				'usage'        => array(
					'input_tokens'  => 0,
					'output_tokens' => 0,
				),
			);
		}

		// Google Generative Language.
		if ( false !== strpos( $host, 'googleapis.com' ) ) {
			return array(
				'candidates' => array(
					array(
						'content'      => array(
							'parts' => array(
								array( 'text' => '' ),
							),
							'role'  => 'model',
						),
						'finishReason' => 'STOP',
					),
				),
			);
		}

		// OpenAI-compatible chat.completion (default + most providers).
		return array(
			'id'      => 'chatcmpl-handl-soft-deny',
			'object'  => 'chat.completion',
			'created' => 0,
			'model'   => 'handl-soft-deny',
			'choices' => array(
				array(
					'index'         => 0,
					'message'       => array(
						'role'    => 'assistant',
						'content' => '',
					),
					'finish_reason' => 'stop',
				),
			),
			'usage'   => array(
				'prompt_tokens'     => 0,
				'completion_tokens' => 0,
				'total_tokens'      => 0,
			),
		);
	}

	/**
	 * @param array<string,mixed> $row
	 */
	public static function outcome_from_row( array $row ): string {
		$raw = isset( $row['outcome'] ) ? sanitize_key( (string) $row['outcome'] ) : '';

		return self::OUTCOME === $raw ? self::OUTCOME : '';
	}
}
