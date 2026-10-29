<?php
/**
 * AICAC-CARPOOL (#486): serve repeat identical ALLOWED asks from a TTL cache.
 *
 * Acting half of Déjà vu (#453). Per-connector opt-in (off by default) on the
 * Déjà vu screen. Byte-identical asks (Dejavu fingerprint + prompt hash) that
 * hit within TTL are stubbed on pre_http_request — zero outbound provider call.
 * Cache hits write Activity outcome served-from-cache referencing the source row.
 * Denies stay out of scope. Cost::estimate_usd is read-only for saved-spend UI.
 *
 * README-FREE.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Per-connector response carpool for allowed generating calls.
 */
final class Carpool {

	public const OUTCOME = 'served-from-cache';

	public const SETTINGS_OPTION = 'handl_aicac_carpool';

	public const STORE_OPTION = 'handl_aicac_carpool_store';

	public const ACTION_SAVE = 'handl_aicac_carpool_save';

	public const POST_PRESENT = 'handl_aicac_carpool_present';

	public const POST_CONNECTORS = 'handl_aicac_carpool_connectors';

	public const POST_TTL = 'handl_aicac_carpool_ttl';

	public const DEFAULT_TTL = 300;

	public const TTL_MIN = 30;

	public const TTL_MAX = 86400;

	public const MAX_ENTRIES = 40;

	public const MAX_BODY_BYTES = 524288;

	/**
	 * Request-local arm: hit stub or store-capture.
	 *
	 * @var array{mode:string,key?:string,log_key?:string,response?:array<string,mixed>,source_log_key?:string,tokens_in?:?int,tokens_out?:?int}|null
	 */
	private static $armed = null;

	/** @var self|null */
	private static $instance = null;

	/** @var int|null */
	private static $test_now = null;

	/** @var bool */
	private static $registered = false;

	public static function instance(): self {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}

		return self::$instance;
	}

	public function init(): void {
		if ( self::$registered ) {
			return;
		}
		self::$registered = true;

		// Priority 7: before Soft_Deny (8), MCP (9), Shadow (10).
		add_filter( 'pre_http_request', array( $this, 'maybe_stub' ), 7, 3 );
		add_filter( 'http_response', array( $this, 'maybe_capture' ), 10, 3 );
		add_action( 'admin_post_' . self::ACTION_SAVE, array( self::class, 'handle_save' ) );
		add_action( 'updated_option', array( self::class, 'on_updated_option' ), 10, 3 );
		add_action( 'added_option', array( self::class, 'on_added_option' ), 10, 2 );
	}

	public static function reset_for_tests(): void {
		self::$armed      = null;
		self::$registered = false;
		self::$test_now   = null;
		self::$instance   = null;
		delete_option( self::SETTINGS_OPTION );
		delete_option( self::STORE_OPTION );
	}

	public static function set_test_now( ?int $now ): void {
		self::$test_now = $now;
	}

	public static function now(): int {
		if ( null !== self::$test_now ) {
			return (int) self::$test_now;
		}
		if ( class_exists( Clock::class, false ) && method_exists( Clock::class, 'now' ) ) {
			return (int) Clock::now();
		}

		return time();
	}

	/* ---------------------------------------------------------------------
	 * Settings
	 * ------------------------------------------------------------------ */

	/**
	 * @return array{
	 *   connectors:array<string,true>,
	 *   ttl:int,
	 *   hits:int,
	 *   saved_input_tokens:int,
	 *   saved_output_tokens:int
	 * }
	 */
	public static function get_settings(): array {
		$raw = get_option( self::SETTINGS_OPTION, null );

		return self::sanitize_settings( is_array( $raw ) ? $raw : array() );
	}

	/**
	 * @param mixed $raw
	 * @return array{
	 *   connectors:array<string,true>,
	 *   ttl:int,
	 *   hits:int,
	 *   saved_input_tokens:int,
	 *   saved_output_tokens:int
	 * }
	 */
	public static function sanitize_settings( $raw ): array {
		$raw = is_array( $raw ) ? $raw : array();
		$connectors = array();
		if ( isset( $raw['connectors'] ) && is_array( $raw['connectors'] ) ) {
			foreach ( $raw['connectors'] as $plugin => $on ) {
				$plugin = class_exists( Plugin_Profile::class, false )
					? Plugin_Profile::sanitize_plugin( (string) $plugin )
					: sanitize_text_field( (string) $plugin );
				if ( '' === $plugin ) {
					continue;
				}
				if ( ! empty( $on ) ) {
					$connectors[ $plugin ] = true;
				}
			}
		}
		$ttl = isset( $raw['ttl'] ) ? (int) $raw['ttl'] : self::DEFAULT_TTL;
		if ( $ttl < self::TTL_MIN ) {
			$ttl = self::TTL_MIN;
		}
		if ( $ttl > self::TTL_MAX ) {
			$ttl = self::TTL_MAX;
		}

		return array(
			'connectors'          => $connectors,
			'ttl'                 => $ttl,
			'hits'                => max( 0, (int) ( $raw['hits'] ?? 0 ) ),
			'saved_input_tokens'  => max( 0, (int) ( $raw['saved_input_tokens'] ?? 0 ) ),
			'saved_output_tokens' => max( 0, (int) ( $raw['saved_output_tokens'] ?? 0 ) ),
		);
	}

	/**
	 * @param array<string,mixed> $settings
	 */
	public static function save_settings( array $settings ): void {
		$clean = self::sanitize_settings( $settings );
		update_option( self::SETTINGS_OPTION, $clean, false );
	}

	public static function is_enabled_for( ?string $plugin ): bool {
		$plugin = class_exists( Plugin_Profile::class, false )
			? Plugin_Profile::sanitize_plugin( (string) $plugin )
			: sanitize_text_field( (string) $plugin );
		if ( '' === $plugin ) {
			return false;
		}
		$settings = self::get_settings();

		return ! empty( $settings['connectors'][ $plugin ] );
	}

	public static function ttl(): int {
		return (int) self::get_settings()['ttl'];
	}

	/* ---------------------------------------------------------------------
	 * Ask fingerprint (Dejavu base + prompt hash)
	 * ------------------------------------------------------------------ */

	/**
	 * SHA-256 of the full prompt text (not the truncated preview).
	 *
	 * @param mixed $builder WP_AI_Client_Prompt_Builder or null.
	 */
	public static function prompt_hash_from_builder( $builder ): string {
		$text = self::extract_prompt_text( $builder );
		if ( null === $text ) {
			$preview = '';
			if ( is_array( $builder ) && isset( $builder['prompt_preview'] ) && is_string( $builder['prompt_preview'] ) ) {
				$preview = $builder['prompt_preview'];
			}

			return hash( 'sha256', $preview );
		}

		return hash( 'sha256', $text );
	}

	/**
	 * @param array<string,mixed> $row
	 * @param string              $prompt_hash
	 */
	public static function ask_key( array $row, string $prompt_hash = '' ): string {
		if ( '' !== $prompt_hash ) {
			$row['prompt_hash'] = $prompt_hash;
		}
		if ( class_exists( Dejavu::class, false ) && method_exists( Dejavu::class, 'fingerprint' ) ) {
			return Dejavu::fingerprint( $row );
		}
		$plugin   = strtolower( trim( (string) ( $row['plugin'] ?? '' ) ) );
		$op       = sanitize_key( (string) ( $row['operation'] ?? '' ) );
		$provider = strtolower( trim( (string) ( $row['provider'] ?? '' ) ) );
		$model    = strtolower( trim( (string) ( $row['model'] ?? '' ) ) );
		$hash     = strtolower( trim( (string) ( $row['prompt_hash'] ?? $prompt_hash ) ) );
		$parts    = array( $plugin, $op, $provider, $model );
		if ( '' !== $hash ) {
			$parts[] = $hash;
		}

		return implode( '|', $parts );
	}

	/**
	 * @param mixed $builder
	 */
	private static function extract_prompt_text( $builder ): ?string {
		if ( ! is_object( $builder ) ) {
			return null;
		}
		try {
			$ref = new \ReflectionClass( $builder );
			$inner = null;
			if ( $ref->hasProperty( 'builder' ) ) {
				$prop = $ref->getProperty( 'builder' );
				$prop->setAccessible( true );
				$candidate = $prop->getValue( $builder );
				if ( is_object( $candidate ) ) {
					$inner = $candidate;
				}
			}
			if ( null === $inner ) {
				$inner = $builder;
			}
			$inner_ref = new \ReflectionClass( $inner );
			if ( ! $inner_ref->hasProperty( 'messages' ) ) {
				return null;
			}
			$msg_prop = $inner_ref->getProperty( 'messages' );
			$msg_prop->setAccessible( true );
			$messages = $msg_prop->getValue( $inner );
			if ( ! is_array( $messages ) ) {
				return null;
			}
			$chunks = array();
			foreach ( $messages as $message ) {
				if ( ! is_object( $message ) || ! method_exists( $message, 'getParts' ) ) {
					continue;
				}
				$parts = $message->getParts();
				if ( ! is_array( $parts ) ) {
					continue;
				}
				foreach ( $parts as $part ) {
					if ( ! is_object( $part ) || ! method_exists( $part, 'getText' ) ) {
						continue;
					}
					$text = $part->getText();
					if ( is_string( $text ) && '' !== trim( $text ) ) {
						$chunks[] = trim( $text );
					}
				}
			}
			if ( empty( $chunks ) ) {
				return '';
			}

			return implode( "\n", $chunks );
		} catch ( \Throwable $e ) { // phpcs:ignore Generic.CodeAnalysis.EmptyStatement.DetectedCatch
			return null;
		}
	}

	public static function applies_to_operation( string $operation ): bool {
		if ( '' === $operation ) {
			return false;
		}

		return 0 === strpos( $operation, 'generate_' )
			|| 0 === strpos( $operation, 'convert_text_to_speech' );
	}

	/* ---------------------------------------------------------------------
	 * Arm / stub / capture
	 * ------------------------------------------------------------------ */

	/**
	 * On an ALLOWED generating call for an opted-in connector: hit → stub, miss → capture.
	 * Mutates $event with prompt_hash and outcome when serving from cache.
	 *
	 * @param array<string,mixed> $event
	 * @param mixed               $builder
	 */
	public static function maybe_arm_from_allow(
		bool $prevent,
		array &$event,
		$builder,
		?string $plugin,
		string $operation
	): void {
		if ( $prevent ) {
			return;
		}
		if ( ! empty( $event['audit_only'] ) || ! empty( $event['selftest'] ) ) {
			return;
		}
		if ( ! self::applies_to_operation( $operation ) ) {
			return;
		}
		if ( ! self::is_enabled_for( $plugin ) ) {
			return;
		}

		$prompt_hash = self::prompt_hash_from_builder( $builder );
		if ( isset( $event['prompt_preview'] ) && is_string( $event['prompt_preview'] ) && '' === $prompt_hash ) {
			$prompt_hash = hash( 'sha256', (string) $event['prompt_preview'] );
		}
		$event['prompt_hash'] = $prompt_hash;

		$key = self::ask_key( $event, $prompt_hash );
		$hit = self::lookup( $key );
		if ( null !== $hit ) {
			$event['outcome']             = self::OUTCOME;
			$event['carpool_source']      = (string) ( $hit['log_key'] ?? '' );
			$event['carpool_ask_key']     = $key;
			self::$armed                  = array(
				'mode'           => 'hit',
				'response'       => $hit['response'],
				'source_log_key' => (string) ( $hit['log_key'] ?? '' ),
				'tokens_in'      => isset( $hit['tokens_in'] ) ? (int) $hit['tokens_in'] : null,
				'tokens_out'     => isset( $hit['tokens_out'] ) ? (int) $hit['tokens_out'] : null,
			);
			self::record_hit(
				isset( $hit['tokens_in'] ) ? (int) $hit['tokens_in'] : null,
				isset( $hit['tokens_out'] ) ? (int) $hit['tokens_out'] : null
			);

			return;
		}

		$log_key = isset( $event['log_key'] ) ? (string) $event['log_key'] : '';
		self::$armed = array(
			'mode'    => 'store',
			'key'     => $key,
			'log_key' => $log_key,
		);
	}

	public static function is_armed(): bool {
		return null !== self::$armed;
	}

	/**
	 * @return array<string,mixed>|null
	 */
	public static function armed_state(): ?array {
		return self::$armed;
	}

	public static function disarm(): void {
		self::$armed = null;
	}

	/**
	 * @param false|array|\WP_Error $preempt
	 * @param array<string,mixed>   $args
	 * @param string                $url
	 * @return false|array|\WP_Error
	 */
	public function maybe_stub( $preempt, $args, $url ) {
		unset( $args, $url );
		if ( null === self::$armed || 'hit' !== ( self::$armed['mode'] ?? '' ) ) {
			return $preempt;
		}
		$response = self::$armed['response'] ?? null;
		self::disarm();
		if ( ! is_array( $response ) ) {
			return $preempt;
		}

		return $response;
	}

	/**
	 * Capture a successful provider response for a pending store arm.
	 *
	 * @param array<string,mixed> $response
	 * @param array<string,mixed> $args
	 * @param string              $url
	 * @return array<string,mixed>
	 */
	public function maybe_capture( $response, $args, $url ) {
		unset( $args, $url );
		if ( null === self::$armed || 'store' !== ( self::$armed['mode'] ?? '' ) ) {
			return $response;
		}
		$key     = (string) ( self::$armed['key'] ?? '' );
		$log_key = (string) ( self::$armed['log_key'] ?? '' );
		self::disarm();

		if ( '' === $key || ! is_array( $response ) ) {
			return $response;
		}
		$code = isset( $response['response']['code'] ) ? (int) $response['response']['code'] : 0;
		if ( $code < 200 || $code >= 300 ) {
			return $response;
		}
		$body = isset( $response['body'] ) ? (string) $response['body'] : '';
		if ( strlen( $body ) > self::MAX_BODY_BYTES ) {
			return $response;
		}

		$headers = array();
		if ( isset( $response['headers'] ) && is_array( $response['headers'] ) ) {
			foreach ( $response['headers'] as $h_key => $h_val ) {
				if ( is_string( $h_key ) && ( is_string( $h_val ) || is_numeric( $h_val ) ) ) {
					$headers[ strtolower( $h_key ) ] = (string) $h_val;
				}
			}
		}
		if ( empty( $headers['content-type'] ) ) {
			$headers['content-type'] = 'application/json; charset=utf-8';
		}

		self::store_entry(
			$key,
			array(
				'log_key'   => $log_key,
				'stored_at' => self::now(),
				'response'  => array(
					'headers'  => $headers,
					'body'     => $body,
					'response' => array(
						'code'    => $code,
						'message' => isset( $response['response']['message'] )
							? (string) $response['response']['message']
							: 'OK',
					),
					'cookies'  => array(),
					'filename' => null,
				),
				'tokens_in'  => null,
				'tokens_out' => null,
				'plugin'     => self::plugin_from_ask_key( $key ),
			)
		);

		return $response;
	}

	/**
	 * Attach token counts to a freshly stored entry (called when Activity tokens land).
	 */
	public static function attach_tokens_for_log_key( string $log_key, ?int $tokens_in, ?int $tokens_out ): void {
		if ( '' === $log_key ) {
			return;
		}
		$store = self::get_store();
		$changed = false;
		foreach ( $store as $key => $entry ) {
			if ( ! is_array( $entry ) ) {
				continue;
			}
			if ( (string) ( $entry['log_key'] ?? '' ) !== $log_key ) {
				continue;
			}
			$store[ $key ]['tokens_in']  = null !== $tokens_in ? max( 0, $tokens_in ) : null;
			$store[ $key ]['tokens_out'] = null !== $tokens_out ? max( 0, $tokens_out ) : null;
			$changed = true;
			break;
		}
		if ( $changed ) {
			self::save_store( $store );
		}
	}

	/* ---------------------------------------------------------------------
	 * Store
	 * ------------------------------------------------------------------ */

	/**
	 * @return array<string,array<string,mixed>>
	 */
	public static function get_store(): array {
		$raw = get_option( self::STORE_OPTION, null );
		if ( ! is_array( $raw ) ) {
			return array();
		}
		$out = array();
		foreach ( $raw as $key => $entry ) {
			if ( is_string( $key ) && is_array( $entry ) ) {
				$out[ $key ] = $entry;
			}
		}

		return $out;
	}

	/**
	 * @param array<string,array<string,mixed>> $store
	 */
	public static function save_store( array $store ): void {
		update_option( self::STORE_OPTION, $store, false );
	}

	/**
	 * @return array{log_key:string,response:array<string,mixed>,tokens_in:?int,tokens_out:?int}|null
	 */
	public static function lookup( string $key ): ?array {
		if ( '' === $key ) {
			return null;
		}
		$store = self::get_store();
		if ( ! isset( $store[ $key ] ) || ! is_array( $store[ $key ] ) ) {
			return null;
		}
		$entry = $store[ $key ];
		$stored_at = isset( $entry['stored_at'] ) ? (int) $entry['stored_at'] : 0;
		$ttl       = self::ttl();
		if ( $stored_at <= 0 || ( self::now() - $stored_at ) > $ttl ) {
			unset( $store[ $key ] );
			self::save_store( $store );

			return null;
		}
		$response = $entry['response'] ?? null;
		if ( ! is_array( $response ) || ! isset( $response['body'] ) ) {
			return null;
		}

		return array(
			'log_key'    => (string) ( $entry['log_key'] ?? '' ),
			'response'   => $response,
			'tokens_in'  => array_key_exists( 'tokens_in', $entry ) && null !== $entry['tokens_in']
				? (int) $entry['tokens_in']
				: null,
			'tokens_out' => array_key_exists( 'tokens_out', $entry ) && null !== $entry['tokens_out']
				? (int) $entry['tokens_out']
				: null,
		);
	}

	/**
	 * @param array<string,mixed> $entry
	 */
	public static function store_entry( string $key, array $entry ): void {
		if ( '' === $key ) {
			return;
		}
		$store         = self::get_store();
		$store[ $key ] = $entry;
		if ( count( $store ) > self::MAX_ENTRIES ) {
			uasort(
				$store,
				static function ( array $a, array $b ): int {
					return ( (int) ( $a['stored_at'] ?? 0 ) ) <=> ( (int) ( $b['stored_at'] ?? 0 ) );
				}
			);
			while ( count( $store ) > self::MAX_ENTRIES ) {
				array_shift( $store );
			}
		}
		self::save_store( $store );
	}

	public static function flush_all(): void {
		delete_option( self::STORE_OPTION );
		self::disarm();
	}

	public static function flush_plugin( string $plugin ): void {
		$plugin = class_exists( Plugin_Profile::class, false )
			? Plugin_Profile::sanitize_plugin( $plugin )
			: sanitize_text_field( $plugin );
		if ( '' === $plugin ) {
			return;
		}
		$store   = self::get_store();
		$changed = false;
		foreach ( $store as $key => $entry ) {
			$entry_plugin = isset( $entry['plugin'] ) ? (string) $entry['plugin'] : self::plugin_from_ask_key( (string) $key );
			if ( strtolower( $entry_plugin ) === strtolower( $plugin ) ) {
				unset( $store[ $key ] );
				$changed = true;
			}
		}
		if ( $changed ) {
			self::save_store( $store );
		}
	}

	/**
	 * Drop entries whose source Activity log_key is no longer present.
	 *
	 * @param list<array<string,mixed>> $rows
	 */
	public static function prune_missing_sources( array $rows ): void {
		$keys = array();
		foreach ( $rows as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$lk = isset( $row['log_key'] ) ? (string) $row['log_key'] : '';
			if ( '' !== $lk ) {
				$keys[ $lk ] = true;
			}
		}
		$store   = self::get_store();
		$changed = false;
		foreach ( $store as $key => $entry ) {
			$lk = isset( $entry['log_key'] ) ? (string) $entry['log_key'] : '';
			if ( '' !== $lk && empty( $keys[ $lk ] ) ) {
				unset( $store[ $key ] );
				$changed = true;
			}
		}
		if ( $changed ) {
			self::save_store( $store );
		}
	}

	private static function plugin_from_ask_key( string $key ): string {
		$parts = explode( '|', $key );

		return isset( $parts[0] ) ? (string) $parts[0] : '';
	}

	/**
	 * @param int|null $tokens_in
	 * @param int|null $tokens_out
	 */
	private static function record_hit( ?int $tokens_in, ?int $tokens_out ): void {
		$settings = self::get_settings();
		$settings['hits'] = (int) $settings['hits'] + 1;
		if ( null !== $tokens_in ) {
			$settings['saved_input_tokens'] = (int) $settings['saved_input_tokens'] + max( 0, $tokens_in );
		}
		if ( null !== $tokens_out ) {
			$settings['saved_output_tokens'] = (int) $settings['saved_output_tokens'] + max( 0, $tokens_out );
		}
		self::save_settings( $settings );
	}

	/**
	 * Estimated saved spend from accumulated token counters (Cost rates only).
	 */
	public static function estimated_saved_usd( ?array $settings = null ): ?float {
		$settings = null !== $settings ? self::sanitize_settings( $settings ) : self::get_settings();
		$in       = (int) $settings['saved_input_tokens'];
		$out      = (int) $settings['saved_output_tokens'];
		if ( 0 === $in && 0 === $out ) {
			return 0.0;
		}
		if ( ! class_exists( Cost::class, false ) || ! method_exists( Cost::class, 'estimate_usd' ) ) {
			return null;
		}
		$rates = null;
		if ( class_exists( Policy::class, false ) && method_exists( Policy::class, 'get_policy' )
			&& method_exists( Cost::class, 'fallback_rates_from_policy' ) ) {
			$policy = Policy::get_policy();
			if ( is_array( $policy ) ) {
				$rates = Cost::fallback_rates_from_policy( $policy );
			}
		}

		return Cost::estimate_usd( $in, $out, $rates );
	}

	/* ---------------------------------------------------------------------
	 * Flush hooks
	 * ------------------------------------------------------------------ */

	/**
	 * @param mixed $old_value
	 * @param mixed $value
	 */
	public static function on_updated_option( string $option, $old_value, $value ): void {
		unset( $old_value );
		self::maybe_flush_for_option( $option, $value );
	}

	/**
	 * @param mixed $value
	 */
	public static function on_added_option( string $option, $value ): void {
		self::maybe_flush_for_option( $option, $value );
	}

	/**
	 * @param mixed $value
	 */
	private static function maybe_flush_for_option( string $option, $value ): void {
		$policy_key = class_exists( Plugin::class, false ) ? Plugin::OPTION_KEY : 'handl_aicac_policy';
		$log_key    = class_exists( Plugin::class, false ) ? Plugin::LOG_OPTION_KEY : 'handl_aicac_recent_calls';

		if ( $option === $policy_key ) {
			self::flush_all();

			return;
		}
		if ( $option === self::SETTINGS_OPTION ) {
			// Connector disable: flush that plugin's entries. Full wipe when map empties.
			$settings = self::sanitize_settings( is_array( $value ) ? $value : array() );
			if ( empty( $settings['connectors'] ) ) {
				self::flush_all();
			}

			return;
		}
		if ( $option === $log_key && is_array( $value ) ) {
			self::prune_missing_sources( $value );
		}
	}

	/* ---------------------------------------------------------------------
	 * Déjà vu screen wiring
	 * ------------------------------------------------------------------ */

	public static function handle_save(): void {
		if ( ! class_exists( Caps::class, false ) || ! Caps::user_can_manage() ) {
			wp_die( esc_html__( 'You do not have permission to save carpool settings.', 'handl-ai-connector-access-control' ) );
		}
		check_admin_referer( self::ACTION_SAVE );
		if ( empty( $_POST[ self::POST_PRESENT ] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing
			wp_die( esc_html__( 'Security check failed. Go back, reload the page, and try again.', 'handl-ai-connector-access-control' ) );
		}

		$prev        = self::get_settings();
		$posted      = isset( $_POST[ self::POST_CONNECTORS ] ) && is_array( $_POST[ self::POST_CONNECTORS ] ) // phpcs:ignore WordPress.Security.NonceVerification.Missing
			? wp_unslash( $_POST[ self::POST_CONNECTORS ] ) // phpcs:ignore WordPress.Security.NonceVerification.Missing,WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
			: array();
		$connectors  = array();
		foreach ( $posted as $plugin => $on ) {
			$plugin = class_exists( Plugin_Profile::class, false )
				? Plugin_Profile::sanitize_plugin( (string) $plugin )
				: sanitize_text_field( (string) $plugin );
			if ( '' !== $plugin && ! empty( $on ) ) {
				$connectors[ $plugin ] = true;
			}
		}
		$ttl = isset( $_POST[ self::POST_TTL ] ) ? (int) $_POST[ self::POST_TTL ] : self::DEFAULT_TTL; // phpcs:ignore WordPress.Security.NonceVerification.Missing

		// Flush entries for connectors that were just turned off.
		foreach ( array_keys( $prev['connectors'] ) as $was_on ) {
			if ( empty( $connectors[ $was_on ] ) ) {
				self::flush_plugin( $was_on );
			}
		}

		self::save_settings(
			array(
				'connectors'          => $connectors,
				'ttl'                 => $ttl,
				'hits'                => $prev['hits'],
				'saved_input_tokens'  => $prev['saved_input_tokens'],
				'saved_output_tokens' => $prev['saved_output_tokens'],
			)
		);

		$page = class_exists( Dejavu::class, false ) ? Dejavu::PAGE_SLUG : 'handl-aicac-dejavu';
		$url  = admin_url( 'admin.php?page=' . $page );
		if ( function_exists( 'wp_safe_redirect' ) ) {
			wp_safe_redirect( $url );
			exit;
		}
	}

	/**
	 * Render opt-in + savings panel on the Déjà vu screen.
	 *
	 * @param list<array<string,mixed>> $census_rows
	 */
	public static function render_dejavu_panel( array $census_rows = array() ): void {
		$settings   = self::get_settings();
		$can_manage = class_exists( Caps::class, false ) && Caps::user_can_manage();
		$hits       = (int) $settings['hits'];
		$saved_usd  = self::estimated_saved_usd( $settings );

		echo '<h2>' . esc_html__( 'Carpool', 'handl-ai-connector-access-control' ) . '</h2>';
		echo '<p class="description">' . esc_html__( 'Reuse a stored response when the same connector sends an identical allowed request before the cache expires. Off by default. Enable caching separately for each connector. Blocked requests are never cached.', 'handl-ai-connector-access-control' ) . '</p>';

		$saved_label = '';
		if ( null !== $saved_usd && class_exists( Cost::class, false ) && method_exists( Cost::class, 'format_usd' ) ) {
			$saved_label = Cost::format_usd( $saved_usd );
		} elseif ( null !== $saved_usd ) {
			$saved_label = '$' . number_format( $saved_usd, 2, '.', ',' );
		}
		echo '<p>';
		echo esc_html(
			sprintf(
				/* translators: 1: cache hit count, 2: estimated USD saved (or em dash) */
				__( 'Calls avoided: %1$d. Estimated savings: %2$s.', 'handl-ai-connector-access-control' ),
				$hits,
				'' !== $saved_label ? $saved_label : '—'
			)
		);
		echo '</p>';

		$connectors = array();
		foreach ( $census_rows as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$c = isset( $row['connector'] ) ? (string) $row['connector'] : '';
			if ( '' !== $c && 'unknown' !== $c ) {
				$connectors[ $c ] = true;
			}
		}
		foreach ( array_keys( $settings['connectors'] ) as $c ) {
			$connectors[ $c ] = true;
		}
		ksort( $connectors );

		if ( ! $can_manage ) {
			if ( empty( $settings['connectors'] ) ) {
				echo '<p>' . esc_html__( 'No connectors opted in.', 'handl-ai-connector-access-control' ) . '</p>';
			} else {
				echo '<ul class="ul-disc">';
				foreach ( array_keys( $settings['connectors'] ) as $c ) {
					echo '<li>' . esc_html( $c ) . '</li>';
				}
				echo '</ul>';
			}

			return;
		}

		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
		echo '<input type="hidden" name="action" value="' . esc_attr( self::ACTION_SAVE ) . '" />';
		echo '<input type="hidden" name="' . esc_attr( self::POST_PRESENT ) . '" value="1" />';
		wp_nonce_field( self::ACTION_SAVE );
		echo '<table class="form-table" role="presentation"><tbody>';
		echo '<tr><th scope="row"><label for="handl-aicac-carpool-ttl">' . esc_html__( 'Cache duration (seconds)', 'handl-ai-connector-access-control' ) . '</label></th><td>';
		echo '<input name="' . esc_attr( self::POST_TTL ) . '" id="handl-aicac-carpool-ttl" type="number" min="' . esc_attr( (string) self::TTL_MIN ) . '" max="' . esc_attr( (string) self::TTL_MAX ) . '" value="' . esc_attr( (string) (int) $settings['ttl'] ) . '" class="small-text" />';
		echo '<p class="description">' . esc_html__( 'Default: 300 seconds. Cached responses expire after this time and are cleared when policy changes.', 'handl-ai-connector-access-control' ) . '</p>';
		echo '</td></tr>';
		echo '<tr><th scope="row">' . esc_html__( 'Opt-in connectors', 'handl-ai-connector-access-control' ) . '</th><td>';
		if ( empty( $connectors ) ) {
			echo '<p>' . esc_html__( 'No connectors available to enable yet. Check again after connectors send more allowed requests.', 'handl-ai-connector-access-control' ) . '</p>';
		} else {
			echo '<fieldset><legend class="screen-reader-text">' . esc_html__( 'Opt-in connectors', 'handl-ai-connector-access-control' ) . '</legend>';
			foreach ( array_keys( $connectors ) as $c ) {
				$id = 'handl-aicac-carpool-' . md5( $c );
				echo '<label for="' . esc_attr( $id ) . '" style="display:block;margin-bottom:4px;">';
				echo '<input type="checkbox" id="' . esc_attr( $id ) . '" name="' . esc_attr( self::POST_CONNECTORS ) . '[' . esc_attr( $c ) . ']" value="1"' . checked( ! empty( $settings['connectors'][ $c ] ), true, false ) . ' /> ';
				echo esc_html( $c );
				echo '</label>';
			}
			echo '</fieldset>';
		}
		echo '</td></tr></tbody></table>';
		submit_button( __( 'Save carpool settings', 'handl-ai-connector-access-control' ) );
		echo '</form>';
	}

	/**
	 * Activity outcome helper.
	 *
	 * @param array<string,mixed> $row
	 */
	public static function outcome_from_row( array $row ): string {
		$raw = isset( $row['outcome'] ) ? (string) $row['outcome'] : '';

		return self::OUTCOME === $raw ? self::OUTCOME : '';
	}
}
