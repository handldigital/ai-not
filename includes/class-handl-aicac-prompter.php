<?php
/**
 * AICAC-PROMPTER (#517): system-instruction fingerprint.
 *
 * Per calling plugin, keep a salted hash of the normalized system instruction
 * seen on governed AI calls. First sighting is baseline (no alert). A new hash
 * alerts once through the existing alert email/webhook paths and respects
 * snooze. Store hash, length, first-seen and last-seen only — never the
 * instruction text. Off by default. Observability only — never Allow/Deny.
 *
 * README-FREE. Own options + own admin screen. Keep-both: plugin.php require
 * + init, tests/bootstrap.php, policy.php observe/skip-list lines,
 * policy-simulator.php unused (no deny reason).
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * System-instruction drift watch.
 */
final class Prompter {

	public const SETTINGS_OPTION = 'handl_aicac_prompter';

	public const STATE_OPTION = 'handl_aicac_prompter_state';

	public const PAGE_SLUG = 'handl-aicac-prompter';

	public const ACTION_SAVE = 'handl_aicac_prompter_save';

	public const POST_PRESENT = 'handl_aicac_prompter_present';

	public const POST_ENABLED = 'handl_aicac_prompter_enabled';

	public const CHANNEL = 'prompter';

	public const NONE_HASH = 'none';

	public const CHANGE_WINDOW = 7776000; // 90 days.

	public const HISTORY_MAX = 40;

	/** @var bool */
	private static $registered = false;

	/** @var int|null */
	private static $test_now = null;

	/** @var string|null */
	private static $test_plugin = null;

	/** @var array<string,string>|null plugin => version override for tests. */
	private static $test_versions = null;

	/**
	 * Deferred alert payloads (flushed after the activity row is retained).
	 *
	 * @var list<array{policy:array<string,mixed>,plugin:string,hash:string,length:int,version:string,coincided:bool,now:int}>
	 */
	private static array $deferred_alerts = array();

	public static function init(): void {
		if ( self::$registered ) {
			return;
		}
		self::$registered = true;
		add_action( 'admin_menu', array( self::class, 'register_menu' ), 20 );
		add_action( 'admin_post_' . self::ACTION_SAVE, array( self::class, 'handle_save' ) );
		add_filter( 'http_request_args', array( self::class, 'observe_http' ), 11, 2 );
	}

	public static function reset_for_tests(): void {
		self::$registered      = false;
		self::$test_now        = null;
		self::$test_plugin     = null;
		self::$test_versions   = null;
		self::$deferred_alerts = array();
		delete_option( self::SETTINGS_OPTION );
		delete_option( self::STATE_OPTION );
	}

	public static function set_test_now( ?int $now ): void {
		self::$test_now = $now;
	}

	public static function set_test_plugin( ?string $plugin ): void {
		self::$test_plugin = ( is_string( $plugin ) && '' !== $plugin ) ? $plugin : null;
	}

	/**
	 * @param array<string,string>|null $map
	 */
	public static function set_test_versions( ?array $map ): void {
		self::$test_versions = $map;
	}

	public static function now(): int {
		if ( null !== self::$test_now ) {
			return self::$test_now;
		}
		$env = getenv( 'HANDL_AICAC_TEST_NOW' );
		if ( false !== $env && '' !== $env && is_numeric( $env ) ) {
			return (int) $env;
		}

		return time();
	}

	/**
	 * @return array{enabled:bool}
	 */
	public static function settings_defaults(): array {
		return array(
			'enabled' => false,
		);
	}

	/**
	 * @return array{enabled:bool}
	 */
	public static function get_settings(): array {
		return self::sanitize_settings( get_option( self::SETTINGS_OPTION, array() ) );
	}

	/**
	 * @param mixed $raw
	 * @return array{enabled:bool}
	 */
	public static function sanitize_settings( $raw ): array {
		$out = self::settings_defaults();
		if ( ! is_array( $raw ) ) {
			return $out;
		}
		$out['enabled'] = ! empty( $raw['enabled'] );

		return $out;
	}

	/**
	 * @param mixed $raw
	 */
	public static function save_settings( $raw ): void {
		$clean = self::sanitize_settings( $raw );
		if ( empty( $clean['enabled'] ) ) {
			delete_option( self::SETTINGS_OPTION );

			return;
		}
		update_option( self::SETTINGS_OPTION, $clean, false );
	}

	public static function is_enabled(): bool {
		return ! empty( self::get_settings()['enabled'] );
	}

	/**
	 * @return array<string,array<string,mixed>>
	 */
	public static function get_state(): array {
		return self::sanitize_state( get_option( self::STATE_OPTION, array() ) );
	}

	/**
	 * @param mixed $raw
	 * @return array<string,array<string,mixed>>
	 */
	public static function sanitize_state( $raw ): array {
		if ( ! is_array( $raw ) ) {
			return array();
		}
		$out = array();
		foreach ( $raw as $plugin => $row ) {
			$plugin = self::sanitize_plugin( (string) $plugin );
			if ( '' === $plugin || ! is_array( $row ) ) {
				continue;
			}
			$clean = self::sanitize_plugin_row( $row );
			if ( null !== $clean ) {
				$out[ $plugin ] = $clean;
			}
		}

		return $out;
	}

	/**
	 * @param array<string,mixed> $row
	 * @return array{hash:string,length:int,first_seen:int,last_seen:int,version:string,changes:list<array{ts:int,version:string,coincided:bool}>}|null
	 */
	private static function sanitize_plugin_row( array $row ): ?array {
		$hash = self::sanitize_hash( $row['hash'] ?? '' );
		if ( '' === $hash ) {
			return null;
		}
		$first = max( 0, (int) ( $row['first_seen'] ?? 0 ) );
		$last  = max( 0, (int) ( $row['last_seen'] ?? 0 ) );
		if ( $first <= 0 ) {
			$first = $last > 0 ? $last : self::now();
		}
		if ( $last < $first ) {
			$last = $first;
		}
		$changes = array();
		$src     = isset( $row['changes'] ) && is_array( $row['changes'] ) ? $row['changes'] : array();
		foreach ( $src as $entry ) {
			if ( ! is_array( $entry ) ) {
				continue;
			}
			$ts = max( 0, (int) ( $entry['ts'] ?? 0 ) );
			if ( $ts <= 0 ) {
				continue;
			}
			$changes[] = array(
				'ts'        => $ts,
				'version'   => self::sanitize_version( $entry['version'] ?? '' ),
				'coincided' => ! empty( $entry['coincided'] ),
			);
			if ( count( $changes ) >= self::HISTORY_MAX ) {
				break;
			}
		}

		return array(
			'hash'       => $hash,
			'length'     => max( 0, (int) ( $row['length'] ?? 0 ) ),
			'first_seen' => $first,
			'last_seen'  => $last,
			'version'    => self::sanitize_version( $row['version'] ?? '' ),
			'changes'    => $changes,
		);
	}

	/**
	 * @param array<string,array<string,mixed>> $state
	 */
	public static function save_state( array $state ): void {
		$state = self::sanitize_state( $state );
		if ( empty( $state ) ) {
			delete_option( self::STATE_OPTION );

			return;
		}
		update_option( self::STATE_OPTION, $state, false );
	}

	public static function sanitize_plugin( string $raw ): string {
		if ( class_exists( Plugin_Profile::class, false ) ) {
			return Plugin_Profile::sanitize_plugin( $raw );
		}
		$raw = strtolower( str_replace( '\\', '/', trim( $raw ) ) );

		return preg_replace( '/[^a-z0-9._\-\/]/', '', $raw ) ?? '';
	}

	public static function sanitize_version( $raw ): string {
		$ver = sanitize_text_field( (string) $raw );
		if ( strlen( $ver ) > 64 ) {
			$ver = substr( $ver, 0, 64 );
		}

		return $ver;
	}

	public static function sanitize_hash( $raw ): string {
		$hash = strtolower( trim( (string) $raw ) );
		if ( self::NONE_HASH === $hash ) {
			return self::NONE_HASH;
		}
		if ( ! preg_match( '/^[a-f0-9]{64}$/', $hash ) ) {
			return '';
		}

		return $hash;
	}

	/**
	 * Collapse whitespace so formatting-only edits do not count as drift.
	 */
	public static function normalize_instruction( string $text ): string {
		$text = trim( $text );
		if ( '' === $text ) {
			return '';
		}
		$collapsed = preg_replace( '/\s+/u', ' ', $text );

		return is_string( $collapsed ) ? trim( $collapsed ) : trim( $text );
	}

	/**
	 * Salted fingerprint. Empty normalized text → NONE_HASH.
	 */
	public static function fingerprint( string $text ): array {
		$normalized = self::normalize_instruction( $text );
		if ( '' === $normalized ) {
			return array(
				'hash'   => self::NONE_HASH,
				'length' => 0,
			);
		}
		$salt = function_exists( 'wp_salt' ) ? (string) wp_salt( 'auth' ) : 'handl-aicac-prompter';

		return array(
			'hash'   => hash_hmac( 'sha256', $normalized, $salt ),
			'length' => strlen( $normalized ),
		);
	}

	/**
	 * Extract system instruction from an AI Client prompt builder (read-only).
	 *
	 * Prefers ModelConfig::systemInstruction (full text). Does not use the
	 * truncated Prompt_Snapshot copy and never logs the text.
	 *
	 * @param mixed $builder
	 */
	public static function extract_from_builder( $builder ): string {
		if ( ! is_object( $builder ) ) {
			return '';
		}

		try {
			$ref   = new \ReflectionClass( $builder );
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

			$iref = new \ReflectionClass( $inner );
			if ( $iref->hasProperty( 'modelConfig' ) ) {
				$cprop  = $iref->getProperty( 'modelConfig' );
				$cprop->setAccessible( true );
				$config = $cprop->getValue( $inner );
				if ( is_object( $config ) && method_exists( $config, 'toArray' ) ) {
					$arr = $config->toArray();
					if ( is_array( $arr ) && ! empty( $arr['systemInstruction'] ) && is_string( $arr['systemInstruction'] ) ) {
						return (string) $arr['systemInstruction'];
					}
				}
			}
		} catch ( \Throwable $e ) { // phpcs:ignore Generic.CodeAnalysis.EmptyStatement.DetectedCatch
			return '';
		}

		return '';
	}

	/**
	 * Recognized HTTP JSON shapes (OpenAI / Anthropic / Google-ish).
	 * Returns the system instruction text or '' when absent/unrecognized.
	 */
	public static function extract_from_http_body( string $body ): string {
		$body = trim( $body );
		if ( '' === $body || ( '{' !== $body[0] && '[' !== $body[0] ) ) {
			return '';
		}
		$decoded = json_decode( $body, true );
		if ( ! is_array( $decoded ) ) {
			return '';
		}

		// OpenAI Chat Completions: messages[].role=system
		if ( isset( $decoded['messages'] ) && is_array( $decoded['messages'] ) ) {
			$chunks = array();
			foreach ( $decoded['messages'] as $message ) {
				if ( ! is_array( $message ) ) {
					continue;
				}
				$role = strtolower( (string) ( $message['role'] ?? '' ) );
				if ( 'system' !== $role && 'developer' !== $role ) {
					continue;
				}
				$content = $message['content'] ?? '';
				if ( is_string( $content ) && '' !== trim( $content ) ) {
					$chunks[] = trim( $content );
				} elseif ( is_array( $content ) ) {
					foreach ( $content as $part ) {
						if ( is_array( $part ) && isset( $part['text'] ) && is_string( $part['text'] ) && '' !== trim( $part['text'] ) ) {
							$chunks[] = trim( (string) $part['text'] );
						} elseif ( is_string( $part ) && '' !== trim( $part ) ) {
							$chunks[] = trim( $part );
						}
					}
				}
			}
			if ( ! empty( $chunks ) ) {
				return implode( "\n", $chunks );
			}
		}

		// Anthropic Messages API.
		if ( isset( $decoded['system'] ) ) {
			$system = $decoded['system'];
			if ( is_string( $system ) ) {
				return $system;
			}
			if ( is_array( $system ) ) {
				$chunks = array();
				foreach ( $system as $part ) {
					if ( is_array( $part ) && isset( $part['text'] ) && is_string( $part['text'] ) ) {
						$chunks[] = (string) $part['text'];
					} elseif ( is_string( $part ) ) {
						$chunks[] = $part;
					}
				}
				if ( ! empty( $chunks ) ) {
					return implode( "\n", $chunks );
				}
			}
		}

		// Google-ish: systemInstruction.parts[].text
		if ( isset( $decoded['systemInstruction'] ) ) {
			$si = $decoded['systemInstruction'];
			if ( is_string( $si ) ) {
				return $si;
			}
			if ( is_array( $si ) ) {
				if ( isset( $si['parts'] ) && is_array( $si['parts'] ) ) {
					$chunks = array();
					foreach ( $si['parts'] as $part ) {
						if ( is_array( $part ) && isset( $part['text'] ) && is_string( $part['text'] ) ) {
							$chunks[] = (string) $part['text'];
						}
					}
					if ( ! empty( $chunks ) ) {
						return implode( "\n", $chunks );
					}
				}
				if ( isset( $si['text'] ) && is_string( $si['text'] ) ) {
					return (string) $si['text'];
				}
			}
		}

		return '';
	}

	/**
	 * Stamp hash/length onto an Activity event from the builder. Never the text.
	 *
	 * @param array<string,mixed> $event
	 * @param mixed               $builder
	 */
	public static function stamp_event( array &$event, $builder = null ): void {
		if ( ! self::is_enabled() ) {
			return;
		}
		if ( ! empty( $event['selftest'] ) ) {
			return;
		}
		$channel = isset( $event['channel'] ) ? (string) $event['channel'] : '';
		if ( self::CHANNEL === $channel ) {
			return;
		}

		$text = self::extract_from_builder( $builder );
		$fp   = self::fingerprint( $text );
		$event['prompter_hash'] = $fp['hash'];
		$event['prompter_len']  = $fp['length'];
	}

	/**
	 * Observe a stamped Activity row (or an explicit hash/length).
	 *
	 * @param array<string,mixed> $event
	 * @param array<string,mixed> $policy
	 * @return array{tagged:bool,alerted:bool,baseline:bool,reason:string}
	 */
	public static function observe( array &$event, array $policy, bool $defer_alerts = false ): array {
		$empty = array(
			'tagged'   => false,
			'alerted'  => false,
			'baseline' => false,
			'reason'   => '',
		);

		if ( ! self::is_enabled() ) {
			$empty['reason'] = 'disabled';

			return $empty;
		}

		$channel = isset( $event['channel'] ) ? (string) $event['channel'] : '';
		if ( in_array( $channel, array( self::CHANNEL, 'anomaly', 'spend_threshold', 'drift', 'alert_snooze', 'budget', 'selftest' ), true ) ) {
			$empty['reason'] = 'skip_channel';

			return $empty;
		}
		if ( ! empty( $event['selftest'] ) ) {
			$empty['reason'] = 'selftest';

			return $empty;
		}

		$plugin = isset( $event['plugin'] ) ? self::sanitize_plugin( (string) $event['plugin'] ) : '';
		if ( '' === $plugin ) {
			$empty['reason'] = 'no_plugin';

			return $empty;
		}

		$hash = self::sanitize_hash( $event['prompter_hash'] ?? '' );
		$len  = max( 0, (int) ( $event['prompter_len'] ?? 0 ) );
		if ( '' === $hash ) {
			$empty['reason'] = 'no_fingerprint';

			return $empty;
		}

		$ts = isset( $event['ts'] ) ? (int) $event['ts'] : self::now();
		if ( $ts <= 0 ) {
			$ts = self::now();
		}

		$result = self::observe_fingerprint( $plugin, $hash, $len, $policy, $ts, $defer_alerts );
		if ( ! empty( $result['baseline'] ) ) {
			$event['prompter_first_seen'] = true;
		}
		if ( ! empty( $result['tagged'] ) && empty( $result['baseline'] ) && 'known' !== (string) ( $result['reason'] ?? '' ) ) {
			$event['prompter_changed'] = true;
		}

		return $result;
	}

	/**
	 * Core fingerprint compare + optional alert.
	 *
	 * @param array<string,mixed> $policy
	 * @return array{tagged:bool,alerted:bool,baseline:bool,reason:string}
	 */
	public static function observe_fingerprint(
		string $plugin,
		string $hash,
		int $length,
		array $policy,
		?int $ts = null,
		bool $defer_alerts = false
	): array {
		$empty = array(
			'tagged'   => false,
			'alerted'  => false,
			'baseline' => false,
			'reason'   => '',
		);

		if ( ! self::is_enabled() ) {
			$empty['reason'] = 'disabled';

			return $empty;
		}

		$plugin = self::sanitize_plugin( $plugin );
		$hash   = self::sanitize_hash( $hash );
		if ( '' === $plugin || '' === $hash ) {
			$empty['reason'] = 'bad_input';

			return $empty;
		}

		$ts = null !== $ts && $ts > 0 ? $ts : self::now();
		$state  = self::get_state();
		$prev   = isset( $state[ $plugin ] ) && is_array( $state[ $plugin ] ) ? $state[ $plugin ] : null;
		$version = self::plugin_version( $plugin );

		if ( null === $prev ) {
			$state[ $plugin ] = array(
				'hash'       => $hash,
				'length'     => $length,
				'first_seen' => $ts,
				'last_seen'  => $ts,
				'version'    => $version,
				'changes'    => array(),
			);
			self::save_state( $state );

			return array(
				'tagged'   => true,
				'alerted'  => false,
				'baseline' => true,
				'reason'   => 'baseline',
			);
		}

		if ( (string) $prev['hash'] === $hash ) {
			$prev['last_seen'] = $ts;
			$state[ $plugin ]  = $prev;
			self::save_state( $state );
			$empty['reason'] = 'known';

			return $empty;
		}

		$prev_version = self::sanitize_version( $prev['version'] ?? '' );
		$coincided    = ( '' !== $version && '' !== $prev_version && $version !== $prev_version );

		$changes   = isset( $prev['changes'] ) && is_array( $prev['changes'] ) ? $prev['changes'] : array();
		array_unshift(
			$changes,
			array(
				'ts'        => $ts,
				'version'   => $version,
				'coincided' => $coincided,
			)
		);
		$changes = array_slice( $changes, 0, self::HISTORY_MAX );

		$state[ $plugin ] = array(
			'hash'       => $hash,
			'length'     => $length,
			'first_seen' => $ts,
			'last_seen'  => $ts,
			'version'    => $version,
			'changes'    => $changes,
		);
		self::save_state( $state );

		if ( $defer_alerts ) {
			self::$deferred_alerts[] = array(
				'policy'    => $policy,
				'plugin'    => $plugin,
				'hash'      => $hash,
				'length'    => $length,
				'version'   => $version,
				'coincided' => $coincided,
				'now'       => $ts,
			);

			return array(
				'tagged'   => true,
				'alerted'  => false,
				'baseline' => false,
				'reason'   => 'deferred',
			);
		}

		$fired = self::maybe_fire( $policy, $plugin, $hash, $length, $version, $coincided, $ts );

		return array(
			'tagged'   => true,
			'alerted'  => $fired,
			'baseline' => false,
			'reason'   => $fired ? 'alerted' : 'suppressed',
		);
	}

	public static function flush_deferred_alerts(): void {
		$queue                 = self::$deferred_alerts;
		self::$deferred_alerts = array();
		foreach ( $queue as $item ) {
			self::maybe_fire(
				$item['policy'],
				$item['plugin'],
				$item['hash'],
				$item['length'],
				$item['version'],
				$item['coincided'],
				$item['now']
			);
		}
	}

	/**
	 * @param array<string,mixed> $policy
	 */
	private static function maybe_fire(
		array $policy,
		string $plugin,
		string $hash,
		int $length,
		string $version,
		bool $coincided,
		int $now
	): bool {
		if ( class_exists( Alert_Snooze::class, false ) && Alert_Snooze::should_suppress( $plugin, self::CHANNEL, $now ) ) {
			return false;
		}
		if ( ! class_exists( Alerts::class, false ) ) {
			return false;
		}

		$to = Alerts::resolve_email( $policy );
		if ( '' === $to ) {
			return false;
		}

		$subject = self::build_subject( $plugin );
		$body    = self::build_body( $plugin, $version, $coincided );
		$ok      = Alerts::safe_wp_mail( $to, $subject, $body );

		$hook_url = Alerts::resolve_webhook( $policy );
		if ( '' !== $hook_url ) {
			Alerts::safe_wp_remote_post(
				$hook_url,
				array(
					'type'      => 'handl_aicac_prompter_alert',
					'plugin'    => $plugin,
					'length'    => $length,
					'version'   => $version,
					'coincided' => $coincided,
					'activity'  => self::screen_url(),
					'site'      => function_exists( 'home_url' ) ? home_url( '/' ) : '',
				)
			);
		}

		if ( ! $ok ) {
			return false;
		}

		if ( class_exists( Policy::class, false ) ) {
			Policy::append_log_event(
				array(
					'ts'       => $now,
					'decision' => 'prompter_alert',
					'channel'  => self::CHANNEL,
					'plugin'   => $plugin,
					'version'  => $version,
					'coincided'=> $coincided,
					'prompter_len' => $length,
				)
			);
		}

		return true;
	}

	public static function build_subject( string $plugin ): string {
		$site  = function_exists( 'get_bloginfo' )
			? wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES )
			: 'WordPress';
		$label = self::plugin_label( $plugin );

		return sprintf(
			/* translators: 1: site name, 2: plugin name */
			__( '[%1$s] HandL: %2$s changed its AI system instruction', 'handl-ai-connector-access-control' ),
			$site,
			$label
		);
	}

	public static function build_body( string $plugin, string $version, bool $coincided ): string {
		$lines   = array();
		$lines[] = __( 'HandL AI Connector Access Control — system instruction change', 'handl-ai-connector-access-control' );
		$lines[] = '';
		$lines[] = sprintf(
			/* translators: %s: plugin display name or basename */
			__( 'Plugin: %s', 'handl-ai-connector-access-control' ),
			self::plugin_label( $plugin )
		);
		if ( '' !== $version ) {
			$lines[] = sprintf(
				/* translators: %s: installed plugin version */
				__( 'Installed version: %s', 'handl-ai-connector-access-control' ),
				$version
			);
		}
		if ( $coincided ) {
			$lines[] = __( 'This change coincided with a plugin version change.', 'handl-ai-connector-access-control' );
		}
		$lines[] = '';
		$lines[] = __( 'The alert does not include the instruction text. Prompter records a salted fingerprint only.', 'handl-ai-connector-access-control' );
		$lines[] = '';
		$lines[] = __( 'Open the Prompter screen:', 'handl-ai-connector-access-control' );
		$lines[] = self::screen_url();

		return implode( "\n", $lines ) . "\n";
	}

	/**
	 * Read-only HTTP observer for recognized AI JSON bodies. Never mutates args.
	 *
	 * @param mixed $args
	 * @param mixed $url
	 * @return mixed
	 */
	public static function observe_http( $args, $url ) {
		if ( ! self::is_enabled() || ! is_array( $args ) ) {
			return $args;
		}
		if ( class_exists( Shadow_AI::class, false ) && method_exists( Shadow_AI::class, 'stack_is_ai_client' ) && Shadow_AI::stack_is_ai_client() ) {
			// AI Client path is stamped from the builder in maybe_prevent_prompt.
			return $args;
		}

		$url  = is_string( $url ) ? $url : '';
		$host = strtolower( (string) ( function_exists( 'wp_parse_url' ) ? wp_parse_url( $url, PHP_URL_HOST ) : parse_url( $url, PHP_URL_HOST ) ) );
		if ( '' === $host ) {
			return $args;
		}
		if ( ! class_exists( Shadow_AI::class, false ) || null === Shadow_AI::match_provider( $host ) ) {
			return $args;
		}

		$body = isset( $args['body'] ) ? $args['body'] : '';
		if ( is_array( $body ) ) {
			$body = wp_json_encode( $body );
		}
		if ( ! is_string( $body ) || '' === $body ) {
			return $args;
		}

		$text = self::extract_from_http_body( $body );
		// Absent system instruction still counts as "none" for attributed plugins.
		$plugin = self::caller_plugin();
		if ( '' === $plugin ) {
			return $args;
		}

		$fp     = self::fingerprint( $text );
		$policy = class_exists( Policy::class, false ) ? Policy::get_policy() : array();
		self::observe_fingerprint( $plugin, $fp['hash'], $fp['length'], $policy, self::now(), false );

		return $args;
	}

	/**
	 * Rows for the admin table.
	 *
	 * @return list<array{plugin:string,label:string,age_days:int,changes_90d:int,last_change:int,coincided:bool,length:int,is_none:bool}>
	 */
	public static function screen_rows( ?int $now = null ): array {
		$now   = null !== $now && $now > 0 ? $now : self::now();
		$state = self::get_state();
		$out   = array();
		foreach ( $state as $plugin => $row ) {
			$changes = isset( $row['changes'] ) && is_array( $row['changes'] ) ? $row['changes'] : array();
			$count   = 0;
			$last    = 0;
			$coincided = false;
			foreach ( $changes as $entry ) {
				if ( ! is_array( $entry ) ) {
					continue;
				}
				$ts = (int) ( $entry['ts'] ?? 0 );
				if ( $ts <= 0 ) {
					continue;
				}
				if ( ( $now - $ts ) <= self::CHANGE_WINDOW ) {
					++$count;
				}
				if ( $ts >= $last ) {
					$last      = $ts;
					$coincided = ! empty( $entry['coincided'] );
				}
			}
			$first    = (int) ( $row['first_seen'] ?? 0 );
			$day_secs = defined( 'DAY_IN_SECONDS' ) ? (int) DAY_IN_SECONDS : 86400;
			$age      = $first > 0 ? (int) floor( max( 0, $now - $first ) / $day_secs ) : 0;
			$out[] = array(
				'plugin'      => $plugin,
				'label'       => self::plugin_label( $plugin ),
				'age_days'    => $age,
				'changes_90d' => $count,
				'last_change' => $last,
				'coincided'   => $coincided,
				'length'      => (int) ( $row['length'] ?? 0 ),
				'is_none'     => self::NONE_HASH === (string) ( $row['hash'] ?? '' ),
			);
		}
		usort(
			$out,
			static function ( $a, $b ) {
				return strcmp( (string) $a['plugin'], (string) $b['plugin'] );
			}
		);

		return $out;
	}

	public static function register_menu(): void {
		if ( ! class_exists( Caps::class, false ) || ! Caps::user_can_view() ) {
			return;
		}
		if ( ! function_exists( 'add_submenu_page' ) || ! class_exists( Admin::class, false ) ) {
			return;
		}
		add_submenu_page(
			Admin::MENU_SLUG,
			__( 'Prompter', 'handl-ai-connector-access-control' ),
			__( 'Prompter', 'handl-ai-connector-access-control' ),
			Caps::VIEW,
			self::PAGE_SLUG,
			array( self::class, 'render_page' )
		);
	}

	public static function render_page(): void {
		if ( ! class_exists( Caps::class, false ) || ! Caps::user_can_view() ) {
			return;
		}
		$settings   = self::get_settings();
		$can_manage = Caps::user_can_manage();
		$rows       = self::screen_rows();

		echo '<div class="wrap">';
		echo '<h1>' . esc_html__( 'Prompter', 'handl-ai-connector-access-control' ) . '</h1>';
		echo '<p class="description">' . esc_html__( 'Watches the hidden system instruction each plugin sends with its AI calls. First sighting is a baseline. A later change alerts once. The instruction text is never stored or shown.', 'handl-ai-connector-access-control' ) . '</p>';
		echo '<p class="description">' . esc_html__( 'Off by default. Observability only — never changes Allow or Deny.', 'handl-ai-connector-access-control' ) . '</p>';

		if ( $can_manage ) {
			echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
			echo '<input type="hidden" name="action" value="' . esc_attr( self::ACTION_SAVE ) . '" />';
			echo '<input type="hidden" name="' . esc_attr( self::POST_PRESENT ) . '" value="1" />';
			if ( function_exists( 'wp_nonce_field' ) ) {
				wp_nonce_field( self::ACTION_SAVE );
			}
			echo '<p><label><input type="checkbox" name="' . esc_attr( self::POST_ENABLED ) . '" value="1" ' . checked( ! empty( $settings['enabled'] ), true, false ) . ' /> ';
			echo esc_html__( 'Watch system-instruction fingerprints', 'handl-ai-connector-access-control' ) . '</label></p>';
			if ( function_exists( 'submit_button' ) ) {
				submit_button( __( 'Save Prompter', 'handl-ai-connector-access-control' ) );
			} else {
				echo '<p><button type="submit" class="button button-primary">' . esc_html__( 'Save Prompter', 'handl-ai-connector-access-control' ) . '</button></p>';
			}
			echo '</form>';
		} else {
			echo '<p>' . esc_html( ! empty( $settings['enabled'] ) ? __( 'Prompter is on.', 'handl-ai-connector-access-control' ) : __( 'Prompter is off.', 'handl-ai-connector-access-control' ) ) . '</p>';
		}

		if ( empty( $rows ) ) {
			echo '<p>' . esc_html__( 'No fingerprints recorded yet.', 'handl-ai-connector-access-control' ) . '</p>';
			echo '</div>';

			return;
		}

		echo '<table class="widefat striped" style="max-width:64em;"><thead><tr>';
		echo '<th>' . esc_html__( 'Plugin', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Fingerprint age', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Changes (90 days)', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Last change', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'With version change', 'handl-ai-connector-access-control' ) . '</th>';
		echo '</tr></thead><tbody>';
		foreach ( $rows as $row ) {
			$age = sprintf(
				/* translators: %d: number of days */
				_n( '%d day', '%d days', (int) $row['age_days'], 'handl-ai-connector-access-control' ),
				(int) $row['age_days']
			);
			if ( ! empty( $row['is_none'] ) ) {
				$age .= ' · ' . __( 'none', 'handl-ai-connector-access-control' );
			}
			$last = (int) $row['last_change'] > 0
				? ( function_exists( 'wp_date' ) ? wp_date( 'Y-m-d', (int) $row['last_change'] ) : gmdate( 'Y-m-d', (int) $row['last_change'] ) )
				: '—';
			echo '<tr>';
			echo '<td>' . esc_html( (string) $row['label'] ) . '<br /><code>' . esc_html( (string) $row['plugin'] ) . '</code></td>';
			echo '<td>' . esc_html( $age ) . '</td>';
			echo '<td>' . esc_html( (string) (int) $row['changes_90d'] ) . '</td>';
			echo '<td>' . esc_html( $last ) . '</td>';
			echo '<td>' . esc_html( ! empty( $row['coincided'] ) ? __( 'Yes', 'handl-ai-connector-access-control' ) : __( 'No', 'handl-ai-connector-access-control' ) ) . '</td>';
			echo '</tr>';
		}
		echo '</tbody></table>';
		echo '</div>';
	}

	public static function handle_save(): void {
		if ( ! class_exists( Caps::class, false ) || ! Caps::user_can_manage() ) {
			wp_die( esc_html__( 'Forbidden', 'handl-ai-connector-access-control' ), 403 );
		}
		if ( function_exists( 'check_admin_referer' ) ) {
			check_admin_referer( self::ACTION_SAVE );
		}
		if ( empty( $_POST[ self::POST_PRESENT ] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing
			self::redirect();

			return;
		}
		self::save_settings(
			array(
				'enabled' => ! empty( $_POST[ self::POST_ENABLED ] ), // phpcs:ignore WordPress.Security.NonceVerification.Missing
			)
		);
		self::redirect();
	}

	private static function redirect(): void {
		$url = self::screen_url();
		if ( function_exists( 'wp_safe_redirect' ) ) {
			wp_safe_redirect( $url );
			exit;
		}
		if ( function_exists( 'wp_redirect' ) ) {
			wp_redirect( $url ); // phpcs:ignore WordPress.Security.SafeRedirect.wp_redirect_wp_redirect
			exit;
		}
	}

	public static function screen_url(): string {
		if ( class_exists( Admin::class, false ) && method_exists( Admin::class, 'screen_url' ) ) {
			// Own page slug — Admin::screen_url is tab-oriented; build directly.
		}
		if ( function_exists( 'admin_url' ) ) {
			return admin_url( 'admin.php?page=' . self::PAGE_SLUG );
		}

		return 'admin.php?page=' . self::PAGE_SLUG;
	}

	public static function plugin_version( string $basename ): string {
		$basename = self::sanitize_plugin( $basename );
		if ( '' === $basename ) {
			return '';
		}
		if ( is_array( self::$test_versions ) && isset( self::$test_versions[ $basename ] ) ) {
			return self::sanitize_version( self::$test_versions[ $basename ] );
		}
		if ( class_exists( Version_Watch::class, false ) && method_exists( Version_Watch::class, 'plugin_version' ) ) {
			return Version_Watch::plugin_version( $basename );
		}
		if ( function_exists( 'get_plugins' ) ) {
			$plugins = get_plugins();
			if ( isset( $plugins[ $basename ]['Version'] ) ) {
				return self::sanitize_version( $plugins[ $basename ]['Version'] );
			}
		}

		return '';
	}

	private static function plugin_label( string $basename ): string {
		if ( '' === $basename ) {
			return __( 'Unknown plugin', 'handl-ai-connector-access-control' );
		}
		if ( ! function_exists( 'get_plugins' ) ) {
			$plugin_php = ABSPATH . 'wp-admin/includes/plugin.php';
			if ( is_string( $plugin_php ) && is_readable( $plugin_php ) ) {
				require_once $plugin_php;
			}
		}
		if ( function_exists( 'get_plugins' ) ) {
			$plugins = get_plugins();
			if ( isset( $plugins[ $basename ]['Name'] ) && is_string( $plugins[ $basename ]['Name'] ) ) {
				return (string) $plugins[ $basename ]['Name'];
			}
		}

		return $basename;
	}

	private static function caller_plugin(): string {
		if ( null !== self::$test_plugin ) {
			return self::sanitize_plugin( self::$test_plugin );
		}
		if ( class_exists( Attribution::class, false ) ) {
			$attrib = Attribution::resolve_from_backtrace();
			if ( is_array( $attrib ) && isset( $attrib['plugin'] ) && is_string( $attrib['plugin'] ) ) {
				return self::sanitize_plugin( $attrib['plugin'] );
			}
		}

		return '';
	}
}
