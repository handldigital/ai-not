<?php
/**
 * AICAC-EMBARGO (#371): unpublished/private content guard for AI payloads.
 *
 * Salted fingerprint index of non-public post content in its OWN option
 * (never the text). Rebuild on save_post / transition_post_status. Payload
 * screen at the shared pre-flight gate (priority 2). Warn-only default via
 * per-class Plugin::LOG_OPTION_KEY append; enforce = embargoed_content deny.
 * Per-post override on own meta key. Own roster + CSV + WP-CLI.
 * OFF by default. No admin.php/policy.php/cost.php/logger edits.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Embargo unpublished WordPress content from leaving via AI payloads.
 */
final class Embargo {

	public const REASON = 'embargoed_content';

	public const SETTINGS_OPTION = 'handl_aicac_embargo';

	public const INDEX_OPTION = 'handl_aicac_embargo_index';

	public const HITS_OPTION = 'handl_aicac_embargo_hits';

	public const META_ALLOW = '_handl_aicac_embargo_allow';

	public const FILTER_PRIORITY = 2;

	public const MODE_WARN = 'warn';

	public const MODE_ENFORCE = 'enforce';

	public const INDEX_CAP = 200;

	public const HASHES_PER_POST = 48;

	public const SHINGLE_WORDS = 8;

	public const MIN_CHUNK = 32;

	public const HITS_CAP = 200;

	public const PAGE_SLUG = 'handl-aicac-embargo';

	public const CHANNEL = 'embargo';

	public const POST_PRESENT = 'handl_aicac_embargo_present';

	public const POST_ENABLED = 'handl_aicac_embargo_enabled';

	public const POST_MODE = 'handl_aicac_embargo_mode';

	public const ACTION_SAVE = 'handl_aicac_embargo_save';

	public const ACTION_REBUILD = 'handl_aicac_embargo_rebuild';

	public const ACTION_META = 'handl_aicac_embargo_meta';

	public const NON_PUBLIC = array( 'draft', 'pending', 'private', 'future' );

	/** @var bool */
	private static $registered = false;

	/**
	 * Test post store: id => {ID,post_status,post_title,post_content,post_password,post_type}.
	 *
	 * @var array<int,array<string,mixed>>|null
	 */
	private static $test_posts = null;

	public static function init(): void {
		if ( self::$registered ) {
			return;
		}
		self::$registered = true;

		add_filter( 'wp_ai_client_prevent_prompt', array( self::class, 'maybe_prevent_prompt' ), self::FILTER_PRIORITY, 2 );
		add_action( 'save_post', array( self::class, 'on_save_post' ), 20, 2 );
		add_action( 'transition_post_status', array( self::class, 'on_transition_status' ), 20, 3 );
		add_action( 'admin_menu', array( self::class, 'register_menu' ), 20 );
		add_action( 'admin_init', array( self::class, 'maybe_handle_csv' ), 5 );
		add_action( 'admin_post_' . self::ACTION_SAVE, array( self::class, 'handle_save' ) );
		add_action( 'admin_post_' . self::ACTION_REBUILD, array( self::class, 'handle_rebuild' ) );
		add_action( 'add_meta_boxes', array( self::class, 'register_metabox' ) );
		add_action( 'save_post', array( self::class, 'save_metabox' ), 15, 2 );
		self::register_cli();
	}

	public static function reset_for_tests(): void {
		self::$registered = false;
		self::$test_posts = null;
		delete_option( self::SETTINGS_OPTION );
		delete_option( self::INDEX_OPTION );
		delete_option( self::HITS_OPTION );
		if ( isset( $GLOBALS['handl_aicac_test_post_meta'] ) && is_array( $GLOBALS['handl_aicac_test_post_meta'] ) ) {
			foreach ( $GLOBALS['handl_aicac_test_post_meta'] as $pid => $meta ) {
				if ( is_array( $meta ) ) {
					unset( $GLOBALS['handl_aicac_test_post_meta'][ $pid ][ self::META_ALLOW ] );
				}
			}
		}
	}

	/**
	 * @internal Tests only.
	 *
	 * @param array<int,array<string,mixed>>|null $posts Posts keyed by id.
	 */
	public static function set_test_posts( ?array $posts ): void {
		self::$test_posts = $posts;
	}

	/**
	 * @return array{enabled:bool,mode:string}
	 */
	public static function defaults(): array {
		return array(
			'enabled' => false,
			'mode'    => self::MODE_WARN,
		);
	}

	/**
	 * @return array{enabled:bool,mode:string}
	 */
	public static function get_settings(): array {
		return self::sanitize_settings( get_option( self::SETTINGS_OPTION, array() ) );
	}

	/**
	 * @param mixed $raw Raw settings.
	 * @return array{enabled:bool,mode:string}
	 */
	public static function sanitize_settings( $raw ): array {
		$defaults = self::defaults();
		if ( ! is_array( $raw ) ) {
			return $defaults;
		}
		$mode = isset( $raw['mode'] ) ? (string) $raw['mode'] : self::MODE_WARN;
		if ( self::MODE_ENFORCE !== $mode ) {
			$mode = self::MODE_WARN;
		}

		return array(
			'enabled' => ! empty( $raw['enabled'] ),
			'mode'    => $mode,
		);
	}

	/**
	 * @param array<string,mixed> $settings Settings.
	 */
	public static function save_settings( array $settings ): bool {
		$clean  = self::sanitize_settings( $settings );
		$before = self::get_settings();
		if ( $clean === $before ) {
			return false;
		}
		if ( $clean === self::defaults() ) {
			delete_option( self::SETTINGS_OPTION );

			return true;
		}
		update_option( self::SETTINGS_OPTION, $clean, false );

		return true;
	}

	public static function is_enabled(): bool {
		return ! empty( self::get_settings()['enabled'] );
	}

	public static function mode(): string {
		return self::get_settings()['mode'];
	}

	public static function salt(): string {
		if ( function_exists( 'wp_salt' ) ) {
			return (string) wp_salt( 'auth' ) . '|' . (string) wp_salt( 'secure_auth' );
		}

		return 'handl-aicac-embargo-test-salt';
	}

	/**
	 * Normalize text for fingerprinting (never persisted).
	 */
	public static function normalize_text( string $text ): string {
		$text = strtolower( $text );
		$text = preg_replace( '/\s+/u', ' ', $text );
		$text = trim( (string) $text );

		return $text;
	}

	/**
	 * Salted shingle hashes for a content blob. Never returns plaintext.
	 *
	 * @return list<string>
	 */
	public static function fingerprints_for_text( string $text, ?string $salt = null ): array {
		$norm = self::normalize_text( $text );
		if ( strlen( $norm ) < self::MIN_CHUNK ) {
			return array();
		}
		$salt   = null !== $salt ? (string) $salt : self::salt();
		$hashes = array();
		$hashes[] = hash_hmac( 'sha256', $norm, $salt );

		$words = preg_split( '/\s+/u', $norm, -1, PREG_SPLIT_NO_EMPTY );
		if ( is_array( $words ) && count( $words ) >= self::SHINGLE_WORDS ) {
			$max = count( $words ) - self::SHINGLE_WORDS;
			for ( $i = 0; $i <= $max; $i++ ) {
				$shingle  = implode( ' ', array_slice( $words, $i, self::SHINGLE_WORDS ) );
				$hashes[] = hash_hmac( 'sha256', $shingle, $salt );
				if ( count( $hashes ) >= self::HASHES_PER_POST ) {
					break;
				}
			}
		}

		// Fixed-width char windows for short dense drafts.
		if ( count( $hashes ) < self::HASHES_PER_POST && strlen( $norm ) >= self::MIN_CHUNK ) {
			$win = 48;
			$len = strlen( $norm );
			for ( $i = 0; $i + $win <= $len; $i += 24 ) {
				$hashes[] = hash_hmac( 'sha256', substr( $norm, $i, $win ), $salt );
				if ( count( $hashes ) >= self::HASHES_PER_POST ) {
					break;
				}
			}
		}

		return array_values( array_unique( $hashes ) );
	}

	/**
	 * Whether a post status / password marks content non-public.
	 *
	 * @param object|array<string,mixed> $post Post-like.
	 */
	public static function is_non_public( $post ): bool {
		$status   = self::post_field( $post, 'post_status' );
		$password = self::post_field( $post, 'post_password' );
		if ( '' !== trim( (string) $password ) ) {
			return true;
		}

		return in_array( (string) $status, self::NON_PUBLIC, true );
	}

	/**
	 * @param object|array<string,mixed> $post Post-like.
	 * @return array{id:int,status:string,title:string,updated:int,hashes:list<string>}|null
	 */
	public static function entry_from_post( $post ): ?array {
		$id = (int) self::post_field( $post, 'ID' );
		if ( $id <= 0 ) {
			return null;
		}
		if ( ! self::is_non_public( $post ) ) {
			return null;
		}
		$content = (string) self::post_field( $post, 'post_content' );
		$title   = (string) self::post_field( $post, 'post_title' );
		$blob    = trim( $title . "\n" . $content );
		$hashes  = self::fingerprints_for_text( $blob );
		if ( empty( $hashes ) ) {
			return null;
		}

		return array(
			'id'      => $id,
			'status'  => (string) self::post_field( $post, 'post_status' ),
			'title'   => self::sanitize_title( $title ),
			'updated' => Clock::now(),
			'hashes'  => $hashes,
		);
	}

	/**
	 * @return array{built:int,posts:array<string,array{id:int,status:string,title:string,updated:int,hashes:list<string>}>}
	 */
	public static function get_index(): array {
		$raw = get_option( self::INDEX_OPTION, array() );
		if ( ! is_array( $raw ) ) {
			return array(
				'built' => 0,
				'posts' => array(),
			);
		}
		$posts = array();
		$src   = isset( $raw['posts'] ) && is_array( $raw['posts'] ) ? $raw['posts'] : $raw;
		foreach ( $src as $key => $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$id = isset( $row['id'] ) ? (int) $row['id'] : (int) $key;
			if ( $id <= 0 ) {
				continue;
			}
			$hashes = array();
			if ( isset( $row['hashes'] ) && is_array( $row['hashes'] ) ) {
				foreach ( $row['hashes'] as $h ) {
					$h = (string) $h;
					if ( preg_match( '/^[a-f0-9]{64}$/', $h ) ) {
						$hashes[] = $h;
					}
				}
			}
			if ( empty( $hashes ) ) {
				continue;
			}
			$posts[ (string) $id ] = array(
				'id'      => $id,
				'status'  => isset( $row['status'] ) ? sanitize_key( (string) $row['status'] ) : '',
				'title'   => self::sanitize_title( isset( $row['title'] ) ? (string) $row['title'] : '' ),
				'updated' => isset( $row['updated'] ) ? max( 0, (int) $row['updated'] ) : 0,
				'hashes'  => array_values( array_unique( $hashes ) ),
			);
		}

		return array(
			'built' => isset( $raw['built'] ) ? max( 0, (int) $raw['built'] ) : 0,
			'posts' => $posts,
		);
	}

	/**
	 * @param array{built?:int,posts?:array<string,array{id:int,status:string,title:string,updated:int,hashes:list<string>}>} $index Index.
	 */
	public static function save_index( array $index ): void {
		$posts = isset( $index['posts'] ) && is_array( $index['posts'] ) ? $index['posts'] : array();
		uasort(
			$posts,
			static function ( $a, $b ) {
				return ( (int) ( $b['updated'] ?? 0 ) ) <=> ( (int) ( $a['updated'] ?? 0 ) );
			}
		);
		if ( count( $posts ) > self::INDEX_CAP ) {
			$posts = array_slice( $posts, 0, self::INDEX_CAP, true );
		}
		if ( empty( $posts ) ) {
			delete_option( self::INDEX_OPTION );

			return;
		}
		update_option(
			self::INDEX_OPTION,
			array(
				'built' => isset( $index['built'] ) ? max( 0, (int) $index['built'] ) : Clock::now(),
				'posts' => $posts,
			),
			false
		);
	}

	/**
	 * Upsert or prune one post in the fingerprint index.
	 *
	 * @param object|array<string,mixed>|int $post Post or id.
	 */
	public static function index_post( $post ): void {
		if ( is_numeric( $post ) ) {
			$post = self::load_post( (int) $post );
		}
		if ( null === $post ) {
			return;
		}
		$id    = (int) self::post_field( $post, 'ID' );
		$index = self::get_index();
		if ( ! self::is_non_public( $post ) ) {
			unset( $index['posts'][ (string) $id ] );
			$index['built'] = Clock::now();
			self::save_index( $index );

			return;
		}
		$entry = self::entry_from_post( $post );
		if ( null === $entry ) {
			unset( $index['posts'][ (string) $id ] );
		} else {
			$index['posts'][ (string) $id ] = $entry;
		}
		$index['built'] = Clock::now();
		self::save_index( $index );
	}

	/**
	 * Full rebuild from non-public posts (capped).
	 *
	 * @param list<object|array<string,mixed>>|null $posts Optional post list (tests).
	 * @return int Indexed post count.
	 */
	public static function rebuild_index( ?array $posts = null ): int {
		if ( null === $posts ) {
			$posts = self::fetch_non_public_posts();
		}
		$out = array();
		foreach ( $posts as $post ) {
			$entry = self::entry_from_post( $post );
			if ( null === $entry ) {
				continue;
			}
			$out[ (string) $entry['id'] ] = $entry;
		}
		uasort(
			$out,
			static function ( $a, $b ) {
				return ( (int) ( $b['updated'] ?? 0 ) ) <=> ( (int) ( $a['updated'] ?? 0 ) );
			}
		);
		if ( count( $out ) > self::INDEX_CAP ) {
			$out = array_slice( $out, 0, self::INDEX_CAP, true );
		}
		self::save_index(
			array(
				'built' => Clock::now(),
				'posts' => $out,
			)
		);

		return count( $out );
	}

	/**
	 * @return list<object|array<string,mixed>>
	 */
	public static function fetch_non_public_posts(): array {
		if ( null !== self::$test_posts ) {
			return array_values( self::$test_posts );
		}
		if ( ! function_exists( 'get_posts' ) ) {
			return array();
		}
		$posts = get_posts(
			array(
				'post_type'              => 'any',
				'post_status'            => self::NON_PUBLIC,
				'posts_per_page'         => self::INDEX_CAP,
				'orderby'                => 'modified',
				'order'                  => 'DESC',
				'no_found_rows'          => true,
				'update_post_meta_cache' => false,
				'update_post_term_cache' => false,
			)
		);
		if ( ! is_array( $posts ) ) {
			return array();
		}
		// Password-protected published posts are also embargoed.
		$protected = get_posts(
			array(
				'post_type'              => 'any',
				'post_status'            => 'publish',
				'has_password'           => true,
				'posts_per_page'         => self::INDEX_CAP,
				'orderby'                => 'modified',
				'order'                  => 'DESC',
				'no_found_rows'          => true,
				'update_post_meta_cache' => false,
				'update_post_term_cache' => false,
			)
		);
		if ( is_array( $protected ) ) {
			$posts = array_merge( $posts, $protected );
		}

		return $posts;
	}

	/**
	 * @param int $post_id Post id.
	 * @return object|array<string,mixed>|null
	 */
	public static function load_post( int $post_id ) {
		if ( $post_id <= 0 ) {
			return null;
		}
		if ( null !== self::$test_posts && isset( self::$test_posts[ $post_id ] ) ) {
			return self::$test_posts[ $post_id ];
		}
		if ( function_exists( 'get_post' ) ) {
			$post = get_post( $post_id );
			if ( null !== $post && false !== $post ) {
				return $post;
			}
		}

		return null;
	}

	/**
	 * Match payload text against the fingerprint index.
	 *
	 * @return array{post_id:int,title:string,status:string}|null
	 */
	public static function match_payload( string $text ): ?array {
		$payload_hashes = self::fingerprints_for_text( $text );
		if ( empty( $payload_hashes ) ) {
			return null;
		}
		$lookup = array_fill_keys( $payload_hashes, true );
		$index  = self::get_index();
		foreach ( $index['posts'] as $row ) {
			$id = (int) ( $row['id'] ?? 0 );
			if ( $id <= 0 || self::is_override_allowed( $id ) ) {
				continue;
			}
			foreach ( $row['hashes'] as $h ) {
				if ( isset( $lookup[ $h ] ) ) {
					return array(
						'post_id' => $id,
						'title'   => (string) ( $row['title'] ?? '' ),
						'status'  => (string) ( $row['status'] ?? '' ),
					);
				}
			}
		}

		return null;
	}

	public static function is_override_allowed( int $post_id ): bool {
		if ( $post_id <= 0 || ! function_exists( 'get_post_meta' ) ) {
			return false;
		}
		$raw = get_post_meta( $post_id, self::META_ALLOW, true );

		return '1' === (string) $raw || 1 === $raw || true === $raw;
	}

	public static function set_override( int $post_id, bool $allow ): void {
		if ( $post_id <= 0 || ! function_exists( 'update_post_meta' ) ) {
			return;
		}
		if ( $allow ) {
			update_post_meta( $post_id, self::META_ALLOW, '1' );
		} elseif ( function_exists( 'delete_post_meta' ) ) {
			delete_post_meta( $post_id, self::META_ALLOW );
		} else {
			update_post_meta( $post_id, self::META_ALLOW, '0' );
		}
	}

	/**
	 * Gate filter at priority 2 (same slot as USER-QUOTA / DORMANT / CIRCUIT-BREAKER / AUP).
	 *
	 * @param mixed $prevent Prior filter result.
	 * @param mixed $builder Prompt builder.
	 */
	public static function maybe_prevent_prompt( $prevent, $builder ): bool {
		if ( $prevent ) {
			return true;
		}
		if ( ! self::is_enabled() ) {
			return false;
		}

		$policy = Policy::get_policy();
		if ( ! empty( $policy['audit_only'] ) ) {
			return false;
		}
		if ( class_exists( Break_Glass::class, false ) && method_exists( Break_Glass::class, 'is_active' ) && Break_Glass::is_active() ) {
			return false;
		}

		$text = self::payload_text( $builder );
		if ( '' === $text ) {
			return false;
		}

		$hit = self::match_payload( $text );
		if ( null === $hit ) {
			return false;
		}

		$mode      = self::mode();
		$now       = Clock::now();
		$user_id   = Policy::current_user_id_for_gate();
		$attrib    = Attribution::resolve_from_backtrace();
		$plugin    = is_string( $attrib['plugin'] ?? null ) ? (string) $attrib['plugin'] : null;
		$snapshot  = class_exists( Prompt_Snapshot::class, false ) ? Prompt_Snapshot::from_builder( $builder ) : array();
		$operation = isset( $snapshot['operation'] ) ? (string) $snapshot['operation'] : '';
		$family    = isset( $snapshot['capability_family'] ) && is_string( $snapshot['capability_family'] )
			? (string) $snapshot['capability_family']
			: ( class_exists( Operations::class, false ) ? Operations::family_from_operation( $operation ) : '' );

		$base = array_merge(
			array(
				'ts'                => $now,
				'plugin'            => $plugin,
				'file'              => $attrib['file'] ?? null,
				'caller'            => $attrib['method'] ?? null,
				'capability_family' => $family,
				'user_id'           => $user_id,
				'user_role'         => Policy::current_user_role_for_log(),
				'embargo'           => $mode,
				'embargo_hit'       => (int) $hit['post_id'],
				'channel'           => self::CHANNEL,
				'uri'               => isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( (string) $_SERVER['REQUEST_URI'] ) ) : null,
			),
			is_array( $snapshot ) ? $snapshot : array()
		);

		self::record_hit(
			array(
				'ts'      => $now,
				'post_id' => (int) $hit['post_id'],
				'user_id' => $user_id,
				'plugin'  => $plugin,
				'mode'    => $mode,
			)
		);

		if ( self::MODE_WARN === $mode ) {
			$event = array_merge(
				$base,
				array(
					'decision'        => 'allow',
					'would_decision'  => 'deny',
					'decision_source' => 'embargo_warn',
					'denial_reason'   => '',
				)
			);
			self::append_activity( $event );

			return false;
		}

		$event = array_merge(
			$base,
			array(
				'decision'        => 'deny',
				'would_decision'  => 'deny',
				'denial_reason'   => self::REASON,
				'decision_source' => self::REASON,
			)
		);

		self::reclassify_latest_allow( $event );

		$soft = false;
		if ( class_exists( Soft_Deny::class, false ) && method_exists( Soft_Deny::class, 'maybe_arm_from_deny' ) ) {
			$soft = Soft_Deny::maybe_arm_from_deny(
				true,
				$event,
				$policy,
				is_string( $plugin ) ? $plugin : null,
				$operation,
				$family
			);
		}

		self::append_activity( $event );

		$suppress = class_exists( Retry_Storm::class, false ) && method_exists( Retry_Storm::class, 'should_suppress_deny_alert' )
			&& Retry_Storm::should_suppress_deny_alert( $event, $policy );
		if ( class_exists( Alerts::class, false ) && method_exists( Alerts::class, 'maybe_notify_denial' ) && ! $suppress ) {
			Alerts::maybe_notify_denial( $event, $policy );
		}
		if ( class_exists( Access_Request::class, false ) && method_exists( Access_Request::class, 'note_deny' ) ) {
			Access_Request::note_deny( $event );
		}

		return $soft ? false : true;
	}

	/**
	 * @param mixed $builder Prompt builder.
	 */
	public static function payload_text( $builder ): string {
		if ( class_exists( Pii_Warn::class, false ) && method_exists( Pii_Warn::class, 'payload_text_from_builder' ) ) {
			$text = Pii_Warn::payload_text_from_builder( $builder );
			if ( is_string( $text ) && '' !== $text ) {
				return $text;
			}
		}
		if ( is_string( $builder ) ) {
			return $builder;
		}
		if ( is_object( $builder ) && isset( $builder->handl_aicac_test_payload ) && is_string( $builder->handl_aicac_test_payload ) ) {
			return (string) $builder->handl_aicac_test_payload;
		}

		return '';
	}

	/**
	 * @param array<string,mixed> $event Deny event.
	 */
	public static function reclassify_latest_allow( array $event ): void {
		$policy = Policy::get_policy();
		if ( empty( $policy['log_enabled'] ) && empty( $policy['audit_only'] ) ) {
			return;
		}
		$log = get_option( Plugin::LOG_OPTION_KEY );
		if ( ! is_array( $log ) || empty( $log ) ) {
			return;
		}
		$i    = count( $log ) - 1;
		$last = $log[ $i ];
		if ( ! is_array( $last ) ) {
			return;
		}
		if ( 'allow' !== (string) ( $last['decision'] ?? '' ) ) {
			return;
		}
		if ( (int) ( $last['user_id'] ?? 0 ) !== (int) ( $event['user_id'] ?? 0 ) ) {
			return;
		}
		$last_ts  = (int) ( $last['ts'] ?? 0 );
		$event_ts = (int) ( $event['ts'] ?? 0 );
		if ( $last_ts > 0 && $event_ts > 0 && abs( $last_ts - $event_ts ) > 5 ) {
			return;
		}
		array_pop( $log );
		update_option( Plugin::LOG_OPTION_KEY, $log, false );
	}

	/**
	 * @param array<string,mixed> $event Activity row.
	 */
	public static function append_activity( array $event ): void {
		if ( class_exists( Policy::class, false ) && method_exists( Policy::class, 'append_log_event' ) ) {
			Policy::append_log_event( $event );

			return;
		}
		$log = get_option( Plugin::LOG_OPTION_KEY, array() );
		if ( ! is_array( $log ) ) {
			$log = array();
		}
		$log[] = $event;
		if ( count( $log ) > 200 ) {
			$log = array_slice( $log, -200 );
		}
		update_option( Plugin::LOG_OPTION_KEY, $log, false );
	}

	/**
	 * @param array{ts:int,post_id:int,user_id:int,plugin:?string,mode:string} $hit Hit.
	 */
	public static function record_hit( array $hit ): void {
		$hits   = self::hits();
		$hits[] = array(
			'ts'      => (int) ( $hit['ts'] ?? Clock::now() ),
			'post_id' => (int) ( $hit['post_id'] ?? 0 ),
			'user_id' => (int) ( $hit['user_id'] ?? 0 ),
			'plugin'  => isset( $hit['plugin'] ) && is_string( $hit['plugin'] ) ? $hit['plugin'] : null,
			'mode'    => self::MODE_ENFORCE === ( $hit['mode'] ?? '' ) ? self::MODE_ENFORCE : self::MODE_WARN,
		);
		if ( count( $hits ) > self::HITS_CAP ) {
			$hits = array_slice( $hits, -self::HITS_CAP );
		}
		update_option( self::HITS_OPTION, $hits, false );
	}

	/**
	 * @return list<array{ts:int,post_id:int,user_id:int,plugin:?string,mode:string}>
	 */
	public static function hits(): array {
		$raw = get_option( self::HITS_OPTION, array() );
		if ( ! is_array( $raw ) ) {
			return array();
		}
		$out = array();
		foreach ( $raw as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$out[] = array(
				'ts'      => (int) ( $row['ts'] ?? 0 ),
				'post_id' => (int) ( $row['post_id'] ?? 0 ),
				'user_id' => (int) ( $row['user_id'] ?? 0 ),
				'plugin'  => isset( $row['plugin'] ) && is_string( $row['plugin'] ) ? $row['plugin'] : null,
				'mode'    => self::MODE_ENFORCE === ( $row['mode'] ?? '' ) ? self::MODE_ENFORCE : self::MODE_WARN,
			);
		}

		return $out;
	}

	/**
	 * Indexed posts for roster UI.
	 *
	 * @return list<array{id:int,status:string,title:string,updated:int,hash_count:int,override:bool}>
	 */
	public static function indexed_roster(): array {
		$index = self::get_index();
		$out   = array();
		foreach ( $index['posts'] as $row ) {
			$id    = (int) ( $row['id'] ?? 0 );
			$out[] = array(
				'id'         => $id,
				'status'     => (string) ( $row['status'] ?? '' ),
				'title'      => (string) ( $row['title'] ?? '' ),
				'updated'    => (int) ( $row['updated'] ?? 0 ),
				'hash_count' => count( $row['hashes'] ?? array() ),
				'override'   => self::is_override_allowed( $id ),
			);
		}

		return $out;
	}

	/**
	 * @param int  $post_id Post id.
	 * @param int  $post    Unused WP arg when hooked as save_post.
	 * @param mixed $_post  Post object when called as save_post.
	 */
	public static function on_save_post( $post_id, $post = null ): void {
		$post_id = (int) $post_id;
		if ( $post_id <= 0 ) {
			return;
		}
		if ( defined( 'DOING_AUTOSAVE' ) && DOING_AUTOSAVE ) {
			return;
		}
		if ( null !== $post && ( is_object( $post ) || is_array( $post ) ) ) {
			self::index_post( $post );

			return;
		}
		self::index_post( $post_id );
	}

	/**
	 * @param string               $new_status New status.
	 * @param string               $old_status Old status.
	 * @param object|array<string,mixed> $post Post.
	 */
	public static function on_transition_status( $new_status, $old_status, $post ): void {
		unset( $old_status );
		if ( null === $post ) {
			return;
		}
		// Publishing / making public drops the post from the index.
		if ( 'publish' === (string) $new_status && '' === trim( (string) self::post_field( $post, 'post_password' ) ) ) {
			$id    = (int) self::post_field( $post, 'ID' );
			$index = self::get_index();
			unset( $index['posts'][ (string) $id ] );
			$index['built'] = Clock::now();
			self::save_index( $index );

			return;
		}
		self::index_post( $post );
	}

	public static function register_menu(): void {
		if ( ! Caps::user_can_view() ) {
			return;
		}
		if ( ! function_exists( 'add_submenu_page' ) ) {
			return;
		}
		add_submenu_page(
			Admin::MENU_SLUG,
			__( 'AI content embargo', 'handl-ai-connector-access-control' ),
			__( 'Content embargo', 'handl-ai-connector-access-control' ),
			Caps::VIEW,
			self::PAGE_SLUG,
			array( self::class, 'render_page' )
		);
	}

	public static function render_page(): void {
		if ( ! Caps::user_can_view() ) {
			return;
		}
		$settings   = self::get_settings();
		$can_manage = Caps::user_can_manage();
		$index      = self::get_index();
		$csv        = add_query_arg(
			array(
				'page'                    => self::PAGE_SLUG,
				'handl_aicac_embargo_csv' => '1',
				'_wpnonce'                => function_exists( 'wp_create_nonce' ) ? wp_create_nonce( 'handl_aicac_embargo_csv' ) : '',
			),
			admin_url( 'admin.php' )
		);

		echo '<div class="wrap">';
		echo '<h1>' . esc_html__( 'AI content embargo', 'handl-ai-connector-access-control' ) . '</h1>';
		echo '<p class="description">' . esc_html__( 'Flag or block AI payloads that contain unpublished or private post content. Off by default. Fingerprints are salted hashes — post text is never stored.', 'handl-ai-connector-access-control' ) . '</p>';

		if ( $can_manage ) {
			$action = admin_url( 'admin-post.php' );
			echo '<form method="post" action="' . esc_url( $action ) . '">';
			echo '<input type="hidden" name="action" value="' . esc_attr( self::ACTION_SAVE ) . '" />';
			if ( function_exists( 'wp_nonce_field' ) ) {
				wp_nonce_field( self::ACTION_SAVE );
			}
			echo '<input type="hidden" name="' . esc_attr( self::POST_PRESENT ) . '" value="1" />';
			echo '<table class="form-table" role="presentation"><tbody>';
			echo '<tr><th scope="row">' . esc_html__( 'Enable embargo', 'handl-ai-connector-access-control' ) . '</th><td>';
			echo '<label><input type="checkbox" name="' . esc_attr( self::POST_ENABLED ) . '" value="1" ' . checked( ! empty( $settings['enabled'] ), true, false ) . ' /> ';
			echo esc_html__( 'Screen AI payloads for unpublished / private post content', 'handl-ai-connector-access-control' );
			echo '</label></td></tr>';
			echo '<tr><th scope="row">' . esc_html__( 'Mode', 'handl-ai-connector-access-control' ) . '</th><td>';
			echo '<label><input type="radio" name="' . esc_attr( self::POST_MODE ) . '" value="' . esc_attr( self::MODE_WARN ) . '" ' . checked( self::MODE_WARN === $settings['mode'], true, false ) . ' /> ';
			echo esc_html__( 'Warn only (allow + annotate activity)', 'handl-ai-connector-access-control' ) . '</label><br />';
			echo '<label><input type="radio" name="' . esc_attr( self::POST_MODE ) . '" value="' . esc_attr( self::MODE_ENFORCE ) . '" ' . checked( self::MODE_ENFORCE === $settings['mode'], true, false ) . ' /> ';
			echo esc_html__( 'Enforce (deny with embargoed_content)', 'handl-ai-connector-access-control' ) . '</label>';
			echo '</td></tr></tbody></table>';
			submit_button( __( 'Save content embargo', 'handl-ai-connector-access-control' ) );
			echo '</form>';

			echo '<form method="post" action="' . esc_url( $action ) . '" style="margin-top:12px;">';
			echo '<input type="hidden" name="action" value="' . esc_attr( self::ACTION_REBUILD ) . '" />';
			if ( function_exists( 'wp_nonce_field' ) ) {
				wp_nonce_field( self::ACTION_REBUILD );
			}
			submit_button( __( 'Rebuild fingerprint index', 'handl-ai-connector-access-control' ), 'secondary', 'submit', false );
			echo '</form>';
		}

		echo '<p class="description">' . esc_html(
			sprintf(
				/* translators: 1: indexed post count, 2: last rebuild timestamp */
				__( 'Indexed posts: %1$d. Last rebuild: %2$s.', 'handl-ai-connector-access-control' ),
				count( $index['posts'] ),
				self::format_ts( (int) $index['built'] )
			)
		) . '</p>';

		echo '<h2>' . esc_html__( 'Indexed unpublished posts', 'handl-ai-connector-access-control' ) . '</h2>';
		$rows = self::indexed_roster();
		if ( empty( $rows ) ) {
			echo '<p>' . esc_html__( 'No non-public posts are indexed yet. Save a draft or rebuild.', 'handl-ai-connector-access-control' ) . '</p>';
		} else {
			echo '<table class="widefat striped"><thead><tr>';
			echo '<th>' . esc_html__( 'Post', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Status', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Fingerprints', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'AI override', 'handl-ai-connector-access-control' ) . '</th>';
			echo '</tr></thead><tbody>';
			foreach ( $rows as $r ) {
				echo '<tr><td>' . esc_html( '' !== $r['title'] ? (string) $r['title'] : ( '#' . (int) $r['id'] ) ) . ' <span class="description">#' . esc_html( (string) (int) $r['id'] ) . '</span></td>';
				echo '<td>' . esc_html( (string) $r['status'] ) . '</td>';
				echo '<td>' . esc_html( (string) (int) $r['hash_count'] ) . '</td>';
				echo '<td>' . esc_html( ! empty( $r['override'] ) ? __( 'Allowed', 'handl-ai-connector-access-control' ) : '—' ) . '</td></tr>';
			}
			echo '</tbody></table>';
		}

		echo '<h2>' . esc_html__( 'Recent embargo hits', 'handl-ai-connector-access-control' ) . '</h2>';
		echo '<p><a class="button" href="' . esc_url( $csv ) . '">' . esc_html__( 'Download CSV', 'handl-ai-connector-access-control' ) . '</a></p>';
		$hits = array_reverse( self::hits() );
		if ( empty( $hits ) ) {
			echo '<p>' . esc_html__( 'No embargo hits recorded yet.', 'handl-ai-connector-access-control' ) . '</p>';
		} else {
			echo '<table class="widefat striped"><thead><tr>';
			echo '<th>' . esc_html__( 'When', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Post', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'User', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Plugin', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Mode', 'handl-ai-connector-access-control' ) . '</th>';
			echo '</tr></thead><tbody>';
			foreach ( array_slice( $hits, 0, 100 ) as $h ) {
				echo '<tr><td>' . esc_html( self::format_ts( (int) $h['ts'] ) ) . '</td>';
				echo '<td>#' . esc_html( (string) (int) $h['post_id'] ) . '</td>';
				echo '<td>' . esc_html( (string) (int) $h['user_id'] ) . '</td>';
				echo '<td>' . esc_html( null !== $h['plugin'] ? (string) $h['plugin'] : '—' ) . '</td>';
				echo '<td>' . esc_html( (string) $h['mode'] ) . '</td></tr>';
			}
			echo '</tbody></table>';
		}
		echo '</div>';
	}

	public static function maybe_handle_csv(): void {
		if ( function_exists( 'is_admin' ) && ! is_admin() ) {
			return;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$page = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( (string) $_GET['page'] ) ) : '';
		if ( self::PAGE_SLUG !== $page ) {
			return;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$action = isset( $_GET['handl_aicac_embargo_csv'] ) ? sanitize_key( wp_unslash( (string) $_GET['handl_aicac_embargo_csv'] ) ) : '';
		if ( '1' !== $action ) {
			return;
		}
		if ( ! Caps::user_can_view() ) {
			if ( function_exists( 'wp_die' ) ) {
				wp_die( esc_html__( 'You do not have permission to export this list.', 'handl-ai-connector-access-control' ) );
			}
			return;
		}
		check_admin_referer( 'handl_aicac_embargo_csv' );
		$csv = self::csv_for_hits();
		if ( function_exists( 'nocache_headers' ) ) {
			nocache_headers();
		}
		header( 'Content-Type: text/csv; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename="handl-aicac-embargo-hits.csv"' );
		// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- raw CSV download body.
		echo $csv;
		exit;
	}

	public static function csv_for_hits(): string {
		$lines = array( self::csv_line( array( 'ts', 'post_id', 'user_id', 'plugin', 'mode' ) ) );
		foreach ( self::hits() as $h ) {
			$lines[] = self::csv_line(
				array(
					(string) (int) $h['ts'],
					(string) (int) $h['post_id'],
					(string) (int) $h['user_id'],
					null !== $h['plugin'] ? (string) $h['plugin'] : '',
					(string) $h['mode'],
				)
			);
		}

		return implode( "\n", $lines ) . "\n";
	}

	/**
	 * @param list<string> $fields Fields.
	 */
	private static function csv_line( array $fields ): string {
		$out = array();
		foreach ( $fields as $f ) {
			$f = str_replace( '"', '""', (string) $f );
			if ( preg_match( '/[",\n\r]/', $f ) ) {
				$out[] = '"' . $f . '"';
			} else {
				$out[] = $f;
			}
		}

		return implode( ',', $out );
	}

	public static function handle_save(): void {
		if ( ! Caps::user_can_manage() ) {
			if ( function_exists( 'wp_die' ) ) {
				wp_die( esc_html__( 'You do not have permission to save this setting.', 'handl-ai-connector-access-control' ) );
			}
			return;
		}
		check_admin_referer( self::ACTION_SAVE );
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		$enabled = ! empty( $_POST[ self::POST_ENABLED ] );
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		$mode = isset( $_POST[ self::POST_MODE ] ) ? sanitize_key( wp_unslash( (string) $_POST[ self::POST_MODE ] ) ) : self::MODE_WARN;
		self::save_settings(
			array(
				'enabled' => $enabled,
				'mode'    => $mode,
			)
		);
		if ( $enabled && empty( self::get_index()['posts'] ) ) {
			self::rebuild_index();
		}
		$redirect = add_query_arg(
			array(
				'page'    => self::PAGE_SLUG,
				'updated' => '1',
			),
			admin_url( 'admin.php' )
		);
		if ( function_exists( 'wp_safe_redirect' ) ) {
			wp_safe_redirect( $redirect );
			exit;
		}
	}

	public static function handle_rebuild(): void {
		if ( ! Caps::user_can_manage() ) {
			if ( function_exists( 'wp_die' ) ) {
				wp_die( esc_html__( 'You do not have permission to rebuild the index.', 'handl-ai-connector-access-control' ) );
			}
			return;
		}
		check_admin_referer( self::ACTION_REBUILD );
		$count = self::rebuild_index();
		$redirect = add_query_arg(
			array(
				'page'    => self::PAGE_SLUG,
				'rebuilt' => (string) $count,
			),
			admin_url( 'admin.php' )
		);
		if ( function_exists( 'wp_safe_redirect' ) ) {
			wp_safe_redirect( $redirect );
			exit;
		}
	}

	public static function register_metabox(): void {
		if ( ! function_exists( 'add_meta_box' ) ) {
			return;
		}
		add_meta_box(
			'handl-aicac-embargo',
			__( 'AI content embargo', 'handl-ai-connector-access-control' ),
			array( self::class, 'render_metabox' ),
			null,
			'side',
			'default'
		);
	}

	/**
	 * @param \WP_Post|object $post Post.
	 */
	public static function render_metabox( $post ): void {
		if ( ! is_object( $post ) && ! is_array( $post ) ) {
			return;
		}
		$id = (int) self::post_field( $post, 'ID' );
		if ( $id <= 0 ) {
			return;
		}
		if ( function_exists( 'wp_nonce_field' ) ) {
			wp_nonce_field( self::ACTION_META, 'handl_aicac_embargo_meta_nonce' );
		}
		$allowed = self::is_override_allowed( $id );
		echo '<p><label><input type="checkbox" name="handl_aicac_embargo_allow" value="1" ' . checked( $allowed, true, false ) . ' /> ';
		echo esc_html__( 'Allow AI on this unpublished / private post', 'handl-ai-connector-access-control' );
		echo '</label></p>';
		echo '<p class="description">' . esc_html__( 'When checked, this post is skipped by the content embargo guard.', 'handl-ai-connector-access-control' ) . '</p>';
	}

	/**
	 * @param int                        $post_id Post id.
	 * @param \WP_Post|object|null       $post    Post.
	 */
	public static function save_metabox( $post_id, $post = null ): void {
		unset( $post );
		$post_id = (int) $post_id;
		if ( $post_id <= 0 ) {
			return;
		}
		if ( defined( 'DOING_AUTOSAVE' ) && DOING_AUTOSAVE ) {
			return;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		if ( empty( $_POST['handl_aicac_embargo_meta_nonce'] ) ) {
			return;
		}
		if ( function_exists( 'wp_verify_nonce' ) && ! wp_verify_nonce( sanitize_text_field( wp_unslash( (string) $_POST['handl_aicac_embargo_meta_nonce'] ) ), self::ACTION_META ) ) {
			return;
		}
		if ( function_exists( 'current_user_can' ) && ! current_user_can( 'edit_post', $post_id ) ) {
			return;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		$allow = ! empty( $_POST['handl_aicac_embargo_allow'] );
		self::set_override( $post_id, $allow );
	}

	private static function format_ts( int $ts ): string {
		if ( $ts <= 0 ) {
			return '—';
		}
		if ( function_exists( 'wp_date' ) ) {
			return (string) wp_date( 'Y-m-d H:i', $ts );
		}

		return gmdate( 'Y-m-d H:i', $ts );
	}

	private static function sanitize_title( string $title ): string {
		$title = trim( $title );
		if ( function_exists( 'sanitize_text_field' ) ) {
			$title = sanitize_text_field( $title );
		}
		if ( strlen( $title ) > 200 ) {
			$title = substr( $title, 0, 200 );
		}

		return $title;
	}

	/**
	 * @param object|array<string,mixed> $post Post-like.
	 * @param string                     $key  Field.
	 * @return mixed
	 */
	private static function post_field( $post, string $key ) {
		if ( is_array( $post ) ) {
			return $post[ $key ] ?? null;
		}
		if ( is_object( $post ) ) {
			return $post->{$key} ?? null;
		}

		return null;
	}

	public static function register_cli(): void {
		if ( ! defined( 'WP_CLI' ) || ! WP_CLI ) {
			return;
		}
		if ( ! class_exists( '\WP_CLI' ) ) {
			return;
		}
		\WP_CLI::add_command( 'handl-aicac embargo', CLI_Embargo::class );
	}
}

/**
 * WP-CLI: wp handl-aicac embargo status|rebuild|check|hits
 */
final class CLI_Embargo {

	/**
	 * Show embargo status.
	 *
	 * ## OPTIONS
	 *
	 * @when after_wp_load
	 *
	 * @param list<string>             $args       Positional.
	 * @param array<string,string|int> $assoc_args Flags.
	 */
	public function status( $args, $assoc_args ): void {
		unset( $args, $assoc_args );
		$settings = Embargo::get_settings();
		$index    = Embargo::get_index();
		\WP_CLI::log(
			sprintf(
				'enabled=%s mode=%s indexed=%d built=%d hits=%d',
				! empty( $settings['enabled'] ) ? 'yes' : 'no',
				(string) $settings['mode'],
				count( $index['posts'] ),
				(int) $index['built'],
				count( Embargo::hits() )
			)
		);
	}

	/**
	 * Rebuild the fingerprint index.
	 *
	 * @when after_wp_load
	 *
	 * @param list<string>             $args       Positional.
	 * @param array<string,string|int> $assoc_args Flags.
	 */
	public function rebuild( $args, $assoc_args ): void {
		unset( $args, $assoc_args );
		$count = Embargo::rebuild_index();
		\WP_CLI::success( 'Indexed ' . $count . ' non-public posts.' );
	}

	/**
	 * Check whether a post is indexed / would match sample text.
	 *
	 * ## OPTIONS
	 *
	 * <post_id>
	 * : Post ID.
	 *
	 * [--text=<text>]
	 * : Optional payload text to screen.
	 *
	 * @when after_wp_load
	 *
	 * @param list<string>             $args       Positional.
	 * @param array<string,string|int> $assoc_args Flags.
	 */
	public function check( $args, $assoc_args ): void {
		$post_id = isset( $args[0] ) ? (int) $args[0] : 0;
		if ( $post_id <= 0 ) {
			\WP_CLI::error( 'Need a post id.' );
		}
		$index  = Embargo::get_index();
		$in     = isset( $index['posts'][ (string) $post_id ] );
		$allow  = Embargo::is_override_allowed( $post_id );
		\WP_CLI::log(
			sprintf(
				'post=%d indexed=%s override=%s',
				$post_id,
				$in ? 'yes' : 'no',
				$allow ? 'yes' : 'no'
			)
		);
		if ( isset( $assoc_args['text'] ) ) {
			$hit = Embargo::match_payload( (string) $assoc_args['text'] );
			if ( null === $hit ) {
				\WP_CLI::log( 'match=none' );
			} else {
				\WP_CLI::log( 'match=post#' . (int) $hit['post_id'] );
			}
		}
	}

	/**
	 * List recent embargo hits.
	 *
	 * ## OPTIONS
	 *
	 * [--format=<format>]
	 * : table, json, csv, or yaml.
	 *
	 * @when after_wp_load
	 *
	 * @param list<string>             $args       Positional.
	 * @param array<string,string|int> $assoc_args Flags.
	 */
	public function hits( $args, $assoc_args ): void {
		unset( $args );
		$format = isset( $assoc_args['format'] ) ? (string) $assoc_args['format'] : 'table';
		$rows   = Embargo::hits();
		if ( empty( $rows ) ) {
			\WP_CLI::log( 'No embargo hits.' );
			return;
		}
		$table = array();
		foreach ( $rows as $r ) {
			$table[] = array(
				'ts'      => (int) $r['ts'],
				'post_id' => (int) $r['post_id'],
				'user_id' => (int) $r['user_id'],
				'plugin'  => null !== $r['plugin'] ? (string) $r['plugin'] : '',
				'mode'    => (string) $r['mode'],
			);
		}
		\WP_CLI\Utils\format_items( $format, $table, array( 'ts', 'post_id', 'user_id', 'plugin', 'mode' ) );
	}
}
