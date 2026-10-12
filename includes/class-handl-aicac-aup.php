<?php
/**
 * AICAC-AUP-ACK (#369): per-user AI acceptable-use acknowledgment gate.
 *
 * Policy text + version stamp in own option. Own settings/roster screen.
 * Acceptance in user_meta. Deny aup_not_accepted at the shared pre-flight
 * gate (priority 2). Re-ack on policy edit with a grace window so an edit
 * never hard-locks a live site. Own profile section (no my-ai edits).
 * OFF by default. No admin.php/policy.php/cost.php edits.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Acceptable-use acknowledgment gate for logged-in users.
 */
final class Aup {

	public const REASON = 'aup_not_accepted';

	public const SETTINGS_OPTION = 'handl_aicac_aup';

	public const INDEX_OPTION = 'handl_aicac_aup_ack_index';

	public const USER_META_KEY = 'handl_aicac_aup_ack';

	public const FILTER_PRIORITY = 2;

	public const DEFAULT_GRACE_DAYS = 7;

	public const PAGE_SLUG = 'handl-aicac-aup';

	public const CHANNEL = 'aup';

	public const STATUS_OFF = 'off';

	public const STATUS_CURRENT = 'current';

	public const STATUS_GRACE = 'grace';

	public const STATUS_LOCKED = 'locked';

	public const POST_PRESENT = 'handl_aicac_aup_present';

	public const POST_ENABLED = 'handl_aicac_aup_enabled';

	public const POST_POLICY = 'handl_aicac_aup_policy_text';

	public const POST_GRACE = 'handl_aicac_aup_grace_days';

	public const ACTION_SAVE = 'handl_aicac_aup_save';

	public const ACTION_ACCEPT = 'handl_aicac_aup_accept';

	public const ACTION_RESET = 'handl_aicac_aup_reset';

	public const INDEX_CAP = 5000;

	/** @var bool */
	private static $registered = false;

	public static function init(): void {
		if ( self::$registered ) {
			return;
		}
		self::$registered = true;

		add_filter( 'wp_ai_client_prevent_prompt', array( self::class, 'maybe_prevent_prompt' ), self::FILTER_PRIORITY, 2 );
		add_action( 'admin_menu', array( self::class, 'register_menu' ), 20 );
		add_action( 'admin_init', array( self::class, 'maybe_handle_csv' ), 5 );
		add_action( 'admin_post_' . self::ACTION_SAVE, array( self::class, 'handle_save' ) );
		add_action( 'admin_post_' . self::ACTION_ACCEPT, array( self::class, 'handle_accept' ) );
		add_action( 'admin_post_' . self::ACTION_RESET, array( self::class, 'handle_reset' ) );
		add_action( 'show_user_profile', array( self::class, 'render_profile' ) );
		add_action( 'edit_user_profile', array( self::class, 'render_profile' ) );
		if ( function_exists( 'is_admin' ) && is_admin() ) {
			add_action( 'admin_notices', array( self::class, 'maybe_render_notice' ) );
		}
		self::register_cli();
	}

	public static function reset_for_tests(): void {
		self::$registered = false;
		delete_option( self::SETTINGS_OPTION );
		delete_option( self::INDEX_OPTION );
		if ( isset( $GLOBALS['handl_aicac_test_user_meta'] ) && is_array( $GLOBALS['handl_aicac_test_user_meta'] ) ) {
			foreach ( $GLOBALS['handl_aicac_test_user_meta'] as $uid => $meta ) {
				if ( is_array( $meta ) ) {
					unset( $GLOBALS['handl_aicac_test_user_meta'][ $uid ][ self::USER_META_KEY ] );
				}
			}
		}
	}

	/**
	 * @return array{enabled:bool,policy_text:string,version:string,version_ts:int,grace_days:int}
	 */
	public static function defaults(): array {
		return array(
			'enabled'     => false,
			'policy_text' => '',
			'version'     => '',
			'version_ts'  => 0,
			'grace_days'  => self::DEFAULT_GRACE_DAYS,
		);
	}

	/**
	 * @return array{enabled:bool,policy_text:string,version:string,version_ts:int,grace_days:int}
	 */
	public static function get_settings(): array {
		return self::sanitize_settings( get_option( self::SETTINGS_OPTION, array() ) );
	}

	/**
	 * @param mixed $raw Raw settings.
	 * @return array{enabled:bool,policy_text:string,version:string,version_ts:int,grace_days:int}
	 */
	public static function sanitize_settings( $raw ): array {
		$defaults = self::defaults();
		if ( ! is_array( $raw ) ) {
			return $defaults;
		}
		$text = isset( $raw['policy_text'] ) ? self::sanitize_policy_text( (string) $raw['policy_text'] ) : '';
		$ver  = isset( $raw['version'] ) ? self::sanitize_version( (string) $raw['version'] ) : '';
		if ( '' !== $text && '' === $ver ) {
			$ver = self::hash_policy( $text );
		}

		return array(
			'enabled'     => ! empty( $raw['enabled'] ),
			'policy_text' => $text,
			'version'     => $ver,
			'version_ts'  => isset( $raw['version_ts'] ) ? max( 0, (int) $raw['version_ts'] ) : 0,
			'grace_days'  => self::sanitize_grace_days( $raw['grace_days'] ?? self::DEFAULT_GRACE_DAYS ),
		);
	}

	/**
	 * @param array<string,mixed> $settings Settings.
	 * @param int|null            $now      Clock override.
	 */
	public static function save_settings( array $settings, ?int $now = null ): bool {
		$now   = null !== $now ? (int) $now : Clock::now();
		$clean = self::sanitize_settings( $settings );
		$before = self::get_settings();

		$text_changed = $clean['policy_text'] !== $before['policy_text'];
		if ( $text_changed ) {
			$clean['version']    = '' === $clean['policy_text'] ? '' : self::hash_policy( $clean['policy_text'] );
			$clean['version_ts'] = '' === $clean['version'] ? 0 : $now;
		} else {
			$clean['version']    = $before['version'];
			$clean['version_ts'] = $before['version_ts'];
			if ( '' !== $clean['policy_text'] && '' === $clean['version'] ) {
				$clean['version']    = self::hash_policy( $clean['policy_text'] );
				$clean['version_ts'] = $now;
			}
		}

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
		$settings = self::get_settings();

		return ! empty( $settings['enabled'] ) && '' !== $settings['policy_text'] && '' !== $settings['version'];
	}

	public static function sanitize_policy_text( string $text ): string {
		$text = trim( $text );
		if ( function_exists( 'wp_kses_post' ) ) {
			$text = wp_kses_post( $text );
		} else {
			$text = strip_tags( $text );
		}
		if ( strlen( $text ) > 50000 ) {
			$text = substr( $text, 0, 50000 );
		}

		return $text;
	}

	public static function sanitize_version( string $version ): string {
		$version = strtolower( trim( $version ) );
		$version = preg_replace( '/[^a-f0-9]/', '', $version ) ?? '';

		return substr( $version, 0, 64 );
	}

	/**
	 * @param mixed $raw Raw grace days.
	 */
	public static function sanitize_grace_days( $raw ): int {
		if ( ! is_numeric( $raw ) ) {
			return self::DEFAULT_GRACE_DAYS;
		}
		$v = (int) $raw;
		if ( $v < 0 ) {
			$v = 0;
		}
		if ( $v > 365 ) {
			$v = 365;
		}

		return $v;
	}

	public static function hash_policy( string $text ): string {
		$text = self::sanitize_policy_text( $text );
		if ( '' === $text ) {
			return '';
		}

		return substr( hash( 'sha256', $text ), 0, 16 );
	}

	/**
	 * @return array{version:string,ts:int,ip:string}|null
	 */
	public static function get_acceptance( int $user_id ): ?array {
		if ( $user_id <= 0 ) {
			return null;
		}
		$raw = get_user_meta( $user_id, self::USER_META_KEY, true );
		if ( ! is_array( $raw ) ) {
			return null;
		}
		$version = self::sanitize_version( (string) ( $raw['version'] ?? '' ) );
		if ( '' === $version ) {
			return null;
		}

		return array(
			'version' => $version,
			'ts'      => isset( $raw['ts'] ) ? max( 0, (int) $raw['ts'] ) : 0,
			'ip'      => isset( $raw['ip'] ) ? self::sanitize_ip( (string) $raw['ip'] ) : '',
		);
	}

	/**
	 * @param array{version?:string,ts?:int,ip?:string} $row Acceptance.
	 */
	public static function set_acceptance( int $user_id, array $row ): bool {
		if ( $user_id <= 0 ) {
			return false;
		}
		$version = self::sanitize_version( (string) ( $row['version'] ?? '' ) );
		if ( '' === $version ) {
			return false;
		}
		$payload = array(
			'version' => $version,
			'ts'      => isset( $row['ts'] ) ? max( 0, (int) $row['ts'] ) : Clock::now(),
			'ip'      => isset( $row['ip'] ) ? self::sanitize_ip( (string) $row['ip'] ) : '',
		);
		update_user_meta( $user_id, self::USER_META_KEY, $payload );
		self::index_add( $user_id );

		return true;
	}

	public static function clear_acceptance( int $user_id ): bool {
		if ( $user_id <= 0 ) {
			return false;
		}
		delete_user_meta( $user_id, self::USER_META_KEY );
		self::index_remove( $user_id );

		return true;
	}

	public static function sanitize_ip( string $ip ): string {
		$ip = trim( $ip );
		if ( function_exists( 'sanitize_text_field' ) ) {
			$ip = sanitize_text_field( $ip );
		}
		if ( strlen( $ip ) > 45 ) {
			$ip = substr( $ip, 0, 45 );
		}

		return $ip;
	}

	/**
	 * Status for a user relative to the current policy version.
	 *
	 * @return self::STATUS_*
	 */
	public static function status_for_user( int $user_id, ?array $settings = null, ?int $now = null ): string {
		$settings = is_array( $settings ) ? self::sanitize_settings( $settings ) : self::get_settings();
		if ( empty( $settings['enabled'] ) || '' === $settings['policy_text'] || '' === $settings['version'] ) {
			return self::STATUS_OFF;
		}
		if ( $user_id <= 0 ) {
			return self::STATUS_LOCKED;
		}
		$ack = self::get_acceptance( $user_id );
		if ( null === $ack ) {
			return self::STATUS_LOCKED;
		}
		if ( $ack['version'] === $settings['version'] ) {
			return self::STATUS_CURRENT;
		}
		$now       = null !== $now ? (int) $now : Clock::now();
		$grace_end = self::grace_deadline( $settings );
		if ( $grace_end > 0 && $now <= $grace_end ) {
			return self::STATUS_GRACE;
		}

		return self::STATUS_LOCKED;
	}

	/**
	 * @param array{enabled:bool,policy_text:string,version:string,version_ts:int,grace_days:int} $settings
	 */
	public static function grace_deadline( array $settings ): int {
		$settings = self::sanitize_settings( $settings );
		if ( $settings['version_ts'] <= 0 || $settings['grace_days'] <= 0 ) {
			return 0;
		}
		$day = defined( 'DAY_IN_SECONDS' ) ? (int) DAY_IN_SECONDS : 86400;

		return (int) $settings['version_ts'] + ( (int) $settings['grace_days'] * $day );
	}

	/**
	 * Whether the gate should deny this user right now.
	 */
	public static function should_deny( int $user_id, ?array $settings = null, ?int $now = null ): bool {
		$status = self::status_for_user( $user_id, $settings, $now );

		return self::STATUS_LOCKED === $status;
	}

	/**
	 * Record acceptance of the current policy version.
	 *
	 * @return array{accepted:bool,version:string}
	 */
	public static function accept_current( int $user_id, ?int $now = null, string $ip = '' ): array {
		$empty = array(
			'accepted' => false,
			'version'  => '',
		);
		if ( $user_id <= 0 ) {
			return $empty;
		}
		$settings = self::get_settings();
		if ( '' === $settings['version'] || '' === $settings['policy_text'] ) {
			return $empty;
		}
		$now = null !== $now ? (int) $now : Clock::now();
		if ( '' === $ip && isset( $_SERVER['REMOTE_ADDR'] ) ) {
			$ip = self::sanitize_ip( (string) wp_unslash( $_SERVER['REMOTE_ADDR'] ) );
		}
		$ok = self::set_acceptance(
			$user_id,
			array(
				'version' => $settings['version'],
				'ts'      => $now,
				'ip'      => $ip,
			)
		);
		if ( ! $ok ) {
			return $empty;
		}
		self::append_activity(
			array(
				'ts'           => $now,
				'decision'     => 'aup_accept',
				'channel'      => self::CHANNEL,
				'aup_action'   => 'accept',
				'aup_version'  => $settings['version'],
				'user_id'      => $user_id,
				'user_role'    => Policy::current_user_role_for_log(),
			)
		);

		return array(
			'accepted' => true,
			'version'  => $settings['version'],
		);
	}

	/**
	 * Gate filter at priority 2 (same slot as USER-QUOTA / DORMANT / CIRCUIT-BREAKER).
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

		$user_id = Policy::current_user_id_for_gate();
		$now     = Clock::now();
		if ( ! self::should_deny( $user_id, null, $now ) ) {
			return false;
		}

		$attrib    = Attribution::resolve_from_backtrace();
		$plugin    = is_string( $attrib['plugin'] ?? null ) ? (string) $attrib['plugin'] : null;
		$snapshot  = class_exists( Prompt_Snapshot::class, false ) ? Prompt_Snapshot::from_builder( $builder ) : array();
		$operation = isset( $snapshot['operation'] ) ? (string) $snapshot['operation'] : '';
		$family    = isset( $snapshot['capability_family'] ) && is_string( $snapshot['capability_family'] )
			? (string) $snapshot['capability_family']
			: ( class_exists( Operations::class, false ) ? Operations::family_from_operation( $operation ) : '' );
		$settings  = self::get_settings();

		$event = array_merge(
			array(
				'ts'                => $now,
				'plugin'            => $plugin,
				'file'              => $attrib['file'] ?? null,
				'caller'            => $attrib['method'] ?? null,
				'decision'          => 'deny',
				'would_decision'    => 'deny',
				'capability_family' => $family,
				'denial_reason'     => self::REASON,
				'decision_source'   => self::REASON,
				'user_id'           => $user_id,
				'user_role'         => Policy::current_user_role_for_log(),
				'aup'               => true,
				'aup_version'       => $settings['version'],
				'uri'               => isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( (string) $_SERVER['REQUEST_URI'] ) ) : null,
			),
			is_array( $snapshot ) ? $snapshot : array()
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

		Policy::append_log_event( $event );

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
	 * Roster rows for admin / CSV / CLI.
	 *
	 * @param list<int>|null $user_ids Optional user id list (tests).
	 * @return list<array{user_id:int,login:string,display:string,status:string,version:string,ts:int,grace_until:int}>
	 */
	public static function roster( ?array $user_ids = null, ?array $settings = null, ?int $now = null ): array {
		$settings = is_array( $settings ) ? self::sanitize_settings( $settings ) : self::get_settings();
		$now      = null !== $now ? (int) $now : Clock::now();
		$ids      = null !== $user_ids ? $user_ids : self::candidate_user_ids();
		$grace    = self::grace_deadline( $settings );
		$out      = array();
		foreach ( $ids as $uid ) {
			$uid = (int) $uid;
			if ( $uid <= 0 ) {
				continue;
			}
			$ack    = self::get_acceptance( $uid );
			$status = self::status_for_user( $uid, $settings, $now );
			$out[]  = array(
				'user_id'     => $uid,
				'login'       => self::user_login( $uid ),
				'display'     => self::user_display( $uid ),
				'status'      => $status,
				'version'     => null !== $ack ? (string) $ack['version'] : '',
				'ts'          => null !== $ack ? (int) $ack['ts'] : 0,
				'grace_until' => self::STATUS_GRACE === $status ? $grace : 0,
			);
		}
		usort(
			$out,
			static function ( $a, $b ) {
				return ( (int) $b['ts'] ) <=> ( (int) $a['ts'] );
			}
		);

		return $out;
	}

	/**
	 * @return list<int>
	 */
	public static function candidate_user_ids(): array {
		if ( isset( $GLOBALS['handl_aicac_test_aup_users'] ) && is_array( $GLOBALS['handl_aicac_test_aup_users'] ) ) {
			return array_values( array_map( 'intval', $GLOBALS['handl_aicac_test_aup_users'] ) );
		}
		$ids = self::index_ids();
		if ( function_exists( 'get_users' ) ) {
			$fetched = get_users(
				array(
					'fields' => 'ID',
					'number' => 500,
				)
			);
			if ( is_array( $fetched ) ) {
				foreach ( $fetched as $id ) {
					$id = (int) $id;
					if ( $id > 0 ) {
						$ids[] = $id;
					}
				}
			}
		}

		return array_values( array_unique( array_filter( array_map( 'intval', $ids ) ) ) );
	}

	/**
	 * @return list<int>
	 */
	public static function index_ids(): array {
		$raw = get_option( self::INDEX_OPTION, array() );
		if ( ! is_array( $raw ) ) {
			return array();
		}
		$out = array();
		foreach ( $raw as $id ) {
			$id = (int) $id;
			if ( $id > 0 ) {
				$out[] = $id;
			}
		}

		return array_values( array_unique( $out ) );
	}

	private static function index_add( int $user_id ): void {
		$ids = self::index_ids();
		if ( ! in_array( $user_id, $ids, true ) ) {
			array_unshift( $ids, $user_id );
		}
		if ( count( $ids ) > self::INDEX_CAP ) {
			$ids = array_slice( $ids, 0, self::INDEX_CAP );
		}
		update_option( self::INDEX_OPTION, $ids, false );
	}

	private static function index_remove( int $user_id ): void {
		$ids = array_values(
			array_filter(
				self::index_ids(),
				static function ( $id ) use ( $user_id ) {
					return (int) $id !== $user_id;
				}
			)
		);
		if ( empty( $ids ) ) {
			delete_option( self::INDEX_OPTION );
			return;
		}
		update_option( self::INDEX_OPTION, $ids, false );
	}

	public static function user_login( int $user_id ): string {
		if ( function_exists( 'get_userdata' ) ) {
			$user = get_userdata( $user_id );
			if ( is_object( $user ) && isset( $user->user_login ) ) {
				return (string) $user->user_login;
			}
		}

		return 'user#' . $user_id;
	}

	public static function user_display( int $user_id ): string {
		if ( function_exists( 'get_userdata' ) ) {
			$user = get_userdata( $user_id );
			if ( is_object( $user ) && isset( $user->display_name ) && '' !== (string) $user->display_name ) {
				return (string) $user->display_name;
			}
		}

		return self::user_login( $user_id );
	}

	public static function csv_for_roster( ?array $user_ids = null ): string {
		$rows = self::roster( $user_ids );
		$lines = array(
			self::csv_line( array( 'user_id', 'login', 'display', 'status', 'version', 'accepted_ts', 'grace_until' ) ),
		);
		foreach ( $rows as $r ) {
			$lines[] = self::csv_line(
				array(
					(string) (int) $r['user_id'],
					(string) $r['login'],
					(string) $r['display'],
					(string) $r['status'],
					(string) $r['version'],
					(string) (int) $r['ts'],
					(string) (int) $r['grace_until'],
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

	public static function register_menu(): void {
		if ( ! Caps::user_can_view() ) {
			return;
		}
		if ( ! function_exists( 'add_submenu_page' ) ) {
			return;
		}
		add_submenu_page(
			Admin::MENU_SLUG,
			__( 'AI acceptable use', 'handl-ai-connector-access-control' ),
			__( 'Acceptable use', 'handl-ai-connector-access-control' ),
			Caps::VIEW,
			self::PAGE_SLUG,
			array( self::class, 'render_page' )
		);
	}

	public static function render_page(): void {
		if ( ! Caps::user_can_view() ) {
			return;
		}
		$settings = self::get_settings();
		$can_manage = Caps::user_can_manage();
		$csv = add_query_arg(
			array(
				'page'                => self::PAGE_SLUG,
				'handl_aicac_aup_csv' => '1',
				'_wpnonce'            => function_exists( 'wp_create_nonce' ) ? wp_create_nonce( 'handl_aicac_aup_csv' ) : '',
			),
			admin_url( 'admin.php' )
		);

		echo '<div class="wrap">';
		echo '<h1>' . esc_html__( 'AI acceptable use', 'handl-ai-connector-access-control' ) . '</h1>';
		echo '<p class="description">' . esc_html__( 'Require logged-in users to acknowledge your AI acceptable-use policy before governed AI calls. Off by default.', 'handl-ai-connector-access-control' ) . '</p>';

		if ( $can_manage ) {
			$action = admin_url( 'admin-post.php' );
			echo '<form method="post" action="' . esc_url( $action ) . '">';
			echo '<input type="hidden" name="action" value="' . esc_attr( self::ACTION_SAVE ) . '" />';
			if ( function_exists( 'wp_nonce_field' ) ) {
				wp_nonce_field( self::ACTION_SAVE );
			}
			echo '<input type="hidden" name="' . esc_attr( self::POST_PRESENT ) . '" value="1" />';
			echo '<table class="form-table" role="presentation"><tbody>';
			echo '<tr><th scope="row">' . esc_html__( 'Enable gate', 'handl-ai-connector-access-control' ) . '</th><td>';
			echo '<label><input type="checkbox" name="' . esc_attr( self::POST_ENABLED ) . '" value="1" ' . checked( ! empty( $settings['enabled'] ), true, false ) . ' /> ';
			echo esc_html__( 'Require acknowledgment before AI calls (needs policy text)', 'handl-ai-connector-access-control' );
			echo '</label></td></tr>';
			echo '<tr><th scope="row"><label for="' . esc_attr( self::POST_POLICY ) . '">' . esc_html__( 'Policy text', 'handl-ai-connector-access-control' ) . '</label></th><td>';
			echo '<textarea class="large-text" rows="10" id="' . esc_attr( self::POST_POLICY ) . '" name="' . esc_attr( self::POST_POLICY ) . '">' . esc_textarea( $settings['policy_text'] ) . '</textarea>';
			echo '<p class="description">' . esc_html__( 'Editing this text bumps the version. Users must re-acknowledge after the grace window.', 'handl-ai-connector-access-control' ) . '</p>';
			if ( '' !== $settings['version'] ) {
				echo '<p class="description">' . esc_html(
					sprintf(
						/* translators: 1: version hash, 2: unix timestamp */
						__( 'Current version: %1$s (since %2$s)', 'handl-ai-connector-access-control' ),
						$settings['version'],
						self::format_ts( (int) $settings['version_ts'] )
					)
				) . '</p>';
			}
			echo '</td></tr>';
			echo '<tr><th scope="row"><label for="' . esc_attr( self::POST_GRACE ) . '">' . esc_html__( 'Grace days after edit', 'handl-ai-connector-access-control' ) . '</label></th><td>';
			echo '<input type="number" min="0" max="365" class="small-text" id="' . esc_attr( self::POST_GRACE ) . '" name="' . esc_attr( self::POST_GRACE ) . '" value="' . esc_attr( (string) (int) $settings['grace_days'] ) . '" />';
			echo '<p class="description">' . esc_html__( 'After a policy edit, users who already accepted a prior version keep access during this window. Default 7. Set 0 for immediate re-ack.', 'handl-ai-connector-access-control' ) . '</p>';
			echo '</td></tr></tbody></table>';
			submit_button( __( 'Save acceptable use', 'handl-ai-connector-access-control' ) );
			echo '</form>';
		}

		echo '<h2>' . esc_html__( 'Acknowledgment roster', 'handl-ai-connector-access-control' ) . '</h2>';
		echo '<p><a class="button" href="' . esc_url( $csv ) . '">' . esc_html__( 'Download CSV', 'handl-ai-connector-access-control' ) . '</a></p>';
		$rows = self::roster();
		if ( empty( $rows ) ) {
			echo '<p>' . esc_html__( 'No acknowledgment records yet.', 'handl-ai-connector-access-control' ) . '</p>';
		} else {
			echo '<table class="widefat striped"><thead><tr>';
			echo '<th>' . esc_html__( 'User', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Status', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Accepted version', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Accepted at', 'handl-ai-connector-access-control' ) . '</th>';
			if ( $can_manage ) {
				echo '<th>' . esc_html__( 'Reset', 'handl-ai-connector-access-control' ) . '</th>';
			}
			echo '</tr></thead><tbody>';
			foreach ( $rows as $r ) {
				echo '<tr><td>' . esc_html( (string) $r['display'] ) . ' <span class="description">(' . esc_html( (string) $r['login'] ) . ')</span></td>';
				echo '<td>' . esc_html( self::status_label( (string) $r['status'] ) ) . '</td>';
				echo '<td>' . esc_html( '' !== $r['version'] ? (string) $r['version'] : '—' ) . '</td>';
				echo '<td>' . esc_html( self::format_ts( (int) $r['ts'] ) ) . '</td>';
				if ( $can_manage ) {
					$reset = wp_nonce_url(
						admin_url( 'admin-post.php?action=' . self::ACTION_RESET . '&user_id=' . (int) $r['user_id'] ),
						self::ACTION_RESET . '_' . (int) $r['user_id']
					);
					echo '<td><a href="' . esc_url( $reset ) . '">' . esc_html__( 'Reset', 'handl-ai-connector-access-control' ) . '</a></td>';
				}
				echo '</tr>';
			}
			echo '</tbody></table>';
		}
		echo '</div>';
	}

	public static function status_label( string $status ): string {
		switch ( $status ) {
			case self::STATUS_CURRENT:
				return __( 'Current', 'handl-ai-connector-access-control' );
			case self::STATUS_GRACE:
				return __( 'Grace', 'handl-ai-connector-access-control' );
			case self::STATUS_LOCKED:
				return __( 'Locked', 'handl-ai-connector-access-control' );
			case self::STATUS_OFF:
				return __( 'Off', 'handl-ai-connector-access-control' );
			default:
				return $status;
		}
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
		$action = isset( $_GET['handl_aicac_aup_csv'] ) ? sanitize_key( wp_unslash( (string) $_GET['handl_aicac_aup_csv'] ) ) : '';
		if ( '1' !== $action ) {
			return;
		}
		if ( ! Caps::user_can_view() ) {
			if ( function_exists( 'wp_die' ) ) {
				wp_die( esc_html__( 'You do not have permission to export this list.', 'handl-ai-connector-access-control' ) );
			}
			return;
		}
		check_admin_referer( 'handl_aicac_aup_csv' );
		$csv = self::csv_for_roster();
		if ( function_exists( 'nocache_headers' ) ) {
			nocache_headers();
		}
		if ( function_exists( 'header' ) ) {
			header( 'Content-Type: text/csv; charset=utf-8' );
			header( 'Content-Disposition: attachment; filename="handl-aicac-aup-roster.csv"' );
		}
		// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- raw CSV download body.
		echo $csv;
		exit;
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
		// phpcs:ignore WordPress.Security.NonceVerification.Missing,WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		$text = isset( $_POST[ self::POST_POLICY ] ) ? wp_unslash( (string) $_POST[ self::POST_POLICY ] ) : '';
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		$grace = isset( $_POST[ self::POST_GRACE ] ) ? wp_unslash( $_POST[ self::POST_GRACE ] ) : self::DEFAULT_GRACE_DAYS;
		self::save_settings(
			array(
				'enabled'     => $enabled,
				'policy_text' => $text,
				'grace_days'  => $grace,
			)
		);
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

	public static function handle_accept(): void {
		$user_id = (int) get_current_user_id();
		if ( $user_id <= 0 || ! current_user_can( 'read' ) ) {
			if ( function_exists( 'wp_die' ) ) {
				wp_die( esc_html__( 'You must be logged in to accept this policy.', 'handl-ai-connector-access-control' ) );
			}
			return;
		}
		check_admin_referer( self::ACTION_ACCEPT );
		self::accept_current( $user_id );
		$redirect = wp_get_referer();
		if ( ! is_string( $redirect ) || '' === $redirect ) {
			$redirect = admin_url( 'profile.php' );
		}
		if ( function_exists( 'wp_safe_redirect' ) ) {
			wp_safe_redirect( $redirect );
			exit;
		}
	}

	public static function handle_reset(): void {
		if ( ! Caps::user_can_manage() ) {
			if ( function_exists( 'wp_die' ) ) {
				wp_die( esc_html__( 'You do not have permission to reset acknowledgments.', 'handl-ai-connector-access-control' ) );
			}
			return;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$user_id = isset( $_GET['user_id'] ) ? (int) $_GET['user_id'] : 0;
		check_admin_referer( self::ACTION_RESET . '_' . $user_id );
		if ( $user_id > 0 ) {
			self::clear_acceptance( $user_id );
			self::append_activity(
				array(
					'ts'          => Clock::now(),
					'decision'    => 'aup_reset',
					'channel'     => self::CHANNEL,
					'aup_action'  => 'reset',
					'user_id'     => $user_id,
					'actor_id'    => (int) get_current_user_id(),
				)
			);
		}
		$redirect = add_query_arg(
			array(
				'page'   => self::PAGE_SLUG,
				'reset'  => '1',
			),
			admin_url( 'admin.php' )
		);
		if ( function_exists( 'wp_safe_redirect' ) ) {
			wp_safe_redirect( $redirect );
			exit;
		}
	}

	/**
	 * @param \WP_User|object $user Profile user.
	 */
	public static function render_profile( $user ): void {
		if ( ! is_object( $user ) || ! isset( $user->ID ) ) {
			return;
		}
		$user_id = (int) $user->ID;
		$current = (int) get_current_user_id();
		if ( $user_id <= 0 || $user_id !== $current ) {
			return;
		}
		if ( ! current_user_can( 'read' ) ) {
			return;
		}
		$settings = self::get_settings();
		if ( empty( $settings['enabled'] ) && '' === $settings['policy_text'] ) {
			return;
		}
		$status = self::status_for_user( $user_id, $settings );
		echo '<h2>' . esc_html__( 'AI acceptable use', 'handl-ai-connector-access-control' ) . '</h2>';
		if ( empty( $settings['enabled'] ) ) {
			echo '<p class="description">' . esc_html__( 'The acceptable-use gate is off. No acknowledgment is required for AI calls.', 'handl-ai-connector-access-control' ) . '</p>';
			return;
		}
		if ( '' === $settings['policy_text'] ) {
			echo '<p class="description">' . esc_html__( 'No acceptable-use policy text is configured yet.', 'handl-ai-connector-access-control' ) . '</p>';
			return;
		}
		echo '<div class="handl-aicac-aup-profile">';
		echo '<p><strong>' . esc_html__( 'Status:', 'handl-ai-connector-access-control' ) . '</strong> ' . esc_html( self::status_label( $status ) ) . '</p>';
		echo '<div class="handl-aicac-aup-policy" style="max-height:240px;overflow:auto;border:1px solid #c3c4c7;padding:12px;background:#fff;">';
		echo wp_kses_post( wpautop( $settings['policy_text'] ) );
		echo '</div>';
		if ( self::STATUS_CURRENT === $status ) {
			$ack = self::get_acceptance( $user_id );
			echo '<p class="description">' . esc_html(
				sprintf(
					/* translators: %s: acceptance timestamp */
					__( 'You accepted the current policy on %s.', 'handl-ai-connector-access-control' ),
					self::format_ts( null !== $ack ? (int) $ack['ts'] : 0 )
				)
			) . '</p>';
		} else {
			if ( self::STATUS_GRACE === $status ) {
				echo '<p class="description">' . esc_html__( 'The policy was updated. You still have access during the grace window — please re-acknowledge.', 'handl-ai-connector-access-control' ) . '</p>';
			} elseif ( self::STATUS_LOCKED === $status ) {
				echo '<p class="description">' . esc_html__( 'You must accept this policy before making AI calls on this site.', 'handl-ai-connector-access-control' ) . '</p>';
			}
			$action = admin_url( 'admin-post.php' );
			echo '<form method="post" action="' . esc_url( $action ) . '" style="margin-top:12px;">';
			echo '<input type="hidden" name="action" value="' . esc_attr( self::ACTION_ACCEPT ) . '" />';
			if ( function_exists( 'wp_nonce_field' ) ) {
				wp_nonce_field( self::ACTION_ACCEPT );
			}
			submit_button( __( 'I accept this AI acceptable-use policy', 'handl-ai-connector-access-control' ), 'primary', 'submit', false );
			echo '</form>';
		}
		echo '</div>';
	}

	public static function maybe_render_notice(): void {
		if ( ! function_exists( 'get_current_screen' ) ) {
			return;
		}
		$user_id = (int) get_current_user_id();
		if ( $user_id <= 0 || ! self::is_enabled() ) {
			return;
		}
		$status = self::status_for_user( $user_id );
		if ( self::STATUS_CURRENT === $status || self::STATUS_OFF === $status ) {
			return;
		}
		$profile = admin_url( 'profile.php' );
		echo '<div class="notice notice-warning"><p>';
		if ( self::STATUS_GRACE === $status ) {
			echo esc_html__( 'The AI acceptable-use policy was updated. Please re-acknowledge it on your profile. AI access continues during the grace window.', 'handl-ai-connector-access-control' );
		} else {
			echo esc_html__( 'You must accept the AI acceptable-use policy before making AI calls.', 'handl-ai-connector-access-control' );
		}
		echo ' <a href="' . esc_url( $profile ) . '">' . esc_html__( 'Review and accept', 'handl-ai-connector-access-control' ) . '</a>';
		echo '</p></div>';
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

	public static function register_cli(): void {
		if ( ! defined( 'WP_CLI' ) || ! WP_CLI ) {
			return;
		}
		if ( ! class_exists( '\WP_CLI' ) ) {
			return;
		}
		\WP_CLI::add_command( 'handl-aicac aup', CLI_Aup::class );
	}
}

/**
 * WP-CLI: wp handl-aicac aup status|roster|reset
 */
final class CLI_Aup {

	/**
	 * Show AUP gate status for the site or a user.
	 *
	 * ## OPTIONS
	 *
	 * [<user_id>]
	 * : Optional user ID.
	 *
	 * @when after_wp_load
	 *
	 * @param list<string>             $args       Positional.
	 * @param array<string,string|int> $assoc_args Flags.
	 */
	public function status( $args, $assoc_args ): void {
		unset( $assoc_args );
		$settings = Aup::get_settings();
		\WP_CLI::log(
			sprintf(
				'enabled=%s version=%s grace_days=%d version_ts=%d',
				! empty( $settings['enabled'] ) ? 'yes' : 'no',
				'' !== $settings['version'] ? $settings['version'] : '(none)',
				(int) $settings['grace_days'],
				(int) $settings['version_ts']
			)
		);
		$user_id = isset( $args[0] ) ? (int) $args[0] : 0;
		if ( $user_id > 0 ) {
			$ack    = Aup::get_acceptance( $user_id );
			$status = Aup::status_for_user( $user_id );
			\WP_CLI::log(
				sprintf(
					'user=%d status=%s accepted_version=%s accepted_ts=%d',
					$user_id,
					$status,
					null !== $ack ? $ack['version'] : '(none)',
					null !== $ack ? (int) $ack['ts'] : 0
				)
			);
		}
	}

	/**
	 * List acknowledgment roster.
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
	public function roster( $args, $assoc_args ): void {
		unset( $args );
		$format = isset( $assoc_args['format'] ) ? (string) $assoc_args['format'] : 'table';
		$rows   = Aup::roster();
		if ( 'csv' === $format ) {
			\WP_CLI::print_value( Aup::csv_for_roster(), array( 'format' => 'csv' ) );
			return;
		}
		$table = array();
		foreach ( $rows as $r ) {
			$table[] = array(
				'user_id'     => (int) $r['user_id'],
				'login'       => (string) $r['login'],
				'status'      => (string) $r['status'],
				'version'     => (string) $r['version'],
				'ts'          => (int) $r['ts'],
				'grace_until' => (int) $r['grace_until'],
			);
		}
		if ( empty( $table ) ) {
			\WP_CLI::log( 'No acknowledgment records.' );
			return;
		}
		\WP_CLI\Utils\format_items( $format, $table, array( 'user_id', 'login', 'status', 'version', 'ts', 'grace_until' ) );
	}

	/**
	 * Clear a user's acceptance (forces re-ack).
	 *
	 * ## OPTIONS
	 *
	 * <user_id>
	 * : User ID.
	 *
	 * @when after_wp_load
	 *
	 * @param list<string>             $args       Positional.
	 * @param array<string,string|int> $assoc_args Flags.
	 */
	public function reset( $args, $assoc_args ): void {
		unset( $assoc_args );
		$user_id = isset( $args[0] ) ? (int) $args[0] : 0;
		if ( $user_id <= 0 ) {
			\WP_CLI::error( 'Need a user id.' );
		}
		Aup::clear_acceptance( $user_id );
		\WP_CLI::success( 'Cleared AUP acceptance for user ' . $user_id . '.' );
	}
}
