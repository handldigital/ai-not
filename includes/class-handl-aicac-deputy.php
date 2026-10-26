<?php
/**
 * AICAC-DEPUTY (#357): backup approver + request SLA.
 *
 * After a pending Access_Request waits N hours, notify a designated deputy
 * with signed links scoped to that one request. Admin stays primary. Optional
 * auto-expire denies stale requests. OFF by default. Own class + options only.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * SLA-armed deputy approve/deny for pending AI access requests.
 */
final class Deputy {

	public const SETTINGS_OPTION = 'handl_aicac_deputy';

	public const STATE_OPTION = 'handl_aicac_deputy_state';

	public const TOKEN_OPTION = 'handl_aicac_deputy_tokens';

	public const PAGE_SLUG = 'handl-aicac-deputy';

	public const CRON_HOOK = 'handl_aicac_deputy_hourly';

	public const OPEN_HOOK = 'handl_aicac_deputy';

	public const APPLY_HOOK = 'handl_aicac_deputy_apply';

	public const ACTION_SAVE = 'handl_aicac_deputy_save';

	public const NONCE_APPLY = 'handl_aicac_deputy_apply';

	public const ACT_APPROVE = 'approve';

	public const ACT_DENY = 'deny';

	public const DEFAULT_SLA_HOURS = 48;

	public const MIN_SLA_HOURS = 1;

	public const MAX_SLA_HOURS = 720;

	public const DEFAULT_EXPIRE_DAYS = 0;

	public const MAX_EXPIRE_DAYS = 365;

	public const TOKEN_TTL = 172800; // 48h.

	public const FRAMING = 'admin_stays_primary_deputy_after_sla';

	public const POST_PRESENT = 'handl_aicac_deputy_present';

	public const POST_ENABLED = 'handl_aicac_deputy_enabled';

	public const POST_USER = 'handl_aicac_deputy_user_id';

	public const POST_ROLE = 'handl_aicac_deputy_role';

	public const POST_SLA = 'handl_aicac_deputy_sla_hours';

	public const POST_EXPIRE = 'handl_aicac_deputy_expire_days';

	/** @var bool */
	private static $registered = false;

	/** @var list<array<string,mixed>> */
	private static $test_mails = array();

	/** @var string */
	private static $last_halt = '';

	public static function init(): void {
		if ( self::$registered ) {
			return;
		}
		self::$registered = true;

		add_action( 'admin_menu', array( self::class, 'register_menu' ), 20 );
		add_action( 'admin_post_' . self::ACTION_SAVE, array( self::class, 'handle_save' ) );
		add_action( 'admin_post_' . self::OPEN_HOOK, array( self::class, 'handle_open' ) );
		add_action( 'admin_post_nopriv_' . self::OPEN_HOOK, array( self::class, 'handle_open' ) );
		add_action( 'admin_post_' . self::APPLY_HOOK, array( self::class, 'handle_apply' ) );
		add_action( self::CRON_HOOK, array( self::class, 'cron_run' ) );
		add_action( 'init', array( self::class, 'maybe_sweep' ), 30 );
		self::maybe_schedule();
	}

	public static function reset_for_tests(): void {
		self::$registered = false;
		self::$test_mails = array();
		self::$last_halt  = '';
		delete_option( self::SETTINGS_OPTION );
		delete_option( self::STATE_OPTION );
		delete_option( self::TOKEN_OPTION );
	}

	/**
	 * @return list<array<string,mixed>>
	 */
	public static function test_mails(): array {
		return self::$test_mails;
	}

	public static function last_halt(): string {
		return self::$last_halt;
	}

	/* ---------------------------------------------------------------------
	 * Settings
	 * ------------------------------------------------------------------ */

	/**
	 * @return array{enabled:bool,deputy_user_id:int,deputy_role:string,sla_hours:int,expire_days:int}
	 */
	public static function defaults(): array {
		return array(
			'enabled'        => false,
			'deputy_user_id' => 0,
			'deputy_role'    => '',
			'sla_hours'      => self::DEFAULT_SLA_HOURS,
			'expire_days'    => self::DEFAULT_EXPIRE_DAYS,
		);
	}

	/**
	 * @return array{enabled:bool,deputy_user_id:int,deputy_role:string,sla_hours:int,expire_days:int}
	 */
	public static function get_settings(): array {
		return self::sanitize_settings( get_option( self::SETTINGS_OPTION, array() ) );
	}

	/**
	 * @param mixed $raw Raw settings.
	 * @return array{enabled:bool,deputy_user_id:int,deputy_role:string,sla_hours:int,expire_days:int}
	 */
	public static function sanitize_settings( $raw ): array {
		$defaults = self::defaults();
		if ( ! is_array( $raw ) ) {
			return $defaults;
		}

		return array(
			'enabled'        => ! empty( $raw['enabled'] ),
			'deputy_user_id' => max( 0, (int) ( $raw['deputy_user_id'] ?? 0 ) ),
			'deputy_role'    => self::sanitize_role( $raw['deputy_role'] ?? '' ),
			'sla_hours'      => self::sanitize_sla_hours( $raw['sla_hours'] ?? $defaults['sla_hours'] ),
			'expire_days'    => self::sanitize_expire_days( $raw['expire_days'] ?? $defaults['expire_days'] ),
		);
	}

	/**
	 * @param mixed $raw Raw.
	 */
	public static function sanitize_sla_hours( $raw ): int {
		if ( ! is_numeric( $raw ) ) {
			return self::DEFAULT_SLA_HOURS;
		}
		$v = (int) $raw;
		if ( $v < self::MIN_SLA_HOURS ) {
			$v = self::MIN_SLA_HOURS;
		}
		if ( $v > self::MAX_SLA_HOURS ) {
			$v = self::MAX_SLA_HOURS;
		}

		return $v;
	}

	/**
	 * @param mixed $raw Raw.
	 */
	public static function sanitize_expire_days( $raw ): int {
		if ( ! is_numeric( $raw ) ) {
			return self::DEFAULT_EXPIRE_DAYS;
		}
		$v = (int) $raw;
		if ( $v < 0 ) {
			$v = 0;
		}
		if ( $v > self::MAX_EXPIRE_DAYS ) {
			$v = self::MAX_EXPIRE_DAYS;
		}

		return $v;
	}

	/**
	 * @param mixed $raw Raw role slug.
	 */
	public static function sanitize_role( $raw ): string {
		$role = function_exists( 'sanitize_key' )
			? sanitize_key( (string) $raw )
			: strtolower( preg_replace( '/[^a-z0-9_]/', '', (string) $raw ) ?? '' );
		if ( 'administrator' === $role ) {
			return '';
		}

		return $role;
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
			self::clear_schedule();

			return true;
		}
		update_option( self::SETTINGS_OPTION, $clean, false );
		if ( ! empty( $clean['enabled'] ) ) {
			self::maybe_schedule();
		} else {
			self::clear_schedule();
		}

		return true;
	}

	public static function is_enabled(): bool {
		return ! empty( self::get_settings()['enabled'] );
	}

	/* ---------------------------------------------------------------------
	 * State (notified request ids)
	 * ------------------------------------------------------------------ */

	/**
	 * @return array{notified:array<string,array{ts:int,kind:string}>}
	 */
	public static function defaults_state(): array {
		return array(
			'notified' => array(),
		);
	}

	/**
	 * @return array{notified:array<string,array{ts:int,kind:string}>}
	 */
	public static function get_state(): array {
		return self::sanitize_state( get_option( self::STATE_OPTION, array() ) );
	}

	/**
	 * @param mixed $raw Raw.
	 * @return array{notified:array<string,array{ts:int,kind:string}>}
	 */
	public static function sanitize_state( $raw ): array {
		$defaults = self::defaults_state();
		if ( ! is_array( $raw ) ) {
			return $defaults;
		}
		$notified = array();
		if ( isset( $raw['notified'] ) && is_array( $raw['notified'] ) ) {
			foreach ( $raw['notified'] as $id => $row ) {
				$id = self::sanitize_request_id( (string) $id );
				if ( '' === $id || ! is_array( $row ) ) {
					continue;
				}
				$notified[ $id ] = array(
					'ts'   => max( 0, (int) ( $row['ts'] ?? 0 ) ),
					'kind' => sanitize_key( (string) ( $row['kind'] ?? 'deputy' ) ),
				);
			}
		}

		return array(
			'notified' => $notified,
		);
	}

	/**
	 * @param array{notified:array<string,array{ts:int,kind:string}>} $state State.
	 */
	public static function put_state( array $state ): void {
		$clean = self::sanitize_state( $state );
		if ( $clean === self::defaults_state() ) {
			delete_option( self::STATE_OPTION );

			return;
		}
		update_option( self::STATE_OPTION, $clean, false );
	}

	public static function was_notified( string $request_id ): bool {
		$id = self::sanitize_request_id( $request_id );

		return '' !== $id && isset( self::get_state()['notified'][ $id ] );
	}

	public static function mark_notified( string $request_id, string $kind, int $now ): void {
		$id = self::sanitize_request_id( $request_id );
		if ( '' === $id ) {
			return;
		}
		$state                         = self::get_state();
		$state['notified'][ $id ]      = array(
			'ts'   => $now,
			'kind' => sanitize_key( $kind ),
		);
		self::put_state( $state );
	}

	/* ---------------------------------------------------------------------
	 * Identity
	 * ------------------------------------------------------------------ */

	public static function is_deputy( int $user_id ): bool {
		if ( $user_id <= 0 ) {
			return false;
		}
		$settings = self::get_settings();
		if ( $settings['deputy_user_id'] > 0 ) {
			return $user_id === $settings['deputy_user_id'];
		}
		if ( '' === $settings['deputy_role'] ) {
			return false;
		}
		$user = function_exists( 'get_userdata' ) ? get_userdata( $user_id ) : false;
		if ( ! is_object( $user ) ) {
			return false;
		}
		$roles = isset( $user->roles ) ? (array) $user->roles : array();
		if ( in_array( $settings['deputy_role'], $roles, true ) ) {
			return true;
		}

		return method_exists( $user, 'has_cap' ) && (bool) $user->has_cap( $settings['deputy_role'] );
	}

	/**
	 * @return list<array{user_id:int,email:string,login:string}>
	 */
	public static function deputy_recipients(): array {
		$settings = self::get_settings();
		$out      = array();
		if ( $settings['deputy_user_id'] > 0 ) {
			$row = self::recipient_from_user_id( $settings['deputy_user_id'] );
			if ( null !== $row ) {
				$out[] = $row;
			}

			return $out;
		}
		if ( '' === $settings['deputy_role'] ) {
			return $out;
		}
		foreach ( self::users_for_role( $settings['deputy_role'] ) as $user ) {
			$row = self::recipient_from_user( $user );
			if ( null !== $row ) {
				$out[] = $row;
			}
		}

		return $out;
	}

	public static function waited_hours( int $ts, int $now ): int {
		if ( $now <= $ts ) {
			return 0;
		}
		$hour = defined( 'HOUR_IN_SECONDS' ) ? (int) HOUR_IN_SECONDS : 3600;

		return (int) floor( ( $now - $ts ) / $hour );
	}

	public static function actor_label( int $user_id ): string {
		if ( $user_id <= 0 ) {
			return 'system';
		}
		$user = function_exists( 'get_userdata' ) ? get_userdata( $user_id ) : false;
		if ( is_object( $user ) && isset( $user->user_login ) && '' !== (string) $user->user_login ) {
			return sanitize_text_field( (string) $user->user_login );
		}

		return 'user#' . (string) $user_id;
	}

	/* ---------------------------------------------------------------------
	 * Sweep
	 * ------------------------------------------------------------------ */

	public static function maybe_schedule(): void {
		if ( ! self::is_enabled() ) {
			self::clear_schedule();

			return;
		}
		if ( ! function_exists( 'wp_next_scheduled' ) || ! function_exists( 'wp_schedule_event' ) ) {
			return;
		}
		if ( ! wp_next_scheduled( self::CRON_HOOK ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'hourly', self::CRON_HOOK );
		}
	}

	public static function clear_schedule(): void {
		if ( function_exists( 'wp_clear_scheduled_hook' ) ) {
			wp_clear_scheduled_hook( self::CRON_HOOK );
		}
	}

	public static function cron_run(): void {
		self::sweep();
	}

	public static function maybe_sweep(): void {
		if ( ! self::is_enabled() ) {
			return;
		}
		self::sweep();
	}

	/**
	 * @return array{notified:int,expired:int}
	 */
	public static function sweep( ?int $now = null ): array {
		$now = null !== $now ? (int) $now : ( class_exists( Clock::class, false ) ? Clock::now() : time() );
		$out = array(
			'notified' => 0,
			'expired'  => 0,
		);
		if ( ! self::is_enabled() ) {
			return $out;
		}
		if ( ! class_exists( Access_Request::class, false ) || ! method_exists( Access_Request::class, 'pending_rows' ) ) {
			return $out;
		}

		$settings    = self::get_settings();
		$sla_seconds = $settings['sla_hours'] * ( defined( 'HOUR_IN_SECONDS' ) ? (int) HOUR_IN_SECONDS : 3600 );
		$expire_sec  = $settings['expire_days'] > 0
			? $settings['expire_days'] * ( defined( 'DAY_IN_SECONDS' ) ? (int) DAY_IN_SECONDS : 86400 )
			: 0;

		foreach ( Access_Request::pending_rows() as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$id = self::sanitize_request_id( (string) ( $row['id'] ?? '' ) );
			$ts = (int) ( $row['ts'] ?? 0 );
			if ( '' === $id || $ts <= 0 ) {
				continue;
			}
			$age = $now - $ts;
			if ( $expire_sec > 0 && $age >= $expire_sec ) {
				if ( self::expire_request( $row, $now ) ) {
					++$out['expired'];
				}
				continue;
			}
			if ( $age < $sla_seconds ) {
				continue;
			}
			if ( self::was_notified( $id ) ) {
				continue;
			}
			if ( self::notify_request( $row, $now ) ) {
				++$out['notified'];
			}
		}

		return $out;
	}

	/**
	 * @param array<string,mixed> $row Pending Access_Request row.
	 */
	public static function notify_request( array $row, int $now ): bool {
		$id = self::sanitize_request_id( (string) ( $row['id'] ?? '' ) );
		if ( '' === $id || self::was_notified( $id ) ) {
			return false;
		}
		$recipients = self::deputy_recipients();
		if ( array() === $recipients ) {
			return false;
		}
		$plugin = class_exists( Plugin_Profile::class, false )
			? Plugin_Profile::sanitize_plugin( (string) ( $row['plugin'] ?? '' ) )
			: (string) ( $row['plugin'] ?? '' );
		$sent   = false;
		foreach ( $recipients as $recipient ) {
			if ( self::email_deputy( $row, $recipient, $now ) ) {
				$sent = true;
			}
		}
		if ( ! $sent ) {
			return false;
		}
		self::mark_notified( $id, 'deputy', $now );
		if ( class_exists( Policy::class, false ) && method_exists( Policy::class, 'append_log_event' ) ) {
			Policy::append_log_event(
				array(
					'ts'        => $now,
					'plugin'    => $plugin,
					'decision'  => 'deputy_notified',
					'channel'   => 'deputy',
					'source'    => 'deputy',
					'actor_id'  => 0,
					'reason'    => sprintf(
						'deputy notified (SLA breach, requester waited %dh)',
						self::waited_hours( (int) ( $row['ts'] ?? 0 ), $now )
					),
					'operation' => '',
					'provider'  => '',
				)
			);
		}

		return true;
	}

	/**
	 * @param array<string,mixed> $row Pending Access_Request row.
	 */
	public static function expire_request( array $row, int $now ): bool {
		$id = self::sanitize_request_id( (string) ( $row['id'] ?? '' ) );
		if ( '' === $id ) {
			return false;
		}
		$plugin = class_exists( Plugin_Profile::class, false )
			? Plugin_Profile::sanitize_plugin( (string) ( $row['plugin'] ?? '' ) )
			: (string) ( $row['plugin'] ?? '' );
		$result = Access_Request::deny( $id, 0, $now );
		if ( empty( $result['ok'] ) ) {
			return false;
		}
		self::mark_notified( $id, 'expired', $now );
		$hours   = self::waited_hours( (int) ( $row['ts'] ?? 0 ), $now );
		$days    = (int) self::get_settings()['expire_days'];
		$reason  = sprintf( 'expired after %d days (requester waited %dh)', $days, $hours );
		if ( class_exists( Policy::class, false ) && method_exists( Policy::class, 'append_log_event' ) ) {
			Policy::append_log_event(
				array(
					'ts'        => $now,
					'plugin'    => $plugin,
					'decision'  => 'deputy_expired',
					'channel'   => 'deputy',
					'source'    => 'deputy',
					'actor_id'  => 0,
					'reason'    => $reason,
					'operation' => '',
					'provider'  => '',
				)
			);
		}
		self::email_requester_expired( $row, $reason, $now );

		return true;
	}

	/* ---------------------------------------------------------------------
	 * Signed links (own store; no manage_options)
	 * ------------------------------------------------------------------ */

	public static function mint_url( string $action, string $request_id, string $plugin, ?int $now = null ): string {
		$action     = self::sanitize_action( $action );
		$request_id = self::sanitize_request_id( $request_id );
		$plugin     = class_exists( Plugin_Profile::class, false )
			? Plugin_Profile::sanitize_plugin( $plugin )
			: $plugin;
		$now        = null !== $now ? (int) $now : ( class_exists( Clock::class, false ) ? Clock::now() : time() );
		if ( '' === $action || '' === $request_id || '' === $plugin ) {
			return '';
		}
		$id  = self::new_id();
		$exp = $now + self::TOKEN_TTL;
		$sig = self::signature_for( $id, $action, $request_id, $plugin, $exp );

		$map        = self::get_tokens();
		$map        = self::purge_expired_tokens( $map, $now );
		$map[ $id ] = array(
			'action'     => $action,
			'request_id' => $request_id,
			'plugin'     => $plugin,
			'exp'        => $exp,
			'used'       => false,
		);
		self::save_tokens( $map );

		return add_query_arg(
			array(
				'action' => self::OPEN_HOOK,
				't'      => $id,
				's'      => $sig,
			),
			admin_url( 'admin-post.php' )
		);
	}

	/**
	 * @return array{ok:bool,error:string,row:?array<string,mixed>}
	 */
	public static function inspect( string $id, string $sig, ?int $now = null ): array {
		$empty = array(
			'ok'    => false,
			'error' => 'invalid',
			'row'   => null,
		);
		$id    = self::sanitize_token_id( $id );
		$sig   = self::sanitize_sig( $sig );
		if ( '' === $id || '' === $sig ) {
			return $empty;
		}
		$now  = null !== $now ? (int) $now : ( class_exists( Clock::class, false ) ? Clock::now() : time() );
		$map  = self::get_tokens();
		if ( ! isset( $map[ $id ] ) || ! is_array( $map[ $id ] ) ) {
			return $empty;
		}
		$row = self::sanitize_token_row( $map[ $id ] );
		if ( null === $row ) {
			return $empty;
		}
		$expected = self::signature_for( $id, $row['action'], $row['request_id'], $row['plugin'], $row['exp'] );
		if ( ! hash_equals( $expected, $sig ) ) {
			return $empty;
		}
		if ( ! empty( $row['used'] ) ) {
			return array(
				'ok'    => false,
				'error' => 'used',
				'row'   => $row,
			);
		}
		if ( (int) $row['exp'] <= $now ) {
			return array(
				'ok'    => false,
				'error' => 'expired',
				'row'   => $row,
			);
		}

		return array(
			'ok'    => true,
			'error' => '',
			'row'   => $row,
		);
	}

	/**
	 * @param array<string,mixed> $row Token row.
	 * @return array{ok:bool,error:string,message:string}
	 */
	public static function apply_verified( array $row, string $id, int $user_id, ?int $now = null ): array {
		$id     = self::sanitize_token_id( $id );
		$action = self::sanitize_action( (string) ( $row['action'] ?? '' ) );
		$req_id = self::sanitize_request_id( (string) ( $row['request_id'] ?? '' ) );
		$plugin = class_exists( Plugin_Profile::class, false )
			? Plugin_Profile::sanitize_plugin( (string) ( $row['plugin'] ?? '' ) )
			: (string) ( $row['plugin'] ?? '' );
		if ( '' === $id || '' === $action || '' === $req_id || '' === $plugin ) {
			return array(
				'ok'      => false,
				'error'   => 'invalid',
				'message' => self::error_message( 'invalid' ),
			);
		}
		$now = null !== $now ? (int) $now : ( class_exists( Clock::class, false ) ? Clock::now() : time() );
		if ( ! self::is_deputy( $user_id ) && ! self::current_user_is_admin( $user_id ) ) {
			return array(
				'ok'      => false,
				'error'   => 'cap',
				'message' => self::error_message( 'cap' ),
			);
		}
		if ( ! class_exists( Access_Request::class, false ) ) {
			return array(
				'ok'      => false,
				'error'   => 'invalid',
				'message' => self::error_message( 'invalid' ),
			);
		}

		$pending = self::pending_row( $req_id );
		$waited  = self::waited_hours( (int) ( $pending['ts'] ?? 0 ), $now );
		$who     = self::actor_label( $user_id );

		if ( self::ACT_APPROVE === $action ) {
			$result = Access_Request::approve( $req_id, $user_id, $now );
			$verb   = 'approved';
		} else {
			$result = Access_Request::deny( $req_id, $user_id, $now );
			$verb   = 'denied';
		}
		if ( empty( $result['ok'] ) ) {
			return array(
				'ok'      => false,
				'error'   => 'invalid',
				'message' => self::error_message( 'invalid' ),
			);
		}

		self::mark_token_used( $id );
		$reason = sprintf( '%s by deputy %s (SLA breach, requester waited %dh)', $verb, $who, $waited );
		if ( class_exists( Policy::class, false ) && method_exists( Policy::class, 'append_log_event' ) ) {
			Policy::append_log_event(
				array(
					'ts'        => $now,
					'plugin'    => $plugin,
					'decision'  => 'approved' === $verb ? 'deputy_approved' : 'deputy_denied',
					'channel'   => 'deputy',
					'source'    => 'deputy',
					'actor_id'  => $user_id,
					'reason'    => $reason,
					'operation' => '',
					'provider'  => '',
				)
			);
		}

		return array(
			'ok'      => true,
			'error'   => '',
			'message' => self::success_message( $action ),
		);
	}

	public static function error_message( string $code ): string {
		if ( 'expired' === $code ) {
			return __( 'This link has expired. Nothing was changed.', 'handl-ai-connector-access-control' );
		}
		if ( 'used' === $code ) {
			return __( 'This link was already used. Nothing was changed.', 'handl-ai-connector-access-control' );
		}
		if ( 'cap' === $code ) {
			return __( 'You are not the designated deputy for this request. Nothing was changed.', 'handl-ai-connector-access-control' );
		}

		return __( 'This link is not valid. Nothing was changed.', 'handl-ai-connector-access-control' );
	}

	public static function success_message( string $action ): string {
		if ( self::ACT_APPROVE === $action ) {
			return __( 'This plugin is allowed for 24 hours (deputy approval).', 'handl-ai-connector-access-control' );
		}

		return __( 'The access request was denied (deputy).', 'handl-ai-connector-access-control' );
	}

	public static function handle_open(): void {
		if ( function_exists( 'nocache_headers' ) ) {
			nocache_headers();
		}
		if ( function_exists( 'is_user_logged_in' ) && ! is_user_logged_in() ) {
			if ( function_exists( 'auth_redirect' ) ) {
				auth_redirect();
			}
			self::halt( self::error_message( 'cap' ) );

			return;
		}
		$id  = isset( $_GET['t'] ) ? self::sanitize_token_id( wp_unslash( (string) $_GET['t'] ) ) : '';
		$sig = isset( $_GET['s'] ) ? self::sanitize_sig( wp_unslash( (string) $_GET['s'] ) ) : '';
		$got = self::inspect( $id, $sig );
		if ( ! $got['ok'] || ! is_array( $got['row'] ) ) {
			self::halt( self::error_message( (string) $got['error'] ) );

			return;
		}
		$user_id = (int) get_current_user_id();
		if ( ! self::is_deputy( $user_id ) && ! self::current_user_is_admin( $user_id ) ) {
			self::halt( self::error_message( 'cap' ) );

			return;
		}
		self::render_confirm( $id, $sig, $got['row'] );
	}

	public static function handle_apply(): void {
		if ( function_exists( 'nocache_headers' ) ) {
			nocache_headers();
		}
		if ( function_exists( 'is_user_logged_in' ) && ! is_user_logged_in() ) {
			self::halt( self::error_message( 'cap' ) );

			return;
		}
		check_admin_referer( self::NONCE_APPLY );
		$id  = isset( $_POST['t'] ) ? self::sanitize_token_id( wp_unslash( (string) $_POST['t'] ) ) : '';
		$sig = isset( $_POST['s'] ) ? self::sanitize_sig( wp_unslash( (string) $_POST['s'] ) ) : '';
		$got = self::inspect( $id, $sig );
		if ( ! $got['ok'] || ! is_array( $got['row'] ) ) {
			self::halt( self::error_message( (string) $got['error'] ) );

			return;
		}
		$result = self::apply_verified( $got['row'], $id, (int) get_current_user_id() );
		self::halt( $result['message'] );
	}

	/**
	 * @param array<string,mixed> $row Token row.
	 */
	public static function render_confirm( string $id, string $sig, array $row ): void {
		$action  = self::sanitize_action( (string) ( $row['action'] ?? '' ) );
		$plugin  = (string) ( $row['plugin'] ?? '' );
		$req_id  = (string) ( $row['request_id'] ?? '' );
		$pending = self::pending_row( $req_id );
		$who     = (string) ( $pending['user_login'] ?? '' );
		if ( '' === $who && isset( $pending['user_id'] ) ) {
			$who = 'user#' . (string) (int) $pending['user_id'];
		}
		$waited = self::waited_hours( (int) ( $pending['ts'] ?? 0 ), class_exists( Clock::class, false ) ? Clock::now() : time() );
		$verb   = self::ACT_APPROVE === $action
			? __( 'Approve this AI access request for 24 hours?', 'handl-ai-connector-access-control' )
			: __( 'Deny this AI access request?', 'handl-ai-connector-access-control' );

		echo '<div class="wrap">';
		echo '<h1>' . esc_html__( 'Deputy decision', 'handl-ai-connector-access-control' ) . '</h1>';
		echo '<p>' . esc_html( $verb ) . '</p>';
		echo '<ul>';
		echo '<li>' . esc_html( sprintf( /* translators: %s: plugin file */ __( 'Plugin: %s', 'handl-ai-connector-access-control' ), $plugin ) ) . '</li>';
		if ( '' !== $who ) {
			echo '<li>' . esc_html( sprintf( /* translators: %s: login */ __( 'Requested by: %s', 'handl-ai-connector-access-control' ), $who ) ) . '</li>';
		}
		echo '<li>' . esc_html( sprintf( /* translators: %d: hours */ __( 'Requester has waited: %d hours', 'handl-ai-connector-access-control' ), $waited ) ) . '</li>';
		echo '</ul>';
		echo '<p>' . esc_html__( 'This link is scoped to this one request. It does not grant any other capability.', 'handl-ai-connector-access-control' ) . '</p>';
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
		echo '<input type="hidden" name="action" value="' . esc_attr( self::APPLY_HOOK ) . '" />';
		echo '<input type="hidden" name="t" value="' . esc_attr( $id ) . '" />';
		echo '<input type="hidden" name="s" value="' . esc_attr( $sig ) . '" />';
		if ( function_exists( 'wp_nonce_field' ) ) {
			wp_nonce_field( self::NONCE_APPLY );
		}
		$button = self::ACT_APPROVE === $action
			? __( 'Approve for 24 hours', 'handl-ai-connector-access-control' )
			: __( 'Deny request', 'handl-ai-connector-access-control' );
		echo '<p><button type="submit" class="button button-primary">' . esc_html( $button ) . '</button></p>';
		echo '</form>';
		echo '</div>';
	}

	/* ---------------------------------------------------------------------
	 * Admin UI
	 * ------------------------------------------------------------------ */

	public static function register_menu(): void {
		if ( ! class_exists( Caps::class, false ) || ! Caps::user_can_view() ) {
			return;
		}
		if ( ! function_exists( 'add_submenu_page' ) || ! class_exists( Admin::class, false ) ) {
			return;
		}
		add_submenu_page(
			Admin::MENU_SLUG,
			__( 'Deputy', 'handl-ai-connector-access-control' ),
			__( 'Deputy', 'handl-ai-connector-access-control' ),
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
		$enabled    = self::is_enabled();
		$now        = class_exists( Clock::class, false ) ? Clock::now() : time();

		echo '<div class="wrap">';
		echo '<h1>' . esc_html__( 'Deputy', 'handl-ai-connector-access-control' ) . '</h1>';
		echo '<p class="description">' . esc_html__( 'When a pending AI access request waits longer than the SLA, notify a designated deputy. The site owner stays the primary approver. Deputy links approve or deny that one request only. Off by default.', 'handl-ai-connector-access-control' ) . '</p>';

		if ( $can_manage ) {
			$action = admin_url( 'admin-post.php' );
			echo '<form method="post" action="' . esc_url( $action ) . '">';
			echo '<input type="hidden" name="action" value="' . esc_attr( self::ACTION_SAVE ) . '" />';
			if ( function_exists( 'wp_nonce_field' ) ) {
				wp_nonce_field( self::ACTION_SAVE );
			}
			echo '<input type="hidden" name="' . esc_attr( self::POST_PRESENT ) . '" value="1" />';
			echo '<table class="form-table" role="presentation"><tbody>';
			echo '<tr><th scope="row">' . esc_html__( 'Enable deputy', 'handl-ai-connector-access-control' ) . '</th><td>';
			echo '<label><input type="checkbox" name="' . esc_attr( self::POST_ENABLED ) . '" value="1" ' . checked( ! empty( $settings['enabled'] ), true, false ) . ' /> ';
			echo esc_html__( 'Notify a backup approver after the SLA window', 'handl-ai-connector-access-control' );
			echo '</label></td></tr>';
			echo '<tr><th scope="row"><label for="handl-aicac-deputy-user">' . esc_html__( 'Deputy user ID', 'handl-ai-connector-access-control' ) . '</label></th><td>';
			echo '<input name="' . esc_attr( self::POST_USER ) . '" id="handl-aicac-deputy-user" type="number" min="0" step="1" value="' . esc_attr( (string) (int) $settings['deputy_user_id'] ) . '" class="small-text" />';
			echo '<p class="description">' . esc_html__( 'WordPress user ID of the backup approver. Takes precedence over role.', 'handl-ai-connector-access-control' ) . '</p>';
			echo '</td></tr>';
			echo '<tr><th scope="row"><label for="handl-aicac-deputy-role">' . esc_html__( 'Deputy role', 'handl-ai-connector-access-control' ) . '</label></th><td>';
			echo '<input name="' . esc_attr( self::POST_ROLE ) . '" id="handl-aicac-deputy-role" type="text" value="' . esc_attr( (string) $settings['deputy_role'] ) . '" class="regular-text" />';
			echo '<p class="description">' . esc_html__( 'Used when no user ID is set. Any user with this role may use the signed link. Administrator is ignored.', 'handl-ai-connector-access-control' ) . '</p>';
			echo '</td></tr>';
			echo '<tr><th scope="row"><label for="handl-aicac-deputy-sla">' . esc_html__( 'SLA window (hours)', 'handl-ai-connector-access-control' ) . '</label></th><td>';
			echo '<input name="' . esc_attr( self::POST_SLA ) . '" id="handl-aicac-deputy-sla" type="number" min="' . esc_attr( (string) self::MIN_SLA_HOURS ) . '" max="' . esc_attr( (string) self::MAX_SLA_HOURS ) . '" step="1" value="' . esc_attr( (string) (int) $settings['sla_hours'] ) . '" class="small-text" />';
			echo '<p class="description">' . esc_html__( 'Default 48. The deputy is notified only after a pending request is this old.', 'handl-ai-connector-access-control' ) . '</p>';
			echo '</td></tr>';
			echo '<tr><th scope="row"><label for="handl-aicac-deputy-expire">' . esc_html__( 'Auto-expire (days)', 'handl-ai-connector-access-control' ) . '</label></th><td>';
			echo '<input name="' . esc_attr( self::POST_EXPIRE ) . '" id="handl-aicac-deputy-expire" type="number" min="0" max="' . esc_attr( (string) self::MAX_EXPIRE_DAYS ) . '" step="1" value="' . esc_attr( (string) (int) $settings['expire_days'] ) . '" class="small-text" />';
			echo '<p class="description">' . esc_html__( 'Optional. After this many days a pending request is denied and the requester can ask again. 0 keeps requests open.', 'handl-ai-connector-access-control' ) . '</p>';
			echo '</td></tr></tbody></table>';
			submit_button( __( 'Save deputy settings', 'handl-ai-connector-access-control' ) );
			echo '</form>';
		}

		if ( ! $enabled ) {
			echo '<p>' . esc_html__( 'Deputy is off. The site owner remains the only approver of AI access requests.', 'handl-ai-connector-access-control' ) . '</p>';
			echo '</div>';

			return;
		}

		echo '<p><strong>' . esc_html__( 'The site owner stays the primary approver. Deputy links arm only after the SLA.', 'handl-ai-connector-access-control' ) . '</strong></p>';

		$who = self::deputy_identity_label();
		echo '<ul>';
		echo '<li>' . esc_html( sprintf( /* translators: %s: identity */ __( 'Deputy: %s', 'handl-ai-connector-access-control' ), $who ) ) . '</li>';
		echo '<li>' . esc_html( sprintf( /* translators: %d: hours */ __( 'SLA: %d hours', 'handl-ai-connector-access-control' ), (int) $settings['sla_hours'] ) ) . '</li>';
		if ( (int) $settings['expire_days'] > 0 ) {
			echo '<li>' . esc_html( sprintf( /* translators: %d: days */ __( 'Auto-expire after %d days', 'handl-ai-connector-access-control' ), (int) $settings['expire_days'] ) ) . '</li>';
		} else {
			echo '<li>' . esc_html__( 'Auto-expire is off.', 'handl-ai-connector-access-control' ) . '</li>';
		}
		echo '</ul>';

		$overdue = self::overdue_pending( $now );
		echo '<h2>' . esc_html__( 'Overdue requests', 'handl-ai-connector-access-control' ) . '</h2>';
		if ( array() === $overdue ) {
			echo '<p>' . esc_html__( 'No pending requests older than the SLA.', 'handl-ai-connector-access-control' ) . '</p>';
		} else {
			echo '<table class="widefat striped"><thead><tr>';
			echo '<th>' . esc_html__( 'Plugin', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Requested by', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Waited', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Deputy notified', 'handl-ai-connector-access-control' ) . '</th>';
			echo '</tr></thead><tbody>';
			foreach ( $overdue as $row ) {
				$login = (string) ( $row['user_login'] ?? '' );
				if ( '' === $login ) {
					$login = 'user#' . (string) (int) ( $row['user_id'] ?? 0 );
				}
				$hours    = self::waited_hours( (int) ( $row['ts'] ?? 0 ), $now );
				$notified = self::was_notified( (string) ( $row['id'] ?? '' ) )
					? __( 'yes', 'handl-ai-connector-access-control' )
					: __( 'no', 'handl-ai-connector-access-control' );
				echo '<tr>';
				echo '<td><code>' . esc_html( (string) ( $row['plugin'] ?? '' ) ) . '</code></td>';
				echo '<td>' . esc_html( $login ) . '</td>';
				echo '<td>' . esc_html( (string) $hours . 'h' ) . '</td>';
				echo '<td>' . esc_html( $notified ) . '</td>';
				echo '</tr>';
			}
			echo '</tbody></table>';
		}

		echo '</div>';
	}

	public static function handle_save(): void {
		if ( function_exists( 'nocache_headers' ) ) {
			nocache_headers();
		}
		if ( ! class_exists( Caps::class, false ) || ! Caps::user_can_manage() ) {
			self::halt( __( 'You need permission to manage these settings.', 'handl-ai-connector-access-control' ) );

			return;
		}
		check_admin_referer( self::ACTION_SAVE );
		if ( empty( $_POST[ self::POST_PRESENT ] ) ) {
			self::halt( __( 'Security check failed. Go back, reload the page, and try again.', 'handl-ai-connector-access-control' ) );

			return;
		}
		self::save_settings(
			array(
				'enabled'        => ! empty( $_POST[ self::POST_ENABLED ] ),
				'deputy_user_id' => isset( $_POST[ self::POST_USER ] ) ? (int) wp_unslash( (string) $_POST[ self::POST_USER ] ) : 0,
				'deputy_role'    => isset( $_POST[ self::POST_ROLE ] ) ? wp_unslash( (string) $_POST[ self::POST_ROLE ] ) : '',
				'sla_hours'      => isset( $_POST[ self::POST_SLA ] ) ? wp_unslash( (string) $_POST[ self::POST_SLA ] ) : self::DEFAULT_SLA_HOURS,
				'expire_days'    => isset( $_POST[ self::POST_EXPIRE ] ) ? wp_unslash( (string) $_POST[ self::POST_EXPIRE ] ) : 0,
			)
		);
		$url = function_exists( 'admin_url' )
			? add_query_arg( array( 'page' => self::PAGE_SLUG, 'updated' => '1' ), admin_url( 'admin.php' ) )
			: '';
		if ( '' !== $url && function_exists( 'wp_safe_redirect' ) ) {
			wp_safe_redirect( $url );
			exit;
		}
		self::halt( __( 'Deputy settings saved.', 'handl-ai-connector-access-control' ) );
	}

	/* ---------------------------------------------------------------------
	 * Mail
	 * ------------------------------------------------------------------ */

	/**
	 * @param array<string,mixed>                    $row Pending request.
	 * @param array{user_id:int,email:string,login:string} $recipient Recipient.
	 */
	private static function email_deputy( array $row, array $recipient, int $now ): bool {
		$email = self::sanitize_email_addr( (string) ( $recipient['email'] ?? '' ) );
		if ( '' === $email ) {
			return false;
		}
		$plugin = (string) ( $row['plugin'] ?? '' );
		$who    = (string) ( $row['user_login'] ?? '' );
		if ( '' === $who ) {
			$who = 'user#' . (string) (int) ( $row['user_id'] ?? 0 );
		}
		$hours = self::waited_hours( (int) ( $row['ts'] ?? 0 ), $now );
		$site  = function_exists( 'get_bloginfo' )
			? wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES )
			: 'WordPress';
		$subject = sprintf(
			/* translators: 1: site name */
			__( '[%1$s] [DEPUTY] AI access request waiting on the owner', 'handl-ai-connector-access-control' ),
			$site
		);
		$approve = self::mint_url( self::ACT_APPROVE, (string) ( $row['id'] ?? '' ), $plugin, $now );
		$deny    = self::mint_url( self::ACT_DENY, (string) ( $row['id'] ?? '' ), $plugin, $now );
		$body    = __( 'A pending AI access request is older than the SLA. The site owner has not decided. You are the designated deputy.', 'handl-ai-connector-access-control' ) . "\n\n";
		$body   .= __( 'Plugin:', 'handl-ai-connector-access-control' ) . ' ' . $plugin . "\n";
		$body   .= __( 'Requested by:', 'handl-ai-connector-access-control' ) . ' ' . $who . "\n";
		$body   .= sprintf(
			/* translators: %d: hours */
			__( 'Requester has waited: %d hours', 'handl-ai-connector-access-control' ),
			$hours
		) . "\n\n";
		$body .= __( 'Approve this request for 24 hours:', 'handl-ai-connector-access-control' ) . "\n" . $approve . "\n\n";
		$body .= __( 'Deny this request:', 'handl-ai-connector-access-control' ) . "\n" . $deny . "\n\n";
		$body .= __( 'You must log in. These links do not grant any other capability and apply only to this request.', 'handl-ai-connector-access-control' ) . "\n";

		$ok = self::send_mail( $email, $subject, $body );
		self::$test_mails[] = array(
			'to'      => $email,
			'subject' => $subject,
			'body'    => $body,
			'kind'    => 'deputy',
		);

		return $ok;
	}

	/**
	 * @param array<string,mixed> $row Pending request (pre-deny snapshot).
	 */
	private static function email_requester_expired( array $row, string $reason, int $now ): void {
		unset( $now );
		$user_id = (int) ( $row['user_id'] ?? 0 );
		$user    = ( $user_id > 0 && function_exists( 'get_userdata' ) ) ? get_userdata( $user_id ) : false;
		$email   = ( is_object( $user ) && isset( $user->user_email ) )
			? self::sanitize_email_addr( (string) $user->user_email )
			: '';
		if ( '' === $email ) {
			return;
		}
		$plugin = (string) ( $row['plugin'] ?? '' );
		$site   = function_exists( 'get_bloginfo' )
			? wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES )
			: 'WordPress';
		$subject = sprintf(
			/* translators: 1: site name */
			__( '[%1$s] Your AI access request expired', 'handl-ai-connector-access-control' ),
			$site
		);
		$reask = function_exists( 'admin_url' ) ? admin_url() : '';
		$body  = __( "Your AI access request expired because it waited longer than this site's auto-expire window.", 'handl-ai-connector-access-control' ) . "\n\n";
		$body .= __( 'Plugin:', 'handl-ai-connector-access-control' ) . ' ' . $plugin . "\n";
		$body .= __( 'Reason:', 'handl-ai-connector-access-control' ) . ' ' . $reason . "\n\n";
		$body .= __( 'You can sign in and request access again.', 'handl-ai-connector-access-control' ) . "\n";
		if ( '' !== $reask ) {
			$body .= $reask . "\n";
		}
		self::send_mail( $email, $subject, $body );
		self::$test_mails[] = array(
			'to'      => $email,
			'subject' => $subject,
			'body'    => $body,
			'kind'    => 'expired',
		);
	}

	private static function send_mail( string $email, string $subject, string $body ): bool {
		if ( class_exists( Alerts::class, false ) && method_exists( Alerts::class, 'safe_wp_mail' ) ) {
			return (bool) Alerts::safe_wp_mail( $email, $subject, $body );
		}
		if ( function_exists( 'wp_mail' ) ) {
			return (bool) wp_mail( $email, $subject, $body );
		}

		return true;
	}

	/* ---------------------------------------------------------------------
	 * Internals
	 * ------------------------------------------------------------------ */

	/**
	 * @return list<array<string,mixed>>
	 */
	public static function overdue_pending( int $now ): array {
		if ( ! class_exists( Access_Request::class, false ) || ! method_exists( Access_Request::class, 'pending_rows' ) ) {
			return array();
		}
		$sla = self::get_settings()['sla_hours'] * ( defined( 'HOUR_IN_SECONDS' ) ? (int) HOUR_IN_SECONDS : 3600 );
		$out = array();
		foreach ( Access_Request::pending_rows() as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			if ( ( $now - (int) ( $row['ts'] ?? 0 ) ) >= $sla ) {
				$out[] = $row;
			}
		}

		return $out;
	}

	public static function deputy_identity_label(): string {
		$settings = self::get_settings();
		if ( $settings['deputy_user_id'] > 0 ) {
			return self::actor_label( $settings['deputy_user_id'] ) . ' (#' . (string) $settings['deputy_user_id'] . ')';
		}
		if ( '' !== $settings['deputy_role'] ) {
			return $settings['deputy_role'];
		}

		return __( 'not set', 'handl-ai-connector-access-control' );
	}

	/**
	 * @return array<string,mixed>|null
	 */
	private static function pending_row( string $id ): ?array {
		$id = self::sanitize_request_id( $id );
		if ( '' === $id || ! class_exists( Access_Request::class, false ) ) {
			return null;
		}
		foreach ( Access_Request::pending_rows() as $row ) {
			if ( $id === self::sanitize_request_id( (string) ( $row['id'] ?? '' ) ) ) {
				return $row;
			}
		}

		return null;
	}

	private static function current_user_is_admin( int $user_id ): bool {
		if ( $user_id <= 0 || (int) get_current_user_id() !== $user_id ) {
			return false;
		}

		return class_exists( Caps::class, false ) ? Caps::user_can_manage() : current_user_can( 'manage_options' );
	}

	/**
	 * @return array{user_id:int,email:string,login:string}|null
	 */
	private static function recipient_from_user_id( int $user_id ): ?array {
		if ( $user_id <= 0 || ! function_exists( 'get_userdata' ) ) {
			return null;
		}
		$user = get_userdata( $user_id );

		return is_object( $user ) ? self::recipient_from_user( $user ) : null;
	}

	/**
	 * @param object $user User-like.
	 * @return array{user_id:int,email:string,login:string}|null
	 */
	private static function recipient_from_user( $user ): ?array {
		if ( ! is_object( $user ) || ! isset( $user->ID ) ) {
			return null;
		}
		$email = isset( $user->user_email ) ? self::sanitize_email_addr( (string) $user->user_email ) : '';
		if ( '' === $email ) {
			return null;
		}

		return array(
			'user_id' => (int) $user->ID,
			'email'   => $email,
			'login'   => isset( $user->user_login ) ? sanitize_text_field( (string) $user->user_login ) : '',
		);
	}

	/**
	 * @return list<object>
	 */
	private static function users_for_role( string $role ): array {
		$role = self::sanitize_role( $role );
		if ( '' === $role ) {
			return array();
		}
		$store = $GLOBALS['handl_aicac_test_users'] ?? null;
		if ( is_array( $store ) ) {
			$out = array();
			foreach ( $store as $uid => $row ) {
				if ( ! is_array( $row ) ) {
					continue;
				}
				$roles = isset( $row['roles'] ) ? (array) $row['roles'] : array();
				if ( ! in_array( $role, $roles, true ) ) {
					continue;
				}
				$out[] = (object) array_merge( $row, array( 'ID' => (int) $uid ) );
			}

			return $out;
		}
		if ( function_exists( 'get_users' ) ) {
			$got = get_users(
				array(
					'role'   => $role,
					'number' => 20,
					'fields' => array( 'ID', 'user_email', 'user_login' ),
				)
			);

			return is_array( $got ) ? $got : array();
		}

		return array();
	}

	private static function sanitize_email_addr( string $raw ): string {
		$email = function_exists( 'sanitize_email' ) ? sanitize_email( $raw ) : trim( $raw );
		if ( '' === $email ) {
			return '';
		}
		if ( function_exists( 'is_email' ) && ! is_email( $email ) ) {
			return '';
		}

		return $email;
	}

	private static function sanitize_action( string $action ): string {
		$action = sanitize_key( $action );

		return in_array( $action, array( self::ACT_APPROVE, self::ACT_DENY ), true ) ? $action : '';
	}

	private static function sanitize_request_id( string $id ): string {
		$id = strtolower( preg_replace( '/[^a-f0-9]/', '', $id ) ?? '' );

		return ( 32 === strlen( $id ) ) ? $id : '';
	}

	private static function sanitize_token_id( string $id ): string {
		return self::sanitize_request_id( $id );
	}

	private static function sanitize_sig( string $sig ): string {
		$sig = strtolower( preg_replace( '/[^a-f0-9]/', '', $sig ) ?? '' );

		return ( 64 === strlen( $sig ) ) ? $sig : '';
	}

	/**
	 * @return array<string,array<string,mixed>>
	 */
	private static function get_tokens(): array {
		$raw = get_option( self::TOKEN_OPTION, array() );
		if ( ! is_array( $raw ) ) {
			return array();
		}
		$out = array();
		foreach ( $raw as $id => $row ) {
			$id = self::sanitize_token_id( (string) $id );
			if ( '' === $id || ! is_array( $row ) ) {
				continue;
			}
			$clean = self::sanitize_token_row( $row );
			if ( null === $clean ) {
				continue;
			}
			$out[ $id ] = $clean;
		}

		return $out;
	}

	/**
	 * @param array<string,mixed> $row Raw.
	 * @return array{action:string,request_id:string,plugin:string,exp:int,used:bool}|null
	 */
	private static function sanitize_token_row( array $row ): ?array {
		$action = self::sanitize_action( (string) ( $row['action'] ?? '' ) );
		$req    = self::sanitize_request_id( (string) ( $row['request_id'] ?? '' ) );
		$plugin = class_exists( Plugin_Profile::class, false )
			? Plugin_Profile::sanitize_plugin( (string) ( $row['plugin'] ?? '' ) )
			: (string) ( $row['plugin'] ?? '' );
		$exp    = isset( $row['exp'] ) ? (int) $row['exp'] : 0;
		if ( '' === $action || '' === $req || '' === $plugin || $exp <= 0 ) {
			return null;
		}

		return array(
			'action'     => $action,
			'request_id' => $req,
			'plugin'     => $plugin,
			'exp'        => $exp,
			'used'       => ! empty( $row['used'] ),
		);
	}

	/**
	 * @param array<string,array<string,mixed>> $map Map.
	 */
	private static function save_tokens( array $map ): void {
		if ( empty( $map ) ) {
			delete_option( self::TOKEN_OPTION );

			return;
		}
		update_option( self::TOKEN_OPTION, $map, false );
	}

	/**
	 * @param array<string,array<string,mixed>> $map Map.
	 * @return array<string,array<string,mixed>>
	 */
	private static function purge_expired_tokens( array $map, int $now ): array {
		foreach ( $map as $id => $row ) {
			$exp = isset( $row['exp'] ) ? (int) $row['exp'] : 0;
			if ( $exp <= $now ) {
				unset( $map[ $id ] );
			}
		}

		return $map;
	}

	private static function mark_token_used( string $id ): void {
		$map = self::get_tokens();
		if ( ! isset( $map[ $id ] ) ) {
			return;
		}
		$map[ $id ]['used'] = true;
		self::save_tokens( $map );
	}

	private static function signature_for( string $id, string $action, string $request_id, string $plugin, int $exp ): string {
		$payload = $id . '|' . $action . '|' . $request_id . '|' . $plugin . '|' . (string) $exp;

		return hash_hmac( 'sha256', $payload, self::secret() );
	}

	private static function secret(): string {
		if ( function_exists( 'wp_salt' ) ) {
			return (string) wp_salt( 'auth' ) . '|deputy';
		}

		return 'handl-aicac-deputy';
	}

	private static function new_id(): string {
		if ( function_exists( 'wp_generate_password' ) ) {
			$raw = wp_generate_password( 32, false, false );
			$hex = strtolower( preg_replace( '/[^a-f0-9]/', '', $raw ) ?? '' );
			if ( strlen( $hex ) >= 32 ) {
				return substr( $hex, 0, 32 );
			}
		}

		return bin2hex( random_bytes( 16 ) );
	}

	private static function halt( string $message ): void {
		self::$last_halt = $message;
		if ( defined( 'HANDL_AICAC_PHPUNIT' ) && HANDL_AICAC_PHPUNIT ) {
			return;
		}
		if ( function_exists( 'wp_die' ) ) {
			wp_die( esc_html( $message ) );
		}
		echo esc_html( $message );
		exit;
	}
}
