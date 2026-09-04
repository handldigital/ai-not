<?php
/**
 * AICAC-INBOX-ACTIONS: signed one-click actions in alert emails (#225).
 *
 * Tokens are HMAC-signed, stored server-side, single-use, and expire in 48h.
 * Clicking never changes state by itself: WordPress login, manage_options, and
 * a confirm nonce are required. Open-rule is read-only (no confirm, no consume).
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Mint / verify email action tokens and render admin-post confirm screens.
 */
final class Inbox_Actions {

	public const OPTION_KEY = 'handl_aicac_inbox_tokens';

	public const OPEN_HOOK  = 'handl_aicac_inbox';
	public const APPLY_HOOK = 'handl_aicac_inbox_apply';
	public const NONCE_KEY  = 'handl_aicac_inbox_apply';

	public const ACT_ALLOW_24H      = 'allow_24h';
	public const ACT_SNOOZE_7D      = 'snooze_7d';
	public const ACT_OPEN_RULE      = 'open_rule';
	public const ACT_ACCESS_APPROVE = 'access_approve';
	public const ACT_ACCESS_DENY    = 'access_deny';

	/** @var array{plugin?:string,kind?:string,recipient?:string}|null */
	private static $mail_context = null;

	private static ?Inbox_Actions $instance = null;

	public static function instance(): Inbox_Actions {
		if ( null === self::$instance ) {
			self::$instance = new Inbox_Actions();
		}
		return self::$instance;
	}

	public function init(): void {
		add_action( 'admin_post_' . self::OPEN_HOOK, array( $this, 'handle_open' ) );
		add_action( 'admin_post_nopriv_' . self::OPEN_HOOK, array( $this, 'handle_open' ) );
		add_action( 'admin_post_' . self::APPLY_HOOK, array( $this, 'handle_apply' ) );
		// No nopriv apply — unauthenticated POST must not change state.
	}

	/**
	 * Bind action links to the next Email_Template::compose() call.
	 *
	 * @param array{plugin:string,kind:string,recipient:string} $ctx
	 * @param callable                                          $fn
	 * @return mixed
	 */
	public static function with_mail( array $ctx, callable $fn ) {
		self::$mail_context = $ctx;
		try {
			return $fn();
		} finally {
			self::$mail_context = null;
		}
	}

	/**
	 * Footer lines (outside the content block) for the current mail context.
	 * Mints tokens once per compose().
	 *
	 * @return list<string>
	 */
	public static function email_footer_lines(): array {
		$ctx = self::$mail_context;
		if ( ! is_array( $ctx ) ) {
			return array();
		}

		$plugin    = Plugin_Profile::sanitize_plugin( (string) ( $ctx['plugin'] ?? '' ) );
		$recipient = self::sanitize_recipient( (string) ( $ctx['recipient'] ?? '' ) );
		$kind      = sanitize_key( (string) ( $ctx['kind'] ?? 'denial' ) );
		$now       = isset( $ctx['now'] ) ? (int) $ctx['now'] : time();
		if ( '' === $plugin || '' === $recipient ) {
			return array();
		}

		$lines = array();
		if ( 'access_request' === $kind ) {
			$lines[] = __( 'Approve — allow this plugin for 24 hours:', 'handl-ai-connector-access-control' );
			$lines[] = self::mint_url( self::ACT_ACCESS_APPROVE, $plugin, $recipient, $now );
			$lines[] = '';
			$lines[] = __( 'Deny this access request:', 'handl-ai-connector-access-control' );
			$lines[] = self::mint_url( self::ACT_ACCESS_DENY, $plugin, $recipient, $now );
			return $lines;
		}

		if ( 'denial' === $kind ) {
			$lines[] = __( 'Allow this plugin for 24 hours:', 'handl-ai-connector-access-control' );
			$lines[] = self::mint_url( self::ACT_ALLOW_24H, $plugin, $recipient, $now );
			$lines[] = '';
		}

		$lines[] = __( 'Snooze these alerts for 7 days:', 'handl-ai-connector-access-control' );
		$lines[] = self::mint_url( self::ACT_SNOOZE_7D, $plugin, $recipient, $now );
		$lines[] = '';
		$lines[] = __( 'Open this plugin’s rule:', 'handl-ai-connector-access-control' );
		$lines[] = self::mint_url( self::ACT_OPEN_RULE, $plugin, $recipient, $now );

		return $lines;
	}

	/**
	 * Public temp-allow apply used by Access_Request and inbox approve tokens.
	 */
	public static function apply_temp_allow_24h( string $plugin, ?int $now = null ): bool {
		$plugin = Plugin_Profile::sanitize_plugin( $plugin );
		if ( '' === $plugin ) {
			return false;
		}
		$now = null !== $now ? (int) $now : time();
		return self::apply_allow_24h( $plugin, $now );
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
		$id    = self::sanitize_id( $id );
		$sig   = self::sanitize_sig( $sig );
		if ( '' === $id || '' === $sig ) {
			return $empty;
		}

		$now  = null !== $now ? (int) $now : time();
		$map  = self::get_map();
		if ( ! isset( $map[ $id ] ) || ! is_array( $map[ $id ] ) ) {
			return $empty;
		}

		$row = self::sanitize_row( $map[ $id ] );
		if ( null === $row ) {
			return $empty;
		}

		$expected = self::signature_for( $id, $row['action'], $row['plugin'], $row['recipient'], $row['exp'] );
		if ( ! hash_equals( $expected, $sig ) ) {
			return $empty;
		}

		if ( ! empty( $row['used'] ) && self::ACT_OPEN_RULE !== $row['action'] ) {
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
	 * Apply a verified state-changing action. Open-rule is not applied here.
	 *
	 * @param array<string,mixed> $row
	 * @return array{ok:bool,error:string,message:string}
	 */
	public static function apply_verified( array $row, string $id, int $user_id, ?int $now = null ): array {
		$id     = self::sanitize_id( $id );
		$action = self::sanitize_action( (string) ( $row['action'] ?? '' ) );
		$plugin = Plugin_Profile::sanitize_plugin( (string) ( $row['plugin'] ?? '' ) );
		if ( '' === $id || '' === $plugin || self::ACT_OPEN_RULE === $action ) {
			return array(
				'ok'      => false,
				'error'   => 'invalid',
				'message' => self::error_message( 'invalid' ),
			);
		}

		$now = null !== $now ? (int) $now : time();

		if ( self::ACT_ALLOW_24H === $action ) {
			$ok = self::apply_allow_24h( $plugin, $now );
		} elseif ( self::ACT_ACCESS_APPROVE === $action ) {
			$ok = Access_Request::approve_plugin( $plugin, $user_id, $now )['ok'];
		} elseif ( self::ACT_ACCESS_DENY === $action ) {
			$ok = Access_Request::deny_plugin( $plugin, $user_id, $now )['ok'];
		} elseif ( self::ACT_SNOOZE_7D === $action ) {
			$ok = Alert_Snooze::set( $plugin, '7d', $now );
		} else {
			$ok = false;
		}

		if ( ! $ok ) {
			return array(
				'ok'      => false,
				'error'   => 'invalid',
				'message' => self::error_message( 'invalid' ),
			);
		}

		self::mark_used( $id );
		self::log_action( $plugin, $action, $user_id, (string) ( $row['recipient'] ?? '' ), $now );

		return array(
			'ok'      => true,
			'error'   => '',
			'message' => self::success_message( $action ),
		);
	}

	public static function rules_url( string $plugin ): string {
		$plugin = Plugin_Profile::sanitize_plugin( $plugin );
		return Admin::screen_url(
			'rules',
			array(
				'plugin' => $plugin,
			)
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
			return __( 'You need permission to manage these settings.', 'handl-ai-connector-access-control' );
		}

		return __( 'This link is not valid. Nothing was changed.', 'handl-ai-connector-access-control' );
	}

	public function handle_open(): void {
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

		if ( ! current_user_can( 'manage_options' ) ) {
			self::halt( self::error_message( 'cap' ) );
			return;
		}

		$id  = isset( $_GET['t'] ) ? self::sanitize_id( wp_unslash( (string) $_GET['t'] ) ) : '';
		$sig = isset( $_GET['s'] ) ? self::sanitize_sig( wp_unslash( (string) $_GET['s'] ) ) : '';
		$got = self::inspect( $id, $sig );
		if ( ! $got['ok'] || ! is_array( $got['row'] ) ) {
			self::halt( self::error_message( (string) $got['error'] ) );
			return;
		}

		$row = $got['row'];
		if ( self::ACT_OPEN_RULE === $row['action'] ) {
			if ( function_exists( 'wp_safe_redirect' ) ) {
				wp_safe_redirect( self::rules_url( (string) $row['plugin'] ) );
				exit;
			}
			self::halt( self::rules_url( (string) $row['plugin'] ) );
			return;
		}

		self::render_confirm( $id, $sig, $row );
	}

	public function handle_apply(): void {
		if ( function_exists( 'nocache_headers' ) ) {
			nocache_headers();
		}

		if ( function_exists( 'is_user_logged_in' ) && ! is_user_logged_in() ) {
			self::halt( self::error_message( 'cap' ) );
			return;
		}

		if ( ! current_user_can( 'manage_options' ) ) {
			self::halt( self::error_message( 'cap' ) );
			return;
		}

		check_admin_referer( self::NONCE_KEY );

		$id  = isset( $_POST['t'] ) ? self::sanitize_id( wp_unslash( (string) $_POST['t'] ) ) : '';
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
	 * @param mixed $raw
	 */
	private static function sanitize_recipient( $raw ): string {
		$email = Alerts::sanitize_email( $raw );
		if ( '' !== $email ) {
			return $email;
		}
		$list = Alert_Routing::sanitize_recipient_list( $raw );
		return ! empty( $list ) ? $list[0] : '';
	}

	private static function sanitize_id( string $id ): string {
		$id = strtolower( preg_replace( '/[^a-f0-9]/', '', $id ) ?? '' );
		return ( 32 === strlen( $id ) ) ? $id : '';
	}

	private static function sanitize_sig( string $sig ): string {
		$sig = strtolower( preg_replace( '/[^a-f0-9]/', '', $sig ) ?? '' );
		return ( 64 === strlen( $sig ) ) ? $sig : '';
	}

	private static function sanitize_action( string $action ): string {
		$action = sanitize_key( $action );
		$ok     = array(
			self::ACT_ALLOW_24H,
			self::ACT_SNOOZE_7D,
			self::ACT_OPEN_RULE,
			self::ACT_ACCESS_APPROVE,
			self::ACT_ACCESS_DENY,
		);
		return in_array( $action, $ok, true ) ? $action : '';
	}

	private static function mint_url( string $action, string $plugin, string $recipient, ?int $now = null ): string {
		$now = null !== $now ? (int) $now : time();
		$id  = self::new_id();
		$exp = $now + ( 48 * HOUR_IN_SECONDS );
		$sig = self::signature_for( $id, $action, $plugin, $recipient, $exp );

		$map        = self::get_map();
		$map        = self::purge_expired( $map, $now );
		$map[ $id ] = array(
			'action'    => $action,
			'plugin'    => $plugin,
			'recipient' => $recipient,
			'exp'       => $exp,
			'used'      => false,
		);
		self::save_map( $map );

		return add_query_arg(
			array(
				'action' => self::OPEN_HOOK,
				't'      => $id,
				's'      => $sig,
			),
			admin_url( 'admin-post.php' )
		);
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

	private static function signature_for( string $id, string $action, string $plugin, string $recipient, int $exp ): string {
		$payload = $id . '|' . $action . '|' . $plugin . '|' . $recipient . '|' . (string) $exp;
		return hash_hmac( 'sha256', $payload, self::secret() );
	}

	private static function secret(): string {
		if ( function_exists( 'wp_salt' ) ) {
			return (string) wp_salt( 'auth' );
		}

		return 'handl-aicac-inbox';
	}

	/**
	 * @return array<string,array<string,mixed>>
	 */
	private static function get_map(): array {
		$raw = get_option( self::OPTION_KEY, array() );
		if ( ! is_array( $raw ) ) {
			return array();
		}
		$out = array();
		foreach ( $raw as $id => $row ) {
			$id = self::sanitize_id( (string) $id );
			if ( '' === $id || ! is_array( $row ) ) {
				continue;
			}
			$clean = self::sanitize_row( $row );
			if ( null === $clean ) {
				continue;
			}
			$out[ $id ] = $clean;
		}

		return $out;
	}

	/**
	 * @param array<string,mixed> $row
	 * @return array{action:string,plugin:string,recipient:string,exp:int,used:bool}|null
	 */
	private static function sanitize_row( array $row ): ?array {
		$action    = self::sanitize_action( (string) ( $row['action'] ?? '' ) );
		$plugin    = Plugin_Profile::sanitize_plugin( (string) ( $row['plugin'] ?? '' ) );
		$recipient = self::sanitize_recipient( (string) ( $row['recipient'] ?? '' ) );
		$exp       = isset( $row['exp'] ) ? (int) $row['exp'] : 0;
		if ( '' === $action || '' === $plugin || '' === $recipient || $exp <= 0 ) {
			return null;
		}

		return array(
			'action'    => $action,
			'plugin'    => $plugin,
			'recipient' => $recipient,
			'exp'       => $exp,
			'used'      => ! empty( $row['used'] ),
		);
	}

	/**
	 * @param array<string,array<string,mixed>> $map
	 */
	private static function save_map( array $map ): void {
		if ( empty( $map ) ) {
			delete_option( self::OPTION_KEY );
			return;
		}
		update_option( self::OPTION_KEY, $map, false );
	}

	/**
	 * @param array<string,array<string,mixed>> $map
	 * @return array<string,array<string,mixed>>
	 */
	private static function purge_expired( array $map, int $now ): array {
		foreach ( $map as $id => $row ) {
			$exp = isset( $row['exp'] ) ? (int) $row['exp'] : 0;
			if ( $exp <= $now ) {
				unset( $map[ $id ] );
			}
		}

		return $map;
	}

	private static function mark_used( string $id ): void {
		$map = self::get_map();
		if ( ! isset( $map[ $id ] ) ) {
			return;
		}
		$map[ $id ]['used'] = true;
		self::save_map( $map );
	}

	private static function apply_allow_24h( string $plugin, int $now ): bool {
		$policy  = Policy::get_policy();
		$plugins = isset( $policy['plugins'] ) && is_array( $policy['plugins'] ) ? $policy['plugins'] : array();
		$plugins[ $plugin ] = 'allow';
		$policy['plugins']  = $plugins;

		$expires = Temp_Allow::sanitize_plugin_expires( $policy['plugin_expires'] ?? array() );
		$expires[ $plugin ]   = $now + DAY_IN_SECONDS;
		$policy['plugin_expires'] = $expires;
		Temp_Allow::clear_warned( $plugin );

		Policy::save_policy( $policy );
		Temp_Allow::maybe_schedule( Policy::get_policy() );

		return true;
	}

	private static function log_action( string $plugin, string $action, int $user_id, string $recipient, int $now ): void {
		Policy::append_log_event(
			array(
				'ts'        => $now,
				'plugin'    => $plugin,
				'decision'  => 'inbox_' . $action,
				'channel'   => 'email',
				'source'    => 'email',
				'actor_id'  => $user_id,
				'recipient' => $recipient,
				'operation' => '',
				'provider'  => '',
			)
		);
	}

	private static function success_message( string $action ): string {
		if ( self::ACT_ALLOW_24H === $action || self::ACT_ACCESS_APPROVE === $action ) {
			return __( 'This plugin is allowed for 24 hours.', 'handl-ai-connector-access-control' );
		}
		if ( self::ACT_ACCESS_DENY === $action ) {
			return __( 'The access request was denied.', 'handl-ai-connector-access-control' );
		}
		if ( self::ACT_SNOOZE_7D === $action ) {
			return __( 'Alerts for this plugin are snoozed for 7 days.', 'handl-ai-connector-access-control' );
		}

		return __( 'Done.', 'handl-ai-connector-access-control' );
	}

	/**
	 * @param array<string,mixed> $row
	 */
	private static function render_confirm( string $id, string $sig, array $row ): void {
		$action  = (string) $row['action'];
		$plugin  = (string) $row['plugin'];
		$heading = __( 'Confirm this email action', 'handl-ai-connector-access-control' );
		if ( self::ACT_ALLOW_24H === $action || self::ACT_ACCESS_APPROVE === $action ) {
			$detail = __( 'Allow this plugin for 24 hours', 'handl-ai-connector-access-control' );
		} elseif ( self::ACT_ACCESS_DENY === $action ) {
			$detail = __( 'Deny this access request', 'handl-ai-connector-access-control' );
		} else {
			$detail = __( 'Snooze alerts for this plugin for 7 days', 'handl-ai-connector-access-control' );
		}

		$form_action = admin_url( 'admin-post.php' );
		$nonce       = function_exists( 'wp_create_nonce' ) ? wp_create_nonce( self::NONCE_KEY ) : '';

		echo '<div class="wrap">';
		echo '<h1>' . esc_html( $heading ) . '</h1>';
		echo '<p>' . esc_html( $detail ) . '</p>';
		echo '<p><code>' . esc_html( $plugin ) . '</code></p>';
		echo '<p>' . esc_html__( 'This does not change anything until you confirm.', 'handl-ai-connector-access-control' ) . '</p>';
		echo '<form method="post" action="' . esc_url( $form_action ) . '">';
		echo '<input type="hidden" name="action" value="' . esc_attr( self::APPLY_HOOK ) . '" />';
		echo '<input type="hidden" name="t" value="' . esc_attr( $id ) . '" />';
		echo '<input type="hidden" name="s" value="' . esc_attr( $sig ) . '" />';
		echo '<input type="hidden" name="_wpnonce" value="' . esc_attr( $nonce ) . '" />';
		echo '<p><button type="submit" class="button button-primary">' . esc_html__( 'Confirm', 'handl-ai-connector-access-control' ) . '</button></p>';
		echo '</form>';
		echo '</div>';
		exit;
	}

	private static function halt( string $message ): void {
		if ( function_exists( 'wp_die' ) ) {
			wp_die( esc_html( $message ) );
		}
		echo esc_html( $message );
		exit;
	}
}
