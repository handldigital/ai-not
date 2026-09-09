<?php
/**
 * AICAC-REQUEST: blocked-plugin users request AI access; owners approve by email (#232).
 *
 * Deny-path notice (admin, edit-level users) → pending request → owner email with
 * signed Inbox_Actions approve/deny links. Duplicate plugin requests within 24h
 * collapse (no mailbox flood). Protections screen shows a pending inbox.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Access-request lifecycle + blocked-UX notice + Protections inbox.
 */
final class Access_Request {

	public const OPTION_KEY = 'handl_aicac_access_requests';

	public const NOTICE_META = 'handl_aicac_access_request_notice';

	public const SUBMIT_HOOK = 'handl_aicac_access_request_submit';

	public const DECIDE_HOOK = 'handl_aicac_access_request_decide';

	public const NONCE_SUBMIT = 'handl_aicac_access_request_submit';

	public const NONCE_DECIDE = 'handl_aicac_access_request_decide';

	/** Capability above subscriber — contributors and up. */
	public const REQUEST_CAP = 'edit_posts';

	public const STATUS_PENDING  = 'pending';
	public const STATUS_APPROVED = 'approved';
	public const STATUS_DENIED   = 'denied';

	private static ?Access_Request $instance = null;

	public static function instance(): Access_Request {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	public function init(): void {
		add_action( 'admin_post_' . self::SUBMIT_HOOK, array( $this, 'handle_submit' ) );
		add_action( 'admin_post_' . self::DECIDE_HOOK, array( $this, 'handle_decide' ) );
		if ( is_admin() ) {
			add_action( 'admin_notices', array( $this, 'maybe_render_blocked_notice' ) );
		}
	}

	/**
	 * After a real deny: stash a per-user notice when the caller may request access.
	 *
	 * Anonymous / frontend / cron / REST denials never get a notice.
	 *
	 * @param array<string,mixed> $event
	 */
	public static function note_deny( array $event ): void {
		if ( ! empty( $event['selftest'] ) ) {
			return;
		}
		if ( ! function_exists( 'is_user_logged_in' ) || ! is_user_logged_in() ) {
			return;
		}
		if ( ! current_user_can( self::REQUEST_CAP ) ) {
			return;
		}

		$ctx = isset( $event['request_context'] )
			? Policy::normalize_request_context( $event['request_context'] )
			: Policy::detect_request_context();
		if ( 'admin' !== $ctx ) {
			return;
		}

		$plugin = Plugin_Profile::sanitize_plugin( (string) ( $event['plugin'] ?? '' ) );
		if ( '' === $plugin ) {
			return;
		}

		$user_id = (int) get_current_user_id();
		if ( $user_id <= 0 ) {
			return;
		}

		update_user_meta(
			$user_id,
			self::NOTICE_META,
			array(
				'plugin' => $plugin,
				'ts'     => isset( $event['ts'] ) ? (int) $event['ts'] : time(),
			)
		);
	}

	/**
	 * Blocked-UX admin notice with "Request AI access" for edit-level users.
	 */
	public function maybe_render_blocked_notice(): void {
		if ( ! current_user_can( self::REQUEST_CAP ) ) {
			return;
		}

		$user_id = (int) get_current_user_id();
		$notice  = self::get_notice( $user_id );
		if ( null === $notice ) {
			return;
		}

		$plugin  = $notice['plugin'];
		$plugins = function_exists( 'get_plugins' ) ? get_plugins() : array();
		$label   = isset( $plugins[ $plugin ]['Name'] ) ? (string) $plugins[ $plugin ]['Name'] : $plugin;
		$action  = admin_url( 'admin-post.php' );
		$nonce   = function_exists( 'wp_create_nonce' ) ? wp_create_nonce( self::NONCE_SUBMIT ) : '';

		echo '<div class="notice notice-warning"><p>';
		echo esc_html(
			sprintf(
				/* translators: %s: plugin name */
				__( 'HandL blocked an AI Client call from %s.', 'handl-ai-connector-access-control' ),
				$label
			)
		);
		echo '</p>';
		echo '<form method="post" action="' . esc_url( $action ) . '" style="margin:0.5em 0 0.75em;">';
		echo '<input type="hidden" name="action" value="' . esc_attr( self::SUBMIT_HOOK ) . '" />';
		echo '<input type="hidden" name="handl_aicac_plugin" value="' . esc_attr( $plugin ) . '" />';
		echo '<input type="hidden" name="_wpnonce" value="' . esc_attr( $nonce ) . '" />';
		echo '<p><label for="handl-aicac-access-reason">' . esc_html__( 'Why do you need access? (optional)', 'handl-ai-connector-access-control' ) . '</label><br />';
		echo '<input type="text" class="regular-text" id="handl-aicac-access-reason" name="handl_aicac_reason" maxlength="200" value="" /></p>';
		echo '<p><button type="submit" class="button button-primary">' . esc_html__( 'Request AI access', 'handl-ai-connector-access-control' ) . '</button></p>';
		echo '</form>';
		echo '</div>';
	}

	/**
	 * Pending requests section for the Protections screen.
	 *
	 * @param array<string,array<string,mixed>> $plugins
	 */
	public static function render_inbox_section( array $plugins ): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		$pending = self::pending_rows();
		echo '<div class="handl-aicac-access-request-inbox" style="margin:1.5em 0;">';
		echo '<h2>' . esc_html__( 'AI access requests', 'handl-ai-connector-access-control' ) . '</h2>';
		echo '<p class="description">' . esc_html__( 'When an editor’s AI request is blocked, they can ask for temporary access. Approving allows the plugin for 24 hours. Denying closes the request.', 'handl-ai-connector-access-control' ) . '</p>';

		if ( empty( $pending ) ) {
			echo '<p>' . esc_html__( 'No pending requests.', 'handl-ai-connector-access-control' ) . '</p>';
			echo '</div>';
			return;
		}

		$action = admin_url( 'admin-post.php' );
		$nonce  = function_exists( 'wp_create_nonce' ) ? wp_create_nonce( self::NONCE_DECIDE ) : '';

		echo '<table class="widefat striped" style="max-width:52em;"><thead><tr>';
		echo '<th>' . esc_html__( 'Plugin', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Requested by', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Reason', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'When', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Actions', 'handl-ai-connector-access-control' ) . '</th>';
		echo '</tr></thead><tbody>';

		foreach ( $pending as $row ) {
			$plugin = (string) $row['plugin'];
			$label  = isset( $plugins[ $plugin ]['Name'] ) ? (string) $plugins[ $plugin ]['Name'] : $plugin;
			$who    = '' !== (string) $row['user_login']
				? (string) $row['user_login']
				: ( 'user#' . (string) (int) $row['user_id'] );
			$when   = function_exists( 'wp_date' )
				? (string) wp_date( 'Y-m-d H:i', (int) $row['ts'] )
				: gmdate( 'Y-m-d H:i', (int) $row['ts'] );
			$reason = (string) ( $row['reason'] ?? '' );

			echo '<tr>';
			echo '<td>' . esc_html( $label ) . '<br /><code>' . esc_html( $plugin ) . '</code></td>';
			echo '<td>' . esc_html( $who ) . '</td>';
			echo '<td>' . ( '' !== $reason ? esc_html( $reason ) : '&mdash;' ) . '</td>';
			echo '<td>' . esc_html( $when ) . '</td>';
			echo '<td>';
			echo '<form method="post" action="' . esc_url( $action ) . '" style="display:inline-block;margin:0 0.35em 0.35em 0;">';
			echo '<input type="hidden" name="action" value="' . esc_attr( self::DECIDE_HOOK ) . '" />';
			echo '<input type="hidden" name="handl_aicac_request_id" value="' . esc_attr( (string) $row['id'] ) . '" />';
			echo '<input type="hidden" name="handl_aicac_decision" value="approve" />';
			echo '<input type="hidden" name="_wpnonce" value="' . esc_attr( $nonce ) . '" />';
			echo '<button type="submit" class="button button-primary">' . esc_html__( 'Approve for 24 hours', 'handl-ai-connector-access-control' ) . '</button>';
			echo '</form>';
			echo '<form method="post" action="' . esc_url( $action ) . '" style="display:inline-block;margin:0 0.35em 0.35em 0;">';
			echo '<input type="hidden" name="action" value="' . esc_attr( self::DECIDE_HOOK ) . '" />';
			echo '<input type="hidden" name="handl_aicac_request_id" value="' . esc_attr( (string) $row['id'] ) . '" />';
			echo '<input type="hidden" name="handl_aicac_decision" value="deny" />';
			echo '<input type="hidden" name="_wpnonce" value="' . esc_attr( $nonce ) . '" />';
			echo '<button type="submit" class="button">' . esc_html__( 'Deny', 'handl-ai-connector-access-control' ) . '</button>';
			echo '</form>';
			echo '</td>';
			echo '</tr>';
		}

		echo '</tbody></table>';
		echo '</div>';
	}

	public function handle_submit(): void {
		if ( function_exists( 'nocache_headers' ) ) {
			nocache_headers();
		}

		if ( ! is_user_logged_in() || ! current_user_can( self::REQUEST_CAP ) ) {
			self::halt( __( 'You do not have permission to request AI access.', 'handl-ai-connector-access-control' ) );
			return;
		}

		check_admin_referer( self::NONCE_SUBMIT );

		$plugin = Plugin_Profile::sanitize_plugin(
			isset( $_POST['handl_aicac_plugin'] ) ? wp_unslash( (string) $_POST['handl_aicac_plugin'] ) : ''
		);
		$reason = isset( $_POST['handl_aicac_reason'] )
			? sanitize_text_field( wp_unslash( (string) $_POST['handl_aicac_reason'] ) )
			: '';
		if ( strlen( $reason ) > 200 ) {
			$reason = substr( $reason, 0, 200 );
		}

		if ( '' === $plugin ) {
			self::halt( __( 'That request is not valid.', 'handl-ai-connector-access-control' ) );
			return;
		}

		$result = self::submit_request( $plugin, (int) get_current_user_id(), $reason, time() );
		delete_user_meta( (int) get_current_user_id(), self::NOTICE_META );

		$message = ! empty( $result['emailed'] )
			? __( 'Your request was sent to the site owner.', 'handl-ai-connector-access-control' )
			: __( 'Your request was recorded, but no new email was sent to the site owner.', 'handl-ai-connector-access-control' );

		if ( function_exists( 'wp_safe_redirect' ) ) {
			wp_safe_redirect(
				add_query_arg(
					array(
						'handl_aicac_access_request' => ! empty( $result['emailed'] ) ? 'sent' : 'recorded',
					),
					admin_url()
				)
			);
			exit;
		}

		self::halt( $message );
	}

	public function handle_decide(): void {
		if ( function_exists( 'nocache_headers' ) ) {
			nocache_headers();
		}

		if ( ! is_user_logged_in() || ! current_user_can( 'manage_options' ) ) {
			self::halt( __( 'You need permission to manage these settings.', 'handl-ai-connector-access-control' ) );
			return;
		}

		check_admin_referer( self::NONCE_DECIDE );

		$id       = isset( $_POST['handl_aicac_request_id'] ) ? self::sanitize_id( wp_unslash( (string) $_POST['handl_aicac_request_id'] ) ) : '';
		$decision = isset( $_POST['handl_aicac_decision'] ) ? sanitize_key( wp_unslash( (string) $_POST['handl_aicac_decision'] ) ) : '';
		if ( '' === $id || ! in_array( $decision, array( 'approve', 'deny' ), true ) ) {
			self::halt( __( 'That request is not valid.', 'handl-ai-connector-access-control' ) );
			return;
		}

		$now = time();
		if ( 'approve' === $decision ) {
			$result = self::approve( $id, (int) get_current_user_id(), $now );
			$message = $result['ok']
				? __( 'This plugin is allowed for 24 hours.', 'handl-ai-connector-access-control' )
				: __( 'That request could not be approved.', 'handl-ai-connector-access-control' );
		} else {
			$result = self::deny( $id, (int) get_current_user_id(), $now );
			$message = $result['ok']
				? __( 'The access request was denied.', 'handl-ai-connector-access-control' )
				: __( 'That request could not be denied.', 'handl-ai-connector-access-control' );
		}

		if ( function_exists( 'wp_safe_redirect' ) ) {
			wp_safe_redirect( Admin::screen_url( 'protections' ) );
			exit;
		}

		self::halt( $message );
	}

	/**
	 * Create or collapse a pending request; email the owner at most once per plugin per 24h.
	 *
	 * @return array{ok:bool,emailed:bool,id:string}
	 */
	public static function submit_request( string $plugin, int $user_id, string $reason = '', ?int $now = null ): array {
		$plugin = Plugin_Profile::sanitize_plugin( $plugin );
		$now    = null !== $now ? (int) $now : time();
		$user_id = (int) $user_id;
		$reason  = sanitize_text_field( $reason );
		if ( strlen( $reason ) > 200 ) {
			$reason = substr( $reason, 0, 200 );
		}

		if ( '' === $plugin || $user_id <= 0 ) {
			return array(
				'ok'      => false,
				'emailed' => false,
				'id'      => '',
			);
		}

		$map     = self::get_map();
		$pending = self::find_collapsible_pending( $map, $plugin, $now );
		$emailed = false;

		if ( null !== $pending ) {
			$id                      = (string) $pending['id'];
			$map[ $id ]['user_id']   = $user_id;
			$map[ $id ]['user_login'] = self::user_login_for( $user_id );
			$map[ $id ]['reason']    = $reason;
			$map[ $id ]['ts']        = $now;
			// Keep emailed_ts — collapse window is based on first owner email.
		} else {
			$id         = self::new_id();
			$map[ $id ] = array(
				'id'         => $id,
				'plugin'     => $plugin,
				'user_id'    => $user_id,
				'user_login' => self::user_login_for( $user_id ),
				'reason'     => $reason,
				'status'     => self::STATUS_PENDING,
				'ts'         => $now,
				'emailed_ts' => 0,
			);
			$emailed = self::email_owner( $map[ $id ], $now );
			if ( $emailed ) {
				$map[ $id ]['emailed_ts'] = $now;
			}
		}

		self::save_map( $map );

		Policy::append_log_event(
			array(
				'ts'       => $now,
				'plugin'   => $plugin,
				'decision' => 'access_request',
				'channel'  => 'access_request',
				'source'   => 'user',
				'actor_id' => $user_id,
				'reason'   => $reason,
				'operation'=> '',
				'provider' => '',
			)
		);

		return array(
			'ok'      => true,
			'emailed' => $emailed,
			'id'      => $id,
		);
	}

	/**
	 * @return array{ok:bool,error:string}
	 */
	public static function approve( string $id, int $actor_id, ?int $now = null ): array {
		$now = null !== $now ? (int) $now : time();
		$id  = self::sanitize_id( $id );
		$map = self::get_map();
		if ( '' === $id || ! isset( $map[ $id ] ) || self::STATUS_PENDING !== (string) ( $map[ $id ]['status'] ?? '' ) ) {
			return array(
				'ok'    => false,
				'error' => 'invalid',
			);
		}

		$plugin = Plugin_Profile::sanitize_plugin( (string) $map[ $id ]['plugin'] );
		if ( '' === $plugin || ! Inbox_Actions::apply_temp_allow_24h( $plugin, $now ) ) {
			return array(
				'ok'    => false,
				'error' => 'invalid',
			);
		}

		$map[ $id ]['status']      = self::STATUS_APPROVED;
		$map[ $id ]['resolved_ts'] = $now;
		$map[ $id ]['resolved_by'] = (int) $actor_id;
		self::save_map( $map );

		Policy::append_log_event(
			array(
				'ts'       => $now,
				'plugin'   => $plugin,
				'decision' => 'access_approved',
				'channel'  => 'access_request',
				'source'   => 'admin',
				'actor_id' => (int) $actor_id,
				'operation'=> '',
				'provider' => '',
			)
		);

		return array(
			'ok'    => true,
			'error' => '',
		);
	}

	/**
	 * Approve the newest pending request for a plugin (email-token path).
	 *
	 * @return array{ok:bool,error:string}
	 */
	public static function approve_plugin( string $plugin, int $actor_id, ?int $now = null ): array {
		$plugin  = Plugin_Profile::sanitize_plugin( $plugin );
		$now     = null !== $now ? (int) $now : time();
		$row     = self::newest_pending_for_plugin( $plugin );
		if ( null === $row ) {
			// Still apply the temp-allow when the token is valid but the row was already resolved.
			Inbox_Actions::apply_temp_allow_24h( $plugin, $now );
			return array(
				'ok'    => true,
				'error' => '',
			);
		}

		return self::approve( (string) $row['id'], $actor_id, $now );
	}

	/**
	 * @return array{ok:bool,error:string}
	 */
	public static function deny( string $id, int $actor_id, ?int $now = null ): array {
		$now = null !== $now ? (int) $now : time();
		$id  = self::sanitize_id( $id );
		$map = self::get_map();
		if ( '' === $id || ! isset( $map[ $id ] ) || self::STATUS_PENDING !== (string) ( $map[ $id ]['status'] ?? '' ) ) {
			return array(
				'ok'    => false,
				'error' => 'invalid',
			);
		}

		$plugin                    = Plugin_Profile::sanitize_plugin( (string) $map[ $id ]['plugin'] );
		$map[ $id ]['status']      = self::STATUS_DENIED;
		$map[ $id ]['resolved_ts'] = $now;
		$map[ $id ]['resolved_by'] = (int) $actor_id;
		self::save_map( $map );

		Policy::append_log_event(
			array(
				'ts'       => $now,
				'plugin'   => $plugin,
				'decision' => 'access_denied',
				'channel'  => 'access_request',
				'source'   => 'admin',
				'actor_id' => (int) $actor_id,
				'operation'=> '',
				'provider' => '',
			)
		);

		return array(
			'ok'    => true,
			'error' => '',
		);
	}

	/**
	 * Deny the newest pending request for a plugin (email-token path).
	 *
	 * @return array{ok:bool,error:string}
	 */
	public static function deny_plugin( string $plugin, int $actor_id, ?int $now = null ): array {
		$row = self::newest_pending_for_plugin( $plugin );
		if ( null === $row ) {
			return array(
				'ok'    => true,
				'error' => '',
			);
		}

		return self::deny( (string) $row['id'], $actor_id, $now );
	}

	/**
	 * @return list<array<string,mixed>>
	 */
	public static function pending_rows(): array {
		$out = array();
		foreach ( self::get_map() as $row ) {
			if ( self::STATUS_PENDING === (string) ( $row['status'] ?? '' ) ) {
				$out[] = $row;
			}
		}
		usort(
			$out,
			static function ( array $a, array $b ): int {
				return (int) ( $b['ts'] ?? 0 ) <=> (int) ( $a['ts'] ?? 0 );
			}
		);

		return $out;
	}

	/**
	 * @param array<string,mixed> $row
	 */
	private static function email_owner( array $row, int $now ): bool {
		$policy = Policy::get_policy();
		$to     = Alerts::resolve_email( $policy );
		if ( '' === $to ) {
			return false;
		}

		$plugin  = (string) ( $row['plugin'] ?? '' );
		$who     = '' !== (string) ( $row['user_login'] ?? '' )
			? (string) $row['user_login']
			: ( 'user#' . (string) (int) ( $row['user_id'] ?? 0 ) );
		$reason  = (string) ( $row['reason'] ?? '' );
		$plugins = function_exists( 'get_plugins' ) ? get_plugins() : array();
		$label   = isset( $plugins[ $plugin ]['Name'] ) ? (string) $plugins[ $plugin ]['Name'] : $plugin;

		$subject = sprintf(
			/* translators: %s: site name */
			__( '[%s] AI access request', 'handl-ai-connector-access-control' ),
			wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES )
		);

		$body  = __( 'Someone requested temporary AI access for a blocked plugin.', 'handl-ai-connector-access-control' ) . "\n\n";
		$body .= __( 'Plugin:', 'handl-ai-connector-access-control' ) . ' ' . $label . ' (' . $plugin . ")\n";
		$body .= __( 'Requested by:', 'handl-ai-connector-access-control' ) . ' ' . $who . "\n";
		if ( '' !== $reason ) {
			$body .= __( 'Reason:', 'handl-ai-connector-access-control' ) . ' ' . $reason . "\n";
		}
		$body .= "\n" . __( 'Approving allows this plugin for 24 hours. Denying closes the request. You must log in and confirm before anything changes.', 'handl-ai-connector-access-control' ) . "\n";
		$body .= Admin::screen_url( 'protections' ) . "\n";

		return (bool) Inbox_Actions::with_mail(
			array(
				'plugin'    => $plugin,
				'kind'      => 'access_request',
				'recipient' => $to,
				'now'       => $now,
			),
			static function () use ( $to, $subject, $body ) {
				return Alerts::safe_wp_mail( $to, $subject, $body );
			}
		);
	}

	/**
	 * @return array{plugin:string,ts:int}|null
	 */
	private static function get_notice( int $user_id ): ?array {
		$raw = get_user_meta( $user_id, self::NOTICE_META, true );
		if ( ! is_array( $raw ) ) {
			return null;
		}
		$plugin = Plugin_Profile::sanitize_plugin( (string) ( $raw['plugin'] ?? '' ) );
		if ( '' === $plugin ) {
			return null;
		}

		return array(
			'plugin' => $plugin,
			'ts'     => isset( $raw['ts'] ) ? (int) $raw['ts'] : 0,
		);
	}

	/**
	 * @param array<string,array<string,mixed>> $map
	 * @return array<string,mixed>|null
	 */
	private static function find_collapsible_pending( array $map, string $plugin, int $now ): ?array {
		$best = null;
		foreach ( $map as $row ) {
			if ( self::STATUS_PENDING !== (string) ( $row['status'] ?? '' ) ) {
				continue;
			}
			if ( $plugin !== Plugin_Profile::sanitize_plugin( (string) ( $row['plugin'] ?? '' ) ) ) {
				continue;
			}
			$emailed = isset( $row['emailed_ts'] ) ? (int) $row['emailed_ts'] : 0;
			// Collapse while a pending row exists and its owner email is still inside 24h
			// (or was never emailed — keep one pending row).
			if ( $emailed > 0 && ( $emailed + DAY_IN_SECONDS ) <= $now ) {
				continue;
			}
			if ( null === $best || (int) ( $row['ts'] ?? 0 ) > (int) ( $best['ts'] ?? 0 ) ) {
				$best = $row;
			}
		}

		return $best;
	}

	/**
	 * @return array<string,mixed>|null
	 */
	private static function newest_pending_for_plugin( string $plugin ): ?array {
		$plugin = Plugin_Profile::sanitize_plugin( $plugin );
		$best   = null;
		foreach ( self::get_map() as $row ) {
			if ( self::STATUS_PENDING !== (string) ( $row['status'] ?? '' ) ) {
				continue;
			}
			if ( $plugin !== Plugin_Profile::sanitize_plugin( (string) ( $row['plugin'] ?? '' ) ) ) {
				continue;
			}
			if ( null === $best || (int) ( $row['ts'] ?? 0 ) > (int) ( $best['ts'] ?? 0 ) ) {
				$best = $row;
			}
		}

		return $best;
	}

	private static function user_login_for( int $user_id ): string {
		if ( function_exists( 'get_userdata' ) ) {
			$user = get_userdata( $user_id );
			if ( $user && isset( $user->user_login ) ) {
				return sanitize_text_field( (string) $user->user_login );
			}
		}
		if ( ! empty( $GLOBALS['handl_aicac_test_user_login'] ) ) {
			return sanitize_text_field( (string) $GLOBALS['handl_aicac_test_user_login'] );
		}

		return '';
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
			$clean = self::sanitize_row( $row, $id );
			if ( null === $clean ) {
				continue;
			}
			$out[ $id ] = $clean;
		}

		return $out;
	}

	/**
	 * @param array<string,mixed> $row
	 * @return array<string,mixed>|null
	 */
	private static function sanitize_row( array $row, string $id ): ?array {
		$plugin = Plugin_Profile::sanitize_plugin( (string) ( $row['plugin'] ?? '' ) );
		$status = sanitize_key( (string) ( $row['status'] ?? '' ) );
		$ok     = array( self::STATUS_PENDING, self::STATUS_APPROVED, self::STATUS_DENIED );
		if ( '' === $plugin || ! in_array( $status, $ok, true ) ) {
			return null;
		}

		return array(
			'id'          => $id,
			'plugin'      => $plugin,
			'user_id'     => isset( $row['user_id'] ) ? (int) $row['user_id'] : 0,
			'user_login'  => sanitize_text_field( (string) ( $row['user_login'] ?? '' ) ),
			'reason'      => sanitize_text_field( (string) ( $row['reason'] ?? '' ) ),
			'status'      => $status,
			'ts'          => isset( $row['ts'] ) ? (int) $row['ts'] : 0,
			'emailed_ts'  => isset( $row['emailed_ts'] ) ? (int) $row['emailed_ts'] : 0,
			'resolved_ts' => isset( $row['resolved_ts'] ) ? (int) $row['resolved_ts'] : 0,
			'resolved_by' => isset( $row['resolved_by'] ) ? (int) $row['resolved_by'] : 0,
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

	private static function sanitize_id( string $id ): string {
		$id = strtolower( preg_replace( '/[^a-f0-9]/', '', $id ) ?? '' );
		return ( 32 === strlen( $id ) ) ? $id : '';
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
		if ( function_exists( 'wp_die' ) ) {
			wp_die( esc_html( $message ) );
		}
		echo esc_html( $message );
		exit;
	}
}
