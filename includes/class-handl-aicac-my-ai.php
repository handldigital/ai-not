<?php
/**
 * AICAC-MYAI (#365): read-only "My AI access" self-view for logged-in users.
 *
 * Profile section + [handl_aicac_my_ai] shortcode. Own calls/denies from
 * Plugin::LOG_OPTION_KEY (read-only). Grants via Temp_Allow / Policy public
 * methods. Quota + pending requests behind class_exists guards for queued
 * User_Quota / Access_Request. Strictly self-scoped; no admin.php edits.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * End-user self-view of AI governance that applies to them.
 */
final class My_AI {

	public const SHORTCODE = 'handl_aicac_my_ai';

	public const RECENT_LIMIT = 20;

	/** @var bool */
	private static $registered = false;

	public static function init(): void {
		if ( self::$registered ) {
			return;
		}
		self::$registered = true;

		add_action( 'show_user_profile', array( self::class, 'render_profile' ) );
		add_shortcode( self::SHORTCODE, array( self::class, 'render_shortcode' ) );
	}

	public static function reset_for_tests(): void {
		self::$registered = false;
	}

	/**
	 * @param \WP_User|object $user Profile user.
	 */
	public static function render_profile( $user ): void {
		if ( ! is_object( $user ) || ! isset( $user->ID ) ) {
			return;
		}
		$user_id = (int) $user->ID;
		if ( $user_id <= 0 || $user_id !== (int) get_current_user_id() ) {
			return;
		}
		if ( ! current_user_can( 'read' ) ) {
			return;
		}

		// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- panel_html escapes.
		echo self::panel_html( $user_id );
	}

	/**
	 * @param array<string,mixed>|string $atts Shortcode attributes (unused).
	 */
	public static function render_shortcode( $atts = array() ): string {
		unset( $atts );
		$user_id = (int) get_current_user_id();
		if ( $user_id <= 0 || ! current_user_can( 'read' ) ) {
			return '';
		}

		return self::panel_html( $user_id );
	}

	/**
	 * Full panel markup (escaped).
	 */
	public static function panel_html( int $user_id ): string {
		if ( $user_id <= 0 ) {
			return '';
		}

		$calls    = self::own_calls( $user_id );
		$denies   = self::own_denies( $user_id );
		$grants   = self::grants_for_user( $user_id );
		$quota    = self::quota_for_user( $user_id );
		$pending  = self::pending_requests_for_user( $user_id );
		$is_admin = Caps::user_can_view();

		ob_start();
		echo '<div class="handl-aicac-my-ai">';
		echo '<h2>' . esc_html__( 'My AI access', 'handl-ai-connector-access-control' ) . '</h2>';
		echo '<p class="description">' . esc_html__( 'A read-only summary of your recent AI activity, grants, and limits on this site.', 'handl-ai-connector-access-control' ) . '</p>';

		if ( $is_admin ) {
			$url = class_exists( Admin::class, false ) ? Admin::screen_url( 'activity' ) : '';
			echo '<p class="description">';
			if ( '' !== $url ) {
				echo esc_html__( 'You can manage site-wide AI activity from the Activity screen.', 'handl-ai-connector-access-control' );
				echo ' <a href="' . esc_url( $url ) . '">' . esc_html__( 'Open Activity', 'handl-ai-connector-access-control' ) . '</a>';
			} else {
				echo esc_html__( 'Site admins can review full AI activity from the AI Not Activity screen.', 'handl-ai-connector-access-control' );
			}
			echo '</p>';
		}

		self::render_calls_section( $calls );
		self::render_denies_section( $denies );
		self::render_grants_section( $grants );
		self::render_quota_section( $quota );
		self::render_pending_section( $pending );

		echo '</div>';

		return (string) ob_get_clean();
	}

	/**
	 * Recent activity rows for this user (newest first).
	 *
	 * @return list<array<string,mixed>>
	 */
	public static function own_calls( int $user_id, int $limit = self::RECENT_LIMIT ): array {
		return self::filter_log_rows( $user_id, null, $limit );
	}

	/**
	 * Recent deny rows for this user (newest first).
	 *
	 * @return list<array<string,mixed>>
	 */
	public static function own_denies( int $user_id, int $limit = self::RECENT_LIMIT ): array {
		return self::filter_log_rows( $user_id, 'deny', $limit );
	}

	/**
	 * Plain-language reason for a deny/allow row.
	 *
	 * @param array<string,mixed> $row
	 */
	public static function reason_for_row( array $row ): string {
		if ( class_exists( Why::class, false ) && method_exists( Why::class, 'explain_line' ) ) {
			$line = Why::explain_line( $row );
			if ( is_string( $line ) && '' !== $line ) {
				return $line;
			}
		}
		$reason = isset( $row['denial_reason'] ) ? (string) $row['denial_reason'] : '';
		if ( '' !== $reason ) {
			return $reason;
		}
		$decision = isset( $row['decision'] ) ? (string) $row['decision'] : '';

		return '' !== $decision ? $decision : __( 'No reason recorded.', 'handl-ai-connector-access-control' );
	}

	/**
	 * Standing grants that currently apply to this user.
	 *
	 * @return list<array{type:string,label:string,expires_at:?int,expires_label:string}>
	 */
	public static function grants_for_user( int $user_id, $policy = null, ?int $now = null ): array {
		$policy = is_array( $policy ) ? $policy : Policy::get_policy();
		$now    = null !== $now ? (int) $now : Clock::now();
		$out    = array();

		$plugins = isset( $policy['plugins'] ) && is_array( $policy['plugins'] ) ? $policy['plugins'] : array();
		foreach ( $plugins as $plugin => $rule ) {
			$plugin = (string) $plugin;
			if ( 'allow' !== (string) $rule || '' === $plugin ) {
				continue;
			}
			if ( class_exists( Temp_Allow::class, false ) && method_exists( Temp_Allow::class, 'is_expired' ) && Temp_Allow::is_expired( $policy, $plugin, $now ) ) {
				continue;
			}
			$expires = null;
			$label   = '';
			if ( class_exists( Temp_Allow::class, false ) && method_exists( Temp_Allow::class, 'expires_at' ) ) {
				$expires = Temp_Allow::expires_at( $policy, $plugin );
			}
			if ( null !== $expires && class_exists( Temp_Allow::class, false ) && method_exists( Temp_Allow::class, 'remaining_label' ) ) {
				$label = Temp_Allow::remaining_label( $policy, $plugin, $now );
			}
			$out[] = array(
				'type'          => 'plugin_allow',
				'label'         => $plugin,
				'expires_at'    => $expires,
				'expires_label' => is_string( $label ) ? $label : '',
			);
		}

		// Role-gate membership is current-user scoped (self-view only).
		if (
			$user_id > 0
			&& $user_id === Policy::current_user_id_for_gate()
			&& ! empty( $policy['role_gate_enabled'] )
			&& method_exists( Policy::class, 'sanitize_allowed_roles' )
		) {
			$allowed = Policy::sanitize_allowed_roles( $policy['allowed_roles'] ?? array() );
			$roles   = Policy::current_user_roles();
			$labels  = method_exists( Policy::class, 'available_roles_for_gate' ) ? Policy::available_roles_for_gate() : array();
			foreach ( $roles as $role ) {
				$role = (string) $role;
				if ( '' === $role || ! in_array( $role, $allowed, true ) ) {
					continue;
				}
				$out[] = array(
					'type'          => 'role_gate',
					'label'         => isset( $labels[ $role ] ) ? (string) $labels[ $role ] : $role,
					'expires_at'    => null,
					'expires_label' => '',
				);
			}
		}

		return $out;
	}

	/**
	 * Quota usage when User_Quota is loaded; null when unavailable.
	 *
	 * @return array{limit:?int,count:int,source:string,prevent:bool}|null
	 */
	public static function quota_for_user( int $user_id, $policy = null ): ?array {
		if ( $user_id <= 0 ) {
			return null;
		}
		$quota_class = __NAMESPACE__ . '\\User_Quota';
		if ( ! class_exists( $quota_class, false ) || ! method_exists( $quota_class, 'evaluate' ) ) {
			return null;
		}
		$policy = is_array( $policy ) ? $policy : Policy::get_policy();
		$eval   = $quota_class::evaluate( $policy, $user_id );
		if ( ! is_array( $eval ) ) {
			return null;
		}

		return array(
			'limit'   => array_key_exists( 'limit', $eval ) ? $eval['limit'] : null,
			'count'   => isset( $eval['count'] ) ? (int) $eval['count'] : 0,
			'source'  => isset( $eval['source'] ) ? (string) $eval['source'] : '',
			'prevent' => ! empty( $eval['prevent'] ),
		);
	}

	/**
	 * Pending access requests filed by this user.
	 *
	 * @return list<array<string,mixed>>
	 */
	public static function pending_requests_for_user( int $user_id ): array {
		if ( $user_id <= 0 ) {
			return array();
		}
		if ( ! class_exists( Access_Request::class, false ) || ! method_exists( Access_Request::class, 'pending_rows' ) ) {
			return array();
		}
		$out = array();
		foreach ( Access_Request::pending_rows() as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			if ( (int) ( $row['user_id'] ?? 0 ) !== $user_id ) {
				continue;
			}
			$out[] = $row;
		}

		return $out;
	}

	/**
	 * @param list<array<string,mixed>> $calls
	 */
	private static function render_calls_section( array $calls ): void {
		echo '<h3>' . esc_html__( 'Recent AI calls', 'handl-ai-connector-access-control' ) . '</h3>';
		if ( array() === $calls ) {
			echo '<p>' . esc_html__( 'No recent AI calls on record for your account.', 'handl-ai-connector-access-control' ) . '</p>';
			return;
		}
		echo '<ul class="handl-aicac-my-ai-calls">';
		foreach ( $calls as $row ) {
			$plugin   = isset( $row['plugin'] ) ? (string) $row['plugin'] : '';
			$decision = isset( $row['decision'] ) ? (string) $row['decision'] : '';
			$ts       = isset( $row['ts'] ) ? (int) $row['ts'] : 0;
			$when     = $ts > 0 ? self::format_ts( $ts ) : '—';
			echo '<li>';
			echo esc_html( $when );
			echo ' — ';
			echo esc_html( '' !== $plugin ? $plugin : __( '(unknown plugin)', 'handl-ai-connector-access-control' ) );
			echo ' — ';
			echo esc_html( '' !== $decision ? $decision : '—' );
			echo '</li>';
		}
		echo '</ul>';
	}

	/**
	 * @param list<array<string,mixed>> $denies
	 */
	private static function render_denies_section( array $denies ): void {
		echo '<h3>' . esc_html__( 'Recent denies', 'handl-ai-connector-access-control' ) . '</h3>';
		if ( array() === $denies ) {
			echo '<p>' . esc_html__( 'No recent denies on record for your account.', 'handl-ai-connector-access-control' ) . '</p>';
			return;
		}
		echo '<ul class="handl-aicac-my-ai-denies">';
		foreach ( $denies as $row ) {
			$plugin = isset( $row['plugin'] ) ? (string) $row['plugin'] : '';
			$ts     = isset( $row['ts'] ) ? (int) $row['ts'] : 0;
			$when   = $ts > 0 ? self::format_ts( $ts ) : '—';
			$reason = self::reason_for_row( $row );
			echo '<li>';
			echo esc_html( $when );
			echo ' — ';
			echo esc_html( '' !== $plugin ? $plugin : __( '(unknown plugin)', 'handl-ai-connector-access-control' ) );
			echo ' — ';
			echo esc_html( $reason );
			echo '</li>';
		}
		echo '</ul>';
	}

	/**
	 * @param list<array{type:string,label:string,expires_at:?int,expires_label:string}> $grants
	 */
	private static function render_grants_section( array $grants ): void {
		echo '<h3>' . esc_html__( 'Standing grants', 'handl-ai-connector-access-control' ) . '</h3>';
		if ( array() === $grants ) {
			echo '<p>' . esc_html__( 'No standing Allow grants currently apply to you.', 'handl-ai-connector-access-control' ) . '</p>';
			return;
		}
		echo '<ul class="handl-aicac-my-ai-grants">';
		foreach ( $grants as $grant ) {
			$type  = (string) ( $grant['type'] ?? '' );
			$label = (string) ( $grant['label'] ?? '' );
			$exp   = (string) ( $grant['expires_label'] ?? '' );
			$prefix = 'role_gate' === $type
				? __( 'Role', 'handl-ai-connector-access-control' )
				: __( 'Plugin', 'handl-ai-connector-access-control' );
			echo '<li>';
			echo esc_html( $prefix . ': ' . $label );
			if ( '' !== $exp ) {
				echo ' — ';
				echo esc_html( $exp );
			} elseif ( null !== ( $grant['expires_at'] ?? null ) ) {
				echo ' — ';
				echo esc_html(
					sprintf(
						/* translators: %s: localized datetime */
						__( 'Expires %s', 'handl-ai-connector-access-control' ),
						self::format_ts( (int) $grant['expires_at'] )
					)
				);
			}
			echo '</li>';
		}
		echo '</ul>';
	}

	/**
	 * @param array{limit:?int,count:int,source:string,prevent:bool}|null $quota
	 */
	private static function render_quota_section( ?array $quota ): void {
		echo '<h3>' . esc_html__( 'Quota', 'handl-ai-connector-access-control' ) . '</h3>';
		if ( null === $quota ) {
			echo '<p>' . esc_html__( 'Per-user quota is not available on this site yet.', 'handl-ai-connector-access-control' ) . '</p>';
			return;
		}
		if ( null === $quota['limit'] ) {
			echo '<p>' . esc_html__( 'No rolling call quota applies to your account.', 'handl-ai-connector-access-control' ) . '</p>';
			return;
		}
		echo '<p>';
		echo esc_html(
			sprintf(
				/* translators: 1: usage count, 2: limit */
				__( 'Usage (rolling 24h): %1$s / %2$s', 'handl-ai-connector-access-control' ),
				(string) (int) $quota['count'],
				(string) (int) $quota['limit']
			)
		);
		if ( ! empty( $quota['prevent'] ) ) {
			echo ' — ';
			echo esc_html__( 'Limit reached.', 'handl-ai-connector-access-control' );
		}
		echo '</p>';
	}

	/**
	 * @param list<array<string,mixed>> $pending
	 */
	private static function render_pending_section( array $pending ): void {
		echo '<h3>' . esc_html__( 'Pending access requests', 'handl-ai-connector-access-control' ) . '</h3>';
		if ( array() === $pending ) {
			echo '<p>' . esc_html__( 'You have no pending AI access requests.', 'handl-ai-connector-access-control' ) . '</p>';
			return;
		}
		echo '<ul class="handl-aicac-my-ai-pending">';
		foreach ( $pending as $row ) {
			$plugin = isset( $row['plugin'] ) ? (string) $row['plugin'] : '';
			$ts     = isset( $row['ts'] ) ? (int) $row['ts'] : 0;
			$when   = $ts > 0 ? self::format_ts( $ts ) : '—';
			$reason = isset( $row['reason'] ) ? (string) $row['reason'] : '';
			echo '<li>';
			echo esc_html( $when );
			echo ' — ';
			echo esc_html( '' !== $plugin ? $plugin : __( '(unknown plugin)', 'handl-ai-connector-access-control' ) );
			if ( '' !== $reason ) {
				echo ' — ';
				echo esc_html( $reason );
			}
			echo '</li>';
		}
		echo '</ul>';
	}

	/**
	 * @return list<array<string,mixed>>
	 */
	private static function filter_log_rows( int $user_id, ?string $decision, int $limit ): array {
		if ( $user_id <= 0 ) {
			return array();
		}
		$limit = max( 1, min( 100, (int) $limit ) );
		$log   = get_option( Plugin::LOG_OPTION_KEY, array() );
		if ( ! is_array( $log ) ) {
			return array();
		}

		$matched = array();
		foreach ( $log as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			if ( (int) ( $row['user_id'] ?? 0 ) !== $user_id ) {
				continue;
			}
			if ( null !== $decision && (string) ( $row['decision'] ?? '' ) !== $decision ) {
				continue;
			}
			$matched[] = $row;
		}

		usort(
			$matched,
			static function ( array $a, array $b ): int {
				return (int) ( $b['ts'] ?? 0 ) <=> (int) ( $a['ts'] ?? 0 );
			}
		);

		return array_slice( $matched, 0, $limit );
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
}
