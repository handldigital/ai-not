<?php
/**
 * AICAC-FIRST-DENY (#326): one-time first-block explainer.
 *
 * Listens on the deny log funnel (not policy evaluation). Fires once per site
 * on the first non-demo deny that is retained as its own Activity row.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Turn the first real deny into a plain-language trust moment.
 */
final class First_Deny {

	public const OPTION_KEY = 'handl_aicac_first_deny';

	public const ACTION_TEMP_ALLOW = 'handl_aicac_first_deny_temp_allow';

	public const ACTION_DISMISS = 'handl_aicac_first_deny_dismiss';

	private static ?First_Deny $instance = null;

	public static function instance(): First_Deny {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}

		return self::$instance;
	}

	public function init(): void {
		add_action( 'admin_post_' . self::ACTION_TEMP_ALLOW, array( $this, 'handle_temp_allow' ) );
		add_action( 'admin_post_' . self::ACTION_DISMISS, array( $this, 'handle_dismiss' ) );
		if ( is_admin() ) {
			add_action( 'admin_notices', array( $this, 'maybe_render_notice' ) );
		}
	}

	/**
	 * Called from the log funnel after a deny row is retained.
	 *
	 * @param array<string,mixed> $event
	 * @param array<string,mixed> $policy
	 * @return array{fired:bool,reason:string}
	 */
	public static function observe( array $event, array $policy ): array {
		$empty = array(
			'fired'  => false,
			'reason' => '',
		);

		$state = self::get_state();
		if ( ! empty( $state['fired'] ) ) {
			$empty['reason'] = 'already_fired';
			return $empty;
		}

		if ( 'deny' !== (string) ( $event['decision'] ?? '' ) ) {
			$empty['reason'] = 'not_deny';
			return $empty;
		}

		if ( class_exists( Selftest::class, false ) && Selftest::is_synthetic_row( $event ) ) {
			$empty['reason'] = 'selftest';
			return $empty;
		}

		if ( class_exists( Demo_Mode::class, false ) && Demo_Mode::is_demo_row( $event ) ) {
			$empty['reason'] = 'demo';
			return $empty;
		}

		// Storm / aggregate rows never trigger the one-time explainer.
		if ( ! empty( $event['retry_storm'] ) || ! empty( $event['retry_storm_collapsed'] ) ) {
			$empty['reason'] = 'storm';
			return $empty;
		}

		$channel = isset( $event['channel'] ) ? (string) $event['channel'] : '';
		if ( in_array( $channel, array( 'direct_http', 'anomaly', 'spend_threshold', 'drift', 'budget', 'selftest', 'pii', 'retry_storm', 'threat_feed', 'temp_allow', 'went_ai', 'email' ), true ) ) {
			$empty['reason'] = 'skip_channel';
			return $empty;
		}

		$plugin = Plugin_Profile::sanitize_plugin( (string) ( $event['plugin'] ?? '' ) );
		if ( '' === $plugin || ( class_exists( Analytics::class, false ) && Analytics::UNKNOWN_KEY === $plugin ) ) {
			$empty['reason'] = 'no_plugin';
			return $empty;
		}

		$ts = isset( $event['ts'] ) ? (int) $event['ts'] : Clock::now();
		if ( $ts <= 0 ) {
			$ts = Clock::now();
		}

		$source = '';
		if ( class_exists( Why::class, false ) ) {
			$source = Why::bucket_for_row( $event );
			if ( Why::FILTER_NONE === $source ) {
				$source = '';
			}
		}
		if ( '' === $source && isset( $event['source'] ) ) {
			$source = sanitize_key( (string) $event['source'] );
		}

		$state = array(
			'fired'     => true,
			'pending'   => true,
			'plugin'    => $plugin,
			'ts'        => $ts,
			'source'    => $source,
			'operation' => sanitize_key( (string) ( $event['operation'] ?? '' ) ),
			'provider'  => sanitize_text_field( (string) ( $event['provider'] ?? '' ) ),
			'caller'    => sanitize_text_field( (string) ( $event['caller'] ?? '' ) ),
			'fired_at'  => Clock::now(),
		);
		self::save_state( $state );

		return array(
			'fired'  => true,
			'reason' => 'ok',
		);
	}

	/**
	 * @return array{
	 *   fired:bool,
	 *   pending:bool,
	 *   plugin:string,
	 *   ts:int,
	 *   source:string,
	 *   operation:string,
	 *   provider:string,
	 *   caller:string,
	 *   fired_at:int
	 * }
	 */
	public static function get_state(): array {
		return self::sanitize_state( get_option( self::OPTION_KEY, array() ) );
	}

	/**
	 * @param mixed $raw
	 * @return array{
	 *   fired:bool,
	 *   pending:bool,
	 *   plugin:string,
	 *   ts:int,
	 *   source:string,
	 *   operation:string,
	 *   provider:string,
	 *   caller:string,
	 *   fired_at:int
	 * }
	 */
	public static function sanitize_state( $raw ): array {
		$row = is_array( $raw ) ? $raw : array();

		return array(
			'fired'     => ! empty( $row['fired'] ),
			'pending'   => ! empty( $row['pending'] ),
			'plugin'    => Plugin_Profile::sanitize_plugin( (string) ( $row['plugin'] ?? '' ) ),
			'ts'        => max( 0, (int) ( $row['ts'] ?? 0 ) ),
			'source'    => sanitize_key( (string) ( $row['source'] ?? '' ) ),
			'operation' => sanitize_key( (string) ( $row['operation'] ?? '' ) ),
			'provider'  => sanitize_text_field( (string) ( $row['provider'] ?? '' ) ),
			'caller'    => sanitize_text_field( (string) ( $row['caller'] ?? '' ) ),
			'fired_at'  => max( 0, (int) ( $row['fired_at'] ?? 0 ) ),
		);
	}

	/**
	 * @param array<string,mixed> $state
	 */
	public static function save_state( array $state ): void {
		update_option( self::OPTION_KEY, self::sanitize_state( $state ), false );
	}

	public static function dismiss(): void {
		$state            = self::get_state();
		$state['fired']   = true;
		$state['pending'] = false;
		self::save_state( $state );
	}

	public static function reset_for_tests(): void {
		delete_option( self::OPTION_KEY );
	}

	public static function user_can_manage(): bool {
		return class_exists( Caps::class, false )
			? Caps::user_can_manage()
			: current_user_can( 'manage_options' );
	}

	/**
	 * Activity deep-link for the first-deny row (plugin + deny + source when known).
	 *
	 * @param array<string,mixed> $state
	 */
	public static function activity_url( array $state ): string {
		$args = array(
			'handl_aicac_log_decision' => 'deny',
		);
		$plugin = (string) ( $state['plugin'] ?? '' );
		if ( '' !== $plugin ) {
			$args['handl_aicac_log_plugin'] = $plugin;
		}
		$source = (string) ( $state['source'] ?? '' );
		if ( '' !== $source && class_exists( Why::class, false ) && Why::FILTER_NONE !== $source ) {
			$args['handl_aicac_log_source'] = $source;
		}

		return Admin::screen_url( 'activity', $args ) . '#handl-aicac-log-wrap';
	}

	/**
	 * Plain-language label for the deciding rule / source.
	 *
	 * @param array<string,mixed> $state
	 */
	public static function reason_label( array $state ): string {
		$source = (string) ( $state['source'] ?? '' );
		if ( '' !== $source && class_exists( Why::class, false ) ) {
			$labels = Why::filter_choices();
			if ( isset( $labels[ $source ] ) ) {
				return (string) $labels[ $source ];
			}
		}

		return __( 'an access rule', 'handl-ai-connector-access-control' );
	}

	public function handle_dismiss(): void {
		if ( ! self::user_can_manage() ) {
			wp_die( esc_html__( 'Sorry, you are not allowed to do that.', 'handl-ai-connector-access-control' ) );
		}
		check_admin_referer( self::ACTION_DISMISS );
		self::dismiss();
		self::redirect_back();
	}

	public function handle_temp_allow(): void {
		if ( ! self::user_can_manage() ) {
			wp_die( esc_html__( 'Sorry, you are not allowed to do that.', 'handl-ai-connector-access-control' ) );
		}
		check_admin_referer( self::ACTION_TEMP_ALLOW );

		$state  = self::get_state();
		$plugin = (string) ( $state['plugin'] ?? '' );
		if ( '' !== $plugin && class_exists( Inbox_Actions::class, false ) ) {
			Inbox_Actions::apply_temp_allow_24h( $plugin );
		}
		self::dismiss();
		self::redirect_back();
	}

	private static function redirect_back(): void {
		$redirect = wp_get_referer();
		if ( ! is_string( $redirect ) || '' === $redirect ) {
			$redirect = Admin::screen_url( 'dashboard' );
		}
		wp_safe_redirect( $redirect );
		exit;
	}

	public function maybe_render_notice(): void {
		if ( ! self::user_can_manage() ) {
			return;
		}
		$state = self::get_state();
		if ( empty( $state['fired'] ) || empty( $state['pending'] ) ) {
			return;
		}
		$plugin = (string) $state['plugin'];
		if ( '' === $plugin ) {
			return;
		}

		$plugins = function_exists( 'get_plugins' ) ? get_plugins() : array();
		$label   = isset( $plugins[ $plugin ]['Name'] ) ? (string) $plugins[ $plugin ]['Name'] : $plugin;
		$reason  = self::reason_label( $state );
		$act_url = self::activity_url( $state );
		$caller  = (string) ( $state['caller'] ?? '' );

		$who = $label;
		if ( '' !== $caller ) {
			$who = sprintf(
				/* translators: 1: plugin name, 2: caller/method */
				__( '%1$s (%2$s)', 'handl-ai-connector-access-control' ),
				$label,
				$caller
			);
		}

		echo '<div class="notice notice-warning is-dismissible handl-aicac-first-deny-notice">';
		echo '<p><strong>' . esc_html__( 'HandL AI Access blocked a call for the first time', 'handl-ai-connector-access-control' ) . '</strong></p>';
		echo '<p>';
		echo esc_html(
			sprintf(
				/* translators: 1: plugin (and optional caller), 2: reason label */
				__( 'An AI call from %1$s was blocked by %2$s.', 'handl-ai-connector-access-control' ),
				$who,
				$reason
			)
		);
		echo '</p>';
		echo '<p><a href="' . esc_url( $act_url ) . '">' . esc_html__( 'View blocked calls in Activity', 'handl-ai-connector-access-control' ) . '</a></p>';
		echo '<p>';
		printf(
			'<a class="button button-primary" href="%s">%s</a> ',
			esc_url(
				add_query_arg(
					array(
						'action'   => self::ACTION_TEMP_ALLOW,
						'_wpnonce' => wp_create_nonce( self::ACTION_TEMP_ALLOW ),
					),
					admin_url( 'admin-post.php' )
				)
			),
			esc_html__( 'Allow plugin for 24 hours', 'handl-ai-connector-access-control' )
		);
		printf(
			'<a class="button" href="%s">%s</a>',
			esc_url(
				add_query_arg(
					array(
						'action'   => self::ACTION_DISMISS,
						'_wpnonce' => wp_create_nonce( self::ACTION_DISMISS ),
					),
					admin_url( 'admin-post.php' )
				)
			),
			esc_html__( 'Keep blocking', 'handl-ai-connector-access-control' )
		);
		echo '</p>';
		echo '</div>';
	}

}
