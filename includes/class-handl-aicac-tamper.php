<?php
/**
 * AICAC-TAMPER (#222): deactivation dead-man's switch.
 *
 * Logs + alerts when enforcement is switched off, stamps the gap, and surfaces
 * it again on reactivation (admin notice + Site Health).
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Deactivation / reactivation governance signals.
 */
final class Tamper {

	/** Option: unix timestamp when the plugin was last deactivated. */
	public const DEACTIVATED_AT_OPTION = 'handl_aicac_deactivated_at';

	/** Option: actor who deactivated (login or wp-cli); survives until reactivate. */
	public const DEACTIVATED_BY_OPTION = 'handl_aicac_deactivated_by';

	/**
	 * Option: pending reactivation notice payload.
	 *
	 * @var string
	 */
	public const NOTICE_OPTION = 'handl_aicac_tamper_gap_notice';

	/** User meta: last dismissed notice key (from-to). */
	public const NOTICE_DISMISS_META = 'handl_aicac_tamper_gap_dismissed';

	public const CHANNEL = 'tamper';

	public const DECISION_STOPPED = 'enforcement_stopped';
	public const DECISION_RESUMED = 'enforcement_resumed';

	private static ?Tamper $instance = null;

	public static function instance(): Tamper {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Load classes needed from activation/deactivation hooks (plugins_loaded may not have run).
	 */
	public static function ensure_deps(): void {
		static $loaded = false;
		if ( $loaded ) {
			return;
		}

		$dir = HANDL_AICAC_DIR . '/includes/';
		require_once $dir . 'class-handl-aicac-plugin.php';
		require_once $dir . 'class-handl-aicac-email-template.php';
		require_once $dir . 'class-handl-aicac-alert-health.php';
		require_once $dir . 'class-handl-aicac-webhook-delivery-log.php';
		require_once $dir . 'class-handl-aicac-alerts.php';
		require_once $dir . 'class-handl-aicac-alert-routing.php';
		require_once $dir . 'class-handl-aicac-policy.php';

		$loaded = true;
	}

	public function init(): void {
		if ( ! is_admin() ) {
			return;
		}

		add_action( 'admin_init', array( $this, 'maybe_handle_dismiss' ), 6 );
		add_action( 'admin_notices', array( $this, 'maybe_render_notice' ) );
		add_action( 'network_admin_notices', array( $this, 'maybe_render_notice' ) );
	}

	/**
	 * register_deactivation_hook callback.
	 *
	 * @param int|null $now Injectable clock for tests.
	 */
	public static function on_deactivate( ?int $now = null ): void {
		self::ensure_deps();

		$now = ( null !== $now && $now > 0 ) ? $now : time();
		$actor = self::resolve_actor();

		update_option( self::DEACTIVATED_AT_OPTION, $now, false );
		update_option( self::DEACTIVATED_BY_OPTION, $actor, false );

		self::append_governance_event(
			array(
				'ts'       => $now,
				'decision' => self::DECISION_STOPPED,
				'channel'  => self::CHANNEL,
				'actor'    => $actor,
			),
			$now
		);

		self::send_deactivation_alert( $actor, $now );
	}

	/**
	 * register_activation_hook callback (after onboarding seed).
	 *
	 * No-op on first install (no prior deactivation stamp).
	 *
	 * @param int|null $now Injectable clock for tests.
	 */
	public static function on_activate( ?int $now = null ): void {
		self::ensure_deps();

		$raw = get_option( self::DEACTIVATED_AT_OPTION, null );
		if ( null === $raw || false === $raw || '' === $raw ) {
			return;
		}

		$from = (int) $raw;
		if ( $from <= 0 ) {
			delete_option( self::DEACTIVATED_AT_OPTION );
			delete_option( self::DEACTIVATED_BY_OPTION );
			return;
		}

		$now = ( null !== $now && $now > 0 ) ? $now : time();
		if ( $now < $from ) {
			$now = $from;
		}

		// Who turned enforcement off (persisted at deactivate) — not who is reactivating.
		$stopped_by = sanitize_text_field( (string) get_option( self::DEACTIVATED_BY_OPTION, '' ) );
		$resumed_by = self::resolve_actor();

		self::append_governance_event(
			array(
				'ts'             => $now,
				'decision'       => self::DECISION_RESUMED,
				'channel'        => self::CHANNEL,
				'actor'          => $resumed_by,
				'stopped_by'     => $stopped_by,
				'deactivated_at' => $from,
			),
			$now
		);

		update_option(
			self::NOTICE_OPTION,
			array(
				'from'  => $from,
				'to'    => $now,
				'actor' => $stopped_by,
			),
			false
		);

		delete_option( self::DEACTIVATED_AT_OPTION );
		delete_option( self::DEACTIVATED_BY_OPTION );
	}

	/**
	 * Acting principal for the stop/resume event.
	 */
	public static function resolve_actor(): string {
		if ( isset( $GLOBALS['handl_aicac_test_actor'] ) && is_string( $GLOBALS['handl_aicac_test_actor'] ) ) {
			$test = sanitize_text_field( $GLOBALS['handl_aicac_test_actor'] );
			if ( '' !== $test ) {
				return $test;
			}
		}

		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			return 'wp-cli';
		}

		$user_id = function_exists( 'get_current_user_id' ) ? (int) get_current_user_id() : 0;
		if ( $user_id <= 0 ) {
			return '';
		}

		if ( function_exists( 'wp_get_current_user' ) ) {
			$user = wp_get_current_user();
			if ( is_object( $user ) && ! empty( $user->user_login ) ) {
				return sanitize_text_field( (string) $user->user_login );
			}
		}

		return 'user-' . $user_id;
	}

	/**
	 * Gap windows from the activity log (last 30 days by default).
	 *
	 * @param list<mixed> $log
	 * @return list<array{from:int,to:int,actor:string}>
	 */
	public static function recent_gap_windows( array $log, ?int $now = null, int $window_seconds = 0 ): array {
		$now = ( null !== $now && $now > 0 ) ? $now : time();
		if ( $window_seconds <= 0 ) {
			$window_seconds = defined( 'DAY_IN_SECONDS' ) ? ( 30 * DAY_IN_SECONDS ) : ( 30 * 86400 );
		}
		$cutoff = $now - $window_seconds;
		$out    = array();

		foreach ( $log as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			if ( self::CHANNEL !== (string) ( $row['channel'] ?? '' ) ) {
				continue;
			}

			$decision = (string) ( $row['decision'] ?? '' );
			$actor    = sanitize_text_field( (string) ( $row['actor'] ?? '' ) );

			if ( self::DECISION_RESUMED === $decision ) {
				$to   = (int) ( $row['ts'] ?? 0 );
				$from = (int) ( $row['deactivated_at'] ?? 0 );
				if ( $to >= $cutoff || $from >= $cutoff ) {
					$out[] = array(
						'from'  => max( 0, $from ),
						'to'    => max( 0, $to ),
						'actor' => $actor,
					);
				}
				continue;
			}

			if ( self::DECISION_STOPPED === $decision ) {
				$from = (int) ( $row['ts'] ?? 0 );
				if ( $from >= $cutoff ) {
					$out[] = array(
						'from'  => $from,
						'to'    => 0,
						'actor' => $actor,
					);
				}
			}
		}

		return $out;
	}

	/**
	 * Human-readable gap window for notices / Site Health.
	 */
	public static function format_gap_window( int $from, int $to ): string {
		$from_label = self::format_ts( $from );
		$to_label   = $to > 0 ? self::format_ts( $to ) : __( 'now', 'handl-ai-connector-access-control' );

		return sprintf(
			/* translators: 1: start datetime, 2: end datetime */
			__( 'Enforcement was off from %1$s to %2$s', 'handl-ai-connector-access-control' ),
			$from_label,
			$to_label
		);
	}

	/**
	 * Stable key for dismissible notice identity.
	 *
	 * @param array{from?:int,to?:int} $notice
	 */
	public static function notice_key( array $notice ): string {
		return (int) ( $notice['from'] ?? 0 ) . '-' . (int) ( $notice['to'] ?? 0 );
	}

	public function maybe_handle_dismiss(): void {
		if ( ! isset( $_POST['handl_aicac_action'] ) ) {
			return;
		}
		$action = sanitize_key( wp_unslash( (string) $_POST['handl_aicac_action'] ) );
		if ( 'tamper_gap_dismiss' !== $action ) {
			return;
		}
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		check_admin_referer( 'handl_aicac_tamper_gap_dismiss', 'handl_aicac_nonce' );

		$notice = get_option( self::NOTICE_OPTION, null );
		if ( is_array( $notice ) ) {
			update_user_meta( get_current_user_id(), self::NOTICE_DISMISS_META, self::notice_key( $notice ) );
		}
		delete_option( self::NOTICE_OPTION );

		$redirect = wp_get_referer();
		if ( ! is_string( $redirect ) || '' === $redirect ) {
			$redirect = admin_url();
		}
		wp_safe_redirect( $redirect );
		exit;
	}

	public function maybe_render_notice(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		$notice = get_option( self::NOTICE_OPTION, null );
		if ( ! is_array( $notice ) ) {
			return;
		}

		$from = (int) ( $notice['from'] ?? 0 );
		$to   = (int) ( $notice['to'] ?? 0 );
		if ( $from <= 0 || $to <= 0 ) {
			return;
		}

		$key       = self::notice_key( $notice );
		$dismissed = (string) get_user_meta( get_current_user_id(), self::NOTICE_DISMISS_META, true );
		if ( $dismissed === $key ) {
			return;
		}

		$actor = sanitize_text_field( (string) ( $notice['actor'] ?? '' ) );
		$text  = self::format_gap_window( $from, $to );
		if ( '' !== $actor ) {
			$text .= ' ' . sprintf(
				/* translators: %s: WordPress user login or wp-cli */
				__( '(last stopped by %s.)', 'handl-ai-connector-access-control' ),
				$actor
			);
		}

		echo '<div class="notice notice-warning"><p>' . esc_html( $text ) . '</p>';
		echo '<form method="post" action="">';
		wp_nonce_field( 'handl_aicac_tamper_gap_dismiss', 'handl_aicac_nonce' );
		echo '<input type="hidden" name="handl_aicac_action" value="tamper_gap_dismiss" />';
		submit_button(
			__( 'Dismiss', 'handl-ai-connector-access-control' ),
			'secondary',
			'handl_aicac_tamper_dismiss',
			false
		);
		echo '</form></div>';
	}

	/**
	 * Always-on log write (governance must not depend on Activity logging being enabled).
	 *
	 * @param array<string,mixed> $event
	 */
	public static function append_governance_event( array $event, ?int $now = null ): void {
		$now = ( null !== $now && $now > 0 ) ? $now : time();
		if ( ! isset( $event['ts'] ) ) {
			$event['ts'] = $now;
		}

		$log = get_option( Plugin::LOG_OPTION_KEY );
		if ( ! is_array( $log ) ) {
			$log = array();
		}
		$log[] = $event;

		if ( class_exists( Policy::class ) ) {
			$policy = Policy::get_policy();
			$log    = Policy::apply_log_retention( $log, $policy, $now );
		} else {
			$count = count( $log );
			if ( $count > 200 ) {
				$log = array_values( array_slice( $log, $count - 200 ) );
			}
		}

		update_option( Plugin::LOG_OPTION_KEY, $log, false );
	}

	/**
	 * @param string $actor Acting user or wp-cli.
	 */
	private static function send_deactivation_alert( string $actor, int $now ): void {
		$policy = class_exists( Policy::class ) ? Policy::get_policy() : array();
		if ( ! is_array( $policy ) ) {
			$policy = array();
		}

		// No dedicated routing type yet — unknown type falls back to alert_email / admin_email.
		$to = Alert_Routing::resolve_email( $policy, 'tamper' );
		if ( '' === $to ) {
			return;
		}

		$site = function_exists( 'get_bloginfo' )
			? wp_specialchars_decode( (string) get_bloginfo( 'name' ), ENT_QUOTES )
			: 'WordPress';

		$subject = sprintf(
			/* translators: %s: site name */
			__( '[%s] HandL: AI enforcement was deactivated', 'handl-ai-connector-access-control' ),
			$site
		);

		$when = self::format_ts( $now );
		$lines = array(
			__( 'HandL AI Connector Access Control was deactivated. Deny rules and budgets are no longer enforced, and alerts will not be sent.', 'handl-ai-connector-access-control' ),
			sprintf(
				/* translators: %s: datetime */
				__( 'Stopped at: %s', 'handl-ai-connector-access-control' ),
				$when
			),
		);
		if ( '' !== $actor ) {
			$lines[] = sprintf(
				/* translators: %s: user login or wp-cli */
				__( 'Stopped by: %s', 'handl-ai-connector-access-control' ),
				$actor
			);
		}
		$lines[] = '';
		$lines[] = __( 'Reactivate the plugin to restore enforcement. Site Health will note recent enforcement gaps.', 'handl-ai-connector-access-control' );

		Alerts::safe_wp_mail( $to, $subject, implode( "\n", $lines ) );
	}

	private static function format_ts( int $ts ): string {
		if ( $ts <= 0 ) {
			return '—';
		}
		if ( function_exists( 'wp_date' ) ) {
			$format = trim(
				(string) get_option( 'date_format', 'Y-m-d' ) . ' ' . (string) get_option( 'time_format', 'H:i' )
			);
			$label = wp_date( $format, $ts );
			if ( is_string( $label ) && '' !== $label ) {
				return $label;
			}
		}

		return gmdate( 'Y-m-d H:i', $ts ) . ' UTC';
	}
}
