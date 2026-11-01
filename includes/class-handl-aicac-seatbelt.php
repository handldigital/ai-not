<?php
/**
 * AICAC-SEATBELT (#487): automatic deny-all while WordPress is mid-update.
 *
 * Opt-in (off by default). During an upgrader run or while `.maintenance` is
 * present, reuses Freeze (#267) snapshot → lockdown → restore so half-swapped
 * plugin code cannot make governed AI calls. Denials use reason
 * `update_in_progress`. One Activity summary row per window. Panic freeze wins:
 * seatbelt never ends a freeze it did not start.
 *
 * README-FREE. Does not edit freeze.php.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Update-window seatbelt over Freeze's public API.
 */
final class Seatbelt {

	public const REASON = 'update_in_progress';

	public const SETTINGS_OPTION = 'handl_aicac_seatbelt';

	public const WINDOW_OPTION = 'handl_aicac_seatbelt_window';

	/** Stored on Freeze::start reason so we can recognize our freeze. */
	public const FREEZE_REASON = 'seatbelt-update';

	public const ACTION_SAVE = 'handl_aicac_seatbelt_save';

	public const CRON_HOOK = 'handl_aicac_seatbelt_failsafe';

	/** Default failsafe max window (seconds). */
	public const DEFAULT_FAILSAFE = 600;

	public const FAILSAFE_MIN = 60;

	public const FAILSAFE_MAX = 3600;

	/**
	 * Nearest Freeze::ALLOWED_MINUTES above the failsafe — outer timer bound.
	 * Seatbelt ends earlier via its own failsafe cron / update-complete.
	 */
	public const FREEZE_MINUTES = 15;

	/** @var bool */
	private static $registered = false;

	/** @var int Nested upgrader_pre_install depth. */
	private static $upgrader_depth = 0;

	/** @var int|null */
	private static $test_now = null;

	/** @var bool|null Test override for .maintenance presence. */
	private static $test_maintenance = null;

	public static function init(): void {
		if ( self::$registered ) {
			return;
		}
		self::$registered = true;

		add_filter( 'upgrader_pre_install', array( self::class, 'on_upgrader_pre_install' ), 5, 2 );
		add_action( 'upgrader_process_complete', array( self::class, 'on_upgrader_process_complete' ), 5, 2 );
		add_action( 'init', array( self::class, 'sync_maintenance' ), 5 );
		add_action( self::CRON_HOOK, array( self::class, 'cron_failsafe' ) );
		add_action( 'admin_post_' . self::ACTION_SAVE, array( self::class, 'handle_save' ) );
	}

	public static function reset_for_tests(): void {
		self::$registered       = false;
		self::$upgrader_depth   = 0;
		self::$test_now         = null;
		self::$test_maintenance = null;
		delete_option( self::SETTINGS_OPTION );
		delete_option( self::WINDOW_OPTION );
		if ( function_exists( 'wp_clear_scheduled_hook' ) ) {
			wp_clear_scheduled_hook( self::CRON_HOOK );
		}
	}

	public static function set_test_now( ?int $now ): void {
		self::$test_now = $now;
	}

	public static function set_test_maintenance( ?bool $present ): void {
		self::$test_maintenance = $present;
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
	 * @return array{enabled:bool,failsafe_seconds:int}
	 */
	public static function get_settings(): array {
		$raw = get_option( self::SETTINGS_OPTION, null );
		if ( ! is_array( $raw ) ) {
			return self::default_settings();
		}

		return self::sanitize_settings( $raw );
	}

	/**
	 * @param array<string,mixed> $in
	 * @return array{enabled:bool,failsafe_seconds:int}
	 */
	public static function save_settings( array $in ): array {
		$clean = self::sanitize_settings( $in );
		update_option( self::SETTINGS_OPTION, $clean, false );

		return $clean;
	}

	public static function is_enabled(): bool {
		return ! empty( self::get_settings()['enabled'] );
	}

	/**
	 * @return array{enabled:bool,failsafe_seconds:int}
	 */
	private static function default_settings(): array {
		return array(
			'enabled'          => false,
			'failsafe_seconds' => self::DEFAULT_FAILSAFE,
		);
	}

	/**
	 * @param array<string,mixed> $raw
	 * @return array{enabled:bool,failsafe_seconds:int}
	 */
	private static function sanitize_settings( array $raw ): array {
		$out                   = self::default_settings();
		$out['enabled']        = ! empty( $raw['enabled'] );
		$sec                   = isset( $raw['failsafe_seconds'] ) ? (int) $raw['failsafe_seconds'] : self::DEFAULT_FAILSAFE;
		$out['failsafe_seconds'] = max( self::FAILSAFE_MIN, min( self::FAILSAFE_MAX, $sec ) );

		return $out;
	}

	/* ---------------------------------------------------------------------
	 * Window
	 * ------------------------------------------------------------------ */

	/**
	 * @return array{
	 *   active:bool,
	 *   owns_freeze:bool,
	 *   deferred_manual:bool,
	 *   started_ts:int,
	 *   expires_ts:int,
	 *   held_count:int,
	 *   source:string
	 * }
	 */
	public static function get_window(): array {
		$raw = get_option( self::WINDOW_OPTION, null );
		if ( ! is_array( $raw ) ) {
			return self::empty_window();
		}

		return self::sanitize_window( $raw );
	}

	/**
	 * Whether seatbelt should deny this call with REASON (not kill_switch).
	 */
	public static function should_deny( ?int $now = null ): bool {
		$now = null !== $now ? (int) $now : self::now();
		self::ensure_closed_if_past( $now );

		if ( ! self::is_enabled() ) {
			return false;
		}

		$win = self::get_window();
		if ( empty( $win['active'] ) || ! empty( $win['deferred_manual'] ) ) {
			return false;
		}

		return $now < (int) $win['expires_ts'];
	}

	/**
	 * Count a held call during an active seatbelt window.
	 */
	public static function note_held(): void {
		$win = self::get_window();
		if ( empty( $win['active'] ) || ! empty( $win['deferred_manual'] ) ) {
			return;
		}
		$win['held_count'] = (int) $win['held_count'] + 1;
		update_option( self::WINDOW_OPTION, $win, false );
	}

	/**
	 * Open (or refresh) the update window. Idempotent while already active.
	 *
	 * @param string $source upgrader|maintenance
	 */
	public static function begin_window( string $source = 'upgrader', ?int $now = null ): void {
		if ( ! self::is_enabled() ) {
			return;
		}
		$now    = null !== $now ? (int) $now : self::now();
		$source = in_array( $source, array( 'upgrader', 'maintenance' ), true ) ? $source : 'upgrader';

		$win = self::get_window();
		if ( ! empty( $win['active'] ) ) {
			// Keep the earlier expiry; do not extend on nested upgrader calls.
			return;
		}

		$settings = self::get_settings();
		$failsafe = (int) $settings['failsafe_seconds'];
		$expires  = $now + $failsafe;

		$owns_freeze     = false;
		$deferred_manual = false;

		if ( class_exists( Freeze::class, false ) && Freeze::is_active( $now ) ) {
			// Panic freeze (or other) already owns deny-all — do not fight it.
			$deferred_manual = true;
		} elseif ( class_exists( Freeze::class, false ) ) {
			$result = Freeze::start( self::FREEZE_MINUTES, self::FREEZE_REASON, $now );
			if ( ! empty( $result['ok'] ) ) {
				$owns_freeze = true;
			} elseif ( 'already_active' === (string) ( $result['error'] ?? '' ) ) {
				$deferred_manual = true;
			}
		}

		$state = array(
			'active'          => true,
			'owns_freeze'     => $owns_freeze,
			'deferred_manual' => $deferred_manual,
			'started_ts'      => $now,
			'expires_ts'      => $expires,
			'held_count'      => 0,
			'source'          => $source,
		);
		update_option( self::WINDOW_OPTION, $state, false );
		self::schedule_failsafe( $expires );
	}

	/**
	 * Close the window; restore via Freeze::end only when we own the freeze.
	 *
	 * @param string $cause complete|failsafe|maintenance_clear|manual_cleared
	 */
	public static function end_window( string $cause = 'complete', ?int $now = null ): void {
		$now = null !== $now ? (int) $now : self::now();
		$win = self::get_window();
		if ( empty( $win['active'] ) ) {
			return;
		}

		$held = (int) $win['held_count'];
		$owns = ! empty( $win['owns_freeze'] );

		self::unschedule_failsafe();

		if ( $owns && class_exists( Freeze::class, false ) && Freeze::is_active( $now ) ) {
			$freeze_state = Freeze::get_state();
			$reason       = isset( $freeze_state['reason'] ) ? (string) $freeze_state['reason'] : '';
			// Never end a freeze we did not start (AC4).
			if ( self::FREEZE_REASON === $reason ) {
				Freeze::end( $now );
			}
		}

		self::append_summary( $held, $cause, $now );
		update_option( self::WINDOW_OPTION, self::empty_window(), false );
	}

	public static function ensure_closed_if_past( ?int $now = null ): void {
		$now = null !== $now ? (int) $now : self::now();
		$win = self::get_window();
		if ( empty( $win['active'] ) ) {
			return;
		}
		if ( $now < (int) $win['expires_ts'] ) {
			// If we owned a freeze and an admin restored early, clear our window.
			if ( ! empty( $win['owns_freeze'] ) && class_exists( Freeze::class, false ) && ! Freeze::is_active( $now ) ) {
				self::end_window( 'manual_cleared', $now );
			}
			return;
		}
		self::end_window( 'failsafe', $now );
	}

	/* ---------------------------------------------------------------------
	 * Hooks
	 * ------------------------------------------------------------------ */

	/**
	 * @param bool|mixed           $pass
	 * @param array<string,mixed>  $args
	 * @return mixed
	 */
	public static function on_upgrader_pre_install( $pass, $args = array() ) {
		unset( $args );
		++self::$upgrader_depth;
		self::begin_window( 'upgrader' );

		return $pass;
	}

	/**
	 * @param mixed               $upgrader
	 * @param array<string,mixed> $options
	 */
	public static function on_upgrader_process_complete( $upgrader, $options = array() ): void {
		unset( $upgrader, $options );
		self::$upgrader_depth = max( 0, self::$upgrader_depth - 1 );
		if ( self::$upgrader_depth > 0 ) {
			return;
		}
		if ( self::maintenance_present() ) {
			return;
		}
		self::end_window( 'complete' );
	}

	public static function sync_maintenance(): void {
		if ( ! self::is_enabled() ) {
			return;
		}
		$now = self::now();
		self::ensure_closed_if_past( $now );

		if ( self::maintenance_present() ) {
			$win = self::get_window();
			if ( empty( $win['active'] ) ) {
				self::begin_window( 'maintenance', $now );
			}
			return;
		}

		$win = self::get_window();
		if ( ! empty( $win['active'] ) && 'maintenance' === (string) ( $win['source'] ?? '' ) && self::$upgrader_depth <= 0 ) {
			self::end_window( 'maintenance_clear', $now );
		}
	}

	public static function cron_failsafe(): void {
		self::ensure_closed_if_past( self::now() );
	}

	public static function handle_save(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to save seatbelt settings.', 'handl-ai-connector-access-control' ) );
		}
		check_admin_referer( self::ACTION_SAVE, 'handl_aicac_nonce' );

		$enabled = isset( $_POST['handl_aicac_seatbelt_enabled'] );
		$failsafe = isset( $_POST['handl_aicac_seatbelt_failsafe'] )
			? (int) wp_unslash( (string) $_POST['handl_aicac_seatbelt_failsafe'] )
			: self::DEFAULT_FAILSAFE;

		self::save_settings(
			array(
				'enabled'          => $enabled,
				'failsafe_seconds' => $failsafe,
			)
		);

		$tab = isset( $_POST['handl_aicac_tab'] )
			? sanitize_key( wp_unslash( (string) $_POST['handl_aicac_tab'] ) )
			: 'protections';

		wp_safe_redirect(
			add_query_arg(
				array(
					'page'               => 'handl-aicac',
					'handl_aicac_tab'    => $tab,
					'handl_aicac_seatbelt' => 'saved',
				),
				admin_url( 'options-general.php' )
			)
		);
		exit;
	}

	/**
	 * Opt-in toggle on the Freeze screen (no freeze.php edits).
	 */
	public static function render_panel( string $tab = 'protections' ): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$settings = self::get_settings();
		$win      = self::get_window();

		echo '<div class="handl-aicac-seatbelt-panel" style="border:1px solid #c3c4c7;padding:12px 16px;background:#fff;max-width:40em;margin:0 0 1.25em;">';
		echo '<h2 style="margin-top:0;">' . esc_html__( 'Update seatbelt', 'handl-ai-connector-access-control' ) . '</h2>';
		echo '<p>' . esc_html__( 'Block AI calls controlled by HandL during WordPress, plugin, and theme updates. Your policy is restored when this protection ends. Off by default.', 'handl-ai-connector-access-control' ) . '</p>';

		if ( ! empty( $win['active'] ) ) {
			echo '<p><strong>' . esc_html__( 'Update protection is active.', 'handl-ai-connector-access-control' ) . '</strong> ';
			echo esc_html(
				sprintf(
					/* translators: %d: blocked AI call count during the update window */
					__( 'AI calls blocked during this update: %d.', 'handl-ai-connector-access-control' ),
					(int) $win['held_count']
				)
			);
			echo '</p>';
		}

		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
		echo '<input type="hidden" name="action" value="' . esc_attr( self::ACTION_SAVE ) . '" />';
		echo '<input type="hidden" name="handl_aicac_tab" value="' . esc_attr( $tab ) . '" />';
		wp_nonce_field( self::ACTION_SAVE, 'handl_aicac_nonce' );
		echo '<p><label><input type="checkbox" name="handl_aicac_seatbelt_enabled" value="1" ' . checked( ! empty( $settings['enabled'] ), true, false ) . ' /> ';
		echo esc_html__( 'Block AI calls during updates', 'handl-ai-connector-access-control' ) . '</label></p>';
		echo '<p><label for="handl-aicac-seatbelt-failsafe">' . esc_html__( 'Maximum blocking time (seconds)', 'handl-ai-connector-access-control' ) . '</label> ';
		echo '<input type="number" min="' . esc_attr( (string) self::FAILSAFE_MIN ) . '" max="' . esc_attr( (string) self::FAILSAFE_MAX ) . '" name="handl_aicac_seatbelt_failsafe" id="handl-aicac-seatbelt-failsafe" value="' . esc_attr( (string) $settings['failsafe_seconds'] ) . '" /></p>';
		echo '<p class="description">' . esc_html__( 'Default: 600 seconds (10 minutes). Protection ends when the update finishes or this limit is reached, whichever comes first. An existing manual freeze stays active.', 'handl-ai-connector-access-control' ) . '</p>';
		submit_button( __( 'Save seatbelt settings', 'handl-ai-connector-access-control' ), 'secondary', 'submit', false );
		echo '</form>';
		echo '</div>';
	}

	/* ---------------------------------------------------------------------
	 * Internals
	 * ------------------------------------------------------------------ */

	/**
	 * @return array{
	 *   active:bool,
	 *   owns_freeze:bool,
	 *   deferred_manual:bool,
	 *   started_ts:int,
	 *   expires_ts:int,
	 *   held_count:int,
	 *   source:string
	 * }
	 */
	private static function empty_window(): array {
		return array(
			'active'          => false,
			'owns_freeze'     => false,
			'deferred_manual' => false,
			'started_ts'      => 0,
			'expires_ts'      => 0,
			'held_count'      => 0,
			'source'          => '',
		);
	}

	/**
	 * @param array<string,mixed> $raw
	 * @return array{
	 *   active:bool,
	 *   owns_freeze:bool,
	 *   deferred_manual:bool,
	 *   started_ts:int,
	 *   expires_ts:int,
	 *   held_count:int,
	 *   source:string
	 * }
	 */
	private static function sanitize_window( array $raw ): array {
		$out                    = self::empty_window();
		$out['active']          = ! empty( $raw['active'] );
		$out['owns_freeze']     = ! empty( $raw['owns_freeze'] );
		$out['deferred_manual'] = ! empty( $raw['deferred_manual'] );
		$out['started_ts']      = isset( $raw['started_ts'] ) ? (int) $raw['started_ts'] : 0;
		$out['expires_ts']      = isset( $raw['expires_ts'] ) ? (int) $raw['expires_ts'] : 0;
		$out['held_count']      = isset( $raw['held_count'] ) ? max( 0, (int) $raw['held_count'] ) : 0;
		$out['source']          = isset( $raw['source'] ) ? sanitize_key( (string) $raw['source'] ) : '';

		return $out;
	}

	private static function maintenance_present(): bool {
		if ( null !== self::$test_maintenance ) {
			return (bool) self::$test_maintenance;
		}
		if ( ! defined( 'ABSPATH' ) ) {
			return false;
		}
		$path = ABSPATH . '.maintenance';

		return is_string( $path ) && file_exists( $path );
	}

	private static function schedule_failsafe( int $expires_ts ): void {
		self::unschedule_failsafe();
		if ( function_exists( 'wp_schedule_single_event' ) ) {
			wp_schedule_single_event( $expires_ts, self::CRON_HOOK );
		}
	}

	private static function unschedule_failsafe(): void {
		if ( function_exists( 'wp_next_scheduled' ) && function_exists( 'wp_unschedule_event' ) ) {
			$ts = wp_next_scheduled( self::CRON_HOOK );
			if ( $ts ) {
				wp_unschedule_event( (int) $ts, self::CRON_HOOK );
			}
		}
		if ( function_exists( 'wp_clear_scheduled_hook' ) ) {
			wp_clear_scheduled_hook( self::CRON_HOOK );
		}
	}

	/**
	 * Plain Activity label for an internal window-end cause code.
	 */
	public static function cause_label( string $cause ): string {
		$map = array(
			'complete'          => __( 'update finished', 'handl-ai-connector-access-control' ),
			'failsafe'          => __( 'time limit reached', 'handl-ai-connector-access-control' ),
			'maintenance_clear' => __( 'maintenance ended', 'handl-ai-connector-access-control' ),
			'manual_cleared'    => __( 'manual restore', 'handl-ai-connector-access-control' ),
		);
		$key = sanitize_key( $cause );

		return $map[ $key ] ?? __( 'protection ended', 'handl-ai-connector-access-control' );
	}

	private static function append_summary( int $held, string $cause, int $now ): void {
		if ( ! class_exists( Policy::class, false ) ) {
			return;
		}
		$held  = max( 0, $held );
		$label = self::cause_label( $cause );
		Policy::append_log_event(
			array(
				'ts'       => $now,
				'decision' => 'seatbelt_window',
				'channel'  => 'seatbelt',
				'cause'    => sanitize_key( $cause ),
				'held'     => $held,
				'summary'  => sprintf(
					/* translators: 1: plain end reason (e.g. update finished), 2: blocked call count */
					__( 'Update protection ended (%1$s). AI calls blocked: %2$d.', 'handl-ai-connector-access-control' ),
					$label,
					$held
				),
			)
		);
	}
}
