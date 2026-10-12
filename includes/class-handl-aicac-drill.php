<?php
/**
 * AICAC-DRILL (#397): incident drill — rehearse the alert path without a real incident.
 *
 * Pick a bundled scenario (provider outage, leaked key, budget blowout, train-by-default
 * provider), run it, and get a scorecard of which protections WOULD fire versus which
 * are dead ends (control off / unavailable / no recipient / routing empty / default allow).
 * Evaluation is read-only: no rule, budget, key, canary or policy is changed and the
 * activity log is never written. One clearly-labelled [DRILL] alert is sent per run
 * (email + optional webhook) with an acknowledgement link; if nobody acknowledges within
 * the window, exactly one [DRILL] follow-up is sent. Optional monthly schedule (daily cron
 * with a calendar-month gate). OFF by default. Own two options. Print + CSV + WP-CLI
 * `aicac drill run|status|export` (status non-zero when the latest drill has dead ends or
 * an expired unacknowledged run).
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Incident drill scorecard + acknowledgement tracking.
 */
final class Drill {

	public const SETTINGS_OPTION = 'handl_aicac_drill';

	public const HISTORY_OPTION = 'handl_aicac_drill_history';

	public const PAGE_SLUG = 'handl-aicac-drill';

	public const CRON_HOOK = 'handl_aicac_drill_cron';

	public const FILTER_SCENARIOS = 'handl_aicac_drill_scenarios';

	public const FILTER_ACK_WINDOW = 'handl_aicac_drill_ack_window';

	public const ALERT_KIND = 'drill';

	public const SUBJECT_PREFIX = '[DRILL]';

	public const DEFAULT_ACK_WINDOW_HOURS = 72;

	public const DEFAULT_SCENARIO = 'provider_outage';

	public const HISTORY_CAP = 50;

	public const STATUS_FIRE = 'fire';

	public const STATUS_DEAD_END = 'dead_end';

	public const TRIGGER_MANUAL = 'manual';

	public const TRIGGER_SCHEDULE = 'schedule';

	public const POST_PRESENT = 'handl_aicac_drill_present';

	public const POST_ENABLED = 'handl_aicac_drill_enabled';

	public const POST_SCHEDULE = 'handl_aicac_drill_schedule_enabled';

	public const POST_WINDOW = 'handl_aicac_drill_ack_window_hours';

	public const POST_SCENARIO = 'handl_aicac_drill_default_scenario';

	public const POST_RUN_SCENARIO = 'handl_aicac_drill_run_scenario';

	public const ACTION_SAVE = 'handl_aicac_drill_save';

	public const ACTION_RUN = 'handl_aicac_drill_run';

	public const ACTION_ACK = 'handl_aicac_drill_ack';

	public const QUERY_ACK = 'handl_aicac_drill_ack';

	/** @var list<string> */
	public const REASONS = array(
		'ready',
		'control_off',
		'control_unavailable',
		'no_recipient',
		'routing_empty',
		'default_allow',
	);

	/** @var bool */
	private static $registered = false;

	/**
	 * Mail buffer (also populated outside tests; read-only diagnostic).
	 *
	 * @var list<array<string,mixed>>
	 */
	public static $test_mails = array();

	public static function init(): void {
		if ( self::$registered ) {
			return;
		}
		self::$registered = true;

		add_action( 'admin_menu', array( self::class, 'register_menu' ), 20 );
		add_action( 'admin_init', array( self::class, 'maybe_handle_csv' ), 5 );
		add_action( 'admin_init', array( self::class, 'maybe_handle_print' ), 5 );
		add_action( 'admin_init', array( self::class, 'maybe_handle_ack' ), 5 );
		add_action( 'admin_post_' . self::ACTION_SAVE, array( self::class, 'handle_save' ) );
		add_action( 'admin_post_' . self::ACTION_RUN, array( self::class, 'handle_run' ) );
		add_action( 'admin_post_' . self::ACTION_ACK, array( self::class, 'handle_ack' ) );
		add_action( self::CRON_HOOK, array( self::class, 'cron_run' ) );
		// Self-heal: schedules only when wanted, otherwise clears a stray event.
		add_action( 'init', array( self::class, 'maybe_schedule' ), 25 );

		if ( self::is_enabled() ) {
			add_action( 'init', array( self::class, 'maybe_send_followups' ), 30 );
		}

		if ( function_exists( 'register_deactivation_hook' ) && defined( 'HANDL_AICAC_FILE' ) ) {
			register_deactivation_hook( HANDL_AICAC_FILE, array( self::class, 'on_deactivate' ) );
		}

		self::register_cli();
	}

	public static function reset_for_tests(): void {
		self::$registered = false;
		self::$test_mails = array();
		delete_option( self::SETTINGS_OPTION );
		delete_option( self::HISTORY_OPTION );
		self::clear_schedule();
	}

	/**
	 * @return list<array<string,mixed>>
	 */
	public static function test_mails(): array {
		return self::$test_mails;
	}

	/**
	 * @return array{enabled:bool,schedule_enabled:bool,ack_window_hours:int,default_scenario:string}
	 */
	public static function defaults(): array {
		return array(
			'enabled'          => false,
			'schedule_enabled' => false,
			'ack_window_hours' => self::DEFAULT_ACK_WINDOW_HOURS,
			'default_scenario' => self::DEFAULT_SCENARIO,
		);
	}

	/**
	 * @return array{enabled:bool,schedule_enabled:bool,ack_window_hours:int,default_scenario:string}
	 */
	public static function get_settings(): array {
		return self::sanitize_settings( get_option( self::SETTINGS_OPTION, array() ) );
	}

	/**
	 * @param mixed $raw Raw settings.
	 * @return array{enabled:bool,schedule_enabled:bool,ack_window_hours:int,default_scenario:string}
	 */
	public static function sanitize_settings( $raw ): array {
		$defaults = self::defaults();
		if ( ! is_array( $raw ) ) {
			return $defaults;
		}

		return array(
			'enabled'          => ! empty( $raw['enabled'] ),
			'schedule_enabled' => ! empty( $raw['schedule_enabled'] ),
			'ack_window_hours' => self::sanitize_ack_window_hours( $raw['ack_window_hours'] ?? $defaults['ack_window_hours'] ),
			'default_scenario' => self::sanitize_scenario_id( $raw['default_scenario'] ?? $defaults['default_scenario'] ),
		);
	}

	/**
	 * @param mixed $raw Raw hours.
	 */
	public static function sanitize_ack_window_hours( $raw ): int {
		if ( ! is_numeric( $raw ) ) {
			return self::DEFAULT_ACK_WINDOW_HOURS;
		}
		$v = (int) $raw;
		if ( $v < 1 ) {
			$v = 1;
		}
		if ( $v > 720 ) {
			$v = 720;
		}

		return $v;
	}

	/**
	 * Known scenario id, else the default.
	 *
	 * @param mixed $raw Raw id.
	 */
	public static function sanitize_scenario_id( $raw ): string {
		$id = sanitize_key( (string) $raw );
		if ( '' !== $id && isset( self::scenarios()[ $id ] ) ) {
			return $id;
		}

		return self::DEFAULT_SCENARIO;
	}

	/**
	 * Persist settings, then reconcile the cron schedule.
	 *
	 * @param array<string,mixed> $settings Settings.
	 */
	public static function save_settings( array $settings ): bool {
		$clean  = self::sanitize_settings( $settings );
		$before = self::get_settings();
		if ( $clean === $before ) {
			self::maybe_schedule();

			return false;
		}
		if ( $clean === self::defaults() ) {
			delete_option( self::SETTINGS_OPTION );
		} else {
			update_option( self::SETTINGS_OPTION, $clean, false );
		}
		self::maybe_schedule();

		return true;
	}

	public static function is_enabled(): bool {
		$settings = self::get_settings();

		return ! empty( $settings['enabled'] );
	}

	/**
	 * Seconds an unacknowledged drill may stay open before the single follow-up.
	 */
	public static function ack_window_seconds(): int {
		$settings = self::get_settings();
		$base     = (int) $settings['ack_window_hours'] * 3600;
		$out      = $base;
		if ( function_exists( 'apply_filters' ) ) {
			$filtered = apply_filters( self::FILTER_ACK_WINDOW, $base );
			if ( is_numeric( $filtered ) ) {
				$out = (int) $filtered;
			}
		}

		return $out < 1 ? 1 : $out;
	}

	/* ------------------------------------------------------------------ */
	/* Scenarios                                                          */
	/* ------------------------------------------------------------------ */

	/**
	 * Bundled scenario table (filterable).
	 *
	 * @return array<string,array{id:string,label:string,description:string,controls:list<string>}>
	 */
	public static function bundled_scenarios(): array {
		return array(
			'provider_outage'           => array(
				'id'          => 'provider_outage',
				'label'       => __( 'Provider outage', 'handl-ai-connector-access-control' ),
				'description' => __( 'An AI provider starts failing. Would the circuit breaker trip, would you be told, and could you restore a known-good policy?', 'handl-ai-connector-access-control' ),
				'controls'    => array( 'circuit_breaker', 'alerts', 'policy_backup' ),
			),
			'leaked_key'                => array(
				'id'          => 'leaked_key',
				'label'       => __( 'Leaked API key', 'handl-ai-connector-access-control' ),
				'description' => __( 'A provider key leaks. Would the canary trip, would a key scan notice, and would you be told?', 'handl-ai-connector-access-control' ),
				'controls'    => array( 'canary', 'alerts', 'keyscan' ),
			),
			'budget_blowout'            => array(
				'id'          => 'budget_blowout',
				'label'       => __( 'Budget blowout', 'handl-ai-connector-access-control' ),
				'description' => __( 'A plugin burns through its AI budget. Would the cap fire and would the right people hear about it?', 'handl-ai-connector-access-control' ),
				'controls'    => array( 'budget', 'alerts' ),
			),
			'train_by_default_provider' => array(
				'id'          => 'train_by_default_provider',
				'label'       => __( 'Train-by-default provider', 'handl-ai-connector-access-control' ),
				'description' => __( 'A newly added plugin routes data to a provider that trains by default. Would deny-by-default and new-plugin review catch it?', 'handl-ai-connector-access-control' ),
				'controls'    => array( 'policy_default_deny', 'new_plugin', 'alerts' ),
			),
		);
	}

	/**
	 * Scenario table after the `handl_aicac_drill_scenarios` filter, sanitized.
	 *
	 * @return array<string,array{id:string,label:string,description:string,controls:list<string>}>
	 */
	public static function scenarios(): array {
		$table = self::bundled_scenarios();
		if ( function_exists( 'apply_filters' ) ) {
			$filtered = apply_filters( self::FILTER_SCENARIOS, $table );
			if ( is_array( $filtered ) ) {
				$table = $filtered;
			}
		}
		$out = array();
		foreach ( $table as $key => $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$id = sanitize_key( (string) ( $row['id'] ?? $key ) );
			if ( '' === $id ) {
				continue;
			}
			$controls = array();
			foreach ( (array) ( $row['controls'] ?? array() ) as $control ) {
				$control = sanitize_key( (string) $control );
				if ( '' !== $control && ! in_array( $control, $controls, true ) ) {
					$controls[] = $control;
				}
			}
			if ( empty( $controls ) ) {
				continue;
			}
			$out[ $id ] = array(
				'id'          => $id,
				'label'       => sanitize_text_field( (string) ( $row['label'] ?? $id ) ),
				'description' => sanitize_text_field( (string) ( $row['description'] ?? '' ) ),
				'controls'    => $controls,
			);
		}
		if ( empty( $out ) ) {
			return self::bundled_scenarios();
		}

		return $out;
	}

	/**
	 * @return array<string,string>
	 */
	public static function control_labels(): array {
		return array(
			'circuit_breaker'     => __( 'Circuit breaker', 'handl-ai-connector-access-control' ),
			'alerts'              => __( 'Denial alerts', 'handl-ai-connector-access-control' ),
			'policy_backup'       => __( 'Policy backup email', 'handl-ai-connector-access-control' ),
			'canary'              => __( 'Canary token', 'handl-ai-connector-access-control' ),
			'keyscan'             => __( 'Key scan', 'handl-ai-connector-access-control' ),
			'budget'              => __( 'Plugin budgets', 'handl-ai-connector-access-control' ),
			'policy_default_deny' => __( 'Default deny', 'handl-ai-connector-access-control' ),
			'new_plugin'          => __( 'New-plugin review', 'handl-ai-connector-access-control' ),
		);
	}

	public static function control_label( string $control ): string {
		$labels = self::control_labels();

		return $labels[ $control ] ?? $control;
	}

	/**
	 * @return array<string,string>
	 */
	public static function reason_labels(): array {
		return array(
			'ready'               => __( 'Ready', 'handl-ai-connector-access-control' ),
			'control_off'         => __( 'Control is off', 'handl-ai-connector-access-control' ),
			'control_unavailable' => __( 'Control unavailable', 'handl-ai-connector-access-control' ),
			'no_recipient'        => __( 'No alert recipient', 'handl-ai-connector-access-control' ),
			'routing_empty'       => __( 'Alert routing is empty', 'handl-ai-connector-access-control' ),
			'default_allow'       => __( 'Default is allow', 'handl-ai-connector-access-control' ),
		);
	}

	/* ------------------------------------------------------------------ */
	/* Scorecard                                                          */
	/* ------------------------------------------------------------------ */

	/**
	 * Admin deep link for a control (Admin::screen_url when available).
	 */
	public static function deep_link_for_control( string $control ): string {
		$screens = array(
			'circuit_breaker'     => 'protections',
			'budget'              => 'protections',
			'canary'              => 'protections',
			'alerts'              => 'alerts',
			'policy_backup'       => 'alerts',
			'new_plugin'          => 'rules',
			'policy_default_deny' => 'rules',
			'keyscan'             => 'activity',
		);
		$screen  = $screens[ $control ] ?? 'dashboard';
		if ( class_exists( Admin::class, false ) && method_exists( Admin::class, 'screen_url' ) ) {
			return (string) Admin::screen_url( $screen );
		}
		if ( ! function_exists( 'admin_url' ) ) {
			return '';
		}
		$pages = array(
			'protections' => 'handl-aicac-protections',
			'alerts'      => 'handl-aicac-alerts',
			'rules'       => 'handl-aicac-rules',
			'activity'    => 'handl-aicac-activity',
			'dashboard'   => 'handl-aicac',
		);

		return (string) add_query_arg( 'page', $pages[ $screen ] ?? 'handl-aicac', admin_url( 'admin.php' ) );
	}

	/**
	 * @return array<string,mixed>
	 */
	private static function current_policy(): array {
		if ( class_exists( Policy::class, false ) ) {
			$policy = Policy::get_policy();
		} else {
			$policy = get_option( Plugin::OPTION_KEY, array() );
		}

		return is_array( $policy ) ? $policy : array();
	}

	/**
	 * Recipient for an alert type; '' when none.
	 *
	 * @param array<string,mixed> $policy Policy.
	 */
	private static function recipient( array $policy, string $routing_type = '' ): string {
		if ( '' !== $routing_type && class_exists( Alert_Routing::class, false ) && method_exists( Alert_Routing::class, 'resolve_email' ) ) {
			return trim( (string) Alert_Routing::resolve_email( $policy, $routing_type ) );
		}
		if ( class_exists( Alerts::class, false ) && method_exists( Alerts::class, 'resolve_email' ) ) {
			return trim( (string) Alerts::resolve_email( $policy ) );
		}

		return '';
	}

	/**
	 * @return array{status:string,reason:string}
	 */
	private static function verdict( bool $fires, string $reason ): array {
		return array(
			'status' => $fires ? self::STATUS_FIRE : self::STATUS_DEAD_END,
			'reason' => $reason,
		);
	}

	/**
	 * Evaluate one control against the current policy. Read-only.
	 *
	 * @param array<string,mixed> $policy Policy.
	 * @return array{status:string,reason:string}
	 */
	public static function evaluate_control( string $control, array $policy ): array {
		switch ( $control ) {
			case 'alerts':
				if ( ! class_exists( Alerts::class, false ) ) {
					return self::verdict( false, 'control_unavailable' );
				}
				if ( empty( $policy['alert_on_deny'] ) ) {
					return self::verdict( false, 'control_off' );
				}
				if ( '' === self::recipient( $policy ) ) {
					return self::verdict( false, 'no_recipient' );
				}

				return self::verdict( true, 'ready' );

			case 'circuit_breaker':
				if ( ! class_exists( Circuit_Breaker::class, false ) || ! method_exists( Circuit_Breaker::class, 'is_enabled' ) ) {
					return self::verdict( false, 'control_unavailable' );
				}
				if ( ! Circuit_Breaker::is_enabled() ) {
					return self::verdict( false, 'control_off' );
				}

				return self::verdict( true, 'ready' );

			case 'budget':
				if ( ! class_exists( Budget::class, false ) || ! method_exists( Budget::class, 'sanitize_plugin_budgets' ) ) {
					return self::verdict( false, 'control_unavailable' );
				}
				$budgets = Budget::sanitize_plugin_budgets( $policy['plugin_budgets'] ?? array() );
				if ( empty( $budgets ) ) {
					return self::verdict( false, 'control_off' );
				}
				if ( '' === self::recipient( $policy, 'budget' ) ) {
					return self::verdict( false, 'routing_empty' );
				}

				return self::verdict( true, 'ready' );

			case 'canary':
				if ( ! class_exists( Canary::class, false ) || ! method_exists( Canary::class, 'token' ) ) {
					return self::verdict( false, 'control_unavailable' );
				}
				if ( '' === (string) Canary::token() ) {
					return self::verdict( false, 'control_off' );
				}
				if ( '' === self::recipient( $policy, 'canary' ) ) {
					return self::verdict( false, 'routing_empty' );
				}

				return self::verdict( true, 'ready' );

			case 'policy_backup':
				if ( ! class_exists( Policy_Backup::class, false ) || ! method_exists( Policy_Backup::class, 'is_enabled' ) ) {
					return self::verdict( false, 'control_unavailable' );
				}
				if ( ! Policy_Backup::is_enabled( $policy ) ) {
					return self::verdict( false, 'control_off' );
				}
				if ( '' === self::recipient( $policy ) ) {
					return self::verdict( false, 'no_recipient' );
				}

				return self::verdict( true, 'ready' );

			case 'new_plugin':
				if ( ! class_exists( New_Plugin::class, false ) || ! method_exists( New_Plugin::class, 'is_enabled' ) ) {
					return self::verdict( false, 'control_unavailable' );
				}
				if ( ! New_Plugin::is_enabled( $policy ) ) {
					return self::verdict( false, 'control_off' );
				}

				return self::verdict( true, 'ready' );

			case 'keyscan':
				// Feature presence only: the scanner class is loaded.
				if ( ! class_exists( Keyscan::class, false ) ) {
					return self::verdict( false, 'control_unavailable' );
				}

				return self::verdict( true, 'ready' );

			case 'policy_default_deny':
				if ( 'deny' === ( $policy['default'] ?? 'allow' ) ) {
					return self::verdict( true, 'ready' );
				}

				return self::verdict( false, 'default_allow' );
		}

		return self::verdict( false, 'control_unavailable' );
	}

	/**
	 * Scorecard rows for a scenario (read-only; mutates nothing).
	 *
	 * @param array<string,mixed>|null $policy Optional policy override.
	 * @return list<array{control:string,label:string,status:string,reason:string,deep_link:string}>
	 */
	public static function evaluate_scorecard( string $scenario_id, ?array $policy = null ): array {
		$scenarios = self::scenarios();
		$scenario  = $scenarios[ $scenario_id ] ?? ( $scenarios[ self::DEFAULT_SCENARIO ] ?? reset( $scenarios ) );
		if ( ! is_array( $scenario ) ) {
			return array();
		}
		if ( null === $policy ) {
			$policy = self::current_policy();
		}
		$rows = array();
		foreach ( $scenario['controls'] as $control ) {
			$verdict = self::evaluate_control( (string) $control, $policy );
			$rows[]  = array(
				'control'   => (string) $control,
				'label'     => self::control_label( (string) $control ),
				'status'    => $verdict['status'],
				'reason'    => $verdict['reason'],
				'deep_link' => self::deep_link_for_control( (string) $control ),
			);
		}

		return $rows;
	}

	/**
	 * @param list<array<string,mixed>> $scorecard Rows.
	 */
	public static function count_dead_ends( array $scorecard ): int {
		$n = 0;
		foreach ( $scorecard as $row ) {
			if ( is_array( $row ) && self::STATUS_DEAD_END === ( $row['status'] ?? '' ) ) {
				++$n;
			}
		}

		return $n;
	}

	/* ------------------------------------------------------------------ */
	/* History                                                            */
	/* ------------------------------------------------------------------ */

	/**
	 * @param mixed $raw Raw run.
	 * @return array<string,mixed>|null
	 */
	public static function sanitize_run( $raw ): ?array {
		if ( ! is_array( $raw ) ) {
			return null;
		}
		$id = preg_replace( '/[^A-Za-z0-9]/', '', (string) ( $raw['id'] ?? '' ) ) ?? '';
		if ( '' === $id ) {
			return null;
		}
		$rows = array();
		foreach ( (array) ( $raw['scorecard'] ?? array() ) as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$reason = (string) ( $row['reason'] ?? '' );
			$rows[] = array(
				'control'   => sanitize_key( (string) ( $row['control'] ?? '' ) ),
				'label'     => sanitize_text_field( (string) ( $row['label'] ?? '' ) ),
				'status'    => self::STATUS_FIRE === ( $row['status'] ?? '' ) ? self::STATUS_FIRE : self::STATUS_DEAD_END,
				'reason'    => in_array( $reason, self::REASONS, true ) ? $reason : 'control_unavailable',
				'deep_link' => (string) ( $row['deep_link'] ?? '' ),
			);
		}
		$ts      = isset( $raw['ts'] ) ? max( 0, (int) $raw['ts'] ) : 0;
		$ack_ts  = isset( $raw['ack_ts'] ) ? max( 0, (int) $raw['ack_ts'] ) : 0;
		$trigger = self::TRIGGER_SCHEDULE === ( $raw['trigger'] ?? '' ) ? self::TRIGGER_SCHEDULE : self::TRIGGER_MANUAL;

		return array(
			'id'                  => substr( $id, 0, 40 ),
			'ts'                  => $ts,
			'ym'                  => preg_replace( '/[^0-9-]/', '', (string) ( $raw['ym'] ?? '' ) ) ?? '',
			'trigger'             => $trigger,
			'scenario'            => sanitize_key( (string) ( $raw['scenario'] ?? '' ) ),
			'scenario_label'      => sanitize_text_field( (string) ( $raw['scenario_label'] ?? '' ) ),
			'scorecard'           => $rows,
			'dead_end_count'      => self::count_dead_ends( $rows ),
			'alert_sent'          => ! empty( $raw['alert_sent'] ),
			'followup_sent'       => ! empty( $raw['followup_sent'] ),
			'ack_nonce'           => substr( preg_replace( '/[^A-Za-z0-9]/', '', (string) ( $raw['ack_nonce'] ?? '' ) ) ?? '', 0, 64 ),
			'ack_ts'              => $ack_ts,
			'ack_user_id'         => isset( $raw['ack_user_id'] ) ? max( 0, (int) $raw['ack_user_id'] ) : 0,
			'time_to_ack_seconds' => $ack_ts > 0 ? max( 0, $ack_ts - $ts ) : 0,
		);
	}

	/**
	 * Oldest first, newest last.
	 *
	 * @return list<array<string,mixed>>
	 */
	public static function get_history(): array {
		$raw = get_option( self::HISTORY_OPTION, array() );
		if ( ! is_array( $raw ) ) {
			return array();
		}
		$out = array();
		foreach ( $raw as $row ) {
			$run = self::sanitize_run( $row );
			if ( null !== $run ) {
				$out[] = $run;
			}
		}
		if ( count( $out ) > self::HISTORY_CAP ) {
			$out = array_slice( $out, -self::HISTORY_CAP );
		}

		return $out;
	}

	/**
	 * @param list<array<string,mixed>> $history History.
	 */
	public static function put_history( array $history ): void {
		$clean = array();
		foreach ( $history as $row ) {
			$run = self::sanitize_run( $row );
			if ( null !== $run ) {
				$clean[] = $run;
			}
		}
		if ( count( $clean ) > self::HISTORY_CAP ) {
			$clean = array_slice( $clean, -self::HISTORY_CAP );
		}
		if ( empty( $clean ) ) {
			delete_option( self::HISTORY_OPTION );

			return;
		}
		update_option( self::HISTORY_OPTION, $clean, false );
	}

	/**
	 * @return array<string,mixed>|null
	 */
	public static function latest_run(): ?array {
		$history = self::get_history();
		if ( empty( $history ) ) {
			return null;
		}

		return $history[ count( $history ) - 1 ];
	}

	/**
	 * Calendar month (Y-m) of the last scheduled drill, or ''.
	 */
	public static function last_scheduled_run_ym(): string {
		$last = '';
		foreach ( self::get_history() as $run ) {
			if ( self::TRIGGER_SCHEDULE === $run['trigger'] && '' !== (string) $run['ym'] ) {
				$last = (string) $run['ym'];
			}
		}

		return $last;
	}

	private static function now( ?int $now = null ): int {
		if ( null !== $now && $now > 0 ) {
			return $now;
		}

		return class_exists( Clock::class, false ) ? Clock::now() : time();
	}

	/* ------------------------------------------------------------------ */
	/* Run                                                                */
	/* ------------------------------------------------------------------ */

	/**
	 * Run one drill. Returns the stored run, or an empty array when the feature is off.
	 *
	 * @return array<string,mixed>
	 */
	public static function run( string $scenario_id = '', ?int $now = null, string $trigger = self::TRIGGER_MANUAL ): array {
		if ( ! self::is_enabled() ) {
			return array();
		}
		$now         = self::now( $now );
		$settings    = self::get_settings();
		$scenario_id = '' !== $scenario_id ? sanitize_key( $scenario_id ) : (string) $settings['default_scenario'];
		$scenarios   = self::scenarios();
		if ( ! isset( $scenarios[ $scenario_id ] ) ) {
			$scenario_id = self::sanitize_scenario_id( $settings['default_scenario'] );
		}
		$scenario  = $scenarios[ $scenario_id ];
		$scorecard = self::evaluate_scorecard( $scenario_id );

		$password = function_exists( 'wp_generate_password' ) ? (string) wp_generate_password( 8, false, false ) : substr( md5( uniqid( '', true ) ), 0, 8 );
		$nonce    = function_exists( 'wp_generate_password' ) ? (string) wp_generate_password( 20, false, false ) : substr( md5( uniqid( 'ack', true ) ), 0, 20 );

		$run = array(
			'id'                  => 'd' . dechex( $now ) . $password,
			'ts'                  => $now,
			'ym'                  => gmdate( 'Y-m', $now ),
			'trigger'             => self::TRIGGER_SCHEDULE === $trigger ? self::TRIGGER_SCHEDULE : self::TRIGGER_MANUAL,
			'scenario'            => $scenario_id,
			'scenario_label'      => (string) $scenario['label'],
			'scorecard'           => $scorecard,
			'dead_end_count'      => self::count_dead_ends( $scorecard ),
			'alert_sent'          => false,
			'followup_sent'       => false,
			'ack_nonce'           => $nonce,
			'ack_ts'              => 0,
			'ack_user_id'         => 0,
			'time_to_ack_seconds' => 0,
		);
		$run = self::sanitize_run( $run );
		if ( null === $run ) {
			return array();
		}

		$run['alert_sent'] = self::deliver( $run, false, $now );

		$history   = self::get_history();
		$history[] = $run;
		self::put_history( $history );

		return $run;
	}

	/* ------------------------------------------------------------------ */
	/* Acknowledge + follow-up                                            */
	/* ------------------------------------------------------------------ */

	/**
	 * Acknowledge a drill. Single-shot; the per-run token must match.
	 */
	public static function acknowledge( string $run_id, string $token, int $user_id = 0, ?int $now = null ): bool {
		$run_id = preg_replace( '/[^A-Za-z0-9]/', '', $run_id ) ?? '';
		if ( '' === $run_id || '' === $token ) {
			return false;
		}
		$now     = self::now( $now );
		$history = self::get_history();
		foreach ( $history as $i => $run ) {
			if ( $run['id'] !== $run_id ) {
				continue;
			}
			if ( (int) $run['ack_ts'] > 0 || '' === (string) $run['ack_nonce'] || ! hash_equals( (string) $run['ack_nonce'], $token ) ) {
				return false;
			}
			$run['ack_ts']              = $now;
			$run['ack_user_id']         = max( 0, $user_id );
			$run['time_to_ack_seconds'] = max( 0, $now - (int) $run['ts'] );
			$history[ $i ]              = $run;
			self::put_history( $history );

			return true;
		}

		return false;
	}

	/**
	 * Whether a run is unacknowledged and past the ack window.
	 *
	 * @param array<string,mixed> $run Run.
	 */
	public static function is_ack_expired( array $run, ?int $now = null ): bool {
		if ( (int) ( $run['ack_ts'] ?? 0 ) > 0 ) {
			return false;
		}
		$now = self::now( $now );

		return $now > (int) ( $run['ts'] ?? 0 ) + self::ack_window_seconds();
	}

	/**
	 * Send one follow-up per expired unacknowledged run (single-fire).
	 *
	 * @return list<string> Run ids followed up.
	 */
	public static function maybe_send_followups( ?int $now = null ): array {
		if ( ! self::is_enabled() ) {
			return array();
		}
		$now     = self::now( $now );
		$history = self::get_history();
		$fired   = array();
		foreach ( $history as $i => $run ) {
			if ( ! empty( $run['followup_sent'] ) || ! self::is_ack_expired( $run, $now ) ) {
				continue;
			}
			// Mark first: a mail-transport failure must never cause a second follow-up.
			$run['followup_sent'] = true;
			$history[ $i ]        = $run;
			self::put_history( $history );
			self::deliver( $run, true, $now );
			$fired[] = (string) $run['id'];
		}

		return $fired;
	}

	/**
	 * Non-zero `status` helper: latest (or given) run has dead ends or an expired unacked run.
	 *
	 * @param array<string,mixed>|null $run Optional run.
	 */
	public static function has_status_failure( ?array $run = null, ?int $now = null ): bool {
		if ( null === $run ) {
			$run = self::latest_run();
		}
		if ( null === $run ) {
			return false;
		}
		if ( (int) ( $run['dead_end_count'] ?? 0 ) > 0 ) {
			return true;
		}

		return self::is_ack_expired( $run, $now );
	}

	/* ------------------------------------------------------------------ */
	/* Alert                                                              */
	/* ------------------------------------------------------------------ */

	public static function ack_url( array $run ): string {
		if ( ! function_exists( 'admin_url' ) ) {
			return '';
		}

		return (string) add_query_arg(
			array(
				'action' => self::ACTION_ACK,
				'run'    => (string) ( $run['id'] ?? '' ),
				'token'  => (string) ( $run['ack_nonce'] ?? '' ),
			),
			admin_url( 'admin-post.php' )
		);
	}

	/**
	 * @param array<string,mixed> $run Run.
	 */
	public static function build_subject( array $run, bool $followup = false ): string {
		$site = function_exists( 'get_bloginfo' )
			? wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES )
			: 'WordPress';
		if ( $followup ) {
			return sprintf(
				/* translators: 1: [DRILL] prefix, 2: site name, 3: scenario label */
				__( '%1$s [%2$s] Drill not acknowledged: %3$s (SIMULATION)', 'handl-ai-connector-access-control' ),
				self::SUBJECT_PREFIX,
				$site,
				(string) ( $run['scenario_label'] ?? '' )
			);
		}

		return sprintf(
			/* translators: 1: [DRILL] prefix, 2: site name, 3: scenario label */
			__( '%1$s [%2$s] Incident drill: %3$s (SIMULATION)', 'handl-ai-connector-access-control' ),
			self::SUBJECT_PREFIX,
			$site,
			(string) ( $run['scenario_label'] ?? '' )
		);
	}

	/**
	 * @param array<string,mixed> $run Run.
	 */
	public static function build_body( array $run, bool $followup = false ): string {
		$reasons = self::reason_labels();
		$lines   = array();
		$lines[] = __( 'SIMULATION — this is a drill, not a real incident. Nothing was changed: no rule, budget, key or policy was touched and nothing was written to the activity log.', 'handl-ai-connector-access-control' );
		if ( $followup ) {
			$lines[] = '';
			$lines[] = __( 'Nobody acknowledged this drill inside the acknowledgement window. If this had been real, would anyone have seen it? This is the only follow-up that will be sent.', 'handl-ai-connector-access-control' );
		}
		$lines[] = '';
		$lines[] = sprintf(
			/* translators: %s: scenario label */
			__( 'Scenario: %s', 'handl-ai-connector-access-control' ),
			(string) ( $run['scenario_label'] ?? '' )
		);
		$lines[] = sprintf(
			/* translators: 1: dead-end count, 2: control count */
			__( 'Scorecard: %1$d dead end(s) out of %2$d control(s).', 'handl-ai-connector-access-control' ),
			(int) ( $run['dead_end_count'] ?? 0 ),
			count( (array) ( $run['scorecard'] ?? array() ) )
		);
		foreach ( (array) ( $run['scorecard'] ?? array() ) as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$fires   = self::STATUS_FIRE === ( $row['status'] ?? '' );
			$reason  = (string) ( $row['reason'] ?? '' );
			$lines[] = sprintf(
				/* translators: 1: control label, 2: FIRES or DEAD END, 3: reason label */
				__( '- %1$s: %2$s (%3$s)', 'handl-ai-connector-access-control' ),
				(string) ( $row['label'] ?? '' ),
				$fires ? __( 'would fire', 'handl-ai-connector-access-control' ) : __( 'DEAD END', 'handl-ai-connector-access-control' ),
				$reasons[ $reason ] ?? $reason
			);
			if ( ! $fires && '' !== (string) ( $row['deep_link'] ?? '' ) ) {
				$lines[] = '  ' . (string) $row['deep_link'];
			}
		}
		$url = self::ack_url( $run );
		if ( '' !== $url ) {
			$lines[] = '';
			$lines[] = sprintf(
				/* translators: %s: acknowledgement URL */
				__( 'Acknowledge this drill (sign-in required): %s', 'handl-ai-connector-access-control' ),
				$url
			);
		}

		return implode( "\n", $lines );
	}

	/**
	 * Send one [DRILL] alert (email + optional webhook). Never touches the activity log.
	 *
	 * @param array<string,mixed> $run Run.
	 */
	private static function deliver( array $run, bool $followup, int $now ): bool {
		$policy = self::current_policy();
		$email  = self::recipient( $policy );
		$ok     = false;

		if ( '' !== $email ) {
			$subject = self::build_subject( $run, $followup );
			$body    = self::build_body( $run, $followup );
			if ( class_exists( Alerts::class, false ) && method_exists( Alerts::class, 'safe_wp_mail' ) ) {
				$ok = (bool) Alerts::safe_wp_mail( $email, $subject, $body );
			} elseif ( function_exists( 'wp_mail' ) ) {
				$ok = (bool) wp_mail( $email, $subject, $body ); // phpcs:ignore WordPress.WP.AlternativeFunctions.wp_mail -- drill notification.
			}
			self::$test_mails[] = array(
				'to'       => $email,
				'subject'  => $subject,
				'body'     => $body,
				'followup' => $followup,
				'run_id'   => (string) ( $run['id'] ?? '' ),
			);
		}

		if ( class_exists( Alerts::class, false ) && method_exists( Alerts::class, 'resolve_webhook' ) && method_exists( Alerts::class, 'safe_wp_remote_post' ) ) {
			$hook_url = (string) Alerts::resolve_webhook( $policy );
			if ( '' !== $hook_url ) {
				Alerts::safe_wp_remote_post(
					$hook_url,
					array(
						'type'           => 'handl_aicac_drill',
						'simulation'     => true,
						'followup'       => $followup,
						'run_id'         => (string) ( $run['id'] ?? '' ),
						'scenario'       => (string) ( $run['scenario'] ?? '' ),
						'dead_end_count' => (int) ( $run['dead_end_count'] ?? 0 ),
						'site'           => function_exists( 'home_url' ) ? home_url( '/' ) : '',
						'ts'             => $now,
					)
				);
			}
		}

		return $ok;
	}

	/* ------------------------------------------------------------------ */
	/* Cron                                                               */
	/* ------------------------------------------------------------------ */

	/**
	 * Schedule the daily gate only when enabled AND schedule_enabled; otherwise clear it.
	 */
	public static function maybe_schedule(): void {
		$settings = self::get_settings();
		$want     = ! empty( $settings['enabled'] ) && ! empty( $settings['schedule_enabled'] );
		if ( ! $want ) {
			if ( function_exists( 'wp_next_scheduled' ) && false === wp_next_scheduled( self::CRON_HOOK ) ) {
				return;
			}
			self::clear_schedule();

			return;
		}
		if ( ! function_exists( 'wp_next_scheduled' ) || ! function_exists( 'wp_schedule_event' ) ) {
			return;
		}
		if ( false === wp_next_scheduled( self::CRON_HOOK ) ) {
			$day = defined( 'DAY_IN_SECONDS' ) ? (int) DAY_IN_SECONDS : 86400;
			wp_schedule_event( self::now() + $day, 'daily', self::CRON_HOOK );
		}
	}

	public static function clear_schedule(): void {
		if ( function_exists( 'wp_clear_scheduled_hook' ) ) {
			wp_clear_scheduled_hook( self::CRON_HOOK );
		}
	}

	/**
	 * register_deactivation_hook callback.
	 */
	public static function on_deactivate(): void {
		self::clear_schedule();
	}

	/**
	 * Daily cron: run the default scenario at most once per calendar month.
	 *
	 * @return array<string,mixed> The run, or empty when skipped.
	 */
	public static function cron_run( ?int $now = null ): array {
		$settings = self::get_settings();
		if ( empty( $settings['enabled'] ) || empty( $settings['schedule_enabled'] ) ) {
			return array();
		}
		$now = self::now( $now );
		if ( gmdate( 'Y-m', $now ) === self::last_scheduled_run_ym() ) {
			return array();
		}

		return self::run( (string) $settings['default_scenario'], $now, self::TRIGGER_SCHEDULE );
	}

	/* ------------------------------------------------------------------ */
	/* Export                                                             */
	/* ------------------------------------------------------------------ */

	/**
	 * @param list<string> $cols Columns.
	 */
	public static function csv_line( array $cols ): string {
		$out = array();
		foreach ( $cols as $col ) {
			$col   = (string) $col;
			$needs = str_contains( $col, ',' ) || str_contains( $col, '"' ) || str_contains( $col, "\n" );
			$col   = str_replace( '"', '""', $col );
			$out[] = $needs ? '"' . $col . '"' : $col;
		}

		return implode( ',', $out );
	}

	/**
	 * @param array<string,mixed> $run Run.
	 */
	private static function dead_end_summary( array $run ): string {
		$parts = array();
		foreach ( (array) ( $run['scorecard'] ?? array() ) as $row ) {
			if ( is_array( $row ) && self::STATUS_DEAD_END === ( $row['status'] ?? '' ) ) {
				$parts[] = (string) ( $row['control'] ?? '' ) . ':' . (string) ( $row['reason'] ?? '' );
			}
		}

		return implode( ';', $parts );
	}

	/**
	 * @param list<array<string,mixed>>|null $history Optional history (oldest first).
	 */
	public static function csv_for_history( ?array $history = null ): string {
		if ( null === $history ) {
			$history = self::get_history();
		}
		$lines   = array();
		$lines[] = self::csv_line(
			array(
				'run_id',
				'ts',
				'iso_ts',
				'scenario',
				'trigger',
				'controls',
				'fire_count',
				'dead_end_count',
				'dead_ends',
				'alert_sent',
				'followup_sent',
				'acknowledged',
				'ack_ts',
				'ack_user_id',
				'time_to_ack_seconds',
			)
		);
		foreach ( $history as $run ) {
			$run = self::sanitize_run( $run );
			if ( null === $run ) {
				continue;
			}
			$total   = count( $run['scorecard'] );
			$dead    = (int) $run['dead_end_count'];
			$lines[] = self::csv_line(
				array(
					(string) $run['id'],
					(string) (int) $run['ts'],
					gmdate( 'c', (int) $run['ts'] ),
					(string) $run['scenario'],
					(string) $run['trigger'],
					(string) $total,
					(string) ( $total - $dead ),
					(string) $dead,
					self::dead_end_summary( $run ),
					! empty( $run['alert_sent'] ) ? 'yes' : 'no',
					! empty( $run['followup_sent'] ) ? 'yes' : 'no',
					(int) $run['ack_ts'] > 0 ? 'yes' : 'no',
					(string) (int) $run['ack_ts'],
					(string) (int) $run['ack_user_id'],
					(string) (int) $run['time_to_ack_seconds'],
				)
			);
		}

		return implode( "\n", $lines ) . "\n";
	}

	/**
	 * @param list<array<string,mixed>> $history History (oldest first).
	 */
	public static function build_print_html( array $history ): string {
		$html  = '<!DOCTYPE html><html><head><meta charset="utf-8"><title>';
		$html .= esc_html__( 'Incident drill history', 'handl-ai-connector-access-control' );
		$html .= '</title><style>body{font-family:sans-serif;margin:24px}table{border-collapse:collapse;width:100%;margin-bottom:24px}th,td{border:1px solid #ccc;padding:6px 8px;text-align:left}th{background:#f6f7f7}</style></head><body>';
		$html .= '<h1>' . esc_html__( 'Incident drill history', 'handl-ai-connector-access-control' ) . '</h1>';
		$html .= '<p>' . esc_html__( 'Every drill is a SIMULATION. Nothing is changed and the activity log is never written.', 'handl-ai-connector-access-control' ) . '</p>';
		$html .= '<table><thead><tr>';
		foreach ( array( 'When (UTC)', 'Scenario', 'Trigger', 'Dead ends', 'Alert sent', 'Follow-up', 'Acknowledged', 'Time to ack (s)' ) as $th ) {
			$html .= '<th>' . esc_html( $th ) . '</th>';
		}
		$html .= '</tr></thead><tbody>';
		foreach ( array_reverse( $history ) as $run ) {
			$run = self::sanitize_run( $run );
			if ( null === $run ) {
				continue;
			}
			$html .= '<tr>';
			$html .= '<td>' . esc_html( gmdate( 'Y-m-d H:i', (int) $run['ts'] ) ) . '</td>';
			$html .= '<td>' . esc_html( (string) $run['scenario_label'] ) . '</td>';
			$html .= '<td>' . esc_html( (string) $run['trigger'] ) . '</td>';
			$html .= '<td>' . esc_html( (string) (int) $run['dead_end_count'] ) . '</td>';
			$html .= '<td>' . esc_html( ! empty( $run['alert_sent'] ) ? 'yes' : 'no' ) . '</td>';
			$html .= '<td>' . esc_html( ! empty( $run['followup_sent'] ) ? 'yes' : 'no' ) . '</td>';
			$html .= '<td>' . esc_html( (int) $run['ack_ts'] > 0 ? 'yes' : 'no' ) . '</td>';
			$html .= '<td>' . esc_html( (int) $run['ack_ts'] > 0 ? (string) (int) $run['time_to_ack_seconds'] : '—' ) . '</td>';
			$html .= '</tr>';
		}
		$html .= '</tbody></table></body></html>';

		return $html;
	}

	/* ------------------------------------------------------------------ */
	/* Admin UI                                                           */
	/* ------------------------------------------------------------------ */

	public static function admin_url(): string {
		if ( ! function_exists( 'admin_url' ) ) {
			return '';
		}

		return (string) add_query_arg( 'page', self::PAGE_SLUG, admin_url( 'admin.php' ) );
	}

	public static function register_menu(): void {
		if ( ! Caps::user_can_view() ) {
			return;
		}
		if ( ! function_exists( 'add_submenu_page' ) ) {
			return;
		}
		$parent = class_exists( Admin::class, false ) ? Admin::MENU_SLUG : 'handl-aicac';
		add_submenu_page(
			$parent,
			__( 'Incident drill', 'handl-ai-connector-access-control' ),
			__( 'Drill', 'handl-ai-connector-access-control' ),
			Caps::VIEW,
			self::PAGE_SLUG,
			array( self::class, 'render_page' )
		);
	}

	/**
	 * @param array<string,mixed> $run Run.
	 */
	private static function render_scorecard( array $run ): void {
		$reasons = self::reason_labels();
		echo '<table class="widefat striped"><thead><tr>';
		echo '<th>' . esc_html__( 'Control', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Result', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Reason', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Fix', 'handl-ai-connector-access-control' ) . '</th>';
		echo '</tr></thead><tbody>';
		foreach ( (array) ( $run['scorecard'] ?? array() ) as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$fires  = self::STATUS_FIRE === ( $row['status'] ?? '' );
			$reason = (string) ( $row['reason'] ?? '' );
			$link   = (string) ( $row['deep_link'] ?? '' );
			echo '<tr>';
			echo '<td>' . esc_html( (string) ( $row['label'] ?? '' ) ) . '</td>';
			echo '<td>' . esc_html( $fires ? __( 'Would fire', 'handl-ai-connector-access-control' ) : __( 'Dead end', 'handl-ai-connector-access-control' ) ) . '</td>';
			echo '<td>' . esc_html( $reasons[ $reason ] ?? $reason ) . '</td>';
			if ( '' !== $link ) {
				echo '<td><a href="' . esc_url( $link ) . '">' . esc_html__( 'Open screen', 'handl-ai-connector-access-control' ) . '</a></td>';
			} else {
				echo '<td>—</td>';
			}
			echo '</tr>';
		}
		echo '</tbody></table>';
	}

	public static function render_page(): void {
		if ( ! Caps::user_can_view() ) {
			return;
		}
		$settings   = self::get_settings();
		$can_manage = Caps::user_can_manage();
		$enabled    = self::is_enabled();
		$history    = $enabled ? self::get_history() : array();
		$latest     = empty( $history ) ? null : $history[ count( $history ) - 1 ];
		$scenarios  = self::scenarios();
		$csv        = add_query_arg(
			array(
				'page'                  => self::PAGE_SLUG,
				'handl_aicac_drill_csv' => '1',
				'_wpnonce'              => function_exists( 'wp_create_nonce' ) ? wp_create_nonce( 'handl_aicac_drill_csv' ) : '',
			),
			admin_url( 'admin.php' )
		);
		$print      = add_query_arg(
			array(
				'page'                    => self::PAGE_SLUG,
				'handl_aicac_drill_print' => '1',
				'_wpnonce'                => function_exists( 'wp_create_nonce' ) ? wp_create_nonce( 'handl_aicac_drill_print' ) : '',
			),
			admin_url( 'admin.php' )
		);

		echo '<div class="wrap">';
		echo '<h1>' . esc_html__( 'Incident drill', 'handl-ai-connector-access-control' ) . '</h1>';
		echo '<p class="description">' . esc_html__( 'Rehearse the alert path without a real incident. A drill is a SIMULATION: it reports which protections would fire and which are dead ends, sends one clearly-labelled [DRILL] alert, and never changes rules or writes the activity log. Off by default.', 'handl-ai-connector-access-control' ) . '</p>';

		if ( $can_manage ) {
			$action = admin_url( 'admin-post.php' );
			echo '<form method="post" action="' . esc_url( $action ) . '">';
			echo '<input type="hidden" name="action" value="' . esc_attr( self::ACTION_SAVE ) . '" />';
			if ( function_exists( 'wp_nonce_field' ) ) {
				wp_nonce_field( self::ACTION_SAVE );
			}
			echo '<input type="hidden" name="' . esc_attr( self::POST_PRESENT ) . '" value="1" />';
			echo '<table class="form-table" role="presentation"><tbody>';
			echo '<tr><th scope="row">' . esc_html__( 'Enable incident drills', 'handl-ai-connector-access-control' ) . '</th><td>';
			echo '<label><input type="checkbox" name="' . esc_attr( self::POST_ENABLED ) . '" value="1" ' . checked( ! empty( $settings['enabled'] ), true, false ) . ' /> ';
			echo esc_html__( 'Allow drills and follow-up reminders', 'handl-ai-connector-access-control' );
			echo '</label></td></tr>';
			echo '<tr><th scope="row">' . esc_html__( 'Monthly drill', 'handl-ai-connector-access-control' ) . '</th><td>';
			echo '<label><input type="checkbox" name="' . esc_attr( self::POST_SCHEDULE ) . '" value="1" ' . checked( ! empty( $settings['schedule_enabled'] ), true, false ) . ' /> ';
			echo esc_html__( 'Run the default scenario once per calendar month (only while drills are enabled)', 'handl-ai-connector-access-control' );
			echo '</label></td></tr>';
			echo '<tr><th scope="row"><label for="handl-aicac-drill-window">' . esc_html__( 'Acknowledgement window (hours)', 'handl-ai-connector-access-control' ) . '</label></th><td>';
			echo '<input name="' . esc_attr( self::POST_WINDOW ) . '" id="handl-aicac-drill-window" type="number" min="1" max="720" step="1" value="' . esc_attr( (string) (int) $settings['ack_window_hours'] ) . '" class="small-text" />';
			echo '<p class="description">' . esc_html__( 'If nobody acknowledges a drill within this window, exactly one [DRILL] follow-up is sent. Default 72.', 'handl-ai-connector-access-control' ) . '</p>';
			echo '</td></tr>';
			echo '<tr><th scope="row"><label for="handl-aicac-drill-scenario">' . esc_html__( 'Default scenario', 'handl-ai-connector-access-control' ) . '</label></th><td>';
			echo '<select name="' . esc_attr( self::POST_SCENARIO ) . '" id="handl-aicac-drill-scenario">';
			foreach ( $scenarios as $id => $scenario ) {
				echo '<option value="' . esc_attr( (string) $id ) . '" ' . selected( (string) $settings['default_scenario'], (string) $id, false ) . '>' . esc_html( (string) $scenario['label'] ) . '</option>';
			}
			echo '</select>';
			echo '</td></tr></tbody></table>';
			submit_button( __( 'Save drill settings', 'handl-ai-connector-access-control' ) );
			echo '</form>';
		}

		if ( ! $enabled ) {
			echo '<p>' . esc_html__( 'Incident drills are off. Enable them to run a simulated incident and get a scorecard.', 'handl-ai-connector-access-control' ) . '</p>';
			echo '</div>';

			return;
		}

		if ( $can_manage ) {
			echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
			echo '<input type="hidden" name="action" value="' . esc_attr( self::ACTION_RUN ) . '" />';
			if ( function_exists( 'wp_nonce_field' ) ) {
				wp_nonce_field( self::ACTION_RUN );
			}
			echo '<select name="' . esc_attr( self::POST_RUN_SCENARIO ) . '" aria-label="' . esc_attr__( 'Scenario', 'handl-ai-connector-access-control' ) . '">';
			foreach ( $scenarios as $id => $scenario ) {
				echo '<option value="' . esc_attr( (string) $id ) . '" ' . selected( (string) $settings['default_scenario'], (string) $id, false ) . '>' . esc_html( (string) $scenario['label'] ) . '</option>';
			}
			echo '</select> ';
			submit_button( __( 'Run drill', 'handl-ai-connector-access-control' ), 'secondary', 'submit', false );
			echo '</form>';
		}

		echo '<h2>' . esc_html__( 'Latest scorecard', 'handl-ai-connector-access-control' ) . '</h2>';
		if ( null === $latest ) {
			echo '<p>' . esc_html__( 'No drills yet. Run one to see which protections would fire.', 'handl-ai-connector-access-control' ) . '</p>';
		} else {
			echo '<p>' . esc_html(
				sprintf(
					/* translators: 1: scenario label, 2: UTC time, 3: dead-end count */
					__( '%1$s — %2$s UTC — %3$d dead end(s). SIMULATION.', 'handl-ai-connector-access-control' ),
					(string) $latest['scenario_label'],
					gmdate( 'Y-m-d H:i', (int) $latest['ts'] ),
					(int) $latest['dead_end_count']
				)
			) . '</p>';
			self::render_scorecard( $latest );
		}

		echo '<p>';
		echo '<a class="button" href="' . esc_url( $csv ) . '">' . esc_html__( 'Download CSV', 'handl-ai-connector-access-control' ) . '</a> ';
		echo '<a class="button" href="' . esc_url( $print ) . '" target="_blank" rel="noopener noreferrer">' . esc_html__( 'Print / PDF view', 'handl-ai-connector-access-control' ) . '</a>';
		echo '</p>';

		echo '<h2>' . esc_html__( 'Drill history', 'handl-ai-connector-access-control' ) . '</h2>';
		if ( empty( $history ) ) {
			echo '<p>' . esc_html__( 'No drills recorded.', 'handl-ai-connector-access-control' ) . '</p>';
		} else {
			echo '<table class="widefat striped"><thead><tr>';
			foreach ( array( 'When (UTC)', 'Scenario', 'Trigger', 'Dead ends', 'Acknowledged', 'Time to ack' ) as $th ) {
				echo '<th>' . esc_html( $th ) . '</th>';
			}
			echo '</tr></thead><tbody>';
			foreach ( array_reverse( $history ) as $run ) {
				$acked = (int) $run['ack_ts'] > 0;
				echo '<tr>';
				echo '<td>' . esc_html( gmdate( 'Y-m-d H:i', (int) $run['ts'] ) ) . '</td>';
				echo '<td>' . esc_html( (string) $run['scenario_label'] ) . '</td>';
				echo '<td>' . esc_html( (string) $run['trigger'] ) . '</td>';
				echo '<td>' . esc_html( (string) (int) $run['dead_end_count'] ) . '</td>';
				if ( $acked ) {
					echo '<td>' . esc_html__( 'Yes', 'handl-ai-connector-access-control' ) . '</td>';
					echo '<td>' . esc_html( (string) (int) $run['time_to_ack_seconds'] ) . 's</td>';
				} else {
					$ack_link = add_query_arg(
						array(
							'page'          => self::PAGE_SLUG,
							self::QUERY_ACK => (string) $run['id'],
							'token'         => (string) $run['ack_nonce'],
						),
						admin_url( 'admin.php' )
					);
					echo '<td><a href="' . esc_url( $ack_link ) . '">' . esc_html__( 'Acknowledge', 'handl-ai-connector-access-control' ) . '</a></td>';
					echo '<td>—</td>';
				}
				echo '</tr>';
			}
			echo '</tbody></table>';
		}

		echo '</div>';
	}

	public static function maybe_handle_csv(): void {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( empty( $_GET['handl_aicac_drill_csv'] ) ) {
			return;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$page = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( (string) $_GET['page'] ) ) : '';
		if ( self::PAGE_SLUG !== $page ) {
			return;
		}
		if ( ! Caps::user_can_view() || ! self::is_enabled() ) {
			return;
		}
		check_admin_referer( 'handl_aicac_drill_csv' );
		$csv = self::csv_for_history();
		if ( function_exists( 'nocache_headers' ) ) {
			nocache_headers();
		}
		if ( ! headers_sent() ) {
			header( 'Content-Type: text/csv; charset=utf-8' );
			header( 'Content-Disposition: attachment; filename=handl-aicac-drill.csv' );
		}
		echo $csv; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- CSV download.
		exit;
	}

	public static function maybe_handle_print(): void {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( empty( $_GET['handl_aicac_drill_print'] ) ) {
			return;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$page = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( (string) $_GET['page'] ) ) : '';
		if ( self::PAGE_SLUG !== $page ) {
			return;
		}
		if ( ! Caps::user_can_view() || ! self::is_enabled() ) {
			return;
		}
		check_admin_referer( 'handl_aicac_drill_print' );
		if ( function_exists( 'nocache_headers' ) ) {
			nocache_headers();
		}
		if ( ! headers_sent() ) {
			header( 'Content-Type: text/html; charset=utf-8' );
		}
		echo self::build_print_html( self::get_history() ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped inside builder.
		exit;
	}

	/**
	 * In-page acknowledge link (admin_init, drill screen only).
	 */
	public static function maybe_handle_ack(): void {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( empty( $_GET[ self::QUERY_ACK ] ) ) {
			return;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$page = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( (string) $_GET['page'] ) ) : '';
		if ( self::PAGE_SLUG !== $page ) {
			return;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$run = wp_unslash( (string) $_GET[ self::QUERY_ACK ] );
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$token = isset( $_GET['token'] ) ? wp_unslash( (string) $_GET['token'] ) : '';
		self::process_ack_request( $run, $token );
	}

	/**
	 * admin-post.php acknowledge link from the alert email.
	 */
	public static function handle_ack(): void {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$run = isset( $_GET['run'] ) ? wp_unslash( (string) $_GET['run'] ) : '';
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$token = isset( $_GET['token'] ) ? wp_unslash( (string) $_GET['token'] ) : '';
		self::process_ack_request( $run, $token );
	}

	private static function process_ack_request( string $run, string $token ): void {
		if ( ! Caps::user_can_view() ) {
			wp_die( esc_html__( 'You do not have permission to acknowledge drills.', 'handl-ai-connector-access-control' ) );
		}
		$ok       = self::acknowledge( $run, $token, function_exists( 'get_current_user_id' ) ? (int) get_current_user_id() : 0 );
		$redirect = add_query_arg(
			array(
				'page'      => self::PAGE_SLUG,
				'drill_ack' => $ok ? '1' : '0',
			),
			admin_url( 'admin.php' )
		);
		if ( function_exists( 'wp_safe_redirect' ) ) {
			wp_safe_redirect( $redirect );
			exit;
		}
	}

	public static function handle_save(): void {
		if ( ! Caps::user_can_manage() ) {
			wp_die( esc_html__( 'You do not have permission to save drill settings.', 'handl-ai-connector-access-control' ) );
		}
		check_admin_referer( self::ACTION_SAVE );
		if ( empty( $_POST[ self::POST_PRESENT ] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing
			wp_die( esc_html__( 'Invalid form', 'handl-ai-connector-access-control' ) );
		}
		// phpcs:disable WordPress.Security.NonceVerification.Missing
		$window_raw   = isset( $_POST[ self::POST_WINDOW ] ) ? wp_unslash( (string) $_POST[ self::POST_WINDOW ] ) : '';
		$scenario_raw = isset( $_POST[ self::POST_SCENARIO ] ) ? wp_unslash( (string) $_POST[ self::POST_SCENARIO ] ) : '';
		self::save_settings(
			array(
				'enabled'          => ! empty( $_POST[ self::POST_ENABLED ] ),
				'schedule_enabled' => ! empty( $_POST[ self::POST_SCHEDULE ] ),
				'ack_window_hours' => self::sanitize_ack_window_hours( '' !== $window_raw ? $window_raw : self::DEFAULT_ACK_WINDOW_HOURS ),
				'default_scenario' => self::sanitize_scenario_id( $scenario_raw ),
			)
		);
		// phpcs:enable WordPress.Security.NonceVerification.Missing
		self::maybe_schedule();
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

	public static function handle_run(): void {
		if ( ! Caps::user_can_manage() ) {
			wp_die( esc_html__( 'You do not have permission to run drills.', 'handl-ai-connector-access-control' ) );
		}
		check_admin_referer( self::ACTION_RUN );
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		$scenario = isset( $_POST[ self::POST_RUN_SCENARIO ] ) ? sanitize_key( wp_unslash( (string) $_POST[ self::POST_RUN_SCENARIO ] ) ) : '';
		$run      = self::run( $scenario );
		$redirect = add_query_arg(
			array(
				'page'      => self::PAGE_SLUG,
				'drill_run' => empty( $run ) ? '0' : '1',
			),
			admin_url( 'admin.php' )
		);
		if ( function_exists( 'wp_safe_redirect' ) ) {
			wp_safe_redirect( $redirect );
			exit;
		}
	}

	public static function register_cli(): void {
		if ( ! defined( 'WP_CLI' ) || ! WP_CLI ) {
			return;
		}
		if ( ! class_exists( '\WP_CLI' ) ) {
			return;
		}
		\WP_CLI::add_command( 'aicac drill', CLI_Drill::class );
	}
}

/**
 * WP-CLI: wp aicac drill run|status|export
 */
final class CLI_Drill {

	/**
	 * Run an incident drill (a SIMULATION; sends one [DRILL] alert).
	 *
	 * ## OPTIONS
	 *
	 * [--scenario=<id>]
	 * : Scenario id (default: the configured default scenario).
	 *
	 * @when after_wp_load
	 *
	 * @param array<int,string>    $args       Positional.
	 * @param array<string,string> $assoc_args Flags.
	 */
	public function run( $args, $assoc_args ): void {
		unset( $args );
		if ( ! Drill::is_enabled() ) {
			\WP_CLI::error( 'Incident drills are disabled.' );
			return;
		}
		$scenario = isset( $assoc_args['scenario'] ) ? sanitize_key( (string) $assoc_args['scenario'] ) : '';
		if ( '' !== $scenario && ! isset( Drill::scenarios()[ $scenario ] ) ) {
			\WP_CLI::error( 'Unknown scenario: ' . $scenario . '. Known: ' . implode( ', ', array_keys( Drill::scenarios() ) ) );
			return;
		}
		$run = Drill::run( $scenario );
		if ( empty( $run ) ) {
			\WP_CLI::error( 'Drill did not run.' );
			return;
		}
		\WP_CLI::log(
			sprintf(
				'run=%s scenario=%s dead_ends=%d alert_sent=%s simulation=yes',
				(string) $run['id'],
				(string) $run['scenario'],
				(int) $run['dead_end_count'],
				! empty( $run['alert_sent'] ) ? 'yes' : 'no'
			)
		);
		foreach ( (array) $run['scorecard'] as $row ) {
			\WP_CLI::log( sprintf( '%s %s %s', (string) $row['control'], (string) $row['status'], (string) $row['reason'] ) );
		}
		\WP_CLI::success( 'Drill complete (simulation).' );
	}

	/**
	 * Show the latest drill status. Non-zero when it has dead ends or an expired unacknowledged run.
	 *
	 * ## OPTIONS
	 *
	 * [--format=<format>]
	 * : table or json. Default table.
	 *
	 * @when after_wp_load
	 *
	 * @param array<int,string>    $args       Positional.
	 * @param array<string,string> $assoc_args Flags.
	 */
	public function status( $args, $assoc_args ): void {
		unset( $args );
		$settings = Drill::get_settings();
		if ( empty( $settings['enabled'] ) ) {
			\WP_CLI::log( 'enabled=no' );
			\WP_CLI::log( 'Incident drills are disabled.' );
			return;
		}
		$latest = Drill::latest_run();
		if ( null === $latest ) {
			\WP_CLI::log( 'enabled=yes runs=0' );
			\WP_CLI::log( 'No drills recorded yet.' );
			return;
		}
		$format  = isset( $assoc_args['format'] ) ? (string) $assoc_args['format'] : 'table';
		$expired = Drill::is_ack_expired( $latest );
		$failure = Drill::has_status_failure( $latest );
		\WP_CLI::log(
			sprintf(
				'enabled=yes run=%s scenario=%s dead_ends=%d acknowledged=%s ack_expired=%s',
				(string) $latest['id'],
				(string) $latest['scenario'],
				(int) $latest['dead_end_count'],
				(int) $latest['ack_ts'] > 0 ? 'yes' : 'no',
				$expired ? 'yes' : 'no'
			)
		);

		$display = array();
		foreach ( (array) $latest['scorecard'] as $row ) {
			$display[] = array(
				'control' => (string) $row['control'],
				'status'  => (string) $row['status'],
				'reason'  => (string) $row['reason'],
			);
		}
		if ( 'json' === $format ) {
			\WP_CLI::print_value( $display, array( 'format' => 'json' ) );
		} elseif ( class_exists( '\WP_CLI\Utils' ) ) {
			\WP_CLI\Utils\format_items( 'table', $display, array( 'control', 'status', 'reason' ) );
		} else {
			foreach ( $display as $row ) {
				\WP_CLI::log( implode( "\t", $row ) );
			}
		}

		if ( $failure ) {
			\WP_CLI::error( 'Latest drill has dead ends or an expired unacknowledged run.', false );
			if ( method_exists( '\WP_CLI', 'halt' ) ) {
				\WP_CLI::halt( 1 );
			}
		}
	}

	/**
	 * Export drill history as CSV.
	 *
	 * ## OPTIONS
	 *
	 * [--porcelain]
	 * : Print CSV only.
	 *
	 * @when after_wp_load
	 *
	 * @param array<int,string>    $args       Positional.
	 * @param array<string,string> $assoc_args Flags.
	 */
	public function export( $args, $assoc_args ): void {
		unset( $args );
		$csv = Drill::csv_for_history();
		if ( ! empty( $assoc_args['porcelain'] ) ) {
			echo $csv; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- CLI CSV.
			return;
		}
		\WP_CLI::print_value( $csv, array( 'format' => 'csv' ) );
	}
}
