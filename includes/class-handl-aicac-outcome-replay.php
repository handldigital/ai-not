<?php
/**
 * AICAC-OUTCOME-REPLAY (#347): after updates, replay recent calls and alert only on flips.
 *
 * Observability only — never mutates allow/deny. Evaluation reuses Policy::evaluate()
 * (same path as the policy simulator). No outbound HTTP during replay.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Deferred post-update outcome diff against handl_aicac_recent_calls.
 */
final class Outcome_Replay {

	public const CRON_HOOK = 'handl_aicac_outcome_replay';

	public const PENDING_OPTION = 'handl_aicac_outcome_replay_pending';

	public const NOTICE_OPTION = 'handl_aicac_outcome_replay_notice';

	public const VERSIONS_OPTION = 'handl_aicac_outcome_replay_versions';

	public const SCAN_TRANSIENT_KEY = 'handl_aicac_outcome_replay_scanned';

	public const SCAN_INTERVAL = 300;

	public const ALERT_KIND = 'outcome_replay';

	public const REPLAY_CAP = 200;

	public const ACTION_DISMISS = 'handl_aicac_outcome_replay_dismiss';

	/** @var bool */
	private static $registered = false;

	public static function init(): void {
		if ( self::$registered ) {
			return;
		}
		self::$registered = true;

		add_action( 'upgrader_process_complete', array( self::class, 'on_upgrader_process_complete' ), 20, 2 );
		add_action( self::CRON_HOOK, array( self::class, 'cron_run' ) );
		add_action( 'init', array( self::class, 'lazy_version_scan' ), 35 );
		add_action( 'admin_post_' . self::ACTION_DISMISS, array( self::class, 'handle_dismiss' ) );
		if ( is_admin() ) {
			add_action( 'admin_notices', array( self::class, 'maybe_render_notice' ) );
		}
	}

	public static function reset_for_tests(): void {
		self::$registered = false;
		delete_option( self::PENDING_OPTION );
		delete_option( self::NOTICE_OPTION );
		delete_option( self::VERSIONS_OPTION );
		delete_transient( self::SCAN_TRANSIENT_KEY );
		if ( function_exists( 'wp_clear_scheduled_hook' ) ) {
			wp_clear_scheduled_hook( self::CRON_HOOK );
		}
	}

	/**
	 * Plugin basename for this plugin (AICAC self-update → replay all).
	 */
	public static function aicac_basename(): string {
		if ( ! defined( 'HANDL_AICAC_FILE' ) ) {
			return 'handl-ai-connector-access-control/handl-ai-connector-access-control.php';
		}
		if ( function_exists( 'plugin_basename' ) ) {
			return Plugin_Profile::sanitize_plugin( plugin_basename( HANDL_AICAC_FILE ) );
		}

		return Plugin_Profile::sanitize_plugin( basename( dirname( HANDL_AICAC_FILE ) ) . '/' . basename( HANDL_AICAC_FILE ) );
	}

	/**
	 * @param WP_Upgrader|mixed         $upgrader Unused.
	 * @param array<string,mixed>|mixed $options
	 */
	public static function on_upgrader_process_complete( $upgrader, $options ): void {
		unset( $upgrader );
		if ( ! is_array( $options ) ) {
			return;
		}

		$scope = self::parse_update_scope( $options );
		if ( null === $scope ) {
			return;
		}

		self::schedule_replay( $scope['scope'], $scope['plugins'], $scope['trigger'] );
	}

	/**
	 * @param array<string,mixed> $options Upgrader options.
	 * @return array{scope:string,plugins:list<string>,trigger:string}|null
	 */
	public static function parse_update_scope( array $options ): ?array {
		$type = isset( $options['type'] ) ? (string) $options['type'] : '';

		if ( 'core' === $type || 'theme' === $type ) {
			return array(
				'scope'   => 'all',
				'plugins' => array(),
				'trigger' => $type,
			);
		}

		if ( 'plugin' !== $type ) {
			return null;
		}

		$plugins = array();
		if ( ! empty( $options['bulk'] ) && isset( $options['plugins'] ) && is_array( $options['plugins'] ) ) {
			foreach ( $options['plugins'] as $file ) {
				$file = Plugin_Profile::sanitize_plugin( (string) $file );
				if ( '' !== $file ) {
					$plugins[] = $file;
				}
			}
		} elseif ( isset( $options['plugin'] ) ) {
			$file = Plugin_Profile::sanitize_plugin( (string) $options['plugin'] );
			if ( '' !== $file ) {
				$plugins[] = $file;
			}
		}

		$plugins = array_values( array_unique( $plugins ) );
		if ( empty( $plugins ) ) {
			return null;
		}

		$aicac = self::aicac_basename();
		if ( '' !== $aicac && in_array( $aicac, $plugins, true ) ) {
			return array(
				'scope'   => 'all',
				'plugins' => array(),
				'trigger' => 'aicac',
			);
		}

		return array(
			'scope'   => 'plugins',
			'plugins' => $plugins,
			'trigger' => 'plugin',
		);
	}

	/**
	 * @param 'all'|'plugins' $scope
	 * @param list<string>    $plugins
	 */
	public static function schedule_replay( string $scope, array $plugins = array(), string $trigger = 'manual' ): void {
		$scope = 'all' === $scope ? 'all' : 'plugins';
		$clean = array();
		foreach ( $plugins as $plugin ) {
			$plugin = Plugin_Profile::sanitize_plugin( (string) $plugin );
			if ( '' !== $plugin ) {
				$clean[] = $plugin;
			}
		}
		$clean = array_values( array_unique( $clean ) );
		if ( 'plugins' === $scope && empty( $clean ) ) {
			return;
		}

		$pending = self::get_pending();
		$pending[] = array(
			'scope'   => $scope,
			'plugins' => $clean,
			'trigger' => sanitize_key( $trigger ),
			'queued'  => time(),
		);
		// Cap pending queue so a broken cron cannot grow forever.
		if ( count( $pending ) > 20 ) {
			$pending = array_slice( $pending, -20 );
		}
		update_option( self::PENDING_OPTION, $pending, false );

		if ( function_exists( 'wp_next_scheduled' ) && ! wp_next_scheduled( self::CRON_HOOK ) ) {
			if ( function_exists( 'wp_schedule_single_event' ) ) {
				wp_schedule_single_event( time() + 1, self::CRON_HOOK );
			}
		}
	}

	/**
	 * @return list<array{scope:string,plugins:list<string>,trigger:string,queued:int}>
	 */
	public static function get_pending(): array {
		$raw = get_option( self::PENDING_OPTION, array() );
		if ( ! is_array( $raw ) ) {
			return array();
		}
		$out = array();
		foreach ( $raw as $job ) {
			if ( ! is_array( $job ) ) {
				continue;
			}
			$scope = isset( $job['scope'] ) && 'all' === $job['scope'] ? 'all' : 'plugins';
			$plugins = array();
			if ( isset( $job['plugins'] ) && is_array( $job['plugins'] ) ) {
				foreach ( $job['plugins'] as $p ) {
					$p = Plugin_Profile::sanitize_plugin( (string) $p );
					if ( '' !== $p ) {
						$plugins[] = $p;
					}
				}
			}
			$out[] = array(
				'scope'   => $scope,
				'plugins' => array_values( array_unique( $plugins ) ),
				'trigger' => sanitize_key( (string) ( $job['trigger'] ?? '' ) ),
				'queued'  => isset( $job['queued'] ) ? (int) $job['queued'] : 0,
			);
		}

		return $out;
	}

	public static function cron_run(): void {
		try {
			self::run_pending();
		} catch ( \Throwable $e ) {
			unset( $e );
		}
	}

	/**
	 * Process coalesced pending jobs (fail-open).
	 *
	 * @return array{jobs:int,flips:int,alerted:bool,noticed:bool}
	 */
	public static function run_pending( ?array $policy = null, ?array $log = null, ?int $now = null ): array {
		$stats = array(
			'jobs'    => 0,
			'flips'   => 0,
			'alerted' => false,
			'noticed' => false,
		);
		$pending = self::get_pending();
		delete_option( self::PENDING_OPTION );
		if ( empty( $pending ) ) {
			return $stats;
		}

		$policy = null !== $policy ? $policy : Policy::get_policy();
		$log    = null !== $log ? $log : self::load_log();
		$now    = null !== $now && $now > 0 ? $now : time();

		// Coalesce: any "all" wins; else union plugin filters.
		$scope_all = false;
		$plugins   = array();
		$trigger   = 'update';
		foreach ( $pending as $job ) {
			++$stats['jobs'];
			if ( 'all' === $job['scope'] ) {
				$scope_all = true;
			}
			foreach ( $job['plugins'] as $p ) {
				$plugins[] = $p;
			}
			if ( '' !== $job['trigger'] ) {
				$trigger = $job['trigger'];
			}
		}
		$plugins = array_values( array_unique( $plugins ) );
		$filter  = $scope_all ? null : $plugins;

		$result = self::replay( $policy, $log, $filter, self::REPLAY_CAP, $now );
		$stats['flips'] = count( $result['flips'] );

		if ( empty( $result['flips'] ) ) {
			return $stats;
		}

		$stats['alerted'] = self::maybe_alert( $result['flips'], $policy, $trigger, $now );
		$stats['noticed'] = self::store_notice( $result['flips'], $trigger, $now );

		return $stats;
	}

	/**
	 * @return list<array<string,mixed>>
	 */
	public static function load_log(): array {
		$log = get_option( Plugin::LOG_OPTION_KEY, array() );
		return is_array( $log ) ? $log : array();
	}

	/**
	 * Replay recent governable calls; return only verdict / gate-class flips.
	 *
	 * @param array<string,mixed>      $policy
	 * @param array<int,mixed>         $log
	 * @param list<string>|null        $plugin_filter null = all plugins
	 * @return array{scanned:int,flips:list<array<string,mixed>>,http_calls:int}
	 */
	public static function replay(
		array $policy,
		array $log,
		?array $plugin_filter = null,
		int $cap = self::REPLAY_CAP,
		?int $now = null
	): array {
		$now = null !== $now && $now > 0 ? $now : time();
		$cap = max( 1, min( 500, (int) $cap ) );

		$filter_map = null;
		if ( null !== $plugin_filter ) {
			$filter_map = array();
			foreach ( $plugin_filter as $p ) {
				$p = Plugin_Profile::sanitize_plugin( (string) $p );
				if ( '' !== $p ) {
					$filter_map[ $p ] = true;
				}
			}
			if ( empty( $filter_map ) ) {
				return array(
					'scanned'    => 0,
					'flips'      => array(),
					'http_calls' => 0,
				);
			}
		}

		$per_plugin = array();
		$flips      = array();
		$scanned    = 0;
		$http_calls = 0;

		// Newest first.
		for ( $i = count( $log ) - 1; $i >= 0; $i-- ) {
			$row = $log[ $i ];
			if ( ! is_array( $row ) ) {
				continue;
			}
			if ( self::row_is_ungovernable( $row ) ) {
				continue;
			}

			$plugin = self::row_plugin( $row );
			if ( '' === $plugin ) {
				continue;
			}
			if ( null !== $filter_map && ! isset( $filter_map[ $plugin ] ) ) {
				continue;
			}

			$count = $per_plugin[ $plugin ] ?? 0;
			if ( $count >= $cap ) {
				continue;
			}
			$per_plugin[ $plugin ] = $count + 1;
			++$scanned;

			$recorded = self::recorded_verdict( $row );
			if ( null === $recorded ) {
				continue;
			}

			$operation = self::row_operation( $row );
			$family    = self::row_family( $row, $operation );
			$armed     = self::row_armed_tools( $row );

			// Trap: replay must not issue HTTP. Counters only; Policy::evaluate is local.
			$before_http = self::http_counter();
			$eval        = Policy_Simulator::evaluate_call(
				$policy,
				$plugin,
				'' !== $operation ? $operation : null,
				$armed,
				$family
			);
			$http_calls += max( 0, self::http_counter() - $before_http );

			$fresh_deny = ! empty( $eval['prevent'] );
			$fresh      = $fresh_deny ? 'deny' : 'allow';
			$fresh_cls  = self::gate_class( (string) ( $eval['reason'] ?? '' ) );
			$old_cls    = self::gate_class(
				(string) ( $row['decision_source'] ?? $row['reason'] ?? '' )
			);

			$kind = '';
			if ( $recorded !== $fresh ) {
				$kind = $recorded . '_to_' . $fresh;
			} elseif ( '' !== $old_cls && '' !== $fresh_cls && $old_cls !== $fresh_cls ) {
				$kind = 'class_change';
			}

			if ( '' === $kind ) {
				continue;
			}

			if ( Alert_Snooze::should_suppress( $plugin, self::ALERT_KIND, $now ) ) {
				continue;
			}

			$flips[] = array(
				'plugin'     => $plugin,
				'operation'  => $operation,
				'provider'   => isset( $row['provider'] ) ? (string) $row['provider'] : '',
				'model'      => isset( $row['model'] ) ? (string) $row['model'] : '',
				'old'        => $recorded,
				'new'        => $fresh,
				'old_class'  => $old_cls,
				'new_class'  => $fresh_cls,
				'new_reason' => (string) ( $eval['reason'] ?? '' ),
				'kind'       => $kind,
			);
		}

		return array(
			'scanned'    => $scanned,
			'flips'      => $flips,
			'http_calls' => $http_calls,
		);
	}

	/**
	 * @param list<array<string,mixed>> $flips
	 * @param array<string,mixed>       $policy
	 */
	public static function maybe_alert( array $flips, array $policy, string $trigger, int $now ): bool {
		if ( empty( $flips ) ) {
			return false;
		}

		// Unknown type falls back to alert_email / admin_email (no Alert_Routing edit).
		$to = Alert_Routing::resolve_email( $policy, 'outcome_replay' );
		if ( '' === $to ) {
			return false;
		}

		$subject = self::build_subject( $flips, $trigger );
		$body    = self::build_body( $flips, $trigger );
		$ok      = Alerts::safe_wp_mail( $to, $subject, $body );

		$hook_url = Alerts::resolve_webhook( $policy );
		if ( '' !== $hook_url ) {
			Alerts::safe_wp_remote_post(
				$hook_url,
				array(
					'type'    => 'handl_aicac_outcome_replay_alert',
					'trigger' => $trigger,
					'flips'   => array_slice( $flips, 0, 25 ),
					'count'   => count( $flips ),
					'site'    => function_exists( 'home_url' ) ? home_url( '/' ) : '',
				)
			);
		}

		if ( ! $ok ) {
			return false;
		}

		Policy::append_log_event(
			array(
				'ts'       => $now,
				'decision' => 'outcome_replay_alert',
				'channel'  => 'outcome_replay',
				'trigger'  => $trigger,
				'flips'    => count( $flips ),
			)
		);

		return true;
	}

	/**
	 * @param list<array<string,mixed>> $flips
	 */
	public static function store_notice( array $flips, string $trigger, int $now ): bool {
		if ( empty( $flips ) ) {
			return false;
		}
		update_option(
			self::NOTICE_OPTION,
			array(
				'ts'      => $now,
				'trigger' => sanitize_key( $trigger ),
				'flips'   => array_slice( $flips, 0, 25 ),
				'count'   => count( $flips ),
			),
			false
		);

		return true;
	}

	public static function handle_dismiss(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Sorry, you are not allowed to do that.', 'handl-ai-connector-access-control' ) );
		}
		check_admin_referer( self::ACTION_DISMISS );
		delete_option( self::NOTICE_OPTION );
		$redirect = wp_get_referer();
		if ( ! is_string( $redirect ) || '' === $redirect ) {
			$redirect = Admin::screen_url( 'rules' );
		}
		wp_safe_redirect( $redirect );
		exit;
	}

	public static function maybe_render_notice(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$notice = get_option( self::NOTICE_OPTION, null );
		if ( ! is_array( $notice ) || empty( $notice['flips'] ) || ! is_array( $notice['flips'] ) ) {
			return;
		}

		$count = isset( $notice['count'] ) ? (int) $notice['count'] : count( $notice['flips'] );
		$dismiss = wp_nonce_url(
			admin_url( 'admin-post.php?action=' . self::ACTION_DISMISS ),
			self::ACTION_DISMISS
		);

		echo '<div class="notice notice-warning is-dismissible"><p>';
		echo esc_html(
			sprintf(
				/* translators: %d: number of verdict flips */
				_n(
					'HandL AI Connector: %d access outcome changed after a recent update.',
					'HandL AI Connector: %d access outcomes changed after a recent update.',
					$count,
					'handl-ai-connector-access-control'
				),
				$count
			)
		);
		echo '</p><ul style="list-style:disc;margin-left:1.5em;">';
		$shown = 0;
		foreach ( $notice['flips'] as $flip ) {
			if ( ! is_array( $flip ) || $shown >= 8 ) {
				break;
			}
			$plugin = Plugin_Profile::sanitize_plugin( (string) ( $flip['plugin'] ?? '' ) );
			$old    = sanitize_key( (string) ( $flip['old'] ?? '' ) );
			$new    = sanitize_key( (string) ( $flip['new'] ?? '' ) );
			$label  = self::plugin_label( $plugin );
			$url    = Plugin_Profile::rules_url( $plugin );
			echo '<li>';
			echo esc_html(
				sprintf(
					/* translators: 1: plugin name, 2: old verdict, 3: new verdict */
					__( '%1$s: %2$s → %3$s', 'handl-ai-connector-access-control' ),
					$label,
					$old,
					$new
				)
			);
			echo ' — <a href="' . esc_url( $url ) . '">' . esc_html__( 'Review rules', 'handl-ai-connector-access-control' ) . '</a>';
			echo '</li>';
			++$shown;
		}
		echo '</ul><p><a href="' . esc_url( $dismiss ) . '">' . esc_html__( 'Dismiss', 'handl-ai-connector-access-control' ) . '</a></p></div>';
	}

	/**
	 * Missed upgrader hooks / CLI updates: compare stored versions, schedule scoped replay.
	 */
	public static function lazy_version_scan(): void {
		if ( get_transient( self::SCAN_TRANSIENT_KEY ) ) {
			return;
		}
		set_transient( self::SCAN_TRANSIENT_KEY, 1, self::SCAN_INTERVAL );

		if ( ! function_exists( 'get_plugins' ) ) {
			return;
		}
		if ( function_exists( 'wp_clean_plugins_cache' ) ) {
			wp_clean_plugins_cache( false );
		}

		$installed = get_plugins();
		$current   = array();
		foreach ( $installed as $basename => $meta ) {
			$basename = Plugin_Profile::sanitize_plugin( (string) $basename );
			if ( '' === $basename || ! is_array( $meta ) ) {
				continue;
			}
			$ver = isset( $meta['Version'] ) ? sanitize_text_field( (string) $meta['Version'] ) : '';
			if ( '' === $ver ) {
				continue;
			}
			$current[ $basename ] = $ver;
		}

		$previous = get_option( self::VERSIONS_OPTION, array() );
		if ( ! is_array( $previous ) || empty( $previous ) ) {
			update_option( self::VERSIONS_OPTION, $current, false );
			return;
		}

		$changed = array();
		foreach ( $current as $basename => $ver ) {
			if ( ! isset( $previous[ $basename ] ) || (string) $previous[ $basename ] !== $ver ) {
				$changed[] = $basename;
			}
		}

		update_option( self::VERSIONS_OPTION, $current, false );

		if ( empty( $changed ) ) {
			return;
		}

		$aicac = self::aicac_basename();
		if ( '' !== $aicac && in_array( $aicac, $changed, true ) ) {
			self::schedule_replay( 'all', array(), 'version' );
			return;
		}

		self::schedule_replay( 'plugins', $changed, 'version' );
	}

	/**
	 * @param list<array<string,mixed>> $flips
	 */
	public static function build_subject( array $flips, string $trigger ): string {
		$site  = function_exists( 'get_bloginfo' )
			? wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES )
			: 'WordPress';
		$count = count( $flips );

		return sprintf(
			/* translators: 1: site name, 2: flip count */
			__( '[%1$s] HandL: %2$d AI access outcome(s) changed after an update', 'handl-ai-connector-access-control' ),
			$site,
			$count
		);
	}

	/**
	 * @param list<array<string,mixed>> $flips
	 */
	public static function build_body( array $flips, string $trigger ): string {
		$lines   = array();
		$lines[] = __( 'HandL AI Connector Access Control: post-update outcome replay', 'handl-ai-connector-access-control' );
		$lines[] = '';
		$lines[] = sprintf(
			/* translators: %s: update trigger label */
			__( 'Trigger: %s', 'handl-ai-connector-access-control' ),
			sanitize_key( $trigger )
		);
		$lines[] = sprintf(
			/* translators: %d: flip count */
			__( 'Verdict flips: %d', 'handl-ai-connector-access-control' ),
			count( $flips )
		);
		$lines[] = '';
		$lines[] = __( 'Only changes are listed. Your access rules were not modified by this check.', 'handl-ai-connector-access-control' );
		$lines[] = '';

		$i = 0;
		foreach ( $flips as $flip ) {
			if ( $i >= 25 ) {
				$lines[] = __( '…additional flips omitted.', 'handl-ai-connector-access-control' );
				break;
			}
			$plugin = Plugin_Profile::sanitize_plugin( (string) ( $flip['plugin'] ?? '' ) );
			$old    = (string) ( $flip['old'] ?? '' );
			$new    = (string) ( $flip['new'] ?? '' );
			$op     = (string) ( $flip['operation'] ?? '' );
			$prov   = (string) ( $flip['provider'] ?? '' );
			$lines[] = sprintf(
				'- %s%s%s: %s → %s',
				self::plugin_label( $plugin ),
				'' !== $op ? ' / ' . $op : '',
				'' !== $prov ? ' / ' . $prov : '',
				$old,
				$new
			);
			$lines[] = '  ' . Plugin_Profile::rules_url( $plugin );
			++$i;
		}

		return implode( "\n", $lines ) . "\n";
	}

	/**
	 * @param array<string,mixed> $row
	 */
	private static function row_is_ungovernable( array $row ): bool {
		$operation = self::row_operation( $row );
		$decision  = isset( $row['decision'] ) ? (string) $row['decision'] : '';
		if ( 'direct_http' === $operation || 'observe' === $decision ) {
			return true;
		}
		// Alert / system rows are not live call outcomes.
		if ( in_array( $decision, array( 'outcome_replay_alert', 'version_watch_alert', 'access_request', 'access_approved', 'access_denied' ), true ) ) {
			return true;
		}

		return false;
	}

	/**
	 * @param array<string,mixed> $row
	 * @return 'allow'|'deny'|null
	 */
	private static function recorded_verdict( array $row ): ?string {
		$decision = isset( $row['decision'] ) ? (string) $row['decision'] : '';
		if ( 'allow' === $decision || 'deny' === $decision ) {
			return $decision;
		}

		return null;
	}

	/**
	 * Normalize budget / rate_cap / user_quota style reasons into a gate class.
	 */
	public static function gate_class( string $reason ): string {
		$reason = strtolower( trim( $reason ) );
		if ( '' === $reason ) {
			return '';
		}
		if ( 0 === strpos( $reason, 'budget' ) ) {
			return 'budget';
		}
		if ( 0 === strpos( $reason, 'rate_cap' ) || 0 === strpos( $reason, 'rate-cap' ) ) {
			return 'rate_cap';
		}
		if ( 0 === strpos( $reason, 'user_quota' ) || 0 === strpos( $reason, 'user-quota' ) ) {
			return 'user_quota';
		}

		return '';
	}

	/**
	 * @param array<string,mixed> $row
	 */
	private static function row_plugin( array $row ): string {
		return Plugin_Profile::sanitize_plugin( isset( $row['plugin'] ) ? (string) $row['plugin'] : '' );
	}

	/**
	 * @param array<string,mixed> $row
	 */
	private static function row_operation( array $row ): string {
		return isset( $row['operation'] ) ? (string) $row['operation'] : '';
	}

	/**
	 * @param array<string,mixed> $row
	 */
	private static function row_family( array $row, string $operation ): ?string {
		if ( isset( $row['capability_family'] ) && is_string( $row['capability_family'] ) && '' !== $row['capability_family'] ) {
			return (string) $row['capability_family'];
		}
		if ( '' === $operation ) {
			return null;
		}
		if ( class_exists( Operations::class, false ) ) {
			return Operations::family_from_operation( $operation );
		}

		return null;
	}

	/**
	 * @param array<string,mixed> $row
	 * @return list<string>
	 */
	private static function row_armed_tools( array $row ): array {
		$raw = $row['armed_tools'] ?? $row['armed_abilities'] ?? array();
		if ( ! is_array( $raw ) ) {
			return array();
		}
		$out = array();
		foreach ( $raw as $tool ) {
			$tool = sanitize_text_field( (string) $tool );
			if ( '' !== $tool ) {
				$out[] = $tool;
			}
		}

		return array_values( array_unique( $out ) );
	}

	private static function plugin_label( string $basename ): string {
		if ( function_exists( 'get_plugins' ) ) {
			$plugins = get_plugins();
			if ( isset( $plugins[ $basename ]['Name'] ) && is_string( $plugins[ $basename ]['Name'] ) ) {
				return (string) $plugins[ $basename ]['Name'];
			}
		}

		return '' !== $basename ? $basename : __( 'unknown plugin', 'handl-ai-connector-access-control' );
	}

	/**
	 * Test seam: number of HTTP attempts recorded by the optional trap filter.
	 */
	private static function http_counter(): int {
		return isset( $GLOBALS['handl_aicac_outcome_replay_http'] )
			? (int) $GLOBALS['handl_aicac_outcome_replay_http']
			: 0;
	}
}
