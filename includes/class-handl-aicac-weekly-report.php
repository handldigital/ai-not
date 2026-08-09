<?php
/**
 * Weekly aggregate stats email (opt-in / default-on with logging).
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Mails a weekly summary of the F5 dashboard aggregates via wp_mail.
 *
 * First surface where retained log data can leave the site. Body is aggregates
 * only (counts, plugin names, estimated $) — no prompts, user names, or paths.
 * Observability only; never influences allow/deny.
 *
 * Window is self-dated from retained log min/max timestamps so a late WP-cron
 * fire stays honest. Reuses Cost, Model_Force, and Analytics helpers — same
 * units as the Dashboard (calls vs log entries).
 */
final class Weekly_Report {
	public const CRON_HOOK = 'handl_aicac_send_weekly_report';

	/** Max top plugins listed by estimated spend. */
	private const TOP_PLUGINS = 8;

	private static ?Weekly_Report $instance = null;

	public static function instance(): Weekly_Report {
		if ( null === self::$instance ) {
			self::$instance = new Weekly_Report();
		}
		return self::$instance;
	}

	public function init(): void {
		add_action( self::CRON_HOOK, array( $this, 'send_report' ) );
		// Self-heal lost cron events (hosting resets / "optimize" plugins).
		add_action( 'init', array( $this, 'maybe_self_heal_schedule' ), 21 );
	}

	/**
	 * Re-schedule weekly report when policy wants it and the event is missing.
	 */
	public function maybe_self_heal_schedule(): void {
		self::maybe_schedule( Policy::get_policy() );
	}

	/**
	 * Schedule weekly cron when the report is enabled and logging/learn is on.
	 * A stats digest with no stats path is spam — unschedule otherwise.
	 *
	 * @param array<string,mixed> $policy
	 */
	public static function maybe_schedule( array $policy ): void {
		$want = self::is_active( $policy );

		if ( $want ) {
			if ( ! wp_next_scheduled( self::CRON_HOOK ) ) {
				// First fire ~7 days out; subsequent weekly cadence via WP schedules.
				wp_schedule_event( time() + WEEK_IN_SECONDS, 'weekly', self::CRON_HOOK );
			}
			return;
		}

		$ts = wp_next_scheduled( self::CRON_HOOK );
		if ( $ts ) {
			wp_unschedule_event( $ts, self::CRON_HOOK );
		}
	}

	/**
	 * Report is active when the toggle is on and something is being logged.
	 *
	 * @param array<string,mixed> $policy
	 */
	public static function is_active( array $policy ): bool {
		if ( empty( $policy['weekly_report_enabled'] ) ) {
			return false;
		}
		return ! empty( $policy['log_enabled'] ) || ! empty( $policy['audit_only'] );
	}

	/**
	 * Staged preference when the option key has never been saved.
	 *
	 * Always selected (checked-but-inactive). Delivery still requires logging or
	 * learn mode via is_active() — same pattern as kill-switch exceptions staging.
	 *
	 * @param array<string,mixed> $policy Unused; kept for call-site stability.
	 */
	public static function default_enabled_for_policy( array $policy ): bool {
		unset( $policy );
		return true;
	}

	/**
	 * Recipient: same address as denial alerts when set, else site admin_email.
	 *
	 * @param array<string,mixed> $policy
	 */
	public static function resolve_email( array $policy ): string {
		return Alerts::resolve_email( $policy );
	}

	/**
	 * Cron entry point.
	 */
	public function send_report(): void {
		$policy = Policy::get_policy();
		if ( ! self::is_active( $policy ) ) {
			return;
		}

		$to = self::resolve_email( $policy );
		if ( '' === $to ) {
			return;
		}

		$log = get_option( Plugin::LOG_OPTION_KEY );
		if ( ! is_array( $log ) ) {
			$log = array();
		}

		// Cron context may not have loaded plugin.php yet.
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		$plugins = get_plugins();

		$stats   = self::build_stats( $log, $policy, $plugins );
		$subject = self::build_subject( $stats );
		$body    = self::build_body( $stats, $policy );

		self::safe_wp_mail( $to, $subject, $body );
	}

	/**
	 * Aggregate the same numbers the F5 Dashboard shows (retained log window).
	 *
	 * @param array<int,mixed>                  $log
	 * @param array<string,mixed>               $policy
	 * @param array<string,array<string,mixed>> $plugins
	 * @return array<string,mixed>
	 */
	public static function build_stats( array $log, array $policy, array $plugins ): array {
		$coverage = Analytics::coverage_from_log( $log, $policy );
		$pin      = Model_Force::pin_hold_stats( $log );
		$unforced = Model_Force::count_unforced_unattributed( $log );
		$has_pins = Model_Force::has_any_force_rules( $policy );

		$est_total    = 0.0;
		$est_any      = false;
		$deny_n       = 0;
		$plugin_spend = array();

		foreach ( $log as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$is_direct = isset( $row['channel'] ) && 'direct_http' === (string) $row['channel'];
			if ( ! $is_direct && 'deny' === (string) ( $row['decision'] ?? '' ) ) {
				++$deny_n;
			}
			if ( $is_direct ) {
				continue;
			}
			$in  = array_key_exists( 'input_tokens', $row ) ? (int) $row['input_tokens'] : null;
			$out = array_key_exists( 'output_tokens', $row ) ? (int) $row['output_tokens'] : null;
			$rates = Cost::rates_from_policy( $policy, isset( $row['provider'] ) ? (string) $row['provider'] : null );
			$usd   = Cost::estimate_usd( $in, $out, $rates );
			if ( null === $usd ) {
				continue;
			}
			$est_any    = true;
			$est_total += $usd;
			$p          = isset( $row['plugin'] ) ? (string) $row['plugin'] : '';
			if ( '' === $p ) {
				$p = Analytics::UNKNOWN_KEY;
			}
			if ( ! isset( $plugin_spend[ $p ] ) ) {
				$plugin_spend[ $p ] = array( 'usd' => 0.0, 'calls' => 0 );
			}
			$plugin_spend[ $p ]['usd']   += $usd;
			$plugin_spend[ $p ]['calls'] += 1;
		}

		uasort(
			$plugin_spend,
			static function ( $a, $b ) {
				return $b['usd'] <=> $a['usd'];
			}
		);

		$top = array();
		$i   = 0;
		foreach ( $plugin_spend as $p => $row ) {
			if ( $i >= self::TOP_PLUGINS ) {
				break;
			}
			++$i;
			$label = Analytics::UNKNOWN_KEY === $p
				? __( '(unknown)', 'handl-ai-connector-access-control' )
				: ( isset( $plugins[ $p ]['Name'] ) ? (string) $plugins[ $p ]['Name'] : $p );
			$top[] = array(
				'label' => $label,
				'usd'   => (float) $row['usd'],
				'calls' => (int) $row['calls'],
			);
		}

		return array(
			'coverage'           => $coverage,
			'deny_n'             => $deny_n,
			'est_any'            => $est_any,
			'est_total'          => $est_total,
			'top_plugins'        => $top,
			'has_pins'           => $has_pins,
			'pin'                => $pin,
			'unforced'           => $unforced,
			'using_default_rates'=> Cost::using_default_rates( $policy ),
			'window_label'       => self::format_window_label(
				(int) ( $coverage['min_ts'] ?? 0 ),
				(int) ( $coverage['max_ts'] ?? 0 )
			),
		);
	}

	/**
	 * Human calendar window for the subject/body (self-dating).
	 */
	public static function format_window_label( int $min_ts, int $max_ts ): string {
		if ( $min_ts <= 0 || $max_ts <= 0 ) {
			return __( 'retained log (no timestamps yet)', 'handl-ai-connector-access-control' );
		}
		if ( $min_ts === $max_ts ) {
			return wp_date( 'M j, Y', $min_ts );
		}
		// Same calendar year → omit year on the start date.
		$y1 = wp_date( 'Y', $min_ts );
		$y2 = wp_date( 'Y', $max_ts );
		if ( $y1 === $y2 ) {
			return sprintf(
				/* translators: 1: start date (e.g. Jul 24), 2: end date (e.g. Jul 31, 2026) */
				__( '%1$s – %2$s', 'handl-ai-connector-access-control' ),
				wp_date( 'M j', $min_ts ),
				wp_date( 'M j, Y', $max_ts )
			);
		}

		return sprintf(
			/* translators: 1: start date with year, 2: end date with year */
			__( '%1$s – %2$s', 'handl-ai-connector-access-control' ),
			wp_date( 'M j, Y', $min_ts ),
			wp_date( 'M j, Y', $max_ts )
		);
	}

	/**
	 * @param array<string,mixed> $stats
	 */
	public static function build_subject( array $stats ): string {
		$site   = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
		$window = (string) ( $stats['window_label'] ?? '' );

		return sprintf(
			/* translators: 1: site name, 2: dated window */
			__( '[%1$s] HandL AICAC weekly report (%2$s)', 'handl-ai-connector-access-control' ),
			$site,
			$window
		);
	}

	/**
	 * Plain-text body. Aggregates only — claims sheet applies to every line.
	 *
	 * @param array<string,mixed> $stats
	 * @param array<string,mixed> $policy
	 */
	public static function build_body( array $stats, array $policy ): string {
		$coverage = is_array( $stats['coverage'] ?? null ) ? $stats['coverage'] : array();
		$window   = (string) ( $stats['window_label'] ?? '' );
		$deny_n   = (int) ( $stats['deny_n'] ?? 0 );
		$lines    = array();

		$lines[] = __( 'HandL AI Connector Access Control — weekly report', 'handl-ai-connector-access-control' );
		$lines[] = '';
		$lines[] = sprintf(
			/* translators: %s: dated window from retained log */
			__( 'Window: %s', 'handl-ai-connector-access-control' ),
			$window
		);
		$lines[] = __( 'Dates come from the retained log on this site. WP-cron may deliver this email late on low-traffic sites; the window stays accurate.', 'handl-ai-connector-access-control' );
		$lines[] = '';

		// --- Coverage (same vocabulary as Dashboard) ---
		$lines[] = __( 'Coverage', 'handl-ai-connector-access-control' );
		$d = (int) ( $coverage['D'] ?? 0 );
		$m = (int) ( $coverage['M'] ?? 0 );
		if ( $d > 0 ) {
			$lines[] = __( 'Some AI activity on this site is outside what these rules can control', 'handl-ai-connector-access-control' );
		} elseif ( $m > 0 ) {
			$lines[] = __( 'Known AI activity in this log is flowing through the AI Client', 'handl-ai-connector-access-control' );
		} else {
			$lines[] = __( 'No AI activity retained in the log yet', 'handl-ai-connector-access-control' );
		}
		$lines[] = sprintf(
			/* translators: 1: log entry limit, 2: human span */
			__( 'from the last %1$s log entries · spanning %2$s', 'handl-ai-connector-access-control' ),
			number_format_i18n( (int) ( $coverage['log_limit'] ?? 200 ) ),
			(string) ( $coverage['span_label'] ?? '—' )
		);
		$lines[] = sprintf(
			/* translators: %s: total known AI activity calls */
			__( 'Known AI activity: %s calls', 'handl-ai-connector-access-control' ),
			number_format_i18n( $m )
		);
		$lines[] = sprintf(
			/* translators: 1: through AI Client, 2: attributed, 3: unattributed */
			__( '— Through the AI Client: %1$s (attributed %2$s · unattributed %3$s)', 'handl-ai-connector-access-control' ),
			number_format_i18n( (int) ( $coverage['N'] ?? 0 ) ),
			number_format_i18n( (int) ( $coverage['A'] ?? 0 ) ),
			number_format_i18n( (int) ( $coverage['U'] ?? 0 ) )
		);
		$lines[] = sprintf(
			/* translators: %s: outside AI Client call count */
			__( '— Outside the AI Client: %s — seen, not governed by these rules', 'handl-ai-connector-access-control' ),
			number_format_i18n( $d )
		);
		$lines[] = __( 'One log entry can represent many calls from the same plugin.', 'handl-ai-connector-access-control' );
		if ( ! empty( $coverage['saturated'] ) ) {
			$lines[] = sprintf(
				/* translators: %d: log entry limit */
				__( 'Log is at its %d-entry limit; older entries have aged out.', 'handl-ai-connector-access-control' ),
				(int) ( $coverage['log_limit'] ?? 200 )
			);
		}
		$lines[] = '';

		// --- Safety ---
		$lines[] = __( 'Safety & control', 'handl-ai-connector-access-control' );
		$default = ( ( $policy['default'] ?? 'allow' ) === 'deny' )
			? __( 'Deny', 'handl-ai-connector-access-control' )
			: __( 'Allow', 'handl-ai-connector-access-control' );
		$learn   = ! empty( $policy['audit_only'] )
			? __( 'Learn mode on (observation only — no deny/force)', 'handl-ai-connector-access-control' )
			: __( 'Learn mode off (enforcing)', 'handl-ai-connector-access-control' );
		$lines[] = sprintf(
			/* translators: 1: Allow/Deny default, 2: learn mode state */
			__( 'Default: %1$s · %2$s', 'handl-ai-connector-access-control' ),
			$default,
			$learn
		);
		if ( ! empty( $policy['kill_switch'] ) ) {
			$lines[] = __( 'Emergency kill switch is on.', 'handl-ai-connector-access-control' );
		}
		$lines[] = sprintf(
			/* translators: %d: deny count in retained log */
			_n( '%d deny in this log window.', '%d denies in this log window.', $deny_n, 'handl-ai-connector-access-control' ),
			$deny_n
		);
		$lines[] = '';

		// --- Spend (estimated, not billing) ---
		$lines[] = __( 'Spend (estimated)', 'handl-ai-connector-access-control' );
		if ( ! empty( $stats['est_any'] ) ) {
			$rate_note = ! empty( $stats['using_default_rates'] )
				? __( 'est. · default rates', 'handl-ai-connector-access-control' )
				: __( 'est. · custom rates', 'handl-ai-connector-access-control' );
			$lines[]   = sprintf(
				/* translators: 1: USD amount, 2: rate note */
				__( 'Total: $%1$s (%2$s) — not billing', 'handl-ai-connector-access-control' ),
				number_format_i18n( (float) ( $stats['est_total'] ?? 0 ), 2 ),
				$rate_note
			);
			$top = is_array( $stats['top_plugins'] ?? null ) ? $stats['top_plugins'] : array();
			if ( ! empty( $top ) ) {
				$lines[] = __( 'Top plugins by estimated spend:', 'handl-ai-connector-access-control' );
				foreach ( $top as $row ) {
					if ( ! is_array( $row ) ) {
						continue;
					}
					$lines[] = sprintf(
						/* translators: 1: plugin name, 2: USD, 3: call count */
						__( '— %1$s: $%2$s est. · %3$s calls', 'handl-ai-connector-access-control' ),
						(string) ( $row['label'] ?? '' ),
						number_format_i18n( (float) ( $row['usd'] ?? 0 ), 2 ),
						number_format_i18n( (int) ( $row['calls'] ?? 0 ) )
					);
				}
			}
		} else {
			$lines[] = __( 'No token-backed estimates in the retained log yet.', 'handl-ai-connector-access-control' );
		}
		$lines[] = '';

		// --- Pins (quiet when none configured) ---
		if ( ! empty( $stats['has_pins'] ) ) {
			$pin = is_array( $stats['pin'] ?? null ) ? $stats['pin'] : array();
			$lines[] = __( 'Did my pins hold?', 'handl-ai-connector-access-control' );
			$lines[] = sprintf(
				/* translators: 1: held count, 2: attempted count */
				__( 'Pins held for %1$s of %2$s attempted forces', 'handl-ai-connector-access-control' ),
				number_format_i18n( (int) ( $pin['held'] ?? 0 ) ),
				number_format_i18n( (int) ( $pin['attempted'] ?? 0 ) )
			);
			$unforced = (int) ( $stats['unforced'] ?? 0 );
			if ( $unforced > 0 ) {
				$lines[] = sprintf(
					/* translators: %d: unattributed never-evaluated count */
					_n(
						'%d call could not be attributed; pins were never evaluated for it.',
						'%d calls could not be attributed; pins were never evaluated for them.',
						$unforced,
						'handl-ai-connector-access-control'
					),
					$unforced
				);
			}
			$lines[] = '';
		}

		// --- Privacy + manage ---
		$lines[] = __( 'This report includes aggregate counts, estimated spend, and plugin names or plugin file identifiers only. It does not include prompt text, user names, request paths, hosts, or per-call URIs.', 'handl-ai-connector-access-control' );
		$lines[] = __( 'This message was sent by HandL AICAC via your site’s wp_mail transport (core PHP mail or an SMTP plugin you installed).', 'handl-ai-connector-access-control' );
		$lines[] = '';
		$lines[] = __( 'Manage weekly reports (opt out / change recipient):', 'handl-ai-connector-access-control' );
		$lines[] = admin_url( 'options-general.php?page=handl-ai-connector-access-control&handl_aicac_tab=activity' );
		$lines[] = '';
		$lines[] = __( 'Open Dashboard:', 'handl-ai-connector-access-control' );
		$lines[] = admin_url( 'options-general.php?page=handl-ai-connector-access-control&handl_aicac_tab=dashboard' );

		return implode( "\n", $lines ) . "\n";
	}

	/**
	 * wp_mail is pluggable; SMTP replacements may throw. A failed weekly report
	 * must never fatally break a cron request.
	 */
	private static function safe_wp_mail( string $to, string $subject, string $body ): bool {
		try {
			// phpcs:ignore WordPress.WP.AlternativeFunctions.wp_mail -- intentional notification path.
			return (bool) wp_mail( $to, $subject, $body );
		} catch ( \Throwable $e ) {
			return false;
		}
	}
}
