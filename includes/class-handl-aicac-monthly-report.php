<?php
/**
 * AICAC-REPORT-SCHED: opt-in monthly email of the printable audit evidence report.
 *
 * Reuses Audit_Evidence for HTML and Alerts::safe_wp_mail for delivery + alert-health.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * First-of-month audit report email (off by default).
 */
final class Monthly_Report {

	public const CRON_HOOK = 'handl_aicac_send_monthly_report';

	/** Last successfully attempted period (Y-m). */
	public const SENT_OPTION_KEY = 'handl_aicac_monthly_report_sent';

	/** Report window token — same Rest catalog as on-demand Activity export. */
	public const REPORT_WINDOW = '30d';

	private static ?Monthly_Report $instance = null;

	public static function instance(): Monthly_Report {
		if ( null === self::$instance ) {
			self::$instance = new Monthly_Report();
		}
		return self::$instance;
	}

	public function init(): void {
		add_action( self::CRON_HOOK, array( $this, 'cron_send' ) );
		add_action( 'init', array( $this, 'maybe_self_heal_schedule' ), 22 );
	}

	public function maybe_self_heal_schedule(): void {
		self::maybe_schedule( Policy::get_policy() );
	}

	/**
	 * Daily cron; send_if_due gates to one email per calendar month on/after the 1st.
	 *
	 * @param array<string,mixed> $policy
	 */
	public static function maybe_schedule( array $policy ): void {
		$want = self::is_active( $policy );

		if ( $want ) {
			if ( ! wp_next_scheduled( self::CRON_HOOK ) ) {
				$delay = defined( 'DAY_IN_SECONDS' ) ? (int) DAY_IN_SECONDS : 86400;
				wp_schedule_event( Clock::now() + $delay, 'daily', self::CRON_HOOK );
			}
			return;
		}

		$ts = wp_next_scheduled( self::CRON_HOOK );
		if ( $ts ) {
			wp_unschedule_event( $ts, self::CRON_HOOK );
		}
	}

	/**
	 * @param array<string,mixed> $policy
	 */
	public static function is_active( array $policy ): bool {
		if ( empty( $policy['monthly_report_enabled'] ) ) {
			return false;
		}

		return ! empty( $policy['log_enabled'] ) || ! empty( $policy['audit_only'] );
	}

	/**
	 * @param array<string,mixed> $policy
	 */
	public static function resolve_email( array $policy ): string {
		return Alerts::resolve_email( $policy );
	}

	/**
	 * Cron entry — uses wall clock.
	 */
	public function cron_send(): void {
		self::send_if_due( Policy::get_policy(), null, Clock::now() );
	}

	/**
	 * Send at most one email for the site-TZ calendar month containing $now.
	 * Runs on day 1+ until that month is marked sent (catch-up if cron was late).
	 *
	 * @param array<string,mixed>               $policy
	 * @param array<string,array<string,mixed>>|null $plugins
	 * @return array{sent:bool,status:string,period_ym:string}
	 */
	public static function send_if_due( array $policy, ?array $plugins = null, ?int $now = null ): array {
		$now = null !== $now ? $now : Clock::now();
		$tz  = self::timezone();
		$dt  = ( new \DateTimeImmutable( '@' . $now ) )->setTimezone( $tz );
		$period_ym = $dt->format( 'Y-m' );

		$base = array(
			'sent'       => false,
			'status'     => 'skipped',
			'period_ym'  => $period_ym,
		);

		if ( ! self::is_active( $policy ) ) {
			$base['status'] = 'inactive';
			return $base;
		}

		$to = self::resolve_email( $policy );
		if ( '' === $to ) {
			$base['status'] = 'no_recipient';
			return $base;
		}

		if ( self::get_sent_period() === $period_ym ) {
			$base['status'] = 'already_sent';
			return $base;
		}

		// Month boundary: only fire on/after the 1st of this calendar month.
		if ( (int) $dt->format( 'j' ) < 1 ) {
			$base['status'] = 'not_due';
			return $base;
		}

		if ( null === $plugins ) {
			if ( ! function_exists( 'get_plugins' ) && defined( 'ABSPATH' ) ) {
				$plugin_php = ABSPATH . 'wp-admin/includes/plugin.php';
				if ( is_readable( $plugin_php ) ) {
					require_once $plugin_php;
				}
			}
			$plugins = function_exists( 'get_plugins' ) ? get_plugins() : array();
		}
		if ( ! is_array( $plugins ) ) {
			$plugins = array();
		}

		$log = Policy::get_retained_log( $now );
		$result = self::send_report_email( $policy, $log, $plugins, $to, $now );
		if ( $result['ok'] ) {
			update_option( self::SENT_OPTION_KEY, $period_ym, false );
			return array(
				'sent'      => true,
				'status'    => (string) $result['status'],
				'period_ym' => $period_ym,
			);
		}

		return array(
			'sent'      => false,
			'status'    => 'failed',
			'period_ym' => $period_ym,
		);
	}

	/**
	 * Build + send (or skip-note) without mutating the sent-period option.
	 * Used by cron path and parity tests.
	 *
	 * @param array<string,mixed>               $policy
	 * @param array<int,mixed>                  $log
	 * @param array<string,array<string,mixed>> $plugins
	 * @return array{ok:bool,status:string,html:string,body:string,subject:string}
	 */
	public static function send_report_email( array $policy, array $log, array $plugins, string $to, int $now ): array {
		$summary = self::build_month_summary( $log, $policy, $now );
		$has_activity = (int) $summary['calls'] > 0
			|| (float) $summary['spend'] > 0.0
			|| (int) $summary['incidents'] > 0;

		$site = function_exists( 'get_bloginfo' )
			? wp_specialchars_decode( (string) get_bloginfo( 'name' ), ENT_QUOTES )
			: '';
		if ( '' === $site ) {
			$site = __( 'WordPress', 'handl-ai-connector-access-control' );
		}

		if ( ! $has_activity ) {
			$subject = sprintf(
				/* translators: %s: site name */
				__( '[%s] HandL AI audit report: no activity recorded', 'handl-ai-connector-access-control' ),
				$site
			);
			$body = self::build_skip_body( $summary );
			$ok   = Alerts::safe_wp_mail( $to, $subject, $body );

			return array(
				'ok'      => $ok,
				'status'  => $ok ? 'no_activity' : 'failed',
				'html'    => '',
				'body'    => $body,
				'subject' => $subject,
			);
		}

		$data = Audit_Evidence::build_report_data( $policy, $log, self::REPORT_WINDOW, $now, $plugins );
		$html = Audit_Evidence::build_html( $data );

		$subject = sprintf(
			/* translators: %s: site name */
			__( '[%s] HandL AI monthly audit report', 'handl-ai-connector-access-control' ),
			$site
		);
		$body = self::build_summary_body( $summary );

		$attachment = self::write_temp_html_attachment( $html, $now );
		$attachments = '' !== $attachment ? array( $attachment ) : array();
		$ok = Alerts::safe_wp_mail( $to, $subject, $body, $attachments );
		if ( '' !== $attachment && is_string( $attachment ) ) {
			// phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- best-effort temp cleanup.
			@unlink( $attachment );
		}

		return array(
			'ok'      => $ok,
			'status'  => $ok ? 'report' : 'failed',
			'html'    => $html,
			'body'    => $body,
			'subject' => $subject,
		);
	}

	/**
	 * HTML attachment bytes for the same window as on-demand export (parity helper).
	 *
	 * @param array<string,mixed>               $policy
	 * @param array<int,mixed>                  $log
	 * @param array<string,array<string,mixed>> $plugins
	 */
	public static function build_attachment_html( array $policy, array $log, array $plugins, int $now ): string {
		$data = Audit_Evidence::build_report_data( $policy, $log, self::REPORT_WINDOW, $now, $plugins );

		return Audit_Evidence::build_html( $data );
	}

	/**
	 * Three-line MoM summary: calls, estimated spend, incidents vs prior calendar month.
	 *
	 * @param array<int,mixed>    $log
	 * @param array<string,mixed> $policy
	 * @return array{
	 *   period_label:string,
	 *   prior_label:string,
	 *   calls:int,
	 *   prior_calls:int,
	 *   spend:float,
	 *   prior_spend:float,
	 *   incidents:int,
	 *   prior_incidents:int
	 * }
	 */
	public static function build_month_summary( array $log, array $policy, int $now ): array {
		$tz = self::timezone();
		$now_dt = ( new \DateTimeImmutable( '@' . $now ) )->setTimezone( $tz );

		// On the 1st, "this month so far" is empty — summarize the previous full calendar month.
		$day = (int) $now_dt->format( 'j' );
		if ( 1 === $day ) {
			$current_start = $now_dt->modify( 'first day of last month' )->setTime( 0, 0, 0 );
			$current_end   = $now_dt->modify( 'first day of this month' )->setTime( 0, 0, 0 );
			$prior_start   = $current_start->modify( 'first day of last month' );
			$prior_end     = $current_start;
		} else {
			$current_start = $now_dt->modify( 'first day of this month' )->setTime( 0, 0, 0 );
			$current_end   = $now_dt;
			$prior_start   = $current_start->modify( 'first day of last month' );
			$prior_end     = $current_start;
		}

		$cur = self::tally_window( $log, $policy, $current_start->getTimestamp(), $current_end->getTimestamp() );
		$pri = self::tally_window( $log, $policy, $prior_start->getTimestamp(), $prior_end->getTimestamp() );

		return array(
			'period_label'    => $current_start->format( 'F Y' ),
			'prior_label'     => $prior_start->format( 'F Y' ),
			'calls'           => $cur['calls'],
			'prior_calls'     => $pri['calls'],
			'spend'           => $cur['spend'],
			'prior_spend'     => $pri['spend'],
			'incidents'       => $cur['incidents'],
			'prior_incidents' => $pri['incidents'],
		);
	}

	/**
	 * @param array<string,mixed> $summary
	 */
	public static function build_summary_body( array $summary ): string {
		$lines   = array();
		$lines[] = __( 'HandL AI Connector Access Control monthly audit report', 'handl-ai-connector-access-control' );
		$lines[] = '';
		$lines[] = sprintf(
			/* translators: 1: month label, 2: call count, 3: prior month label, 4: prior call count */
			__( 'Calls: %2$s in %1$s (%4$s in %3$s)', 'handl-ai-connector-access-control' ),
			(string) $summary['period_label'],
			number_format_i18n( (int) $summary['calls'] ),
			(string) $summary['prior_label'],
			number_format_i18n( (int) $summary['prior_calls'] )
		);
		$lines[] = sprintf(
			/* translators: 1: month label, 2: dollar amount, 3: prior month label, 4: prior dollar amount */
			__( 'Estimated spend: $%2$s in %1$s ($%4$s in %3$s)', 'handl-ai-connector-access-control' ),
			(string) $summary['period_label'],
			number_format_i18n( (float) $summary['spend'], 2 ),
			(string) $summary['prior_label'],
			number_format_i18n( (float) $summary['prior_spend'], 2 )
		);
		$lines[] = sprintf(
			/* translators: 1: month label, 2: blocked-call count, 3: prior month label, 4: prior blocked-call count */
			__( 'Blocked calls: %2$s in %1$s (%4$s in %3$s)', 'handl-ai-connector-access-control' ),
			(string) $summary['period_label'],
			number_format_i18n( (int) $summary['incidents'] ),
			(string) $summary['prior_label'],
			number_format_i18n( (int) $summary['prior_incidents'] )
		);
		$lines[] = '';
		$lines[] = __( 'The printable report is attached as an HTML file. Open it in a browser, then use Print → Save as PDF. Estimated spend is an estimate, not a bill. Prompt text and user names are not included.', 'handl-ai-connector-access-control' );
		$lines[] = '';
		$lines[] = __( 'Manage this schedule:', 'handl-ai-connector-access-control' );
		$lines[] = Admin::screen_url( 'activity' );

		return implode( "\n", $lines ) . "\n";
	}

	/**
	 * @param array<string,mixed> $summary
	 */
	public static function build_skip_body( array $summary ): string {
		$lines   = array();
		$lines[] = __( 'HandL AI Connector Access Control monthly audit report', 'handl-ai-connector-access-control' );
		$lines[] = '';
		$lines[] = sprintf(
			/* translators: %s: month label */
			__( 'No activity was retained for %s.', 'handl-ai-connector-access-control' ),
			(string) $summary['period_label']
		);
		$lines[] = '';
		$lines[] = __( 'No report file is attached because no activity was retained for this period. The monthly email schedule is still on.', 'handl-ai-connector-access-control' );
		$lines[] = '';
		$lines[] = __( 'Manage this schedule:', 'handl-ai-connector-access-control' );
		$lines[] = Admin::screen_url( 'activity' );

		return implode( "\n", $lines ) . "\n";
	}

	public static function get_sent_period(): string {
		$raw = get_option( self::SENT_OPTION_KEY, '' );

		return is_string( $raw ) ? $raw : '';
	}

	/**
	 * @param array<int,mixed>    $log
	 * @param array<string,mixed> $policy
	 * @return array{calls:int,spend:float,incidents:int}
	 */
	private static function tally_window( array $log, array $policy, int $start_ts, int $end_ts ): array {
		$calls     = 0;
		$spend     = 0.0;
		$incidents = 0;

		foreach ( $log as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$channel = isset( $row['channel'] ) ? (string) $row['channel'] : '';
			if ( 'direct_http' === $channel
				|| 'spend_threshold' === $channel
				|| 'anomaly' === $channel
				|| 'forecast_warn' === $channel ) {
				continue;
			}
			$ts = isset( $row['ts'] ) ? (int) $row['ts'] : 0;
			if ( $ts < $start_ts || $ts >= $end_ts ) {
				continue;
			}
			++$calls;
			if ( 'deny' === (string) ( $row['decision'] ?? '' ) ) {
				++$incidents;
			}
			$in  = array_key_exists( 'input_tokens', $row ) ? (int) $row['input_tokens'] : null;
			$out = array_key_exists( 'output_tokens', $row ) ? (int) $row['output_tokens'] : null;
			$rates = Cost::rates_from_policy( $policy, isset( $row['provider'] ) ? (string) $row['provider'] : null );
			$usd   = Cost::estimate_usd( $in, $out, $rates );
			if ( null !== $usd ) {
				$spend += $usd;
			}
		}

		return array(
			'calls'     => $calls,
			'spend'     => $spend,
			'incidents' => $incidents,
		);
	}

	private static function write_temp_html_attachment( string $html, int $now ): string {
		if ( '' === $html ) {
			return '';
		}
		$base = function_exists( 'wp_tempnam' )
			? wp_tempnam( 'handl-aicac-audit-' )
			: tempnam( sys_get_temp_dir(), 'handl-aicac-audit-' );
		if ( ! is_string( $base ) || '' === $base ) {
			return '';
		}
		$path = $base . '.html';
		// phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		@unlink( $base );
		$written = file_put_contents( $path, $html );
		if ( false === $written ) {
			return '';
		}
		unset( $now );

		return $path;
	}

	private static function timezone(): \DateTimeZone {
		if ( function_exists( 'wp_timezone' ) ) {
			$tz = wp_timezone();
			if ( $tz instanceof \DateTimeZone ) {
				return $tz;
			}
		}

		return new \DateTimeZone( 'UTC' );
	}
}
