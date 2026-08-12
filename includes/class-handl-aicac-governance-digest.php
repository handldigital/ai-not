<?php
/**
 * AICAC-DIGEST (#120): opt-in weekly AI governance digest email.
 *
 * Distinct from Weekly_Report (retained-log dashboard mirror). This digest uses
 * the same Activity/REST 7-day window as the widget rule (#110), compares
 * estimated spend to the prior week, and stays off by default.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Weekly governance digest (cron + settings + Email_Template via safe_wp_mail).
 */
final class Governance_Digest {

	public const CRON_HOOK = 'handl_aicac_send_governance_digest';

	/** Last successfully sent ISO week id (o-WW). */
	public const SENT_OPTION_KEY = 'handl_aicac_governance_digest_sent';

	/** Same Rest catalog token as Activity summaries. */
	public const WINDOW = '7d';

	public const TOP_PLUGINS = 3;

	private static ?Governance_Digest $instance = null;

	public static function instance(): Governance_Digest {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	public function init(): void {
		add_action( self::CRON_HOOK, array( $this, 'cron_send' ) );
		add_action( 'init', array( $this, 'maybe_self_heal_schedule' ), 23 );
	}

	public function maybe_self_heal_schedule(): void {
		self::maybe_schedule( Policy::get_policy() );
	}

	/**
	 * @param array<string,mixed> $policy
	 */
	public static function maybe_schedule( array $policy ): void {
		$want = self::is_active( $policy );

		if ( $want ) {
			if ( ! wp_next_scheduled( self::CRON_HOOK ) ) {
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
	 * @param array<string,mixed> $policy
	 */
	public static function is_active( array $policy ): bool {
		if ( empty( $policy['governance_digest_enabled'] ) ) {
			return false;
		}

		return ! empty( $policy['log_enabled'] ) || ! empty( $policy['audit_only'] );
	}

	/**
	 * @param array<string,mixed> $policy
	 */
	public static function always_send( array $policy ): bool {
		return ! empty( $policy['governance_digest_always_send'] );
	}

	/**
	 * @param array<string,mixed> $policy
	 */
	public static function resolve_email( array $policy ): string {
		return Alerts::resolve_email( $policy );
	}

	public function cron_send(): void {
		self::send_if_due( Policy::get_policy(), null, time() );
	}

	/**
	 * At most one email per ISO week (site timezone).
	 *
	 * @param array<string,mixed>                    $policy
	 * @param array<string,array<string,mixed>>|null $plugins
	 * @return array{sent:bool,status:string,week_id:string}
	 */
	public static function send_if_due( array $policy, ?array $plugins = null, ?int $now = null ): array {
		$now     = null !== $now ? (int) $now : time();
		$week_id = self::week_id( $now );
		$base    = array(
			'sent'    => false,
			'status'  => 'skipped',
			'week_id' => $week_id,
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

		if ( self::get_sent_week() === $week_id ) {
			$base['status'] = 'already_sent';
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

		$log   = Policy::get_retained_log( $now );
		$stats = self::build_stats( $policy, $log, $plugins, $now );

		if ( empty( $stats['has_activity'] ) && ! self::always_send( $policy ) ) {
			$base['status'] = 'no_activity';
			return $base;
		}

		$subject = self::build_subject( $stats );
		$body    = self::build_body( $stats );
		$ok      = Alerts::safe_wp_mail( $to, $subject, $body );
		if ( ! $ok ) {
			$base['status'] = 'mail_failed';
			return $base;
		}

		self::set_sent_week( $week_id );
		$base['sent']   = true;
		$base['status'] = 'sent';

		return $base;
	}

	/**
	 * Pure assembly for PHPUnit + cron. Uses Rest::build_activity_summary for
	 * this-week / prior-week numbers (Activity parity).
	 *
	 * @param array<string,mixed>               $policy
	 * @param array<int,mixed>                  $log
	 * @param array<string,array<string,mixed>> $plugins
	 * @return array<string,mixed>
	 */
	public static function build_stats( array $policy, array $log, array $plugins, int $now ): array {
		$current  = Rest::build_activity_summary( $policy, $log, self::WINDOW, $now );
		$previous = Rest::build_activity_summary( $policy, $log, self::WINDOW, $now - WEEK_IN_SECONDS );

		$deny_n = 0;
		if ( isset( $current['calls_by_decision'] ) && is_array( $current['calls_by_decision'] ) ) {
			$deny_n = (int) ( $current['calls_by_decision']['deny'] ?? 0 );
		}

		$client_calls = (int) ( $current['ai_client_call_count'] ?? 0 );
		$shadow_n     = (int) ( $current['shadow_ai_observation_count'] ?? 0 );
		$est_this     = isset( $current['estimated_spend_usd'] ) ? (float) $current['estimated_spend_usd'] : null;
		$est_prev     = isset( $previous['estimated_spend_usd'] ) ? (float) $previous['estimated_spend_usd'] : null;

		$anomaly_n = self::count_anomaly_rows( $log, $now );

		$top = array();
		$raw_top = isset( $current['top_plugins'] ) && is_array( $current['top_plugins'] )
			? $current['top_plugins']
			: array();
		$i = 0;
		foreach ( $raw_top as $row ) {
			if ( $i >= self::TOP_PLUGINS || ! is_array( $row ) ) {
				continue;
			}
			++$i;
			$basename = isset( $row['plugin'] ) && is_string( $row['plugin'] ) ? $row['plugin'] : '';
			$label    = '' !== $basename && isset( $plugins[ $basename ]['Name'] )
				? (string) $plugins[ $basename ]['Name']
				: ( '' !== $basename ? $basename : __( '(unknown plugin)', 'handl-ai-connector-access-control' ) );
			$entry = array(
				'label' => $label,
				'calls' => (int) ( $row['calls'] ?? 0 ),
			);
			if ( isset( $row['estimated_usd'] ) ) {
				$entry['estimated_usd'] = (float) $row['estimated_usd'];
			}
			$top[] = $entry;
		}

		$has_activity = $client_calls > 0 || $shadow_n > 0 || $anomaly_n > 0 || $deny_n > 0;

		return array(
			'week_id'          => self::week_id( $now ),
			'window'           => self::WINDOW,
			'current'          => $current,
			'previous'         => $previous,
			'ai_client_calls'  => $client_calls,
			'blocked_calls'    => $deny_n,
			'shadow_count'     => $shadow_n,
			'anomaly_count'    => $anomaly_n,
			'estimated_spend'  => $est_this,
			'estimated_spend_prev' => $est_prev,
			'top_plugins'      => $top,
			'has_activity'     => $has_activity,
			'status'           => (string) ( $current['status'] ?? 'ok' ),
		);
	}

	/**
	 * @param array<int,mixed> $log
	 */
	public static function count_anomaly_rows( array $log, int $now ): int {
		$filtered = Rest::filter_log_by_window( $log, self::WINDOW, $now );
		$n        = 0;
		foreach ( $filtered as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			if ( isset( $row['channel'] ) && 'anomaly' === (string) $row['channel'] ) {
				++$n;
			}
		}

		return $n;
	}

	/**
	 * @param array<string,mixed> $stats
	 */
	public static function build_subject( array $stats ): string {
		$site = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );

		return sprintf(
			/* translators: %s: site name */
			__( '[%s] HandL weekly AI governance digest', 'handl-ai-connector-access-control' ),
			$site
		);
	}

	/**
	 * @param array<string,mixed> $stats
	 */
	public static function build_body( array $stats ): string {
		$lines   = array();
		$lines[] = __( 'HandL AI Connector Access Control weekly governance digest', 'handl-ai-connector-access-control' );
		$lines[] = '';
		$lines[] = __( 'Last 7 days of saved Activity (same window as the Activity summary).', 'handl-ai-connector-access-control' );
		$lines[] = '';

		if ( 'logging_disabled' === (string) ( $stats['status'] ?? '' ) ) {
			$lines[] = __( 'Activity logging and Learn mode are off, so there is nothing to summarize.', 'handl-ai-connector-access-control' );
		} elseif ( empty( $stats['has_activity'] ) ) {
			$lines[] = __( 'No AI activity was recorded in the last 7 days.', 'handl-ai-connector-access-control' );
		} else {
			$lines[] = sprintf(
				/* translators: %s: formatted call count */
				__( 'AI Client calls: %s', 'handl-ai-connector-access-control' ),
				number_format_i18n( (int) ( $stats['ai_client_calls'] ?? 0 ) )
			);
			$lines[] = sprintf(
				/* translators: %s: formatted blocked call count */
				__( 'Blocked calls: %s', 'handl-ai-connector-access-control' ),
				number_format_i18n( (int) ( $stats['blocked_calls'] ?? 0 ) )
			);
			$lines[] = sprintf(
				/* translators: %s: shadow observation count */
				__( 'Direct connections outside the AI Client: %s', 'handl-ai-connector-access-control' ),
				number_format_i18n( (int) ( $stats['shadow_count'] ?? 0 ) )
			);
			$lines[] = sprintf(
				/* translators: %s: anomaly alert count */
				__( 'Usage spike alerts: %s', 'handl-ai-connector-access-control' ),
				number_format_i18n( (int) ( $stats['anomaly_count'] ?? 0 ) )
			);

			$est = $stats['estimated_spend'] ?? null;
			if ( null !== $est ) {
				$prev = $stats['estimated_spend_prev'] ?? null;
				if ( null !== $prev ) {
					$delta = (float) $est - (float) $prev;
					if ( $delta > 0.00005 ) {
						$sign = '+';
					} elseif ( $delta < -0.00005 ) {
						$sign = '-';
					} else {
						$sign = '';
					}
					$lines[] = sprintf(
						/* translators: 1: this week estimated USD, 2: + or - or empty, 3: absolute delta vs previous 7 days */
						__( 'Estimated spend: $%1$s (%2$s$%3$s vs the previous 7 days)', 'handl-ai-connector-access-control' ),
						self::format_amount( (float) $est ),
						$sign,
						self::format_amount( abs( $delta ) )
					);
				} else {
					$lines[] = sprintf(
						/* translators: %s: estimated USD */
						__( 'Estimated spend: $%s (no estimate from the previous 7 days to compare)', 'handl-ai-connector-access-control' ),
						self::format_amount( (float) $est )
					);
				}
			} else {
				$lines[] = __( 'Estimated spend: none yet (token counts required).', 'handl-ai-connector-access-control' );
			}

			$top = isset( $stats['top_plugins'] ) && is_array( $stats['top_plugins'] ) ? $stats['top_plugins'] : array();
			if ( ! empty( $top ) ) {
				$lines[] = '';
				$lines[] = __( 'Top plugins by estimated spend:', 'handl-ai-connector-access-control' );
				foreach ( $top as $row ) {
					if ( ! is_array( $row ) ) {
						continue;
					}
					if ( isset( $row['estimated_usd'] ) ) {
						$lines[] = sprintf(
							/* translators: 1: plugin name, 2: estimated USD, 3: call count */
							__( '%1$s: $%2$s estimated, %3$s calls', 'handl-ai-connector-access-control' ),
							(string) ( $row['label'] ?? '' ),
							self::format_amount( (float) $row['estimated_usd'] ),
							number_format_i18n( (int) ( $row['calls'] ?? 0 ) )
						);
					} else {
						$lines[] = sprintf(
							/* translators: 1: plugin name, 2: call count */
							__( '%1$s: %2$s calls (no estimate)', 'handl-ai-connector-access-control' ),
							(string) ( $row['label'] ?? '' ),
							number_format_i18n( (int) ( $row['calls'] ?? 0 ) )
						);
					}
				}
			}
		}

		$lines[] = '';
		$lines[] = __( 'Amounts are estimates from logged token usage and your rates. They are not a bill.', 'handl-ai-connector-access-control' );
		$lines[] = '';
		$lines[] = __( 'Turn off or change this digest:', 'handl-ai-connector-access-control' );
		$lines[] = admin_url( 'options-general.php?page=handl-ai-connector-access-control&handl_aicac_tab=activity' );
		$lines[] = '';
		$lines[] = __( 'Open Dashboard:', 'handl-ai-connector-access-control' );
		$lines[] = admin_url( 'options-general.php?page=handl-ai-connector-access-control&handl_aicac_tab=dashboard' );

		return implode( "\n", $lines ) . "\n";
	}

	public static function format_amount( float $amount ): string {
		if ( $amount > 0 && $amount < 0.01 ) {
			return '0.01';
		}

		return function_exists( 'number_format_i18n' )
			? number_format_i18n( $amount, 2 )
			: number_format( $amount, 2, '.', '' );
	}

	public static function week_id( ?int $now = null, ?\DateTimeZone $tz = null ): string {
		$now = null !== $now ? (int) $now : time();
		$tz  = null !== $tz ? $tz : Quiet_Hours::timezone();

		return ( new \DateTimeImmutable( '@' . $now ) )->setTimezone( $tz )->format( 'o-\WW' );
	}

	public static function get_sent_week(): string {
		$raw = get_option( self::SENT_OPTION_KEY, '' );

		return is_string( $raw ) ? $raw : '';
	}

	public static function set_sent_week( string $week_id ): void {
		$week_id = sanitize_text_field( $week_id );
		if ( '' === $week_id ) {
			delete_option( self::SENT_OPTION_KEY );
			return;
		}
		update_option( self::SENT_OPTION_KEY, $week_id, false );
	}

	/**
	 * @param array<string,mixed> $policy
	 * @return array{ok:bool,status:string,to:string}
	 */
	public static function send_test_email( array $policy ): array {
		return Alerts::send_test_email( $policy, 'governance_digest' );
	}
}
