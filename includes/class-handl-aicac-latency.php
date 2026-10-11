<?php
/**
 * AICAC-LATENCY (#302): per-call duration + provider p95 degradation alerts.
 *
 * Times AI Client generations between prevent_prompt (start) and
 * after_generate_result (end). Calls without a measured interval are left
 * without duration_ms — never guessed. Rolling one-hour per-provider stats
 * drive optional p95 alerts through the existing mail/webhook pipeline.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Latency {

	public const SAMPLES_OPTION_KEY = 'handl_aicac_latency_samples';

	public const FIRED_OPTION_KEY = 'handl_aicac_latency_fired';

	public const WINDOW_SECONDS = 3600;

	public const DEDUPE_SECONDS = 3600;

	public const DEFAULT_P95_THRESHOLD_MS = 10000;

	public const DEFAULT_MIN_SAMPLES = 5;

	public const POLICY_ENABLED = 'latency_alert_enabled';

	public const POLICY_THRESHOLD = 'latency_p95_threshold_ms';

	public const POLICY_MIN_SAMPLES = 'latency_min_samples';

	public const POST_PRESENT = 'handl_aicac_latency_present';

	public const POST_ENABLED = 'handl_aicac_latency_alert_enabled';

	public const POST_THRESHOLD = 'handl_aicac_latency_p95_threshold_ms';

	public const POST_MIN_SAMPLES = 'handl_aicac_latency_min_samples';

	public const FILTER_THRESHOLD = 'handl_aicac_latency_p95_threshold_ms';

	public const FILTER_MIN_SAMPLES = 'handl_aicac_latency_min_samples';

	public const UNKNOWN_PROVIDER = 'unknown';

	/** @var list<array{key:string,start_ns:int}> */
	private static array $pending = array();

	private static ?self $instance = null;

	public static function instance(): self {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}

		return self::$instance;
	}

	public function init(): void {
		add_action( 'wp_ai_client_after_generate_result', array( $this, 'maybe_record_duration' ), 11, 1 );
		add_action( 'handl_aicac_protections_settings', array( $this, 'render_settings' ) );
		add_filter( 'pre_update_option_' . Plugin::OPTION_KEY, array( self::class, 'merge_policy_on_save' ), 10, 2 );
	}

	/**
	 * Start the timer for a generating call that was just logged with $log_key.
	 */
	public static function mark_start( string $log_key ): void {
		if ( '' === $log_key ) {
			return;
		}
		self::$pending[] = array(
			'key'      => $log_key,
			'start_ns' => self::now_ns(),
		);
	}

	/**
	 * @internal Tests only.
	 */
	public static function reset_pending_for_tests(): void {
		self::$pending = array();
	}

	/**
	 * @param object $event AfterGenerateResultEvent (WordPress AI Client).
	 */
	public function maybe_record_duration( object $event ): void {
		unset( $event );
		if ( empty( self::$pending ) ) {
			return;
		}

		$entry = array_pop( self::$pending );
		if ( ! is_array( $entry ) ) {
			return;
		}

		$log_key  = isset( $entry['key'] ) ? (string) $entry['key'] : '';
		$start_ns = isset( $entry['start_ns'] ) ? (int) $entry['start_ns'] : 0;
		if ( '' === $log_key || $start_ns <= 0 ) {
			return;
		}

		$elapsed_ns = self::now_ns() - $start_ns;
		if ( $elapsed_ns < 0 ) {
			return;
		}

		$duration_ms = (int) round( $elapsed_ns / 1e6 );
		if ( $duration_ms < 0 ) {
			return;
		}

		$policy = Policy::get_policy();
		if ( empty( $policy['log_enabled'] ) && empty( $policy['audit_only'] ) ) {
			return;
		}

		if ( ! Policy::patch_log_entry( $log_key, array( 'duration_ms' => $duration_ms ) ) ) {
			return;
		}

		$provider = self::provider_for_log_key( $log_key );
		self::record_sample( $provider, $duration_ms, Clock::now() );
		self::maybe_evaluate( $policy, Clock::now() );
	}

	/**
	 * @param mixed $raw
	 */
	public static function sanitize_threshold_ms( $raw ): int {
		if ( ! is_numeric( $raw ) ) {
			return self::DEFAULT_P95_THRESHOLD_MS;
		}
		$n = (int) $raw;
		if ( $n < 100 ) {
			return 100;
		}
		if ( $n > 600000 ) {
			return 600000;
		}

		return $n;
	}

	/**
	 * @param mixed $raw
	 */
	public static function sanitize_min_samples( $raw ): int {
		if ( ! is_numeric( $raw ) ) {
			return self::DEFAULT_MIN_SAMPLES;
		}
		$n = (int) $raw;
		if ( $n < 1 ) {
			return 1;
		}
		if ( $n > 10000 ) {
			return 10000;
		}

		return $n;
	}

	/**
	 * Effective p95 threshold (ms), filterable.
	 *
	 * @param array<string,mixed> $policy
	 */
	public static function threshold_ms( array $policy ): int {
		$base = self::sanitize_threshold_ms( $policy[ self::POLICY_THRESHOLD ] ?? self::DEFAULT_P95_THRESHOLD_MS );
		$filtered = apply_filters( self::FILTER_THRESHOLD, $base, $policy );

		return self::sanitize_threshold_ms( $filtered );
	}

	/**
	 * @param array<string,mixed> $policy
	 */
	public static function min_samples( array $policy ): int {
		$base = self::sanitize_min_samples( $policy[ self::POLICY_MIN_SAMPLES ] ?? self::DEFAULT_MIN_SAMPLES );
		$filtered = apply_filters( self::FILTER_MIN_SAMPLES, $base, $policy );

		return self::sanitize_min_samples( $filtered );
	}

	/**
	 * Default ON when the policy key is absent.
	 *
	 * @param array<string,mixed> $policy
	 */
	public static function is_alert_enabled( array $policy ): bool {
		if ( ! array_key_exists( self::POLICY_ENABLED, $policy ) ) {
			return true;
		}

		return ! empty( $policy[ self::POLICY_ENABLED ] );
	}

	/**
	 * @param mixed $value New option value.
	 * @param mixed $old   Previous option value.
	 * @return mixed
	 */
	public static function merge_policy_on_save( $value, $old ) {
		if ( ! is_array( $value ) ) {
			return $value;
		}

		$posted = isset( $_POST[ self::POST_PRESENT ] ); // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Admin save already verified the form nonce.
		if ( $posted ) {
			$value[ self::POLICY_ENABLED ]     = ! empty( $_POST[ self::POST_ENABLED ] ); // phpcs:ignore WordPress.Security.NonceVerification.Missing
			$value[ self::POLICY_THRESHOLD ]   = self::sanitize_threshold_ms(
				isset( $_POST[ self::POST_THRESHOLD ] ) ? wp_unslash( $_POST[ self::POST_THRESHOLD ] ) : self::DEFAULT_P95_THRESHOLD_MS // phpcs:ignore WordPress.Security.NonceVerification.Missing,WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
			);
			$value[ self::POLICY_MIN_SAMPLES ] = self::sanitize_min_samples(
				isset( $_POST[ self::POST_MIN_SAMPLES ] ) ? wp_unslash( $_POST[ self::POST_MIN_SAMPLES ] ) : self::DEFAULT_MIN_SAMPLES // phpcs:ignore WordPress.Security.NonceVerification.Missing,WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
			);

			return $value;
		}

		if ( is_array( $old ) ) {
			foreach ( array( self::POLICY_ENABLED, self::POLICY_THRESHOLD, self::POLICY_MIN_SAMPLES ) as $key ) {
				if ( array_key_exists( $key, $old ) ) {
					$value[ $key ] = $old[ $key ];
				}
			}
		}

		return $value;
	}

	/**
	 * Protections settings row: enable + threshold + live per-provider stats.
	 *
	 * @param array<string,mixed> $policy
	 */
	public function render_settings( $policy ): void {
		$policy      = is_array( $policy ) ? $policy : array();
		$enabled     = self::is_alert_enabled( $policy );
		$threshold   = self::threshold_ms( $policy );
		$min_samples = self::min_samples( $policy );
		$stats       = self::provider_stats( Clock::now() );

		echo '<tr>';
		echo '<th scope="row">' . esc_html__( 'Slow AI call alerts', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<td>';
		echo '<input type="hidden" name="' . esc_attr( self::POST_PRESENT ) . '" value="1" />';
		echo '<label for="handl-aicac-latency-alert-enabled">';
		echo '<input type="checkbox" name="' . esc_attr( self::POST_ENABLED ) . '" id="handl-aicac-latency-alert-enabled" value="1"' . ( $enabled ? ' checked="checked"' : '' ) . ' /> ';
		echo esc_html__( 'Email me when a provider’s AI calls get unusually slow', 'handl-ai-connector-access-control' );
		echo '</label>';
		echo '<p class="description">' . esc_html__( 'Measures how long each AI Client call takes and watches the last hour per provider. When the 95th percentile stays above the threshold (and enough calls were timed), one alert is sent for that provider for the hour. Uses the blocked-call alert email. Alerts do not block calls. Calls without a measured duration are skipped.', 'handl-ai-connector-access-control' ) . '</p>';

		echo '<p><label for="handl-aicac-latency-threshold">' . esc_html__( 'Alert when p95 exceeds (milliseconds)', 'handl-ai-connector-access-control' ) . '</label><br />';
		echo '<input type="number" step="100" min="100" max="600000" class="small-text" id="handl-aicac-latency-threshold" name="' . esc_attr( self::POST_THRESHOLD ) . '" value="' . esc_attr( (string) $threshold ) . '" /> ';
		echo '<span class="description">' . esc_html__( 'Default: 10000 (10 seconds).', 'handl-ai-connector-access-control' ) . '</span></p>';

		echo '<p><label for="handl-aicac-latency-min-samples">' . esc_html__( 'Minimum timed calls in the last hour before an alert', 'handl-ai-connector-access-control' ) . '</label><br />';
		echo '<input type="number" step="1" min="1" max="10000" class="small-text" id="handl-aicac-latency-min-samples" name="' . esc_attr( self::POST_MIN_SAMPLES ) . '" value="' . esc_attr( (string) $min_samples ) . '" /> ';
		echo '<span class="description">' . esc_html__( 'Default: 5.', 'handl-ai-connector-access-control' ) . '</span></p>';

		if ( empty( $stats ) ) {
			echo '<p class="description"><em>' . esc_html__( 'No timed calls yet.', 'handl-ai-connector-access-control' ) . '</em></p>';
		} else {
			echo '<p style="margin-top:12px;"><strong>' . esc_html__( 'Last hour (timed calls)', 'handl-ai-connector-access-control' ) . '</strong></p>';
			echo '<table class="widefat striped" style="max-width:36em;"><thead><tr>';
			echo '<th scope="col">' . esc_html__( 'Provider', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th scope="col">' . esc_html__( 'Calls', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th scope="col">' . esc_html__( 'p50 (ms)', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th scope="col">' . esc_html__( 'p95 (ms)', 'handl-ai-connector-access-control' ) . '</th>';
			echo '</tr></thead><tbody>';
			foreach ( $stats as $row ) {
				echo '<tr>';
				echo '<td>' . esc_html( (string) $row['provider'] ) . '</td>';
				echo '<td>' . esc_html( (string) (int) $row['count'] ) . '</td>';
				echo '<td>' . esc_html( (string) (int) $row['p50'] ) . '</td>';
				echo '<td>' . esc_html( (string) (int) $row['p95'] ) . '</td>';
				echo '</tr>';
			}
			echo '</tbody></table>';
		}

		echo '</td>';
		echo '</tr>';
	}

	/**
	 * Record a timed sample for a provider (rolling one-hour window).
	 */
	public static function record_sample( string $provider, int $duration_ms, int $now ): void {
		$provider = self::sanitize_provider( $provider );
		if ( $duration_ms < 0 ) {
			return;
		}

		$store = get_option( self::SAMPLES_OPTION_KEY, array() );
		if ( ! is_array( $store ) ) {
			$store = array();
		}

		$bucket = isset( $store[ $provider ] ) && is_array( $store[ $provider ] ) ? $store[ $provider ] : array();
		$bucket[] = array(
			'ts' => $now,
			'ms' => $duration_ms,
		);
		$store[ $provider ] = self::prune_samples( $bucket, $now );
		$store              = self::prune_empty_providers( $store, $now );

		update_option( self::SAMPLES_OPTION_KEY, $store, false );
	}

	/**
	 * Per-provider count / p50 / p95 over the rolling window.
	 *
	 * @return list<array{provider:string,count:int,p50:int,p95:int}>
	 */
	public static function provider_stats( ?int $now = null ): array {
		$now   = null !== $now ? $now : Clock::now();
		$store = get_option( self::SAMPLES_OPTION_KEY, array() );
		if ( ! is_array( $store ) ) {
			return array();
		}

		$out = array();
		foreach ( $store as $provider => $samples ) {
			if ( ! is_array( $samples ) ) {
				continue;
			}
			$ms = self::ms_in_window( $samples, $now );
			if ( empty( $ms ) ) {
				continue;
			}
			sort( $ms, SORT_NUMERIC );
			$out[] = array(
				'provider' => self::sanitize_provider( (string) $provider ),
				'count'    => count( $ms ),
				'p50'      => self::percentile_ms( $ms, 50 ),
				'p95'      => self::percentile_ms( $ms, 95 ),
			);
		}

		usort(
			$out,
			static function ( array $a, array $b ): int {
				return strcmp( $a['provider'], $b['provider'] );
			}
		);

		return $out;
	}

	/**
	 * @param list<int> $sorted_ms Ascending.
	 */
	public static function percentile_ms( array $sorted_ms, int $percentile ): int {
		$n = count( $sorted_ms );
		if ( $n <= 0 ) {
			return 0;
		}
		if ( $percentile < 0 ) {
			$percentile = 0;
		}
		if ( $percentile > 100 ) {
			$percentile = 100;
		}
		$rank = (int) ceil( ( $percentile / 100 ) * $n ) - 1;
		if ( $rank < 0 ) {
			$rank = 0;
		}
		if ( $rank >= $n ) {
			$rank = $n - 1;
		}

		return (int) $sorted_ms[ $rank ];
	}

	/**
	 * @param array<string,mixed>|null $policy
	 * @param int|null                 $now
	 */
	public static function maybe_evaluate( ?array $policy = null, ?int $now = null ): void {
		$policy = is_array( $policy ) ? $policy : Policy::get_policy();
		if ( ! self::is_alert_enabled( $policy ) ) {
			return;
		}
		if ( empty( $policy['log_enabled'] ) && empty( $policy['audit_only'] ) ) {
			return;
		}

		$now         = null !== $now ? $now : Clock::now();
		$threshold   = self::threshold_ms( $policy );
		$min_samples = self::min_samples( $policy );
		$to          = Alert_Routing::resolve_email( $policy, 'latency' );
		if ( '' === $to ) {
			return;
		}

		foreach ( self::provider_stats( $now ) as $row ) {
			$count = (int) $row['count'];
			$p95   = (int) $row['p95'];
			if ( $count < $min_samples || $p95 < $threshold ) {
				self::clear_fire_key( self::fire_key( (string) $row['provider'] ) );
				continue;
			}
			self::maybe_fire(
				$policy,
				$to,
				(string) $row['provider'],
				$count,
				(int) $row['p50'],
				$p95,
				$threshold,
				$now
			);
		}
	}

	/**
	 * @param array<string,mixed> $policy
	 */
	private static function maybe_fire(
		array $policy,
		string $to,
		string $provider,
		int $count,
		int $p50,
		int $p95,
		int $threshold,
		int $now
	): void {
		$key = self::fire_key( $provider );
		if ( self::is_deduped( $key, $threshold, $now ) ) {
			return;
		}

		$subject = self::build_subject( $provider, $p95, $threshold );
		$body    = self::build_body( $provider, $count, $p50, $p95, $threshold );
		$ok      = Alerts::safe_wp_mail( $to, $subject, $body );

		$hook_url = Alerts::resolve_webhook( $policy );
		if ( '' !== $hook_url ) {
			Alerts::safe_wp_remote_post(
				$hook_url,
				array(
					'type'       => 'handl_aicac_latency_alert',
					'provider'   => $provider,
					'count'      => $count,
					'p50_ms'     => $p50,
					'p95_ms'     => $p95,
					'threshold'  => $threshold,
					'window_s'   => self::WINDOW_SECONDS,
					'site'       => function_exists( 'home_url' ) ? home_url( '/' ) : '',
				)
			);
		}

		if ( ! $ok ) {
			return;
		}

		self::record_fire( $key, $threshold, $now );
		self::append_audit_row( $provider, $count, $p50, $p95, $threshold );
	}

	public static function fire_key( string $provider ): string {
		return 'p95:' . self::sanitize_provider( $provider );
	}

	public static function build_subject( string $provider, int $p95, int $threshold ): string {
		$site = function_exists( 'get_bloginfo' )
			? wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES )
			: 'WordPress';

		return sprintf(
			/* translators: 1: site name, 2: provider id */
			__( '[%1$s] HandL slow AI calls: %2$s is above the latency threshold', 'handl-ai-connector-access-control' ),
			$site,
			self::sanitize_provider( $provider )
		);
	}

	public static function build_body(
		string $provider,
		int $count,
		int $p50,
		int $p95,
		int $threshold
	): string {
		$lines   = array();
		$lines[] = __( 'HandL AI Connector Access Control slow AI call alert', 'handl-ai-connector-access-control' );
		$lines[] = '';
		$lines[] = sprintf(
			/* translators: %s: provider id */
			__( 'Provider: %s', 'handl-ai-connector-access-control' ),
			self::sanitize_provider( $provider )
		);
		$lines[] = sprintf(
			/* translators: %d: timed call count */
			__( 'Timed calls (last hour): %d', 'handl-ai-connector-access-control' ),
			$count
		);
		$lines[] = sprintf(
			/* translators: %d: milliseconds */
			__( 'p50: %d ms', 'handl-ai-connector-access-control' ),
			$p50
		);
		$lines[] = sprintf(
			/* translators: %d: milliseconds */
			__( 'p95: %d ms', 'handl-ai-connector-access-control' ),
			$p95
		);
		$lines[] = sprintf(
			/* translators: %d: milliseconds */
			__( 'Alert threshold (p95): %d ms', 'handl-ai-connector-access-control' ),
			$threshold
		);
		$lines[] = '';
		$lines[] = __( 'This watches AI Client call duration over the last hour. It does not block calls.', 'handl-ai-connector-access-control' );
		$lines[] = '';
		$lines[] = __( 'Manage slow AI call alerts:', 'handl-ai-connector-access-control' );
		$lines[] = Admin::screen_url( 'protections' );

		return implode( "\n", $lines ) . "\n";
	}

	private static function append_audit_row(
		string $provider,
		int $count,
		int $p50,
		int $p95,
		int $threshold
	): void {
		Policy::append_log_event(
			array(
				'ts'           => Clock::now(),
				'decision'     => 'latency_alert',
				'channel'      => 'latency',
				'provider'     => self::sanitize_provider( $provider ),
				'count'        => $count,
				'p50_ms'       => $p50,
				'p95_ms'       => $p95,
				'threshold_ms' => $threshold,
			)
		);
	}

	private static function is_deduped( string $key, int $threshold, int $now ): bool {
		$state = get_option( self::FIRED_OPTION_KEY, array() );
		if ( ! is_array( $state ) || ! isset( $state[ $key ] ) || ! is_array( $state[ $key ] ) ) {
			return false;
		}
		$row = $state[ $key ];
		$at  = isset( $row['at'] ) ? (int) $row['at'] : 0;
		$th  = isset( $row['threshold'] ) ? (int) $row['threshold'] : 0;
		if ( $at <= 0 ) {
			return false;
		}
		if ( $th !== $threshold ) {
			return false;
		}

		return ( $now - $at ) < self::DEDUPE_SECONDS;
	}

	private static function record_fire( string $key, int $threshold, int $now ): void {
		$state = get_option( self::FIRED_OPTION_KEY, array() );
		if ( ! is_array( $state ) ) {
			$state = array();
		}
		$state[ $key ] = array(
			'at'        => $now,
			'threshold' => $threshold,
		);
		update_option( self::FIRED_OPTION_KEY, $state, false );
	}

	private static function clear_fire_key( string $key ): void {
		$state = get_option( self::FIRED_OPTION_KEY, array() );
		if ( ! is_array( $state ) || ! isset( $state[ $key ] ) ) {
			return;
		}
		unset( $state[ $key ] );
		update_option( self::FIRED_OPTION_KEY, $state, false );
	}

	private static function provider_for_log_key( string $log_key ): string {
		$log = get_option( Plugin::LOG_OPTION_KEY );
		if ( ! is_array( $log ) ) {
			return self::UNKNOWN_PROVIDER;
		}
		for ( $i = count( $log ) - 1; $i >= 0; $i-- ) {
			if ( ! is_array( $log[ $i ] ) ) {
				continue;
			}
			if ( ( $log[ $i ]['log_key'] ?? '' ) !== $log_key ) {
				continue;
			}
			$provider = isset( $log[ $i ]['provider'] ) ? (string) $log[ $i ]['provider'] : '';

			return self::sanitize_provider( $provider );
		}

		return self::UNKNOWN_PROVIDER;
	}

	public static function sanitize_provider( string $provider ): string {
		$provider = strtolower( trim( $provider ) );
		$provider = preg_replace( '/[^a-z0-9_\-\.]/', '', $provider ) ?? '';
		if ( '' === $provider ) {
			return self::UNKNOWN_PROVIDER;
		}

		return $provider;
	}

	/**
	 * @param list<array{ts?:int,ms?:int}> $samples
	 * @return list<array{ts:int,ms:int}>
	 */
	private static function prune_samples( array $samples, int $now ): array {
		$out    = array();
		$cutoff = $now - self::WINDOW_SECONDS;
		foreach ( $samples as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$ts = isset( $row['ts'] ) ? (int) $row['ts'] : 0;
			$ms = isset( $row['ms'] ) ? (int) $row['ms'] : -1;
			if ( $ts < $cutoff || $ms < 0 ) {
				continue;
			}
			$out[] = array(
				'ts' => $ts,
				'ms' => $ms,
			);
		}

		// Cap memory: keep newest 2000 samples per provider inside the window.
		if ( count( $out ) > 2000 ) {
			$out = array_slice( $out, -2000 );
		}

		return $out;
	}

	/**
	 * @param array<string,mixed> $store
	 * @return array<string,list<array{ts:int,ms:int}>>
	 */
	private static function prune_empty_providers( array $store, int $now ): array {
		$out = array();
		foreach ( $store as $provider => $samples ) {
			if ( ! is_array( $samples ) ) {
				continue;
			}
			$pruned = self::prune_samples( $samples, $now );
			if ( empty( $pruned ) ) {
				continue;
			}
			$out[ self::sanitize_provider( (string) $provider ) ] = $pruned;
		}

		return $out;
	}

	/**
	 * @param list<array{ts?:int,ms?:int}> $samples
	 * @return list<int>
	 */
	private static function ms_in_window( array $samples, int $now ): array {
		$cutoff = $now - self::WINDOW_SECONDS;
		$out    = array();
		foreach ( $samples as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$ts = isset( $row['ts'] ) ? (int) $row['ts'] : 0;
			$ms = isset( $row['ms'] ) ? (int) $row['ms'] : -1;
			if ( $ts < $cutoff || $ms < 0 ) {
				continue;
			}
			$out[] = $ms;
		}

		return $out;
	}

	private static function now_ns(): int {
		if ( function_exists( 'hrtime' ) ) {
			$t = hrtime( true );
			if ( is_int( $t ) || is_float( $t ) ) {
				return (int) $t;
			}
		}

		return (int) round( microtime( true ) * 1e9 );
	}
}
