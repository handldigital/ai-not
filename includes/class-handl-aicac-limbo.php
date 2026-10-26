<?php
/**
 * AICAC-LIMBO (#411): access-request time-to-decision meter (read-only).
 *
 * Observes the Access_Request lifecycle (created → decided) without editing
 * Access_Request or Request_Chat. Aging roster (oldest first), stale findings
 * over a configurable SLA (default 7 days), median/worst time-to-decision
 * stats from decided history. Exactly one re-arming [LIMBO] alert naming the
 * over-SLA count and oldest request. Print + CSV + WP-CLI. OFF by default.
 * Own two options. Suggestion/report only — never decides, reminds, or
 * mutates request rows (delegation = DEPUTY #357).
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Request-queue latency meter.
 */
final class Limbo {

	public const SETTINGS_OPTION = 'handl_aicac_limbo';

	public const STATE_OPTION = 'handl_aicac_limbo_state';

	public const PAGE_SLUG = 'handl-aicac-limbo';

	public const ALERT_KIND = 'limbo';

	public const FRAMING = 'report_only_never_decides';

	public const FILTER_SLA_DAYS = 'handl_aicac_limbo_sla_days';

	public const POST_PRESENT = 'handl_aicac_limbo_present';

	public const POST_ENABLED = 'handl_aicac_limbo_enabled';

	public const POST_SLA_DAYS = 'handl_aicac_limbo_sla_days';

	public const ACTION_SAVE = 'handl_aicac_limbo_save';

	public const DEFAULT_SLA_DAYS = 7;

	public const MIN_SLA_DAYS = 1;

	public const MAX_SLA_DAYS = 365;

	public const HISTORY_CAP = 40;

	public const DECIDED_STATS_CAP = 200;

	/** @var bool */
	private static $registered = false;

	/** @var list<array<string,mixed>> */
	private static $test_mails = array();

	/** @var list<array<string,mixed>>|null */
	private static $test_requests = null;

	public static function init(): void {
		if ( self::$registered ) {
			return;
		}
		self::$registered = true;

		add_action( 'admin_menu', array( self::class, 'register_menu' ), 20 );
		add_action( 'admin_init', array( self::class, 'maybe_handle_csv' ), 5 );
		add_action( 'admin_init', array( self::class, 'maybe_handle_print' ), 5 );
		add_action( 'admin_post_' . self::ACTION_SAVE, array( self::class, 'handle_save' ) );

		if ( self::is_enabled() ) {
			add_action( 'init', array( self::class, 'maybe_fire_alerts' ), 30 );
		}

		self::register_cli();
	}

	public static function reset_for_tests(): void {
		self::$registered    = false;
		self::$test_mails    = array();
		self::$test_requests = null;
		delete_option( self::SETTINGS_OPTION );
		delete_option( self::STATE_OPTION );
	}

	/**
	 * @return list<array<string,mixed>>
	 */
	public static function test_mails(): array {
		return self::$test_mails;
	}

	/**
	 * Inject request rows for unit tests (bypasses option / Access_Request).
	 *
	 * @param list<array<string,mixed>>|null $rows Rows or null to clear.
	 */
	public static function set_test_requests( ?array $rows ): void {
		self::$test_requests = $rows;
	}

	/* ---------------------------------------------------------------------
	 * Settings
	 * ------------------------------------------------------------------ */

	/**
	 * @return array{enabled:bool,sla_days:int}
	 */
	public static function defaults(): array {
		return array(
			'enabled'  => false,
			'sla_days' => self::DEFAULT_SLA_DAYS,
		);
	}

	/**
	 * @return array{enabled:bool,sla_days:int}
	 */
	public static function get_settings(): array {
		return self::sanitize_settings( get_option( self::SETTINGS_OPTION, array() ) );
	}

	/**
	 * @param mixed $raw Raw settings.
	 * @return array{enabled:bool,sla_days:int}
	 */
	public static function sanitize_settings( $raw ): array {
		$defaults = self::defaults();
		if ( ! is_array( $raw ) ) {
			return $defaults;
		}

		return array(
			'enabled'  => ! empty( $raw['enabled'] ),
			'sla_days' => self::sanitize_sla_days( $raw['sla_days'] ?? $defaults['sla_days'] ),
		);
	}

	/**
	 * @param mixed $raw Raw days.
	 */
	public static function sanitize_sla_days( $raw ): int {
		if ( ! is_numeric( $raw ) ) {
			return self::DEFAULT_SLA_DAYS;
		}
		$v = (int) $raw;
		if ( $v < self::MIN_SLA_DAYS ) {
			$v = self::MIN_SLA_DAYS;
		}
		if ( $v > self::MAX_SLA_DAYS ) {
			$v = self::MAX_SLA_DAYS;
		}

		return $v;
	}

	/**
	 * Effective SLA days after filter.
	 */
	public static function sla_days(): int {
		$settings = self::get_settings();
		$base     = (int) $settings['sla_days'];
		if ( function_exists( 'apply_filters' ) ) {
			return self::sanitize_sla_days( apply_filters( self::FILTER_SLA_DAYS, $base ) );
		}

		return $base;
	}

	/**
	 * @param array<string,mixed> $settings Settings.
	 */
	public static function save_settings( array $settings ): bool {
		$clean  = self::sanitize_settings( $settings );
		$before = self::get_settings();
		if ( $clean === $before ) {
			return false;
		}
		if ( $clean === self::defaults() ) {
			delete_option( self::SETTINGS_OPTION );

			return true;
		}
		update_option( self::SETTINGS_OPTION, $clean, false );

		return true;
	}

	public static function is_enabled(): bool {
		$settings = self::get_settings();

		return ! empty( $settings['enabled'] );
	}

	/* ---------------------------------------------------------------------
	 * State
	 * ------------------------------------------------------------------ */

	/**
	 * @return array{alerted:bool,history:list<array<string,mixed>>}
	 */
	public static function defaults_state(): array {
		return array(
			'alerted' => false,
			'history' => array(),
		);
	}

	/**
	 * @return array{alerted:bool,history:list<array<string,mixed>>}
	 */
	public static function get_state(): array {
		return self::sanitize_state( get_option( self::STATE_OPTION, array() ) );
	}

	/**
	 * @param mixed $raw Raw state.
	 * @return array{alerted:bool,history:list<array<string,mixed>>}
	 */
	public static function sanitize_state( $raw ): array {
		$defaults = self::defaults_state();
		if ( ! is_array( $raw ) ) {
			return $defaults;
		}
		$history = array();
		if ( isset( $raw['history'] ) && is_array( $raw['history'] ) ) {
			foreach ( $raw['history'] as $row ) {
				$clean = self::sanitize_history_entry( $row );
				if ( null !== $clean ) {
					$history[] = $clean;
				}
			}
		}
		if ( count( $history ) > self::HISTORY_CAP ) {
			$history = array_slice( $history, -self::HISTORY_CAP );
		}

		return array(
			'alerted' => ! empty( $raw['alerted'] ),
			'history' => $history,
		);
	}

	/**
	 * @param mixed $row Raw history row.
	 * @return array{ts:int,stale_count:int,oldest_id:string,oldest_days:int}|null
	 */
	public static function sanitize_history_entry( $row ): ?array {
		if ( ! is_array( $row ) ) {
			return null;
		}
		$ts = isset( $row['ts'] ) ? (int) $row['ts'] : 0;
		if ( $ts <= 0 ) {
			return null;
		}

		return array(
			'ts'          => $ts,
			'stale_count' => max( 0, (int) ( $row['stale_count'] ?? 0 ) ),
			'oldest_id'   => self::sanitize_request_id( (string) ( $row['oldest_id'] ?? '' ) ),
			'oldest_days' => max( 0, (int) ( $row['oldest_days'] ?? 0 ) ),
		);
	}

	/**
	 * @param array<string,mixed> $state State.
	 */
	public static function put_state( array $state ): void {
		$clean = self::sanitize_state( $state );
		if ( $clean === self::defaults_state() ) {
			delete_option( self::STATE_OPTION );

			return;
		}
		update_option( self::STATE_OPTION, $clean, false );
	}

	public static function is_alerted(): bool {
		$state = self::get_state();

		return ! empty( $state['alerted'] );
	}

	public static function set_alerted( bool $alerted ): void {
		$state            = self::get_state();
		$state['alerted'] = $alerted;
		self::put_state( $state );
	}

	/* ---------------------------------------------------------------------
	 * Observe Access_Request (read-only)
	 * ------------------------------------------------------------------ */

	public static function requests_option_key(): string {
		if ( class_exists( Access_Request::class, false ) && defined( Access_Request::class . '::OPTION_KEY' ) ) {
			return (string) Access_Request::OPTION_KEY;
		}

		return 'handl_aicac_access_requests';
	}

	public static function status_pending(): string {
		if ( class_exists( Access_Request::class, false ) && defined( Access_Request::class . '::STATUS_PENDING' ) ) {
			return (string) Access_Request::STATUS_PENDING;
		}

		return 'pending';
	}

	public static function sanitize_request_id( string $id ): string {
		$id = strtolower( preg_replace( '/[^a-f0-9]/', '', $id ) ?? '' );

		return ( 32 === strlen( $id ) ) ? $id : ( '' !== $id ? sanitize_key( $id ) : '' );
	}

	/**
	 * Read-only map of access requests. Never writes.
	 *
	 * @return list<array<string,mixed>>
	 */
	public static function load_requests(): array {
		if ( null !== self::$test_requests ) {
			return self::$test_requests;
		}

		$out = array();
		$raw = get_option( self::requests_option_key(), array() );
		if ( ! is_array( $raw ) ) {
			return array();
		}
		foreach ( $raw as $id => $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$clean = self::normalize_request_row( $row, (string) $id );
			if ( null !== $clean ) {
				$out[] = $clean;
			}
		}

		return $out;
	}

	/**
	 * @param array<string,mixed> $row Raw row.
	 * @return array<string,mixed>|null
	 */
	public static function normalize_request_row( array $row, string $fallback_id = '' ): ?array {
		$id = self::sanitize_request_id( (string) ( $row['id'] ?? $fallback_id ) );
		$plugin = '';
		if ( class_exists( Plugin_Profile::class, false ) && method_exists( Plugin_Profile::class, 'sanitize_plugin' ) ) {
			$plugin = Plugin_Profile::sanitize_plugin( (string) ( $row['plugin'] ?? '' ) );
		} else {
			$plugin = sanitize_text_field( (string) ( $row['plugin'] ?? '' ) );
		}
		$status = sanitize_key( (string) ( $row['status'] ?? '' ) );
		if ( '' === $plugin || '' === $status ) {
			return null;
		}
		$created  = isset( $row['ts'] ) ? (int) $row['ts'] : 0;
		$resolved = isset( $row['resolved_ts'] ) ? (int) $row['resolved_ts'] : 0;

		return array(
			'id'          => $id,
			'plugin'      => $plugin,
			'user_id'     => isset( $row['user_id'] ) ? (int) $row['user_id'] : 0,
			'user_login'  => sanitize_text_field( (string) ( $row['user_login'] ?? '' ) ),
			'reason'      => sanitize_text_field( (string) ( $row['reason'] ?? '' ) ),
			'status'      => $status,
			'ts'          => $created,
			'resolved_ts' => $resolved,
			'resolved_by' => isset( $row['resolved_by'] ) ? (int) $row['resolved_by'] : 0,
		);
	}

	public static function inbox_url( string $request_id = '' ): string {
		$url = '';
		if ( class_exists( Admin::class, false ) && method_exists( Admin::class, 'screen_url' ) ) {
			$url = (string) Admin::screen_url( 'protections' );
		} elseif ( function_exists( 'admin_url' ) ) {
			$url = (string) add_query_arg( 'page', 'handl-aicac-protections', admin_url( 'admin.php' ) );
		}
		if ( '' === $url ) {
			return '';
		}
		$anchor = 'handl-aicac-access-request-inbox';
		$id     = self::sanitize_request_id( $request_id );
		if ( '' !== $id ) {
			$anchor = 'handl-aicac-request-' . $id;
		}

		return $url . '#' . $anchor;
	}

	/**
	 * Days since created (floor). Null when created ts missing/invalid.
	 */
	public static function days_in_limbo( int $created_ts, ?int $now = null ): ?int {
		if ( $created_ts <= 0 ) {
			return null;
		}
		$now = null !== $now && $now > 0
			? $now
			: ( class_exists( Clock::class, false ) ? Clock::now() : time() );
		if ( $now < $created_ts ) {
			return 0;
		}
		$day = defined( 'DAY_IN_SECONDS' ) ? (int) DAY_IN_SECONDS : 86400;

		return (int) floor( ( $now - $created_ts ) / $day );
	}

	/**
	 * Created-to-decided duration in seconds, or null if not decided.
	 *
	 * @param array<string,mixed> $row Request row.
	 */
	public static function decision_duration_seconds( array $row ): ?int {
		$created  = (int) ( $row['ts'] ?? 0 );
		$resolved = (int) ( $row['resolved_ts'] ?? 0 );
		if ( $created <= 0 || $resolved <= 0 || $resolved < $created ) {
			return null;
		}

		return $resolved - $created;
	}

	/**
	 * Pending aging roster, oldest first.
	 *
	 * @param list<array<string,mixed>>|null $requests Optional rows.
	 * @return list<array<string,mixed>>
	 */
	public static function aging_roster( ?array $requests = null, ?int $now = null ): array {
		$now      = null !== $now && $now > 0
			? $now
			: ( class_exists( Clock::class, false ) ? Clock::now() : time() );
		$pending  = self::status_pending();
		$sla      = self::sla_days();
		$requests = null !== $requests ? $requests : self::load_requests();
		$out      = array();

		foreach ( $requests as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			if ( $pending !== (string) ( $row['status'] ?? '' ) ) {
				continue;
			}
			$created = (int) ( $row['ts'] ?? 0 );
			$days    = self::days_in_limbo( $created, $now );
			if ( null === $days ) {
				continue;
			}
			$id = self::sanitize_request_id( (string) ( $row['id'] ?? '' ) );
			$out[] = array(
				'id'            => $id,
				'plugin'        => (string) ( $row['plugin'] ?? '' ),
				'user_id'       => (int) ( $row['user_id'] ?? 0 ),
				'user_login'    => (string) ( $row['user_login'] ?? '' ),
				'reason'        => (string) ( $row['reason'] ?? '' ),
				'created_ts'    => $created,
				'created_utc'   => $created > 0 ? gmdate( 'Y-m-d H:i:s', $created ) . ' UTC' : '',
				'days_in_limbo' => $days,
				'stale'         => $days >= $sla,
				'url'           => self::inbox_url( $id ),
			);
		}

		usort(
			$out,
			static function ( array $a, array $b ): int {
				$cmp = (int) ( $a['created_ts'] ?? 0 ) <=> (int) ( $b['created_ts'] ?? 0 );
				if ( 0 !== $cmp ) {
					return $cmp;
				}

				return strcmp( (string) ( $a['id'] ?? '' ), (string) ( $b['id'] ?? '' ) );
			}
		);

		return $out;
	}

	/**
	 * Pending rows over the SLA.
	 *
	 * @param list<array<string,mixed>>|null $requests Optional rows.
	 * @return list<array<string,mixed>>
	 */
	public static function stale_findings( ?array $requests = null, ?int $now = null ): array {
		$out = array();
		foreach ( self::aging_roster( $requests, $now ) as $row ) {
			if ( ! empty( $row['stale'] ) ) {
				$out[] = $row;
			}
		}

		return $out;
	}

	/**
	 * Decided ledger (created → decided), newest decided first, capped.
	 *
	 * @param list<array<string,mixed>>|null $requests Optional rows.
	 * @return list<array<string,mixed>>
	 */
	public static function decided_ledger( ?array $requests = null ): array {
		$pending  = self::status_pending();
		$requests = null !== $requests ? $requests : self::load_requests();
		$out      = array();

		foreach ( $requests as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			if ( $pending === (string) ( $row['status'] ?? '' ) ) {
				continue;
			}
			$seconds = self::decision_duration_seconds( $row );
			if ( null === $seconds ) {
				continue;
			}
			$created  = (int) ( $row['ts'] ?? 0 );
			$resolved = (int) ( $row['resolved_ts'] ?? 0 );
			$day      = defined( 'DAY_IN_SECONDS' ) ? (int) DAY_IN_SECONDS : 86400;
			$out[]    = array(
				'id'             => self::sanitize_request_id( (string) ( $row['id'] ?? '' ) ),
				'plugin'         => (string) ( $row['plugin'] ?? '' ),
				'status'         => (string) ( $row['status'] ?? '' ),
				'created_ts'     => $created,
				'decided_ts'     => $resolved,
				'duration_sec'   => $seconds,
				'duration_days'  => (int) floor( $seconds / $day ),
				'user_login'     => (string) ( $row['user_login'] ?? '' ),
			);
		}

		usort(
			$out,
			static function ( array $a, array $b ): int {
				return (int) ( $b['decided_ts'] ?? 0 ) <=> (int) ( $a['decided_ts'] ?? 0 );
			}
		);
		if ( count( $out ) > self::DECIDED_STATS_CAP ) {
			$out = array_slice( $out, 0, self::DECIDED_STATS_CAP );
		}

		return $out;
	}

	/**
	 * @param list<int> $values Sorted or unsorted durations in seconds.
	 */
	/**
	 * Admin/print copy for historical time-to-decision; avoids bare em-dash placeholders when n=0.
	 *
	 * @param array<string,mixed> $stats Stats map from snapshot().
	 */
	public static function time_to_decision_label( array $stats ): string {
		$n = (int) ( $stats['sample_count'] ?? 0 );
		if ( $n <= 0 ) {
			return __( 'Time-to-decision: no completed decisions yet.', 'handl-ai-connector-access-control' );
		}

		return sprintf(
			/* translators: 1: median days, 2: worst days, 3: sample count */
			__( 'Time-to-decision: median %1$s days, worst %2$s days (n=%3$d)', 'handl-ai-connector-access-control' ),
			null !== ( $stats['median_days'] ?? null ) ? (string) $stats['median_days'] : '—',
			null !== ( $stats['worst_days'] ?? null ) ? (string) $stats['worst_days'] : '—',
			$n
		);
	}

	public static function median_int( array $values ): ?int {
		$n = count( $values );
		if ( 0 === $n ) {
			return null;
		}
		sort( $values, SORT_NUMERIC );
		$mid = (int) floor( ( $n - 1 ) / 2 );
		if ( 0 === $n % 2 ) {
			return (int) floor( ( $values[ $mid ] + $values[ $mid + 1 ] ) / 2 );
		}

		return (int) $values[ $mid ];
	}

	/**
	 * @param list<array<string,mixed>>|null $requests Optional rows.
	 * @return array{sample_count:int,median_sec:?int,worst_sec:?int,median_days:?float,worst_days:?float}
	 */
	public static function decision_stats( ?array $requests = null ): array {
		$ledger = self::decided_ledger( $requests );
		$secs   = array();
		foreach ( $ledger as $row ) {
			$secs[] = (int) ( $row['duration_sec'] ?? 0 );
		}
		$day    = defined( 'DAY_IN_SECONDS' ) ? (int) DAY_IN_SECONDS : 86400;
		$median = self::median_int( $secs );
		$worst  = empty( $secs ) ? null : max( $secs );

		return array(
			'sample_count' => count( $secs ),
			'median_sec'   => $median,
			'worst_sec'    => $worst,
			'median_days'  => null === $median ? null : round( $median / $day, 2 ),
			'worst_days'   => null === $worst ? null : round( $worst / $day, 2 ),
		);
	}

	/**
	 * @param list<array<string,mixed>>|null $requests Optional rows.
	 * @return array<string,mixed>
	 */
	public static function snapshot( ?array $requests = null, ?int $now = null ): array {
		$now      = null !== $now && $now > 0
			? $now
			: ( class_exists( Clock::class, false ) ? Clock::now() : time() );
		$requests = null !== $requests ? $requests : self::load_requests();
		$roster   = self::aging_roster( $requests, $now );
		$stale    = self::stale_findings( $requests, $now );
		$stats    = self::decision_stats( $requests );
		$oldest   = ! empty( $stale ) ? $stale[0] : ( ! empty( $roster ) ? $roster[0] : null );
		$state    = self::get_state();

		return array(
			'enabled'       => self::is_enabled(),
			'sla_days'      => self::sla_days(),
			'pending_count' => count( $roster ),
			'stale_count'   => count( $stale ),
			'oldest'        => $oldest,
			'roster'        => $roster,
			'stale'         => $stale,
			'stats'         => $stats,
			'ledger'        => self::decided_ledger( $requests ),
			'alerted'       => ! empty( $state['alerted'] ),
			'history'       => $state['history'],
			'framing'       => self::FRAMING,
			'now'           => $now,
		);
	}

	/* ---------------------------------------------------------------------
	 * Alerts
	 * ------------------------------------------------------------------ */

	/**
	 * @return bool True when a new alert was sent.
	 */
	public static function maybe_fire_alerts( ?int $now = null ): bool {
		if ( ! self::is_enabled() ) {
			return false;
		}
		$now  = null !== $now && $now > 0
			? $now
			: ( class_exists( Clock::class, false ) ? Clock::now() : time() );
		$snap = self::snapshot( null, $now );
		$stale_count = (int) $snap['stale_count'];

		if ( $stale_count <= 0 ) {
			if ( self::is_alerted() ) {
				self::set_alerted( false );
			}

			return false;
		}

		if ( self::is_alerted() ) {
			return false;
		}

		if ( ! self::fire_alert( $snap, $now ) ) {
			return false;
		}

		$oldest = is_array( $snap['oldest'] ?? null ) ? (array) $snap['oldest'] : array();
		$state  = self::get_state();
		$state['alerted']  = true;
		$state['history']  = $state['history'] ?? array();
		$state['history'][] = array(
			'ts'          => $now,
			'stale_count' => $stale_count,
			'oldest_id'   => (string) ( $oldest['id'] ?? '' ),
			'oldest_days' => (int) ( $oldest['days_in_limbo'] ?? 0 ),
		);
		self::put_state( $state );

		return true;
	}

	/**
	 * @param array<string,mixed> $snap Snapshot.
	 */
	private static function fire_alert( array $snap, int $now ): bool {
		$policy = class_exists( Policy::class, false ) ? Policy::get_policy() : array();
		if ( ! is_array( $policy ) ) {
			$policy = array();
		}

		$email = '';
		if ( class_exists( Alerts::class, false ) && method_exists( Alerts::class, 'resolve_email' ) ) {
			$email = (string) Alerts::resolve_email( $policy );
		}
		if ( '' === $email ) {
			$email = function_exists( 'sanitize_email' )
				? sanitize_email( (string) get_option( 'admin_email' ) )
				: (string) get_option( 'admin_email' );
		}
		if ( '' === $email ) {
			return false;
		}

		$subject = self::build_subject( $snap );
		$body    = self::build_body( $snap );
		$ok      = false;
		if ( class_exists( Alerts::class, false ) && method_exists( Alerts::class, 'safe_wp_mail' ) ) {
			$ok = (bool) Alerts::safe_wp_mail( $email, $subject, $body );
		} elseif ( function_exists( 'wp_mail' ) ) {
			$ok = (bool) wp_mail( $email, $subject, $body );
		}
		self::$test_mails[] = array(
			'to'      => $email,
			'subject' => $subject,
			'body'    => $body,
		);

		if ( $ok && class_exists( Alerts::class, false ) && method_exists( Alerts::class, 'resolve_webhook' ) ) {
			$hook_url = (string) Alerts::resolve_webhook( $policy );
			if ( '' !== $hook_url && method_exists( Alerts::class, 'safe_wp_remote_post' ) ) {
				$oldest = is_array( $snap['oldest'] ?? null ) ? (array) $snap['oldest'] : array();
				Alerts::safe_wp_remote_post(
					$hook_url,
					array(
						'type'        => 'handl_aicac_limbo',
						'stale_count' => (int) ( $snap['stale_count'] ?? 0 ),
						'oldest_id'   => (string) ( $oldest['id'] ?? '' ),
						'oldest_days' => (int) ( $oldest['days_in_limbo'] ?? 0 ),
						'sla_days'    => (int) ( $snap['sla_days'] ?? self::DEFAULT_SLA_DAYS ),
						'site'        => function_exists( 'home_url' ) ? home_url( '/' ) : '',
						'ts'          => $now,
					)
				);
			}
		}

		return $ok;
	}

	/**
	 * @param array<string,mixed> $snap Snapshot.
	 */
	public static function build_subject( array $snap ): string {
		$site   = function_exists( 'get_bloginfo' )
			? wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES )
			: 'WordPress';
		$oldest = is_array( $snap['oldest'] ?? null ) ? (array) $snap['oldest'] : array();

		return sprintf(
			/* translators: 1: site name, 2: stale count, 3: oldest days */
			__( '[%1$s] [LIMBO] %2$d access request(s) waiting past SLA (oldest %3$d days)', 'handl-ai-connector-access-control' ),
			$site,
			(int) ( $snap['stale_count'] ?? 0 ),
			(int) ( $oldest['days_in_limbo'] ?? 0 )
		);
	}

	/**
	 * @param array<string,mixed> $snap Snapshot.
	 */
	public static function build_body( array $snap ): string {
		$lines  = array();
		$oldest = is_array( $snap['oldest'] ?? null ) ? (array) $snap['oldest'] : array();
		$lines[] = __( 'One or more AI access requests have been waiting longer than the configured decision SLA.', 'handl-ai-connector-access-control' );
		$lines[] = '';
		$lines[] = sprintf(
			/* translators: 1: stale count, 2: sla days */
			__( 'Over-SLA pending: %1$d (SLA %2$d days)', 'handl-ai-connector-access-control' ),
			(int) ( $snap['stale_count'] ?? 0 ),
			(int) ( $snap['sla_days'] ?? self::DEFAULT_SLA_DAYS )
		);
		$lines[] = sprintf(
			/* translators: 1: plugin, 2: days, 3: login */
			__( 'Oldest: %1$s — %2$d days in limbo (requested by %3$s)', 'handl-ai-connector-access-control' ),
			(string) ( $oldest['plugin'] ?? '' ),
			(int) ( $oldest['days_in_limbo'] ?? 0 ),
			'' !== (string) ( $oldest['user_login'] ?? '' ) ? (string) $oldest['user_login'] : ( 'user#' . (string) (int) ( $oldest['user_id'] ?? 0 ) )
		);
		$stats = is_array( $snap['stats'] ?? null ) ? (array) $snap['stats'] : array();
		if ( (int) ( $stats['sample_count'] ?? 0 ) > 0 ) {
			$lines[] = sprintf(
				/* translators: 1: median days, 2: worst days, 3: sample count */
				__( 'Historical time-to-decision: median %1$s days, worst %2$s days (n=%3$d)', 'handl-ai-connector-access-control' ),
				null !== ( $stats['median_days'] ?? null ) ? (string) $stats['median_days'] : '—',
				null !== ( $stats['worst_days'] ?? null ) ? (string) $stats['worst_days'] : '—',
				(int) $stats['sample_count']
			);
		}
		$lines[] = '';
		$lines[] = __( 'Report only — never decides, reminds, or changes request rows.', 'handl-ai-connector-access-control' );
		$url     = self::admin_url();
		$inbox   = self::inbox_url( (string) ( $oldest['id'] ?? '' ) );
		if ( '' !== $inbox ) {
			$lines[] = '';
			$lines[] = sprintf(
				/* translators: %s: inbox URL */
				__( 'Open pending inbox: %s', 'handl-ai-connector-access-control' ),
				$inbox
			);
		}
		if ( '' !== $url ) {
			$lines[] = sprintf(
				/* translators: %s: admin URL */
				__( 'Open limbo meter: %s', 'handl-ai-connector-access-control' ),
				$url
			);
		}

		return implode( "\n", $lines );
	}

	public static function admin_url(): string {
		if ( ! function_exists( 'admin_url' ) ) {
			return '';
		}

		return (string) add_query_arg( 'page', self::PAGE_SLUG, admin_url( 'admin.php' ) );
	}

	/* ---------------------------------------------------------------------
	 * CSV + print
	 * ------------------------------------------------------------------ */

	/**
	 * @param array<string,mixed>|null $snap Optional snapshot.
	 */
	public static function csv_for_snapshot( ?array $snap = null ): string {
		if ( null === $snap ) {
			$snap = self::snapshot();
		}
		$lines   = array();
		$lines[] = self::csv_line(
			array(
				'section',
				'id',
				'plugin',
				'status',
				'days_in_limbo',
				'created_utc',
				'decided_utc',
				'duration_days',
				'user_login',
				'stale',
				'url',
				'framing',
			)
		);

		$lines[] = self::csv_line(
			array(
				'summary',
				'',
				'',
				'',
				'',
				'',
				'',
				'',
				'',
				(string) (int) ( $snap['stale_count'] ?? 0 ),
				'',
				self::FRAMING,
			)
		);

		$stats = is_array( $snap['stats'] ?? null ) ? (array) $snap['stats'] : array();
		$lines[] = self::csv_line(
			array(
				'stats',
				'median_days',
				'',
				'',
				null !== ( $stats['median_days'] ?? null ) ? (string) $stats['median_days'] : '',
				'',
				'',
				null !== ( $stats['worst_days'] ?? null ) ? (string) $stats['worst_days'] : '',
				'n=' . (string) (int) ( $stats['sample_count'] ?? 0 ),
				'',
				'',
				self::FRAMING,
			)
		);

		foreach ( (array) ( $snap['roster'] ?? array() ) as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$lines[] = self::csv_line(
				array(
					'pending',
					(string) ( $row['id'] ?? '' ),
					(string) ( $row['plugin'] ?? '' ),
					'pending',
					(string) (int) ( $row['days_in_limbo'] ?? 0 ),
					(string) ( $row['created_utc'] ?? '' ),
					'',
					'',
					(string) ( $row['user_login'] ?? '' ),
					! empty( $row['stale'] ) ? 'yes' : 'no',
					(string) ( $row['url'] ?? '' ),
					self::FRAMING,
				)
			);
		}

		foreach ( (array) ( $snap['ledger'] ?? array() ) as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$decided = (int) ( $row['decided_ts'] ?? 0 );
			$lines[] = self::csv_line(
				array(
					'decided',
					(string) ( $row['id'] ?? '' ),
					(string) ( $row['plugin'] ?? '' ),
					(string) ( $row['status'] ?? '' ),
					'',
					(int) ( $row['created_ts'] ?? 0 ) > 0 ? gmdate( 'Y-m-d H:i:s', (int) $row['created_ts'] ) . ' UTC' : '',
					$decided > 0 ? gmdate( 'Y-m-d H:i:s', $decided ) . ' UTC' : '',
					(string) (int) ( $row['duration_days'] ?? 0 ),
					(string) ( $row['user_login'] ?? '' ),
					'',
					'',
					self::FRAMING,
				)
			);
		}

		return implode( "\n", $lines ) . "\n";
	}

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
	 * @param array<string,mixed> $snap Snapshot.
	 */
	public static function build_print_html( array $snap ): string {
		$html  = '<!DOCTYPE html><html><head><meta charset="utf-8"><title>';
		$html .= esc_html__( 'AI Connector limbo', 'handl-ai-connector-access-control' );
		$html .= '</title><style>body{font-family:sans-serif;margin:24px}table{border-collapse:collapse;width:100%;margin-bottom:24px}th,td{border:1px solid #ccc;padding:6px 8px;text-align:left}th{background:#f6f7f7}</style></head><body>';
		$html .= '<h1>' . esc_html__( 'AI Connector limbo', 'handl-ai-connector-access-control' ) . '</h1>';
		$html .= '<p>' . esc_html__( 'Report only — never decides, reminds, or changes request rows.', 'handl-ai-connector-access-control' ) . '</p>';

		$stats = is_array( $snap['stats'] ?? null ) ? (array) $snap['stats'] : array();
		$html .= '<ul>';
		$html .= '<li>' . esc_html(
			sprintf(
				/* translators: 1: pending count, 2: stale count, 3: sla days */
				__( 'Pending: %1$d — over SLA: %2$d (SLA %3$d days)', 'handl-ai-connector-access-control' ),
				(int) ( $snap['pending_count'] ?? 0 ),
				(int) ( $snap['stale_count'] ?? 0 ),
				(int) ( $snap['sla_days'] ?? self::DEFAULT_SLA_DAYS )
			)
		) . '</li>';
		$html .= '<li>' . esc_html( self::time_to_decision_label( $stats ) ) . '</li>';
		$html .= '</ul>';

		$html .= '<h2>' . esc_html__( 'Aging roster (oldest first)', 'handl-ai-connector-access-control' ) . '</h2>';
		$html .= '<table><thead><tr>';
		$html .= '<th>' . esc_html__( 'Plugin', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '<th>' . esc_html__( 'Requested by', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '<th>' . esc_html__( 'Days in limbo', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '<th>' . esc_html__( 'Created (UTC)', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '<th>' . esc_html__( 'Stale', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '</tr></thead><tbody>';
		$roster = (array) ( $snap['roster'] ?? array() );
		if ( empty( $roster ) ) {
			$html .= '<tr><td colspan="5">' . esc_html__( 'No pending access requests.', 'handl-ai-connector-access-control' ) . '</td></tr>';
		} else {
			foreach ( $roster as $row ) {
				if ( ! is_array( $row ) ) {
					continue;
				}
				$html .= '<tr>';
				$html .= '<td>' . esc_html( (string) ( $row['plugin'] ?? '' ) ) . '</td>';
				$html .= '<td>' . esc_html( (string) ( $row['user_login'] ?? '' ) ) . '</td>';
				$html .= '<td>' . esc_html( (string) (int) ( $row['days_in_limbo'] ?? 0 ) ) . '</td>';
				$html .= '<td>' . esc_html( (string) ( $row['created_utc'] ?? '' ) ) . '</td>';
				$html .= '<td>' . esc_html( ! empty( $row['stale'] ) ? __( 'Yes', 'handl-ai-connector-access-control' ) : __( 'No', 'handl-ai-connector-access-control' ) ) . '</td>';
				$html .= '</tr>';
			}
		}
		$html .= '</tbody></table></body></html>';

		return $html;
	}

	/* ---------------------------------------------------------------------
	 * Admin UI
	 * ------------------------------------------------------------------ */

	public static function register_menu(): void {
		if ( ! Caps::user_can_view() ) {
			return;
		}
		if ( ! function_exists( 'add_submenu_page' ) ) {
			return;
		}
		add_submenu_page(
			Admin::MENU_SLUG,
			__( 'Request limbo', 'handl-ai-connector-access-control' ),
			__( 'Limbo', 'handl-ai-connector-access-control' ),
			Caps::VIEW,
			self::PAGE_SLUG,
			array( self::class, 'render_page' )
		);
	}

	public static function render_page(): void {
		if ( ! Caps::user_can_view() ) {
			return;
		}
		$settings   = self::get_settings();
		$can_manage = Caps::user_can_manage();
		$enabled    = self::is_enabled();
		$snap       = $enabled ? self::snapshot() : null;
		$csv        = add_query_arg(
			array(
				'page'                   => self::PAGE_SLUG,
				'handl_aicac_limbo_csv'  => '1',
				'_wpnonce'               => function_exists( 'wp_create_nonce' ) ? wp_create_nonce( 'handl_aicac_limbo_csv' ) : '',
			),
			admin_url( 'admin.php' )
		);
		$print = add_query_arg(
			array(
				'page'                    => self::PAGE_SLUG,
				'handl_aicac_limbo_print' => '1',
				'_wpnonce'                => function_exists( 'wp_create_nonce' ) ? wp_create_nonce( 'handl_aicac_limbo_print' ) : '',
			),
			admin_url( 'admin.php' )
		);

		echo '<div class="wrap">';
		echo '<h1>' . esc_html__( 'Request limbo', 'handl-ai-connector-access-control' ) . '</h1>';
		echo '<p class="description">' . esc_html__( 'Measure how long AI access requests wait for a human decision. Report only — never decides, reminds, or changes request rows. Off by default.', 'handl-ai-connector-access-control' ) . '</p>';

		if ( $can_manage ) {
			$action = admin_url( 'admin-post.php' );
			echo '<form method="post" action="' . esc_url( $action ) . '">';
			echo '<input type="hidden" name="action" value="' . esc_attr( self::ACTION_SAVE ) . '" />';
			if ( function_exists( 'wp_nonce_field' ) ) {
				wp_nonce_field( self::ACTION_SAVE );
			}
			echo '<input type="hidden" name="' . esc_attr( self::POST_PRESENT ) . '" value="1" />';
			echo '<table class="form-table" role="presentation"><tbody>';
			echo '<tr><th scope="row">' . esc_html__( 'Enable limbo meter', 'handl-ai-connector-access-control' ) . '</th><td>';
			echo '<label><input type="checkbox" name="' . esc_attr( self::POST_ENABLED ) . '" value="1" ' . checked( ! empty( $settings['enabled'] ), true, false ) . ' /> ';
			echo esc_html__( 'Track pending access-request age and alert when any request exceeds the decision SLA', 'handl-ai-connector-access-control' );
			echo '</label></td></tr>';
			echo '<tr><th scope="row"><label for="handl-aicac-limbo-sla">' . esc_html__( 'Decision SLA (days)', 'handl-ai-connector-access-control' ) . '</label></th><td>';
			echo '<input name="' . esc_attr( self::POST_SLA_DAYS ) . '" id="handl-aicac-limbo-sla" type="number" min="' . esc_attr( (string) self::MIN_SLA_DAYS ) . '" max="' . esc_attr( (string) self::MAX_SLA_DAYS ) . '" step="1" value="' . esc_attr( (string) (int) $settings['sla_days'] ) . '" class="small-text" />';
			echo '<p class="description">' . esc_html__( 'Default 7. Pending requests older than this become stale findings.', 'handl-ai-connector-access-control' ) . '</p>';
			echo '</td></tr></tbody></table>';
			submit_button( __( 'Save limbo settings', 'handl-ai-connector-access-control' ) );
			echo '</form>';
		}

		if ( ! $enabled || ! is_array( $snap ) ) {
			echo '<p>' . esc_html__( 'Limbo meter is off. Enable it to measure how long access requests wait for a decision.', 'handl-ai-connector-access-control' ) . '</p>';
			echo '</div>';

			return;
		}

		echo '<p><strong>' . esc_html__( 'Report only — never decides, reminds, or changes request rows.', 'handl-ai-connector-access-control' ) . '</strong></p>';

		$stats  = (array) $snap['stats'];
		$oldest = is_array( $snap['oldest'] ?? null ) ? (array) $snap['oldest'] : array();
		echo '<ul>';
		echo '<li>' . esc_html(
			sprintf(
				/* translators: 1: pending, 2: stale, 3: sla */
				__( 'Pending: %1$d — over SLA: %2$d (SLA %3$d days)', 'handl-ai-connector-access-control' ),
				(int) $snap['pending_count'],
				(int) $snap['stale_count'],
				(int) $snap['sla_days']
			)
		) . '</li>';
		echo '<li>' . esc_html( self::time_to_decision_label( $stats ) ) . '</li>';
		if ( (int) $snap['stale_count'] > 0 && ! empty( $oldest ) ) {
			echo '<li><strong>' . esc_html(
				sprintf(
					/* translators: 1: plugin, 2: days */
					__( 'Oldest over-SLA: %1$s (%2$d days)', 'handl-ai-connector-access-control' ),
					(string) ( $oldest['plugin'] ?? '' ),
					(int) ( $oldest['days_in_limbo'] ?? 0 )
				)
			) . '</strong></li>';
		}
		echo '</ul>';

		$inbox = self::inbox_url();
		echo '<p>';
		if ( '' !== $inbox ) {
			echo '<a href="' . esc_url( $inbox ) . '">' . esc_html__( 'Open pending inbox', 'handl-ai-connector-access-control' ) . '</a> ';
		}
		echo '<a class="button" href="' . esc_url( $csv ) . '">' . esc_html__( 'Download CSV', 'handl-ai-connector-access-control' ) . '</a> ';
		echo '<a class="button" href="' . esc_url( $print ) . '" target="_blank" rel="noopener noreferrer">' . esc_html__( 'Print / PDF view', 'handl-ai-connector-access-control' ) . '</a>';
		echo '</p>';

		echo '<h2>' . esc_html__( 'Aging roster (oldest first)', 'handl-ai-connector-access-control' ) . '</h2>';
		if ( empty( $snap['roster'] ) ) {
			echo '<p>' . esc_html__( 'No pending access requests.', 'handl-ai-connector-access-control' ) . '</p>';
		} else {
			echo '<table class="widefat striped"><thead><tr>';
			echo '<th>' . esc_html__( 'Plugin', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Requested by', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Days in limbo', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Created (UTC)', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Stale', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Inbox', 'handl-ai-connector-access-control' ) . '</th>';
			echo '</tr></thead><tbody>';
			foreach ( $snap['roster'] as $row ) {
				echo '<tr>';
				echo '<td><code>' . esc_html( (string) $row['plugin'] ) . '</code></td>';
				echo '<td>' . esc_html( (string) $row['user_login'] ) . '</td>';
				echo '<td>' . esc_html( (string) (int) $row['days_in_limbo'] ) . '</td>';
				echo '<td>' . esc_html( (string) $row['created_utc'] ) . '</td>';
				echo '<td>' . esc_html( ! empty( $row['stale'] ) ? __( 'Yes', 'handl-ai-connector-access-control' ) : __( 'No', 'handl-ai-connector-access-control' ) ) . '</td>';
				echo '<td>';
				if ( '' !== (string) $row['url'] ) {
					echo '<a href="' . esc_url( (string) $row['url'] ) . '">' . esc_html__( 'Open', 'handl-ai-connector-access-control' ) . '</a>';
				} else {
					echo '&mdash;';
				}
				echo '</td>';
				echo '</tr>';
			}
			echo '</tbody></table>';
		}

		echo '</div>';
	}

	public static function maybe_handle_csv(): void {
		if ( empty( $_GET['handl_aicac_limbo_csv'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			return;
		}
		$page = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( (string) $_GET['page'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( self::PAGE_SLUG !== $page ) {
			return;
		}
		if ( ! Caps::user_can_view() || ! self::is_enabled() ) {
			return;
		}
		$nonce = isset( $_GET['_wpnonce'] ) ? (string) wp_unslash( $_GET['_wpnonce'] ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( ! function_exists( 'wp_verify_nonce' ) || ! wp_verify_nonce( $nonce, 'handl_aicac_limbo_csv' ) ) {
			return;
		}
		$csv = self::csv_for_snapshot();
		if ( function_exists( 'nocache_headers' ) ) {
			nocache_headers();
		}
		header( 'Content-Type: text/csv; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename=handl-aicac-limbo.csv' );
		echo $csv; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- CSV download.
		exit;
	}

	public static function maybe_handle_print(): void {
		if ( empty( $_GET['handl_aicac_limbo_print'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			return;
		}
		$page = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( (string) $_GET['page'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( self::PAGE_SLUG !== $page ) {
			return;
		}
		if ( ! Caps::user_can_view() || ! self::is_enabled() ) {
			return;
		}
		$nonce = isset( $_GET['_wpnonce'] ) ? (string) wp_unslash( $_GET['_wpnonce'] ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( ! function_exists( 'wp_verify_nonce' ) || ! wp_verify_nonce( $nonce, 'handl_aicac_limbo_print' ) ) {
			return;
		}
		if ( function_exists( 'nocache_headers' ) ) {
			nocache_headers();
		}
		echo self::build_print_html( self::snapshot() ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped in builder.
		exit;
	}

	public static function handle_save(): void {
		if ( ! Caps::user_can_manage() ) {
			wp_die( esc_html__( 'You do not have permission to save limbo settings.', 'handl-ai-connector-access-control' ) );
		}
		check_admin_referer( self::ACTION_SAVE );
		if ( empty( $_POST[ self::POST_PRESENT ] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing
			wp_die( esc_html__( 'Security check failed. Go back, reload the page, and try again.', 'handl-ai-connector-access-control' ) );
		}
		$days_raw = isset( $_POST[ self::POST_SLA_DAYS ] ) ? wp_unslash( (string) $_POST[ self::POST_SLA_DAYS ] ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing
		self::save_settings(
			array(
				'enabled'  => ! empty( $_POST[ self::POST_ENABLED ] ), // phpcs:ignore WordPress.Security.NonceVerification.Missing
				'sla_days' => self::sanitize_sla_days( '' !== $days_raw ? $days_raw : self::DEFAULT_SLA_DAYS ),
			)
		);
		$redirect = self::admin_url();
		if ( '' === $redirect && function_exists( 'admin_url' ) ) {
			$redirect = admin_url( 'admin.php?page=' . self::PAGE_SLUG );
		}
		wp_safe_redirect( $redirect );
		exit;
	}

	public static function register_cli(): void {
		if ( ! defined( 'WP_CLI' ) || ! WP_CLI ) {
			return;
		}
		if ( ! class_exists( '\\WP_CLI' ) ) {
			return;
		}
		\WP_CLI::add_command( 'handl-aicac limbo', CLI_Limbo::class );
	}
}

/**
 * WP-CLI: wp handl-aicac limbo status|export
 */
final class CLI_Limbo {

	/**
	 * Show limbo status. Exits non-zero on any over-SLA pending request.
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
		$format = isset( $assoc_args['format'] ) ? (string) $assoc_args['format'] : 'table';

		if ( ! Limbo::is_enabled() ) {
			\WP_CLI::log(
				sprintf(
					'enabled=no sla_days=%d framing=%s',
					(int) Limbo::get_settings()['sla_days'],
					Limbo::FRAMING
				)
			);
			\WP_CLI::log( 'Limbo meter is disabled.' );

			return;
		}

		$snap  = Limbo::snapshot();
		$stats = (array) $snap['stats'];
		$oldest = is_array( $snap['oldest'] ?? null ) ? (array) $snap['oldest'] : array();

		\WP_CLI::log(
			sprintf(
				'enabled=yes sla_days=%d pending=%d stale=%d median_days=%s worst_days=%s alerted=%s framing=%s',
				(int) $snap['sla_days'],
				(int) $snap['pending_count'],
				(int) $snap['stale_count'],
				null !== ( $stats['median_days'] ?? null ) ? (string) $stats['median_days'] : 'n/a',
				null !== ( $stats['worst_days'] ?? null ) ? (string) $stats['worst_days'] : 'n/a',
				! empty( $snap['alerted'] ) ? 'yes' : 'no',
				Limbo::FRAMING
			)
		);
		if ( (int) $snap['stale_count'] > 0 && ! empty( $oldest ) ) {
			\WP_CLI::log(
				sprintf(
					'oldest_id=%s oldest_plugin=%s oldest_days=%d',
					(string) ( $oldest['id'] ?? '' ),
					(string) ( $oldest['plugin'] ?? '' ),
					(int) ( $oldest['days_in_limbo'] ?? 0 )
				)
			);
		}

		$display = array();
		foreach ( (array) $snap['roster'] as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$display[] = array(
				'id'            => (string) ( $row['id'] ?? '' ),
				'plugin'        => (string) ( $row['plugin'] ?? '' ),
				'days_in_limbo' => (int) ( $row['days_in_limbo'] ?? 0 ),
				'stale'         => ! empty( $row['stale'] ) ? 'yes' : 'no',
				'user_login'    => (string) ( $row['user_login'] ?? '' ),
			);
		}
		if ( ! empty( $display ) ) {
			if ( 'json' === $format ) {
				\WP_CLI::print_value( $display, array( 'format' => 'json' ) );
			} elseif ( class_exists( '\\WP_CLI\\Utils' ) ) {
				\WP_CLI\Utils\format_items( 'table', $display, array( 'id', 'plugin', 'days_in_limbo', 'stale', 'user_login' ) );
			} else {
				foreach ( $display as $row ) {
					\WP_CLI::log( implode( "\t", $row ) );
				}
			}
		}

		if ( (int) $snap['stale_count'] > 0 ) {
			\WP_CLI::error( 'Over-SLA pending access requests present.', false );
		}
	}

	/**
	 * Export the limbo report as CSV.
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
		$csv = Limbo::csv_for_snapshot();
		if ( ! empty( $assoc_args['porcelain'] ) ) {
			echo $csv; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- CLI CSV.
			return;
		}
		\WP_CLI::print_value( $csv, array( 'format' => 'csv' ) );
	}
}
