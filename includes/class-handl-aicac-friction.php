<?php
/**
 * AICAC-FRICTION (#395): deny-friction hotspot report.
 *
 * Read-only aggregation over the activity log (30/90-day windows): top denied
 * plugin+user pairs, repeat-deny streaks (default 10 denies / rolling 7 days),
 * deny reason mix, first-seen vs still-denying age. Hotspot roster with deep
 * links to the owning rule/budget/cap screen (revisit only — never changes
 * rules). Class_exists-guarded cross-ref to ignored/denied Access_Requests and
 * later Shadow_AI sightings. One alert per pair+window on first streak
 * crossing via Alerts (own _alerted ledger). Print + CSV + WP-CLI friction
 * status|export (status non-zero when any streak is active). Informational
 * only — never denies. OFF by default. Own two options. No
 * admin.php/policy.php/cost.php/logger/rate-cap/shadow-ai/access-request edits.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Deny-friction hotspot report from logged denials.
 */
final class Friction {

	public const SETTINGS_OPTION = 'handl_aicac_friction';

	public const ALERTED_OPTION = 'handl_aicac_friction_alerted';

	public const PAGE_SLUG = 'handl-aicac-friction';

	public const FILTER_STREAK_THRESHOLD = 'handl_aicac_friction_streak_threshold';

	public const ALERT_KIND = 'friction';

	public const DEFAULT_STREAK_THRESHOLD = 10;

	public const STREAK_DAYS = 7;

	/** @var list<int> */
	public const WINDOWS = array( 30, 90 );

	public const UNKNOWN_PLUGIN = '(unknown)';

	public const POST_PRESENT = 'handl_aicac_friction_present';

	public const POST_ENABLED = 'handl_aicac_friction_enabled';

	public const POST_THRESHOLD = 'handl_aicac_friction_streak_threshold';

	public const ACTION_SAVE = 'handl_aicac_friction_save';

	/** @var bool */
	private static $registered = false;

	/** @var list<array<string,mixed>> */
	private static $test_mails = array();

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
		self::$registered = false;
		self::$test_mails = array();
		delete_option( self::SETTINGS_OPTION );
		delete_option( self::ALERTED_OPTION );
	}

	/**
	 * @return list<array<string,mixed>>
	 */
	public static function test_mails(): array {
		return self::$test_mails;
	}

	/**
	 * @return array{enabled:bool,streak_threshold:int}
	 */
	public static function defaults(): array {
		return array(
			'enabled'          => false,
			'streak_threshold' => self::DEFAULT_STREAK_THRESHOLD,
		);
	}

	/**
	 * @return array{enabled:bool,streak_threshold:int}
	 */
	public static function get_settings(): array {
		return self::sanitize_settings( get_option( self::SETTINGS_OPTION, array() ) );
	}

	/**
	 * @param mixed $raw Raw settings.
	 * @return array{enabled:bool,streak_threshold:int}
	 */
	public static function sanitize_settings( $raw ): array {
		$defaults = self::defaults();
		if ( ! is_array( $raw ) ) {
			return $defaults;
		}

		return array(
			'enabled'          => ! empty( $raw['enabled'] ),
			'streak_threshold' => self::sanitize_streak_threshold( $raw['streak_threshold'] ?? $defaults['streak_threshold'] ),
		);
	}

	/**
	 * @param mixed $raw Raw threshold.
	 */
	public static function sanitize_streak_threshold( $raw ): int {
		if ( ! is_numeric( $raw ) ) {
			return self::DEFAULT_STREAK_THRESHOLD;
		}
		$v = (int) $raw;
		if ( $v < 2 ) {
			$v = 2;
		}
		if ( $v > 1000 ) {
			$v = 1000;
		}

		return $v;
	}

	/**
	 * Effective streak threshold after filter.
	 */
	public static function streak_threshold(): int {
		$settings = self::get_settings();
		$base     = (int) $settings['streak_threshold'];
		if ( function_exists( 'apply_filters' ) ) {
			$filtered = apply_filters( self::FILTER_STREAK_THRESHOLD, $base );
			return self::sanitize_streak_threshold( $filtered );
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

	public static function sanitize_plugin( string $raw ): string {
		$raw = trim( $raw );
		if ( '' === $raw ) {
			return self::UNKNOWN_PLUGIN;
		}
		$raw = preg_replace( '/[\r\n\t]+/', ' ', $raw ) ?? $raw;
		if ( function_exists( 'mb_substr' ) ) {
			$raw = mb_substr( $raw, 0, 190 );
		} else {
			$raw = substr( $raw, 0, 190 );
		}

		return '' !== $raw ? $raw : self::UNKNOWN_PLUGIN;
	}

	public static function sanitize_user_id( $raw ): int {
		if ( ! is_numeric( $raw ) ) {
			return 0;
		}
		$v = (int) $raw;

		return $v > 0 ? $v : 0;
	}

	/**
	 * Bucket a denial_reason into rule|budget|rate_cap|policy.
	 */
	public static function reason_bucket( string $raw ): string {
		$r = strtolower( trim( $raw ) );
		if ( 'budget' === $r ) {
			return 'budget';
		}
		if ( 'rate_cap' === $r || ( class_exists( Rate_Cap::class, false ) && Rate_Cap::REASON === $r ) ) {
			return 'rate_cap';
		}
		$ruleish = array(
			'plugin',
			'role',
			'capability_family',
			'tool_armed',
			'unknown_operation',
			'kill_switch',
			'quiet_hours',
			'new_plugin',
			'break_glass',
		);
		if ( in_array( $r, $ruleish, true ) ) {
			return 'rule';
		}
		if ( '' === $r ) {
			return 'policy';
		}

		return 'policy';
	}

	/**
	 * Deep link to the owning screen for a reason bucket (revisit only).
	 */
	public static function deep_link_for_bucket( string $bucket ): string {
		if ( ! function_exists( 'admin_url' ) ) {
			return '';
		}
		$page = 'handl-aicac-rules';
		if ( 'budget' === $bucket || 'rate_cap' === $bucket || 'policy' === $bucket ) {
			$page = 'handl-aicac-protections';
		}

		return (string) add_query_arg( 'page', $page, admin_url( 'admin.php' ) );
	}

	/**
	 * @return list<array<string,mixed>>
	 */
	public static function load_log( ?array $log = null ): array {
		if ( null === $log ) {
			$log = class_exists( Policy::class, false ) ? Policy::get_retained_log() : array();
		}
		if ( ! is_array( $log ) ) {
			return array();
		}
		if ( class_exists( Demo_Mode::class, false ) ) {
			$log = Demo_Mode::without_demo( $log );
		}
		$out = array();
		foreach ( $log as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			if ( class_exists( Selftest::class, false ) && Selftest::is_synthetic_row( $row ) ) {
				continue;
			}
			$out[] = $row;
		}

		return $out;
	}

	/**
	 * True when the row is a gate deny (not shadow observe / access admin).
	 *
	 * @param array<string,mixed> $row Log row.
	 */
	public static function is_deny_row( array $row ): bool {
		if ( 'deny' !== (string) ( $row['decision'] ?? '' ) ) {
			return false;
		}
		$channel = isset( $row['channel'] ) ? (string) $row['channel'] : '';
		if ( 'direct_http' === $channel ) {
			return false;
		}

		return true;
	}

	/**
	 * Aggregate deny friction for one report window.
	 *
	 * @param list<array<string,mixed>>|null $log Optional log.
	 * @return array{
	 *   window:int,
	 *   total_denies:int,
	 *   active_streaks:int,
	 *   pairs:list<array<string,mixed>>,
	 *   framing:string
	 * }
	 */
	public static function analyze_window( int $window_days, ?array $log = null, ?int $now = null ): array {
		$window_days = in_array( $window_days, self::WINDOWS, true ) ? $window_days : 30;
		$now         = null !== $now && $now > 0 ? $now : ( class_exists( Clock::class, false ) ? Clock::now() : time() );
		$day         = defined( 'DAY_IN_SECONDS' ) ? (int) DAY_IN_SECONDS : 86400;
		$cut         = $now - ( ( $window_days - 1 ) * $day );
		$streak_cut  = $now - ( ( self::STREAK_DAYS - 1 ) * $day );
		$threshold   = self::streak_threshold();
		$log         = self::load_log( $log );

		$by_pair = array();

		foreach ( $log as $row ) {
			if ( ! self::is_deny_row( $row ) ) {
				continue;
			}
			$ts = isset( $row['ts'] ) ? (int) $row['ts'] : 0;
			if ( $ts <= 0 ) {
				$ts = $now;
			}
			if ( $ts < $cut ) {
				continue;
			}
			$plugin = self::sanitize_plugin( (string) ( $row['plugin'] ?? '' ) );
			$user   = self::sanitize_user_id( $row['user_id'] ?? 0 );
			$key    = $plugin . '|' . (string) $user;
			$count  = isset( $row['count'] ) ? max( 1, (int) $row['count'] ) : 1;
			$bucket = self::reason_bucket( (string) ( $row['denial_reason'] ?? '' ) );
			$first  = isset( $row['first_ts'] ) ? (int) $row['first_ts'] : $ts;
			if ( $first <= 0 ) {
				$first = $ts;
			}

			if ( ! isset( $by_pair[ $key ] ) ) {
				$by_pair[ $key ] = array(
					'plugin'       => $plugin,
					'user_id'      => $user,
					'denies'       => 0,
					'streak_denies'=> 0,
					'reasons'      => array(
						'rule'     => 0,
						'budget'   => 0,
						'rate_cap' => 0,
						'policy'   => 0,
					),
					'first_ts'     => $first,
					'last_ts'      => $ts,
					'top_reason'   => 'policy',
				);
			}
			$cell =& $by_pair[ $key ];
			$cell['denies'] += $count;
			if ( $ts >= $streak_cut ) {
				$cell['streak_denies'] += $count;
			}
			$cell['reasons'][ $bucket ] = (int) $cell['reasons'][ $bucket ] + $count;
			if ( $first < (int) $cell['first_ts'] ) {
				$cell['first_ts'] = $first;
			}
			if ( $ts > (int) $cell['last_ts'] ) {
				$cell['last_ts'] = $ts;
			}
			unset( $cell );
		}

		$access_flags = self::access_request_flags( array_keys( $by_pair ) );
		$shadow_flags = self::shadow_ai_flags( $by_pair, $log, $now );

		$pairs         = array();
		$total_denies  = 0;
		$active_streaks = 0;
		foreach ( $by_pair as $key => $cell ) {
			$total_denies += (int) $cell['denies'];
			$top_reason    = 'policy';
			$top_n         = -1;
			foreach ( (array) $cell['reasons'] as $bucket => $n ) {
				if ( (int) $n > $top_n ) {
					$top_n      = (int) $n;
					$top_reason = (string) $bucket;
				}
			}
			$streak_active = (int) $cell['streak_denies'] >= $threshold;
			if ( $streak_active ) {
				++$active_streaks;
			}
			$age_days = max( 0, (int) floor( ( $now - (int) $cell['first_ts'] ) / $day ) );
			$pairs[]  = array(
				'window'            => $window_days,
				'plugin'            => (string) $cell['plugin'],
				'user_id'           => (int) $cell['user_id'],
				'denies'            => (int) $cell['denies'],
				'streak_denies'     => (int) $cell['streak_denies'],
				'streak_days'       => self::STREAK_DAYS,
				'streak_threshold'  => $threshold,
				'streak_active'     => $streak_active,
				'reason_mix'        => $cell['reasons'],
				'top_reason'        => $top_reason,
				'first_ts'          => (int) $cell['first_ts'],
				'last_ts'           => (int) $cell['last_ts'],
				'age_days'          => $age_days,
				'deep_link'         => self::deep_link_for_bucket( $top_reason ),
				'access_request'    => ! empty( $access_flags[ $key ] ),
				'shadow_ai_later'   => ! empty( $shadow_flags[ $key ] ),
				'framing'           => 'revisit_only_never_auto_relax',
			);
		}

		usort(
			$pairs,
			static function ( array $a, array $b ): int {
				if ( (int) $a['streak_denies'] !== (int) $b['streak_denies'] ) {
					return ( (int) $b['streak_denies'] <=> (int) $a['streak_denies'] );
				}
				if ( (int) $a['denies'] !== (int) $b['denies'] ) {
					return ( (int) $b['denies'] <=> (int) $a['denies'] );
				}

				return strcmp( (string) $a['plugin'], (string) $b['plugin'] );
			}
		);

		return array(
			'window'          => $window_days,
			'total_denies'    => $total_denies,
			'active_streaks'  => $active_streaks,
			'pairs'           => $pairs,
			'framing'         => 'revisit_only_never_auto_relax',
		);
	}

	/**
	 * @param list<string> $pair_keys plugin|user_id keys.
	 * @return array<string,bool>
	 */
	public static function access_request_flags( array $pair_keys ): array {
		$out = array();
		foreach ( $pair_keys as $key ) {
			$out[ (string) $key ] = false;
		}
		if ( ! class_exists( Access_Request::class, false ) ) {
			return $out;
		}
		$raw = get_option( Access_Request::OPTION_KEY, array() );
		if ( ! is_array( $raw ) ) {
			return $out;
		}
		foreach ( $raw as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$status = (string) ( $row['status'] ?? '' );
			// Ignored / denied: denied outright, or still pending (never acted on).
			if ( Access_Request::STATUS_DENIED !== $status && Access_Request::STATUS_PENDING !== $status ) {
				continue;
			}
			$plugin = self::sanitize_plugin( (string) ( $row['plugin'] ?? '' ) );
			$user   = self::sanitize_user_id( $row['user_id'] ?? 0 );
			$key    = $plugin . '|' . (string) $user;
			if ( array_key_exists( $key, $out ) ) {
				$out[ $key ] = true;
			}
		}

		return $out;
	}

	/**
	 * Flag hotspot plugins that later appear in Shadow_AI (direct_http) observations.
	 *
	 * @param array<string,array<string,mixed>> $by_pair Pair cells.
	 * @param list<array<string,mixed>>         $log     Full log.
	 * @return array<string,bool>
	 */
	public static function shadow_ai_flags( array $by_pair, array $log, int $now ): array {
		$out = array();
		foreach ( array_keys( $by_pair ) as $key ) {
			$out[ (string) $key ] = false;
		}
		if ( ! class_exists( Shadow_AI::class, false ) ) {
			return $out;
		}
		$first_by_plugin = array();
		foreach ( $by_pair as $key => $cell ) {
			$plugin = (string) ( $cell['plugin'] ?? '' );
			$first  = (int) ( $cell['first_ts'] ?? 0 );
			if ( ! isset( $first_by_plugin[ $plugin ] ) || $first < $first_by_plugin[ $plugin ] ) {
				$first_by_plugin[ $plugin ] = $first;
			}
		}
		foreach ( $log as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			if ( 'direct_http' !== (string) ( $row['channel'] ?? '' ) ) {
				continue;
			}
			$plugin = self::sanitize_plugin( (string) ( $row['plugin'] ?? '' ) );
			if ( ! isset( $first_by_plugin[ $plugin ] ) ) {
				continue;
			}
			$ts = isset( $row['ts'] ) ? (int) $row['ts'] : 0;
			if ( $ts <= 0 ) {
				$ts = $now;
			}
			if ( $ts <= $first_by_plugin[ $plugin ] ) {
				continue;
			}
			foreach ( $by_pair as $key => $cell ) {
				if ( (string) ( $cell['plugin'] ?? '' ) === $plugin ) {
					$out[ (string) $key ] = true;
				}
			}
		}

		return $out;
	}

	/**
	 * Full snapshot for 30d + 90d.
	 *
	 * @param list<array<string,mixed>>|null $log Optional log.
	 * @return array{windows:array<int,array<string,mixed>>,streak_threshold:int,framing:string}
	 */
	public static function snapshot( ?array $log = null, ?int $now = null ): array {
		$log = self::load_log( $log );
		$windows = array();
		foreach ( self::WINDOWS as $days ) {
			$windows[ $days ] = self::analyze_window( $days, $log, $now );
		}

		return array(
			'windows'          => $windows,
			'streak_threshold' => self::streak_threshold(),
			'framing'          => 'revisit_only_never_auto_relax',
		);
	}

	/**
	 * Flattened hotspot roster (one row per pair per window).
	 *
	 * @return list<array<string,mixed>>
	 */
	public static function roster( ?array $log = null, ?int $now = null ): array {
		$snap = self::snapshot( $log, $now );
		$rows = array();
		foreach ( $snap['windows'] as $analysis ) {
			foreach ( (array) ( $analysis['pairs'] ?? array() ) as $pair ) {
				$rows[] = $pair;
			}
		}

		return $rows;
	}

	/**
	 * Format reason mix for display/CSV.
	 *
	 * @param array<string,int> $mix Mix.
	 */
	public static function format_reason_mix( array $mix ): string {
		$parts = array();
		foreach ( array( 'rule', 'budget', 'rate_cap', 'policy' ) as $k ) {
			$n = (int) ( $mix[ $k ] ?? 0 );
			if ( $n > 0 ) {
				$parts[] = $k . '=' . (string) $n;
			}
		}

		return implode( ';', $parts );
	}

	/**
	 * @return array<string,bool>
	 */
	public static function get_alerted(): array {
		$raw = get_option( self::ALERTED_OPTION, array() );
		if ( ! is_array( $raw ) ) {
			return array();
		}
		$out = array();
		foreach ( $raw as $fp => $flag ) {
			$fp = self::sanitize_fingerprint( (string) $fp );
			if ( '' === $fp || empty( $flag ) ) {
				continue;
			}
			$out[ $fp ] = true;
		}

		return $out;
	}

	/**
	 * @param array<string,bool> $alerted Fingerprints.
	 */
	public static function put_alerted( array $alerted ): void {
		$clean = array();
		foreach ( $alerted as $fp => $flag ) {
			$fp = self::sanitize_fingerprint( (string) $fp );
			if ( '' === $fp || empty( $flag ) ) {
				continue;
			}
			$clean[ $fp ] = true;
		}
		if ( empty( $clean ) ) {
			delete_option( self::ALERTED_OPTION );

			return;
		}
		update_option( self::ALERTED_OPTION, $clean, false );
	}

	public static function sanitize_fingerprint( string $raw ): string {
		$raw = strtolower( trim( $raw ) );
		$raw = preg_replace( '/[^a-z0-9_|.:\\/-]/', '', $raw ) ?? '';

		return substr( $raw, 0, 160 );
	}

	public static function alert_fingerprint( string $plugin, int $user_id, int $window ): string {
		return self::sanitize_fingerprint(
			self::sanitize_plugin( $plugin ) . '|' . (string) self::sanitize_user_id( $user_id ) . '|' . (string) (int) $window
		);
	}

	/**
	 * Fire at most one alert per pair+window when streak crosses threshold.
	 *
	 * @param list<array<string,mixed>>|null $log Optional log.
	 * @return list<string> Fingerprints newly alerted.
	 */
	public static function maybe_fire_alerts( ?array $log = null, ?int $now = null ): array {
		if ( ! self::is_enabled() ) {
			return array();
		}
		$now     = null !== $now && $now > 0 ? $now : ( class_exists( Clock::class, false ) ? Clock::now() : time() );
		$snap    = self::snapshot( $log, $now );
		$alerted = self::get_alerted();
		$fired   = array();

		foreach ( $snap['windows'] as $window => $analysis ) {
			foreach ( (array) ( $analysis['pairs'] ?? array() ) as $pair ) {
				if ( empty( $pair['streak_active'] ) ) {
					continue;
				}
				$plugin = (string) ( $pair['plugin'] ?? '' );
				$user   = (int) ( $pair['user_id'] ?? 0 );
				$fp     = self::alert_fingerprint( $plugin, $user, (int) $window );
				if ( isset( $alerted[ $fp ] ) ) {
					continue;
				}
				$payload = array(
					'plugin'           => $plugin,
					'user_id'          => $user,
					'window'           => (int) $window,
					'streak_denies'    => (int) ( $pair['streak_denies'] ?? 0 ),
					'streak_threshold' => (int) ( $pair['streak_threshold'] ?? self::streak_threshold() ),
					'top_reason'       => (string) ( $pair['top_reason'] ?? 'policy' ),
					'deep_link'        => (string) ( $pair['deep_link'] ?? '' ),
					'access_request'   => ! empty( $pair['access_request'] ),
					'shadow_ai_later'  => ! empty( $pair['shadow_ai_later'] ),
				);
				if ( ! self::fire_alert( $payload, $now ) ) {
					continue;
				}
				$alerted[ $fp ] = true;
				$fired[]        = $fp;
			}
		}
		if ( ! empty( $fired ) ) {
			self::put_alerted( $alerted );
		}

		return $fired;
	}

	/**
	 * @param array<string,mixed> $payload Payload.
	 */
	private static function fire_alert( array $payload, int $now ): bool {
		$policy = class_exists( Policy::class, false ) ? Policy::get_policy() : array();
		if ( ! is_array( $policy ) ) {
			$policy = array();
		}
		$email = '';
		if ( class_exists( Alerts::class, false ) && method_exists( Alerts::class, 'resolve_email' ) ) {
			$email = (string) Alerts::resolve_email( $policy );
		}
		if ( '' === $email ) {
			return false;
		}

		$subject = self::build_subject( $payload );
		$body    = self::build_body( $payload );
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

		if ( class_exists( Alerts::class, false ) && method_exists( Alerts::class, 'resolve_webhook' ) ) {
			$hook_url = (string) Alerts::resolve_webhook( $policy );
			if ( '' !== $hook_url && method_exists( Alerts::class, 'safe_wp_remote_post' ) ) {
				Alerts::safe_wp_remote_post(
					$hook_url,
					array(
						'type'             => 'handl_aicac_friction',
						'plugin'           => (string) ( $payload['plugin'] ?? '' ),
						'user_id'          => (int) ( $payload['user_id'] ?? 0 ),
						'window'           => (int) ( $payload['window'] ?? 0 ),
						'streak_denies'    => (int) ( $payload['streak_denies'] ?? 0 ),
						'streak_threshold' => (int) ( $payload['streak_threshold'] ?? 0 ),
						'top_reason'       => (string) ( $payload['top_reason'] ?? '' ),
						'site'             => function_exists( 'home_url' ) ? home_url( '/' ) : '',
						'ts'               => $now,
					)
				);
			}
		}

		return $ok;
	}

	/**
	 * @param array<string,mixed> $payload Payload.
	 */
	public static function build_subject( array $payload ): string {
		$site = function_exists( 'get_bloginfo' )
			? wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES )
			: 'WordPress';

		return sprintf(
			/* translators: 1: site name, 2: plugin basename, 3: user id */
			__( '[%1$s] AI deny friction streak: %2$s / user %3$d', 'handl-ai-connector-access-control' ),
			$site,
			(string) ( $payload['plugin'] ?? '' ),
			(int) ( $payload['user_id'] ?? 0 )
		);
	}

	/**
	 * @param array<string,mixed> $payload Payload.
	 */
	public static function build_body( array $payload ): string {
		$lines   = array();
		$lines[] = __( 'A plugin+user pair crossed the deny-friction streak threshold. Revisit the owning rule — this alert never auto-relaxes access.', 'handl-ai-connector-access-control' );
		$lines[] = '';
		$lines[] = sprintf(
			/* translators: %s: plugin basename */
			__( 'Plugin: %s', 'handl-ai-connector-access-control' ),
			(string) ( $payload['plugin'] ?? '' )
		);
		$lines[] = sprintf(
			/* translators: %d: WordPress user id */
			__( 'User ID: %d', 'handl-ai-connector-access-control' ),
			(int) ( $payload['user_id'] ?? 0 )
		);
		$lines[] = sprintf(
			/* translators: 1: streak deny count, 2: threshold, 3: streak days */
			__( 'Streak: %1$d denies (threshold %2$d / %3$d days)', 'handl-ai-connector-access-control' ),
			(int) ( $payload['streak_denies'] ?? 0 ),
			(int) ( $payload['streak_threshold'] ?? self::DEFAULT_STREAK_THRESHOLD ),
			self::STREAK_DAYS
		);
		$lines[] = sprintf(
			/* translators: %s: reason bucket */
			__( 'Top deny reason: %s', 'handl-ai-connector-access-control' ),
			(string) ( $payload['top_reason'] ?? 'policy' )
		);
		if ( ! empty( $payload['access_request'] ) ) {
			$lines[] = __( 'Cross-ref: an Access Request for this pair was ignored or denied.', 'handl-ai-connector-access-control' );
		}
		if ( ! empty( $payload['shadow_ai_later'] ) ) {
			$lines[] = __( 'Cross-ref: this plugin later appeared in Shadow AI observations (possible route-around).', 'handl-ai-connector-access-control' );
		}
		$lines[] = '';
		$lines[] = __( 'Informational only — this alert never denies or relaxes AI calls.', 'handl-ai-connector-access-control' );
		$url     = (string) ( $payload['deep_link'] ?? '' );
		if ( '' === $url ) {
			$url = self::admin_url();
		}
		if ( '' !== $url ) {
			$lines[] = '';
			$lines[] = sprintf(
				/* translators: %s: admin URL */
				__( 'Revisit owning screen: %s', 'handl-ai-connector-access-control' ),
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

	/**
	 * @param list<array<string,mixed>>|null $rows Optional roster.
	 */
	public static function csv_for_roster( ?array $rows = null ): string {
		if ( null === $rows ) {
			$rows = self::roster();
		}
		$lines   = array();
		$lines[] = self::csv_line(
			array(
				'window_days',
				'plugin',
				'user_id',
				'denies',
				'streak_denies',
				'streak_days',
				'streak_threshold',
				'streak_active',
				'top_reason',
				'reason_mix',
				'age_days',
				'deep_link',
				'access_request',
				'shadow_ai_later',
				'framing',
			)
		);
		foreach ( $rows as $row ) {
			$mix = is_array( $row['reason_mix'] ?? null ) ? (array) $row['reason_mix'] : array();
			$lines[] = self::csv_line(
				array(
					(string) (int) ( $row['window'] ?? 0 ),
					(string) ( $row['plugin'] ?? '' ),
					(string) (int) ( $row['user_id'] ?? 0 ),
					(string) (int) ( $row['denies'] ?? 0 ),
					(string) (int) ( $row['streak_denies'] ?? 0 ),
					(string) (int) ( $row['streak_days'] ?? self::STREAK_DAYS ),
					(string) (int) ( $row['streak_threshold'] ?? self::streak_threshold() ),
					! empty( $row['streak_active'] ) ? 'yes' : 'no',
					(string) ( $row['top_reason'] ?? '' ),
					self::format_reason_mix( $mix ),
					(string) (int) ( $row['age_days'] ?? 0 ),
					(string) ( $row['deep_link'] ?? '' ),
					! empty( $row['access_request'] ) ? 'yes' : 'no',
					! empty( $row['shadow_ai_later'] ) ? 'yes' : 'no',
					'revisit_only_never_auto_relax',
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
	 * @param list<array<string,mixed>> $rows Roster.
	 */
	public static function build_print_html( array $rows ): string {
		$html  = '<!DOCTYPE html><html><head><meta charset="utf-8"><title>';
		$html .= esc_html__( 'AI deny friction', 'handl-ai-connector-access-control' );
		$html .= '</title><style>body{font-family:sans-serif;margin:24px}table{border-collapse:collapse;width:100%;margin-bottom:24px}th,td{border:1px solid #ccc;padding:6px 8px;text-align:left}th{background:#f6f7f7}</style></head><body>';
		$html .= '<h1>' . esc_html__( 'AI deny friction', 'handl-ai-connector-access-control' ) . '</h1>';
		$html .= '<p>' . esc_html__( 'Revisit only — never auto-relaxes. Informational; measures what saying no costs.', 'handl-ai-connector-access-control' ) . '</p>';
		$html .= '<table><thead><tr>';
		$html .= '<th>' . esc_html__( 'Window', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '<th>' . esc_html__( 'Plugin', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '<th>' . esc_html__( 'User', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '<th>' . esc_html__( 'Denies', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '<th>' . esc_html__( 'Streak (7d)', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '<th>' . esc_html__( 'Top reason', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '<th>' . esc_html__( 'Age (days)', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '<th>' . esc_html__( 'Access req', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '<th>' . esc_html__( 'Shadow AI later', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '</tr></thead><tbody>';
		foreach ( $rows as $row ) {
			$html .= '<tr>';
			$html .= '<td>' . esc_html( (string) (int) ( $row['window'] ?? 0 ) ) . '</td>';
			$html .= '<td>' . esc_html( (string) ( $row['plugin'] ?? '' ) ) . '</td>';
			$html .= '<td>' . esc_html( (string) (int) ( $row['user_id'] ?? 0 ) ) . '</td>';
			$html .= '<td>' . esc_html( (string) (int) ( $row['denies'] ?? 0 ) ) . '</td>';
			$html .= '<td>' . esc_html( (string) (int) ( $row['streak_denies'] ?? 0 ) ) . ( ! empty( $row['streak_active'] ) ? ' *' : '' ) . '</td>';
			$html .= '<td>' . esc_html( (string) ( $row['top_reason'] ?? '' ) ) . '</td>';
			$html .= '<td>' . esc_html( (string) (int) ( $row['age_days'] ?? 0 ) ) . '</td>';
			$html .= '<td>' . esc_html( ! empty( $row['access_request'] ) ? 'yes' : 'no' ) . '</td>';
			$html .= '<td>' . esc_html( ! empty( $row['shadow_ai_later'] ) ? 'yes' : 'no' ) . '</td>';
			$html .= '</tr>';
		}
		$html .= '</tbody></table></body></html>';

		return $html;
	}

	public static function register_menu(): void {
		if ( ! Caps::user_can_view() ) {
			return;
		}
		if ( ! function_exists( 'add_submenu_page' ) ) {
			return;
		}
		add_submenu_page(
			Admin::MENU_SLUG,
			__( 'AI deny friction', 'handl-ai-connector-access-control' ),
			__( 'Friction', 'handl-ai-connector-access-control' ),
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
		$rows       = $enabled ? self::roster() : array();
		$snap       = $enabled ? self::snapshot() : null;
		$csv        = add_query_arg(
			array(
				'page'                     => self::PAGE_SLUG,
				'handl_aicac_friction_csv' => '1',
				'_wpnonce'                 => function_exists( 'wp_create_nonce' ) ? wp_create_nonce( 'handl_aicac_friction_csv' ) : '',
			),
			admin_url( 'admin.php' )
		);
		$print = add_query_arg(
			array(
				'page'                       => self::PAGE_SLUG,
				'handl_aicac_friction_print' => '1',
				'_wpnonce'                   => function_exists( 'wp_create_nonce' ) ? wp_create_nonce( 'handl_aicac_friction_print' ) : '',
			),
			admin_url( 'admin.php' )
		);

		echo '<div class="wrap">';
		echo '<h1>' . esc_html__( 'AI deny friction', 'handl-ai-connector-access-control' ) . '</h1>';
		echo '<p class="description">' . esc_html__( 'Measure what saying no costs. A deny that fires once is governance; the same deny forty times a week is friction. Revisit the owning rule — never auto-relax. Informational; off by default.', 'handl-ai-connector-access-control' ) . '</p>';

		if ( $can_manage ) {
			$action = admin_url( 'admin-post.php' );
			echo '<form method="post" action="' . esc_url( $action ) . '">';
			echo '<input type="hidden" name="action" value="' . esc_attr( self::ACTION_SAVE ) . '" />';
			if ( function_exists( 'wp_nonce_field' ) ) {
				wp_nonce_field( self::ACTION_SAVE );
			}
			echo '<input type="hidden" name="' . esc_attr( self::POST_PRESENT ) . '" value="1" />';
			echo '<table class="form-table" role="presentation"><tbody>';
			echo '<tr><th scope="row">' . esc_html__( 'Enable deny-friction report', 'handl-ai-connector-access-control' ) . '</th><td>';
			echo '<label><input type="checkbox" name="' . esc_attr( self::POST_ENABLED ) . '" value="1" ' . checked( ! empty( $settings['enabled'] ), true, false ) . ' /> ';
			echo esc_html__( 'Aggregate denied pairs and alert on repeat-deny streaks', 'handl-ai-connector-access-control' );
			echo '</label></td></tr>';
			echo '<tr><th scope="row"><label for="handl-aicac-friction-threshold">' . esc_html__( 'Streak threshold (denies / 7 days)', 'handl-ai-connector-access-control' ) . '</label></th><td>';
			echo '<input name="' . esc_attr( self::POST_THRESHOLD ) . '" id="handl-aicac-friction-threshold" type="number" min="2" max="1000" step="1" value="' . esc_attr( (string) (int) $settings['streak_threshold'] ) . '" class="small-text" />';
			echo '<p class="description">' . esc_html__( 'Alert once per pair+window when denies for that plugin+user reach this count inside a rolling 7 days. Default 10. Revisit only — never auto-relaxes.', 'handl-ai-connector-access-control' ) . '</p>';
			echo '</td></tr></tbody></table>';
			submit_button( __( 'Save friction settings', 'handl-ai-connector-access-control' ) );
			echo '</form>';
		}

		if ( ! $enabled ) {
			echo '<p>' . esc_html__( 'Deny-friction report is off. Enable it to build the hotspot roster from logged denials.', 'handl-ai-connector-access-control' ) . '</p>';
			echo '</div>';

			return;
		}

		echo '<p><strong>' . esc_html__( 'Revisit only — never auto-relaxes.', 'handl-ai-connector-access-control' ) . '</strong> ';
		echo esc_html__( 'Hotspots come from the activity log. Deep links open the owning Rules or Protections screen so you can reconsider the decision; this feature never changes rules.', 'handl-ai-connector-access-control' ) . '</p>';

		if ( is_array( $snap ) ) {
			foreach ( array( 30, 90 ) as $window ) {
				$w = $snap['windows'][ $window ] ?? null;
				if ( ! is_array( $w ) ) {
					continue;
				}
				echo '<h2>' . esc_html(
					sprintf(
						/* translators: %d: window days */
						__( '%d-day summary', 'handl-ai-connector-access-control' ),
						$window
					)
				) . '</h2>';
				echo '<ul>';
				echo '<li>' . esc_html(
					sprintf(
						/* translators: 1: total denies, 2: active streak count */
						__( 'Denied calls: %1$d — active streaks: %2$d', 'handl-ai-connector-access-control' ),
						(int) ( $w['total_denies'] ?? 0 ),
						(int) ( $w['active_streaks'] ?? 0 )
					)
				) . '</li>';
				echo '</ul>';
			}
		}

		echo '<p>';
		echo '<a class="button" href="' . esc_url( $csv ) . '">' . esc_html__( 'Download CSV', 'handl-ai-connector-access-control' ) . '</a> ';
		echo '<a class="button" href="' . esc_url( $print ) . '" target="_blank" rel="noopener noreferrer">' . esc_html__( 'Print / PDF view', 'handl-ai-connector-access-control' ) . '</a>';
		echo '</p>';

		echo '<h2>' . esc_html__( 'Friction hotspots', 'handl-ai-connector-access-control' ) . '</h2>';
		if ( empty( $rows ) ) {
			echo '<p>' . esc_html__( 'No denied AI calls in the 30/90-day windows yet.', 'handl-ai-connector-access-control' ) . '</p>';
		} else {
			echo '<table class="widefat striped"><thead><tr>';
			echo '<th>' . esc_html__( 'Window', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Plugin', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'User', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Denies', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Streak (7d)', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Reason mix', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Age (days)', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Flags', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Revisit', 'handl-ai-connector-access-control' ) . '</th>';
			echo '</tr></thead><tbody>';
			foreach ( $rows as $row ) {
				$mix   = is_array( $row['reason_mix'] ?? null ) ? (array) $row['reason_mix'] : array();
				$flags = array();
				if ( ! empty( $row['streak_active'] ) ) {
					$flags[] = __( 'streak', 'handl-ai-connector-access-control' );
				}
				if ( ! empty( $row['access_request'] ) ) {
					$flags[] = __( 'access request', 'handl-ai-connector-access-control' );
				}
				if ( ! empty( $row['shadow_ai_later'] ) ) {
					$flags[] = __( 'shadow AI later', 'handl-ai-connector-access-control' );
				}
				echo '<tr>';
				echo '<td>' . esc_html( (string) (int) $row['window'] ) . '</td>';
				echo '<td><code>' . esc_html( (string) $row['plugin'] ) . '</code></td>';
				echo '<td>' . esc_html( (string) (int) $row['user_id'] ) . '</td>';
				echo '<td>' . esc_html( (string) (int) $row['denies'] ) . '</td>';
				echo '<td>' . esc_html( (string) (int) $row['streak_denies'] ) . '</td>';
				echo '<td>' . esc_html( self::format_reason_mix( $mix ) ) . '</td>';
				echo '<td>' . esc_html( (string) (int) $row['age_days'] ) . '</td>';
				echo '<td>' . esc_html( empty( $flags ) ? '—' : implode( ', ', $flags ) ) . '</td>';
				$link = (string) ( $row['deep_link'] ?? '' );
				if ( '' !== $link ) {
					echo '<td><a href="' . esc_url( $link ) . '">' . esc_html__( 'Open owning screen', 'handl-ai-connector-access-control' ) . '</a></td>';
				} else {
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
		if ( empty( $_GET['handl_aicac_friction_csv'] ) ) {
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
		check_admin_referer( 'handl_aicac_friction_csv' );
		$csv = self::csv_for_roster();
		if ( function_exists( 'nocache_headers' ) ) {
			nocache_headers();
		}
		if ( ! headers_sent() ) {
			header( 'Content-Type: text/csv; charset=utf-8' );
			header( 'Content-Disposition: attachment; filename=handl-aicac-friction.csv' );
		}
		echo $csv; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- CSV download.
		exit;
	}

	public static function maybe_handle_print(): void {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( empty( $_GET['handl_aicac_friction_print'] ) ) {
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
		check_admin_referer( 'handl_aicac_friction_print' );
		$rows = self::roster();
		if ( function_exists( 'nocache_headers' ) ) {
			nocache_headers();
		}
		if ( ! headers_sent() ) {
			header( 'Content-Type: text/html; charset=utf-8' );
		}
		echo self::build_print_html( $rows ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped inside builder.
		exit;
	}

	public static function handle_save(): void {
		if ( ! Caps::user_can_manage() ) {
			wp_die( esc_html__( 'You do not have permission to save friction settings.', 'handl-ai-connector-access-control' ) );
		}
		check_admin_referer( self::ACTION_SAVE );
		if ( empty( $_POST[ self::POST_PRESENT ] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing
			wp_die( esc_html__( 'Security check failed. Go back, reload the page, and try again.', 'handl-ai-connector-access-control' ) );
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		$threshold_raw = isset( $_POST[ self::POST_THRESHOLD ] ) ? wp_unslash( (string) $_POST[ self::POST_THRESHOLD ] ) : '';
		self::save_settings(
			array(
				'enabled'          => ! empty( $_POST[ self::POST_ENABLED ] ), // phpcs:ignore WordPress.Security.NonceVerification.Missing
				'streak_threshold' => self::sanitize_streak_threshold( '' !== $threshold_raw ? $threshold_raw : self::DEFAULT_STREAK_THRESHOLD ),
			)
		);
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

	public static function register_cli(): void {
		if ( ! defined( 'WP_CLI' ) || ! WP_CLI ) {
			return;
		}
		if ( ! class_exists( '\WP_CLI' ) ) {
			return;
		}
		\WP_CLI::add_command( 'handl-aicac friction', CLI_Friction::class );
	}

	/**
	 * Whether any window currently has an active streak.
	 */
	public static function has_active_streak( ?array $log = null, ?int $now = null ): bool {
		$snap = self::snapshot( $log, $now );
		foreach ( $snap['windows'] as $analysis ) {
			if ( (int) ( $analysis['active_streaks'] ?? 0 ) > 0 ) {
				return true;
			}
		}

		return false;
	}
}

/**
 * WP-CLI: wp handl-aicac friction status|export
 */
final class CLI_Friction {

	/**
	 * Show deny-friction status.
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
		$settings = Friction::get_settings();
		if ( empty( $settings['enabled'] ) ) {
			\WP_CLI::log( 'enabled=no framing=revisit_only_never_auto_relax' );
			\WP_CLI::log( 'Deny-friction report is disabled.' );
			return;
		}
		$format = isset( $assoc_args['format'] ) ? (string) $assoc_args['format'] : 'table';
		$active = Friction::has_active_streak();

		\WP_CLI::log(
			sprintf(
				'enabled=yes streak_threshold=%d streak_days=%d framing=revisit_only_never_auto_relax active_streak=%s',
				Friction::streak_threshold(),
				Friction::STREAK_DAYS,
				$active ? 'yes' : 'no'
			)
		);

		$rows = Friction::roster();
		if ( empty( $rows ) ) {
			\WP_CLI::log( 'No friction rows.' );
			if ( $active ) {
				\WP_CLI::error( 'Active deny-friction streak.', false );
			}
			return;
		}

		$display = array();
		foreach ( $rows as $row ) {
			$mix = is_array( $row['reason_mix'] ?? null ) ? (array) $row['reason_mix'] : array();
			$display[] = array(
				'window'        => (int) $row['window'],
				'plugin'        => (string) $row['plugin'],
				'user_id'       => (int) $row['user_id'],
				'denies'        => (int) $row['denies'],
				'streak_denies' => (int) $row['streak_denies'],
				'streak_active' => ! empty( $row['streak_active'] ) ? 'yes' : 'no',
				'top_reason'    => (string) $row['top_reason'],
				'reason_mix'    => Friction::format_reason_mix( $mix ),
				'age_days'      => (int) $row['age_days'],
			);
		}
		if ( 'json' === $format ) {
			\WP_CLI::print_value( $display, array( 'format' => 'json' ) );
		} elseif ( class_exists( '\WP_CLI\Utils' ) ) {
			\WP_CLI\Utils\format_items(
				'table',
				$display,
				array( 'window', 'plugin', 'user_id', 'denies', 'streak_denies', 'streak_active', 'top_reason', 'reason_mix', 'age_days' )
			);
		} else {
			foreach ( $display as $row ) {
				\WP_CLI::log( implode( "\t", $row ) );
			}
		}

		if ( $active ) {
			\WP_CLI::error( 'Active deny-friction streak.', false );
		}
	}

	/**
	 * Export the friction roster as CSV.
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
		$csv = Friction::csv_for_roster();
		if ( ! empty( $assoc_args['porcelain'] ) ) {
			echo $csv; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- CLI CSV.
			return;
		}
		\WP_CLI::print_value( $csv, array( 'format' => 'csv' ) );
	}
}
