<?php
/**
 * AICAC-NOISE (#405): alert attention-cost meter (read-only).
 *
 * Sent ledger fed by the sanctioned one-line do_action in Alerts::safe_wp_mail.
 * Per-control weekly volume, noisiest roster, wallpaper detector (4 straight
 * weeks), configurable weekly budget with exactly one re-arming [NOISE]
 * meta-alert (self-accounted). Print + CSV + WP-CLI. Never auto-tunes,
 * never suppresses, never stores alert bodies. OFF by default. Own two options.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Alert attention-cost meter.
 */
final class Noise {

	public const SETTINGS_OPTION = 'handl_aicac_noise';

	public const STATE_OPTION = 'handl_aicac_noise_state';

	public const PAGE_SLUG = 'handl-aicac-noise';

	public const ALERT_KIND = 'noise';

	public const HOOK_SENT = 'handl_aicac_alert_sent';

	public const FILTER_BUDGET = 'handl_aicac_noise_budget_per_week';

	public const FILTER_WALLPAPER_WEEKS = 'handl_aicac_noise_wallpaper_weeks';

	public const POST_PRESENT = 'handl_aicac_noise_present';

	public const POST_ENABLED = 'handl_aicac_noise_enabled';

	public const POST_BUDGET = 'handl_aicac_noise_budget_per_week';

	public const POST_WALLPAPER = 'handl_aicac_noise_wallpaper_weeks';

	public const ACTION_SAVE = 'handl_aicac_noise_save';

	public const FRAMING = 'report_only_never_mutates';

	public const DEFAULT_BUDGET_PER_WEEK = 10;

	public const MIN_BUDGET = 1;

	public const MAX_BUDGET = 1000;

	public const DEFAULT_WALLPAPER_WEEKS = 4;

	public const MIN_WALLPAPER_WEEKS = 2;

	public const MAX_WALLPAPER_WEEKS = 12;

	public const LEDGER_CAP = 500;

	public const HISTORY_CAP = 40;

	/** @var bool */
	private static $registered = false;

	/** @var list<array<string,mixed>> */
	private static $test_mails = array();

	public static function init(): void {
		if ( self::$registered ) {
			return;
		}
		self::$registered = true;

		add_action( self::HOOK_SENT, array( self::class, 'on_alert_sent' ), 10, 2 );
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
		delete_option( self::STATE_OPTION );
	}

	/**
	 * @return list<array<string,mixed>>
	 */
	public static function test_mails(): array {
		return self::$test_mails;
	}

	/**
	 * @return array{enabled:bool,budget_per_week:int,wallpaper_weeks:int}
	 */
	public static function defaults(): array {
		return array(
			'enabled'         => false,
			'budget_per_week' => self::DEFAULT_BUDGET_PER_WEEK,
			'wallpaper_weeks' => self::DEFAULT_WALLPAPER_WEEKS,
		);
	}

	/**
	 * @return array{enabled:bool,budget_per_week:int,wallpaper_weeks:int}
	 */
	public static function get_settings(): array {
		return self::sanitize_settings( get_option( self::SETTINGS_OPTION, array() ) );
	}

	/**
	 * @param mixed $raw Raw settings.
	 * @return array{enabled:bool,budget_per_week:int,wallpaper_weeks:int}
	 */
	public static function sanitize_settings( $raw ): array {
		$defaults = self::defaults();
		if ( ! is_array( $raw ) ) {
			return $defaults;
		}

		return array(
			'enabled'         => ! empty( $raw['enabled'] ),
			'budget_per_week' => self::sanitize_budget( $raw['budget_per_week'] ?? $defaults['budget_per_week'] ),
			'wallpaper_weeks' => self::sanitize_wallpaper_weeks( $raw['wallpaper_weeks'] ?? $defaults['wallpaper_weeks'] ),
		);
	}

	/**
	 * @param mixed $raw Raw budget.
	 */
	public static function sanitize_budget( $raw ): int {
		if ( ! is_numeric( $raw ) ) {
			return self::DEFAULT_BUDGET_PER_WEEK;
		}
		$v = (int) $raw;
		if ( $v < self::MIN_BUDGET ) {
			$v = self::MIN_BUDGET;
		}
		if ( $v > self::MAX_BUDGET ) {
			$v = self::MAX_BUDGET;
		}

		return $v;
	}

	/**
	 * @param mixed $raw Raw weeks.
	 */
	public static function sanitize_wallpaper_weeks( $raw ): int {
		if ( ! is_numeric( $raw ) ) {
			return self::DEFAULT_WALLPAPER_WEEKS;
		}
		$v = (int) $raw;
		if ( $v < self::MIN_WALLPAPER_WEEKS ) {
			$v = self::MIN_WALLPAPER_WEEKS;
		}
		if ( $v > self::MAX_WALLPAPER_WEEKS ) {
			$v = self::MAX_WALLPAPER_WEEKS;
		}

		return $v;
	}

	public static function budget_per_week(): int {
		$settings = self::get_settings();
		$base     = (int) $settings['budget_per_week'];
		if ( function_exists( 'apply_filters' ) ) {
			return self::sanitize_budget( apply_filters( self::FILTER_BUDGET, $base ) );
		}

		return $base;
	}

	public static function wallpaper_weeks(): int {
		$settings = self::get_settings();
		$base     = (int) $settings['wallpaper_weeks'];
		if ( function_exists( 'apply_filters' ) ) {
			return self::sanitize_wallpaper_weeks( apply_filters( self::FILTER_WALLPAPER_WEEKS, $base ) );
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

	/**
	 * @return array{alerted:bool,ledger:list<array{control:string,ts:int}>,history:list<array<string,mixed>>}
	 */
	public static function defaults_state(): array {
		return array(
			'alerted' => false,
			'ledger'  => array(),
			'history' => array(),
		);
	}

	/**
	 * @return array{alerted:bool,ledger:list<array{control:string,ts:int}>,history:list<array<string,mixed>>}
	 */
	public static function get_state(): array {
		return self::sanitize_state( get_option( self::STATE_OPTION, array() ) );
	}

	/**
	 * @param mixed $raw Raw state.
	 * @return array{alerted:bool,ledger:list<array{control:string,ts:int}>,history:list<array<string,mixed>>}
	 */
	public static function sanitize_state( $raw ): array {
		$defaults = self::defaults_state();
		if ( ! is_array( $raw ) ) {
			return $defaults;
		}
		$ledger = array();
		if ( isset( $raw['ledger'] ) && is_array( $raw['ledger'] ) ) {
			foreach ( $raw['ledger'] as $row ) {
				$clean = self::sanitize_ledger_entry( $row );
				if ( null !== $clean ) {
					$ledger[] = $clean;
				}
			}
		}
		if ( count( $ledger ) > self::LEDGER_CAP ) {
			$ledger = array_slice( $ledger, -self::LEDGER_CAP );
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
			'ledger'  => $ledger,
			'history' => $history,
		);
	}

	/**
	 * @param mixed $row Raw ledger row.
	 * @return array{control:string,ts:int}|null
	 */
	public static function sanitize_ledger_entry( $row ): ?array {
		if ( ! is_array( $row ) ) {
			return null;
		}
		$control = isset( $row['control'] ) ? sanitize_key( (string) $row['control'] ) : '';
		$ts      = isset( $row['ts'] ) ? (int) $row['ts'] : 0;
		if ( '' === $control || $ts <= 0 ) {
			return null;
		}

		return array(
			'control' => $control,
			'ts'      => $ts,
		);
	}

	/**
	 * @param mixed $row Raw history row.
	 * @return array{ts:int,week:string,count:int,budget:int,over:bool}|null
	 */
	public static function sanitize_history_entry( $row ): ?array {
		if ( ! is_array( $row ) ) {
			return null;
		}
		$ts     = isset( $row['ts'] ) ? (int) $row['ts'] : 0;
		$week   = isset( $row['week'] ) ? sanitize_text_field( (string) $row['week'] ) : '';
		$count  = isset( $row['count'] ) ? (int) $row['count'] : 0;
		$budget = isset( $row['budget'] ) ? (int) $row['budget'] : 0;
		if ( $ts <= 0 || '' === $week ) {
			return null;
		}

		return array(
			'ts'     => $ts,
			'week'   => $week,
			'count'  => max( 0, $count ),
			'budget' => max( 0, $budget ),
			'over'   => ! empty( $row['over'] ),
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

	/**
	 * Classify a transport label (control slug or mail subject) into a control slug.
	 */
	public static function control_from_label( string $label ): string {
		$label = trim( $label );
		if ( '' === $label ) {
			return 'alert';
		}
		if ( (bool) preg_match( '/^[a-z][a-z0-9_]{0,40}$/', $label ) ) {
			return sanitize_key( $label );
		}
		if ( (bool) preg_match( '/^\[[^\]]*\]\s*\[([A-Z][A-Z0-9_-]+)\]/', $label, $m ) ) {
			return sanitize_key( strtolower( str_replace( '-', '_', $m[1] ) ) );
		}

		return 'alert';
	}

	/**
	 * Listener for the sanctioned Alerts send hook. No-op when disabled.
	 *
	 * @param mixed $control Control slug or subject label.
	 * @param mixed $context Optional meta (ts only used).
	 */
	public static function on_alert_sent( $control, $context = array() ): void {
		if ( ! self::is_enabled() ) {
			return;
		}
		$label = is_string( $control ) ? $control : '';
		$slug  = self::control_from_label( $label );
		$ts    = 0;
		if ( is_array( $context ) && isset( $context['ts'] ) ) {
			$ts = (int) $context['ts'];
		}
		if ( $ts <= 0 ) {
			$ts = class_exists( Clock::class, false ) ? Clock::now() : time();
		}
		self::append_ledger( $slug, $ts );
	}

	public static function append_ledger( string $control, int $ts ): void {
		$control = sanitize_key( $control );
		if ( '' === $control || $ts <= 0 ) {
			return;
		}
		$state             = self::get_state();
		$state['ledger'][] = array(
			'control' => $control,
			'ts'      => $ts,
		);
		if ( count( $state['ledger'] ) > self::LEDGER_CAP ) {
			$state['ledger'] = array_slice( $state['ledger'], -self::LEDGER_CAP );
		}
		self::put_state( $state );
	}

	public static function week_key( int $ts ): string {
		return gmdate( 'o-\WW', $ts );
	}

	/**
	 * Prior ISO week keys ending at $end_ts (inclusive), oldest first.
	 *
	 * @return list<string>
	 */
	public static function week_keys_ending_at( int $end_ts, int $count ): array {
		$count = max( 1, $count );
		$keys  = array();
		// Step back ~7 days at a time from end_ts; collect unique ISO weeks.
		$cursor = $end_ts;
		$guard  = 0;
		while ( count( $keys ) < $count && $guard < 400 ) {
			$key = self::week_key( $cursor );
			if ( ! in_array( $key, $keys, true ) ) {
				array_unshift( $keys, $key );
			}
			$cursor -= 7 * 86400;
			++$guard;
		}

		return $keys;
	}

	/**
	 * @param list<array{control:string,ts:int}>|null $ledger Ledger override.
	 * @return array<string,array<string,int>> control => week => count
	 */
	public static function volume_by_control_week( ?array $ledger = null ): array {
		$state  = self::get_state();
		$rows   = null !== $ledger ? $ledger : $state['ledger'];
		$out    = array();
		foreach ( $rows as $row ) {
			$control = sanitize_key( (string) ( $row['control'] ?? '' ) );
			$ts      = (int) ( $row['ts'] ?? 0 );
			if ( '' === $control || $ts <= 0 ) {
				continue;
			}
			$week = self::week_key( $ts );
			if ( ! isset( $out[ $control ] ) ) {
				$out[ $control ] = array();
			}
			if ( ! isset( $out[ $control ][ $week ] ) ) {
				$out[ $control ][ $week ] = 0;
			}
			++$out[ $control ][ $week ];
		}

		return $out;
	}

	/**
	 * @param list<array{control:string,ts:int}>|null $ledger Ledger.
	 */
	public static function week_total( int $now, ?array $ledger = null ): int {
		$week  = self::week_key( $now );
		$state = self::get_state();
		$rows  = null !== $ledger ? $ledger : $state['ledger'];
		$total = 0;
		foreach ( $rows as $row ) {
			$ts = (int) ( $row['ts'] ?? 0 );
			if ( $ts > 0 && self::week_key( $ts ) === $week ) {
				++$total;
			}
		}

		return $total;
	}

	/**
	 * @param list<array{control:string,ts:int}>|null $ledger Ledger.
	 * @return list<array{control:string,count:int}>
	 */
	public static function noisiest_roster( int $now, int $limit = 10, ?array $ledger = null ): array {
		$week   = self::week_key( $now );
		$by     = self::volume_by_control_week( $ledger );
		$roster = array();
		foreach ( $by as $control => $weeks ) {
			$count = isset( $weeks[ $week ] ) ? (int) $weeks[ $week ] : 0;
			if ( $count <= 0 ) {
				continue;
			}
			$roster[] = array(
				'control' => (string) $control,
				'count'   => $count,
			);
		}
		usort(
			$roster,
			static function ( array $a, array $b ): int {
				if ( $a['count'] === $b['count'] ) {
					return strcmp( $a['control'], $b['control'] );
				}

				return $b['count'] <=> $a['count'];
			}
		);

		return array_slice( $roster, 0, max( 1, $limit ) );
	}

	/**
	 * Deep-link page slug suggestions for wallpaper findings (suggestion only).
	 *
	 * @return array<string,string>
	 */
	public static function control_page_map(): array {
		return array(
			'alert'       => 'handl-aicac',
			'noise'       => self::PAGE_SLUG,
			'footprint'   => 'handl-aicac-footprint',
			'unattended'  => 'handl-aicac-unattended',
			'drill'       => 'handl-aicac-drill',
			'key_age'     => 'handl-aicac-key-age',
			'friction'    => 'handl-aicac-friction',
			'dormant'     => 'handl-aicac-dormant',
			'chargeback'  => 'handl-aicac-chargeback',
			'recert'      => 'handl-aicac-recert',
			'went_ai'     => 'handl-aicac',
			'temp_allow'  => 'handl-aicac',
			'shadow'      => 'handl-aicac',
			'denial'      => 'handl-aicac',
		);
	}

	public static function control_admin_url( string $control ): string {
		$map  = self::control_page_map();
		$page = isset( $map[ $control ] ) ? $map[ $control ] : 'handl-aicac';
		if ( ! function_exists( 'admin_url' ) ) {
			return '';
		}

		return (string) add_query_arg( 'page', $page, admin_url( 'admin.php' ) );
	}

	/**
	 * Wallpaper = at least one send in each of the last N consecutive weeks.
	 *
	 * @param list<array{control:string,ts:int}>|null $ledger Ledger.
	 * @return list<array{control:string,weeks:int,url:string}>
	 */
	public static function wallpaper_findings( ?int $now = null, ?array $ledger = null ): array {
		$now    = null !== $now ? $now : ( class_exists( Clock::class, false ) ? Clock::now() : time() );
		$need   = self::wallpaper_weeks();
		$weeks  = self::week_keys_ending_at( $now, $need );
		$by     = self::volume_by_control_week( $ledger );
		$out    = array();
		foreach ( $by as $control => $week_counts ) {
			$ok = true;
			foreach ( $weeks as $week ) {
				if ( empty( $week_counts[ $week ] ) ) {
					$ok = false;
					break;
				}
			}
			if ( ! $ok ) {
				continue;
			}
			$out[] = array(
				'control' => (string) $control,
				'weeks'   => $need,
				'url'     => self::control_admin_url( (string) $control ),
			);
		}
		usort(
			$out,
			static function ( array $a, array $b ): int {
				return strcmp( $a['control'], $b['control'] );
			}
		);

		return $out;
	}

	/**
	 * @param list<array{control:string,ts:int}>|null $ledger Ledger.
	 */
	public static function is_over_budget( ?int $now = null, ?array $ledger = null ): bool {
		$now = null !== $now ? $now : ( class_exists( Clock::class, false ) ? Clock::now() : time() );

		return self::week_total( $now, $ledger ) > self::budget_per_week();
	}

	/**
	 * @return array<string,mixed>
	 */
	public static function snapshot( ?int $now = null ): array {
		$now      = null !== $now ? $now : ( class_exists( Clock::class, false ) ? Clock::now() : time() );
		$budget   = self::budget_per_week();
		$total    = self::week_total( $now );
		$over     = $total > $budget;
		$roster   = self::noisiest_roster( $now );
		$wallpaper = self::wallpaper_findings( $now );
		self::record_history( $now, $total, $budget, $over );
		$state = self::get_state();

		return array(
			'enabled'         => self::is_enabled(),
			'budget_per_week' => $budget,
			'wallpaper_weeks' => self::wallpaper_weeks(),
			'week'            => self::week_key( $now ),
			'week_total'      => $total,
			'over_budget'     => $over,
			'noisiest'        => $roster,
			'wallpaper'       => $wallpaper,
			'ledger_count'    => count( $state['ledger'] ),
			'history'         => $state['history'],
			'alerted'         => ! empty( $state['alerted'] ),
			'framing'         => self::FRAMING,
		);
	}

	public static function record_history( int $now, int $count, int $budget, bool $over ): void {
		$week  = self::week_key( $now );
		$state = self::get_state();
		// One history row per ISO week (update in place).
		$found = false;
		foreach ( $state['history'] as $i => $row ) {
			if ( (string) ( $row['week'] ?? '' ) === $week ) {
				$state['history'][ $i ] = array(
					'ts'     => $now,
					'week'   => $week,
					'count'  => $count,
					'budget' => $budget,
					'over'   => $over,
				);
				$found = true;
				break;
			}
		}
		if ( ! $found ) {
			$state['history'][] = array(
				'ts'     => $now,
				'week'   => $week,
				'count'  => $count,
				'budget' => $budget,
				'over'   => $over,
			);
		}
		if ( count( $state['history'] ) > self::HISTORY_CAP ) {
			$state['history'] = array_slice( $state['history'], -self::HISTORY_CAP );
		}
		self::put_state( $state );
	}

	/**
	 * @return bool True when a new alert was sent.
	 */
	public static function maybe_fire_alerts( ?int $now = null ): bool {
		if ( ! self::is_enabled() ) {
			return false;
		}
		$now      = null !== $now ? $now : ( class_exists( Clock::class, false ) ? Clock::now() : time() );
		$over     = self::is_over_budget( $now );
		$wallpaper = self::wallpaper_findings( $now );
		$hot      = $over || ! empty( $wallpaper );

		if ( ! $hot ) {
			if ( self::is_alerted() ) {
				self::set_alerted( false );
			}

			return false;
		}

		if ( self::is_alerted() ) {
			return false;
		}

		$payload = array(
			'week_total'      => self::week_total( $now ),
			'budget_per_week' => self::budget_per_week(),
			'wallpaper'       => $wallpaper,
			'noisiest'        => self::noisiest_roster( $now, 5 ),
			'over_budget'     => $over,
		);
		if ( ! self::fire_alert( $payload, $now ) ) {
			return false;
		}
		self::set_alerted( true );

		return true;
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

		if ( $ok && class_exists( Alerts::class, false ) && method_exists( Alerts::class, 'resolve_webhook' ) ) {
			$hook_url = (string) Alerts::resolve_webhook( $policy );
			if ( '' !== $hook_url && method_exists( Alerts::class, 'safe_wp_remote_post' ) ) {
				Alerts::safe_wp_remote_post(
					$hook_url,
					array(
						'type'             => 'handl_aicac_noise',
						'week_total'       => (int) ( $payload['week_total'] ?? 0 ),
						'budget_per_week'  => (int) ( $payload['budget_per_week'] ?? 0 ),
						'wallpaper_count'  => is_array( $payload['wallpaper'] ?? null ) ? count( $payload['wallpaper'] ) : 0,
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
		unset( $payload );
		$site = function_exists( 'get_bloginfo' )
			? wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES )
			: 'WordPress';

		return sprintf(
			/* translators: %s: site name */
			__( '[%s] [NOISE] AI Connector alert volume needs attention', 'handl-ai-connector-access-control' ),
			$site
		);
	}

	/**
	 * @param array<string,mixed> $payload Payload.
	 */
	public static function build_body( array $payload ): string {
		$lines   = array();
		$lines[] = __( 'This site\'s AI Connector alerts exceeded the weekly noise budget and/or include wallpaper controls.', 'handl-ai-connector-access-control' );
		$lines[] = '';
		$lines[] = sprintf(
			/* translators: 1: week total, 2: budget */
			__( 'This week: %1$d alerts (budget %2$d).', 'handl-ai-connector-access-control' ),
			(int) ( $payload['week_total'] ?? 0 ),
			(int) ( $payload['budget_per_week'] ?? 0 )
		);
		if ( ! empty( $payload['wallpaper'] ) && is_array( $payload['wallpaper'] ) ) {
			$lines[] = '';
			$lines[] = __( 'Wallpaper controls (fired every week for the configured stretch — suggestion only):', 'handl-ai-connector-access-control' );
			foreach ( $payload['wallpaper'] as $row ) {
				if ( ! is_array( $row ) ) {
					continue;
				}
				$control = (string) ( $row['control'] ?? '' );
				$url     = (string) ( $row['url'] ?? '' );
				$lines[] = sprintf( '- %s — %s', $control, $url );
			}
		}
		$lines[] = '';
		$lines[] = __( 'Report only — never auto-tunes or suppresses alerts.', 'handl-ai-connector-access-control' );
		$lines[] = self::admin_url();

		return implode( "\n", $lines ) . "\n";
	}

	public static function admin_url(): string {
		if ( ! function_exists( 'admin_url' ) ) {
			return '';
		}

		return (string) add_query_arg( 'page', self::PAGE_SLUG, admin_url( 'admin.php' ) );
	}

	/**
	 * @param array<string,mixed>|null $snap Snapshot override.
	 */
	public static function csv_for_snapshot( ?array $snap = null ): string {
		$snap  = null !== $snap ? $snap : self::snapshot();
		$lines = array();
		$lines[] = self::csv_line( array( 'section', 'control', 'count', 'weeks', 'url', 'framing' ) );
		foreach ( (array) ( $snap['noisiest'] ?? array() ) as $row ) {
			$lines[] = self::csv_line(
				array(
					'noisiest',
					(string) ( $row['control'] ?? '' ),
					(string) (int) ( $row['count'] ?? 0 ),
					'',
					'',
					self::FRAMING,
				)
			);
		}
		foreach ( (array) ( $snap['wallpaper'] ?? array() ) as $row ) {
			$lines[] = self::csv_line(
				array(
					'wallpaper',
					(string) ( $row['control'] ?? '' ),
					'',
					(string) (int) ( $row['weeks'] ?? 0 ),
					(string) ( $row['url'] ?? '' ),
					self::FRAMING,
				)
			);
		}
		$lines[] = self::csv_line(
			array(
				'summary',
				(string) ( $snap['week'] ?? '' ),
				(string) (int) ( $snap['week_total'] ?? 0 ),
				(string) (int) ( $snap['budget_per_week'] ?? 0 ),
				! empty( $snap['over_budget'] ) ? 'over_budget' : 'under_budget',
				self::FRAMING,
			)
		);

		return implode( "\n", $lines ) . "\n";
	}

	/**
	 * @param list<string> $cols Columns.
	 */
	public static function csv_line( array $cols ): string {
		$out = array();
		foreach ( $cols as $col ) {
			$col = (string) $col;
			if ( str_contains( $col, ',' ) || str_contains( $col, '"' ) || str_contains( $col, "\n" ) ) {
				$col = '"' . str_replace( '"', '""', $col ) . '"';
			}
			$out[] = $col;
		}

		return implode( ',', $out );
	}

	/**
	 * @param array<string,mixed> $snap Snapshot.
	 */
	public static function build_print_html( array $snap ): string {
		$html  = '<!DOCTYPE html><html><head><meta charset="utf-8"><title>';
		$html .= esc_html__( 'AI Connector noise report', 'handl-ai-connector-access-control' );
		$html .= '</title><style>body{font-family:sans-serif;margin:24px}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ccc;padding:6px;text-align:left}</style></head><body>';
		$html .= '<h1>' . esc_html__( 'AI Connector noise report', 'handl-ai-connector-access-control' ) . '</h1>';
		$html .= '<p>' . esc_html(
			sprintf(
				/* translators: 1: week key, 2: total, 3: budget */
				__( 'Week %1$s — %2$d alerts (budget %3$d).', 'handl-ai-connector-access-control' ),
				(string) ( $snap['week'] ?? '' ),
				(int) ( $snap['week_total'] ?? 0 ),
				(int) ( $snap['budget_per_week'] ?? 0 )
			)
		) . '</p>';
		$html .= '<p><strong>' . esc_html__( 'Report only — never auto-tunes or suppresses alerts.', 'handl-ai-connector-access-control' ) . '</strong></p>';
		$html .= '<h2>' . esc_html__( 'Noisiest this week', 'handl-ai-connector-access-control' ) . '</h2>';
		$html .= '<table><thead><tr><th>' . esc_html__( 'Control', 'handl-ai-connector-access-control' ) . '</th><th>' . esc_html__( 'Count', 'handl-ai-connector-access-control' ) . '</th></tr></thead><tbody>';
		foreach ( (array) ( $snap['noisiest'] ?? array() ) as $row ) {
			$html .= '<tr><td><code>' . esc_html( (string) ( $row['control'] ?? '' ) ) . '</code></td><td>' . esc_html( (string) (int) ( $row['count'] ?? 0 ) ) . '</td></tr>';
		}
		$html .= '</tbody></table>';
		$html .= '<h2>' . esc_html__( 'Wallpaper', 'handl-ai-connector-access-control' ) . '</h2>';
		$html .= '<table><thead><tr><th>' . esc_html__( 'Control', 'handl-ai-connector-access-control' ) . '</th><th>' . esc_html__( 'Weeks', 'handl-ai-connector-access-control' ) . '</th><th>' . esc_html__( 'Link', 'handl-ai-connector-access-control' ) . '</th></tr></thead><tbody>';
		foreach ( (array) ( $snap['wallpaper'] ?? array() ) as $row ) {
			$html .= '<tr><td><code>' . esc_html( (string) ( $row['control'] ?? '' ) ) . '</code></td><td>' . esc_html( (string) (int) ( $row['weeks'] ?? 0 ) ) . '</td><td>' . esc_html( (string) ( $row['url'] ?? '' ) ) . '</td></tr>';
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
			__( 'Alert noise', 'handl-ai-connector-access-control' ),
			__( 'Noise', 'handl-ai-connector-access-control' ),
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
				'handl_aicac_noise_csv'  => '1',
				'_wpnonce'               => function_exists( 'wp_create_nonce' ) ? wp_create_nonce( 'handl_aicac_noise_csv' ) : '',
			),
			admin_url( 'admin.php' )
		);
		$print = add_query_arg(
			array(
				'page'                    => self::PAGE_SLUG,
				'handl_aicac_noise_print' => '1',
				'_wpnonce'                => function_exists( 'wp_create_nonce' ) ? wp_create_nonce( 'handl_aicac_noise_print' ) : '',
			),
			admin_url( 'admin.php' )
		);

		echo '<div class="wrap">';
		echo '<h1>' . esc_html__( 'Alert noise', 'handl-ai-connector-access-control' ) . '</h1>';
		echo '<p class="description">' . esc_html__( 'Measure how many alerts this plugin sends each week. Report only — never auto-tunes or suppresses. Off by default.', 'handl-ai-connector-access-control' ) . '</p>';

		if ( $can_manage ) {
			$action = admin_url( 'admin-post.php' );
			echo '<form method="post" action="' . esc_url( $action ) . '">';
			echo '<input type="hidden" name="action" value="' . esc_attr( self::ACTION_SAVE ) . '" />';
			if ( function_exists( 'wp_nonce_field' ) ) {
				wp_nonce_field( self::ACTION_SAVE );
			}
			echo '<input type="hidden" name="' . esc_attr( self::POST_PRESENT ) . '" value="1" />';
			echo '<table class="form-table" role="presentation"><tbody>';
			echo '<tr><th scope="row">' . esc_html__( 'Enable noise watch', 'handl-ai-connector-access-control' ) . '</th><td>';
			echo '<label><input type="checkbox" name="' . esc_attr( self::POST_ENABLED ) . '" value="1" ' . checked( ! empty( $settings['enabled'] ), true, false ) . ' /> ';
			echo esc_html__( 'Track alert volume, flag wallpaper controls, and alert when the weekly budget is exceeded', 'handl-ai-connector-access-control' );
			echo '</label></td></tr>';
			echo '<tr><th scope="row"><label for="handl-aicac-noise-budget">' . esc_html__( 'Weekly alert budget', 'handl-ai-connector-access-control' ) . '</label></th><td>';
			echo '<input name="' . esc_attr( self::POST_BUDGET ) . '" id="handl-aicac-noise-budget" type="number" min="' . esc_attr( (string) self::MIN_BUDGET ) . '" max="' . esc_attr( (string) self::MAX_BUDGET ) . '" step="1" value="' . esc_attr( (string) (int) $settings['budget_per_week'] ) . '" class="small-text" />';
			echo '<p class="description">' . esc_html__( 'Default 10 alerts per ISO week. Crossing fires one [NOISE] meta-alert (counted in the ledger).', 'handl-ai-connector-access-control' ) . '</p>';
			echo '</td></tr>';
			echo '<tr><th scope="row"><label for="handl-aicac-noise-wallpaper">' . esc_html__( 'Wallpaper weeks', 'handl-ai-connector-access-control' ) . '</label></th><td>';
			echo '<input name="' . esc_attr( self::POST_WALLPAPER ) . '" id="handl-aicac-noise-wallpaper" type="number" min="' . esc_attr( (string) self::MIN_WALLPAPER_WEEKS ) . '" max="' . esc_attr( (string) self::MAX_WALLPAPER_WEEKS ) . '" step="1" value="' . esc_attr( (string) (int) $settings['wallpaper_weeks'] ) . '" class="small-text" />';
			echo '<p class="description">' . esc_html__( 'A control that fires at least once in each of this many consecutive weeks is wallpaper (suggestion only).', 'handl-ai-connector-access-control' ) . '</p>';
			echo '</td></tr></tbody></table>';
			submit_button( __( 'Save noise settings', 'handl-ai-connector-access-control' ) );
			echo '</form>';
		}

		if ( ! $enabled || ! is_array( $snap ) ) {
			echo '<p>' . esc_html__( 'Noise watch is off. Enable it to measure weekly alert volume and wallpaper controls.', 'handl-ai-connector-access-control' ) . '</p>';
			echo '</div>';

			return;
		}

		echo '<p><strong>' . esc_html__( 'Report only — never auto-tunes or suppresses alerts.', 'handl-ai-connector-access-control' ) . '</strong></p>';
		echo '<ul>';
		echo '<li>' . esc_html(
			sprintf(
				/* translators: 1: week, 2: total, 3: budget */
				__( 'Week %1$s: %2$d alerts (budget %3$d)', 'handl-ai-connector-access-control' ),
				(string) $snap['week'],
				(int) $snap['week_total'],
				(int) $snap['budget_per_week']
			)
		) . '</li>';
		if ( ! empty( $snap['over_budget'] ) ) {
			echo '<li><strong>' . esc_html__( 'Over weekly noise budget.', 'handl-ai-connector-access-control' ) . '</strong></li>';
		}
		echo '</ul>';

		echo '<p>';
		echo '<a class="button" href="' . esc_url( $csv ) . '">' . esc_html__( 'Download CSV', 'handl-ai-connector-access-control' ) . '</a> ';
		echo '<a class="button" href="' . esc_url( $print ) . '" target="_blank" rel="noopener noreferrer">' . esc_html__( 'Print / PDF view', 'handl-ai-connector-access-control' ) . '</a>';
		echo '</p>';

		echo '<h2>' . esc_html__( 'Noisiest this week', 'handl-ai-connector-access-control' ) . '</h2>';
		if ( empty( $snap['noisiest'] ) ) {
			echo '<p>' . esc_html__( 'No alerts recorded this week yet.', 'handl-ai-connector-access-control' ) . '</p>';
		} else {
			echo '<table class="widefat striped"><thead><tr>';
			echo '<th>' . esc_html__( 'Control', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Count', 'handl-ai-connector-access-control' ) . '</th>';
			echo '</tr></thead><tbody>';
			foreach ( $snap['noisiest'] as $row ) {
				echo '<tr>';
				echo '<td><code>' . esc_html( (string) $row['control'] ) . '</code></td>';
				echo '<td>' . esc_html( (string) (int) $row['count'] ) . '</td>';
				echo '</tr>';
			}
			echo '</tbody></table>';
		}

		echo '<h2>' . esc_html__( 'Wallpaper controls', 'handl-ai-connector-access-control' ) . '</h2>';
		if ( empty( $snap['wallpaper'] ) ) {
			echo '<p>' . esc_html__( 'No wallpaper controls detected.', 'handl-ai-connector-access-control' ) . '</p>';
		} else {
			echo '<table class="widefat striped"><thead><tr>';
			echo '<th>' . esc_html__( 'Control', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Weeks', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Review', 'handl-ai-connector-access-control' ) . '</th>';
			echo '</tr></thead><tbody>';
			foreach ( $snap['wallpaper'] as $row ) {
				echo '<tr>';
				echo '<td><code>' . esc_html( (string) $row['control'] ) . '</code></td>';
				echo '<td>' . esc_html( (string) (int) $row['weeks'] ) . '</td>';
				echo '<td><a href="' . esc_url( (string) $row['url'] ) . '">' . esc_html__( 'Open settings', 'handl-ai-connector-access-control' ) . '</a></td>';
				echo '</tr>';
			}
			echo '</tbody></table>';
		}

		echo '</div>';
	}

	public static function maybe_handle_csv(): void {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( empty( $_GET['handl_aicac_noise_csv'] ) ) {
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
		check_admin_referer( 'handl_aicac_noise_csv' );
		$csv = self::csv_for_snapshot();
		if ( function_exists( 'nocache_headers' ) ) {
			nocache_headers();
		}
		if ( ! headers_sent() ) {
			header( 'Content-Type: text/csv; charset=utf-8' );
			header( 'Content-Disposition: attachment; filename=handl-aicac-noise.csv' );
		}
		echo $csv; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- CSV download.
		exit;
	}

	public static function maybe_handle_print(): void {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( empty( $_GET['handl_aicac_noise_print'] ) ) {
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
		check_admin_referer( 'handl_aicac_noise_print' );
		$snap = self::snapshot();
		if ( function_exists( 'nocache_headers' ) ) {
			nocache_headers();
		}
		if ( ! headers_sent() ) {
			header( 'Content-Type: text/html; charset=utf-8' );
		}
		echo self::build_print_html( $snap ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped inside builder.
		exit;
	}

	public static function handle_save(): void {
		if ( ! Caps::user_can_manage() ) {
			wp_die( esc_html__( 'You do not have permission to save noise settings.', 'handl-ai-connector-access-control' ) );
		}
		check_admin_referer( self::ACTION_SAVE );
		if ( empty( $_POST[ self::POST_PRESENT ] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing
			wp_die( esc_html__( 'Security check failed. Go back, reload the page, and try again.', 'handl-ai-connector-access-control' ) );
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		$budget_raw = isset( $_POST[ self::POST_BUDGET ] ) ? wp_unslash( (string) $_POST[ self::POST_BUDGET ] ) : '';
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		$wall_raw = isset( $_POST[ self::POST_WALLPAPER ] ) ? wp_unslash( (string) $_POST[ self::POST_WALLPAPER ] ) : '';
		self::save_settings(
			array(
				'enabled'         => ! empty( $_POST[ self::POST_ENABLED ] ), // phpcs:ignore WordPress.Security.NonceVerification.Missing
				'budget_per_week' => self::sanitize_budget( '' !== $budget_raw ? $budget_raw : self::DEFAULT_BUDGET_PER_WEEK ),
				'wallpaper_weeks' => self::sanitize_wallpaper_weeks( '' !== $wall_raw ? $wall_raw : self::DEFAULT_WALLPAPER_WEEKS ),
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
		if ( ! class_exists( '\\WP_CLI' ) ) {
			return;
		}
		\WP_CLI::add_command( 'handl-aicac noise', CLI_Noise::class );
	}
}

/**
 * WP-CLI: wp handl-aicac noise status|export
 */
final class CLI_Noise {

	/**
	 * Show noise status. Exits non-zero when over budget or wallpaper findings exist.
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
		$settings = Noise::get_settings();
		$format   = isset( $assoc_args['format'] ) ? (string) $assoc_args['format'] : 'table';

		if ( ! Noise::is_enabled() ) {
			\WP_CLI::log(
				sprintf(
					'enabled=no budget_per_week=%d wallpaper_weeks=%d framing=%s',
					(int) $settings['budget_per_week'],
					(int) $settings['wallpaper_weeks'],
					Noise::FRAMING
				)
			);
			\WP_CLI::log( 'Noise watch is disabled.' );

			return;
		}

		$snap       = Noise::snapshot();
		$over       = ! empty( $snap['over_budget'] );
		$wallpaper  = (array) $snap['wallpaper'];
		$has_wall   = ! empty( $wallpaper );

		\WP_CLI::log(
			sprintf(
				'enabled=yes week=%s week_total=%d budget_per_week=%d over_budget=%s wallpaper=%d framing=%s',
				(string) $snap['week'],
				(int) $snap['week_total'],
				(int) $snap['budget_per_week'],
				$over ? 'yes' : 'no',
				count( $wallpaper ),
				Noise::FRAMING
			)
		);

		$display = array();
		foreach ( (array) $snap['noisiest'] as $row ) {
			$display[] = array(
				'control' => (string) $row['control'],
				'count'   => (int) $row['count'],
			);
		}
		if ( ! empty( $display ) ) {
			if ( 'json' === $format ) {
				\WP_CLI::print_value( $display, array( 'format' => 'json' ) );
			} elseif ( class_exists( '\\WP_CLI\\Utils' ) ) {
				\WP_CLI\Utils\format_items( 'table', $display, array( 'control', 'count' ) );
			} else {
				foreach ( $display as $row ) {
					\WP_CLI::log( implode( "\t", $row ) );
				}
			}
		}

		if ( $over || $has_wall ) {
			\WP_CLI::error( 'Noise budget exceeded and/or wallpaper controls present.', false );
		}
	}

	/**
	 * Export the noise report as CSV.
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
		$csv = Noise::csv_for_snapshot();
		if ( ! empty( $assoc_args['porcelain'] ) ) {
			echo $csv; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- CLI CSV.
			return;
		}
		\WP_CLI::print_value( $csv, array( 'format' => 'csv' ) );
	}
}
