<?php
/**
 * AICAC-REVIEW-NUDGE (#325): value-anchored WP.org review ask.
 *
 * Distinct from Review_Due (policy-rule staleness). Triggers only after the
 * plugin has delivered measurable value: age + governed volume thresholds.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Respectful, capped WP.org review ask on AICAC screens only.
 */
final class Review_Nudge {

	public const OPTION_KEY = 'handl_aicac_review_nudge';

	public const ACTION_SNOOZE = 'handl_aicac_review_nudge_snooze';

	public const ACTION_FOREVER = 'handl_aicac_review_nudge_forever';

	public const REVIEW_URL = 'https://wordpress.org/support/plugin/handl-ai-connector-access-control/reviews/#new-post';

	public const MIN_AGE_DAYS = 30;

	public const MIN_CALLS = 500;

	public const MIN_DENIES = 25;

	public const MAX_ASKS = 2;

	public const SNOOZE_DAYS = 30;

	/** @var self|null */
	private static $instance = null;

	public static function instance(): self {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}

		return self::$instance;
	}

	public function init(): void {
		add_action( 'admin_post_' . self::ACTION_SNOOZE, array( $this, 'handle_snooze' ) );
		add_action( 'admin_post_' . self::ACTION_FOREVER, array( $this, 'handle_forever' ) );
		if ( is_admin() ) {
			add_action( 'admin_notices', array( $this, 'maybe_render_notice' ) );
		}
		self::ensure_activated_at();
	}

	/**
	 * Stamp activation time once (activation hook + first runtime).
	 */
	public static function ensure_activated_at( ?int $now = null ): int {
		$now   = null === $now ? Clock::now() : max( 0, $now );
		$state = self::get_state();
		if ( $state['activated_at'] > 0 ) {
			return $state['activated_at'];
		}

		$backfill = self::backfill_activated_at( $now );
		$state['activated_at'] = $backfill;
		self::save_state( $state );

		return $backfill;
	}

	/**
	 * Prefer earliest retained Activity ts when upgrading without a stamp.
	 */
	private static function backfill_activated_at( int $now ): int {
		$log = get_option( Plugin::LOG_OPTION_KEY, array() );
		if ( ! is_array( $log ) ) {
			$log = array();
		}
		if ( class_exists( Demo_Mode::class, false ) ) {
			$log = Demo_Mode::without_demo( $log );
		}
		$agg = class_exists( Analytics::class, false )
			? Analytics::aggregate_from_log( $log, array() )
			: array( 'summary' => array( 'first_ts' => 0 ) );
		$first = (int) ( $agg['summary']['first_ts'] ?? 0 );

		return $first > 0 ? $first : $now;
	}

	/**
	 * @return array{
	 *   activated_at:int,
	 *   ask_count:int,
	 *   forever:bool,
	 *   snooze_until:int,
	 *   pending:bool,
	 *   last_shown_at:int
	 * }
	 */
	public static function get_state(): array {
		return self::sanitize_state( get_option( self::OPTION_KEY, array() ) );
	}

	/**
	 * @param mixed $raw
	 * @return array{
	 *   activated_at:int,
	 *   ask_count:int,
	 *   forever:bool,
	 *   snooze_until:int,
	 *   pending:bool,
	 *   last_shown_at:int
	 * }
	 */
	public static function sanitize_state( $raw ): array {
		$row = is_array( $raw ) ? $raw : array();

		return array(
			'activated_at'  => max( 0, (int) ( $row['activated_at'] ?? 0 ) ),
			'ask_count'     => max( 0, min( self::MAX_ASKS, (int) ( $row['ask_count'] ?? 0 ) ) ),
			'forever'       => ! empty( $row['forever'] ),
			'snooze_until'  => max( 0, (int) ( $row['snooze_until'] ?? 0 ) ),
			'pending'       => ! empty( $row['pending'] ),
			'last_shown_at' => max( 0, (int) ( $row['last_shown_at'] ?? 0 ) ),
		);
	}

	/**
	 * @param array<string,mixed> $state
	 */
	public static function save_state( array $state ): void {
		update_option( self::OPTION_KEY, self::sanitize_state( $state ), false );
	}

	public static function reset_for_tests(): void {
		delete_option( self::OPTION_KEY );
		self::$instance = null;
	}

	public static function user_can_manage(): bool {
		return class_exists( Caps::class, false )
			? Caps::user_can_manage()
			: current_user_can( 'manage_options' );
	}

	/**
	 * Governed AI Client calls + enforced denies from retained Activity (no new counters).
	 *
	 * @return array{calls:int,denies:int}
	 */
	public static function value_counts( ?array $log = null ): array {
		if ( null === $log ) {
			$raw = get_option( Plugin::LOG_OPTION_KEY, array() );
			$log = is_array( $raw ) ? $raw : array();
		}
		if ( class_exists( Demo_Mode::class, false ) ) {
			$log = Demo_Mode::without_demo( $log );
		}

		$agg   = Analytics::aggregate_from_log( $log, array() );
		$calls = (int) ( $agg['summary']['calls'] ?? 0 );

		$denies = 0;
		foreach ( $log as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			if ( class_exists( Selftest::class, false ) && Selftest::is_synthetic_row( $row ) ) {
				continue;
			}
			if ( class_exists( Usage_Trends::class, false ) && ! Usage_Trends::is_activity_row( $row ) ) {
				continue;
			}
			if ( 'deny' !== (string) ( $row['decision'] ?? '' ) ) {
				continue;
			}
			$c = isset( $row['count'] ) ? (int) $row['count'] : 1;
			$denies += $c > 0 ? $c : 1;
		}

		return array(
			'calls'  => $calls,
			'denies' => $denies,
		);
	}

	/**
	 * @return array{eligible:bool,reason:string,calls:int,denies:int,age_days:int}
	 */
	public static function eligibility( ?int $now = null, ?array $log = null ): array {
		$now   = null === $now ? Clock::now() : max( 0, $now );
		$state = self::get_state();
		$empty = array(
			'eligible' => false,
			'reason'   => '',
			'calls'    => 0,
			'denies'   => 0,
			'age_days' => 0,
		);

		if ( ! empty( $state['forever'] ) ) {
			$empty['reason'] = 'forever';
			return $empty;
		}

		if ( (int) $state['ask_count'] >= self::MAX_ASKS && empty( $state['pending'] ) ) {
			$empty['reason'] = 'max_asks';
			return $empty;
		}

		if ( (int) $state['snooze_until'] > $now && empty( $state['pending'] ) ) {
			$empty['reason'] = 'snoozed';
			return $empty;
		}

		if ( class_exists( Demo_Mode::class, false ) && Demo_Mode::is_active() ) {
			$empty['reason'] = 'demo';
			return $empty;
		}

		$activated = self::ensure_activated_at( $now );
		$age_days  = $activated > 0 ? (int) floor( ( $now - $activated ) / DAY_IN_SECONDS ) : 0;
		if ( $age_days < self::MIN_AGE_DAYS ) {
			$empty['reason']   = 'too_young';
			$empty['age_days'] = $age_days;
			return $empty;
		}

		$counts = self::value_counts( $log );
		$empty['calls']    = $counts['calls'];
		$empty['denies']   = $counts['denies'];
		$empty['age_days'] = $age_days;

		if ( $counts['calls'] < self::MIN_CALLS && $counts['denies'] < self::MIN_DENIES ) {
			$empty['reason'] = 'low_value';
			return $empty;
		}

		return array(
			'eligible' => true,
			'reason'   => 'ok',
			'calls'    => $counts['calls'],
			'denies'   => $counts['denies'],
			'age_days' => $age_days,
		);
	}

	/**
	 * Open an ask cycle (increments ask_count once per cycle).
	 *
	 * @return array{opened:bool,reason:string}
	 */
	public static function mark_shown( ?int $now = null ): array {
		$now   = null === $now ? Clock::now() : max( 0, $now );
		$state = self::get_state();
		if ( ! empty( $state['pending'] ) ) {
			return array(
				'opened' => false,
				'reason' => 'already_pending',
			);
		}
		if ( ! empty( $state['forever'] ) || (int) $state['ask_count'] >= self::MAX_ASKS ) {
			return array(
				'opened' => false,
				'reason' => 'capped',
			);
		}

		$state['ask_count']     = (int) $state['ask_count'] + 1;
		$state['pending']       = true;
		$state['snooze_until']  = 0;
		$state['last_shown_at'] = $now;
		self::save_state( $state );

		return array(
			'opened' => true,
			'reason' => 'ok',
		);
	}

	public static function snooze( ?int $now = null ): void {
		$now                    = null === $now ? Clock::now() : max( 0, $now );
		$state                  = self::get_state();
		$state['pending']       = false;
		$state['snooze_until']  = $now + ( self::SNOOZE_DAYS * DAY_IN_SECONDS );
		self::save_state( $state );
	}

	public static function forever(): void {
		$state            = self::get_state();
		$state['forever'] = true;
		$state['pending'] = false;
		$state['snooze_until'] = 0;
		self::save_state( $state );
	}

	public static function should_render( ?int $now = null, ?array $log = null ): bool {
		if ( function_exists( 'is_network_admin' ) && is_network_admin() ) {
			return false;
		}
		if ( ! self::user_can_manage() ) {
			return false;
		}
		$hook = '';
		if ( function_exists( 'get_current_screen' ) ) {
			$screen = get_current_screen();
			if ( is_object( $screen ) && isset( $screen->id ) ) {
				$hook = (string) $screen->id;
			}
		}
		if ( ! Admin::is_plugin_admin_hook( $hook ) ) {
			return false;
		}

		$elig = self::eligibility( $now, $log );
		if ( ! $elig['eligible'] ) {
			return false;
		}

		$state = self::get_state();
		if ( ! empty( $state['pending'] ) ) {
			return true;
		}

		return (int) $state['ask_count'] < self::MAX_ASKS;
	}

	public function maybe_render_notice(): void {
		if ( ! self::should_render() ) {
			return;
		}

		$elig = self::eligibility();
		if ( ! $elig['eligible'] ) {
			return;
		}

		$state = self::get_state();
		if ( empty( $state['pending'] ) ) {
			self::mark_shown();
		}

		$calls  = (int) $elig['calls'];
		$denies = (int) $elig['denies'];

		echo '<div class="notice notice-info handl-aicac-review-nudge">';
		echo '<p>';
		echo esc_html(
			sprintf(
				/* translators: 1: governed AI call count, 2: blocked policy violation count */
				__( 'AI Not has governed %1$s AI calls and blocked %2$s policy violations on this site.', 'handl-ai-connector-access-control' ),
				number_format_i18n( $calls ),
				number_format_i18n( $denies )
			)
		);
		echo '</p>';
		echo '<p>';
		printf(
			'<a class="button button-primary" href="%s" target="_blank" rel="noopener noreferrer">%s</a> ',
			esc_url( self::REVIEW_URL ),
			esc_html__( 'Leave a review', 'handl-ai-connector-access-control' )
		);
		printf(
			'<a class="button" href="%s">%s</a> ',
			esc_url(
				add_query_arg(
					array(
						'action'   => self::ACTION_SNOOZE,
						'_wpnonce' => wp_create_nonce( self::ACTION_SNOOZE ),
					),
					admin_url( 'admin-post.php' )
				)
			),
			esc_html__( 'Maybe later', 'handl-ai-connector-access-control' )
		);
		printf(
			'<a class="button-link" href="%s">%s</a>',
			esc_url(
				add_query_arg(
					array(
						'action'   => self::ACTION_FOREVER,
						'_wpnonce' => wp_create_nonce( self::ACTION_FOREVER ),
					),
					admin_url( 'admin-post.php' )
				)
			),
			esc_html__( "Don't ask again", 'handl-ai-connector-access-control' )
		);
		echo '</p>';
		echo '</div>';
	}

	public function handle_snooze(): void {
		if ( ! self::user_can_manage() ) {
			wp_die( esc_html__( 'Sorry, you are not allowed to do that.', 'handl-ai-connector-access-control' ) );
		}
		check_admin_referer( self::ACTION_SNOOZE );
		self::snooze();
		self::redirect_back();
	}

	public function handle_forever(): void {
		if ( ! self::user_can_manage() ) {
			wp_die( esc_html__( 'Sorry, you are not allowed to do that.', 'handl-ai-connector-access-control' ) );
		}
		check_admin_referer( self::ACTION_FOREVER );
		self::forever();
		self::redirect_back();
	}

	private static function redirect_back(): void {
		$redirect = wp_get_referer();
		if ( ! is_string( $redirect ) || '' === $redirect ) {
			$redirect = Admin::screen_url( 'dashboard' );
		}
		wp_safe_redirect( $redirect );
		exit;
	}

}
