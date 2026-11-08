<?php
/**
 * AICAC-UNDERSTUDY (#493): sampled cheaper-model audition.
 *
 * Opt-in per plugin. Cron-async replay only — the live AI Client request
 * path is never hooked. Shadow calls go through Policy::evaluate() as a
 * normal caller and are logged tagged `shadow`. Cost is metered on a
 * distinct budget-ledger line via Budget::add_estimated_spend. Apply
 * writes the existing Model-Force map (no new enforcement path).
 *
 * README-FREE. Own options only (handl_aicac_understudy*). Own admin
 * surface (plugin-profile card + apply). Model-Force, cost/budget,
 * carpool/dejavu, and the recent-calls log are class_exists-guarded
 * read-only consumers. Zero policy.php edits.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Sampled cheaper-model audition with a one-click Model-Force apply.
 */
final class Understudy {

	public const PAGE_SLUG = 'handl-aicac-understudy';

	public const SETTINGS_OPTION = 'handl_aicac_understudy';

	public const SAMPLES_OPTION = 'handl_aicac_understudy_samples';

	public const QUEUE_OPTION = 'handl_aicac_understudy_queue';

	public const DAILY_OPTION = 'handl_aicac_understudy_daily';

	public const SEEN_OPTION = 'handl_aicac_understudy_seen';

	public const ACTION_SAVE = 'handl_aicac_understudy_save';

	public const ACTION_APPLY = 'handl_aicac_understudy_apply';

	public const ACTION_REVERT = 'handl_aicac_understudy_revert';

	public const CRON_HOOK = 'handl_aicac_understudy_tick';

	public const CHANNEL_SHADOW = 'shadow';

	public const LEDGER_PLUGIN = 'handl-aicac-understudy/understudy.php';

	public const FRAMING = 'cron_async_never_on_live_request_path';

	public const SAMPLE_PCT_DEFAULT = 5;

	public const DAILY_CAP_DEFAULT = 20;

	public const MATCH_THRESHOLD = 0.75;

	public const MONTH_SECONDS = 2592000;

	public const MAX_SAMPLES = 400;

	public const MAX_QUEUE = 50;

	public const MAX_SEEN = 800;

	public const VERDICT_CLOSE        = 'close-match';
	public const VERDICT_DRIFT        = 'drift';
	public const VERDICT_INSUFFICIENT = 'insufficient';

	/** @var bool */
	private static $registered = false;

	/** @var list<array<string,mixed>>|null */
	private static $test_log = null;

	/** @var int|null */
	private static $test_now = null;

	/** @var string|null */
	private static $test_shadow_text = null;

	/** @var bool */
	private static $test_force_sample = false;

	public static function init(): void {
		if ( self::$registered ) {
			return;
		}
		self::$registered = true;
		add_action( 'admin_menu', array( self::class, 'register_menu' ), 20 );
		add_action( 'admin_notices', array( self::class, 'maybe_render_profile_notice' ) );
		add_action( 'admin_post_' . self::ACTION_SAVE, array( self::class, 'handle_save' ) );
		add_action( 'admin_post_' . self::ACTION_APPLY, array( self::class, 'handle_apply' ) );
		add_action( 'admin_post_' . self::ACTION_REVERT, array( self::class, 'handle_revert' ) );
		add_action( self::CRON_HOOK, array( self::class, 'cron_run' ) );
		self::maybe_schedule();
	}

	public static function reset_for_tests(): void {
		self::$registered        = false;
		self::$test_log          = null;
		self::$test_now          = null;
		self::$test_shadow_text  = null;
		self::$test_force_sample = false;
		delete_option( self::SETTINGS_OPTION );
		delete_option( self::SAMPLES_OPTION );
		delete_option( self::QUEUE_OPTION );
		delete_option( self::DAILY_OPTION );
		delete_option( self::SEEN_OPTION );
		if ( function_exists( 'wp_clear_scheduled_hook' ) ) {
			wp_clear_scheduled_hook( self::CRON_HOOK );
		}
	}

	/**
	 * @param list<array<string,mixed>>|null $log Injected activity rows.
	 */
	public static function set_test_log( ?array $log ): void {
		self::$test_log = $log;
	}

	public static function set_test_now( ?int $now ): void {
		self::$test_now = $now;
	}

	public static function set_test_shadow_text( ?string $text ): void {
		self::$test_shadow_text = ( is_string( $text ) && '' !== $text ) ? $text : null;
	}

	public static function set_test_force_sample( bool $force ): void {
		self::$test_force_sample = $force;
	}

	public static function now(): int {
		if ( null !== self::$test_now ) {
			return (int) self::$test_now;
		}
		if ( class_exists( Clock::class, false ) && method_exists( Clock::class, 'now' ) ) {
			return (int) Clock::now();
		}

		return time();
	}

	/**
	 * @return array{
	 *   plugins: array<string,array{enabled:bool,provider:string,model:string,sample_pct:int,daily_cap:int}>,
	 *   applied: array<string,array{provider:string,model:string}|null>
	 * }
	 */
	public static function get_settings(): array {
		return self::sanitize_settings( get_option( self::SETTINGS_OPTION, array() ) );
	}

	/**
	 * @param mixed $raw Raw option.
	 * @return array{
	 *   plugins: array<string,array{enabled:bool,provider:string,model:string,sample_pct:int,daily_cap:int}>,
	 *   applied: array<string,array{provider:string,model:string}|null>
	 * }
	 */
	public static function sanitize_settings( $raw ): array {
		$out = array(
			'plugins' => array(),
			'applied' => array(),
		);
		if ( ! is_array( $raw ) ) {
			return $out;
		}
		$plugins = isset( $raw['plugins'] ) && is_array( $raw['plugins'] ) ? $raw['plugins'] : array();
		foreach ( $plugins as $basename => $row ) {
			$plugin = self::sanitize_plugin( $basename );
			if ( '' === $plugin || ! is_array( $row ) ) {
				continue;
			}
			$provider = self::sanitize_id( $row['provider'] ?? '' );
			$model    = self::sanitize_id( $row['model'] ?? '' );
			$pct      = isset( $row['sample_pct'] ) && is_numeric( $row['sample_pct'] ) ? (int) $row['sample_pct'] : self::SAMPLE_PCT_DEFAULT;
			$cap      = isset( $row['daily_cap'] ) && is_numeric( $row['daily_cap'] ) ? (int) $row['daily_cap'] : self::DAILY_CAP_DEFAULT;
			if ( $pct < 1 ) {
				$pct = 1;
			}
			if ( $pct > 100 ) {
				$pct = 100;
			}
			if ( $cap < 1 ) {
				$cap = 1;
			}
			if ( $cap > 500 ) {
				$cap = 500;
			}
			$out['plugins'][ $plugin ] = array(
				'enabled'    => ! empty( $row['enabled'] ),
				'provider'   => $provider,
				'model'      => $model,
				'sample_pct' => $pct,
				'daily_cap'  => $cap,
			);
		}
		$applied = isset( $raw['applied'] ) && is_array( $raw['applied'] ) ? $raw['applied'] : array();
		foreach ( $applied as $basename => $row ) {
			$plugin = self::sanitize_plugin( $basename );
			if ( '' === $plugin ) {
				continue;
			}
			if ( ! is_array( $row ) ) {
				$out['applied'][ $plugin ] = null;
				continue;
			}
			$provider = self::sanitize_id( $row['provider'] ?? '' );
			$model    = self::sanitize_id( $row['model'] ?? '' );
			$out['applied'][ $plugin ] = ( '' === $provider || '' === $model )
				? null
				: array(
					'provider' => $provider,
					'model'    => $model,
				);
		}

		return $out;
	}

	/**
	 * @param array<string,mixed> $settings Settings.
	 */
	public static function save_settings( array $settings ): void {
		$clean = self::sanitize_settings( $settings );
		update_option( self::SETTINGS_OPTION, $clean, false );
		self::maybe_schedule();
	}

	public static function is_enabled(): bool {
		foreach ( self::get_settings()['plugins'] as $row ) {
			if ( ! empty( $row['enabled'] ) && '' !== (string) $row['model'] ) {
				return true;
			}
		}

		return false;
	}

	public static function is_enabled_for( string $plugin ): bool {
		$row = self::plugin_row( $plugin );

		return null !== $row && ! empty( $row['enabled'] ) && '' !== (string) $row['model'];
	}

	/**
	 * @return array{enabled:bool,provider:string,model:string,sample_pct:int,daily_cap:int}|null
	 */
	public static function plugin_row( string $plugin ): ?array {
		$plugin = self::sanitize_plugin( $plugin );
		if ( '' === $plugin ) {
			return null;
		}
		$map = self::get_settings()['plugins'];

		return isset( $map[ $plugin ] ) && is_array( $map[ $plugin ] ) ? $map[ $plugin ] : null;
	}

	/**
	 * Enable an audition for one plugin. Other plugins are unchanged.
	 *
	 * @param array{provider?:string,model?:string,sample_pct?:int,daily_cap?:int} $args Args.
	 */
	public static function enable_for( string $plugin, array $args = array() ): bool {
		$plugin = self::sanitize_plugin( $plugin );
		if ( '' === $plugin ) {
			return false;
		}
		$settings = self::get_settings();
		$prior    = isset( $settings['plugins'][ $plugin ] ) && is_array( $settings['plugins'][ $plugin ] )
			? $settings['plugins'][ $plugin ]
			: array();
		$settings['plugins'][ $plugin ] = array(
			'enabled'    => true,
			'provider'   => isset( $args['provider'] ) ? (string) $args['provider'] : (string) ( $prior['provider'] ?? '' ),
			'model'      => isset( $args['model'] ) ? (string) $args['model'] : (string) ( $prior['model'] ?? '' ),
			'sample_pct' => isset( $args['sample_pct'] ) ? (int) $args['sample_pct'] : (int) ( $prior['sample_pct'] ?? self::SAMPLE_PCT_DEFAULT ),
			'daily_cap'  => isset( $args['daily_cap'] ) ? (int) $args['daily_cap'] : (int) ( $prior['daily_cap'] ?? self::DAILY_CAP_DEFAULT ),
		);
		self::save_settings( $settings );

		return self::is_enabled_for( $plugin );
	}

	public static function disable_for( string $plugin ): void {
		$plugin = self::sanitize_plugin( $plugin );
		if ( '' === $plugin ) {
			return;
		}
		$settings = self::get_settings();
		if ( ! isset( $settings['plugins'][ $plugin ] ) ) {
			return;
		}
		$settings['plugins'][ $plugin ]['enabled'] = false;
		self::save_settings( $settings );
		self::drop_plugin_queue( $plugin );
	}

	/**
	 * Dice coefficient on whitespace/punctuation tokens. Deterministic.
	 */
	public static function similarity( string $live, string $shadow ): float {
		$a = self::tokenize( $live );
		$b = self::tokenize( $shadow );
		if ( empty( $a ) && empty( $b ) ) {
			return 1.0;
		}
		if ( empty( $a ) || empty( $b ) ) {
			return 0.0;
		}
		$counts_a = array_count_values( $a );
		$counts_b = array_count_values( $b );
		$overlap  = 0;
		foreach ( $counts_a as $token => $n ) {
			if ( isset( $counts_b[ $token ] ) ) {
				$overlap += min( $n, $counts_b[ $token ] );
			}
		}
		$denom = count( $a ) + count( $b );
		if ( $denom < 1 ) {
			return 0.0;
		}

		return round( ( 2.0 * $overlap ) / $denom, 4 );
	}

	public static function verdict_for_score( float $score ): string {
		return $score >= self::MATCH_THRESHOLD ? self::VERDICT_CLOSE : self::VERDICT_DRIFT;
	}

	/**
	 * Activity rows that belong to this audition (tagged shadow).
	 *
	 * @param array<string,mixed> $row Log row.
	 */
	public static function is_shadow_row( array $row ): bool {
		if ( ! empty( $row['understudy'] ) ) {
			return true;
		}
		$channel = isset( $row['channel'] ) ? (string) $row['channel'] : '';
		$tag     = isset( $row['tag'] ) ? (string) $row['tag'] : '';

		return self::CHANNEL_SHADOW === $channel || self::CHANNEL_SHADOW === $tag;
	}

	/**
	 * Headline analytics / dividend should skip these rows.
	 *
	 * @param array<string,mixed> $row Log row.
	 */
	public static function is_headline_row( array $row ): bool {
		if ( self::is_shadow_row( $row ) ) {
			return false;
		}
		if ( class_exists( Usage_Trends::class, false ) && method_exists( Usage_Trends::class, 'is_activity_row' ) ) {
			return (bool) Usage_Trends::is_activity_row( $row );
		}

		return true;
	}

	public static function cron_run(): void {
		if ( ! self::is_enabled() ) {
			self::save_queue( array() );

			return;
		}
		self::enqueue_from_log();
		self::drain_queue();
	}

	/**
	 * @return list<array<string,mixed>>
	 */
	public static function samples(): array {
		$raw = get_option( self::SAMPLES_OPTION, array() );
		if ( ! is_array( $raw ) ) {
			return array();
		}
		$out = array();
		foreach ( $raw as $row ) {
			if ( is_array( $row ) ) {
				$out[] = $row;
			}
		}

		return $out;
	}

	/**
	 * @return array{
	 *   plugin:string,
	 *   sample_count:int,
	 *   close_count:int,
	 *   match_pct:float,
	 *   verdict:string,
	 *   monthly_savings:float|null,
	 *   understudy_provider:string,
	 *   understudy_model:string,
	 *   applied:bool
	 * }
	 */
	public static function verdict( string $plugin ): array {
		$plugin = self::sanitize_plugin( $plugin );
		$row    = self::plugin_row( $plugin );
		$empty  = array(
			'plugin'               => $plugin,
			'sample_count'         => 0,
			'close_count'          => 0,
			'match_pct'            => 0.0,
			'verdict'              => self::VERDICT_INSUFFICIENT,
			'monthly_savings'      => null,
			'understudy_provider'  => is_array( $row ) ? (string) $row['provider'] : '',
			'understudy_model'     => is_array( $row ) ? (string) $row['model'] : '',
			'applied'              => self::is_applied( $plugin ),
		);
		if ( '' === $plugin ) {
			return $empty;
		}
		$now   = self::now();
		$cut   = $now - self::MONTH_SECONDS;
		$close = 0;
		$total = 0;
		foreach ( self::samples() as $sample ) {
			if ( (string) ( $sample['plugin'] ?? '' ) !== $plugin ) {
				continue;
			}
			$ts = isset( $sample['ts'] ) ? (int) $sample['ts'] : 0;
			if ( $ts > 0 && $ts < $cut ) {
				continue;
			}
			++$total;
			if ( self::VERDICT_CLOSE === (string) ( $sample['verdict'] ?? '' ) ) {
				++$close;
			}
		}
		$empty['sample_count'] = $total;
		$empty['close_count']  = $close;
		if ( $total < 1 ) {
			return $empty;
		}
		$empty['match_pct']       = round( 100.0 * ( $close / $total ), 1 );
		$empty['verdict']         = $empty['match_pct'] >= 50.0 ? self::VERDICT_CLOSE : self::VERDICT_DRIFT;
		$empty['monthly_savings'] = self::estimated_monthly_savings( $plugin );

		return $empty;
	}

	public static function is_applied( string $plugin ): bool {
		$plugin = self::sanitize_plugin( $plugin );
		if ( '' === $plugin ) {
			return false;
		}
		$applied = self::get_settings()['applied'];

		return array_key_exists( $plugin, $applied );
	}

	/**
	 * Wire the existing Model-Force map for this plugin. Reversible.
	 */
	public static function apply_force( string $plugin ): bool {
		$plugin = self::sanitize_plugin( $plugin );
		$row    = self::plugin_row( $plugin );
		if ( '' === $plugin || null === $row || '' === $row['model'] ) {
			return false;
		}
		if ( ! class_exists( Policy::class, false ) || ! method_exists( Policy::class, 'get_policy' )
			|| ! method_exists( Policy::class, 'save_policy' ) ) {
			return false;
		}
		if ( ! class_exists( Model_Force::class, false ) || ! method_exists( Model_Force::class, 'sanitize_force_map' ) ) {
			return false;
		}
		$policy = Policy::get_policy();
		$map    = Model_Force::sanitize_force_map( $policy['model_force_plugins'] ?? array() );
		$prior  = isset( $map[ $plugin ] ) && is_array( $map[ $plugin ] ) ? $map[ $plugin ] : null;
		$map[ $plugin ] = array(
			'provider' => $row['provider'],
			'model'    => $row['model'],
		);
		$policy['model_force_plugins'] = $map;
		Policy::save_policy( $policy );

		$settings = self::get_settings();
		$settings['applied'][ $plugin ] = $prior;
		self::save_settings( $settings );

		return true;
	}

	public static function revert_force( string $plugin ): bool {
		$plugin = self::sanitize_plugin( $plugin );
		if ( '' === $plugin ) {
			return false;
		}
		if ( ! class_exists( Policy::class, false ) || ! method_exists( Policy::class, 'get_policy' )
			|| ! method_exists( Policy::class, 'save_policy' ) ) {
			return false;
		}
		if ( ! class_exists( Model_Force::class, false ) || ! method_exists( Model_Force::class, 'sanitize_force_map' ) ) {
			return false;
		}
		$settings = self::get_settings();
		if ( ! array_key_exists( $plugin, $settings['applied'] ) ) {
			return false;
		}
		$prior  = $settings['applied'][ $plugin ];
		$policy = Policy::get_policy();
		$map    = Model_Force::sanitize_force_map( $policy['model_force_plugins'] ?? array() );
		if ( is_array( $prior ) && '' !== (string) ( $prior['provider'] ?? '' ) && '' !== (string) ( $prior['model'] ?? '' ) ) {
			$map[ $plugin ] = array(
				'provider' => (string) $prior['provider'],
				'model'    => (string) $prior['model'],
			);
		} else {
			unset( $map[ $plugin ] );
		}
		$policy['model_force_plugins'] = $map;
		Policy::save_policy( $policy );
		unset( $settings['applied'][ $plugin ] );
		self::save_settings( $settings );

		return true;
	}

	public static function register_menu(): void {
		if ( ! class_exists( Caps::class, false ) || ! Caps::user_can_view() ) {
			return;
		}
		if ( ! function_exists( 'add_submenu_page' ) || ! class_exists( Admin::class, false ) ) {
			return;
		}
		add_submenu_page(
			Admin::MENU_SLUG,
			__( 'Model audition', 'handl-ai-connector-access-control' ),
			__( 'Model audition', 'handl-ai-connector-access-control' ),
			Caps::VIEW,
			self::PAGE_SLUG,
			array( self::class, 'render_page' )
		);
	}

	public static function maybe_render_profile_notice(): void {
		if ( ! class_exists( Caps::class, false ) || ! Caps::user_can_view() ) {
			return;
		}
		$page = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( (string) $_GET['page'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( self::PAGE_SLUG === $page ) {
			return;
		}
		$raw    = isset( $_GET['handl_aicac_plugin'] ) ? wp_unslash( (string) $_GET['handl_aicac_plugin'] ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$plugin = self::sanitize_plugin( $raw );
		if ( '' === $plugin ) {
			return;
		}
		echo '<div class="notice notice-info handl-aicac-understudy-profile">';
		self::render_plugin_card( $plugin );
		echo '</div>';
	}

	public static function handle_save(): void {
		if ( ! class_exists( Caps::class, false ) || ! Caps::user_can_manage() ) {
			self::die_forbidden();
		}
		if ( function_exists( 'check_admin_referer' ) ) {
			check_admin_referer( self::ACTION_SAVE );
		}
		$plugin = isset( $_POST['handl_aicac_understudy_plugin'] ) // phpcs:ignore WordPress.Security.NonceVerification.Missing
			? self::sanitize_plugin( wp_unslash( (string) $_POST['handl_aicac_understudy_plugin'] ) )
			: '';
		if ( '' === $plugin ) {
			self::redirect();
		}
		$enabled = ! empty( $_POST['handl_aicac_understudy_enabled'] ); // phpcs:ignore WordPress.Security.NonceVerification.Missing
		if ( $enabled ) {
			self::enable_for(
				$plugin,
				array(
					'provider'   => isset( $_POST['handl_aicac_understudy_provider'] ) ? wp_unslash( (string) $_POST['handl_aicac_understudy_provider'] ) : '', // phpcs:ignore WordPress.Security.NonceVerification.Missing
					'model'      => isset( $_POST['handl_aicac_understudy_model'] ) ? wp_unslash( (string) $_POST['handl_aicac_understudy_model'] ) : '', // phpcs:ignore WordPress.Security.NonceVerification.Missing
					'sample_pct' => isset( $_POST['handl_aicac_understudy_sample_pct'] ) ? (int) $_POST['handl_aicac_understudy_sample_pct'] : self::SAMPLE_PCT_DEFAULT, // phpcs:ignore WordPress.Security.NonceVerification.Missing
					'daily_cap'  => isset( $_POST['handl_aicac_understudy_daily_cap'] ) ? (int) $_POST['handl_aicac_understudy_daily_cap'] : self::DAILY_CAP_DEFAULT, // phpcs:ignore WordPress.Security.NonceVerification.Missing
				)
			);
		} else {
			self::disable_for( $plugin );
		}
		self::redirect();
	}

	public static function handle_apply(): void {
		if ( ! class_exists( Caps::class, false ) || ! Caps::user_can_manage() ) {
			self::die_forbidden();
		}
		if ( function_exists( 'check_admin_referer' ) ) {
			check_admin_referer( self::ACTION_APPLY );
		}
		$plugin = isset( $_POST['handl_aicac_understudy_plugin'] ) // phpcs:ignore WordPress.Security.NonceVerification.Missing
			? self::sanitize_plugin( wp_unslash( (string) $_POST['handl_aicac_understudy_plugin'] ) )
			: '';
		if ( '' !== $plugin ) {
			self::apply_force( $plugin );
		}
		self::redirect();
	}

	public static function handle_revert(): void {
		if ( ! class_exists( Caps::class, false ) || ! Caps::user_can_manage() ) {
			self::die_forbidden();
		}
		if ( function_exists( 'check_admin_referer' ) ) {
			check_admin_referer( self::ACTION_REVERT );
		}
		$plugin = isset( $_POST['handl_aicac_understudy_plugin'] ) // phpcs:ignore WordPress.Security.NonceVerification.Missing
			? self::sanitize_plugin( wp_unslash( (string) $_POST['handl_aicac_understudy_plugin'] ) )
			: '';
		if ( '' !== $plugin ) {
			self::revert_force( $plugin );
		}
		self::redirect();
	}

	public static function render_page(): void {
		if ( ! class_exists( Caps::class, false ) || ! Caps::user_can_view() ) {
			return;
		}
		echo '<div class="wrap">';
		echo '<h1>' . esc_html__( 'Model audition', 'handl-ai-connector-access-control' ) . '</h1>';
		echo '<p class="description">' . esc_html__( 'Try another model on a sample of allowed calls. Tests run in the background. Applying a model changes this plugin\'s future AI calls.', 'handl-ai-connector-access-control' ) . '</p>';

		if ( ! self::is_enabled() ) {
			echo '<p>' . esc_html__( 'Model audition is off.', 'handl-ai-connector-access-control' ) . '</p>';
		}

		$plugins = self::candidate_plugins();
		if ( empty( $plugins ) ) {
			echo '<p>' . esc_html__( 'No plugins are available for an audition yet.', 'handl-ai-connector-access-control' ) . '</p>';
			echo '</div>';

			return;
		}
		foreach ( $plugins as $basename => $label ) {
			echo '<div class="handl-aicac-understudy-card" style="max-width:46em;margin:1.5em 0;padding:1em 1.2em;border:1px solid #c3c4c7;background:#fff;">';
			echo '<h2>' . esc_html( $label ) . '</h2>';
			echo '<p class="description"><code>' . esc_html( $basename ) . '</code></p>';
			self::render_plugin_card( $basename );
			echo '</div>';
		}
		echo '</div>';
	}

	public static function render_plugin_card( string $plugin ): void {
		$plugin = self::sanitize_plugin( $plugin );
		if ( '' === $plugin ) {
			return;
		}
		$row        = self::plugin_row( $plugin );
		$enabled    = self::is_enabled_for( $plugin );
		$can_manage = class_exists( Caps::class, false ) && Caps::user_can_manage();
		$verdict    = self::verdict( $plugin );
		$applied    = ! empty( $verdict['applied'] );

		if ( $can_manage ) {
			echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
			echo '<input type="hidden" name="action" value="' . esc_attr( self::ACTION_SAVE ) . '" />';
			echo '<input type="hidden" name="handl_aicac_understudy_plugin" value="' . esc_attr( $plugin ) . '" />';
			if ( function_exists( 'wp_nonce_field' ) ) {
				wp_nonce_field( self::ACTION_SAVE );
			}
			echo '<p><label><input type="checkbox" name="handl_aicac_understudy_enabled" value="1"' . checked( $enabled, true, false ) . ' /> ';
			echo esc_html__( 'Test another model for this plugin', 'handl-ai-connector-access-control' ) . '</label></p>';
			echo '<p><label>' . esc_html__( 'Provider', 'handl-ai-connector-access-control' ) . ' ';
			echo '<input type="text" class="regular-text code" name="handl_aicac_understudy_provider" value="' . esc_attr( (string) ( $row['provider'] ?? '' ) ) . '" placeholder="openai" autocomplete="off" /></label></p>';
			echo '<p><label>' . esc_html__( 'Model to test', 'handl-ai-connector-access-control' ) . ' ';
			echo '<input type="text" class="regular-text code" name="handl_aicac_understudy_model" value="' . esc_attr( (string) ( $row['model'] ?? '' ) ) . '" placeholder="gpt-4o-mini" autocomplete="off" /></label></p>';
			echo '<p><label>' . esc_html__( 'Sample this percent of allowed calls', 'handl-ai-connector-access-control' ) . ' ';
			echo '<input type="number" min="1" max="100" name="handl_aicac_understudy_sample_pct" value="' . esc_attr( (string) (int) ( $row['sample_pct'] ?? self::SAMPLE_PCT_DEFAULT ) ) . '" /></label></p>';
			echo '<p><label>' . esc_html__( 'Daily sample cap', 'handl-ai-connector-access-control' ) . ' ';
			echo '<input type="number" min="1" max="500" name="handl_aicac_understudy_daily_cap" value="' . esc_attr( (string) (int) ( $row['daily_cap'] ?? self::DAILY_CAP_DEFAULT ) ) . '" /></label></p>';
			if ( function_exists( 'submit_button' ) ) {
				submit_button( __( 'Save audition', 'handl-ai-connector-access-control' ), 'secondary', 'submit', false );
			} else {
				echo '<button type="submit" class="button">' . esc_html__( 'Save audition', 'handl-ai-connector-access-control' ) . '</button>';
			}
			echo '<p class="description">' . esc_html__( 'Test calls may incur provider charges. To stop testing, clear this checkbox and save.', 'handl-ai-connector-access-control' ) . '</p>';
			echo '</form>';
		}

		if ( $applied ) {
			self::render_applied_state( $plugin, $can_manage );
		}

		if ( ! $enabled ) {
			echo '<p>' . esc_html__( 'Model audition is off.', 'handl-ai-connector-access-control' ) . '</p>';

			return;
		}

		if ( $verdict['sample_count'] < 1 ) {
			echo '<p>' . esc_html__( 'Not enough samples yet.', 'handl-ai-connector-access-control' ) . '</p>';

			return;
		}

		echo '<p>' . esc_html(
			sprintf(
				/* translators: 1: similar-wording percent, 2: sample count */
				__( 'Similar wording in %1$s of %2$s samples.', 'handl-ai-connector-access-control' ),
				self::pct_label( (float) $verdict['match_pct'] ),
				self::int_label( (float) $verdict['sample_count'] )
			)
		) . '</p>';
		echo '<p class="description">' . esc_html__( 'Compares shared words only. Similar wording does not confirm accuracy or quality. Review the results before switching models.', 'handl-ai-connector-access-control' ) . '</p>';

		$savings = $verdict['monthly_savings'];
		if ( null !== $savings && $savings > 0 ) {
			echo '<p>' . esc_html(
				sprintf(
					/* translators: %s: estimated USD savings */
					__( 'Estimated savings on priced calls in the last 30 days: %s.', 'handl-ai-connector-access-control' ),
					self::usd_label( (float) $savings )
				)
			) . '</p>';
			echo '<p class="description">' . esc_html__( 'Uses recorded token counts and available rates. Excludes unpriced calls and test-call costs. Actual savings may differ.', 'handl-ai-connector-access-control' ) . '</p>';
		}

		if ( ! $can_manage || $applied ) {
			return;
		}
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" style="margin-top:0.5em;">';
		echo '<input type="hidden" name="action" value="' . esc_attr( self::ACTION_APPLY ) . '" />';
		echo '<input type="hidden" name="handl_aicac_understudy_plugin" value="' . esc_attr( $plugin ) . '" />';
		if ( function_exists( 'wp_nonce_field' ) ) {
			wp_nonce_field( self::ACTION_APPLY );
		}
		echo '<button type="submit" class="button button-primary">' . esc_html__( 'Use this model for this plugin', 'handl-ai-connector-access-control' ) . '</button>';
		echo '</form>';
	}

	private static function render_applied_state( string $plugin, bool $can_manage ): void {
		echo '<p>' . esc_html__( 'This model is applied to future AI calls from this plugin. Stopping the audition does not restore the previous model setting.', 'handl-ai-connector-access-control' ) . '</p>';
		if ( ! $can_manage ) {
			return;
		}
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" style="margin-top:0.5em;">';
		echo '<input type="hidden" name="action" value="' . esc_attr( self::ACTION_REVERT ) . '" />';
		echo '<input type="hidden" name="handl_aicac_understudy_plugin" value="' . esc_attr( $plugin ) . '" />';
		if ( function_exists( 'wp_nonce_field' ) ) {
			wp_nonce_field( self::ACTION_REVERT );
		}
		echo '<button type="submit" class="button">' . esc_html__( 'Restore previous model setting', 'handl-ai-connector-access-control' ) . '</button>';
		echo '</form>';
	}

	/**
	 * @return list<string>
	 */
	private static function tokenize( string $text ): array {
		$text = strtolower( trim( $text ) );
		if ( '' === $text ) {
			return array();
		}
		$parts = preg_split( '/[^a-z0-9]+/i', $text );
		if ( ! is_array( $parts ) ) {
			return array();
		}
		$out = array();
		foreach ( $parts as $part ) {
			if ( is_string( $part ) && '' !== $part ) {
				$out[] = $part;
			}
		}

		return $out;
	}

	private static function sanitize_plugin( $raw ): string {
		if ( class_exists( Plugin_Profile::class, false ) && method_exists( Plugin_Profile::class, 'sanitize_plugin' ) ) {
			return Plugin_Profile::sanitize_plugin( $raw );
		}
		$plugin = sanitize_text_field( (string) $raw );

		return preg_match( '/^[A-Za-z0-9._\-]+(?:\/[A-Za-z0-9._\-]+)*\.php$/', $plugin ) ? $plugin : '';
	}

	private static function sanitize_id( $raw ): string {
		if ( class_exists( Model_Force::class, false ) && method_exists( Model_Force::class, 'sanitize_id' ) ) {
			return Model_Force::sanitize_id( $raw );
		}

		return sanitize_text_field( (string) $raw );
	}

	/**
	 * @return list<array<string,mixed>>
	 */
	private static function activity_rows(): array {
		if ( null !== self::$test_log ) {
			return array_values( self::$test_log );
		}
		if ( class_exists( Dejavu::class, false ) && method_exists( Dejavu::class, 'read_activity_log' ) ) {
			$pack = Dejavu::read_activity_log();
			if ( is_array( $pack ) && isset( $pack['rows'] ) && is_array( $pack['rows'] ) ) {
				return array_values( $pack['rows'] );
			}
		}
		$key = class_exists( Plugin::class, false ) ? Plugin::LOG_OPTION_KEY : 'handl_aicac_recent_calls';
		$raw = get_option( $key, array() );
		if ( ! is_array( $raw ) ) {
			return array();
		}
		$rows = array();
		foreach ( $raw as $row ) {
			if ( is_array( $row ) ) {
				$rows[] = $row;
			}
		}

		return $rows;
	}

	private static function enqueue_from_log(): void {
		$now     = self::now();
		$day_key = gmdate( 'Y-m-d', $now );
		$daily   = self::daily_map();
		$seen    = self::seen_list();
		$queue   = self::queue();
		$cut     = $now - DAY_IN_SECONDS;

		foreach ( self::activity_rows() as $row ) {
			if ( count( $queue ) >= self::MAX_QUEUE ) {
				break;
			}
			if ( ! is_array( $row ) || self::is_shadow_row( $row ) ) {
				continue;
			}
			$decision = strtolower( (string) ( $row['decision'] ?? '' ) );
			if ( ! in_array( $decision, array( 'allow', 'allowed' ), true ) ) {
				continue;
			}
			$plugin = self::sanitize_plugin( $row['plugin'] ?? '' );
			if ( '' === $plugin || ! self::is_enabled_for( $plugin ) ) {
				continue;
			}
			$ts = isset( $row['ts'] ) ? (int) $row['ts'] : 0;
			if ( $ts > 0 && $ts < $cut ) {
				continue;
			}
			$key = self::row_key( $row );
			if ( isset( $seen[ $key ] ) ) {
				continue;
			}
			$cfg = self::plugin_row( $plugin );
			if ( null === $cfg ) {
				continue;
			}
			$used = (int) ( $daily[ $day_key ][ $plugin ] ?? 0 );
			if ( $used >= (int) $cfg['daily_cap'] ) {
				continue;
			}
			if ( ! self::should_sample( $plugin, $row, (int) $cfg['sample_pct'] ) ) {
				$seen[ $key ] = 1;
				continue;
			}
			$queue[] = array(
				'plugin'         => $plugin,
				'ts'             => $ts > 0 ? $ts : $now,
				'operation'      => isset( $row['operation'] ) ? (string) $row['operation'] : '',
				'provider'       => isset( $row['provider'] ) ? (string) $row['provider'] : '',
				'model'          => isset( $row['model'] ) ? (string) $row['model'] : '',
				'live_text'      => self::live_text_from_row( $row ),
				'input_tokens'   => isset( $row['input_tokens'] ) ? (int) $row['input_tokens'] : 0,
				'output_tokens'  => isset( $row['output_tokens'] ) ? (int) $row['output_tokens'] : 0,
				'under_provider' => $cfg['provider'],
				'under_model'    => $cfg['model'],
			);
			$seen[ $key ] = 1;
			if ( ! isset( $daily[ $day_key ] ) ) {
				$daily[ $day_key ] = array();
			}
			$daily[ $day_key ][ $plugin ] = $used + 1;
		}
		self::save_queue( $queue );
		self::save_seen( $seen );
		self::save_daily( $daily );
	}

	private static function drain_queue(): void {
		$queue = self::queue();
		if ( empty( $queue ) ) {
			return;
		}
		$kept = array();
		foreach ( $queue as $job ) {
			if ( ! is_array( $job ) ) {
				continue;
			}
			$plugin = self::sanitize_plugin( $job['plugin'] ?? '' );
			if ( '' === $plugin || ! self::is_enabled_for( $plugin ) ) {
				continue;
			}
			self::replay_job( $job );
		}
		self::save_queue( $kept );
	}

	/**
	 * @param array<string,mixed> $job Queue job.
	 */
	private static function replay_job( array $job ): void {
		$plugin    = self::sanitize_plugin( $job['plugin'] ?? '' );
		$operation = isset( $job['operation'] ) ? (string) $job['operation'] : null;
		$policy    = array();
		$gate      = array(
			'prevent' => false,
			'reason'  => 'allow',
		);
		if ( class_exists( Policy::class, false ) && method_exists( Policy::class, 'get_policy' )
			&& method_exists( Policy::class, 'evaluate' ) ) {
			$policy = Policy::get_policy();
			$eval   = Policy::evaluate( $policy, $plugin, $operation );
			if ( is_array( $eval ) ) {
				$gate = $eval;
			}
		}
		$prevent  = ! empty( $gate['prevent'] );
		$decision = $prevent ? 'deny' : 'allow';
		$now      = self::now();
		$event    = array(
			'ts'         => $now,
			'plugin'     => $plugin,
			'decision'   => $decision,
			'channel'    => self::CHANNEL_SHADOW,
			'tag'        => self::CHANNEL_SHADOW,
			'understudy' => 1,
			'provider'   => (string) ( $job['under_provider'] ?? '' ),
			'model'      => (string) ( $job['under_model'] ?? '' ),
			'operation'  => (string) ( $job['operation'] ?? '' ),
		);
		if ( class_exists( Policy::class, false ) && method_exists( Policy::class, 'append_log_event' ) ) {
			Policy::append_log_event( $event );
		} else {
			self::append_log_fallback( $event );
		}
		if ( $prevent ) {
			return;
		}
		$live   = (string) ( $job['live_text'] ?? '' );
		$shadow = self::shadow_text( $job );
		if ( null === $shadow ) {
			return;
		}
		$score   = self::similarity( $live, $shadow );
		$verdict = self::verdict_for_score( $score );
		$usd     = self::job_usd( $job, $policy, true );
		if ( null !== $usd && $usd > 0 && class_exists( Budget::class, false ) && method_exists( Budget::class, 'add_estimated_spend' ) ) {
			Budget::add_estimated_spend( self::LEDGER_PLUGIN, (float) $usd, $now );
		}
		self::store_sample(
			array(
				'plugin'    => $plugin,
				'ts'        => $now,
				'score'     => $score,
				'verdict'   => $verdict,
				'live'      => (string) ( $job['model'] ?? '' ),
				'under'     => (string) ( $job['under_model'] ?? '' ),
				'usd_under' => $usd,
			)
		);
	}

	/**
	 * @param array<string,mixed> $job Queue job.
	 */
	private static function shadow_text( array $job ): ?string {
		if ( null !== self::$test_shadow_text ) {
			return self::$test_shadow_text;
		}
		$filtered = apply_filters( 'handl_aicac_understudy_shadow_text', null, $job );
		if ( is_string( $filtered ) && '' !== $filtered ) {
			return $filtered;
		}

		return null;
	}

	/**
	 * @param array<string,mixed> $row Activity row.
	 */
	private static function live_text_from_row( array $row ): string {
		foreach ( array( 'prompt_preview', 'response_preview', 'preview' ) as $key ) {
			if ( isset( $row[ $key ] ) && is_string( $row[ $key ] ) && '' !== $row[ $key ] ) {
				return $row[ $key ];
			}
		}

		return '';
	}

	/**
	 * @param array<string,mixed> $row Activity row.
	 */
	private static function row_key( array $row ): string {
		$parts = array(
			(string) ( $row['plugin'] ?? '' ),
			(string) (int) ( $row['ts'] ?? 0 ),
			(string) ( $row['operation'] ?? '' ),
			(string) ( $row['prompt_preview'] ?? '' ),
		);

		return sha1( implode( '|', $parts ) );
	}

	/**
	 * @param array<string,mixed> $row Activity row.
	 */
	private static function should_sample( string $plugin, array $row, int $pct ): bool {
		if ( self::$test_force_sample ) {
			return true;
		}
		$key  = self::row_key( $row ) . '|' . $plugin;
		$mod  = hexdec( substr( sha1( $key ), 0, 8 ) ) % 100;

		return $mod < $pct;
	}

	/**
	 * @param array<string,mixed> $event Log event.
	 */
	private static function append_log_fallback( array $event ): void {
		$key = class_exists( Plugin::class, false ) ? Plugin::LOG_OPTION_KEY : 'handl_aicac_recent_calls';
		$log = get_option( $key, array() );
		if ( ! is_array( $log ) ) {
			$log = array();
		}
		$log[] = $event;
		update_option( $key, $log, false );
	}

	/**
	 * @param array<string,mixed> $sample Sample row (score + verdict only).
	 */
	private static function store_sample( array $sample ): void {
		$rows   = self::samples();
		$rows[] = $sample;
		if ( count( $rows ) > self::MAX_SAMPLES ) {
			$rows = array_slice( $rows, -1 * self::MAX_SAMPLES );
		}
		update_option( self::SAMPLES_OPTION, array_values( $rows ), false );
	}

	/**
	 * @return list<array<string,mixed>>
	 */
	private static function queue(): array {
		$raw = get_option( self::QUEUE_OPTION, array() );
		if ( ! is_array( $raw ) ) {
			return array();
		}
		$out = array();
		foreach ( $raw as $row ) {
			if ( is_array( $row ) ) {
				$out[] = $row;
			}
		}

		return $out;
	}

	/**
	 * @param list<array<string,mixed>> $queue Queue.
	 */
	private static function save_queue( array $queue ): void {
		if ( empty( $queue ) ) {
			delete_option( self::QUEUE_OPTION );

			return;
		}
		update_option( self::QUEUE_OPTION, array_values( $queue ), false );
	}

	private static function drop_plugin_queue( string $plugin ): void {
		$kept = array();
		foreach ( self::queue() as $job ) {
			if ( (string) ( $job['plugin'] ?? '' ) !== $plugin ) {
				$kept[] = $job;
			}
		}
		self::save_queue( $kept );
	}

	/**
	 * @return array<string,int>
	 */
	private static function seen_list(): array {
		$raw = get_option( self::SEEN_OPTION, array() );
		if ( ! is_array( $raw ) ) {
			return array();
		}
		$out = array();
		foreach ( $raw as $key => $one ) {
			if ( is_string( $key ) && '' !== $key ) {
				$out[ $key ] = 1;
			}
		}

		return $out;
	}

	/**
	 * @param array<string,int> $seen Seen keys.
	 */
	private static function save_seen( array $seen ): void {
		if ( count( $seen ) > self::MAX_SEEN ) {
			$seen = array_slice( $seen, -1 * self::MAX_SEEN, null, true );
		}
		update_option( self::SEEN_OPTION, $seen, false );
	}

	/**
	 * @return array<string,array<string,int>>
	 */
	private static function daily_map(): array {
		$raw = get_option( self::DAILY_OPTION, array() );
		if ( ! is_array( $raw ) ) {
			return array();
		}
		$out = array();
		foreach ( $raw as $day => $plugins ) {
			if ( ! is_string( $day ) || ! is_array( $plugins ) ) {
				continue;
			}
			$out[ $day ] = array();
			foreach ( $plugins as $plugin => $n ) {
				if ( is_string( $plugin ) && is_numeric( $n ) ) {
					$out[ $day ][ $plugin ] = (int) $n;
				}
			}
		}

		return $out;
	}

	/**
	 * @param array<string,array<string,int>> $daily Daily map.
	 */
	private static function save_daily( array $daily ): void {
		if ( count( $daily ) > 14 ) {
			$keys = array_keys( $daily );
			sort( $keys );
			foreach ( array_slice( $keys, 0, count( $keys ) - 14 ) as $old ) {
				unset( $daily[ $old ] );
			}
		}
		update_option( self::DAILY_OPTION, $daily, false );
	}

	private static function maybe_schedule(): void {
		if ( ! function_exists( 'wp_next_scheduled' ) || ! function_exists( 'wp_schedule_event' ) ) {
			return;
		}
		$scheduled = wp_next_scheduled( self::CRON_HOOK );
		if ( self::is_enabled() ) {
			if ( false === $scheduled ) {
				wp_schedule_event( self::now() + 60, 'hourly', self::CRON_HOOK );
			}

			return;
		}
		if ( false !== $scheduled && function_exists( 'wp_unschedule_event' ) ) {
			wp_unschedule_event( (int) $scheduled, self::CRON_HOOK );
		}
	}

	/**
	 * @param array<string,mixed> $job    Queue job.
	 * @param array<string,mixed> $policy Policy.
	 */
	private static function job_usd( array $job, array $policy, bool $understudy ): ?float {
		$in  = isset( $job['input_tokens'] ) ? (int) $job['input_tokens'] : 0;
		$out = isset( $job['output_tokens'] ) ? (int) $job['output_tokens'] : 0;
		if ( $in < 1 && $out < 1 ) {
			return null;
		}
		$provider = $understudy ? (string) ( $job['under_provider'] ?? '' ) : (string) ( $job['provider'] ?? '' );
		$model    = $understudy ? (string) ( $job['under_model'] ?? '' ) : (string) ( $job['model'] ?? '' );

		return self::estimate_usd( $policy, $provider, $model, $in, $out );
	}

	/**
	 * @param array<string,mixed> $policy Policy.
	 */
	private static function estimate_usd( array $policy, string $provider, string $model, int $in, int $out ): ?float {
		$rates = null;
		if ( class_exists( Cost_Receipt::class, false ) && method_exists( Cost_Receipt::class, 'rates_for_row' ) ) {
			$rates = Cost_Receipt::rates_for_row( $policy, $provider, $model );
		}
		if ( ! is_array( $rates ) && class_exists( Cost::class, false ) && method_exists( Cost::class, 'rates_from_policy' ) ) {
			$rates = Cost::rates_from_policy( $policy, $provider );
		}
		if ( ! is_array( $rates ) || ! class_exists( Cost::class, false ) || ! method_exists( Cost::class, 'estimate_usd' ) ) {
			return null;
		}
		$usd = Cost::estimate_usd( $in, $out, $rates );

		return is_numeric( $usd ) ? (float) $usd : null;
	}

	private static function estimated_monthly_savings( string $plugin ): ?float {
		$cfg = self::plugin_row( $plugin );
		if ( null === $cfg || '' === $cfg['model'] ) {
			return null;
		}
		$policy = array();
		if ( class_exists( Policy::class, false ) && method_exists( Policy::class, 'get_policy' ) ) {
			$policy = Policy::get_policy();
		}
		$now    = self::now();
		$cut    = $now - self::MONTH_SECONDS;
		$live   = 0.0;
		$under  = 0.0;
		$priced = 0;
		foreach ( self::activity_rows() as $row ) {
			if ( ! is_array( $row ) || self::is_shadow_row( $row ) ) {
				continue;
			}
			if ( self::sanitize_plugin( $row['plugin'] ?? '' ) !== $plugin ) {
				continue;
			}
			$decision = strtolower( (string) ( $row['decision'] ?? '' ) );
			if ( ! in_array( $decision, array( 'allow', 'allowed' ), true ) ) {
				continue;
			}
			$ts = isset( $row['ts'] ) ? (int) $row['ts'] : 0;
			if ( $ts > 0 && $ts < $cut ) {
				continue;
			}
			$in  = isset( $row['input_tokens'] ) ? (int) $row['input_tokens'] : 0;
			$out = isset( $row['output_tokens'] ) ? (int) $row['output_tokens'] : 0;
			$a   = self::estimate_usd( $policy, (string) ( $row['provider'] ?? '' ), (string) ( $row['model'] ?? '' ), $in, $out );
			$b   = self::estimate_usd( $policy, $cfg['provider'], $cfg['model'], $in, $out );
			if ( null === $a || null === $b ) {
				continue;
			}
			$live  += $a;
			$under += $b;
			++$priced;
		}
		if ( $priced < 1 ) {
			return null;
		}
		$delta = $live - $under;

		return $delta > 0 ? round( $delta, 4 ) : 0.0;
	}

	/**
	 * @return array<string,string>
	 */
	private static function candidate_plugins(): array {
		$out = array();
		if ( function_exists( 'get_plugins' ) ) {
			foreach ( get_plugins() as $basename => $info ) {
				$plugin = self::sanitize_plugin( $basename );
				if ( '' === $plugin ) {
					continue;
				}
				$label = is_array( $info ) && isset( $info['Name'] ) ? (string) $info['Name'] : $plugin;
				$out[ $plugin ] = '' !== $label ? $label : $plugin;
			}
		}
		foreach ( self::get_settings()['plugins'] as $plugin => $_row ) {
			if ( ! isset( $out[ $plugin ] ) ) {
				$out[ $plugin ] = $plugin;
			}
		}
		foreach ( self::activity_rows() as $row ) {
			$plugin = self::sanitize_plugin( $row['plugin'] ?? '' );
			if ( '' !== $plugin && ! isset( $out[ $plugin ] ) ) {
				$out[ $plugin ] = $plugin;
			}
		}
		ksort( $out );

		return $out;
	}

	private static function die_forbidden(): void {
		$message = __( 'You do not have permission to save these settings.', 'handl-ai-connector-access-control' );
		if ( function_exists( 'wp_die' ) ) {
			wp_die( esc_html( $message ) );
		}
	}

	private static function redirect(): void {
		$url = admin_url( 'admin.php?page=' . self::PAGE_SLUG );
		if ( function_exists( 'wp_safe_redirect' ) ) {
			wp_safe_redirect( $url );
			exit;
		}
	}

	private static function pct_label( float $pct ): string {
		$n = rtrim( rtrim( number_format( $pct, 1, '.', '' ), '0' ), '.' );

		return $n . '%';
	}

	private static function int_label( float $n ): string {
		$n = (int) round( $n );
		if ( function_exists( 'number_format_i18n' ) ) {
			return (string) number_format_i18n( $n );
		}

		return (string) $n;
	}

	private static function usd_label( float $amount ): string {
		if ( class_exists( Cost::class, false ) && method_exists( Cost::class, 'format_usd' ) ) {
			return (string) Cost::format_usd( $amount );
		}
		$formatted = function_exists( 'number_format_i18n' )
			? number_format_i18n( $amount, 2 )
			: number_format( $amount, 2, '.', ',' );

		return '$' . $formatted;
	}
}
