<?php
/**
 * AICAC-DEMO-MODE (#300): one-click sample data for a fresh install.
 *
 * Seeds labeled Activity rows (never policy rules). Remove restores the log
 * to pre-seed contents when nothing else wrote, and always deletes demo rows.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Sample-data seed, teardown, banner, and emitter skip.
 */
final class Demo_Mode {

	public const OPTION_KEY = 'handl_aicac_demo_mode';

	public const CRON_HOOK = 'handl_aicac_demo_expire';

	public const ACTION_SEED = 'handl_aicac_demo_seed';

	public const ACTION_REMOVE = 'handl_aicac_demo_remove';

	public const ACTION_DISMISS = 'handl_aicac_demo_dismiss';

	public const USER_META_DISMISS = 'handl_aicac_demo_banner_dismissed';

	public const TTL_SECONDS = 604800; // 7 days.

	public const PLUGIN_SEO = 'demo-seo-writer/demo-seo-writer.php';

	public const PLUGIN_CHAT = 'demo-chat-widget/demo-chat-widget.php';

	public const LABEL_SEO = 'Demo SEO Writer';

	public const LABEL_CHAT = 'Demo Chat Widget';

	public const BANNER = 'Showing sample data';

	public const CTA_SEED = 'Preview with sample data';

	public const CTA_REMOVE = 'Remove sample data';

	public const CTA_DISMISS = 'Dismiss';

	/** @var bool */
	private static $registered = false;

	public static function init(): void {
		if ( self::$registered ) {
			return;
		}
		self::$registered = true;
		add_action( self::CRON_HOOK, array( self::class, 'cron_expire' ) );
		add_action( 'admin_init', array( self::class, 'handle_post' ) );
		add_action( 'admin_notices', array( self::class, 'maybe_render_notice' ) );
		add_action( 'network_admin_notices', array( self::class, 'maybe_render_notice' ) );
		self::maybe_schedule();
		self::maybe_expire();
	}

	public static function reset_for_tests(): void {
		self::$registered = false;
		delete_option( self::OPTION_KEY );
	}

	public static function maybe_schedule(): void {
		if ( ! function_exists( 'wp_next_scheduled' ) || ! function_exists( 'wp_schedule_event' ) ) {
			return;
		}
		if ( ! wp_next_scheduled( self::CRON_HOOK ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', self::CRON_HOOK );
		}
	}

	public static function cron_expire(): void {
		self::maybe_expire();
	}

	/**
	 * @param array<string,mixed> $row
	 */
	public static function is_demo_row( array $row ): bool {
		return ! empty( $row['demo'] );
	}

	/**
	 * @param array<int,mixed> $log
	 * @return list<array<string,mixed>|mixed>
	 */
	public static function without_demo( array $log ): array {
		$out = array();
		foreach ( $log as $row ) {
			if ( is_array( $row ) && self::is_demo_row( $row ) ) {
				continue;
			}
			$out[] = $row;
		}

		return array_values( $out );
	}

	/**
	 * @param array<string,mixed> $row
	 */
	public static function skip_emitters( array $row ): bool {
		return self::is_demo_row( $row );
	}

	public static function is_active(): bool {
		$state = self::get_state();

		return $state['seeded_at'] > 0;
	}

	/**
	 * @return array{seeded_at:int,expires_at:int,had_log:bool}
	 */
	public static function get_state(): array {
		return self::sanitize_state( get_option( self::OPTION_KEY, array() ) );
	}

	/**
	 * @param mixed $raw
	 * @return array{seeded_at:int,expires_at:int,had_log:bool}
	 */
	public static function sanitize_state( $raw ): array {
		$raw = is_array( $raw ) ? $raw : array();

		return array(
			'seeded_at'  => isset( $raw['seeded_at'] ) ? (int) $raw['seeded_at'] : 0,
			'expires_at' => isset( $raw['expires_at'] ) ? (int) $raw['expires_at'] : 0,
			'had_log'    => ! empty( $raw['had_log'] ),
		);
	}

	/**
	 * @return array{ok:bool,seeded:int,status:string}
	 */
	public static function seed( ?int $now = null ): array {
		$now = null !== $now && $now > 0 ? $now : time();
		if ( self::is_active() ) {
			return array(
				'ok'     => true,
				'seeded' => 0,
				'status' => 'already',
			);
		}

		$raw     = get_option( Plugin::LOG_OPTION_KEY, false );
		$had_log = false !== $raw;
		$log     = is_array( $raw ) ? $raw : array();
		$rows    = self::sample_rows( $now );
		foreach ( $rows as $row ) {
			$log[] = $row;
		}
		update_option( Plugin::LOG_OPTION_KEY, $log, false );
		update_option(
			self::OPTION_KEY,
			array(
				'seeded_at'  => $now,
				'expires_at' => $now + self::TTL_SECONDS,
				'had_log'    => $had_log,
			),
			false
		);

		return array(
			'ok'     => true,
			'seeded' => count( $rows ),
			'status' => 'seeded',
		);
	}

	/**
	 * @return array{ok:bool,removed:int,status:string}
	 */
	public static function remove(): array {
		$state = self::get_state();
		$raw   = get_option( Plugin::LOG_OPTION_KEY, false );
		$log   = is_array( $raw ) ? $raw : array();
		$kept  = self::without_demo( $log );
		$gone  = count( $log ) - count( $kept );

		if ( empty( $kept ) && ! $state['had_log'] ) {
			delete_option( Plugin::LOG_OPTION_KEY );
		} else {
			update_option( Plugin::LOG_OPTION_KEY, array_values( $kept ), false );
		}
		delete_option( self::OPTION_KEY );

		return array(
			'ok'      => true,
			'removed' => $gone,
			'status'  => $gone > 0 || $state['seeded_at'] > 0 ? 'removed' : 'idle',
		);
	}

	public static function maybe_expire( ?int $now = null ): void {
		$now   = null !== $now && $now > 0 ? $now : time();
		$state = self::get_state();
		if ( $state['seeded_at'] <= 0 ) {
			return;
		}
		$expires = $state['expires_at'] > 0 ? $state['expires_at'] : ( $state['seeded_at'] + self::TTL_SECONDS );
		if ( $now >= $expires ) {
			self::remove();
		}
	}

	/**
	 * @return list<array<string,mixed>>
	 */
	public static function sample_rows( int $now ): array {
		$week_ago = $now - ( 8 * DAY_IN_SECONDS );
		$burst    = $now - 90;
		$seo      = self::PLUGIN_SEO;
		$chat     = self::PLUGIN_CHAT;

		$rows   = array();
		$rows[] = self::row(
			$week_ago,
			$seo,
			'allow',
			'openai',
			'gpt-4o-mini',
			1200,
			400,
			'Demo SEO Writer weekly allow'
		);
		$rows[] = self::row(
			$now - ( 2 * DAY_IN_SECONDS ),
			$seo,
			'allow',
			'openai',
			'gpt-4o-mini',
			800,
			200,
			'Demo SEO Writer recent allow'
		);
		$rows[] = self::row(
			$now - 3600,
			$chat,
			'observe',
			'anthropic',
			'claude-3-haiku',
			400,
			80,
			'Demo Chat Widget newcomer hold',
			array(
				'reason'  => 'newcomer_hold',
				'channel' => 'ai_client',
			)
		);

		for ( $i = 0; $i < 6; $i++ ) {
			$extra = array();
			if ( 5 === $i ) {
				$extra['retry_storm'] = true;
			}
			$rows[] = self::row(
				$burst + $i,
				$chat,
				'deny',
				'openai',
				'gpt-4o-mini',
				50,
				0,
				'Demo Chat Widget deny burst',
				$extra
			);
		}

		return $rows;
	}

	/**
	 * @param array<string,mixed> $extra
	 * @return array<string,mixed>
	 */
	private static function row( int $ts, string $plugin, string $decision, string $provider, string $model, int $in, int $out, string $prompt, array $extra = array() ): array {
		$base = array(
			'ts'            => $ts,
			'plugin'        => $plugin,
			'plugin_name'   => self::PLUGIN_SEO === $plugin ? self::LABEL_SEO : self::LABEL_CHAT,
			'decision'      => $decision,
			'provider'      => $provider,
			'model'         => $model,
			'input_tokens'  => $in,
			'output_tokens' => $out,
			'prompt'        => $prompt,
			'demo'          => true,
		);

		return array_merge( $base, $extra );
	}

	public static function handle_post(): void {
		$action = isset( $_POST['handl_aicac_demo_action'] ) ? sanitize_key( wp_unslash( (string) $_POST['handl_aicac_demo_action'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing -- verified below.
		if ( '' === $action ) {
			return;
		}
		if ( ! Caps::user_can_manage() ) {
			return;
		}
		if ( self::ACTION_SEED === $action ) {
			check_admin_referer( self::ACTION_SEED, 'handl_aicac_nonce' );
			self::seed();
			self::redirect_back();
		}
		if ( self::ACTION_REMOVE === $action ) {
			check_admin_referer( self::ACTION_REMOVE, 'handl_aicac_nonce' );
			self::remove();
			self::redirect_back();
		}
		if ( self::ACTION_DISMISS === $action ) {
			check_admin_referer( self::ACTION_DISMISS, 'handl_aicac_nonce' );
			$user_id = get_current_user_id();
			if ( $user_id > 0 ) {
				update_user_meta( $user_id, self::USER_META_DISMISS, (string) self::get_state()['seeded_at'] );
			}
			self::redirect_back();
		}
	}

	public static function maybe_render_notice(): void {
		if ( ! Caps::user_can_view() ) {
			return;
		}
		$hook = '';
		if ( function_exists( 'get_current_screen' ) ) {
			$screen = get_current_screen();
			if ( is_object( $screen ) && isset( $screen->id ) ) {
				$hook = (string) $screen->id;
			}
		}
		if ( ! Admin::is_plugin_admin_hook( $hook ) ) {
			return;
		}

		$active = self::is_active();
		if ( $active && self::user_dismissed() ) {
			return;
		}

		echo '<div class="notice notice-info handl-aicac-demo-banner"><p>';
		if ( $active ) {
			echo '<strong>' . esc_html__( 'Showing sample data', 'handl-ai-connector-access-control' ) . '</strong>';
			echo '</p>';
			echo '<form method="post" style="margin:0 0 8px 0;display:inline-block;margin-right:8px;">';
			wp_nonce_field( self::ACTION_REMOVE, 'handl_aicac_nonce' );
			echo '<input type="hidden" name="handl_aicac_demo_action" value="' . esc_attr( self::ACTION_REMOVE ) . '" />';
			submit_button( __( 'Remove sample data', 'handl-ai-connector-access-control' ), 'secondary', 'submit', false );
			echo '</form>';
			echo '<form method="post" style="margin:0 0 8px 0;display:inline-block;">';
			wp_nonce_field( self::ACTION_DISMISS, 'handl_aicac_nonce' );
			echo '<input type="hidden" name="handl_aicac_demo_action" value="' . esc_attr( self::ACTION_DISMISS ) . '" />';
			submit_button( __( 'Dismiss', 'handl-ai-connector-access-control' ), 'link', 'submit', false );
			echo '</form>';
		} else {
			echo esc_html__( 'Preview with sample data', 'handl-ai-connector-access-control' );
			echo '</p>';
			echo '<form method="post" style="margin:0 0 8px 0;">';
			wp_nonce_field( self::ACTION_SEED, 'handl_aicac_nonce' );
			echo '<input type="hidden" name="handl_aicac_demo_action" value="' . esc_attr( self::ACTION_SEED ) . '" />';
			submit_button( __( 'Preview with sample data', 'handl-ai-connector-access-control' ), 'secondary', 'submit', false );
			echo '</form>';
		}
		echo '</div>';
	}

	private static function user_dismissed(): bool {
		$user_id = get_current_user_id();
		if ( $user_id <= 0 ) {
			return false;
		}
		$mark = (string) get_user_meta( $user_id, self::USER_META_DISMISS, true );

		return $mark !== '' && $mark === (string) self::get_state()['seeded_at'];
	}

	private static function redirect_back(): void {
		if ( function_exists( 'wp_get_referer' ) && function_exists( 'wp_safe_redirect' ) ) {
			$back = wp_get_referer();
			if ( is_string( $back ) && '' !== $back ) {
				wp_safe_redirect( $back );
				exit;
			}
		}
	}
}
