<?php
/**
 * AI status chips on wp-admin/plugins.php (AICAC-PLUGIN-ROW-CHIPS / #272).
 *
 * One option read for policy + one for the retained log, then an in-memory
 * index. Per-row render is an array lookup — no extra SQL / get_option.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Plugins-screen row chips for users who can view AI Access Control.
 */
final class Plugin_Chips {

	/** Filter: return false to disable chips entirely. */
	public const FILTER = 'handl_aicac_plugin_row_chips';

	/** Activity window for "N denies this week". */
	public const DENY_WINDOW_SECONDS = WEEK_IN_SECONDS;

	private static ?Plugin_Chips $instance = null;

	/**
	 * Request-scoped chip index (basename => chip payload).
	 *
	 * @var array<string,array<string,mixed>>|null
	 */
	private static $index = null;

	public static function instance(): Plugin_Chips {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Reset request cache (PHPUnit).
	 */
	public static function reset_cache(): void {
		self::$index = null;
	}

	public function init(): void {
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_styles' ) );
		add_filter( 'plugin_row_meta', array( $this, 'filter_plugin_row_meta' ), 10, 2 );
		add_action( 'after_plugin_row', array( $this, 'after_plugin_row' ), 10, 2 );
	}

	/**
	 * Styles only on the Plugins screen.
	 *
	 * @param string $hook_suffix Current admin page hook.
	 */
	public function enqueue_styles( string $hook_suffix ): void {
		if ( 'plugins.php' !== $hook_suffix ) {
			return;
		}
		if ( ! self::is_enabled() ) {
			return;
		}
		if ( ! Caps::user_can_view() ) {
			return;
		}
		if ( ! defined( 'HANDL_AICAC_URL' ) || ! function_exists( 'wp_enqueue_style' ) ) {
			return;
		}

		wp_enqueue_style(
			'handl-aicac-plugin-chips',
			HANDL_AICAC_URL . 'assets/plugin-chips.css',
			array(),
			defined( 'HANDL_AICAC_VERSION' ) ? HANDL_AICAC_VERSION : null
		);
	}

	/**
	 * Append a chip link under the plugin description (meta row).
	 *
	 * @param list<string> $plugin_meta Meta HTML fragments.
	 * @param string       $plugin_file Plugin basename.
	 * @return list<string>
	 */
	public function filter_plugin_row_meta( $plugin_meta, $plugin_file ): array {
		$meta = is_array( $plugin_meta ) ? $plugin_meta : array();
		if ( ! self::is_enabled() || ! Caps::user_can_view() ) {
			return $meta;
		}

		$html = self::chip_html( (string) $plugin_file );
		if ( '' === $html ) {
			return $meta;
		}
		$meta[] = $html;

		return $meta;
	}

	/**
	 * Warm the shared index once as rows render (no extra markup — chip lives in meta).
	 *
	 * @param string              $plugin_file Plugin basename.
	 * @param array<string,mixed> $plugin_data Plugin header data (unused).
	 */
	public function after_plugin_row( $plugin_file, $plugin_data = array() ): void {
		unset( $plugin_file, $plugin_data );
		if ( ! self::is_enabled() || ! Caps::user_can_view() ) {
			return;
		}
		self::warm_index();
	}

	/**
	 * Whether chips are enabled (filterable).
	 */
	public static function is_enabled(): bool {
		return (bool) apply_filters( self::FILTER, true );
	}

	/**
	 * Build chip map from policy + log. Pure — no I/O.
	 *
	 * @param array<string,mixed> $policy
	 * @param array<int,mixed>    $log
	 * @return array<string,array{
	 *   status:string,
	 *   label:string,
	 *   class:string,
	 *   deny_count:int,
	 *   has_activity:bool,
	 *   has_storm:bool,
	 *   explicit_rule:string,
	 *   url:string
	 * }>
	 */
	public static function build_index( array $policy, array $log, int $now ): array {
		$rules = is_array( $policy['plugins'] ?? null ) ? (array) $policy['plugins'] : array();
		$audit = ! empty( $policy['audit_only'] );

		$activity = array();
		$denies   = array();
		$storm    = array();

		$week_ago = $now - self::DENY_WINDOW_SECONDS;

		foreach ( $log as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			if ( class_exists( Selftest::class ) && Selftest::is_synthetic_row( $row ) ) {
				continue;
			}
			$channel = isset( $row['channel'] ) ? (string) $row['channel'] : '';
			if ( 'direct_http' === $channel || 'spend_threshold' === $channel ) {
				continue;
			}

			$plugin = isset( $row['plugin'] ) ? Plugin_Profile::sanitize_plugin( (string) $row['plugin'] ) : '';
			if ( '' === $plugin ) {
				continue;
			}

			$activity[ $plugin ] = true;

			$decision = isset( $row['decision'] ) ? (string) $row['decision'] : '';
			$ts       = isset( $row['ts'] ) ? (int) $row['ts'] : 0;
			if ( 'deny' !== $decision || $ts < $week_ago ) {
				continue;
			}

			$n = isset( $row['count'] ) ? (int) $row['count'] : 1;
			if ( $n < 1 ) {
				$n = 1;
			}
			if ( ! isset( $denies[ $plugin ] ) ) {
				$denies[ $plugin ] = 0;
			}
			$denies[ $plugin ] += $n;

			if ( ! empty( $row['retry_storm'] ) || ! empty( $row['retry_storm_collapsed'] ) ) {
				$storm[ $plugin ] = true;
			}
		}

		$keys = array_unique(
			array_merge(
				array_keys( $rules ),
				array_keys( $activity ),
				array_keys( $denies ),
				New_Plugin::pending_plugins( $policy )
			)
		);

		$out = array();
		foreach ( $keys as $plugin ) {
			$plugin = Plugin_Profile::sanitize_plugin( (string) $plugin );
			if ( '' === $plugin ) {
				continue;
			}
			$out[ $plugin ] = self::chip_for_plugin(
				$plugin,
				$policy,
				$rules,
				$audit,
				! empty( $activity[ $plugin ] ),
				isset( $denies[ $plugin ] ) ? (int) $denies[ $plugin ] : 0,
				! empty( $storm[ $plugin ] )
			);
		}

		return $out;
	}

	/**
	 * Resolve one chip payload.
	 *
	 * Priority: storm/recent deny volume → Denied → Watched → Allowed → never seen.
	 *
	 * @param array<string,mixed> $policy
	 * @param array<string,mixed> $rules
	 * @return array{
	 *   status:string,
	 *   label:string,
	 *   class:string,
	 *   deny_count:int,
	 *   has_activity:bool,
	 *   has_storm:bool,
	 *   explicit_rule:string,
	 *   url:string
	 * }
	 */
	public static function chip_for_plugin(
		string $plugin,
		array $policy,
		array $rules,
		bool $audit_only,
		bool $has_activity,
		int $deny_count,
		bool $has_storm
	): array {
		$plugin = Plugin_Profile::sanitize_plugin( $plugin );
		$url    = '' !== $plugin ? Plugin_Profile::rules_url( $plugin ) : Admin::screen_url( 'rules' );

		$explicit = '';
		if ( '' !== $plugin && isset( $rules[ $plugin ] ) ) {
			$rule = (string) $rules[ $plugin ];
			if ( 'allow' === $rule || 'deny' === $rule ) {
				$explicit = $rule;
			}
		}

		$pending_observe = '' !== $plugin
			&& New_Plugin::is_pending( $policy, $plugin )
			&& New_Plugin::INTERIM_OBSERVE === New_Plugin::interim_mode( $policy );
		$pending_deny    = New_Plugin::should_deny_interim( $policy, '' !== $plugin ? $plugin : null );

		if ( $deny_count > 0 && ( $has_storm || $deny_count > 1 ) ) {
			$status = 'denies_week';
			$label  = sprintf(
				/* translators: %d: number of blocked AI calls in the last 7 days */
				_n( 'AI: %d deny this week', 'AI: %d denies this week', $deny_count, 'handl-ai-connector-access-control' ),
				$deny_count
			);
			$class = 'handl-aicac-plugin-chip--denies';
		} elseif ( 'deny' === $explicit || $pending_deny ) {
			$status = 'denied';
			$label  = __( 'AI: Denied', 'handl-ai-connector-access-control' );
			$class  = 'handl-aicac-plugin-chip--denied';
		} elseif (
			$pending_observe
			|| ( $audit_only && $has_activity )
			|| ( '' === $explicit && $has_activity )
		) {
			$status = 'watched';
			$label  = __( 'AI: Watched', 'handl-ai-connector-access-control' );
			$class  = 'handl-aicac-plugin-chip--watched';
		} elseif ( $has_activity || 'allow' === $explicit ) {
			$status = 'allowed';
			$label  = __( 'AI: Allowed', 'handl-ai-connector-access-control' );
			$class  = 'handl-aicac-plugin-chip--allowed';
		} else {
			$status = 'never_seen';
			$label  = __( 'AI: never seen', 'handl-ai-connector-access-control' );
			$class  = 'handl-aicac-plugin-chip--never-seen';
		}

		return array(
			'status'        => $status,
			'label'         => $label,
			'class'         => $class,
			'deny_count'    => $deny_count,
			'has_activity'  => $has_activity,
			'has_storm'     => $has_storm,
			'explicit_rule' => $explicit,
			'url'           => $url,
		);
	}

	/**
	 * HTML for one plugin chip, or empty string when disabled / no cap.
	 */
	public static function chip_html( string $plugin_file ): string {
		if ( ! self::is_enabled() || ! Caps::user_can_view() ) {
			return '';
		}

		$plugin = Plugin_Profile::sanitize_plugin( $plugin_file );
		if ( '' === $plugin ) {
			return '';
		}

		$index = self::warm_index();
		if ( isset( $index[ $plugin ] ) ) {
			$chip = $index[ $plugin ];
		} else {
			$chip = self::chip_for_plugin( $plugin, array(), array(), false, false, 0, false );
		}

		return self::render_chip_anchor( $chip );
	}

	/**
	 * @param array{status:string,label:string,class:string,url:string} $chip
	 */
	public static function render_chip_anchor( array $chip ): string {
		$url   = isset( $chip['url'] ) ? (string) $chip['url'] : '';
		$label = isset( $chip['label'] ) ? (string) $chip['label'] : '';
		$class = isset( $chip['class'] ) ? (string) $chip['class'] : '';
		if ( '' === $label ) {
			return '';
		}

		$title = __( 'Open Rules for this plugin', 'handl-ai-connector-access-control' );

		return sprintf(
			'<a class="handl-aicac-plugin-chip %1$s" href="%2$s" title="%3$s">%4$s</a>',
			esc_attr( $class ),
			esc_url( $url ),
			esc_attr( $title ),
			esc_html( $label )
		);
	}

	/**
	 * Load policy + log once per request and cache the chip index.
	 *
	 * @return array<string,array<string,mixed>>
	 */
	public static function warm_index( ?int $now = null ): array {
		if ( null !== self::$index ) {
			return self::$index;
		}

		$policy      = Policy::get_policy();
		$log         = Policy::get_retained_log( $now );
		$now         = null === $now ? time() : $now;
		self::$index = self::build_index( $policy, $log, $now );

		return self::$index;
	}
}
