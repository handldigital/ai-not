<?php
/**
 * AICAC-SNOWFLAKE (#459): settings-divergence census vs plugin defaults.
 *
 * Read-only support inventory. Own curated defaults map (MERGED trunk only).
 * Secret-like keys render as set/not-set. Writes only handl_aicac_snowflake_*.
 *
 * README-FREE. Own admin screen. No admin.php / policy.php edits.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Settings-divergence census.
 */
final class Snowflake {

	public const PAGE_SLUG = 'handl-aicac-snowflake';

	public const CENSUS_OPTION = 'handl_aicac_snowflake_census';

	public const GENERATED_OPTION = 'handl_aicac_snowflake_generated_at';

	public const FILTER_DEFAULTS = 'handl_aicac_snowflake_defaults';

	public const STATUS_DEFAULT    = 'DEFAULT';
	public const STATUS_CUSTOMIZED = 'CUSTOMIZED';
	public const STATUS_UNKNOWN    = 'UNKNOWN';

	public const REDACT_SET     = 'set';
	public const REDACT_NOT_SET = 'not-set';

	/** @var bool */
	private static $registered = false;

	/** @var bool */
	private static $skip_cache = false;

	/** @var array<string,mixed>|null */
	private static $test_defaults = null;

	/** @var array<string,mixed>|null option path => stored value */
	private static $test_stored = null;

	public static function init(): void {
		if ( self::$registered ) {
			return;
		}
		self::$registered = true;
		add_action( 'admin_menu', array( self::class, 'register_menu' ), 20 );
	}

	public static function reset_for_tests(): void {
		self::$registered    = false;
		self::$skip_cache    = false;
		self::$test_defaults = null;
		self::$test_stored   = null;
		delete_option( self::CENSUS_OPTION );
		delete_option( self::GENERATED_OPTION );
	}

	public static function set_skip_cache( bool $skip ): void {
		self::$skip_cache = $skip;
	}

	/**
	 * @param array<string,mixed>|null $defaults Injected defaults map.
	 */
	public static function set_test_defaults( ?array $defaults ): void {
		self::$test_defaults = $defaults;
	}

	/**
	 * @param array<string,mixed>|null $stored Injected stored values by path.
	 */
	public static function set_test_stored( ?array $stored ): void {
		self::$test_stored = $stored;
	}

	/**
	 * Curated defaults for MERGED-trunk user-facing settings (~25).
	 * Paths use option[.nested_key]. Filterable.
	 *
	 * @return array<string,mixed>
	 */
	public static function curated_defaults(): array {
		if ( null !== self::$test_defaults ) {
			return self::$test_defaults;
		}

		$defaults = array(
			// Core gate / logging / alerts (policy nested keys — MERGED trunk).
			'handl_aicac_policy.default'                 => 'allow',
			'handl_aicac_policy.log_enabled'             => false,
			'handl_aicac_policy.audit_only'              => false,
			'handl_aicac_policy.log_limit'               => 200,
			'handl_aicac_policy.log_max_age_days'        => null,
			'handl_aicac_policy.alert_on_deny'           => false,
			'handl_aicac_policy.alert_on_shadow'         => false,
			'handl_aicac_policy.shadow_block_enabled'    => false,
			'handl_aicac_policy.alert_email'             => '',
			'handl_aicac_policy.alert_webhook_url'       => '',
			'handl_aicac_policy.alert_mode'              => 'immediate',
			'handl_aicac_policy.anomaly_alert_enabled'   => false,
			'handl_aicac_policy.anomaly_multiplier'      => 3.0,
			'handl_aicac_policy.anomaly_floor_calls'     => 20,
			'handl_aicac_policy.anomaly_floor_spend'     => 1.0,
			'handl_aicac_policy.review_due_days'         => 90,
			'handl_aicac_policy.est_usd_input_per_m'     => 2.50,
			'handl_aicac_policy.est_usd_output_per_m'    => 10.00,
			'handl_aicac_policy.monthly_report_enabled'  => false,
			'handl_aicac_policy.governance_digest_enabled' => false,
			'handl_aicac_policy.policy_backup_email_enabled' => false,
			// Standalone trunk options.
			'handl_aicac_hardened_mode'                  => '',
			'handl_aicac_uninstall_policy'               => 'keep',
			'handl_aicac_chat_notify.slack_url'          => '',
			'handl_aicac_chat_notify.teams_url'          => '',
			'handl_aicac_chat_notify.min_severity'       => 0,
			'handl_aicac_residency.region'               => 'none',
			'handl_aicac_siem_file_path'                 => '',
			'handl_aicac_demo_mode.seeded_at'            => 0,
		);

		/**
		 * Filter the Snowflake curated defaults map.
		 *
		 * @param array<string,mixed> $defaults Path => default value.
		 */
		$filtered = apply_filters( self::FILTER_DEFAULTS, $defaults );

		return is_array( $filtered ) ? $filtered : $defaults;
	}

	/**
	 * Whether a setting path looks secret-bearing (display redaction only).
	 */
	public static function is_secret_like( string $path ): bool {
		$lower = strtolower( $path );
		foreach ( array( 'key', 'token', 'secret' ) as $needle ) {
			if ( false !== strpos( $lower, $needle ) ) {
				return true;
			}
		}
		// Common webhook URL fields hold secrets in practice.
		if ( false !== strpos( $lower, 'webhook_url' ) || false !== strpos( $lower, 'slack_url' ) || false !== strpos( $lower, 'teams_url' ) ) {
			return true;
		}

		return false;
	}

	/**
	 * @param mixed $value Raw.
	 */
	public static function is_value_set( $value ): bool {
		if ( null === $value || false === $value ) {
			return false;
		}
		if ( is_string( $value ) ) {
			return '' !== $value;
		}
		if ( is_array( $value ) ) {
			return array() !== $value;
		}

		return true;
	}

	/**
	 * Display form for a value (redacts secret-like paths).
	 *
	 * @param mixed $value Raw.
	 * @return mixed
	 */
	public static function display_value( string $path, $value ) {
		if ( self::is_secret_like( $path ) ) {
			return self::is_value_set( $value ) ? self::REDACT_SET : self::REDACT_NOT_SET;
		}

		return $value;
	}

	/**
	 * @param mixed $a Left.
	 * @param mixed $b Right.
	 */
	public static function values_equal( $a, $b ): bool {
		if ( is_float( $a ) || is_float( $b ) ) {
			if ( ! is_numeric( $a ) || ! is_numeric( $b ) ) {
				return false;
			}

			return abs( (float) $a - (float) $b ) < 0.0000001;
		}

		return $a === $b;
	}

	/**
	 * Classify stored value against the curated map.
	 *
	 * @param mixed                $stored Stored value (null = missing).
	 * @param array<string,mixed>  $map    Defaults map.
	 * @return self::STATUS_*
	 */
	public static function classify( string $path, $stored, array $map ): string {
		if ( ! array_key_exists( $path, $map ) ) {
			return self::STATUS_UNKNOWN;
		}
		if ( null === $stored ) {
			return self::STATUS_DEFAULT;
		}
		$default = $map[ $path ];
		if ( self::values_equal( $stored, $default ) ) {
			return self::STATUS_DEFAULT;
		}

		return self::STATUS_CUSTOMIZED;
	}

	/**
	 * Read a dotted path: option or option.nested.
	 *
	 * @return mixed|null Null when the option (or nested key) is absent.
	 */
	public static function read_path( string $path ) {
		if ( null !== self::$test_stored ) {
			return array_key_exists( $path, self::$test_stored ) ? self::$test_stored[ $path ] : null;
		}

		$parts = explode( '.', $path, 2 );
		$option = $parts[0];
		$raw    = get_option( $option, null );
		if ( null === $raw || false === $raw ) {
			return null;
		}
		if ( ! isset( $parts[1] ) ) {
			return $raw;
		}
		if ( ! is_array( $raw ) || ! array_key_exists( $parts[1], $raw ) ) {
			return null;
		}

		return $raw[ $parts[1] ];
	}

	/**
	 * @return array{
	 *   tracked:int,
	 *   customized:int,
	 *   unknown:int,
	 *   rows:list<array{path:string,status:string,default:mixed,current:mixed,default_display:mixed,current_display:mixed}>,
	 *   customized_paths:list<string>,
	 *   as_of:int,
	 *   all_defaults:bool
	 * }
	 */
	public static function census( ?int $now = null ): array {
		$now  = null !== $now ? (int) $now : time();
		$map  = self::curated_defaults();
		$rows = array();
		$customized_paths = array();
		$customized = 0;
		$unknown    = 0;

		foreach ( $map as $path => $default ) {
			$path   = (string) $path;
			$stored = self::read_path( $path );
			$status = self::classify( $path, $stored, $map );
			if ( self::STATUS_CUSTOMIZED === $status ) {
				++$customized;
				$customized_paths[] = $path;
			}
			$rows[] = array(
				'path'            => $path,
				'status'          => $status,
				'default'         => $default,
				'current'         => $stored,
				'default_display' => self::display_value( $path, $default ),
				'current_display' => self::display_value( $path, $stored ),
			);
		}

		$out = array(
			'tracked'           => count( $map ),
			'customized'        => $customized,
			'unknown'           => $unknown,
			'rows'              => $rows,
			'customized_paths'  => $customized_paths,
			'as_of'             => $now,
			'all_defaults'      => 0 === $customized,
		);

		if ( ! self::$skip_cache ) {
			update_option(
				self::CENSUS_OPTION,
				array(
					'tracked'          => $out['tracked'],
					'customized'       => $out['customized'],
					'customized_paths' => $out['customized_paths'],
				),
				false
			);
			update_option( self::GENERATED_OPTION, $now, false );
		}

		return $out;
	}

	/**
	 * Plain-text support block: customized option paths only.
	 *
	 * @param array<string,mixed> $snap Census snapshot.
	 */
	public static function support_block( array $snap ): string {
		$paths = isset( $snap['customized_paths'] ) && is_array( $snap['customized_paths'] )
			? $snap['customized_paths']
			: array();
		if ( empty( $paths ) ) {
			return "AI Not Snowflake — all tracked settings match defaults.\n";
		}
		$lines   = array();
		$lines[] = 'AI Not Snowflake — customized settings (' . count( $paths ) . '):';
		foreach ( $paths as $path ) {
			$lines[] = '- ' . (string) $path;
		}

		return implode( "\n", $lines ) . "\n";
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
			__( 'Snowflake', 'handl-ai-connector-access-control' ),
			__( 'Snowflake', 'handl-ai-connector-access-control' ),
			Caps::VIEW,
			self::PAGE_SLUG,
			array( self::class, 'render_page' )
		);
	}

	public static function render_page(): void {
		if ( ! class_exists( Caps::class, false ) || ! Caps::user_can_view() ) {
			return;
		}

		$snap = self::census();

		echo '<div class="wrap">';
		echo '<h1>' . esc_html__( 'Snowflake', 'handl-ai-connector-access-control' ) . '</h1>';
		echo '<p class="description">' . esc_html__( 'Which AI Not settings differ from plugin defaults on this site. Read-only — nothing is changed here.', 'handl-ai-connector-access-control' ) . '</p>';

		echo '<p><strong>' . esc_html(
			sprintf(
				/* translators: 1: customized count, 2: tracked count */
				__( '%1$s customized of %2$s tracked', 'handl-ai-connector-access-control' ),
				(string) (int) $snap['customized'],
				(string) (int) $snap['tracked']
			)
		) . '</strong></p>';

		if ( ! empty( $snap['all_defaults'] ) ) {
			echo '<p>' . esc_html__( 'All tracked settings match defaults.', 'handl-ai-connector-access-control' ) . '</p>';
		} else {
			echo '<table class="widefat striped"><thead><tr>';
			echo '<th>' . esc_html__( 'Setting', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Default', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Current', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Status', 'handl-ai-connector-access-control' ) . '</th>';
			echo '</tr></thead><tbody>';
			foreach ( $snap['rows'] as $row ) {
				if ( self::STATUS_CUSTOMIZED !== (string) ( $row['status'] ?? '' ) ) {
					continue;
				}
				echo '<tr>';
				echo '<td><code>' . esc_html( (string) $row['path'] ) . '</code></td>';
				echo '<td>' . esc_html( self::stringify( $row['default_display'] ?? null ) ) . '</td>';
				echo '<td>' . esc_html( self::stringify( $row['current_display'] ?? null ) ) . '</td>';
				echo '<td>' . esc_html( (string) $row['status'] ) . '</td>';
				echo '</tr>';
			}
			echo '</tbody></table>';
		}

		echo '<h2>' . esc_html__( 'Support block', 'handl-ai-connector-access-control' ) . '</h2>';
		echo '<p class="description">' . esc_html__( 'Copyable list of customized setting names for support tickets.', 'handl-ai-connector-access-control' ) . '</p>';
		echo '<textarea class="large-text code" rows="8" readonly="readonly">' . esc_html( self::support_block( $snap ) ) . '</textarea>';
		echo '</div>';
	}

	/**
	 * @param mixed $value Display value.
	 */
	private static function stringify( $value ): string {
		if ( null === $value ) {
			return '(absent)';
		}
		if ( is_bool( $value ) ) {
			return $value ? 'true' : 'false';
		}
		if ( is_scalar( $value ) ) {
			return (string) $value;
		}
		$json = function_exists( 'wp_json_encode' ) ? wp_json_encode( $value ) : json_encode( $value );

		return is_string( $json ) ? $json : '';
	}
}
