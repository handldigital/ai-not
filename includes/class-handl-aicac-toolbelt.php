<?php
/**
 * AICAC-TOOLBELT (#519): outbound tool census.
 *
 * Report-only. Own http_request_args observer. Never mutates args.
 * First tool list for a plugin is baseline (no alert). A new tool name
 * alerts once through the existing email/webhook paths and respects snooze,
 * same contract as Drift. Off by default. README-FREE. Own option and screen.
 * No policy.php, admin.php, drift, luggage, or mcp-gate edits.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Census of tool names plugins hand to AI providers.
 */
final class Toolbelt {

	public const PAGE_SLUG = 'handl-aicac-toolbelt';

	public const SETTINGS_OPTION = 'handl_aicac_toolbelt';

	public const SEEN_OPTION = 'handl_aicac_toolbelt_seen';

	public const ACTION_SAVE = 'handl_aicac_toolbelt_save';

	public const POST_PRESENT = 'handl_aicac_toolbelt_present';

	public const POST_ENABLED = 'handl_aicac_toolbelt_enabled';

	public const ALERT_KIND = 'toolbelt';

	public const MAX_TOOLS = 100;

	public const MAX_NAME = 80;

	/** @var list<string> */
	private const MUTATING_PREFIXES = array(
		'create',
		'update',
		'delete',
		'send',
		'write',
		'set',
		'publish',
		'pay',
		'refund',
	);

	/** @var bool */
	private static $registered = false;

	/** @var int|null */
	private static $test_now = null;

	/** @var string|null */
	private static $test_plugin = null;

	public static function init(): void {
		if ( self::$registered ) {
			return;
		}
		self::$registered = true;

		add_filter( 'http_request_args', array( self::class, 'observe' ), 13, 2 );
		add_action( 'admin_menu', array( self::class, 'register_menu' ), 20 );
		add_action( 'admin_post_' . self::ACTION_SAVE, array( self::class, 'handle_save' ) );
	}

	public static function reset_for_tests(): void {
		self::$registered  = false;
		self::$test_now    = null;
		self::$test_plugin = null;
		delete_option( self::SETTINGS_OPTION );
		delete_option( self::SEEN_OPTION );
	}

	public static function set_test_now( ?int $now ): void {
		self::$test_now = $now;
	}

	public static function set_test_plugin( ?string $plugin ): void {
		self::$test_plugin = $plugin;
	}

	public static function now(): int {
		if ( null !== self::$test_now ) {
			return self::$test_now;
		}

		return time();
	}

	public static function is_enabled(): bool {
		$raw = get_option( self::SETTINGS_OPTION, false );
		if ( ! is_array( $raw ) ) {
			return false;
		}

		return ! empty( $raw['enabled'] );
	}

	/**
	 * @param array<string,mixed> $settings
	 */
	public static function save_settings( array $settings ): bool {
		$enabled = ! empty( $settings['enabled'] );
		$had     = get_option( self::SETTINGS_OPTION, false );
		if ( ! $enabled ) {
			if ( false === $had || array() === $had ) {
				return false;
			}
			delete_option( self::SETTINGS_OPTION );

			return true;
		}
		$clean = array( 'enabled' => true );
		if ( is_array( $had ) && $had === $clean ) {
			return false;
		}
		update_option( self::SETTINGS_OPTION, $clean, false );

		return true;
	}

	/**
	 * Filter callback. Returns $args unchanged.
	 *
	 * @param mixed $args
	 * @param mixed $url
	 * @return mixed
	 */
	public static function observe( $args, $url ) {
		if ( is_array( $args ) ) {
			self::sample( $args, is_string( $url ) ? $url : '' );
		}

		return $args;
	}

	/**
	 * Read-only sample. Never writes into $args.
	 *
	 * @param array<string,mixed> $args
	 */
	public static function sample( array $args, string $url ): void {
		if ( ! self::is_enabled() ) {
			return;
		}
		$match = self::match_provider( $url );
		if ( null === $match ) {
			return;
		}
		$names = self::extract_tool_names( $args['body'] ?? null );
		if ( null === $names || array() === $names ) {
			return;
		}
		$plugin = self::caller_plugin();
		if ( '' === $plugin ) {
			return;
		}
		self::record( $plugin, (string) $match['id'], $names, self::now() );
	}

	/**
	 * @return array{id:string,label:string}|null
	 */
	public static function match_provider( string $url ): ?array {
		if ( '' === $url ) {
			return null;
		}
		$host = strtolower( (string) ( function_exists( 'wp_parse_url' ) ? wp_parse_url( $url, PHP_URL_HOST ) : parse_url( $url, PHP_URL_HOST ) ) );
		if ( '' === $host ) {
			return null;
		}
		if ( ! class_exists( Provider_Map::class, false ) || ! method_exists( Provider_Map::class, 'endpoint_signatures' ) ) {
			return null;
		}
		foreach ( Provider_Map::endpoint_signatures() as $id => $sig ) {
			if ( ! is_array( $sig ) ) {
				continue;
			}
			$hosts = isset( $sig['hosts'] ) && is_array( $sig['hosts'] ) ? $sig['hosts'] : array();
			foreach ( $hosts as $sig_host ) {
				$sig_host = strtolower( trim( (string) $sig_host ) );
				if ( '' === $sig_host ) {
					continue;
				}
				$suffix = '.' . $sig_host;
				if ( $host === $sig_host || ( strlen( $host ) > strlen( $suffix ) && substr( $host, -strlen( $suffix ) ) === $suffix ) ) {
					$label = isset( $sig['label'] ) && '' !== (string) $sig['label'] ? (string) $sig['label'] : (string) $id;

					return array(
						'id'    => (string) $id,
						'label' => $label,
					);
				}
			}
		}

		return null;
	}

	/**
	 * Tool names from a provider body. Null means the body could not be parsed.
	 * An empty list means a parsed body with no tool names.
	 *
	 * @param mixed $body
	 * @return list<string>|null
	 */
	public static function extract_tool_names( $body ): ?array {
		$decoded = self::decode_body( $body );
		if ( null === $decoded ) {
			return null;
		}
		if ( ! is_array( $decoded ) ) {
			return array();
		}

		$names = array();
		$tools = $decoded['tools'] ?? null;
		if ( is_array( $tools ) ) {
			foreach ( $tools as $tool ) {
				if ( ! is_array( $tool ) ) {
					continue;
				}
				self::collect_tool_object( $tool, $names );
			}
		}
		$decls = $decoded['functionDeclarations'] ?? null;
		if ( is_array( $decls ) ) {
			foreach ( $decls as $decl ) {
				self::collect_name( is_array( $decl ) ? ( $decl['name'] ?? '' ) : '', $names );
			}
		}

		return array_keys( $names );
	}

	public static function changes_things( string $name ): bool {
		$lower = strtolower( $name );
		foreach ( self::MUTATING_PREFIXES as $prefix ) {
			if ( 0 === strpos( $lower, $prefix ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * @return array<string,array<string,array{name:string,first_seen:int,last_seen:int,provider:string}>>
	 */
	public static function get_seen(): array {
		return self::sanitize_seen( get_option( self::SEEN_OPTION, array() ) );
	}

	/**
	 * @param mixed $raw
	 * @return array<string,array<string,array{name:string,first_seen:int,last_seen:int,provider:string}>>
	 */
	public static function sanitize_seen( $raw ): array {
		if ( ! is_array( $raw ) ) {
			return array();
		}
		$out = array();
		foreach ( $raw as $plugin => $tools ) {
			$plugin = class_exists( Plugin_Profile::class, false )
				? Plugin_Profile::sanitize_plugin( (string) $plugin )
				: '';
			if ( '' === $plugin || ! is_array( $tools ) ) {
				continue;
			}
			$bucket = array();
			foreach ( $tools as $row ) {
				if ( ! is_array( $row ) ) {
					continue;
				}
				$name = self::sanitize_name( (string) ( $row['name'] ?? '' ) );
				if ( '' === $name ) {
					continue;
				}
				$first = max( 0, (int) ( $row['first_seen'] ?? 0 ) );
				$last  = max( $first, (int) ( $row['last_seen'] ?? 0 ) );
				$bucket[ $name ] = array(
					'name'       => $name,
					'first_seen' => $first,
					'last_seen'  => $last,
					'provider'   => sanitize_key( (string) ( $row['provider'] ?? '' ) ),
				);
				if ( count( $bucket ) >= self::MAX_TOOLS ) {
					break;
				}
			}
			if ( array() !== $bucket ) {
				$out[ $plugin ] = $bucket;
			}
		}

		return $out;
	}

	/**
	 * @return list<array{plugin:string,count:int,tools:list<array{name:string,first_seen:int,last_seen:int,provider:string,changes:bool}>}>
	 */
	public static function screen_rows(): array {
		$rows = array();
		foreach ( self::get_seen() as $plugin => $tools ) {
			$list = array();
			foreach ( $tools as $row ) {
				$list[] = array(
					'name'       => $row['name'],
					'first_seen' => $row['first_seen'],
					'last_seen'  => $row['last_seen'],
					'provider'   => $row['provider'],
					'changes'    => self::changes_things( $row['name'] ),
				);
			}
			usort(
				$list,
				static function ( array $a, array $b ): int {
					return strcmp( $a['name'], $b['name'] );
				}
			);
			$rows[] = array(
				'plugin' => $plugin,
				'count'  => count( $list ),
				'tools'  => $list,
			);
		}
		usort(
			$rows,
			static function ( array $a, array $b ): int {
				return strcmp( $a['plugin'], $b['plugin'] );
			}
		);

		return $rows;
	}

	public static function register_menu(): void {
		if ( ! self::user_can_view() ) {
			return;
		}
		if ( ! function_exists( 'add_submenu_page' ) || ! class_exists( Admin::class, false ) ) {
			return;
		}
		add_submenu_page(
			Admin::MENU_SLUG,
			__( 'Toolbelt', 'handl-ai-connector-access-control' ),
			__( 'Toolbelt', 'handl-ai-connector-access-control' ),
			class_exists( Caps::class, false ) ? Caps::VIEW : 'manage_options',
			self::PAGE_SLUG,
			array( self::class, 'render_page' )
		);
	}

	public static function handle_save(): void {
		if ( ! self::user_can_manage() ) {
			wp_die( esc_html__( 'You do not have permission to save Toolbelt.', 'handl-ai-connector-access-control' ) );
		}
		check_admin_referer( self::ACTION_SAVE );
		if ( empty( $_POST[ self::POST_PRESENT ] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing
			wp_die( esc_html__( 'Security check failed. Go back, reload the page, and try again.', 'handl-ai-connector-access-control' ) );
		}
		self::save_settings(
			array(
				'enabled' => ! empty( $_POST[ self::POST_ENABLED ] ), // phpcs:ignore WordPress.Security.NonceVerification.Missing
			)
		);
		self::redirect_to_page();
	}

	public static function render_page(): void {
		if ( ! self::user_can_view() ) {
			return;
		}
		$enabled    = self::is_enabled();
		$can_manage = self::user_can_manage();

		echo '<div class="wrap">';
		echo '<h1>' . esc_html__( 'Toolbelt', 'handl-ai-connector-access-control' ) . '</h1>';
		echo '<p>' . esc_html__( 'See which functions plugins let the AI call. Off until you turn it on. This does not allow or block anything.', 'handl-ai-connector-access-control' ) . '</p>';

		if ( $can_manage ) {
			echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
			echo '<input type="hidden" name="action" value="' . esc_attr( self::ACTION_SAVE ) . '" />';
			echo '<input type="hidden" name="' . esc_attr( self::POST_PRESENT ) . '" value="1" />';
			if ( function_exists( 'wp_nonce_field' ) ) {
				wp_nonce_field( self::ACTION_SAVE );
			}
			echo '<p><label><input type="checkbox" name="' . esc_attr( self::POST_ENABLED ) . '" value="1"' . checked( $enabled, true, false ) . ' /> ';
			echo esc_html__( 'Watch tool lists', 'handl-ai-connector-access-control' ) . '</label></p>';
			if ( function_exists( 'submit_button' ) ) {
				submit_button( __( 'Save toolbelt', 'handl-ai-connector-access-control' ) );
			} else {
				echo '<p><button type="submit" class="button button-primary">' . esc_html__( 'Save toolbelt', 'handl-ai-connector-access-control' ) . '</button></p>';
			}
			echo '</form>';
		}

		$rows = self::screen_rows();
		if ( array() === $rows ) {
			echo '<p>' . esc_html__( 'No tools recorded yet.', 'handl-ai-connector-access-control' ) . '</p>';
			echo '</div>';

			return;
		}

		foreach ( $rows as $group ) {
			echo '<h2>' . esc_html( $group['plugin'] ) . '</h2>';
			echo '<p>' . esc_html(
				sprintf(
					/* translators: %d: number of tool names */
					_n( '%d tool', '%d tools', $group['count'], 'handl-ai-connector-access-control' ),
					$group['count']
				)
			) . '</p>';
			echo '<table class="widefat striped"><thead><tr>';
			echo '<th>' . esc_html__( 'Tool', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'First seen', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Flag', 'handl-ai-connector-access-control' ) . '</th>';
			echo '</tr></thead><tbody>';
			foreach ( $group['tools'] as $tool ) {
				echo '<tr>';
				echo '<td>' . esc_html( $tool['name'] ) . '</td>';
				echo '<td>' . esc_html( self::format_ts( $tool['first_seen'] ) ) . '</td>';
				echo '<td>' . esc_html( $tool['changes'] ? __( 'Changes things', 'handl-ai-connector-access-control' ) : '' ) . '</td>';
				echo '</tr>';
			}
			echo '</tbody></table>';
		}
		echo '</div>';
	}

	public static function build_subject( string $plugin, string $tool ): string {
		return sprintf(
			/* translators: 1: plugin basename, 2: new tool name */
			__( 'New tool for %1$s: %2$s', 'handl-ai-connector-access-control' ),
			$plugin,
			$tool
		);
	}

	public static function build_body( string $plugin, string $tool ): string {
		$lines   = array();
		$lines[] = sprintf(
			/* translators: %s: plugin basename */
			__( 'Plugin: %s', 'handl-ai-connector-access-control' ),
			$plugin
		);
		$lines[] = sprintf(
			/* translators: %s: new tool name */
			__( 'New tool: %s', 'handl-ai-connector-access-control' ),
			$tool
		);
		$lines[] = __( 'This does not change allow or deny.', 'handl-ai-connector-access-control' );
		$lines[] = self::screen_url();

		return implode( "\n", $lines ) . "\n";
	}

	/**
	 * @param list<string> $names
	 */
	private static function record( string $plugin, string $provider, array $names, int $now ): void {
		$map    = self::get_seen();
		$bucket = isset( $map[ $plugin ] ) && is_array( $map[ $plugin ] ) ? $map[ $plugin ] : array();
		$baseline = array() === $bucket;
		$added    = array();
		$changed  = false;
		foreach ( $names as $name ) {
			if ( isset( $bucket[ $name ] ) ) {
				if ( (int) $bucket[ $name ]['last_seen'] !== $now || (string) $bucket[ $name ]['provider'] !== $provider ) {
					$bucket[ $name ]['last_seen'] = $now;
					$bucket[ $name ]['provider']  = $provider;
					$changed                      = true;
				}
				continue;
			}
			if ( count( $bucket ) >= self::MAX_TOOLS ) {
				continue;
			}
			$bucket[ $name ] = array(
				'name'       => $name,
				'first_seen' => $now,
				'last_seen'  => $now,
				'provider'   => $provider,
			);
			$added[] = $name;
			$changed = true;
		}
		if ( $changed ) {
			$map[ $plugin ] = $bucket;
			update_option( self::SEEN_OPTION, $map, false );
		}
		if ( $baseline || array() === $added ) {
			return;
		}
		foreach ( $added as $name ) {
			self::maybe_alert( $plugin, $name, $now );
		}
	}

	private static function maybe_alert( string $plugin, string $tool, int $now ): bool {
		if ( class_exists( Alert_Snooze::class, false ) && Alert_Snooze::should_suppress( $plugin, self::ALERT_KIND, $now ) ) {
			return false;
		}
		$policy = class_exists( Policy::class, false ) ? Policy::get_policy() : array();
		if ( ! is_array( $policy ) ) {
			$policy = array();
		}
		$to = class_exists( Alert_Routing::class, false )
			? Alert_Routing::resolve_email( $policy, self::ALERT_KIND )
			: '';
		if ( '' === $to && class_exists( Alerts::class, false ) ) {
			$to = Alerts::resolve_email( $policy );
		}
		if ( '' === $to || ! class_exists( Alerts::class, false ) ) {
			return false;
		}
		$ok = Alerts::safe_wp_mail( $to, self::build_subject( $plugin, $tool ), self::build_body( $plugin, $tool ) );
		$hook = Alerts::resolve_webhook( $policy );
		if ( '' !== $hook ) {
			Alerts::safe_wp_remote_post(
				$hook,
				array(
					'type'   => 'handl_aicac_toolbelt_alert',
					'plugin' => $plugin,
					'tool'   => $tool,
				)
			);
		}

		return $ok;
	}

	/**
	 * @param mixed $body
	 * @return array<string,mixed>|null
	 */
	private static function decode_body( $body ): ?array {
		if ( is_array( $body ) ) {
			return $body;
		}
		if ( ! is_string( $body ) || '' === $body ) {
			return array();
		}
		$trimmed = ltrim( $body );
		if ( '' === $trimmed || ( '{' !== $trimmed[0] && '[' !== $trimmed[0] ) ) {
			return null;
		}
		$decoded = json_decode( $body, true );
		if ( JSON_ERROR_NONE !== json_last_error() ) {
			return null;
		}
		if ( ! is_array( $decoded ) ) {
			return array();
		}

		return $decoded;
	}

	/**
	 * @param array<string,mixed> $tool
	 * @param array<string,true>  $names
	 */
	private static function collect_tool_object( array $tool, array &$names ): void {
		$function = $tool['function'] ?? null;
		if ( is_array( $function ) ) {
			self::collect_name( $function['name'] ?? '', $names );
		}
		$decls = $tool['functionDeclarations'] ?? null;
		if ( is_array( $decls ) ) {
			foreach ( $decls as $decl ) {
				self::collect_name( is_array( $decl ) ? ( $decl['name'] ?? '' ) : '', $names );
			}
		}
		if ( ! is_array( $function ) && ! is_array( $decls ) ) {
			self::collect_name( $tool['name'] ?? '', $names );
		}
	}

	/**
	 * @param mixed               $raw
	 * @param array<string,true>  $names
	 */
	private static function collect_name( $raw, array &$names ): void {
		$name = self::sanitize_name( (string) $raw );
		if ( '' === $name ) {
			return;
		}
		$names[ $name ] = true;
	}

	private static function sanitize_name( string $name ): string {
		$name = str_replace( array( "\0", "\r", "\n", "\t" ), '', $name );
		$name = trim( $name );
		if ( strlen( $name ) > self::MAX_NAME ) {
			$name = substr( $name, 0, self::MAX_NAME );
		}
		if ( '' === $name || ! preg_match( '/^[A-Za-z0-9_.:\/\-]+$/', $name ) ) {
			return '';
		}

		return $name;
	}

	private static function caller_plugin(): string {
		$raw = '';
		if ( null !== self::$test_plugin ) {
			$raw = self::$test_plugin;
		} elseif ( class_exists( Attribution::class, false ) && method_exists( Attribution::class, 'resolve_from_backtrace' ) ) {
			$resolved = Attribution::resolve_from_backtrace();
			if ( is_array( $resolved ) && ! empty( $resolved['plugin'] ) && is_string( $resolved['plugin'] ) ) {
				$raw = $resolved['plugin'];
			}
		}
		if ( '' === $raw || ! class_exists( Plugin_Profile::class, false ) ) {
			return '';
		}

		return Plugin_Profile::sanitize_plugin( $raw );
	}

	private static function screen_url(): string {
		if ( function_exists( 'admin_url' ) ) {
			return admin_url( 'admin.php?page=' . self::PAGE_SLUG );
		}

		return '';
	}

	private static function format_ts( int $ts ): string {
		if ( $ts <= 0 ) {
			return '—';
		}
		if ( function_exists( 'wp_date' ) ) {
			return (string) wp_date( 'Y-m-d', $ts );
		}

		return gmdate( 'Y-m-d', $ts );
	}

	private static function redirect_to_page(): void {
		$url = self::screen_url();
		if ( function_exists( 'wp_safe_redirect' ) ) {
			wp_safe_redirect( $url );
			exit;
		}
	}

	private static function user_can_view(): bool {
		if ( class_exists( Caps::class, false ) ) {
			return Caps::user_can_view();
		}

		return function_exists( 'current_user_can' ) && current_user_can( 'manage_options' );
	}

	private static function user_can_manage(): bool {
		if ( class_exists( Caps::class, false ) ) {
			return Caps::user_can_manage();
		}

		return function_exists( 'current_user_can' ) && current_user_can( 'manage_options' );
	}
}
