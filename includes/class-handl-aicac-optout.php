<?php
/**
 * AICAC-OPTOUT (#501): request no-training / zero-retention flags.
 *
 * Enforcement half of TRAIN-EXPOSURE. Mutates outbound AI HTTP at
 * http_request_args only. Train-Exposure table is class_exists-guarded
 * read-only for per-provider shapes. Strict unsupported-provider deny
 * aborts on pre_http_request with a normal deny receipt. OFF by default.
 *
 * README-FREE. Own options (handl_aicac_optout*). Own admin screen.
 * Zero policy.php / tripwire.php / admin.php / readme.txt edits.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Attach provider no-training flags to outbound AI requests.
 */
final class Optout {

	public const SETTINGS_OPTION = 'handl_aicac_optout';

	public const PAGE_SLUG = 'handl-aicac-optout';

	public const FILTER_MAP = 'handl_aicac_optout_map';

	public const ACTION_SAVE = 'handl_aicac_optout_save';

	public const POST_PRESENT = 'handl_aicac_optout_present';

	public const POST_ENABLED = 'handl_aicac_optout_enabled';

	public const POST_STRICT = 'handl_aicac_optout_strict';

	public const POST_MODES = 'handl_aicac_optout_modes';

	public const REASON = 'optout';

	public const CHANNEL = 'optout';

	public const DETAIL_APPLIED = 'no-train requested';

	public const KIND_JSON = 'json_body';

	public const KIND_HEADER = 'header';

	public const MODE_INHERIT = 'inherit';

	public const MODE_ON = 'on';

	public const MODE_OFF = 'off';

	public const BUNDLED_SHIPPED = '2026-11-11';

	public const STALE_AFTER_DAYS = 120;

	public const FRAMING = 'enforces_request_flags_never_edits_policy';

	public const ERROR_CODE = 'handl_aicac_optout';

	public const MAX_EVENTS = 50;

	/** @var bool */
	private static $registered = false;

	/** @var int|null */
	private static $test_now = null;

	/** @var string|null */
	private static $test_plugin = null;

	/**
	 * Request-local strict deny. Never persisted.
	 *
	 * @var array{plugin:string,provider:string,url:string,host:string}|null
	 */
	private static $pending_deny = null;

	/**
	 * @var list<array<string,mixed>>
	 */
	private static $last_events = array();

	public static function init(): void {
		if ( self::$registered ) {
			return;
		}
		self::$registered = true;
		add_filter( 'http_request_args', array( self::class, 'apply' ), 12, 2 );
		add_filter( 'pre_http_request', array( self::class, 'preempt' ), 7, 3 );
		add_action( 'admin_menu', array( self::class, 'register_menu' ), 20 );
		add_action( 'admin_post_' . self::ACTION_SAVE, array( self::class, 'handle_save' ) );
	}

	public static function reset_for_tests(): void {
		self::$registered    = false;
		self::$test_now      = null;
		self::$test_plugin   = null;
		self::$pending_deny  = null;
		self::$last_events   = array();
		delete_option( self::SETTINGS_OPTION );
	}

	public static function set_test_now( ?int $now ): void {
		self::$test_now = $now;
	}

	public static function set_test_plugin( ?string $plugin ): void {
		self::$test_plugin = ( is_string( $plugin ) && '' !== $plugin ) ? $plugin : null;
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
	 * @return list<array<string,mixed>>
	 */
	public static function last_events(): array {
		return self::$last_events;
	}

	/**
	 * @return array{plugin:string,provider:string,url:string,host:string}|null
	 */
	public static function pending_deny(): ?array {
		return self::$pending_deny;
	}

	/**
	 * @return array{enabled:bool,strict:bool,plugin_modes:array<string,string>}
	 */
	public static function defaults(): array {
		return array(
			'enabled'      => false,
			'strict'       => false,
			'plugin_modes' => array(),
		);
	}

	/**
	 * @return array{enabled:bool,strict:bool,plugin_modes:array<string,string>}
	 */
	public static function get_settings(): array {
		return self::sanitize_settings( get_option( self::SETTINGS_OPTION, array() ) );
	}

	/**
	 * @param mixed $raw Raw settings.
	 * @return array{enabled:bool,strict:bool,plugin_modes:array<string,string>}
	 */
	public static function sanitize_settings( $raw ): array {
		$defaults = self::defaults();
		if ( ! is_array( $raw ) ) {
			return $defaults;
		}

		return array(
			'enabled'      => ! empty( $raw['enabled'] ),
			'strict'       => ! empty( $raw['strict'] ),
			'plugin_modes' => self::sanitize_plugin_modes( $raw['plugin_modes'] ?? array() ),
		);
	}

	/**
	 * @param mixed $raw Raw map.
	 * @return array<string,string> plugin => on|off
	 */
	public static function sanitize_plugin_modes( $raw ): array {
		if ( ! is_array( $raw ) ) {
			return array();
		}
		$out = array();
		foreach ( $raw as $plugin => $mode ) {
			$plugin = self::sanitize_plugin( (string) $plugin );
			if ( '' === $plugin ) {
				continue;
			}
			$mode = self::sanitize_mode( $mode );
			if ( self::MODE_INHERIT === $mode ) {
				continue;
			}
			$out[ $plugin ] = $mode;
		}

		return $out;
	}

	/**
	 * @param mixed $raw Raw mode.
	 */
	public static function sanitize_mode( $raw ): string {
		$mode = sanitize_key( (string) $raw );
		if ( self::MODE_ON === $mode || self::MODE_OFF === $mode ) {
			return $mode;
		}

		return self::MODE_INHERIT;
	}

	public static function sanitize_plugin( string $raw ): string {
		if ( class_exists( Plugin_Profile::class, false ) && method_exists( Plugin_Profile::class, 'sanitize_plugin' ) ) {
			return Plugin_Profile::sanitize_plugin( $raw );
		}
		$plugin = sanitize_text_field( $raw );
		$plugin = str_replace( '\\', '/', $plugin );
		if ( '' === $plugin || false !== strpos( $plugin, '..' ) ) {
			return '';
		}

		return $plugin;
	}

	/**
	 * @param array<string,mixed> $settings Incoming.
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
		return ! empty( self::get_settings()['enabled'] );
	}

	public static function is_strict(): bool {
		return ! empty( self::get_settings()['strict'] );
	}

	public static function enabled_for( ?string $plugin ): bool {
		$settings = self::get_settings();
		$plugin   = self::sanitize_plugin( (string) $plugin );
		if ( '' !== $plugin && isset( $settings['plugin_modes'][ $plugin ] ) ) {
			return self::MODE_ON === $settings['plugin_modes'][ $plugin ];
		}

		return ! empty( $settings['enabled'] );
	}

	/**
	 * Bundled per-provider request mechanisms. Directional — not legal advice.
	 * Override via {@see FILTER_MAP}.
	 *
	 * @return array{
	 *   shipped:string,
	 *   providers:array<string,array{kind:string,field:string,value:mixed,label:string}>
	 * }
	 */
	public static function bundled_map(): array {
		return array(
			'shipped'   => self::BUNDLED_SHIPPED,
			'providers' => array(
				'openai' => array(
					'kind'  => self::KIND_JSON,
					'field' => 'store',
					'value' => false,
					'label' => 'store=false',
				),
			),
		);
	}

	/**
	 * @return array{
	 *   shipped:string,
	 *   providers:array<string,array{kind:string,field:string,value:mixed,label:string}>
	 * }
	 */
	public static function map(): array {
		$bundled = self::bundled_map();
		$raw     = apply_filters( self::FILTER_MAP, $bundled );
		if ( ! is_array( $raw ) ) {
			return $bundled;
		}
		$shipped = isset( $raw['shipped'] ) ? sanitize_text_field( (string) $raw['shipped'] ) : $bundled['shipped'];
		if ( ! preg_match( '/^\d{4}-\d{2}-\d{2}$/', $shipped ) ) {
			$shipped = $bundled['shipped'];
		}
		$providers = array();
		$src       = isset( $raw['providers'] ) && is_array( $raw['providers'] ) ? $raw['providers'] : array();
		foreach ( $src as $id => $row ) {
			$id = self::sanitize_provider( (string) $id );
			if ( '' === $id || ! is_array( $row ) ) {
				continue;
			}
			$clean = self::sanitize_mechanism( $row );
			if ( null === $clean ) {
				continue;
			}
			$providers[ $id ] = $clean;
		}

		return array(
			'shipped'   => $shipped,
			'providers' => $providers,
		);
	}

	public static function sanitize_provider( string $raw ): string {
		$id = sanitize_key( $raw );

		return $id;
	}

	/**
	 * @param array<string,mixed> $row Raw mechanism.
	 * @return array{kind:string,field:string,value:mixed,label:string}|null
	 */
	public static function sanitize_mechanism( array $row ): ?array {
		$kind = sanitize_key( (string) ( $row['kind'] ?? '' ) );
		if ( self::KIND_JSON !== $kind && self::KIND_HEADER !== $kind ) {
			return null;
		}
		$field = (string) ( $row['field'] ?? '' );
		if ( self::KIND_HEADER === $kind ) {
			if ( ! preg_match( '/^[A-Za-z0-9\-]+$/', $field ) ) {
				return null;
			}
		} elseif ( ! preg_match( '/^[A-Za-z0-9_]+$/', $field ) ) {
			return null;
		}
		$value = $row['value'] ?? null;
		if ( is_bool( $value ) ) {
			$clean_value = $value;
		} elseif ( is_int( $value ) ) {
			$clean_value = $value;
		} elseif ( is_string( $value ) ) {
			$clean_value = sanitize_text_field( $value );
			if ( strlen( $clean_value ) > 120 ) {
				$clean_value = substr( $clean_value, 0, 120 );
			}
		} else {
			return null;
		}
		$label = sanitize_text_field( (string) ( $row['label'] ?? $field ) );
		if ( '' === $label ) {
			$label = $field;
		}
		if ( strlen( $label ) > 120 ) {
			$label = substr( $label, 0, 120 );
		}

		return array(
			'kind'  => $kind,
			'field' => $field,
			'value' => $clean_value,
			'label' => $label,
		);
	}

	/**
	 * @return array{kind:string,field:string,value:mixed,label:string}|null
	 */
	public static function mechanism_for( string $provider ): ?array {
		$provider = self::sanitize_provider( $provider );
		if ( '' === $provider ) {
			return null;
		}
		$map = self::map();
		if ( isset( $map['providers'][ $provider ] ) && is_array( $map['providers'][ $provider ] ) ) {
			return $map['providers'][ $provider ];
		}

		return null;
	}

	public static function is_map_stale( ?int $now = null ): bool {
		$now     = null !== $now && $now > 0 ? $now : self::now();
		$map     = self::map();
		$age     = strtotime( (string) $map['shipped'] . ' UTC' );
		$stale_s = self::STALE_AFTER_DAYS * ( defined( 'DAY_IN_SECONDS' ) ? DAY_IN_SECONDS : 86400 );
		if ( $age <= 0 ) {
			return true;
		}

		return ( $now - $age ) > $stale_s;
	}

	/**
	 * Mutate outbound args at the sanctioned HTTP hook.
	 *
	 * @param mixed $args WP HTTP args.
	 * @param mixed $url  Request URL.
	 * @return mixed Args, possibly mutated.
	 */
	public static function apply( $args, $url ) {
		self::$pending_deny = null;
		if ( ! is_array( $args ) ) {
			return $args;
		}
		$url    = is_string( $url ) ? $url : '';
		$plugin = self::caller_plugin();
		if ( ! self::enabled_for( $plugin ) ) {
			return $args;
		}
		$match = self::match_provider( $url );
		if ( null === $match ) {
			return $args;
		}
		$mech = self::mechanism_for( $match['id'] );
		if ( null !== $mech && self::can_apply( $mech, $args ) ) {
			$args = self::mutate_args( $args, $mech );
			self::record_event(
				array(
					'decision' => 'allow',
					'plugin'   => $plugin,
					'provider' => $match['id'],
					'host'     => $match['host'],
					'detail'   => self::DETAIL_APPLIED,
					'optout'   => array(
						'applied'    => true,
						'mechanism'  => $mech['kind'] . ':' . $mech['field'],
						'label'      => $mech['label'],
					),
				)
			);

			return $args;
		}

		if ( self::is_strict() ) {
			self::$pending_deny = array(
				'plugin'   => $plugin,
				'provider' => $match['id'],
				'url'      => $url,
				'host'     => $match['host'],
			);

			return $args;
		}

		self::record_event(
			array(
				'decision' => 'warn',
				'plugin'   => $plugin,
				'provider' => $match['id'],
				'host'     => $match['host'],
				'detail'   => self::missing_mechanism_message( $match['id'] ),
				'optout'   => array(
					'applied'   => false,
					'mechanism' => '',
					'label'     => '',
				),
			)
		);

		return $args;
	}

	/**
	 * Abort a strict unsupported-provider call. Does not mutate args.
	 *
	 * @param mixed $preempt Preempted response.
	 * @param mixed $args    WP HTTP args.
	 * @param mixed $url     Request URL.
	 * @return mixed
	 */
	public static function preempt( $preempt, $args, $url ) {
		$pending = self::$pending_deny;
		self::$pending_deny = null;
		if ( null === $pending ) {
			return $preempt;
		}
		$url = is_string( $url ) ? $url : '';
		if ( $url !== $pending['url'] ) {
			return $preempt;
		}

		$message = self::missing_mechanism_message( $pending['provider'] );
		$event   = array(
			'decision'       => 'deny',
			'plugin'         => $pending['plugin'],
			'provider'       => $pending['provider'],
			'host'           => $pending['host'],
			'detail'         => $message,
			'denial_reason'  => self::REASON,
			'returned_error' => $message,
			'optout'         => array(
				'applied'   => false,
				'mechanism' => '',
				'label'     => '',
			),
		);
		if ( class_exists( Deny_Receipt::class, false ) && method_exists( Deny_Receipt::class, 'stamp' ) ) {
			Deny_Receipt::stamp( $event );
		}
		self::record_event( $event );

		if ( class_exists( '\WP_Error' ) ) {
			return new \WP_Error( self::ERROR_CODE, $message );
		}

		return $preempt;
	}

	/**
	 * @param array{kind:string,field:string,value:mixed,label:string} $mech Mechanism.
	 * @param array<string,mixed>                                     $args Args.
	 */
	public static function can_apply( array $mech, array $args ): bool {
		if ( self::KIND_HEADER === $mech['kind'] ) {
			return true;
		}
		$body = $args['body'] ?? null;
		if ( is_array( $body ) ) {
			return true;
		}
		if ( ! is_string( $body ) || '' === $body ) {
			return false;
		}
		$decoded = json_decode( $body, true );

		return is_array( $decoded );
	}

	/**
	 * @param array<string,mixed>                                     $args Args.
	 * @param array{kind:string,field:string,value:mixed,label:string} $mech Mechanism.
	 * @return array<string,mixed>
	 */
	public static function mutate_args( array $args, array $mech ): array {
		if ( self::KIND_HEADER === $mech['kind'] ) {
			$headers = isset( $args['headers'] ) && is_array( $args['headers'] ) ? $args['headers'] : array();
			$headers[ $mech['field'] ] = $mech['value'];
			$args['headers']           = $headers;

			return $args;
		}

		$body = $args['body'] ?? null;
		if ( is_array( $body ) ) {
			$body[ $mech['field'] ] = $mech['value'];
			$args['body']           = $body;

			return $args;
		}
		if ( ! is_string( $body ) || '' === $body ) {
			return $args;
		}
		$decoded = json_decode( $body, true );
		if ( ! is_array( $decoded ) ) {
			return $args;
		}
		$decoded[ $mech['field'] ] = $mech['value'];
		$encoded                     = function_exists( 'wp_json_encode' ) ? wp_json_encode( $decoded ) : json_encode( $decoded );
		if ( ! is_string( $encoded ) || '' === $encoded ) {
			return $args;
		}
		$args['body'] = $encoded;

		return $args;
	}

	public static function missing_mechanism_message( string $provider ): string {
		$provider = self::sanitize_provider( $provider );

		return sprintf(
			/* translators: %s: provider id */
			__( 'This provider has no request-level no-training flag (%s).', 'handl-ai-connector-access-control' ),
			'' !== $provider ? $provider : 'unknown'
		);
	}

	/**
	 * Host match against Provider_Map::endpoint_signatures() hosts only.
	 *
	 * @return array{id:string,label:string,host:string}|null
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
						'host'  => $host,
					);
				}
			}
		}

		return null;
	}

	/**
	 * Read-only Train-Exposure row for a provider, if that class is present.
	 *
	 * @return array{trains_by_default:string,opt_out:string,zero_retention:string}|null
	 */
	public static function train_exposure_row( string $provider ): ?array {
		if ( ! class_exists( Train_Exposure::class, false ) || ! method_exists( Train_Exposure::class, 'table_row_for' ) ) {
			return null;
		}
		$row = Train_Exposure::table_row_for( $provider );

		return is_array( $row ) ? $row : null;
	}

	/**
	 * @param array<string,mixed> $event Event.
	 */
	private static function record_event( array $event ): void {
		$event['ts']      = isset( $event['ts'] ) ? (int) $event['ts'] : self::now();
		$event['channel'] = self::CHANNEL;
		if ( ! isset( $event['decision'] ) ) {
			$event['decision'] = 'allow';
		}
		self::$last_events[] = $event;
		if ( count( self::$last_events ) > self::MAX_EVENTS ) {
			self::$last_events = array_slice( self::$last_events, -self::MAX_EVENTS );
		}
		if ( class_exists( Policy::class, false ) && method_exists( Policy::class, 'append_log_event' ) ) {
			Policy::append_log_event( $event );
		}
	}

	private static function caller_plugin(): string {
		if ( null !== self::$test_plugin ) {
			return self::$test_plugin;
		}
		if ( class_exists( Attribution::class, false ) ) {
			$resolved = Attribution::resolve_from_backtrace();
			if ( is_array( $resolved ) && ! empty( $resolved['plugin'] ) && is_string( $resolved['plugin'] ) ) {
				return $resolved['plugin'];
			}
		}

		return 'unknown';
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
			__( 'No-training flags', 'handl-ai-connector-access-control' ),
			__( 'No-training flags', 'handl-ai-connector-access-control' ),
			Caps::VIEW,
			self::PAGE_SLUG,
			array( self::class, 'render_page' )
		);
	}

	public static function render_page(): void {
		if ( ! class_exists( Caps::class, false ) || ! Caps::user_can_view() ) {
			return;
		}
		$settings   = self::get_settings();
		$can_manage = Caps::user_can_manage();
		$plugins    = self::candidate_plugins();
		$map        = self::map();

		echo '<div class="wrap">';
		echo '<h1>' . esc_html__( 'No-training flags', 'handl-ai-connector-access-control' ) . '</h1>';
		echo '<p class="description">' . esc_html__( 'Ask providers not to train on or keep this site\'s AI requests, when they offer a request flag. Off by default. This does not change Allow or Deny rules.', 'handl-ai-connector-access-control' ) . '</p>';

		if ( empty( $settings['enabled'] ) && array() === $settings['plugin_modes'] ) {
			echo '<p>' . esc_html__( 'No-training flags are off. Outbound requests are not changed.', 'handl-ai-connector-access-control' ) . '</p>';
		}

		if ( self::is_map_stale() ) {
			echo '<div class="notice notice-warning"><p>' . esc_html__( 'The provider flag table is more than 120 days old. Confirm current provider terms.', 'handl-ai-connector-access-control' ) . '</p></div>';
		}
		if ( class_exists( Train_Exposure::class, false ) && method_exists( Train_Exposure::class, 'is_table_stale' ) && Train_Exposure::is_table_stale( self::now() ) ) {
			echo '<div class="notice notice-warning"><p>' . esc_html__( 'The Training exposure table is more than 120 days old. Flag shapes may be out of date.', 'handl-ai-connector-access-control' ) . '</p></div>';
		}

		if ( $can_manage ) {
			echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
			echo '<input type="hidden" name="action" value="' . esc_attr( self::ACTION_SAVE ) . '" />';
			echo '<input type="hidden" name="' . esc_attr( self::POST_PRESENT ) . '" value="1" />';
			if ( function_exists( 'wp_nonce_field' ) ) {
				wp_nonce_field( self::ACTION_SAVE );
			}
			echo '<table class="form-table" role="presentation"><tbody>';
			echo '<tr><th scope="row">' . esc_html__( 'Request flags', 'handl-ai-connector-access-control' ) . '</th><td>';
			echo '<label><input type="checkbox" name="' . esc_attr( self::POST_ENABLED ) . '" value="1" ' . checked( ! empty( $settings['enabled'] ), true, false ) . ' /> ';
			echo esc_html__( 'Request no-training / zero-retention where the provider supports it.', 'handl-ai-connector-access-control' );
			echo '</label></td></tr>';
			echo '<tr><th scope="row">' . esc_html__( 'Unsupported providers', 'handl-ai-connector-access-control' ) . '</th><td>';
			echo '<label><input type="checkbox" name="' . esc_attr( self::POST_STRICT ) . '" value="1" ' . checked( ! empty( $settings['strict'] ), true, false ) . ' /> ';
			echo esc_html__( 'Block calls to providers with no request-level flag.', 'handl-ai-connector-access-control' );
			echo '</label>';
			echo '<p class="description">' . esc_html__( 'When this is off, those calls go out and a warning is logged.', 'handl-ai-connector-access-control' ) . '</p>';
			echo '</td></tr></tbody></table>';
		}

		echo '<h2>' . esc_html__( 'Provider flags', 'handl-ai-connector-access-control' ) . '</h2>';
		echo '<p class="description">' . esc_html__( 'Only listed flags are attached to requests. Other providers have no request-level mechanism.', 'handl-ai-connector-access-control' ) . '</p>';
		echo '<table class="widefat striped" style="max-width:56em;"><thead><tr>';
		echo '<th>' . esc_html__( 'Provider', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Request flag', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Training exposure', 'handl-ai-connector-access-control' ) . '</th>';
		echo '</tr></thead><tbody>';
		$ids = self::provider_ids_for_table( $map );
		if ( array() === $ids ) {
			echo '<tr><td colspan="3">' . esc_html__( 'No provider flag map is available.', 'handl-ai-connector-access-control' ) . '</td></tr>';
		}
		foreach ( $ids as $id ) {
			$mech = $map['providers'][ $id ] ?? null;
			$exp  = self::train_exposure_row( $id );
			echo '<tr><td><code>' . esc_html( $id ) . '</code></td><td>';
			if ( is_array( $mech ) ) {
				echo esc_html( (string) $mech['label'] );
			} else {
				echo esc_html__( 'No request flag', 'handl-ai-connector-access-control' );
			}
			echo '</td><td>';
			if ( is_array( $exp ) ) {
				echo esc_html( (string) ( $exp['opt_out'] ?? '' ) );
			} else {
				echo '—';
			}
			echo '</td></tr>';
		}
		echo '</tbody></table>';

		if ( array() !== $plugins ) {
			echo '<h2>' . esc_html__( 'Per-plugin override', 'handl-ai-connector-access-control' ) . '</h2>';
			echo '<table class="widefat striped" style="max-width:52em;"><thead><tr>';
			echo '<th>' . esc_html__( 'Plugin', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Override', 'handl-ai-connector-access-control' ) . '</th>';
			echo '</tr></thead><tbody>';
			foreach ( $plugins as $basename => $label ) {
				$current = $settings['plugin_modes'][ $basename ] ?? self::MODE_INHERIT;
				echo '<tr><td>' . esc_html( $label ) . '<br /><code>' . esc_html( $basename ) . '</code></td><td>';
				if ( $can_manage ) {
					echo '<select name="' . esc_attr( self::POST_MODES ) . '[' . esc_attr( $basename ) . ']">';
					foreach ( self::mode_choices() as $value => $choice_label ) {
						echo '<option value="' . esc_attr( $value ) . '"' . selected( $current, $value, false ) . '>' . esc_html( $choice_label ) . '</option>';
					}
					echo '</select>';
				} else {
					echo esc_html( self::mode_choices()[ $current ] ?? $current );
				}
				echo '</td></tr>';
			}
			echo '</tbody></table>';
		}

		if ( $can_manage ) {
			if ( function_exists( 'submit_button' ) ) {
				submit_button( __( 'Save no-training flags', 'handl-ai-connector-access-control' ) );
			} else {
				echo '<p><button type="submit" class="button button-primary">' . esc_html__( 'Save no-training flags', 'handl-ai-connector-access-control' ) . '</button></p>';
			}
			echo '</form>';
		}

		echo '</div>';
	}

	/**
	 * @param array{shipped:string,providers:array<string,array<string,mixed>>} $map Map.
	 * @return list<string>
	 */
	public static function provider_ids_for_table( array $map ): array {
		$ids = array_keys( $map['providers'] );
		if ( class_exists( Provider_Map::class, false ) && method_exists( Provider_Map::class, 'endpoint_signatures' ) ) {
			foreach ( array_keys( Provider_Map::endpoint_signatures() ) as $id ) {
				$id = self::sanitize_provider( (string) $id );
				if ( '' !== $id && ! in_array( $id, $ids, true ) ) {
					$ids[] = $id;
				}
			}
		}
		sort( $ids );

		return $ids;
	}

	/**
	 * @return array<string,string>
	 */
	public static function mode_choices(): array {
		return array(
			self::MODE_INHERIT => __( 'Use site setting', 'handl-ai-connector-access-control' ),
			self::MODE_ON      => __( 'Request flags', 'handl-ai-connector-access-control' ),
			self::MODE_OFF     => __( 'Skip this plugin', 'handl-ai-connector-access-control' ),
		);
	}

	/**
	 * @return array<string,string>
	 */
	public static function candidate_plugins(): array {
		$out = array();
		if ( function_exists( 'get_plugins' ) ) {
			foreach ( get_plugins() as $basename => $info ) {
				$plugin = self::sanitize_plugin( (string) $basename );
				if ( '' === $plugin ) {
					continue;
				}
				$label = is_array( $info ) && isset( $info['Name'] ) ? (string) $info['Name'] : $plugin;
				$out[ $plugin ] = '' !== $label ? $label : $plugin;
			}
		}
		foreach ( array_keys( self::get_settings()['plugin_modes'] ) as $basename ) {
			$plugin = self::sanitize_plugin( (string) $basename );
			if ( '' !== $plugin && ! isset( $out[ $plugin ] ) ) {
				$out[ $plugin ] = $plugin;
			}
		}
		ksort( $out );

		return $out;
	}

	public static function handle_save(): void {
		$back = class_exists( Halt::class, false ) ? Halt::admin_page_url( self::PAGE_SLUG ) : '';
		if ( ! class_exists( Caps::class, false ) || ! Caps::user_can_manage() ) {
			if ( class_exists( Halt::class, false ) ) {
				Halt::permission_denied( __( 'You do not have permission to save these settings.', 'handl-ai-connector-access-control' ), $back );
			}

			return;
		}
		if ( function_exists( 'check_admin_referer' ) ) {
			check_admin_referer( self::ACTION_SAVE );
		}
		if ( empty( $_POST[ self::POST_PRESENT ] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing
			if ( class_exists( Halt::class, false ) ) {
				Halt::security_check_failed( $back );
			}

			return;
		}
		$raw_modes = isset( $_POST[ self::POST_MODES ] ) && is_array( $_POST[ self::POST_MODES ] ) // phpcs:ignore WordPress.Security.NonceVerification.Missing
			? wp_unslash( $_POST[ self::POST_MODES ] ) // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
			: array();
		self::save_settings(
			array(
				'enabled'      => ! empty( $_POST[ self::POST_ENABLED ] ), // phpcs:ignore WordPress.Security.NonceVerification.Missing
				'strict'       => ! empty( $_POST[ self::POST_STRICT ] ), // phpcs:ignore WordPress.Security.NonceVerification.Missing
				'plugin_modes' => is_array( $raw_modes ) ? $raw_modes : array(),
			)
		);
		if ( class_exists( Halt::class, false ) ) {
			Halt::saved( __( 'No-training flags saved.', 'handl-ai-connector-access-control' ), $back );
		}
	}
}
