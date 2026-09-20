<?php
/**
 * AICAC-MCP-GATE (#239): per-plugin allow/deny for MCP tool registration and calls.
 *
 * Opt-in. Site default is inherit → allow, so a fresh install does not change
 * behavior. Missing Abilities / MCP APIs fail open (no fatals, no false denials).
 *
 * Settings live in a dedicated option (not admin.php). CLI stub:
 * `wp handl-aicac mcp`.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Mcp_Gate {

	public const OPTION_KEY = 'handl_aicac_mcp';

	public const REASON = 'mcp';

	public const RULE_INHERIT = 'inherit';
	public const RULE_ALLOW   = 'allow';
	public const RULE_DENY    = 'deny';

	public const ACTION_REGISTER = 'register';
	public const ACTION_CALL     = 'call';

	public const BLOCK_ERROR_CODE = 'handl_aicac_mcp_denied';

	private static ?Mcp_Gate $instance = null;

	/**
	 * Ability name → plugin basename recorded at registration.
	 *
	 * @var array<string,string>
	 */
	private static array $ability_owners = array();

	public static function instance(): Mcp_Gate {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	public static function reset_for_tests(): void {
		self::$ability_owners = array();
		self::$instance       = null;
	}

	public function init(): void {
		// Always hook when WP filter APIs exist. Callbacks no-op unless a
		// denied plugin is involved, so absent Abilities/MCP APIs fail open.
		if ( function_exists( 'add_filter' ) ) {
			add_filter( 'wp_register_ability_args', array( $this, 'filter_register_ability_args' ), 10, 2 );
			add_filter( 'mcp_adapter_pre_tool_call', array( $this, 'filter_pre_tool_call' ), 10, 4 );
			add_filter( 'pre_http_request', array( $this, 'filter_http_request' ), 9, 3 );
		}

		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			CLI_Mcp::register();
		}
	}

	/**
	 * True when Abilities API or MCP adapter is actually present.
	 * Tests may override via $GLOBALS['handl_aicac_test_mcp_surfaces'].
	 */
	public static function surfaces_present(): bool {
		if ( array_key_exists( 'handl_aicac_test_mcp_surfaces', $GLOBALS ) ) {
			return (bool) $GLOBALS['handl_aicac_test_mcp_surfaces'];
		}

		if ( function_exists( 'wp_register_ability' ) || function_exists( 'wp_get_abilities' ) ) {
			return true;
		}

		if ( class_exists( '\\WP\\MCP\\Core\\McpAdapter', false ) || class_exists( '\\WP\\MCP\\Plugin', false ) ) {
			return true;
		}

		if ( defined( 'MCP_ADAPTER_VERSION' ) ) {
			return true;
		}

		return false;
	}

	/**
	 * @return 'inherit'|'allow'|'deny'
	 */
	public static function sanitize_rule( $raw ): string {
		$rule = sanitize_key( (string) $raw );
		if ( self::RULE_ALLOW === $rule || self::RULE_DENY === $rule ) {
			return $rule;
		}

		return self::RULE_INHERIT;
	}

	/**
	 * @param mixed $raw
	 * @return array<string,string> plugin => allow|deny (inherit omitted)
	 */
	public static function sanitize_plugins( $raw ): array {
		if ( ! is_array( $raw ) ) {
			return array();
		}
		$out = array();
		foreach ( $raw as $plugin => $rule ) {
			$plugin = Plugin_Profile::sanitize_plugin( (string) $plugin );
			if ( '' === $plugin ) {
				continue;
			}
			$rule = self::sanitize_rule( $rule );
			if ( self::RULE_INHERIT === $rule ) {
				continue;
			}
			$out[ $plugin ] = $rule;
		}

		return $out;
	}

	/**
	 * @param mixed $raw
	 * @return array{default:string,plugins:array<string,string>}
	 */
	public static function sanitize_settings( $raw ): array {
		if ( ! is_array( $raw ) ) {
			$raw = array();
		}

		return array(
			'default' => self::sanitize_rule( $raw['default'] ?? self::RULE_INHERIT ),
			'plugins' => self::sanitize_plugins( $raw['plugins'] ?? array() ),
		);
	}

	/**
	 * @return array{default:string,plugins:array<string,string>}
	 */
	public static function get_settings(): array {
		$raw = get_option( self::OPTION_KEY, array() );
		return self::sanitize_settings( is_array( $raw ) ? $raw : array() );
	}

	/**
	 * @param array<string,mixed> $settings
	 */
	public static function save_settings( array $settings ): void {
		update_option( self::OPTION_KEY, self::sanitize_settings( $settings ), false );
	}

	/**
	 * @return 'allow'|'deny'
	 */
	public static function effective_default( array $settings ): string {
		$default = self::sanitize_rule( $settings['default'] ?? self::RULE_INHERIT );
		return self::RULE_DENY === $default ? self::RULE_DENY : self::RULE_ALLOW;
	}

	/**
	 * Per-plugin MCP decision. Inherit follows site default; inherit default is allow.
	 *
	 * @return array{prevent:bool,reason:string,decision:string,rule:string}
	 */
	public static function evaluate( ?string $plugin_basename, ?array $settings = null ): array {
		$settings = null === $settings ? self::get_settings() : self::sanitize_settings( $settings );
		$plugin   = Plugin_Profile::sanitize_plugin( (string) $plugin_basename );
		$site     = self::effective_default( $settings );
		$explicit = '';
		if ( '' !== $plugin && isset( $settings['plugins'][ $plugin ] ) ) {
			$explicit = self::sanitize_rule( $settings['plugins'][ $plugin ] );
		}

		$decision = $explicit;
		if ( self::RULE_ALLOW !== $decision && self::RULE_DENY !== $decision ) {
			$decision = $site;
		}

		$prevent = self::RULE_DENY === $decision;

		return array(
			'prevent'  => $prevent,
			'reason'   => $prevent ? self::REASON : '',
			'decision' => $prevent ? self::RULE_DENY : self::RULE_ALLOW,
			'rule'     => '' !== $explicit ? $explicit : self::RULE_INHERIT,
		);
	}

	public static function remember_owner( string $ability_name, ?string $plugin ): void {
		$ability_name = self::sanitize_ability_name( $ability_name );
		$plugin       = Plugin_Profile::sanitize_plugin( (string) $plugin );
		if ( '' === $ability_name || '' === $plugin ) {
			return;
		}
		self::$ability_owners[ $ability_name ] = $plugin;
		$sanitized = str_replace( '/', '-', $ability_name );
		if ( $sanitized !== $ability_name ) {
			self::$ability_owners[ $sanitized ] = $plugin;
		}
	}

	public static function owner_for_ability( string $ability_name ): ?string {
		$ability_name = self::sanitize_ability_name( $ability_name );
		if ( '' === $ability_name ) {
			return null;
		}
		if ( isset( self::$ability_owners[ $ability_name ] ) ) {
			return self::$ability_owners[ $ability_name ];
		}
		$sanitized = str_replace( '/', '-', $ability_name );
		if ( isset( self::$ability_owners[ $sanitized ] ) ) {
			return self::$ability_owners[ $sanitized ];
		}

		return null;
	}

	/**
	 * @param array<string,mixed> $args
	 * @param string              $ability_name
	 * @return array<string,mixed>
	 */
	public function filter_register_ability_args( $args, $ability_name ) {
		if ( ! is_array( $args ) ) {
			return $args;
		}

		$ability_name = self::sanitize_ability_name( (string) $ability_name );
		$plugin       = self::plugin_from_attribution();
		self::remember_owner( $ability_name, $plugin );

		$eval = self::evaluate( $plugin );
		if ( empty( $eval['prevent'] ) ) {
			return $args;
		}

		$args = self::strip_mcp_exposure( $args );
		$args['permission_callback'] = static function ( $input = null ) {
			unset( $input );
			return self::block_error();
		};

		self::record_denial( $plugin, self::ACTION_REGISTER, $ability_name );

		return $args;
	}

	/**
	 * MCP adapter tools/call short-circuit. Return WP_Error to block.
	 *
	 * @param mixed  $args
	 * @param string $tool_name
	 * @param mixed  $mcp_tool
	 * @param mixed  $server
	 * @return mixed
	 */
	public function filter_pre_tool_call( $args, $tool_name = '', $mcp_tool = null, $server = null ) {
		unset( $server );
		if ( is_wp_error( $args ) ) {
			return $args;
		}

		$tool_name = self::sanitize_ability_name( (string) $tool_name );
		$plugin    = self::owner_for_ability( $tool_name );
		if ( null === $plugin ) {
			$ability = self::ability_name_from_tool( $mcp_tool );
			if ( '' !== $ability ) {
				$plugin = self::owner_for_ability( $ability );
				if ( '' === $tool_name ) {
					$tool_name = $ability;
				}
			}
		}
		if ( null === $plugin ) {
			$plugin = self::plugin_from_attribution();
		}

		$eval = self::evaluate( $plugin );
		if ( empty( $eval['prevent'] ) ) {
			return $args;
		}

		self::record_denial( $plugin, self::ACTION_CALL, $tool_name );

		return self::block_error();
	}

	/**
	 * Outbound MCP JSON-RPC (tools/call or tools/list) over HTTP.
	 *
	 * @param mixed               $preempt
	 * @param array<string,mixed> $args
	 * @param string              $url
	 * @return mixed
	 */
	public function filter_http_request( $preempt, $args, $url ) {
		if ( false !== $preempt ) {
			return $preempt;
		}
		if ( ! self::looks_like_mcp_request( $args, $url ) ) {
			return $preempt;
		}

		$plugin = self::plugin_from_attribution();
		$eval   = self::evaluate( $plugin );
		if ( empty( $eval['prevent'] ) ) {
			return $preempt;
		}

		self::record_denial( $plugin, self::ACTION_CALL, self::tool_name_from_http_body( $args ) );

		return self::block_error();
	}

	/**
	 * @param mixed  $args
	 * @param string $url
	 */
	public static function looks_like_mcp_request( $args, $url = '' ): bool {
		unset( $url );
		$body = '';
		if ( is_array( $args ) && isset( $args['body'] ) ) {
			if ( is_array( $args['body'] ) ) {
				$encoded = function_exists( 'wp_json_encode' ) ? wp_json_encode( $args['body'] ) : json_encode( $args['body'] );
				$body    = is_string( $encoded ) ? $encoded : '';
			} else {
				$body = (string) $args['body'];
			}
		}
		if ( '' === $body ) {
			return false;
		}
		if ( false === strpos( $body, 'jsonrpc' ) ) {
			return false;
		}

		return false !== strpos( $body, 'tools/call' ) || false !== strpos( $body, 'tools/list' );
	}

	/**
	 * Self-test coverage for the MCP reason. Skip (do not fail) when APIs are absent.
	 *
	 * @return array{status:string,pass:bool,label:string}
	 */
	public static function selftest_probe(): array {
		$skip_label = __( 'MCP gate skipped (Abilities/MCP APIs not present)', 'handl-ai-connector-access-control' );
		$ok_label   = __( 'MCP gate blocked a denied plugin and allowed an allowed plugin', 'handl-ai-connector-access-control' );
		$fail_label = __( 'MCP gate did not apply allow/deny as expected', 'handl-ai-connector-access-control' );

		if ( ! self::surfaces_present() ) {
			return array(
				'status' => 'skipped',
				'pass'   => true,
				'label'  => $skip_label,
			);
		}

		$original = get_option( self::OPTION_KEY, null );
		$plugin   = class_exists( Selftest::class ) ? Selftest::PLUGIN_BASENAME : 'handl-aicac-selftest/selftest.php';

		try {
			self::save_settings(
				array(
					'default' => self::RULE_INHERIT,
					'plugins' => array( $plugin => self::RULE_DENY ),
				)
			);
			$denied = self::evaluate( $plugin );
			$call   = self::instance()->filter_pre_tool_call( array( 'ok' => true ), 'selftest-tool', null, null );
			$deny_ok = ! empty( $denied['prevent'] )
				&& self::REASON === (string) ( $denied['reason'] ?? '' )
				&& is_wp_error( $call );

			self::save_settings(
				array(
					'default' => self::RULE_INHERIT,
					'plugins' => array( $plugin => self::RULE_ALLOW ),
				)
			);
			$allowed  = self::evaluate( $plugin );
			$call_ok  = self::instance()->filter_pre_tool_call( array( 'ok' => true ), 'selftest-tool', null, null );
			$allow_ok = empty( $allowed['prevent'] ) && ! is_wp_error( $call_ok );

			$pass = $deny_ok && $allow_ok;
			return array(
				'status' => $pass ? 'pass' : 'fail',
				'pass'   => $pass,
				'label'  => $pass ? $ok_label : $fail_label,
			);
		} finally {
			if ( null === $original || false === $original ) {
				delete_option( self::OPTION_KEY );
			} else {
				update_option( self::OPTION_KEY, $original, false );
			}
		}
	}

	public static function block_error(): \WP_Error {
		return new \WP_Error( self::BLOCK_ERROR_CODE, self::block_message() );
	}

	public static function block_message(): string {
		return __( 'This plugin is not allowed to register or call MCP tools.', 'handl-ai-connector-access-control' );
	}

	/**
	 * @param array<string,mixed> $args
	 * @return array<string,mixed>
	 */
	private static function strip_mcp_exposure( array $args ): array {
		if ( ! isset( $args['meta'] ) || ! is_array( $args['meta'] ) ) {
			$args['meta'] = array();
		}
		$args['meta']['public'] = false;
		if ( ! isset( $args['meta']['mcp'] ) || ! is_array( $args['meta']['mcp'] ) ) {
			$args['meta']['mcp'] = array();
		}
		$args['meta']['mcp']['public'] = false;

		return $args;
	}

	private static function plugin_from_attribution(): ?string {
		if ( ! class_exists( Attribution::class ) ) {
			return null;
		}
		$attrib = Attribution::resolve_from_backtrace();
		$plugin = isset( $attrib['plugin'] ) ? Plugin_Profile::sanitize_plugin( (string) $attrib['plugin'] ) : '';

		return '' === $plugin ? null : $plugin;
	}

	/**
	 * @param mixed $mcp_tool
	 */
	private static function ability_name_from_tool( $mcp_tool ): string {
		if ( ! is_object( $mcp_tool ) ) {
			return '';
		}
		if ( method_exists( $mcp_tool, 'get_ability_name' ) ) {
			return self::sanitize_ability_name( (string) $mcp_tool->get_ability_name() );
		}
		if ( method_exists( $mcp_tool, 'get_name' ) ) {
			return self::sanitize_ability_name( (string) $mcp_tool->get_name() );
		}

		return '';
	}

	/**
	 * @param mixed $args
	 */
	private static function tool_name_from_http_body( $args ): string {
		if ( ! is_array( $args ) || ! isset( $args['body'] ) ) {
			return '';
		}
		$body = $args['body'];
		if ( is_array( $body ) ) {
			$params = isset( $body['params'] ) && is_array( $body['params'] ) ? $body['params'] : array();
			if ( isset( $params['name'] ) ) {
				return self::sanitize_ability_name( (string) $params['name'] );
			}
			return '';
		}
		$decoded = json_decode( (string) $body, true );
		if ( ! is_array( $decoded ) ) {
			return '';
		}
		$params = isset( $decoded['params'] ) && is_array( $decoded['params'] ) ? $decoded['params'] : array();
		if ( isset( $params['name'] ) ) {
			return self::sanitize_ability_name( (string) $params['name'] );
		}

		return '';
	}

	private static function sanitize_ability_name( string $name ): string {
		$name = strtolower( trim( $name ) );
		$name = preg_replace( '/[^a-z0-9_\-\/]/', '', $name );
		return is_string( $name ) ? $name : '';
	}

	/**
	 * @param 'register'|'call' $action
	 */
	private static function record_denial( ?string $plugin, string $action, string $tool_name ): void {
		$event = array(
			'ts'            => time(),
			'plugin'        => $plugin,
			'decision'      => self::RULE_DENY,
			'denial_reason' => self::REASON,
			'channel'       => self::REASON,
			'mcp_action'    => $action,
			'mcp_tool'      => $tool_name,
		);

		if ( class_exists( Selftest::class ) && Selftest::is_synthetic_plugin( $plugin ) ) {
			$event['selftest'] = true;
			$event['channel']  = Selftest::CHANNEL;
		}

		if ( class_exists( Policy::class ) ) {
			Policy::append_log_event( $event );
		}

		$policy = class_exists( Policy::class ) ? Policy::get_policy() : array();
		if ( class_exists( Alerts::class ) ) {
			Alerts::maybe_notify_denial( $event, $policy );
		}
	}
}

/**
 * WP-CLI stub for MCP rules (no admin.php in v1).
 *
 * @when after_wp_load
 */
final class CLI_Mcp {

	public static function register(): void {
		if ( ! defined( 'WP_CLI' ) || ! WP_CLI ) {
			return;
		}
		if ( ! class_exists( '\WP_CLI' ) ) {
			return;
		}
		\WP_CLI::add_command( 'handl-aicac mcp', self::class );
	}

	/**
	 * Show MCP rules (site default and per-plugin).
	 *
	 * ## OPTIONS
	 *
	 * [--format=<format>]
	 * : table or json.
	 * ---
	 * default: table
	 * options:
	 *   - table
	 *   - json
	 * ---
	 *
	 * ## EXAMPLES
	 *
	 *     wp handl-aicac mcp get
	 *
	 * @subcommand get
	 *
	 * @param array<int,string>    $args
	 * @param array<string,string> $assoc_args
	 */
	public function get( $args, $assoc_args ): void {
		unset( $args );
		$format   = isset( $assoc_args['format'] ) ? (string) $assoc_args['format'] : 'table';
		$settings = Mcp_Gate::get_settings();

		if ( 'json' === $format ) {
			\WP_CLI::print_value( $settings, array( 'format' => 'json' ) );
			return;
		}

		\WP_CLI::log(
			sprintf(
				'Site default: %s (inherit means allow).',
				$settings['default']
			)
		);
		if ( empty( $settings['plugins'] ) ) {
			\WP_CLI::log( 'No per-plugin MCP rules.' );
			return;
		}
		$rows = array();
		foreach ( $settings['plugins'] as $plugin => $rule ) {
			$rows[] = array(
				'plugin' => $plugin,
				'rule'   => $rule,
			);
		}
		\WP_CLI\Utils\format_items( 'table', $rows, array( 'plugin', 'rule' ) );
	}

	/**
	 * Set one plugin’s MCP rule.
	 *
	 * ## OPTIONS
	 *
	 * <plugin>
	 * : Plugin basename (e.g. acme-plugin/acme-plugin.php).
	 *
	 * <rule>
	 * : allow, deny, or inherit.
	 *
	 * ## EXAMPLES
	 *
	 *     wp handl-aicac mcp set acme-plugin/acme-plugin.php deny
	 *
	 * @subcommand set
	 *
	 * @param array<int,string>    $args
	 * @param array<string,string> $assoc_args
	 */
	public function set( $args, $assoc_args ): void {
		unset( $assoc_args );
		$plugin = Plugin_Profile::sanitize_plugin( isset( $args[0] ) ? (string) $args[0] : '' );
		$rule   = Mcp_Gate::sanitize_rule( isset( $args[1] ) ? (string) $args[1] : '' );
		if ( '' === $plugin ) {
			\WP_CLI::error( 'Need a plugin basename like acme-plugin/acme-plugin.php.' );
		}

		$settings = Mcp_Gate::get_settings();
		if ( Mcp_Gate::RULE_INHERIT === $rule ) {
			unset( $settings['plugins'][ $plugin ] );
		} else {
			$settings['plugins'][ $plugin ] = $rule;
		}
		Mcp_Gate::save_settings( $settings );
		\WP_CLI::success( sprintf( 'MCP rule for %s is %s.', $plugin, $rule ) );
	}

	/**
	 * Set the site-wide MCP default (inherit, allow, or deny). Inherit means allow.
	 *
	 * ## OPTIONS
	 *
	 * <rule>
	 * : inherit, allow, or deny.
	 *
	 * ## EXAMPLES
	 *
	 *     wp handl-aicac mcp default inherit
	 *
	 * @subcommand default
	 *
	 * @param array<int,string>    $args
	 * @param array<string,string> $assoc_args
	 */
	public function default_( $args, $assoc_args ): void {
		unset( $assoc_args );
		$rule     = Mcp_Gate::sanitize_rule( isset( $args[0] ) ? (string) $args[0] : Mcp_Gate::RULE_INHERIT );
		$settings = Mcp_Gate::get_settings();
		$settings['default'] = $rule;
		Mcp_Gate::save_settings( $settings );
		\WP_CLI::success( sprintf( 'MCP site default is %s.', $rule ) );
	}
}
