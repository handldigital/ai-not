<?php
/**
 * AICAC-TOMBSTONE (#425): dangling-reference sweeper (report only, never deletes).
 *
 * Rules outlive the things they name. A plugin is uninstalled but its Allow
 * rule stays; a role is deleted but the role gate still lists it; a user is
 * removed but a request from them is still pending. Most of that is harmless
 * clutter. One case is not: when the plugin is installed again the old Allow
 * rule is live again, without anyone having reviewed it. This class lists the
 * dangling references and raises one alert for that sharp edge only.
 *
 * Design rules:
 * - Report only. It never deletes, edits or disables a rule, role, user,
 *   plugin or another control's option. Every inventory read is read-only.
 * - Writes are confined to the two own options (settings + state).
 * - Detection runs on a throttled admin_init (and on demand from WP-CLI and
 *   from the activated_plugin listener), never from a cron hook. This class
 *   schedules nothing.
 * - Dangling references alone stay on screen. The re-arming [TOMBSTONE] alert
 *   is reserved for a resurrection: a plugin that was dangling with an Allow
 *   rule and is installed again. Alerts is reused through class_exists /
 *   method_exists guards only.
 * - wp_die is used only by this class's own settings save.
 * - User-keyed references are flag-only: Offboard owns that cleanup lane.
 * - Own two options. OFF by default.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Dangling-reference sweeper.
 */
final class Tombstone {

	public const SETTINGS_OPTION = 'handl_aicac_tombstone';

	public const STATE_OPTION = 'handl_aicac_tombstone_state';

	public const PAGE_SLUG = 'handl-aicac-tombstone';

	public const ALERT_KIND = 'tombstone';

	public const FRAMING = 'report_only_never_deletes';

	public const POST_PRESENT = 'handl_aicac_tombstone_present';
	public const POST_ENABLED = 'handl_aicac_tombstone_enabled';

	public const ACTION_SAVE = 'handl_aicac_tombstone_save';

	/** Admin check throttle in seconds (5 minutes). */
	public const CHECK_THROTTLE_SECONDS = 300;

	public const CODE_PLUGIN       = 'dangling_plugin_rule';
	public const CODE_ROLE         = 'dangling_role';
	public const CODE_USER         = 'dangling_user_ref';
	public const CODE_RESURRECTION = 'resurrection';

	public const KIND_PLUGIN = 'plugin';
	public const KIND_ROLE   = 'role';
	public const KIND_USER   = 'user';

	public const VIA_ACTIVATION = 'activation';
	public const VIA_INVENTORY  = 'inventory';

	public const SEVERITY_HIGH = 'high';
	public const SEVERITY_INFO = 'info';

	/** Maximum tracked entries per state map / history list. */
	public const STATE_CAP = 500;

	public const HISTORY_CAP = 50;

	/** @var bool */
	private static $registered = false;

	/** @var list<array<string,mixed>> */
	private static $test_mails = array();

	/** @var int|null */
	private static $test_now = null;

	/** @var array<string,mixed>|null */
	private static $test_policy = null;

	/** @var array<int|string,mixed>|null */
	private static $test_installed = null;

	/** @var array<int,mixed>|null */
	private static $test_log = null;

	/** @var array<int|string,mixed>|null */
	private static $test_roles = null;

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
			// Detection rides a throttled admin request, never a cron hook.
			add_action( 'admin_init', array( self::class, 'maybe_check' ), 30 );
			// Pure listener: it only writes this class's own state.
			add_action( 'activated_plugin', array( self::class, 'on_activated_plugin' ), 10, 1 );
		}

		self::register_cli();
	}

	public static function reset_for_tests(): void {
		self::$registered     = false;
		self::$test_mails     = array();
		self::$test_now       = null;
		self::$test_policy    = null;
		self::$test_installed = null;
		self::$test_log       = null;
		self::$test_roles     = null;
		delete_option( self::SETTINGS_OPTION );
		delete_option( self::STATE_OPTION );
	}

	/**
	 * @return list<array<string,mixed>>
	 */
	public static function test_mails(): array {
		return self::$test_mails;
	}

	public static function set_test_now( ?int $now ): void {
		self::$test_now = $now;
	}

	/**
	 * Inject the policy. Null reads the live policy.
	 *
	 * @param array<string,mixed>|null $policy Policy.
	 */
	public static function set_test_policy( ?array $policy ): void {
		self::$test_policy = $policy;
	}

	/**
	 * Inject the installed plugin basenames (list, or get_plugins()-style map).
	 * Null reads get_plugins().
	 *
	 * @param array<int|string,mixed>|null $installed Installed plugins.
	 */
	public static function set_test_installed_plugins( ?array $installed ): void {
		self::$test_installed = $installed;
	}

	/**
	 * Inject the activity log rows. Null reads the live log option.
	 *
	 * @param array<int,mixed>|null $log Log rows.
	 */
	public static function set_test_log( ?array $log ): void {
		self::$test_log = $log;
	}

	/**
	 * Inject the existing role slugs (list, or wp_roles()-style map). Null reads WordPress.
	 *
	 * @param array<int|string,mixed>|null $roles Roles.
	 */
	public static function set_test_roles( ?array $roles ): void {
		self::$test_roles = $roles;
	}

	/* ---------------------------------------------------------------------
	 * Settings
	 * ------------------------------------------------------------------ */

	/**
	 * @return array{enabled:bool}
	 */
	public static function defaults(): array {
		return array( 'enabled' => false );
	}

	/**
	 * @return array{enabled:bool}
	 */
	public static function get_settings(): array {
		return self::sanitize_settings( get_option( self::SETTINGS_OPTION, array() ) );
	}

	/**
	 * @param mixed $raw Raw settings.
	 * @return array{enabled:bool}
	 */
	public static function sanitize_settings( $raw ): array {
		if ( ! is_array( $raw ) ) {
			return self::defaults();
		}

		return array( 'enabled' => ! empty( $raw['enabled'] ) );
	}

	/**
	 * @param array<string,mixed> $settings Settings.
	 * @return bool True when the stored value changed.
	 */
	public static function save_settings( array $settings ): bool {
		$clean  = self::sanitize_settings( $settings );
		$before = self::get_settings();
		if ( $clean === $before ) {
			return false;
		}
		if ( $clean === self::defaults() ) {
			delete_option( self::SETTINGS_OPTION );
		} else {
			update_option( self::SETTINGS_OPTION, $clean, false );
		}

		if ( ! empty( $clean['enabled'] ) ) {
			// Silent first inventory: records what is already dangling, never alerts for it.
			self::scan();
		}

		return true;
	}

	public static function is_enabled(): bool {
		$settings = self::get_settings();

		return ! empty( $settings['enabled'] );
	}

	/* ---------------------------------------------------------------------
	 * State
	 * ------------------------------------------------------------------ */

	/**
	 * @return array<string,mixed>
	 */
	public static function defaults_state(): array {
		return array(
			'alerted'             => false,
			'last_check_ts'       => 0,
			'last_alert_ts'       => 0,
			'last_seen_installed' => array(),
			'dangling'            => array(),
			'history'             => array(),
		);
	}

	/**
	 * @return array<string,mixed>
	 */
	public static function get_state(): array {
		return self::sanitize_state( get_option( self::STATE_OPTION, array() ) );
	}

	/**
	 * @param mixed $raw Raw state.
	 * @return array<string,mixed>
	 */
	public static function sanitize_state( $raw ): array {
		$state = self::defaults_state();
		if ( ! is_array( $raw ) ) {
			return $state;
		}

		$state['alerted']       = ! empty( $raw['alerted'] );
		$state['last_check_ts'] = max( 0, (int) ( $raw['last_check_ts'] ?? 0 ) );
		$state['last_alert_ts'] = max( 0, (int) ( $raw['last_alert_ts'] ?? 0 ) );

		if ( ! empty( $raw['last_seen_installed'] ) && is_array( $raw['last_seen_installed'] ) ) {
			foreach ( $raw['last_seen_installed'] as $plugin => $ts ) {
				$plugin = self::clean_plugin( (string) $plugin );
				if ( '' === $plugin || (int) $ts <= 0 ) {
					continue;
				}
				$state['last_seen_installed'][ $plugin ] = (int) $ts;
				if ( count( $state['last_seen_installed'] ) >= self::STATE_CAP ) {
					break;
				}
			}
		}

		if ( ! empty( $raw['dangling'] ) && is_array( $raw['dangling'] ) ) {
			foreach ( $raw['dangling'] as $row ) {
				if ( ! is_array( $row ) ) {
					continue;
				}
				$kind = (string) ( $row['kind'] ?? '' );
				if ( ! in_array( $kind, array( self::KIND_PLUGIN, self::KIND_ROLE, self::KIND_USER ), true ) ) {
					continue;
				}
				$ref = self::clean_ref( $kind, (string) ( $row['ref'] ?? '' ) );
				if ( '' === $ref ) {
					continue;
				}
				$state['dangling'][ self::ref_key( $kind, $ref ) ] = array(
					'kind'  => $kind,
					'ref'   => $ref,
					'rule'  => substr( sanitize_key( (string) ( $row['rule'] ?? '' ) ), 0, 32 ),
					'since' => max( 0, (int) ( $row['since'] ?? 0 ) ),
				);
				if ( count( $state['dangling'] ) >= self::STATE_CAP ) {
					break;
				}
			}
		}

		if ( ! empty( $raw['history'] ) && is_array( $raw['history'] ) ) {
			foreach ( $raw['history'] as $row ) {
				if ( ! is_array( $row ) ) {
					continue;
				}
				$plugin = self::clean_plugin( (string) ( $row['plugin'] ?? '' ) );
				if ( '' === $plugin ) {
					continue;
				}
				$via              = (string) ( $row['via'] ?? '' );
				$state['history'][] = array(
					'plugin'         => $plugin,
					'rule'           => substr( sanitize_key( (string) ( $row['rule'] ?? 'allow' ) ), 0, 32 ),
					'ts'             => max( 0, (int) ( $row['ts'] ?? 0 ) ),
					'via'            => in_array( $via, array( self::VIA_ACTIVATION, self::VIA_INVENTORY ), true ) ? $via : self::VIA_INVENTORY,
					'dangling_since' => max( 0, (int) ( $row['dangling_since'] ?? 0 ) ),
					'cleared_ts'     => max( 0, (int) ( $row['cleared_ts'] ?? 0 ) ),
				);
			}
			$state['history'] = array_slice( $state['history'], -self::HISTORY_CAP );
		}

		return $state;
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

	private static function resolve_now( ?int $now ): int {
		if ( null !== $now && $now > 0 ) {
			return $now;
		}
		if ( null !== self::$test_now ) {
			return self::$test_now;
		}

		return class_exists( Clock::class, false ) ? Clock::now() : time();
	}

	private static function ref_key( string $kind, string $ref ): string {
		return $kind . ':' . $ref;
	}

	private static function clean_plugin( string $plugin ): string {
		if ( class_exists( Plugin_Profile::class, false ) && method_exists( Plugin_Profile::class, 'sanitize_plugin' ) ) {
			return (string) Plugin_Profile::sanitize_plugin( $plugin );
		}
		$plugin = ltrim( str_replace( '\\', '/', sanitize_text_field( $plugin ) ), '/' );

		return ( '' === $plugin || false !== strpos( $plugin, '..' ) ) ? '' : $plugin;
	}

	private static function clean_ref( string $kind, string $ref ): string {
		if ( self::KIND_PLUGIN === $kind ) {
			return self::clean_plugin( $ref );
		}
		if ( self::KIND_USER === $kind ) {
			return (int) $ref > 0 ? (string) (int) $ref : '';
		}

		return sanitize_key( $ref );
	}

	/* ---------------------------------------------------------------------
	 * Reference inventory (read-only)
	 * ------------------------------------------------------------------ */

	/**
	 * @return array<string,mixed>
	 */
	private static function policy(): array {
		if ( null !== self::$test_policy ) {
			return self::$test_policy;
		}
		$policy = class_exists( Policy::class, false ) && method_exists( Policy::class, 'get_policy' )
			? Policy::get_policy()
			: get_option( Plugin::OPTION_KEY, array() );

		return is_array( $policy ) ? $policy : array();
	}

	/**
	 * Plugin-keyed references: explicit rules plus kill-switch exceptions.
	 *
	 * @param array<string,mixed> $policy Policy.
	 * @return array<string,array{rule:string,source:string}>
	 */
	public static function plugin_refs( array $policy ): array {
		$refs  = array();
		$rules = isset( $policy['plugins'] ) && is_array( $policy['plugins'] ) ? $policy['plugins'] : array();
		foreach ( $rules as $basename => $rule ) {
			$basename = self::clean_plugin( (string) $basename );
			if ( '' === $basename ) {
				continue;
			}
			$refs[ $basename ] = array(
				'rule'   => substr( sanitize_key( is_scalar( $rule ) ? (string) $rule : '' ), 0, 32 ),
				'source' => 'plugin_rule',
			);
		}

		$exceptions = isset( $policy['kill_switch_exceptions'] ) && is_array( $policy['kill_switch_exceptions'] ) ? $policy['kill_switch_exceptions'] : array();
		foreach ( $exceptions as $basename ) {
			$basename = self::clean_plugin( (string) $basename );
			if ( '' === $basename || isset( $refs[ $basename ] ) ) {
				continue;
			}
			$refs[ $basename ] = array(
				'rule'   => 'exception',
				'source' => 'kill_switch_exception',
			);
		}

		return $refs;
	}

	/**
	 * Installed plugin basenames (regular and must-use), or null when unknown.
	 * Unknown never means "everything is dangling".
	 *
	 * @return array<string,true>|null
	 */
	private static function installed_set(): ?array {
		$names = null;
		if ( null !== self::$test_installed ) {
			$names = array();
			foreach ( self::$test_installed as $key => $value ) {
				$names[] = is_string( $value ) ? $value : (string) $key;
			}
		} else {
			if ( ! function_exists( 'get_plugins' ) && defined( 'ABSPATH' ) && file_exists( ABSPATH . 'wp-admin/includes/plugin.php' ) ) {
				require_once ABSPATH . 'wp-admin/includes/plugin.php';
			}
			if ( function_exists( 'get_plugins' ) ) {
				$names = array_map( 'strval', array_keys( (array) get_plugins() ) );
				if ( function_exists( 'get_mu_plugins' ) ) {
					$names = array_merge( $names, array_map( 'strval', array_keys( (array) get_mu_plugins() ) ) );
				}
			}
		}
		if ( null === $names ) {
			return null;
		}

		$set = array();
		foreach ( $names as $name ) {
			$name = self::clean_plugin( $name );
			if ( '' !== $name ) {
				$set[ $name ] = true;
			}
		}

		return $set;
	}

	/**
	 * Existing role slugs, or null when WordPress cannot tell.
	 *
	 * @return array<string,true>|null
	 */
	private static function role_set(): ?array {
		$slugs = null;
		if ( null !== self::$test_roles ) {
			$slugs = array();
			foreach ( self::$test_roles as $key => $value ) {
				$slugs[] = is_string( $value ) ? $value : (string) $key;
			}
		} elseif ( function_exists( 'wp_roles' ) ) {
			$roles = wp_roles();
			if ( is_object( $roles ) && isset( $roles->roles ) && is_array( $roles->roles ) ) {
				$slugs = array_map( 'strval', array_keys( $roles->roles ) );
			}
		} elseif ( function_exists( 'get_editable_roles' ) ) {
			$slugs = array_map( 'strval', array_keys( (array) get_editable_roles() ) );
		}
		if ( null === $slugs ) {
			return null;
		}

		$set = array();
		foreach ( $slugs as $slug ) {
			$slug = sanitize_key( $slug );
			if ( '' !== $slug ) {
				$set[ $slug ] = true;
			}
		}

		return $set;
	}

	/**
	 * Newest activity-log timestamp per referenced plugin.
	 *
	 * @param list<string> $plugins Referenced basenames.
	 * @return array<string,int>
	 */
	private static function log_last_live( array $plugins ): array {
		if ( empty( $plugins ) ) {
			return array();
		}
		$log = self::$test_log;
		if ( null === $log ) {
			$raw = get_option( Plugin::LOG_OPTION_KEY, array() );
			$log = is_array( $raw ) ? $raw : array();
		}
		$wanted = array_flip( $plugins );
		$out    = array();
		foreach ( $log as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$plugin = (string) ( $row['plugin'] ?? '' );
			$ts     = (int) ( $row['ts'] ?? 0 );
			if ( '' === $plugin || $ts <= 0 || ! isset( $wanted[ $plugin ] ) ) {
				continue;
			}
			if ( ! isset( $out[ $plugin ] ) || $ts > $out[ $plugin ] ) {
				$out[ $plugin ] = $ts;
			}
		}

		return $out;
	}

	/**
	 * Pending access requests from users that no longer exist. Flag only:
	 * Offboard owns that cleanup lane, this never touches the requests.
	 *
	 * @return list<array{user_id:int,ts:int}>
	 */
	private static function orphan_user_refs(): array {
		if ( ! class_exists( Access_Request::class, false ) || ! method_exists( Access_Request::class, 'pending_rows' ) || ! function_exists( 'get_userdata' ) ) {
			return array();
		}
		$out  = array();
		$seen = array();
		foreach ( (array) Access_Request::pending_rows() as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$user_id = (int) ( $row['user_id'] ?? 0 );
			if ( $user_id <= 0 || isset( $seen[ $user_id ] ) ) {
				continue;
			}
			$seen[ $user_id ] = true;
			$user = get_userdata( $user_id );
			if ( empty( $user ) ) {
				$out[] = array(
					'user_id' => $user_id,
					'ts'      => (int) ( $row['ts'] ?? 0 ),
				);
			}
		}

		return $out;
	}

	/**
	 * Pure inventory: references, what is installed, what dangles. Writes nothing.
	 *
	 * @param array<string,mixed> $state State (for first-noticed timestamps).
	 * @return array<string,mixed>
	 */
	private static function inventory( array $state, int $now ): array {
		$policy    = self::policy();
		$refs      = self::plugin_refs( $policy );
		$installed = self::installed_set();
		$last_log  = self::log_last_live( array_keys( $refs ) );
		$dangling  = array();
		$live      = array();

		if ( null !== $installed ) {
			foreach ( $refs as $basename => $ref ) {
				if ( isset( $installed[ $basename ] ) ) {
					$live[ $basename ] = $ref;
					continue;
				}
				$key = self::ref_key( self::KIND_PLUGIN, $basename );

				$dangling[ $key ] = array(
					'kind'   => self::KIND_PLUGIN,
					'ref'    => $basename,
					'rule'   => $ref['rule'],
					'source' => $ref['source'],
					'since'  => (int) ( $state['dangling'][ $key ]['since'] ?? 0 ) > 0 ? (int) $state['dangling'][ $key ]['since'] : $now,
					'ref_ts' => 0,
				);
			}
		}

		if ( ! empty( $policy['role_gate_enabled'] ) ) {
			$roles = self::role_set();
			if ( null !== $roles ) {
				$allowed = class_exists( Policy::class, false ) && method_exists( Policy::class, 'sanitize_allowed_roles' )
					? Policy::sanitize_allowed_roles( $policy['allowed_roles'] ?? array() )
					: array_values( array_filter( array_map( 'sanitize_key', array_map( 'strval', (array) ( $policy['allowed_roles'] ?? array() ) ) ) ) );
				foreach ( $allowed as $slug ) {
					if ( isset( $roles[ $slug ] ) ) {
						continue;
					}
					$key              = self::ref_key( self::KIND_ROLE, $slug );
					$dangling[ $key ] = array(
						'kind'   => self::KIND_ROLE,
						'ref'    => $slug,
						'rule'   => 'allowed_role',
						'source' => 'role_gate',
						'since'  => (int) ( $state['dangling'][ $key ]['since'] ?? 0 ) > 0 ? (int) $state['dangling'][ $key ]['since'] : $now,
						'ref_ts' => 0,
					);
				}
			}
		}

		foreach ( self::orphan_user_refs() as $orphan ) {
			$ref              = (string) $orphan['user_id'];
			$key              = self::ref_key( self::KIND_USER, $ref );
			$dangling[ $key ] = array(
				'kind'   => self::KIND_USER,
				'ref'    => $ref,
				'rule'   => 'pending_request',
				'source' => 'access_request',
				'since'  => (int) ( $state['dangling'][ $key ]['since'] ?? 0 ) > 0 ? (int) $state['dangling'][ $key ]['since'] : $now,
				'ref_ts' => (int) $orphan['ts'],
			);
		}

		return array(
			'refs'      => $refs,
			'installed' => $installed,
			'live'      => $live,
			'dangling'  => $dangling,
			'log_live'  => $last_log,
		);
	}

	/* ---------------------------------------------------------------------
	 * Scan (writes own state only) + resurrection watch
	 * ------------------------------------------------------------------ */

	/**
	 * @param array<string,mixed> $state State.
	 */
	private static function active_history_index( array $state, string $plugin ): int {
		foreach ( (array) $state['history'] as $i => $row ) {
			if ( (string) $row['plugin'] === $plugin && (int) $row['cleared_ts'] <= 0 ) {
				return (int) $i;
			}
		}

		return -1;
	}

	/**
	 * @param array<string,mixed> $state State (modified).
	 */
	private static function record_resurrection( array &$state, string $plugin, string $via, int $now ): void {
		$key   = self::ref_key( self::KIND_PLUGIN, $plugin );
		$since = (int) ( $state['dangling'][ $key ]['since'] ?? 0 );
		unset( $state['dangling'][ $key ] );
		if ( self::active_history_index( $state, $plugin ) >= 0 ) {
			return;
		}
		$state['history'][] = array(
			'plugin'         => $plugin,
			'rule'           => 'allow',
			'ts'             => $now,
			'via'            => $via,
			'dangling_since' => $since,
			'cleared_ts'     => 0,
		);
		$state['history']   = array_slice( $state['history'], -self::HISTORY_CAP );
		$state['last_seen_installed'][ $plugin ] = $now;
	}

	/**
	 * Throttled detection entry point, wired to admin_init (never to a cron hook).
	 *
	 * @param int|null $now   Optional timestamp.
	 * @param bool     $force Skip the throttle.
	 * @return bool True when a scan ran.
	 */
	public static function maybe_check( ?int $now = null, bool $force = false ): bool {
		if ( ! self::is_enabled() ) {
			return false;
		}
		$now   = self::resolve_now( is_int( $now ) ? $now : null );
		$state = self::get_state();
		$last  = (int) $state['last_check_ts'];
		if ( ! $force && $last > 0 && $now >= $last && ( $now - $last ) < self::CHECK_THROTTLE_SECONDS ) {
			return false;
		}
		self::scan( $now );

		return true;
	}

	/**
	 * Refresh the dangling map, last-seen map and resurrection history, then
	 * run the alert latch. Writes the own state option only.
	 *
	 * @param int|null $now Optional timestamp.
	 * @return list<string> Plugins newly recorded as resurrected.
	 */
	public static function scan( ?int $now = null ): array {
		$now   = self::resolve_now( $now );
		$state = self::get_state();
		$inv   = self::inventory( $state, $now );
		$refs  = $inv['refs'];
		$inst  = $inv['installed'];

		$new = array();

		// A previously dangling plugin that is installed again with its Allow rule still armed.
		if ( null !== $inst ) {
			foreach ( $state['dangling'] as $entry ) {
				if ( self::KIND_PLUGIN !== $entry['kind'] ) {
					continue;
				}
				$plugin = (string) $entry['ref'];
				if ( isset( $inst[ $plugin ] ) && 'allow' === (string) ( $refs[ $plugin ]['rule'] ?? '' ) ) {
					self::record_resurrection( $state, $plugin, self::VIA_INVENTORY, $now );
					$new[] = $plugin;
				}
			}
		}

		// Resurrections stop being current once the rule is gone / no longer Allow, or the plugin left again.
		foreach ( $state['history'] as $i => $row ) {
			if ( (int) $row['cleared_ts'] > 0 || in_array( (string) $row['plugin'], $new, true ) ) {
				continue;
			}
			$still_installed = null === $inst || isset( $inst[ $row['plugin'] ] );
			$still_allowed   = 'allow' === (string) ( $refs[ $row['plugin'] ]['rule'] ?? '' );
			if ( ! $still_installed || ! $still_allowed ) {
				$state['history'][ $i ]['cleared_ts'] = $now;
			}
		}

		// Rebuild the dangling map. Plugin entries survive when the installed set is unknown.
		$dangling = $inv['dangling'];
		if ( null === $inst ) {
			foreach ( $state['dangling'] as $key => $entry ) {
				if ( self::KIND_PLUGIN === $entry['kind'] && isset( $refs[ $entry['ref'] ] ) ) {
					$dangling[ $key ] = $entry;
				}
			}
		}
		$stored = array();
		foreach ( $dangling as $key => $entry ) {
			$stored[ $key ] = array(
				'kind'  => $entry['kind'],
				'ref'   => $entry['ref'],
				'rule'  => $entry['rule'],
				'since' => $entry['since'],
			);
		}
		$state['dangling'] = $stored;

		// Last seen installed: only for referenced plugins, so the map stays small.
		$seen = array();
		foreach ( $refs as $plugin => $ref ) {
			if ( isset( $inv['live'][ $plugin ] ) ) {
				$seen[ $plugin ] = $now;
			} elseif ( isset( $state['last_seen_installed'][ $plugin ] ) ) {
				$seen[ $plugin ] = (int) $state['last_seen_installed'][ $plugin ];
			}
		}
		$state['last_seen_installed'] = $seen;
		$state['last_check_ts']       = $now;
		self::put_state( $state );

		self::maybe_fire_alerts( $now );

		return $new;
	}

	/**
	 * activated_plugin listener. Escalates to a resurrection when the plugin was
	 * dangling and its rule is still Allow. Writes the own state only.
	 *
	 * @param mixed $plugin Plugin basename.
	 * @return bool True when a resurrection was recorded.
	 */
	public static function on_activated_plugin( $plugin ): bool {
		if ( ! self::is_enabled() ) {
			return false;
		}
		$plugin = self::clean_plugin( is_scalar( $plugin ) ? (string) $plugin : '' );
		if ( '' === $plugin ) {
			return false;
		}
		$now   = self::resolve_now( null );
		$state = self::get_state();
		$refs  = self::plugin_refs( self::policy() );
		$key   = self::ref_key( self::KIND_PLUGIN, $plugin );

		$recorded = false;
		if ( isset( $state['dangling'][ $key ] ) && 'allow' === (string) ( $refs[ $plugin ]['rule'] ?? '' ) ) {
			self::record_resurrection( $state, $plugin, self::VIA_ACTIVATION, $now );
			$recorded = true;
		} elseif ( isset( $state['dangling'][ $key ] ) ) {
			// Back again but no armed Allow rule: no longer dangling, nothing to escalate.
			unset( $state['dangling'][ $key ] );
		}
		if ( isset( $refs[ $plugin ] ) ) {
			$state['last_seen_installed'][ $plugin ] = $now;
		}
		self::put_state( $state );

		if ( $recorded ) {
			self::maybe_fire_alerts( $now );
		}

		return $recorded;
	}

	/* ---------------------------------------------------------------------
	 * Findings + snapshot
	 * ------------------------------------------------------------------ */

	private static function screen_link( string $screen ): string {
		if ( class_exists( Admin::class, false ) && method_exists( Admin::class, 'screen_url' ) ) {
			return (string) Admin::screen_url( $screen );
		}
		if ( function_exists( 'admin_url' ) ) {
			return (string) admin_url( 'admin.php?page=handl-aicac-' . $screen );
		}

		return '';
	}

	public static function age_days( int $from, int $now ): int {
		if ( $from <= 0 || $now < $from ) {
			return 0;
		}

		return intdiv( $now - $from, 86400 );
	}

	public static function age_phrase( int $days ): string {
		if ( $days <= 0 ) {
			return __( 'today', 'handl-ai-connector-access-control' );
		}

		return sprintf(
			/* translators: %d: number of days */
			_n( '%d day ago', '%d days ago', $days, 'handl-ai-connector-access-control' ),
			$days
		);
	}

	/**
	 * @return array<string,mixed>
	 */
	private static function finding( string $code, string $kind, string $ref, string $rule, int $age_ts, string $age_source, int $now, string $summary, string $suggestion, string $link ): array {
		return array(
			'code'       => $code,
			'severity'   => self::CODE_RESURRECTION === $code ? self::SEVERITY_HIGH : self::SEVERITY_INFO,
			'kind'       => $kind,
			'ref'        => $ref,
			'rule'       => $rule,
			'age_ts'     => $age_ts,
			'age_source' => $age_source,
			'age_days'   => self::age_days( $age_ts, $now ),
			'summary'    => $summary,
			'suggestion' => $suggestion,
			'deep_link'  => $link,
			'alerts'     => self::CODE_RESURRECTION === $code,
		);
	}

	/**
	 * @param array<string,mixed> $state State.
	 * @param array<string,mixed> $inv   Inventory.
	 * @return list<array<string,mixed>>
	 */
	private static function build_findings( array $state, array $inv, int $now ): array {
		$rules_link = self::screen_link( 'rules' );
		$prot_link  = self::screen_link( 'protections' );
		$refs       = $inv['refs'];
		$inst       = $inv['installed'];
		$resurrect  = array();
		$dangling   = array();

		foreach ( $state['history'] as $row ) {
			if ( (int) $row['cleared_ts'] > 0 ) {
				continue;
			}
			$plugin = (string) $row['plugin'];
			if ( ( null !== $inst && ! isset( $inst[ $plugin ] ) ) || 'allow' !== (string) ( $refs[ $plugin ]['rule'] ?? '' ) ) {
				continue;
			}
			$away   = self::age_days( (int) $row['dangling_since'], (int) $row['ts'] );
			$resurrect[] = self::finding(
				self::CODE_RESURRECTION,
				self::KIND_PLUGIN,
				$plugin,
				'allow',
				(int) $row['ts'],
				'noticed',
				$now,
				sprintf(
					/* translators: 1: plugin basename, 2: days the rule was unmatched, 3: when it was noticed, 4: how it was noticed */
					__( '%1$s was gone (its Allow rule sat unmatched for about %2$d day(s)) and is installed again. The old Allow rule is live again without a fresh review. Noticed %3$s (%4$s).', 'handl-ai-connector-access-control' ),
					$plugin,
					$away,
					self::age_phrase( self::age_days( (int) $row['ts'], $now ) ),
					self::VIA_ACTIVATION === (string) $row['via'] ? __( 'on activation', 'handl-ai-connector-access-control' ) : __( 'by the inventory check', 'handl-ai-connector-access-control' )
				),
				__( 'Review the plugin, then either remove its Allow rule or re-approve it deliberately on the Rules screen. Tombstone changes nothing for you.', 'handl-ai-connector-access-control' ),
				$rules_link
			);
		}

		foreach ( $inv['dangling'] as $entry ) {
			$ref = (string) $entry['ref'];
			if ( self::KIND_PLUGIN === $entry['kind'] ) {
				$log_ts  = (int) ( $inv['log_live'][ $ref ] ?? 0 );
				$seen_ts = (int) ( $state['last_seen_installed'][ $ref ] ?? 0 );
				$live_ts = max( $log_ts, $seen_ts );
				$source  = 'noticed';
				$age_ts  = (int) $entry['since'];
				if ( $live_ts > 0 ) {
					$source = $log_ts >= $seen_ts ? 'activity_log' : 'installed_scan';
					$age_ts = $live_ts;
				}
				$days = self::age_days( $age_ts, $now );
				$when = $live_ts > 0
					? sprintf(
						/* translators: %s: how long ago */
						__( 'Last seen in use %s.', 'handl-ai-connector-access-control' ),
						self::age_phrase( $days )
					)
					: sprintf(
						/* translators: %s: how long ago */
						__( 'First noticed unmatched %s.', 'handl-ai-connector-access-control' ),
						self::age_phrase( $days )
					);
				$what = 'kill_switch_exception' === (string) $entry['source']
					? __( 'a kill-switch exception', 'handl-ai-connector-access-control' )
					: sprintf(
						/* translators: %s: rule such as allow or deny */
						__( 'an "%s" rule', 'handl-ai-connector-access-control' ),
						(string) $entry['rule']
					);
				$suggest = __( 'Remove the rule from the Rules screen if the plugin is gone for good.', 'handl-ai-connector-access-control' );
				if ( 'allow' === (string) $entry['rule'] ) {
					$suggest .= ' ' . __( 'If the plugin is ever installed again, this Allow rule would apply to it with no review. Tombstone deletes nothing.', 'handl-ai-connector-access-control' );
				}
				$dangling[] = self::finding(
					self::CODE_PLUGIN,
					self::KIND_PLUGIN,
					$ref,
					(string) $entry['rule'],
					$age_ts,
					$source,
					$now,
					sprintf(
						/* translators: 1: plugin basename, 2: description of the rule, 3: age sentence */
						__( '%1$s is no longer installed but still has %2$s. %3$s', 'handl-ai-connector-access-control' ),
						$ref,
						$what,
						$when
					),
					$suggest,
					$rules_link
				);
			} elseif ( self::KIND_ROLE === $entry['kind'] ) {
				$dangling[] = self::finding(
					self::CODE_ROLE,
					self::KIND_ROLE,
					$ref,
					(string) $entry['rule'],
					(int) $entry['since'],
					'noticed',
					$now,
					sprintf(
						/* translators: 1: role slug, 2: age phrase */
						__( 'The role gate allows the role "%1$s", but no such role exists any more (first noticed %2$s). If a role with that name is created again, it would be admitted.', 'handl-ai-connector-access-control' ),
						$ref,
						self::age_phrase( self::age_days( (int) $entry['since'], $now ) )
					),
					__( 'Remove the missing role from the allowed roles in Protections, or recreate the role on purpose.', 'handl-ai-connector-access-control' ),
					$prot_link
				);
			} else {
				$age_ts     = (int) $entry['ref_ts'] > 0 ? (int) $entry['ref_ts'] : (int) $entry['since'];
				$dangling[] = self::finding(
					self::CODE_USER,
					self::KIND_USER,
					$ref,
					(string) $entry['rule'],
					$age_ts,
					(int) $entry['ref_ts'] > 0 ? 'request' : 'noticed',
					$now,
					sprintf(
						/* translators: 1: user id, 2: age phrase */
						__( 'A pending access request belongs to user #%1$s, who no longer exists (requested %2$s).', 'handl-ai-connector-access-control' ),
						$ref,
						self::age_phrase( self::age_days( $age_ts, $now ) )
					),
					__( 'Flag only: Offboard owns user cleanup. Deny the request from the inbox when you next review it.', 'handl-ai-connector-access-control' ),
					$rules_link
				);
			}
		}

		$order = array(
			self::CODE_PLUGIN => 0,
			self::CODE_ROLE   => 1,
			self::CODE_USER   => 2,
		);
		usort(
			$dangling,
			static function ( array $a, array $b ) use ( $order ): int {
				$cmp = $order[ $a['code'] ] <=> $order[ $b['code'] ];
				if ( 0 !== $cmp ) {
					return $cmp;
				}
				$cmp = (int) $b['age_days'] <=> (int) $a['age_days'];

				return 0 !== $cmp ? $cmp : strcmp( (string) $a['ref'], (string) $b['ref'] );
			}
		);

		return array_merge( $resurrect, $dangling );
	}

	/**
	 * Read-only view (writes nothing).
	 *
	 * @return array<string,mixed>
	 */
	public static function snapshot( ?int $now = null ): array {
		$now      = self::resolve_now( $now );
		$state    = self::get_state();
		$inv      = self::inventory( $state, $now );
		$findings = self::build_findings( $state, $inv, $now );

		$counts = array(
			self::CODE_PLUGIN       => 0,
			self::CODE_ROLE         => 0,
			self::CODE_USER         => 0,
			self::CODE_RESURRECTION => 0,
		);
		foreach ( $findings as $row ) {
			++$counts[ (string) $row['code'] ];
		}

		$live = array();
		foreach ( $inv['live'] as $plugin => $ref ) {
			$live[] = array(
				'plugin' => (string) $plugin,
				'rule'   => (string) $ref['rule'],
				'source' => (string) $ref['source'],
			);
		}

		return array(
			'enabled'            => self::is_enabled(),
			'now'                => $now,
			'findings'           => $findings,
			'counts'             => $counts,
			'dangling_count'     => $counts[ self::CODE_PLUGIN ] + $counts[ self::CODE_ROLE ] + $counts[ self::CODE_USER ],
			'resurrection_count' => $counts[ self::CODE_RESURRECTION ],
			'has_resurrection'   => $counts[ self::CODE_RESURRECTION ] > 0,
			'live'               => $live,
			'history'            => array_values( (array) $state['history'] ),
			'alerted'            => ! empty( $state['alerted'] ),
			'last_alert_ts'      => (int) $state['last_alert_ts'],
			'last_check_ts'      => (int) $state['last_check_ts'],
			'plugins_known'      => null !== $inv['installed'],
			'framing'            => self::FRAMING,
		);
	}

	/* ---------------------------------------------------------------------
	 * Alert: re-arming, resurrection only (guarded Alerts reuse)
	 * ------------------------------------------------------------------ */

	/**
	 * One alert per resurrection episode; re-arms once none is current.
	 * Dangling-only findings never alert.
	 *
	 * @param int|null                 $now  Timestamp.
	 * @param array<string,mixed>|null $snap Optional precomputed snapshot.
	 * @return bool True when a new alert was sent.
	 */
	public static function maybe_fire_alerts( ?int $now = null, ?array $snap = null ): bool {
		if ( ! self::is_enabled() ) {
			return false;
		}
		$now  = self::resolve_now( $now );
		$snap = null !== $snap ? $snap : self::snapshot( $now );

		$state = self::get_state();
		if ( (int) $snap['resurrection_count'] <= 0 ) {
			if ( ! empty( $state['alerted'] ) ) {
				$state['alerted']       = false;
				$state['last_alert_ts'] = 0;
				self::put_state( $state );
			}

			return false;
		}
		if ( ! empty( $state['alerted'] ) ) {
			return false;
		}
		if ( ! self::fire_alert( $snap, $now ) ) {
			return false; // Stay un-latched so the next check retries.
		}

		$state['alerted']       = true;
		$state['last_alert_ts'] = $now;
		self::put_state( $state );

		return true;
	}

	/**
	 * @param array<string,mixed> $snap Snapshot.
	 */
	private static function fire_alert( array $snap, int $now ): bool {
		$policy = self::policy();

		$email = '';
		if ( class_exists( Alerts::class, false ) && method_exists( Alerts::class, 'resolve_email' ) ) {
			$email = (string) Alerts::resolve_email( $policy );
		}
		if ( '' === $email ) {
			$email = function_exists( 'sanitize_email' )
				? sanitize_email( (string) get_option( 'admin_email' ) )
				: (string) get_option( 'admin_email' );
		}
		if ( '' === $email ) {
			return false;
		}

		$subject = self::build_subject( $snap );
		$body    = self::build_body( $snap );
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
						'type'               => 'handl_aicac_tombstone',
						'resurrection_count' => (int) ( $snap['resurrection_count'] ?? 0 ),
						'site'               => function_exists( 'home_url' ) ? home_url( '/' ) : '',
						'ts'                 => $now,
					)
				);
			}
		}

		return $ok;
	}

	/**
	 * @param array<string,mixed> $snap Snapshot.
	 * @return list<array<string,mixed>>
	 */
	private static function resurrection_rows( array $snap ): array {
		$rows = array();
		foreach ( (array) ( $snap['findings'] ?? array() ) as $row ) {
			if ( is_array( $row ) && self::CODE_RESURRECTION === (string) ( $row['code'] ?? '' ) ) {
				$rows[] = $row;
			}
		}

		return $rows;
	}

	/**
	 * @param array<string,mixed> $snap Snapshot.
	 */
	public static function build_subject( array $snap ): string {
		$site  = function_exists( 'get_bloginfo' )
			? wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES )
			: 'WordPress';
		$first = '';
		foreach ( self::resurrection_rows( $snap ) as $row ) {
			$first = (string) $row['ref'];
			break;
		}

		return sprintf(
			/* translators: 1: site name, 2: count, 3: first plugin basename */
			__( '[%1$s] [TOMBSTONE] %2$d reinstalled plugin(s) have an old Allow rule live again (first: %3$s)', 'handl-ai-connector-access-control' ),
			$site,
			(int) ( $snap['resurrection_count'] ?? 0 ),
			$first
		);
	}

	/**
	 * @param array<string,mixed> $snap Snapshot.
	 */
	public static function build_body( array $snap ): string {
		$lines   = array();
		$lines[] = __( 'A plugin that was uninstalled while it still had an Allow rule is installed again. The old rule applies to it again, even though nobody reviewed the plugin that came back.', 'handl-ai-connector-access-control' );
		$lines[] = '';
		foreach ( self::resurrection_rows( $snap ) as $row ) {
			$lines[] = '- ' . (string) $row['summary'];
		}
		$lines[] = '';
		$lines[] = __( 'Suggestion only: Tombstone never deletes, edits or disables a rule, role, user or plugin. Review the plugin, then remove the Allow rule or re-approve it deliberately. This check runs on admin page loads and plugin activation, not on cron.', 'handl-ai-connector-access-control' );
		$url     = self::admin_url();
		if ( '' !== $url ) {
			$lines[] = '';
			$lines[] = sprintf(
				/* translators: %s: admin URL */
				__( 'Open tombstone: %s', 'handl-ai-connector-access-control' ),
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

	/* ---------------------------------------------------------------------
	 * CSV + print
	 * ------------------------------------------------------------------ */

	private static function ts_label( int $ts ): string {
		return $ts > 0 ? gmdate( 'Y-m-d H:i:s', $ts ) . ' UTC' : '';
	}

	/**
	 * @param array<string,mixed>|null $snap Optional snapshot.
	 */
	public static function csv_for_snapshot( ?array $snap = null ): string {
		if ( null === $snap ) {
			$snap = self::snapshot();
		}
		$lines   = array();
		$lines[] = self::csv_line( array( 'section', 'code', 'kind', 'reference', 'rule', 'age_days', 'since', 'detail', 'framing' ) );
		$lines[] = self::csv_line(
			array(
				'summary',
				'',
				'',
				'',
				'',
				'',
				'',
				'checked=' . self::ts_label( (int) ( $snap['now'] ?? 0 ) )
					. ' dangling=' . (string) (int) ( $snap['dangling_count'] ?? 0 )
					. ' resurrection=' . (string) (int) ( $snap['resurrection_count'] ?? 0 ),
				self::FRAMING,
			)
		);
		foreach ( (array) ( $snap['findings'] ?? array() ) as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$lines[] = self::csv_line(
				array(
					'finding',
					(string) $row['code'],
					(string) $row['kind'],
					(string) $row['ref'],
					(string) $row['rule'],
					(string) (int) $row['age_days'],
					self::ts_label( (int) $row['age_ts'] ),
					(string) $row['summary'],
					self::FRAMING,
				)
			);
		}
		foreach ( (array) ( $snap['live'] ?? array() ) as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$lines[] = self::csv_line( array( 'live', '', self::KIND_PLUGIN, (string) $row['plugin'], (string) $row['rule'], '', '', (string) $row['source'], self::FRAMING ) );
		}
		foreach ( (array) ( $snap['history'] ?? array() ) as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$lines[] = self::csv_line(
				array(
					'history',
					self::CODE_RESURRECTION,
					self::KIND_PLUGIN,
					(string) $row['plugin'],
					(string) $row['rule'],
					'',
					self::ts_label( (int) $row['ts'] ),
					'via=' . (string) $row['via'] . ' cleared=' . ( (int) $row['cleared_ts'] > 0 ? self::ts_label( (int) $row['cleared_ts'] ) : 'no' ),
					self::FRAMING,
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
			$col = (string) $col;
			// Neutralize spreadsheet formula injection.
			if ( '' !== $col && in_array( $col[0], array( '=', '+', '-', '@', "\t", "\r" ), true ) ) {
				$col = "'" . $col;
			}
			$needs = str_contains( $col, ',' ) || str_contains( $col, '"' ) || str_contains( $col, "\n" );
			$col   = str_replace( '"', '""', $col );
			$out[] = $needs ? '"' . $col . '"' : $col;
		}

		return implode( ',', $out );
	}

	/**
	 * @param list<array<string,mixed>> $rows  Findings.
	 * @param bool                      $links Include deep links.
	 */
	private static function findings_table_html( array $rows, bool $links ): string {
		$html  = '<table><thead><tr>';
		$html .= '<th>' . esc_html__( 'Finding', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '<th>' . esc_html__( 'Reference', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '<th>' . esc_html__( 'Age (days)', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '<th>' . esc_html__( 'What to do', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '</tr></thead><tbody>';
		$shown = 0;
		foreach ( $rows as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			++$shown;
			$html .= '<tr>';
			$html .= '<td><strong>' . esc_html( (string) $row['summary'] ) . '</strong><br /><code>' . esc_html( (string) $row['code'] ) . '</code></td>';
			$html .= '<td>' . esc_html( (string) $row['ref'] ) . '</td>';
			$html .= '<td>' . esc_html( (string) (int) $row['age_days'] ) . '</td>';
			$html .= '<td>' . esc_html( (string) $row['suggestion'] );
			if ( $links && '' !== (string) $row['deep_link'] ) {
				$html .= ' <a href="' . esc_url( (string) $row['deep_link'] ) . '">' . esc_html__( 'Open', 'handl-ai-connector-access-control' ) . '</a>';
			}
			$html .= '</td></tr>';
		}
		if ( 0 === $shown ) {
			$html .= '<tr><td colspan="4">' . esc_html__( 'No dangling references found.', 'handl-ai-connector-access-control' ) . '</td></tr>';
		}
		$html .= '</tbody></table>';

		return $html;
	}

	/**
	 * @param array<string,mixed> $snap Snapshot.
	 */
	public static function build_print_html( array $snap ): string {
		$html  = '<!DOCTYPE html><html><head><meta charset="utf-8"><title>';
		$html .= esc_html__( 'AI Connector tombstone', 'handl-ai-connector-access-control' );
		$html .= '</title><style>body{font-family:sans-serif;margin:24px}table{border-collapse:collapse;width:100%;margin-bottom:24px}th,td{border:1px solid #ccc;padding:6px 8px;text-align:left}th{background:#f6f7f7}</style></head><body>';
		$html .= '<h1>' . esc_html__( 'AI Connector tombstone', 'handl-ai-connector-access-control' ) . '</h1>';
		$html .= '<p>' . esc_html__( 'Report only — never deletes, edits or disables a rule, role, user or plugin.', 'handl-ai-connector-access-control' ) . '</p>';
		$html .= '<ul>';
		$html .= '<li>' . esc_html( sprintf( 'Dangling references: %d', (int) ( $snap['dangling_count'] ?? 0 ) ) ) . '</li>';
		$html .= '<li>' . esc_html( sprintf( 'Resurrections (reinstalled plugin, old Allow rule live again): %d', (int) ( $snap['resurrection_count'] ?? 0 ) ) ) . '</li>';
		$html .= '</ul>';
		$html .= '<h2>' . esc_html__( 'Roster', 'handl-ai-connector-access-control' ) . '</h2>';
		$html .= self::findings_table_html( (array) ( $snap['findings'] ?? array() ), false );
		$html .= '</body></html>';

		return $html;
	}

	/* ---------------------------------------------------------------------
	 * Admin UI
	 * ------------------------------------------------------------------ */

	public static function register_menu(): void {
		if ( ! Caps::user_can_view() ) {
			return;
		}
		if ( ! function_exists( 'add_submenu_page' ) ) {
			return;
		}
		add_submenu_page(
			Admin::MENU_SLUG,
			__( 'Tombstone', 'handl-ai-connector-access-control' ),
			__( 'Tombstone', 'handl-ai-connector-access-control' ),
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
				'page'                     => self::PAGE_SLUG,
				'handl_aicac_tombstone_csv' => '1',
				'_wpnonce'                 => function_exists( 'wp_create_nonce' ) ? wp_create_nonce( 'handl_aicac_tombstone_csv' ) : '',
			),
			admin_url( 'admin.php' )
		);
		$print      = add_query_arg(
			array(
				'page'                       => self::PAGE_SLUG,
				'handl_aicac_tombstone_print' => '1',
				'_wpnonce'                   => function_exists( 'wp_create_nonce' ) ? wp_create_nonce( 'handl_aicac_tombstone_print' ) : '',
			),
			admin_url( 'admin.php' )
		);

		echo '<div class="wrap">';
		echo '<h1>' . esc_html__( 'Tombstone', 'handl-ai-connector-access-control' ) . '</h1>';
		echo '<p class="description">' . esc_html__( 'Finds rules that point at things that no longer exist: plugins that were uninstalled, roles that were deleted, users that are gone. Most of it is harmless clutter and only shows here. The one case that is sent as an alert is a plugin that comes back while its old Allow rule is still in place. Report only — it never deletes, edits or disables anything. Checks run on admin page loads and plugin activation, not on cron. Off by default.', 'handl-ai-connector-access-control' ) . '</p>';

		if ( $can_manage ) {
			echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
			echo '<input type="hidden" name="action" value="' . esc_attr( self::ACTION_SAVE ) . '" />';
			if ( function_exists( 'wp_nonce_field' ) ) {
				wp_nonce_field( self::ACTION_SAVE );
			}
			echo '<input type="hidden" name="' . esc_attr( self::POST_PRESENT ) . '" value="1" />';
			echo '<table class="form-table" role="presentation"><tbody>';
			echo '<tr><th scope="row">' . esc_html__( 'Enable tombstone', 'handl-ai-connector-access-control' ) . '</th><td>';
			echo '<label><input type="checkbox" name="' . esc_attr( self::POST_ENABLED ) . '" value="1" ' . checked( ! empty( $settings['enabled'] ), true, false ) . ' /> ';
			echo esc_html__( 'List dangling references and alert when an old Allow rule comes back to life', 'handl-ai-connector-access-control' );
			echo '</label></td></tr></tbody></table>';
			submit_button( __( 'Save tombstone settings', 'handl-ai-connector-access-control' ) );
			echo '</form>';
		}

		if ( ! $enabled || ! is_array( $snap ) ) {
			echo '<p>' . esc_html__( 'Tombstone is off. Enable it to list dangling references.', 'handl-ai-connector-access-control' ) . '</p>';
			echo '</div>';

			return;
		}

		echo '<p><strong>' . esc_html__( 'Report only — never deletes, edits or disables anything.', 'handl-ai-connector-access-control' ) . '</strong></p>';
		if ( ! empty( $snap['has_resurrection'] ) ) {
			echo '<div class="notice notice-warning inline"><p><strong>' . esc_html__( 'A reinstalled plugin has its old Allow rule live again.', 'handl-ai-connector-access-control' ) . '</strong> ';
			echo esc_html__( 'Review it, then remove the rule or re-approve it deliberately.', 'handl-ai-connector-access-control' ) . '</p></div>';
		}
		echo '<ul>';
		echo '<li>' . esc_html( sprintf( 'Dangling references: %d', (int) $snap['dangling_count'] ) ) . '</li>';
		echo '<li>' . esc_html( sprintf( 'Resurrections: %d', (int) $snap['resurrection_count'] ) ) . '</li>';
		if ( empty( $snap['plugins_known'] ) ) {
			echo '<li>' . esc_html__( 'The installed plugin list is not available on this request, so plugin rules were not checked.', 'handl-ai-connector-access-control' ) . '</li>';
		}
		echo '</ul>';

		echo '<p>';
		echo '<a class="button" href="' . esc_url( $csv ) . '">' . esc_html__( 'Download CSV', 'handl-ai-connector-access-control' ) . '</a> ';
		echo '<a class="button" href="' . esc_url( $print ) . '" target="_blank" rel="noopener noreferrer">' . esc_html__( 'Print / PDF view', 'handl-ai-connector-access-control' ) . '</a>';
		echo '</p>';

		echo '<h2>' . esc_html__( 'Findings', 'handl-ai-connector-access-control' ) . '</h2>';
		echo str_replace( '<table>', '<table class="widefat striped">', self::findings_table_html( (array) $snap['findings'], true ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped in builder.

		echo '</div>';
	}

	public static function maybe_handle_csv(): void {
		if ( empty( $_GET['handl_aicac_tombstone_csv'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			return;
		}
		$page = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( (string) $_GET['page'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( self::PAGE_SLUG !== $page ) {
			return;
		}
		if ( ! Caps::user_can_view() || ! self::is_enabled() ) {
			return;
		}
		$nonce = isset( $_GET['_wpnonce'] ) ? (string) wp_unslash( $_GET['_wpnonce'] ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( ! function_exists( 'wp_verify_nonce' ) || ! wp_verify_nonce( $nonce, 'handl_aicac_tombstone_csv' ) ) {
			return;
		}
		$csv = self::csv_for_snapshot();
		if ( function_exists( 'nocache_headers' ) ) {
			nocache_headers();
		}
		header( 'Content-Type: text/csv; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename=handl-aicac-tombstone.csv' );
		echo $csv; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- CSV download.
		exit;
	}

	public static function maybe_handle_print(): void {
		if ( empty( $_GET['handl_aicac_tombstone_print'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			return;
		}
		$page = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( (string) $_GET['page'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( self::PAGE_SLUG !== $page ) {
			return;
		}
		if ( ! Caps::user_can_view() || ! self::is_enabled() ) {
			return;
		}
		$nonce = isset( $_GET['_wpnonce'] ) ? (string) wp_unslash( $_GET['_wpnonce'] ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( ! function_exists( 'wp_verify_nonce' ) || ! wp_verify_nonce( $nonce, 'handl_aicac_tombstone_print' ) ) {
			return;
		}
		if ( function_exists( 'nocache_headers' ) ) {
			nocache_headers();
		}
		echo self::build_print_html( self::snapshot() ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped in builder.
		exit;
	}

	public static function handle_save(): void {
		if ( ! Caps::user_can_manage() ) {
			wp_die( esc_html__( 'You do not have permission to save tombstone settings.', 'handl-ai-connector-access-control' ) );
		}
		check_admin_referer( self::ACTION_SAVE );
		if ( empty( $_POST[ self::POST_PRESENT ] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing
			wp_die( esc_html__( 'Invalid form', 'handl-ai-connector-access-control' ) );
		}
		self::save_settings( array( 'enabled' => ! empty( $_POST[ self::POST_ENABLED ] ) ) ); // phpcs:ignore WordPress.Security.NonceVerification.Missing

		$redirect = self::admin_url();
		if ( '' === $redirect && function_exists( 'admin_url' ) ) {
			$redirect = admin_url( 'admin.php?page=' . self::PAGE_SLUG );
		}
		wp_safe_redirect( $redirect );
		exit;
	}

	public static function register_cli(): void {
		if ( ! defined( 'WP_CLI' ) || ! WP_CLI ) {
			return;
		}
		if ( ! class_exists( '\\WP_CLI' ) ) {
			return;
		}
		\WP_CLI::add_command( 'handl-aicac tombstone', CLI_Tombstone::class );
	}
}

/**
 * WP-CLI: wp handl-aicac tombstone status|export
 */
final class CLI_Tombstone {

	/**
	 * Exit code for a snapshot: non-zero only when a resurrection is present.
	 * Dangling references alone are informational and exit 0.
	 *
	 * @param array<string,mixed> $snap Snapshot.
	 */
	public static function exit_code( array $snap ): int {
		return ! empty( $snap['has_resurrection'] ) ? 1 : 0;
	}

	/**
	 * Run a sweep now and list dangling references. Exits non-zero only while a
	 * resurrection (reinstalled plugin with its old Allow rule live) is present.
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
		$format = isset( $assoc_args['format'] ) ? (string) $assoc_args['format'] : 'table';

		if ( ! Tombstone::is_enabled() ) {
			\WP_CLI::log( 'enabled=no framing=' . Tombstone::FRAMING );
			\WP_CLI::log( 'Tombstone is disabled.' );

			return;
		}

		Tombstone::maybe_check( null, true );
		$snap = Tombstone::snapshot();

		\WP_CLI::log(
			sprintf(
				'enabled=yes dangling=%d resurrection=%d alerted=%s framing=%s',
				(int) $snap['dangling_count'],
				(int) $snap['resurrection_count'],
				! empty( $snap['alerted'] ) ? 'yes' : 'no',
				Tombstone::FRAMING
			)
		);

		$display = array();
		foreach ( (array) $snap['findings'] as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$display[] = array(
				'code'     => (string) $row['code'],
				'kind'     => (string) $row['kind'],
				'ref'      => (string) $row['ref'],
				'rule'     => (string) $row['rule'],
				'age_days' => (string) (int) $row['age_days'],
			);
		}
		if ( ! empty( $display ) ) {
			if ( 'json' === $format ) {
				\WP_CLI::print_value( $display, array( 'format' => 'json' ) );
			} elseif ( class_exists( '\\WP_CLI\\Utils' ) ) {
				\WP_CLI\Utils\format_items( 'table', $display, array( 'code', 'kind', 'ref', 'rule', 'age_days' ) );
			} else {
				foreach ( $display as $row ) {
					\WP_CLI::log( implode( "\t", $row ) );
				}
			}
		}
		foreach ( (array) $snap['findings'] as $finding ) {
			if ( is_array( $finding ) ) {
				\WP_CLI::log( (string) $finding['summary'] );
			}
		}

		if ( 0 !== self::exit_code( $snap ) ) {
			\WP_CLI::error( 'A reinstalled plugin has its old Allow rule live again.' );
		}
	}

	/**
	 * Export the tombstone roster as CSV.
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
		$csv = Tombstone::csv_for_snapshot();
		if ( ! empty( $assoc_args['porcelain'] ) ) {
			echo $csv; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- CLI CSV.
			return;
		}
		\WP_CLI::print_value( $csv, array( 'format' => 'csv' ) );
	}
}
