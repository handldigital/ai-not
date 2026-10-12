<?php
/**
 * AICAC-DOPPELGANGER (#423): environment-identity watchdog (suggestion-only).
 *
 * A database that is cloned to staging, a dev laptop or a new host keeps every
 * alert address, webhook, budget and schedule it had in production. The copy
 * then keeps talking as if it were the real site. This class remembers an
 * identity fingerprint (site URL, home URL, table prefix, environment type and
 * a salted database hash) and, on a throttled admin request, reports when the
 * running site no longer matches it.
 *
 * Design rules:
 * - Suggestion only. It never flips another control's toggle and never edits a
 *   webhook, email, budget or drill option. The "still live" inventory and the
 *   quiet-the-copy checklist are read-only text for a human to act on.
 * - Writes are confined to the two own options (settings + state).
 * - Detection runs on a throttled admin_init (and on demand from WP-CLI),
 *   never from a cron hook. This class schedules nothing.
 * - The fingerprint is captured silently on the first enable and on an explicit
 *   re-baseline only. No alert fires for that capture.
 * - Default alert delivery is an admin notice plus this class's own screen.
 *   Email / webhook delivery is an opt-in setting that is OFF by default; while
 *   it is off, Alerts::safe_wp_mail and the webhook are never called. When it is
 *   on, Alerts is reused through class_exists / method_exists guards only.
 * - The state holds no raw secret: the database identity is a salted HMAC.
 * - wp_die is used only by this class's own saves (settings + re-baseline).
 * - Own two options. OFF by default.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Environment-identity watchdog.
 */
final class Doppelganger {

	public const SETTINGS_OPTION = 'handl_aicac_doppelganger';

	public const STATE_OPTION = 'handl_aicac_doppelganger_state';

	public const PAGE_SLUG = 'handl-aicac-doppelganger';

	public const ALERT_KIND = 'doppelganger';

	public const FRAMING = 'report_only_never_flips_outbound';

	public const POST_PRESENT  = 'handl_aicac_doppelganger_present';
	public const POST_ENABLED  = 'handl_aicac_doppelganger_enabled';
	public const POST_OUTBOUND = 'handl_aicac_doppelganger_outbound';

	public const ACTION_SAVE       = 'handl_aicac_doppelganger_save';
	public const ACTION_REBASELINE = 'handl_aicac_doppelganger_rebaseline';

	/** Admin check throttle in seconds (5 minutes). */
	public const CHECK_THROTTLE_SECONDS = 300;

	public const CODE_URL         = 'url_changed';
	public const CODE_ENVIRONMENT = 'environment_changed';
	public const CODE_PREFIX      = 'prefix_changed';
	public const CODE_DB          = 'db_changed';

	public const SEVERITY_HIGH = 'high';
	public const SEVERITY_SOFT = 'scheme_only';

	public const CHANNEL_NOTICE   = 'notice';
	public const CHANNEL_OUTBOUND = 'notice+outbound';

	/** @var bool */
	private static $registered = false;

	/** @var list<array<string,mixed>> */
	private static $test_mails = array();

	/** @var list<string> */
	private static $test_notices = array();

	/** @var int|null */
	private static $test_now = null;

	/** @var array<string,mixed>|null */
	private static $test_identity = null;

	public static function init(): void {
		if ( self::$registered ) {
			return;
		}
		self::$registered = true;

		add_action( 'admin_menu', array( self::class, 'register_menu' ), 20 );
		add_action( 'admin_init', array( self::class, 'maybe_handle_csv' ), 5 );
		add_action( 'admin_init', array( self::class, 'maybe_handle_print' ), 5 );
		add_action( 'admin_post_' . self::ACTION_SAVE, array( self::class, 'handle_save' ) );
		add_action( 'admin_post_' . self::ACTION_REBASELINE, array( self::class, 'handle_rebaseline' ) );

		if ( self::is_enabled() ) {
			// Detection rides a throttled admin request, never a cron hook.
			add_action( 'admin_init', array( self::class, 'maybe_check' ), 30 );
			add_action( 'admin_notices', array( self::class, 'maybe_render_notice' ) );
			add_action( 'network_admin_notices', array( self::class, 'maybe_render_notice' ) );
		}

		self::register_cli();
	}

	public static function reset_for_tests(): void {
		self::$registered    = false;
		self::$test_mails    = array();
		self::$test_notices  = array();
		self::$test_now      = null;
		self::$test_identity = null;
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
	 * @return list<string>
	 */
	public static function test_notices(): array {
		return self::$test_notices;
	}

	public static function set_test_now( ?int $now ): void {
		self::$test_now = $now;
	}

	/**
	 * Inject the running identity for unit tests. Null reads the live site.
	 *
	 * @param array<string,mixed>|null $identity Identity or null.
	 */
	public static function set_test_identity( ?array $identity ): void {
		self::$test_identity = $identity;
	}

	/* ---------------------------------------------------------------------
	 * Settings
	 * ------------------------------------------------------------------ */

	/**
	 * @return array{enabled:bool,outbound_alert:bool}
	 */
	public static function defaults(): array {
		return array(
			'enabled'        => false,
			'outbound_alert' => false,
		);
	}

	/**
	 * @return array{enabled:bool,outbound_alert:bool}
	 */
	public static function get_settings(): array {
		return self::sanitize_settings( get_option( self::SETTINGS_OPTION, array() ) );
	}

	/**
	 * @param mixed $raw Raw settings.
	 * @return array{enabled:bool,outbound_alert:bool}
	 */
	public static function sanitize_settings( $raw ): array {
		if ( ! is_array( $raw ) ) {
			return self::defaults();
		}

		return array(
			'enabled'        => ! empty( $raw['enabled'] ),
			'outbound_alert' => ! empty( $raw['outbound_alert'] ),
		);
	}

	/**
	 * Save settings. Capturing the first baseline on enable is part of the save.
	 *
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
			self::ensure_baseline();
		}

		return true;
	}

	public static function is_enabled(): bool {
		$settings = self::get_settings();

		return ! empty( $settings['enabled'] );
	}

	public static function is_outbound_enabled(): bool {
		$settings = self::get_settings();

		return ! empty( $settings['outbound_alert'] );
	}

	/* ---------------------------------------------------------------------
	 * State
	 * ------------------------------------------------------------------ */

	/**
	 * @return array<string,mixed>
	 */
	public static function defaults_state(): array {
		return array(
			'alerted'            => false,
			'last_check_ts'      => 0,
			'baselined_ts'       => 0,
			'rebaselined_ts'     => 0,
			'detected_ts'        => 0,
			'last_alert_ts'      => 0,
			'last_alert_channel' => '',
			'salt'               => '',
			'fingerprint'        => array(),
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

		$channel = (string) ( $raw['last_alert_channel'] ?? '' );
		if ( ! in_array( $channel, array( self::CHANNEL_NOTICE, self::CHANNEL_OUTBOUND ), true ) ) {
			$channel = '';
		}

		$state['alerted']            = ! empty( $raw['alerted'] );
		$state['last_check_ts']      = max( 0, (int) ( $raw['last_check_ts'] ?? 0 ) );
		$state['baselined_ts']       = max( 0, (int) ( $raw['baselined_ts'] ?? 0 ) );
		$state['rebaselined_ts']     = max( 0, (int) ( $raw['rebaselined_ts'] ?? 0 ) );
		$state['detected_ts']        = max( 0, (int) ( $raw['detected_ts'] ?? 0 ) );
		$state['last_alert_ts']      = max( 0, (int) ( $raw['last_alert_ts'] ?? 0 ) );
		$state['last_alert_channel'] = $channel;
		$state['salt']               = substr( (string) preg_replace( '/[^a-f0-9]/', '', strtolower( (string) ( $raw['salt'] ?? '' ) ) ), 0, 64 );
		$state['fingerprint']        = ! empty( $raw['fingerprint'] ) && is_array( $raw['fingerprint'] )
			? self::sanitize_identity( $raw['fingerprint'] )
			: array();

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

	/**
	 * @param array<string,mixed> $state State.
	 */
	private static function has_fingerprint( array $state ): bool {
		return (int) $state['baselined_ts'] > 0 && ! empty( $state['fingerprint'] );
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

	/* ---------------------------------------------------------------------
	 * Identity (read-only)
	 * ------------------------------------------------------------------ */

	/**
	 * Normalize an identity to storable, secret-free scalars.
	 *
	 * @param mixed $raw Raw identity.
	 * @return array{site_url:string,home:string,table_prefix:string,environment:string,db_hash:string}|array{}
	 */
	public static function sanitize_identity( $raw ): array {
		if ( ! is_array( $raw ) ) {
			return array();
		}

		return array(
			'site_url'     => substr( sanitize_text_field( (string) ( $raw['site_url'] ?? '' ) ), 0, 255 ),
			'home'         => substr( sanitize_text_field( (string) ( $raw['home'] ?? '' ) ), 0, 255 ),
			'table_prefix' => substr( (string) preg_replace( '/[^A-Za-z0-9_]/', '', (string) ( $raw['table_prefix'] ?? '' ) ), 0, 64 ),
			'environment'  => substr( sanitize_key( (string) ( $raw['environment'] ?? '' ) ), 0, 32 ),
			'db_hash'      => substr( (string) preg_replace( '/[^a-f0-9]/', '', strtolower( (string) ( $raw['db_hash'] ?? '' ) ) ), 0, 64 ),
		);
	}

	/**
	 * Salted HMAC of the database identity. Never returns the raw values.
	 */
	public static function compute_db_hash( string $db_name, string $db_host, string $salt ): string {
		if ( '' === $db_name && '' === $db_host ) {
			return '';
		}

		return hash_hmac( 'sha256', $db_name . '|' . $db_host, $salt );
	}

	/**
	 * Salt for the database hash: the one stored with the baseline, else the
	 * site's auth salt.
	 *
	 * @param array<string,mixed> $state State.
	 */
	private static function salt_for( array $state ): string {
		$stored = (string) ( $state['salt'] ?? '' );
		if ( '' !== $stored ) {
			return $stored;
		}

		return function_exists( 'wp_salt' ) ? (string) wp_salt( 'auth' ) : 'handl-aicac-doppelganger';
	}

	/**
	 * The identity of the site as it is running right now.
	 *
	 * @param array<string,mixed>|null $state Optional state (for the stored salt).
	 * @return array{site_url:string,home:string,table_prefix:string,environment:string,db_hash:string}|array{}
	 */
	public static function current_identity( ?array $state = null ): array {
		if ( null !== self::$test_identity ) {
			return self::sanitize_identity( self::$test_identity );
		}
		if ( null === $state ) {
			$state = self::get_state();
		}

		$site_url = function_exists( 'site_url' ) ? (string) site_url( '/' ) : '';
		if ( '' === $site_url ) {
			$site_url = (string) get_option( 'siteurl', '' );
		}
		$home = function_exists( 'home_url' ) ? (string) home_url( '/' ) : '';
		if ( '' === $home ) {
			$home = (string) get_option( 'home', '' );
		}

		$prefix = '';
		if ( isset( $GLOBALS['wpdb'] ) && is_object( $GLOBALS['wpdb'] ) && isset( $GLOBALS['wpdb']->prefix ) && is_string( $GLOBALS['wpdb']->prefix ) ) {
			$prefix = $GLOBALS['wpdb']->prefix;
		}

		$environment = function_exists( 'wp_get_environment_type' ) ? (string) wp_get_environment_type() : 'production';

		$db_name = defined( 'DB_NAME' ) ? (string) constant( 'DB_NAME' ) : '';
		$db_host = defined( 'DB_HOST' ) ? (string) constant( 'DB_HOST' ) : '';

		return self::sanitize_identity(
			array(
				'site_url'     => $site_url,
				'home'         => $home,
				'table_prefix' => $prefix,
				'environment'  => $environment,
				'db_hash'      => self::compute_db_hash( $db_name, $db_host, self::salt_for( $state ) ),
			)
		);
	}

	/**
	 * Capture the running identity as the baseline. Writes state only.
	 *
	 * @param array<string,mixed> $state State (modified copy is stored).
	 * @return array<string,mixed> The stored state.
	 */
	private static function capture( array $state, int $now, bool $rebaseline ): array {
		if ( '' === (string) $state['salt'] ) {
			$state['salt'] = bin2hex( random_bytes( 16 ) );
		}
		$state['fingerprint']        = self::current_identity( $state );
		$state['baselined_ts']       = (int) $state['baselined_ts'] > 0 ? (int) $state['baselined_ts'] : $now;
		$state['alerted']            = false;
		$state['detected_ts']        = 0;
		$state['last_alert_ts']      = 0;
		$state['last_alert_channel'] = '';
		$state['last_check_ts']      = $now;
		if ( $rebaseline ) {
			$state['rebaselined_ts'] = $now;
		}
		self::put_state( $state );

		return self::get_state();
	}

	/**
	 * First-enable capture: silent, never alerts. No-op once a fingerprint exists.
	 *
	 * @return bool True when a baseline was just captured.
	 */
	public static function ensure_baseline( ?int $now = null ): bool {
		$state = self::get_state();
		if ( self::has_fingerprint( $state ) ) {
			return false;
		}
		self::capture( $state, self::resolve_now( $now ), false );

		return true;
	}

	/**
	 * Explicit re-baseline for a legitimate migration.
	 *
	 * @return bool True when the fingerprint was replaced.
	 */
	public static function rebaseline( ?int $now = null ): bool {
		if ( ! self::is_enabled() ) {
			return false;
		}
		self::capture( self::get_state(), self::resolve_now( $now ), true );

		return true;
	}

	/* ---------------------------------------------------------------------
	 * Mismatch detection
	 * ------------------------------------------------------------------ */

	/**
	 * Comparison key for a URL: lowercase host (+port) plus path without the
	 * trailing slash. The scheme is deliberately not part of it.
	 */
	public static function url_key( string $url ): string {
		$url = trim( $url );
		if ( '' === $url ) {
			return '';
		}
		$parts = parse_url( $url ); // phpcs:ignore WordPress.WP.AlternativeFunctions.parse_url_parse_url -- plain host/path split.
		if ( ! is_array( $parts ) || empty( $parts['host'] ) ) {
			return strtolower( rtrim( $url, '/' ) );
		}
		$key = strtolower( (string) $parts['host'] );
		if ( ! empty( $parts['port'] ) ) {
			$key .= ':' . (int) $parts['port'];
		}
		$key .= rtrim( (string) ( $parts['path'] ?? '' ), '/' );

		return $key;
	}

	public static function url_scheme( string $url ): string {
		$parts = parse_url( trim( $url ) ); // phpcs:ignore WordPress.WP.AlternativeFunctions.parse_url_parse_url -- scheme only.

		return is_array( $parts ) ? strtolower( (string) ( $parts['scheme'] ?? '' ) ) : '';
	}

	/**
	 * @param array<string,mixed> $fingerprint Baseline identity.
	 * @param array<string,mixed> $current     Running identity.
	 * @return list<array<string,mixed>>
	 */
	public static function compute_findings( array $fingerprint, array $current ): array {
		$findings = array();
		if ( empty( $fingerprint ) ) {
			return $findings;
		}
		$fingerprint = array_merge( self::sanitize_identity( array() ), $fingerprint );
		$current     = array_merge( self::sanitize_identity( array() ), $current );

		// URL: host + path is the primary key; a scheme-only change is a softer finding.
		$site_moved = self::url_key( (string) $fingerprint['site_url'] ) !== self::url_key( (string) $current['site_url'] );
		$home_moved = self::url_key( (string) $fingerprint['home'] ) !== self::url_key( (string) $current['home'] );
		if ( $site_moved || $home_moved ) {
			$before = $site_moved ? (string) $fingerprint['site_url'] : (string) $fingerprint['home'];
			$after  = $site_moved ? (string) $current['site_url'] : (string) $current['home'];
			$what   = $site_moved && $home_moved ? 'site_url+home' : ( $site_moved ? 'site_url' : 'home' );
			$findings[] = self::finding(
				self::CODE_URL,
				self::SEVERITY_HIGH,
				$what,
				$before,
				$after,
				sprintf(
					/* translators: 1: which URL setting, 2: baseline URL, 3: current URL */
					__( 'The site address changed (%1$s): it was %2$s and is now %3$s. A database copied to another address keeps every alert and schedule it had.', 'handl-ai-connector-access-control' ),
					$what,
					$before,
					$after
				)
			);
		} else {
			$site_scheme = self::url_scheme( (string) $fingerprint['site_url'] ) !== self::url_scheme( (string) $current['site_url'] );
			$home_scheme = self::url_scheme( (string) $fingerprint['home'] ) !== self::url_scheme( (string) $current['home'] );
			if ( $site_scheme || $home_scheme ) {
				$before = $site_scheme ? (string) $fingerprint['site_url'] : (string) $fingerprint['home'];
				$after  = $site_scheme ? (string) $current['site_url'] : (string) $current['home'];
				$findings[] = self::finding(
					self::CODE_URL,
					self::SEVERITY_SOFT,
					$site_scheme && $home_scheme ? 'site_url+home' : ( $site_scheme ? 'site_url' : 'home' ),
					$before,
					$after,
					sprintf(
						/* translators: 1: baseline URL, 2: current URL */
						__( 'Only the URL scheme changed: it was %1$s and is now %2$s. This is usually an http/https move; re-baseline if it was intended.', 'handl-ai-connector-access-control' ),
						$before,
						$after
					)
				);
			}
		}

		if ( strtolower( (string) $fingerprint['environment'] ) !== strtolower( (string) $current['environment'] ) ) {
			$findings[] = self::finding(
				self::CODE_ENVIRONMENT,
				self::SEVERITY_HIGH,
				'environment',
				(string) $fingerprint['environment'],
				(string) $current['environment'],
				sprintf(
					/* translators: 1: baseline environment, 2: current environment */
					__( 'The environment type changed from "%1$s" to "%2$s". This site may be a staging or development copy.', 'handl-ai-connector-access-control' ),
					$fingerprint['environment'],
					$current['environment']
				)
			);
		}

		if ( (string) $fingerprint['table_prefix'] !== (string) $current['table_prefix'] ) {
			$findings[] = self::finding(
				self::CODE_PREFIX,
				self::SEVERITY_HIGH,
				'table_prefix',
				(string) $fingerprint['table_prefix'],
				(string) $current['table_prefix'],
				sprintf(
					/* translators: 1: baseline prefix, 2: current prefix */
					__( 'The database table prefix changed from "%1$s" to "%2$s".', 'handl-ai-connector-access-control' ),
					$fingerprint['table_prefix'],
					$current['table_prefix']
				)
			);
		}

		if ( ! hash_equals( (string) $fingerprint['db_hash'], (string) $current['db_hash'] ) ) {
			$findings[] = self::finding(
				self::CODE_DB,
				self::SEVERITY_HIGH,
				'db_hash',
				'',
				'',
				__( 'The database identity (name and host, hashed) differs from the baseline. This site is running against a different database than the one it was baselined on.', 'handl-ai-connector-access-control' )
			);
		}

		return $findings;
	}

	/**
	 * @return array<string,mixed>
	 */
	private static function finding( string $code, string $severity, string $field, string $before, string $after, string $summary ): array {
		return array(
			'code'     => $code,
			'severity' => $severity,
			'field'    => $field,
			'before'   => $before,
			'after'    => $after,
			'summary'  => $summary,
		);
	}

	/* ---------------------------------------------------------------------
	 * Live ammunition inventory (read-only) + quiet-the-copy checklist
	 * ------------------------------------------------------------------ */

	public static function page_link( string $slug ): string {
		if ( ! function_exists( 'admin_url' ) ) {
			return '';
		}

		return (string) admin_url( 'admin.php?page=' . $slug );
	}

	public static function redact_email( string $email ): string {
		$at = strrpos( $email, '@' );
		if ( false === $at || $at < 1 ) {
			return '';
		}

		return substr( $email, 0, 1 ) . '***' . substr( $email, $at );
	}

	public static function url_host( string $url ): string {
		$parts = parse_url( trim( $url ) ); // phpcs:ignore WordPress.WP.AlternativeFunctions.parse_url_parse_url -- host only.
		if ( ! is_array( $parts ) || empty( $parts['host'] ) ) {
			return '';
		}

		return strtolower( (string) $parts['host'] ) . ( ! empty( $parts['port'] ) ? ':' . (int) $parts['port'] : '' );
	}

	/**
	 * What this copy could still do: who it would email, which webhook it would
	 * post to, which budgets and schedules are on. Reads only.
	 *
	 * @return array<string,mixed>
	 */
	public static function ammunition(): array {
		$policy = class_exists( Policy::class, false ) && method_exists( Policy::class, 'get_policy' ) ? Policy::get_policy() : array();
		if ( ! is_array( $policy ) ) {
			$policy = array();
		}

		$email  = '';
		$source = 'none';
		if ( class_exists( Alerts::class, false ) && method_exists( Alerts::class, 'resolve_email' ) ) {
			$email = (string) Alerts::resolve_email( $policy );
		} else {
			$email = sanitize_email( (string) ( $policy['alert_email'] ?? '' ) );
			if ( '' === $email ) {
				$email = sanitize_email( (string) get_option( 'admin_email' ) );
			}
		}
		if ( '' !== $email ) {
			$configured = function_exists( 'sanitize_email' ) ? sanitize_email( (string) ( $policy['alert_email'] ?? '' ) ) : '';
			$source     = '' !== $configured ? 'policy' : 'admin_email';
		}

		$webhook = '';
		if ( class_exists( Alerts::class, false ) && method_exists( Alerts::class, 'resolve_webhook' ) ) {
			$webhook = (string) Alerts::resolve_webhook( $policy );
		}

		$budgets = isset( $policy['plugin_budgets'] ) && is_array( $policy['plugin_budgets'] ) ? $policy['plugin_budgets'] : array();
		if ( class_exists( Budget::class, false ) && method_exists( Budget::class, 'sanitize_plugin_budgets' ) ) {
			$budgets = Budget::sanitize_plugin_budgets( $budgets );
		}

		$alerts_link = self::page_link( 'handl-aicac-alerts' );

		$schedules   = array();
		$schedules[] = array(
			'key'       => 'weekly_report',
			'label'     => __( 'Weekly report email', 'handl-ai-connector-access-control' ),
			'live'      => class_exists( Weekly_Report::class, false ) && method_exists( Weekly_Report::class, 'is_active' )
				? (bool) Weekly_Report::is_active( $policy )
				: ! empty( $policy['weekly_report_enabled'] ),
			'deep_link' => $alerts_link,
		);
		$schedules[] = array(
			'key'       => 'monthly_report',
			'label'     => __( 'Monthly report email', 'handl-ai-connector-access-control' ),
			'live'      => class_exists( Monthly_Report::class, false ) && method_exists( Monthly_Report::class, 'is_active' )
				? (bool) Monthly_Report::is_active( $policy )
				: ! empty( $policy['monthly_report_enabled'] ),
			'deep_link' => $alerts_link,
		);
		$schedules[] = array(
			'key'       => 'governance_digest',
			'label'     => __( 'Governance digest email', 'handl-ai-connector-access-control' ),
			'live'      => class_exists( Governance_Digest::class, false ) && method_exists( Governance_Digest::class, 'is_active' )
				? (bool) Governance_Digest::is_active( $policy )
				: ! empty( $policy['governance_digest_enabled'] ),
			'deep_link' => $alerts_link,
		);
		if ( class_exists( Rescan_Schedule::class, false ) && method_exists( Rescan_Schedule::class, 'is_disabled' ) ) {
			$schedules[] = array(
				'key'       => 'rescan_schedule',
				'label'     => __( 'Weekly change-only re-scan', 'handl-ai-connector-access-control' ),
				'live'      => ! Rescan_Schedule::is_disabled(),
				'deep_link' => self::page_link( 'handl-aicac-protections' ),
			);
		}
		// Drills may not exist in this build: only list one when its class does.
		$drill = __NAMESPACE__ . '\\Drill';
		if ( class_exists( $drill, false ) && method_exists( $drill, 'is_enabled' ) ) {
			$schedules[] = array(
				'key'       => 'drill',
				'label'     => __( 'Scheduled alert drill', 'handl-ai-connector-access-control' ),
				'live'      => (bool) call_user_func( array( $drill, 'is_enabled' ) ),
				'deep_link' => $alerts_link,
			);
		}

		$live_schedules = 0;
		foreach ( $schedules as $row ) {
			if ( ! empty( $row['live'] ) ) {
				++$live_schedules;
			}
		}

		$email_count   = '' !== $email ? 1 : 0;
		$webhook_count = '' !== $webhook ? 1 : 0;

		return array(
			'email'          => array(
				'count'     => $email_count,
				'redacted'  => self::redact_email( $email ),
				'source'    => $source,
				'deep_link' => $alerts_link,
			),
			'webhook'        => array(
				'count'     => $webhook_count,
				'host'      => self::url_host( $webhook ),
				'deep_link' => $alerts_link,
			),
			'budgets'        => array(
				'count'     => count( $budgets ),
				'deep_link' => self::page_link( 'handl-aicac-rules' ),
			),
			'schedules'      => $schedules,
			'live_schedules' => $live_schedules,
			'live_total'     => $email_count + $webhook_count + count( $budgets ) + $live_schedules,
		);
	}

	/**
	 * Quiet-the-copy checklist. Text only: nothing here is ever applied.
	 *
	 * @param array<string,mixed> $ammo Ammunition inventory.
	 * @return list<array<string,string>>
	 */
	public static function checklist( array $ammo ): array {
		$alerts = self::page_link( 'handl-aicac-alerts' );
		$rules  = self::page_link( 'handl-aicac-rules' );
		$items  = array();

		if ( ! empty( $ammo['webhook']['count'] ) ) {
			$items[] = array(
				'key'       => 'webhook',
				'text'      => __( 'Clear the alert webhook URL, or point it at a test endpoint, so the copy stops posting into the real channel.', 'handl-ai-connector-access-control' ),
				'deep_link' => $alerts,
			);
		}
		if ( ! empty( $ammo['email']['count'] ) ) {
			$items[] = array(
				'key'       => 'email',
				'text'      => __( 'Clear or redirect the alert email address to a mailbox you control for this copy.', 'handl-ai-connector-access-control' ),
				'deep_link' => $alerts,
			);
		}
		if ( ! empty( $ammo['live_schedules'] ) ) {
			$items[] = array(
				'key'       => 'schedules',
				'text'      => __( 'Pause the weekly / monthly reports, governance digest and any scheduled drill that is still live.', 'handl-ai-connector-access-control' ),
				'deep_link' => $alerts,
			);
		}
		if ( ! empty( $ammo['budgets']['count'] ) ) {
			$items[] = array(
				'key'       => 'budgets',
				'text'      => __( 'Lower or remove per-plugin budgets so the copy does not enforce, or alert on, production spend limits.', 'handl-ai-connector-access-control' ),
				'deep_link' => $rules,
			);
		}
		$items[] = array(
			'key'       => 'rebaseline',
			'text'      => __( 'If this move was intended (a migration), re-baseline so this site becomes the new reference identity.', 'handl-ai-connector-access-control' ),
			'deep_link' => self::admin_url(),
		);

		return $items;
	}

	/* ---------------------------------------------------------------------
	 * Snapshot
	 * ------------------------------------------------------------------ */

	/**
	 * Read-only view of the identity comparison (writes nothing).
	 *
	 * @return array<string,mixed>
	 */
	public static function snapshot( ?int $now = null ): array {
		return self::build_snapshot( self::get_state(), self::resolve_now( $now ) );
	}

	/**
	 * @param array<string,mixed> $state State.
	 * @return array<string,mixed>
	 */
	private static function build_snapshot( array $state, int $now ): array {
		$has_baseline = self::has_fingerprint( $state );
		$current      = self::current_identity( $state );
		$findings     = $has_baseline ? self::compute_findings( $state['fingerprint'], $current ) : array();
		$ammo         = self::ammunition();

		return array(
			'enabled'              => self::is_enabled(),
			'outbound_alert'       => self::is_outbound_enabled(),
			'now'                  => $now,
			'baseline_pending'     => ! $has_baseline,
			'baselined_ts'         => (int) $state['baselined_ts'],
			'rebaselined_ts'       => (int) $state['rebaselined_ts'],
			'fingerprint'          => $state['fingerprint'],
			'current'              => $current,
			'findings'             => $findings,
			'unacknowledged_count' => count( $findings ),
			'alerted'              => ! empty( $state['alerted'] ),
			'detected_ts'          => (int) $state['detected_ts'],
			'last_alert_ts'        => (int) $state['last_alert_ts'],
			'last_alert_channel'   => (string) $state['last_alert_channel'],
			'last_check_ts'        => (int) $state['last_check_ts'],
			'ammunition'           => $ammo,
			'checklist'            => self::checklist( $ammo ),
			'framing'              => self::FRAMING,
		);
	}

	/* ---------------------------------------------------------------------
	 * Throttled admin_init check
	 * ------------------------------------------------------------------ */

	/**
	 * Throttled identity check, wired to admin_init (never to a cron hook).
	 *
	 * @param int|null $now   Optional timestamp.
	 * @param bool     $force Skip the throttle.
	 * @return bool True when a check ran.
	 */
	public static function maybe_check( ?int $now = null, bool $force = false ): bool {
		if ( ! self::is_enabled() ) {
			return false;
		}
		$now   = self::resolve_now( is_int( $now ) ? $now : null );
		$state = self::get_state();

		if ( ! self::has_fingerprint( $state ) ) {
			// Enabled without a fingerprint: capture silently, no alert.
			self::capture( $state, $now, false );

			return true;
		}

		$last = (int) $state['last_check_ts'];
		if ( ! $force && $last > 0 && $now >= $last && ( $now - $last ) < self::CHECK_THROTTLE_SECONDS ) {
			return false;
		}

		$findings = self::compute_findings( $state['fingerprint'], self::current_identity( $state ) );
		if ( empty( $findings ) ) {
			$state['detected_ts'] = 0;
		} elseif ( (int) $state['detected_ts'] <= 0 ) {
			$state['detected_ts'] = $now;
		}
		$state['last_check_ts'] = $now;
		self::put_state( $state );

		self::maybe_fire_alerts( $now, self::build_snapshot( self::get_state(), $now ) );

		return true;
	}

	/* ---------------------------------------------------------------------
	 * Alerts: admin notice by default, outbound only on opt-in
	 * ------------------------------------------------------------------ */

	/**
	 * One alert per unacknowledged mismatch. Re-arms when the identity matches
	 * again or after a re-baseline.
	 *
	 * @param int|null                 $now  Timestamp.
	 * @param array<string,mixed>|null $snap Optional precomputed snapshot.
	 * @return bool True when a new alert was raised.
	 */
	public static function maybe_fire_alerts( ?int $now = null, ?array $snap = null ): bool {
		if ( ! self::is_enabled() ) {
			return false;
		}
		$now  = self::resolve_now( $now );
		$snap = null !== $snap ? $snap : self::snapshot( $now );

		$state = self::get_state();
		if ( (int) $snap['unacknowledged_count'] <= 0 ) {
			if ( ! empty( $state['alerted'] ) || (int) $state['detected_ts'] > 0 ) {
				$state['alerted']            = false;
				$state['detected_ts']        = 0;
				$state['last_alert_ts']      = 0;
				$state['last_alert_channel'] = '';
				self::put_state( $state );
			}

			return false;
		}

		if ( ! empty( $state['alerted'] ) ) {
			return false;
		}

		// The admin notice and own screen read the unacknowledged mismatch live, so
		// the default channel needs no delivery step. Outbound is opt-in only.
		$channel = self::CHANNEL_NOTICE;
		if ( self::is_outbound_enabled() ) {
			if ( ! self::fire_outbound( $snap, $now ) ) {
				return false; // Stay un-latched so the next check retries.
			}
			$channel = self::CHANNEL_OUTBOUND;
		}

		$state['alerted']            = true;
		$state['last_alert_ts']      = $now;
		$state['last_alert_channel'] = $channel;
		if ( (int) $state['detected_ts'] <= 0 ) {
			$state['detected_ts'] = $now;
		}
		self::put_state( $state );

		return true;
	}

	/**
	 * Email / webhook delivery. Only ever called when outbound_alert is on.
	 *
	 * @param array<string,mixed> $snap Snapshot.
	 */
	private static function fire_outbound( array $snap, int $now ): bool {
		if ( ! self::is_outbound_enabled() ) {
			return false;
		}

		$policy = class_exists( Policy::class, false ) && method_exists( Policy::class, 'get_policy' ) ? Policy::get_policy() : array();
		if ( ! is_array( $policy ) ) {
			$policy = array();
		}

		$email = '';
		if ( class_exists( Alerts::class, false ) && method_exists( Alerts::class, 'resolve_email' ) ) {
			$email = (string) Alerts::resolve_email( $policy );
		}
		if ( '' === $email ) {
			$email = sanitize_email( (string) get_option( 'admin_email' ) );
		}

		$ok = false;
		if ( '' !== $email ) {
			$subject = self::build_subject( $snap );
			$body    = self::build_body( $snap );
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
		}

		if ( class_exists( Alerts::class, false ) && method_exists( Alerts::class, 'resolve_webhook' ) ) {
			$hook_url = (string) Alerts::resolve_webhook( $policy );
			if ( '' !== $hook_url && method_exists( Alerts::class, 'safe_wp_remote_post' ) ) {
				$codes = array();
				foreach ( (array) ( $snap['findings'] ?? array() ) as $row ) {
					$codes[] = (string) ( $row['code'] ?? '' );
				}
				$posted = (bool) Alerts::safe_wp_remote_post(
					$hook_url,
					array(
						'type'                 => 'handl_aicac_doppelganger',
						'unacknowledged_count' => (int) ( $snap['unacknowledged_count'] ?? 0 ),
						'codes'                => $codes,
						'ts'                   => $now,
					)
				);
				$ok     = $ok || $posted;
			}
		}

		return $ok;
	}

	/**
	 * @param array<string,mixed> $snap Snapshot.
	 */
	public static function build_subject( array $snap ): string {
		$site  = function_exists( 'get_bloginfo' )
			? wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES )
			: 'WordPress';
		$first = '';
		foreach ( (array) ( $snap['findings'] ?? array() ) as $row ) {
			$first = (string) ( $row['code'] ?? '' );
			break;
		}

		return sprintf(
			/* translators: 1: site name, 2: finding count, 3: first finding code */
			__( '[%1$s] [DOPPELGANGER] This site no longer matches its recorded identity: %2$d change(s) (first: %3$s)', 'handl-ai-connector-access-control' ),
			$site,
			(int) ( $snap['unacknowledged_count'] ?? 0 ),
			$first
		);
	}

	/**
	 * @param array<string,mixed> $snap Snapshot.
	 */
	public static function build_body( array $snap ): string {
		$lines   = array();
		$lines[] = __( 'AI Access Control recorded an identity for this site (address, environment, table prefix and database). The site now differs from it, which usually means the database was cloned to another environment that still carries the original alert settings.', 'handl-ai-connector-access-control' );
		$lines[] = '';
		foreach ( (array) ( $snap['findings'] ?? array() ) as $row ) {
			$lines[] = '- ' . (string) ( $row['summary'] ?? '' );
		}
		$ammo = (array) ( $snap['ammunition'] ?? array() );
		if ( ! empty( $ammo ) ) {
			$lines[] = '';
			$lines[] = sprintf(
				/* translators: 1: email count, 2: webhook count, 3: budget count, 4: live schedule count */
				__( 'Still live on this copy: alert emails %1$d, webhooks %2$d, budgets %3$d, schedules %4$d.', 'handl-ai-connector-access-control' ),
				(int) ( $ammo['email']['count'] ?? 0 ),
				(int) ( $ammo['webhook']['count'] ?? 0 ),
				(int) ( $ammo['budgets']['count'] ?? 0 ),
				(int) ( $ammo['live_schedules'] ?? 0 )
			);
		}
		$lines[] = '';
		$lines[] = __( 'Suggestion only: Doppelganger never changes a webhook, email, budget or schedule. Review the quiet-the-copy checklist, or re-baseline if this was a planned migration. This check runs on admin page loads, not on cron.', 'handl-ai-connector-access-control' );
		$url     = self::admin_url();
		if ( '' !== $url ) {
			$lines[] = '';
			$lines[] = sprintf(
				/* translators: %s: admin URL */
				__( 'Open doppelganger: %s', 'handl-ai-connector-access-control' ),
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
	 * Admin notice (default alert delivery)
	 * ------------------------------------------------------------------ */

	/**
	 * Notice on admin screens while an unacknowledged mismatch exists. Reads only.
	 */
	public static function maybe_render_notice(): void {
		if ( ! self::is_enabled() || ! Caps::user_can_view() ) {
			return;
		}
		$page = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( (string) $_GET['page'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( self::PAGE_SLUG === $page ) {
			return; // The screen carries its own banner.
		}
		$state = self::get_state();
		if ( ! self::has_fingerprint( $state ) ) {
			return;
		}
		$findings = self::compute_findings( $state['fingerprint'], self::current_identity( $state ) );
		if ( empty( $findings ) ) {
			return;
		}

		$html  = '<div class="notice notice-warning"><p><strong>' . esc_html__( 'AI Access Control — Doppelganger:', 'handl-ai-connector-access-control' ) . '</strong> ';
		$html .= esc_html(
			sprintf(
				/* translators: %d: finding count */
				_n( 'This site no longer matches its recorded identity (%d change). It may be a cloned copy that still has the original alert settings.', 'This site no longer matches its recorded identity (%d changes). It may be a cloned copy that still has the original alert settings.', count( $findings ), 'handl-ai-connector-access-control' ),
				count( $findings )
			)
		);
		$url = self::admin_url();
		if ( '' !== $url ) {
			$html .= ' <a href="' . esc_url( $url ) . '">' . esc_html__( 'Review', 'handl-ai-connector-access-control' ) . '</a>';
		}
		$html .= '</p></div>';

		self::$test_notices[] = $html;
		echo $html; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped above.
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
		$lines[] = self::csv_line( array( 'section', 'code', 'field', 'baseline', 'current', 'detail', 'framing' ) );
		$lines[] = self::csv_line(
			array(
				'summary',
				'',
				'',
				'',
				'',
				'checked=' . self::ts_label( (int) ( $snap['now'] ?? 0 ) )
					. ' baseline=' . ( ! empty( $snap['baseline_pending'] ) ? 'pending' : self::ts_label( (int) ( $snap['baselined_ts'] ?? 0 ) ) )
					. ' unacknowledged=' . (string) (int) ( $snap['unacknowledged_count'] ?? 0 )
					. ' delivery=' . ( ! empty( $snap['outbound_alert'] ) ? self::CHANNEL_OUTBOUND : self::CHANNEL_NOTICE ),
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
					(string) $row['field'],
					(string) $row['before'],
					(string) $row['after'],
					(string) $row['summary'],
					self::FRAMING,
				)
			);
		}

		$ammo = (array) ( $snap['ammunition'] ?? array() );
		if ( ! empty( $ammo ) ) {
			$lines[] = self::csv_line( array( 'ammunition', 'email', 'recipients', '', (string) (int) $ammo['email']['count'], (string) $ammo['email']['redacted'], self::FRAMING ) );
			$lines[] = self::csv_line( array( 'ammunition', 'webhook', 'host', '', (string) (int) $ammo['webhook']['count'], (string) $ammo['webhook']['host'], self::FRAMING ) );
			$lines[] = self::csv_line( array( 'ammunition', 'budgets', 'plugins', '', (string) (int) $ammo['budgets']['count'], '', self::FRAMING ) );
			foreach ( (array) $ammo['schedules'] as $row ) {
				$lines[] = self::csv_line( array( 'ammunition', (string) $row['key'], 'schedule', '', ! empty( $row['live'] ) ? 'live' : 'off', (string) $row['label'], self::FRAMING ) );
			}
		}
		foreach ( (array) ( $snap['checklist'] ?? array() ) as $row ) {
			$lines[] = self::csv_line( array( 'checklist', (string) $row['key'], '', '', '', (string) $row['text'], self::FRAMING ) );
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
	 * @param list<array<string,mixed>> $rows Findings.
	 */
	private static function findings_table_html( array $rows ): string {
		$html  = '<table><thead><tr>';
		$html .= '<th>' . esc_html__( 'Finding', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '<th>' . esc_html__( 'Baseline', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '<th>' . esc_html__( 'Now', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '</tr></thead><tbody>';
		$shown = 0;
		foreach ( $rows as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			++$shown;
			$html .= '<tr>';
			$html .= '<td><strong>' . esc_html( (string) $row['summary'] ) . '</strong><br /><code>' . esc_html( (string) $row['code'] ) . '</code></td>';
			$html .= '<td>' . esc_html( (string) $row['before'] ) . '</td>';
			$html .= '<td>' . esc_html( (string) $row['after'] ) . '</td>';
			$html .= '</tr>';
		}
		if ( 0 === $shown ) {
			$html .= '<tr><td colspan="3">' . esc_html__( 'No unacknowledged identity changes.', 'handl-ai-connector-access-control' ) . '</td></tr>';
		}
		$html .= '</tbody></table>';

		return $html;
	}

	/**
	 * @param array<string,mixed> $ammo Ammunition inventory.
	 */
	private static function ammunition_table_html( array $ammo, bool $links ): string {
		$rows   = array();
		$rows[] = array(
			__( 'Alert email recipients', 'handl-ai-connector-access-control' ),
			(int) $ammo['email']['count'] > 0
				? sprintf( '%d (%s)', (int) $ammo['email']['count'], (string) $ammo['email']['redacted'] )
				: '0',
			(string) $ammo['email']['deep_link'],
		);
		$rows[] = array(
			__( 'Alert webhook', 'handl-ai-connector-access-control' ),
			(int) $ammo['webhook']['count'] > 0
				? sprintf( '%d (%s)', (int) $ammo['webhook']['count'], (string) $ammo['webhook']['host'] )
				: '0',
			(string) $ammo['webhook']['deep_link'],
		);
		$rows[] = array(
			__( 'Plugins with a budget', 'handl-ai-connector-access-control' ),
			(string) (int) $ammo['budgets']['count'],
			(string) $ammo['budgets']['deep_link'],
		);
		foreach ( (array) $ammo['schedules'] as $row ) {
			$rows[] = array(
				(string) $row['label'],
				! empty( $row['live'] ) ? __( 'live', 'handl-ai-connector-access-control' ) : __( 'off', 'handl-ai-connector-access-control' ),
				(string) $row['deep_link'],
			);
		}

		$html  = '<table><thead><tr><th>' . esc_html__( 'Still live on this site', 'handl-ai-connector-access-control' ) . '</th><th>' . esc_html__( 'State', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= $links ? '<th></th>' : '';
		$html .= '</tr></thead><tbody>';
		foreach ( $rows as $row ) {
			$html .= '<tr><td>' . esc_html( (string) $row[0] ) . '</td><td>' . esc_html( (string) $row[1] ) . '</td>';
			if ( $links ) {
				$html .= '<td>' . ( '' !== $row[2] ? '<a href="' . esc_url( $row[2] ) . '">' . esc_html__( 'Open', 'handl-ai-connector-access-control' ) . '</a>' : '' ) . '</td>';
			}
			$html .= '</tr>';
		}
		$html .= '</tbody></table>';

		return $html;
	}

	/**
	 * @param list<array<string,string>> $items Checklist.
	 */
	private static function checklist_html( array $items, bool $links ): string {
		$html = '<ol>';
		foreach ( $items as $item ) {
			$html .= '<li>' . esc_html( (string) $item['text'] );
			if ( $links && '' !== (string) $item['deep_link'] ) {
				$html .= ' <a href="' . esc_url( (string) $item['deep_link'] ) . '">' . esc_html__( 'Open', 'handl-ai-connector-access-control' ) . '</a>';
			}
			$html .= '</li>';
		}
		$html .= '</ol>';

		return $html;
	}

	/**
	 * @param array<string,mixed> $snap Snapshot.
	 */
	public static function build_print_html( array $snap ): string {
		$html  = '<!DOCTYPE html><html><head><meta charset="utf-8"><title>';
		$html .= esc_html__( 'AI Connector doppelganger', 'handl-ai-connector-access-control' );
		$html .= '</title><style>body{font-family:sans-serif;margin:24px}table{border-collapse:collapse;width:100%;margin-bottom:24px}th,td{border:1px solid #ccc;padding:6px 8px;text-align:left}th{background:#f6f7f7}</style></head><body>';
		$html .= '<h1>' . esc_html__( 'AI Connector doppelganger', 'handl-ai-connector-access-control' ) . '</h1>';
		$html .= '<p>' . esc_html__( 'Report only — never changes a webhook, email, budget or schedule.', 'handl-ai-connector-access-control' ) . '</p>';
		$html .= '<ul>';
		$html .= '<li>' . esc_html( sprintf( 'Unacknowledged identity changes: %d', (int) ( $snap['unacknowledged_count'] ?? 0 ) ) ) . '</li>';
		$html .= '<li>' . esc_html( ! empty( $snap['baseline_pending'] ) ? 'Baseline: not captured yet' : sprintf( 'Baseline captured: %s', self::ts_label( (int) ( $snap['baselined_ts'] ?? 0 ) ) ) ) . '</li>';
		$html .= '</ul>';
		$html .= '<h2>' . esc_html__( 'Findings', 'handl-ai-connector-access-control' ) . '</h2>';
		$html .= self::findings_table_html( (array) ( $snap['findings'] ?? array() ) );
		if ( ! empty( $snap['ammunition'] ) ) {
			$html .= '<h2>' . esc_html__( 'Still live on this site', 'handl-ai-connector-access-control' ) . '</h2>';
			$html .= self::ammunition_table_html( (array) $snap['ammunition'], false );
			$html .= '<h2>' . esc_html__( 'Quiet-the-copy checklist (suggestions only)', 'handl-ai-connector-access-control' ) . '</h2>';
			$html .= self::checklist_html( (array) ( $snap['checklist'] ?? array() ), false );
		}
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
			__( 'Doppelganger', 'handl-ai-connector-access-control' ),
			__( 'Doppelganger', 'handl-ai-connector-access-control' ),
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
				'page'                          => self::PAGE_SLUG,
				'handl_aicac_doppelganger_csv'  => '1',
				'_wpnonce'                      => function_exists( 'wp_create_nonce' ) ? wp_create_nonce( 'handl_aicac_doppelganger_csv' ) : '',
			),
			admin_url( 'admin.php' )
		);
		$print      = add_query_arg(
			array(
				'page'                            => self::PAGE_SLUG,
				'handl_aicac_doppelganger_print'  => '1',
				'_wpnonce'                        => function_exists( 'wp_create_nonce' ) ? wp_create_nonce( 'handl_aicac_doppelganger_print' ) : '',
			),
			admin_url( 'admin.php' )
		);

		echo '<div class="wrap">';
		echo '<h1>' . esc_html__( 'Doppelganger', 'handl-ai-connector-access-control' ) . '</h1>';
		echo '<p class="description">' . esc_html__( 'Remembers this site\'s identity (address, environment, table prefix and a hashed database identity) and reports when the site no longer matches it, which is what a database cloned to staging or a new host looks like. Suggestion only — it never changes a webhook, email, budget or schedule. Alerts show here and as an admin notice; email and webhook delivery is a separate opt-in. Checks run on admin page loads, not on cron. Off by default.', 'handl-ai-connector-access-control' ) . '</p>';

		if ( $can_manage ) {
			echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
			echo '<input type="hidden" name="action" value="' . esc_attr( self::ACTION_SAVE ) . '" />';
			if ( function_exists( 'wp_nonce_field' ) ) {
				wp_nonce_field( self::ACTION_SAVE );
			}
			echo '<input type="hidden" name="' . esc_attr( self::POST_PRESENT ) . '" value="1" />';
			echo '<table class="form-table" role="presentation"><tbody>';
			echo '<tr><th scope="row">' . esc_html__( 'Enable doppelganger', 'handl-ai-connector-access-control' ) . '</th><td>';
			echo '<label><input type="checkbox" name="' . esc_attr( self::POST_ENABLED ) . '" value="1" ' . checked( ! empty( $settings['enabled'] ), true, false ) . ' /> ';
			echo esc_html__( 'Record this site\'s identity and flag when it changes', 'handl-ai-connector-access-control' );
			echo '</label></td></tr>';
			echo '<tr><th scope="row">' . esc_html__( 'Outbound alert', 'handl-ai-connector-access-control' ) . '</th><td>';
			echo '<label><input type="checkbox" name="' . esc_attr( self::POST_OUTBOUND ) . '" value="1" ' . checked( ! empty( $settings['outbound_alert'] ), true, false ) . ' /> ';
			echo esc_html__( 'Also send the alert by email / webhook (off by default: a cloned site would send it to production recipients)', 'handl-ai-connector-access-control' );
			echo '</label></td></tr></tbody></table>';
			submit_button( __( 'Save doppelganger settings', 'handl-ai-connector-access-control' ) );
			echo '</form>';
		}

		if ( ! $enabled || ! is_array( $snap ) ) {
			echo '<p>' . esc_html__( 'Doppelganger is off. Enable it to record this site\'s identity.', 'handl-ai-connector-access-control' ) . '</p>';
			echo '</div>';

			return;
		}

		echo '<p><strong>' . esc_html__( 'Report only — never changes a webhook, email, budget or schedule.', 'handl-ai-connector-access-control' ) . '</strong></p>';
		if ( (int) $snap['unacknowledged_count'] > 0 ) {
			echo '<div class="notice notice-warning inline"><p><strong>' . esc_html__( 'This site no longer matches its recorded identity.', 'handl-ai-connector-access-control' ) . '</strong> ';
			echo esc_html__( 'If this is a clone, work through the checklist below. If you moved the site on purpose, re-baseline.', 'handl-ai-connector-access-control' ) . '</p></div>';
		}
		echo '<ul>';
		echo '<li>' . esc_html( sprintf( 'Unacknowledged identity changes: %d', (int) $snap['unacknowledged_count'] ) ) . '</li>';
		echo '<li>' . esc_html( sprintf( 'Baseline captured: %s', self::ts_label( (int) $snap['baselined_ts'] ) ) ) . '</li>';
		if ( (int) $snap['rebaselined_ts'] > 0 ) {
			echo '<li>' . esc_html( sprintf( 'Last re-baseline: %s', self::ts_label( (int) $snap['rebaselined_ts'] ) ) ) . '</li>';
		}
		echo '<li>' . esc_html( sprintf( 'Alert delivery: %s', ! empty( $snap['outbound_alert'] ) ? 'admin notice + this screen + email/webhook' : 'admin notice + this screen' ) ) . '</li>';
		echo '</ul>';

		if ( $can_manage ) {
			echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
			echo '<input type="hidden" name="action" value="' . esc_attr( self::ACTION_REBASELINE ) . '" />';
			if ( function_exists( 'wp_nonce_field' ) ) {
				wp_nonce_field( self::ACTION_REBASELINE );
			}
			submit_button( __( 'Re-baseline to this site (legitimate migration)', 'handl-ai-connector-access-control' ), 'secondary' );
			echo '</form>';
		}

		echo '<p>';
		echo '<a class="button" href="' . esc_url( $csv ) . '">' . esc_html__( 'Download CSV', 'handl-ai-connector-access-control' ) . '</a> ';
		echo '<a class="button" href="' . esc_url( $print ) . '" target="_blank" rel="noopener noreferrer">' . esc_html__( 'Print / PDF view', 'handl-ai-connector-access-control' ) . '</a>';
		echo '</p>';

		echo '<h2>' . esc_html__( 'Findings', 'handl-ai-connector-access-control' ) . '</h2>';
		echo str_replace( '<table>', '<table class="widefat striped">', self::findings_table_html( (array) $snap['findings'] ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped in builder.
		echo '<h2>' . esc_html__( 'Still live on this site', 'handl-ai-connector-access-control' ) . '</h2>';
		echo str_replace( '<table>', '<table class="widefat striped">', self::ammunition_table_html( (array) $snap['ammunition'], true ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped in builder.
		echo '<h2>' . esc_html__( 'Quiet-the-copy checklist', 'handl-ai-connector-access-control' ) . '</h2>';
		echo '<p class="description">' . esc_html__( 'Suggestions only. Nothing here is applied for you.', 'handl-ai-connector-access-control' ) . '</p>';
		echo self::checklist_html( (array) $snap['checklist'], true ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped in builder.

		echo '</div>';
	}

	public static function maybe_handle_csv(): void {
		if ( empty( $_GET['handl_aicac_doppelganger_csv'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
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
		if ( ! function_exists( 'wp_verify_nonce' ) || ! wp_verify_nonce( $nonce, 'handl_aicac_doppelganger_csv' ) ) {
			return;
		}
		$csv = self::csv_for_snapshot();
		if ( function_exists( 'nocache_headers' ) ) {
			nocache_headers();
		}
		header( 'Content-Type: text/csv; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename=handl-aicac-doppelganger.csv' );
		echo $csv; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- CSV download.
		exit;
	}

	public static function maybe_handle_print(): void {
		if ( empty( $_GET['handl_aicac_doppelganger_print'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
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
		if ( ! function_exists( 'wp_verify_nonce' ) || ! wp_verify_nonce( $nonce, 'handl_aicac_doppelganger_print' ) ) {
			return;
		}
		if ( function_exists( 'nocache_headers' ) ) {
			nocache_headers();
		}
		echo self::build_print_html( self::snapshot() ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped in builder.
		exit;
	}

	private static function redirect_to_page(): void {
		$redirect = self::admin_url();
		if ( '' === $redirect && function_exists( 'admin_url' ) ) {
			$redirect = admin_url( 'admin.php?page=' . self::PAGE_SLUG );
		}
		wp_safe_redirect( $redirect );
		exit;
	}

	public static function handle_save(): void {
		if ( ! Caps::user_can_manage() ) {
			wp_die( esc_html__( 'You do not have permission to save doppelganger settings.', 'handl-ai-connector-access-control' ) );
		}
		check_admin_referer( self::ACTION_SAVE );
		if ( empty( $_POST[ self::POST_PRESENT ] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing
			wp_die( esc_html__( 'Invalid form', 'handl-ai-connector-access-control' ) );
		}
		self::save_settings(
			array(
				'enabled'        => ! empty( $_POST[ self::POST_ENABLED ] ), // phpcs:ignore WordPress.Security.NonceVerification.Missing
				'outbound_alert' => ! empty( $_POST[ self::POST_OUTBOUND ] ), // phpcs:ignore WordPress.Security.NonceVerification.Missing
			)
		);
		self::redirect_to_page();
	}

	/**
	 * Accept the running site as the new baseline. Records a fingerprint only.
	 */
	public static function handle_rebaseline(): void {
		if ( ! Caps::user_can_manage() ) {
			wp_die( esc_html__( 'You do not have permission to re-baseline the site identity.', 'handl-ai-connector-access-control' ) );
		}
		check_admin_referer( self::ACTION_REBASELINE );
		self::rebaseline();
		self::redirect_to_page();
	}

	public static function register_cli(): void {
		if ( ! defined( 'WP_CLI' ) || ! WP_CLI ) {
			return;
		}
		if ( ! class_exists( '\\WP_CLI' ) ) {
			return;
		}
		\WP_CLI::add_command( 'handl-aicac doppelganger', CLI_Doppelganger::class );
	}
}

/**
 * WP-CLI: wp handl-aicac doppelganger status|export
 */
final class CLI_Doppelganger {

	/**
	 * Run an identity check now and show the comparison. Exits non-zero while an
	 * unacknowledged identity mismatch is present (while enabled).
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

		if ( ! Doppelganger::is_enabled() ) {
			\WP_CLI::log( 'enabled=no framing=' . Doppelganger::FRAMING );
			\WP_CLI::log( 'Doppelganger is disabled.' );

			return;
		}

		Doppelganger::maybe_check( null, true );
		$snap = Doppelganger::snapshot();

		\WP_CLI::log(
			sprintf(
				'enabled=yes baseline=%s unacknowledged=%d alerted=%s outbound=%s framing=%s',
				! empty( $snap['baseline_pending'] ) ? 'pending' : 'captured',
				(int) $snap['unacknowledged_count'],
				! empty( $snap['alerted'] ) ? 'yes' : 'no',
				! empty( $snap['outbound_alert'] ) ? 'on' : 'off',
				Doppelganger::FRAMING
			)
		);

		$display = array();
		foreach ( (array) $snap['findings'] as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$display[] = array(
				'code'     => (string) $row['code'],
				'field'    => (string) $row['field'],
				'baseline' => (string) $row['before'],
				'current'  => (string) $row['after'],
			);
		}
		if ( ! empty( $display ) ) {
			if ( 'json' === $format ) {
				\WP_CLI::print_value( $display, array( 'format' => 'json' ) );
			} elseif ( class_exists( '\\WP_CLI\\Utils' ) ) {
				\WP_CLI\Utils\format_items( 'table', $display, array( 'code', 'field', 'baseline', 'current' ) );
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

		if ( (int) $snap['unacknowledged_count'] > 0 ) {
			// Default exit=true: an unacknowledged identity mismatch must fail the command.
			\WP_CLI::error( 'Unacknowledged site identity mismatch present.' );
		}
	}

	/**
	 * Export the identity findings, still-live inventory and checklist as CSV.
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
		$csv = Doppelganger::csv_for_snapshot();
		if ( ! empty( $assoc_args['porcelain'] ) ) {
			echo $csv; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- CLI CSV.
			return;
		}
		\WP_CLI::print_value( $csv, array( 'format' => 'csv' ) );
	}
}
