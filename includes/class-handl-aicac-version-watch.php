<?php
/**
 * AICAC-VERSION-WATCH (#283): flag Allow rules for re-review when a plugin updates.
 *
 * Tracks the installed plugin version at Allow save / review-due confirm. When
 * the installed version changes, the rule surfaces in the review-due inbox and
 * one alert fires per plugin+version (snooze respected). Observability only —
 * never mutates allow/deny.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Version stamps + update detection for Allow rules.
 */
final class Version_Watch {

	/** plugin basename => version string at last trust decision. */
	public const VERSION_OPTION_KEY = 'handl_aicac_allow_rule_versions';

	/** plugin basename => version string already alerted. */
	public const ALERTED_OPTION_KEY = 'handl_aicac_version_watch_alerted';

	public const SCAN_TRANSIENT_KEY = 'handl_aicac_version_watch_scanned';

	public const SCAN_INTERVAL = 300; // 5 minutes.

	public const ALERT_KIND = 'version_watch';

	/**
	 * @param mixed $raw
	 * @return array<string,string>
	 */
	public static function sanitize_versions( $raw ): array {
		if ( ! is_array( $raw ) ) {
			return array();
		}
		$out = array();
		foreach ( $raw as $basename => $version ) {
			$basename = Plugin_Profile::sanitize_plugin( (string) $basename );
			$version  = self::sanitize_version( $version );
			if ( '' === $basename || '' === $version ) {
				continue;
			}
			$out[ $basename ] = $version;
		}

		return $out;
	}

	/**
	 * @param mixed $raw
	 */
	public static function sanitize_version( $raw ): string {
		return sanitize_text_field( (string) $raw );
	}

	/**
	 * @return array<string,string>
	 */
	public static function get_versions(): array {
		return self::sanitize_versions( get_option( self::VERSION_OPTION_KEY, array() ) );
	}

	/**
	 * @param array<string,string> $map
	 */
	public static function put_versions( array $map ): void {
		$map = self::sanitize_versions( $map );
		if ( empty( $map ) ) {
			delete_option( self::VERSION_OPTION_KEY );
			return;
		}
		update_option( self::VERSION_OPTION_KEY, $map, false );
	}

	/**
	 * @return array<string,string>
	 */
	public static function get_alerted(): array {
		return self::sanitize_versions( get_option( self::ALERTED_OPTION_KEY, array() ) );
	}

	/**
	 * @param array<string,string> $map
	 */
	public static function put_alerted( array $map ): void {
		$map = self::sanitize_versions( $map );
		if ( empty( $map ) ) {
			delete_option( self::ALERTED_OPTION_KEY );
			return;
		}
		update_option( self::ALERTED_OPTION_KEY, $map, false );
	}

	/**
	 * Keep version stamps only for explicit Allow rules.
	 *
	 * @param array<string,mixed> $policy
	 * @param array<string,string> $versions
	 * @return array<string,string>
	 */
	public static function normalize_versions( array $policy, array $versions ): array {
		$plugins = isset( $policy['plugins'] ) && is_array( $policy['plugins'] )
			? $policy['plugins']
			: array();
		$versions = self::sanitize_versions( $versions );
		$kept     = array();
		foreach ( $versions as $basename => $version ) {
			$rule = isset( $plugins[ $basename ] ) ? (string) $plugins[ $basename ] : '';
			if ( 'allow' !== $rule ) {
				continue;
			}
			$kept[ $basename ] = $version;
		}

		return $kept;
	}

	public static function init(): void {
		add_action( 'upgrader_process_complete', array( self::class, 'on_upgrader_process_complete' ), 10, 2 );
		add_action( 'init', array( self::class, 'lazy_scan' ), 30 );
	}

	/**
	 * Stamp versions when Allow rules are created or their allow/deny value changes.
	 * Does not restamp unchanged Allow rules (preserves trust version).
	 *
	 * @param array<string,mixed>               $incoming
	 * @param array<string,mixed>               $previous
	 * @param array<string,array<string,mixed>> $installed get_plugins()-shaped.
	 */
	public static function stamp_on_rule_changes( array $incoming, array $previous, array $installed = array() ): void {
		if ( empty( $installed ) && function_exists( 'get_plugins' ) ) {
			$installed = get_plugins();
		}
		$before = isset( $previous['plugins'] ) && is_array( $previous['plugins'] )
			? $previous['plugins']
			: array();
		$after = isset( $incoming['plugins'] ) && is_array( $incoming['plugins'] )
			? $incoming['plugins']
			: array();
		$versions = self::get_versions();

		foreach ( $after as $basename => $rule ) {
			$basename = Plugin_Profile::sanitize_plugin( (string) $basename );
			$rule     = (string) $rule;
			if ( '' === $basename ) {
				continue;
			}
			$prev = isset( $before[ $basename ] ) ? (string) $before[ $basename ] : '';
			if ( 'allow' !== $rule ) {
				unset( $versions[ $basename ] );
				continue;
			}
			if ( $prev === $rule && isset( $versions[ $basename ] ) ) {
				continue;
			}
			$ver = self::version_from_installed( $basename, $installed );
			if ( '' === $ver ) {
				continue;
			}
			$versions[ $basename ] = $ver;
		}

		foreach ( array_keys( $versions ) as $basename ) {
			if ( ! isset( $after[ $basename ] ) || 'allow' !== (string) $after[ $basename ] ) {
				unset( $versions[ $basename ] );
			}
		}

		self::put_versions( self::normalize_versions( $incoming, $versions ) );
	}

	/**
	 * Restamp installed version for confirmed Allow rules.
	 *
	 * @param array<string,mixed>               $policy
	 * @param list<string>                      $basenames
	 * @param array<string,array<string,mixed>> $installed
	 */
	public static function stamp_on_confirm( array $policy, array $basenames, array $installed = array() ): void {
		if ( empty( $installed ) && function_exists( 'get_plugins' ) ) {
			$installed = get_plugins();
		}
		$plugins  = isset( $policy['plugins'] ) && is_array( $policy['plugins'] ) ? $policy['plugins'] : array();
		$versions = self::get_versions();
		foreach ( $basenames as $basename ) {
			$basename = Plugin_Profile::sanitize_plugin( (string) $basename );
			if ( '' === $basename ) {
				continue;
			}
			$rule = isset( $plugins[ $basename ] ) ? (string) $plugins[ $basename ] : '';
			if ( 'allow' !== $rule ) {
				unset( $versions[ $basename ] );
				continue;
			}
			$ver = self::version_from_installed( $basename, $installed );
			if ( '' === $ver ) {
				continue;
			}
			$versions[ $basename ] = $ver;
		}
		self::put_versions( self::normalize_versions( $policy, $versions ) );
	}

	/**
	 * @param array<string,array<string,mixed>> $installed
	 */
	public static function version_from_installed( string $basename, array $installed ): string {
		$basename = Plugin_Profile::sanitize_plugin( $basename );
		if ( '' === $basename || ! isset( $installed[ $basename ] ) || ! is_array( $installed[ $basename ] ) ) {
			return '';
		}
		if ( ! isset( $installed[ $basename ]['Version'] ) ) {
			return '';
		}

		return self::sanitize_version( $installed[ $basename ]['Version'] );
	}

	public static function plugin_version( string $basename ): string {
		if ( function_exists( 'get_plugins' ) ) {
			return self::version_from_installed( $basename, get_plugins() );
		}

		return '';
	}

	/**
	 * True when an Allow rule's stamped version differs from the installed version.
	 *
	 * @param array<string,array<string,mixed>>|null $installed
	 */
	public static function is_mismatch( string $basename, ?array $installed = null ): bool {
		$basename = Plugin_Profile::sanitize_plugin( $basename );
		if ( '' === $basename ) {
			return false;
		}
		$versions = self::get_versions();
		if ( ! isset( $versions[ $basename ] ) ) {
			return false;
		}
		if ( null === $installed ) {
			$installed = function_exists( 'get_plugins' ) ? get_plugins() : array();
		}
		$current = self::version_from_installed( $basename, $installed );
		if ( '' === $current ) {
			return false;
		}

		return $versions[ $basename ] !== $current;
	}

	/**
	 * Label for Rules-row chip / plugin profile (UI may consume later).
	 *
	 * @param array<string,array<string,mixed>>|null $installed
	 * @return array{due:bool,stamped:string,installed:string,label:string,note:string}
	 */
	public static function status_for( string $basename, ?array $installed = null ): array {
		$basename = Plugin_Profile::sanitize_plugin( $basename );
		$empty    = array(
			'due'       => false,
			'stamped'   => '',
			'installed' => '',
			'label'     => '',
			'note'      => '',
		);
		if ( '' === $basename ) {
			return $empty;
		}
		if ( null === $installed ) {
			$installed = function_exists( 'get_plugins' ) ? get_plugins() : array();
		}
		$stamped   = self::get_versions()[ $basename ] ?? '';
		$installed_v = self::version_from_installed( $basename, $installed );
		$due         = self::is_mismatch( $basename, $installed );
		if ( ! $due ) {
			return array(
				'due'       => false,
				'stamped'   => $stamped,
				'installed' => $installed_v,
				'label'     => '',
				'note'      => '',
			);
		}

		return array(
			'due'       => true,
			'stamped'   => $stamped,
			'installed' => $installed_v,
			'label'     => __( 'Version changed', 'handl-ai-connector-access-control' ),
			'note'      => sprintf(
				/* translators: 1: previously recorded version, 2: current installed version */
				__( 'Previously recorded version: %1$s. Current version: %2$s. Review the Allow rule.', 'handl-ai-connector-access-control' ),
				$stamped,
				$installed_v
			),
		);
	}

	/**
	 * @param WP_Upgrader|mixed $upgrader Unused.
	 * @param array<string,mixed>|mixed $options
	 */
	public static function on_upgrader_process_complete( $upgrader, $options ): void {
		unset( $upgrader );
		if ( ! is_array( $options ) ) {
			return;
		}
		if ( ( $options['type'] ?? '' ) !== 'plugin' ) {
			return;
		}
		$plugins = array();
		if ( ! empty( $options['bulk'] ) && isset( $options['plugins'] ) && is_array( $options['plugins'] ) ) {
			foreach ( $options['plugins'] as $file ) {
				$file = Plugin_Profile::sanitize_plugin( (string) $file );
				if ( '' !== $file ) {
					$plugins[] = $file;
				}
			}
		} elseif ( isset( $options['plugin'] ) ) {
			$file = Plugin_Profile::sanitize_plugin( (string) $options['plugin'] );
			if ( '' !== $file ) {
				$plugins[] = $file;
			}
		}
		if ( empty( $plugins ) ) {
			return;
		}
		if ( function_exists( 'wp_clean_plugins_cache' ) ) {
			wp_clean_plugins_cache( false );
		}
		$policy    = Policy::get_policy();
		$installed = function_exists( 'get_plugins' ) ? get_plugins() : array();
		foreach ( $plugins as $basename ) {
			self::process_plugin( $policy, $basename, $installed );
		}
	}

	/**
	 * Throttled scan of all Allow rules (missed upgrader hooks / CLI updates).
	 */
	public static function lazy_scan(): void {
		if ( get_transient( self::SCAN_TRANSIENT_KEY ) ) {
			return;
		}
		set_transient( self::SCAN_TRANSIENT_KEY, 1, self::SCAN_INTERVAL );
		self::scan();
	}

	/**
	 * @param array<string,mixed>|null          $policy
	 * @param array<string,array<string,mixed>>|null $installed
	 * @param int|null                          $now
	 * @return array{checked:int,mismatched:int,alerted:int,baselined:int}
	 */
	public static function scan( ?array $policy = null, ?array $installed = null, ?int $now = null ): array {
		$policy    = null !== $policy ? $policy : Policy::get_policy();
		$installed = null !== $installed
			? $installed
			: ( function_exists( 'get_plugins' ) ? get_plugins() : array() );
		$now       = null !== $now && $now > 0 ? $now : time();
		$plugins   = isset( $policy['plugins'] ) && is_array( $policy['plugins'] ) ? $policy['plugins'] : array();
		$stats     = array(
			'checked'    => 0,
			'mismatched' => 0,
			'alerted'    => 0,
			'baselined'  => 0,
		);

		foreach ( $plugins as $basename => $rule ) {
			$basename = Plugin_Profile::sanitize_plugin( (string) $basename );
			if ( '' === $basename || 'allow' !== (string) $rule ) {
				continue;
			}
			++$stats['checked'];
			$result = self::process_plugin( $policy, $basename, $installed, $now );
			if ( $result['baselined'] ) {
				++$stats['baselined'];
			}
			if ( $result['mismatched'] ) {
				++$stats['mismatched'];
			}
			if ( $result['alerted'] ) {
				++$stats['alerted'];
			}
		}

		return $stats;
	}

	/**
	 * @param array<string,mixed>               $policy
	 * @param array<string,array<string,mixed>> $installed
	 * @return array{mismatched:bool,alerted:bool,baselined:bool,reason:string}
	 */
	public static function process_plugin( array $policy, string $basename, array $installed, ?int $now = null ): array {
		$basename = Plugin_Profile::sanitize_plugin( $basename );
		$empty    = array(
			'mismatched' => false,
			'alerted'    => false,
			'baselined'  => false,
			'reason'     => '',
		);
		if ( '' === $basename ) {
			$empty['reason'] = 'bad_plugin';
			return $empty;
		}
		$plugins = isset( $policy['plugins'] ) && is_array( $policy['plugins'] ) ? $policy['plugins'] : array();
		$rule    = isset( $plugins[ $basename ] ) ? (string) $plugins[ $basename ] : '';
		if ( 'allow' !== $rule ) {
			$empty['reason'] = 'not_allow';
			return $empty;
		}

		$now     = null !== $now && $now > 0 ? $now : time();
		$current = self::version_from_installed( $basename, $installed );
		if ( '' === $current ) {
			$empty['reason'] = 'no_installed_version';
			return $empty;
		}

		$versions = self::get_versions();
		if ( ! isset( $versions[ $basename ] ) ) {
			$versions[ $basename ] = $current;
			self::put_versions( self::normalize_versions( $policy, $versions ) );
			return array(
				'mismatched' => false,
				'alerted'    => false,
				'baselined'  => true,
				'reason'     => 'baseline',
			);
		}

		if ( $versions[ $basename ] === $current ) {
			$empty['reason'] = 'match';
			return $empty;
		}

		$alerted_map = self::get_alerted();
		$already     = isset( $alerted_map[ $basename ] ) && $alerted_map[ $basename ] === $current;
		$fired       = false;
		if ( ! $already ) {
			$fired = self::maybe_fire( $policy, $basename, $versions[ $basename ], $current, $now );
			if ( $fired ) {
				$alerted_map[ $basename ] = $current;
				self::put_alerted( $alerted_map );
			}
		}

		return array(
			'mismatched' => true,
			'alerted'    => $fired,
			'baselined'  => false,
			'reason'     => $fired ? 'alerted' : ( $already ? 'deduped' : 'suppressed_or_no_recipient' ),
		);
	}

	/**
	 * @param array<string,mixed> $policy
	 */
	private static function maybe_fire(
		array $policy,
		string $plugin,
		string $stamped,
		string $installed,
		int $now
	): bool {
		if ( Alert_Snooze::should_suppress( $plugin, self::ALERT_KIND, $now ) ) {
			return false;
		}

		$to = Alerts::resolve_email( $policy );
		if ( '' === $to ) {
			return false;
		}

		$subject = self::build_subject( $plugin );
		$body    = self::build_body( $plugin, $stamped, $installed );
		$ok      = Alerts::safe_wp_mail( $to, $subject, $body );

		$hook_url = Alerts::resolve_webhook( $policy );
		if ( '' !== $hook_url ) {
			Alerts::safe_wp_remote_post(
				$hook_url,
				array(
					'type'              => 'handl_aicac_version_watch_alert',
					'plugin'            => $plugin,
					'stamped_version'   => $stamped,
					'installed_version' => $installed,
					'rules'             => Plugin_Profile::rules_url( $plugin ),
					'site'              => function_exists( 'home_url' ) ? home_url( '/' ) : '',
				)
			);
		}

		if ( ! $ok ) {
			return false;
		}

		Policy::append_log_event(
			array(
				'ts'                => $now,
				'decision'          => 'version_watch_alert',
				'channel'           => 'version_watch',
				'plugin'            => $plugin,
				'stamped_version'   => $stamped,
				'installed_version' => $installed,
			)
		);

		return true;
	}

	public static function build_subject( string $plugin ): string {
		$site  = function_exists( 'get_bloginfo' )
			? wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES )
			: 'WordPress';
		$label = self::plugin_label( $plugin );

		return sprintf(
			/* translators: 1: site name, 2: plugin name */
			__( '[%1$s] HandL: Review %2$s after a version change', 'handl-ai-connector-access-control' ),
			$site,
			$label
		);
	}

	public static function build_body( string $plugin, string $stamped, string $installed ): string {
		$lines   = array();
		$lines[] = __( 'HandL AI Connector Access Control: plugin version change', 'handl-ai-connector-access-control' );
		$lines[] = '';
		$lines[] = sprintf(
			/* translators: %s: plugin display name or basename */
			__( 'Plugin: %s', 'handl-ai-connector-access-control' ),
			self::plugin_label( $plugin )
		);
		$lines[] = sprintf(
			/* translators: 1: previously recorded version, 2: current installed version */
			__( 'Previously recorded version: %1$s. Current version: %2$s.', 'handl-ai-connector-access-control' ),
			'' !== $stamped ? $stamped : __( 'unknown', 'handl-ai-connector-access-control' ),
			'' !== $installed ? $installed : __( 'unknown', 'handl-ai-connector-access-control' )
		);
		$lines[] = '';
		$lines[] = __( 'This plugin has an Allow rule. Review whether it should still be allowed after the version change. Your access rules have not changed.', 'handl-ai-connector-access-control' );
		$lines[] = '';
		$lines[] = __( 'Review this plugin’s rules:', 'handl-ai-connector-access-control' );
		$lines[] = Plugin_Profile::rules_url( $plugin );

		return implode( "\n", $lines ) . "\n";
	}

	private static function plugin_label( string $basename ): string {
		if ( function_exists( 'get_plugins' ) ) {
			$plugins = get_plugins();
			if ( isset( $plugins[ $basename ]['Name'] ) && is_string( $plugins[ $basename ]['Name'] ) ) {
				return (string) $plugins[ $basename ]['Name'];
			}
		}

		return $basename;
	}
}
