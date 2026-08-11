<?php
/**
 * AICAC-TEMP-ALLOW: Optional expiry on explicit Allow plugin rules (#100).
 *
 * Decision-time check is authoritative (no cron dependency for correctness).
 * Hourly sweep tidies expired entries, writes an audit row, and emails when
 * denial/shadow alert infrastructure is enabled.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Temporary allow-rule expiry helpers + scheduled tidy.
 */
final class Temp_Allow {

	public const CRON_HOOK = 'handl_aicac_sweep_expired_allows';

	/** Default renew window when an admin renews an expired allow (seconds). */
	public const RENEW_SECONDS = 604800; // 7 days

	/** @var list<string> */
	public const PRESETS = array( '', '24h', '7d', '30d', 'custom' );

	private static ?Temp_Allow $instance = null;

	public static function instance(): Temp_Allow {
		if ( null === self::$instance ) {
			self::$instance = new Temp_Allow();
		}
		return self::$instance;
	}

	public function init(): void {
		add_action( self::CRON_HOOK, array( $this, 'run_sweep' ) );
		add_action( 'init', array( $this, 'maybe_self_heal_schedule' ), 22 );
	}

	/**
	 * Re-schedule hourly sweep when any expiry is stored and the event is missing.
	 */
	public function maybe_self_heal_schedule(): void {
		self::maybe_schedule( Policy::get_policy() );
	}

	/**
	 * Cron entry point.
	 */
	public function run_sweep(): void {
		self::sweep_expired( Policy::get_policy(), null );
	}

	/**
	 * @param array<string,mixed> $policy
	 */
	public static function maybe_schedule( array $policy ): void {
		$expires = self::sanitize_plugin_expires( $policy['plugin_expires'] ?? array() );
		if ( ! empty( $expires ) ) {
			if ( function_exists( 'wp_next_scheduled' ) && function_exists( 'wp_schedule_event' ) ) {
				if ( ! \wp_next_scheduled( self::CRON_HOOK ) ) {
					\wp_schedule_event( time() + HOUR_IN_SECONDS, 'hourly', self::CRON_HOOK );
				}
			}
			return;
		}

		if ( function_exists( 'wp_next_scheduled' ) && function_exists( 'wp_unschedule_event' ) ) {
			$ts = \wp_next_scheduled( self::CRON_HOOK );
			if ( $ts ) {
				\wp_unschedule_event( $ts, self::CRON_HOOK );
			}
		}
	}

	/**
	 * Sanitize basename => unix expiry map. Non-positive / junk dropped.
	 *
	 * @param mixed $raw
	 * @return array<string,int>
	 */
	public static function sanitize_plugin_expires( $raw ): array {
		if ( ! is_array( $raw ) ) {
			return array();
		}
		$out = array();
		foreach ( $raw as $basename => $ts ) {
			$basename = sanitize_text_field( (string) $basename );
			if ( '' === $basename ) {
				continue;
			}
			if ( is_string( $ts ) && ! preg_match( '/^\s*\d+\s*$/', $ts ) ) {
				continue;
			}
			$n = (int) $ts;
			if ( $n <= 0 ) {
				continue;
			}
			$out[ $basename ] = $n;
		}

		return $out;
	}

	/**
	 * Keep expires only for explicit allow rules; drop orphan / deny keys.
	 *
	 * @param array<string,mixed> $policy
	 * @return array<string,mixed>
	 */
	public static function normalize_expires_against_plugins( array $policy ): array {
		$plugins = isset( $policy['plugins'] ) && is_array( $policy['plugins'] )
			? $policy['plugins']
			: array();
		$expires = self::sanitize_plugin_expires( $policy['plugin_expires'] ?? array() );
		$kept    = array();
		foreach ( $expires as $basename => $ts ) {
			$rule = isset( $plugins[ $basename ] ) ? (string) $plugins[ $basename ] : '';
			if ( 'allow' !== $rule ) {
				continue;
			}
			$kept[ $basename ] = $ts;
		}
		$policy['plugin_expires'] = $kept;

		return $policy;
	}

	/**
	 * Unix expiry for a plugin, or null when none / invalid.
	 *
	 * @param array<string,mixed> $policy
	 */
	public static function expires_at( array $policy, string $plugin_basename ): ?int {
		$plugin_basename = sanitize_text_field( $plugin_basename );
		if ( '' === $plugin_basename ) {
			return null;
		}
		$expires = self::sanitize_plugin_expires( $policy['plugin_expires'] ?? array() );
		if ( ! isset( $expires[ $plugin_basename ] ) ) {
			return null;
		}

		return (int) $expires[ $plugin_basename ];
	}

	/**
	 * True when an explicit allow has an expiry that has passed.
	 *
	 * @param array<string,mixed> $policy
	 * @param int|null            $now Injectable clock (unix seconds).
	 */
	public static function is_expired( array $policy, string $plugin_basename, ?int $now = null ): bool {
		$now = null === $now ? time() : $now;
		if ( $now <= 0 ) {
			$now = time();
		}
		$ts = self::expires_at( $policy, $plugin_basename );
		if ( null === $ts ) {
			return false;
		}
		$rule = isset( $policy['plugins'][ $plugin_basename ] )
			? (string) $policy['plugins'][ $plugin_basename ]
			: '';
		if ( 'allow' !== $rule ) {
			return false;
		}

		return $ts <= $now;
	}

	/**
	 * Resolve a posted preset (+ optional custom date) into a unix expiry, or null (never).
	 *
	 * @param mixed    $preset
	 * @param mixed    $custom_date Y-m-d when preset is custom.
	 * @param int|null $now
	 */
	public static function resolve_posted_expiry( $preset, $custom_date, ?int $now = null ): ?int {
		$now    = null === $now ? time() : $now;
		$preset = sanitize_key( (string) $preset );
		if ( '' === $preset || 'never' === $preset ) {
			return null;
		}
		if ( '24h' === $preset ) {
			return $now + DAY_IN_SECONDS;
		}
		if ( '7d' === $preset ) {
			return $now + ( 7 * DAY_IN_SECONDS );
		}
		if ( '30d' === $preset ) {
			return $now + ( 30 * DAY_IN_SECONDS );
		}
		if ( 'custom' === $preset ) {
			$date = sanitize_text_field( (string) $custom_date );
			if ( ! preg_match( '/^\d{4}-\d{2}-\d{2}$/', $date ) ) {
				return null;
			}
			// End of selected local day (site timezone when WP is loaded).
			if ( function_exists( 'wp_timezone' ) ) {
				try {
					$dt = new \DateTimeImmutable( $date . ' 23:59:59', wp_timezone() );
					$ts = $dt->getTimestamp();
					return $ts > $now ? $ts : null;
				} catch ( \Exception $e ) {
					return null;
				}
			}
			$ts = strtotime( $date . ' 23:59:59' );
			if ( false === $ts || $ts <= $now ) {
				return null;
			}

			return (int) $ts;
		}

		return null;
	}

	/**
	 * Human remaining / expired label for Rules UI.
	 *
	 * @param array<string,mixed> $policy
	 * @param int|null            $now
	 */
	public static function remaining_label( array $policy, string $plugin_basename, ?int $now = null ): string {
		$now = null === $now ? time() : $now;
		$ts  = self::expires_at( $policy, $plugin_basename );
		if ( null === $ts ) {
			return '';
		}
		if ( $ts <= $now ) {
			return __( 'Expired', 'handl-ai-connector-access-control' );
		}
		$delta = $ts - $now;
		if ( $delta < HOUR_IN_SECONDS ) {
			$mins = max( 1, (int) ceil( $delta / 60 ) );

			return sprintf(
				/* translators: %d: minutes remaining */
				_n( 'Expires in %d minute', 'Expires in %d minutes', $mins, 'handl-ai-connector-access-control' ),
				$mins
			);
		}
		if ( $delta < DAY_IN_SECONDS ) {
			$hours = max( 1, (int) ceil( $delta / HOUR_IN_SECONDS ) );

			return sprintf(
				/* translators: %d: hours remaining */
				_n( 'Expires in %d hour', 'Expires in %d hours', $hours, 'handl-ai-connector-access-control' ),
				$hours
			);
		}
		$days = max( 1, (int) ceil( $delta / DAY_IN_SECONDS ) );

		return sprintf(
			/* translators: %d: days remaining */
			_n( 'Expires in %d day', 'Expires in %d days', $days, 'handl-ai-connector-access-control' ),
			$days
		);
	}

	/**
	 * Preset select value that best matches a stored expiry (for form redisplay).
	 *
	 * @param array<string,mixed> $policy
	 * @param int|null            $now
	 * @return ''|'24h'|'7d'|'30d'|'custom'
	 */
	public static function preset_for_stored( array $policy, string $plugin_basename, ?int $now = null ): string {
		$now = null === $now ? time() : $now;
		$ts  = self::expires_at( $policy, $plugin_basename );
		if ( null === $ts ) {
			return '';
		}
		$delta = $ts - $now;
		// Match within ±90s of common presets (save-time skew).
		foreach ( array(
			'24h' => DAY_IN_SECONDS,
			'7d'  => 7 * DAY_IN_SECONDS,
			'30d' => 30 * DAY_IN_SECONDS,
		) as $key => $seconds ) {
			if ( abs( $delta - $seconds ) <= 90 ) {
				return $key;
			}
		}

		return 'custom';
	}

	/**
	 * Renew an allow rule: set expiry to now + 7d (or extend from future expiry).
	 * Creates/keeps an explicit allow.
	 *
	 * @param array<string,mixed> $policy
	 * @param int|null            $now
	 * @return array<string,mixed>|false
	 */
	public static function renew_allow_on_policy( array $policy, string $plugin_basename, ?int $now = null ) {
		$plugin_basename = sanitize_text_field( $plugin_basename );
		if ( '' === $plugin_basename ) {
			return false;
		}
		$now = null === $now ? time() : $now;
		if ( $now <= 0 ) {
			$now = time();
		}

		$plugins = isset( $policy['plugins'] ) && is_array( $policy['plugins'] )
			? $policy['plugins']
			: array();
		$plugins[ $plugin_basename ] = 'allow';
		$policy['plugins']            = $plugins;

		$expires = self::sanitize_plugin_expires( $policy['plugin_expires'] ?? array() );
		$base    = isset( $expires[ $plugin_basename ] ) ? (int) $expires[ $plugin_basename ] : 0;
		$from    = $base > $now ? $base : $now;
		$expires[ $plugin_basename ] = $from + self::RENEW_SECONDS;
		$policy['plugin_expires']    = $expires;

		return self::normalize_expires_against_plugins( $policy );
	}

	/**
	 * Tidy expired allow rules: remove explicit allow + expiry, audit, email.
	 *
	 * @param array<string,mixed> $policy
	 * @param int|null            $now
	 * @return array{removed:list<string>,policy:array<string,mixed>}
	 */
	public static function sweep_expired( array $policy, ?int $now = null ): array {
		$now = null === $now ? time() : $now;
		if ( $now <= 0 ) {
			$now = time();
		}

		$plugins = isset( $policy['plugins'] ) && is_array( $policy['plugins'] )
			? $policy['plugins']
			: array();
		$expires = self::sanitize_plugin_expires( $policy['plugin_expires'] ?? array() );
		$removed = array();

		foreach ( $expires as $basename => $ts ) {
			$rule = isset( $plugins[ $basename ] ) ? (string) $plugins[ $basename ] : '';
			if ( 'allow' !== $rule ) {
				unset( $expires[ $basename ] );
				continue;
			}
			if ( $ts > $now ) {
				continue;
			}
			unset( $plugins[ $basename ], $expires[ $basename ] );
			$removed[] = $basename;
		}

		$policy['plugins']        = $plugins;
		$policy['plugin_expires'] = $expires;
		$policy                   = self::normalize_expires_against_plugins( $policy );

		if ( ! empty( $removed ) ) {
			Policy::save_policy( $policy );
			foreach ( $removed as $basename ) {
				self::append_expiry_audit( $basename, $now );
				self::maybe_email_expiry( $basename, $policy );
			}
		} else {
			// Still normalize schedule when nothing removed.
			self::maybe_schedule( $policy );
		}

		return array(
			'removed' => $removed,
			'policy'  => $policy,
		);
	}

	/**
	 * @param array<string,mixed> $policy
	 */
	private static function maybe_email_expiry( string $plugin_basename, array $policy ): void {
		// Reuse denial/shadow alert infrastructure — send only when that opt-in is on.
		if ( empty( $policy['alert_on_deny'] ) && empty( $policy['alert_on_shadow'] ) ) {
			return;
		}
		$to = Alerts::resolve_email( $policy );
		if ( '' === $to ) {
			return;
		}

		$site  = function_exists( 'wp_specialchars_decode' )
			? wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES )
			: (string) get_bloginfo( 'name' );
		$label = self::plugin_label( $plugin_basename );
		$default = ( $policy['default'] ?? 'allow' ) === 'deny' ? 'deny' : 'allow';

		$subject = sprintf(
			/* translators: 1: site name, 2: plugin label */
			__( '[%1$s] Temporary AI allow expired: %2$s', 'handl-ai-connector-access-control' ),
			$site,
			$label
		);

		$body  = __( 'HandL AI Connector Access Control — temporary allow expired', 'handl-ai-connector-access-control' ) . "\n\n";
		$body .= sprintf(
			/* translators: %s: plugin display name or basename */
			__( 'Plugin: %s', 'handl-ai-connector-access-control' ),
			$label
		) . "\n";
		$body .= sprintf(
			/* translators: %s: allow or deny */
			__( 'Site default after expiry: %s', 'handl-ai-connector-access-control' ),
			$default
		) . "\n\n";
		$body .= __( 'The temporary Allow rule was removed. The plugin now follows the site default.', 'handl-ai-connector-access-control' ) . "\n\n";
		$body .= __( 'Manage rules:', 'handl-ai-connector-access-control' ) . "\n";
		$body .= admin_url( 'options-general.php?page=handl-ai-connector-access-control&handl_aicac_tab=rules' ) . "\n";

		try {
			// phpcs:ignore WordPress.WP.AlternativeFunctions.wp_mail -- intentional notification path.
			wp_mail( $to, $subject, $body );
		} catch ( \Throwable $e ) {
			// Contained — tidy already persisted.
		}
	}

	private static function append_expiry_audit( string $plugin_basename, int $now ): void {
		Policy::append_log_event(
			array(
				'ts'       => $now,
				'decision' => 'temp_allow_expired',
				'channel'  => 'temp_allow',
				'plugin'   => $plugin_basename,
			)
		);
	}

	private static function plugin_label( string $basename ): string {
		if ( '' === $basename ) {
			return __( '(unknown plugin)', 'handl-ai-connector-access-control' );
		}
		if ( ! function_exists( 'get_plugins' ) ) {
			$plugin_php = ABSPATH . 'wp-admin/includes/plugin.php';
			if ( is_string( $plugin_php ) && is_readable( $plugin_php ) ) {
				require_once $plugin_php;
			}
		}
		if ( function_exists( 'get_plugins' ) ) {
			$plugins = get_plugins();
			if ( isset( $plugins[ $basename ]['Name'] ) && is_string( $plugins[ $basename ]['Name'] ) ) {
				return (string) $plugins[ $basename ]['Name'];
			}
		}

		return $basename;
	}
}
