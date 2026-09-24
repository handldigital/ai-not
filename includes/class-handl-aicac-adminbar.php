<?php
/**
 * AICAC-ADMINBAR (#280): live protection badge on the WP admin bar.
 *
 * Reads existing recent-calls, retry-storm state, and freeze state. No new
 * storage. Options are read only from admin_bar_menu — init registers hooks.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Always-on admin-bar badge for users who can view Activity.
 */
final class Adminbar {

	public const NODE_ID = 'handl-aicac-adminbar';

	public const POLICY_KEY = 'adminbar_enabled';

	public const POST_PRESENT = 'handl_aicac_adminbar_present';

	public const POST_ENABLED = 'handl_aicac_adminbar_enabled';

	/** @var list<string> */
	private const SKIP_CHANNELS = array(
		'direct_http',
		'spend_threshold',
		'budget',
		'drift',
		'alert_snooze',
		'anomaly',
		'forecast_warn',
		'rate_warn',
		'selftest',
		'share',
		'policy_restore',
		'access_request',
		'policy_checks',
		'policy_save',
		'policy_import',
		'email',
		'temp_allow',
		'went_ai',
		'canary',
		'tamper',
		'hardened_guard',
	);

	private static ?Adminbar $instance = null;

	public static function instance(): Adminbar {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}

		return self::$instance;
	}

	/**
	 * Hook only. No option reads — admin_bar_menu is the first I/O.
	 */
	public function init(): void {
		add_action( 'admin_bar_menu', array( $this, 'populate' ), 80 );
		add_action( 'handl_aicac_protections_settings', array( $this, 'render_settings' ) );
		add_filter( 'pre_update_option_' . Plugin::OPTION_KEY, array( self::class, 'merge_enabled_on_policy_save' ), 10, 2 );
	}

	/**
	 * Default ON when the policy key is absent.
	 *
	 * @param array<string,mixed> $policy
	 */
	public static function is_enabled( array $policy ): bool {
		if ( ! array_key_exists( self::POLICY_KEY, $policy ) ) {
			return true;
		}

		return ! empty( $policy[ self::POLICY_KEY ] );
	}

	/**
	 * @param mixed $value New option value.
	 * @param mixed $old   Previous option value.
	 * @return mixed
	 */
	public static function merge_enabled_on_policy_save( $value, $old ) {
		if ( ! is_array( $value ) ) {
			return $value;
		}

		$posted = isset( $_POST[ self::POST_PRESENT ] ); // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Admin save already verified the form nonce.
		if ( $posted ) {
			$value[ self::POLICY_KEY ] = ! empty( $_POST[ self::POST_ENABLED ] ); // phpcs:ignore WordPress.Security.NonceVerification.Missing

			return $value;
		}

		if ( is_array( $old ) && array_key_exists( self::POLICY_KEY, $old ) ) {
			$value[ self::POLICY_KEY ] = ! empty( $old[ self::POLICY_KEY ] );
		}

		return $value;
	}

	/**
	 * Protections off-switch. Lives inside the existing save form.
	 *
	 * @param array<string,mixed> $policy
	 */
	public function render_settings( $policy ): void {
		$policy  = is_array( $policy ) ? $policy : array();
		$enabled = self::is_enabled( $policy );

		echo '<tr>';
		echo '<th scope="row">' . esc_html__( 'Admin bar badge', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<td>';
		echo '<input type="hidden" name="' . esc_attr( self::POST_PRESENT ) . '" value="1" />';
		echo '<label for="handl-aicac-adminbar-enabled">';
		echo '<input type="checkbox" name="' . esc_attr( self::POST_ENABLED ) . '" id="handl-aicac-adminbar-enabled" value="1"' . ( $enabled ? ' checked="checked"' : '' ) . ' /> ';
		echo esc_html__( 'Show a protection badge in the admin bar', 'handl-ai-connector-access-control' );
		echo '</label>';
		echo '<p class="description">' . esc_html__( 'Shows blocked AI calls from today. Turns red during a retry storm or panic freeze.', 'handl-ai-connector-access-control' ) . '</p>';
		echo '</td>';
		echo '</tr>';
	}

	/**
	 * @param object $wp_admin_bar WP_Admin_Bar (or test double with add_node()).
	 */
	public function populate( $wp_admin_bar ): void {
		if ( ! is_object( $wp_admin_bar ) || ! method_exists( $wp_admin_bar, 'add_node' ) ) {
			return;
		}
		if ( ! Caps::user_can_view() ) {
			return;
		}

		$policy = class_exists( Policy::class ) ? Policy::get_policy() : array();
		if ( ! self::is_enabled( $policy ) ) {
			return;
		}

		$now  = class_exists( Clock::class ) ? Clock::now() : time();
		$log  = get_option( Plugin::LOG_OPTION_KEY, array() );
		$log  = is_array( $log ) ? $log : array();
		$snap = self::build_snapshot(
			$policy,
			$log,
			self::read_storm_state(),
			self::read_freeze_active( $now ),
			$now
		);

		self::add_nodes( $wp_admin_bar, $snap );
	}

	/**
	 * Pure snapshot for tests. No option I/O.
	 *
	 * @param array<string,mixed>              $policy
	 * @param array<int,mixed>                 $log
	 * @param array<string,mixed>              $storm_state Retry_Storm::get_state() shape.
	 * @return array{
	 *   state:string,
	 *   deny_count:int,
	 *   badge:string,
	 *   denies:list<array{plugin:string,label:string,ts:int,when:string}>,
	 *   activity_url:string,
	 *   protections_url:string,
	 *   freeze_url:string
	 * }
	 */
	public static function build_snapshot( array $policy, array $log, array $storm_state, bool $freeze_active, int $now ): array {
		$day_start = self::today_start( $now );
		$denies    = array();
		$count     = 0;

		foreach ( $log as $row ) {
			if ( ! is_array( $row ) || ! self::is_today_deny( $row, $day_start ) ) {
				continue;
			}
			$count += self::deny_attempts( $row );
			$plugin = isset( $row['plugin'] ) ? Plugin_Profile::sanitize_plugin( (string) $row['plugin'] ) : '';
			$ts     = isset( $row['ts'] ) ? (int) $row['ts'] : 0;
			$denies[] = array(
				'plugin' => $plugin,
				'label'  => self::plugin_label( $plugin ),
				'ts'     => $ts,
				'when'   => self::time_label( $ts, $now ),
			);
		}

		usort(
			$denies,
			static function ( array $a, array $b ): int {
				return $b['ts'] <=> $a['ts'];
			}
		);
		$denies = array_slice( $denies, 0, 3 );

		$storm = self::storm_is_live( $policy, $storm_state, $now );
		$state = 'normal';
		if ( $freeze_active ) {
			$state = 'freeze';
		} elseif ( $storm ) {
			$state = 'storm';
		}

		$badge = sprintf(
			/* translators: %d: blocked AI Client calls today */
			_n( 'AI Access · %d blocked today', 'AI Access · %d blocked today', $count, 'handl-ai-connector-access-control' ),
			$count
		);

		$protections = class_exists( Admin::class ) ? Admin::screen_url( 'protections' ) : '';

		return array(
			'state'           => $state,
			'deny_count'      => $count,
			'badge'           => $badge,
			'denies'          => $denies,
			'activity_url'    => class_exists( Admin::class ) ? Admin::screen_url( 'activity' ) : '',
			'protections_url' => $protections,
			'freeze_url'      => $protections,
		);
	}

	/**
	 * @param object              $wp_admin_bar
	 * @param array<string,mixed> $snap
	 */
	public static function add_nodes( $wp_admin_bar, array $snap ): void {
		$badge = isset( $snap['badge'] ) ? (string) $snap['badge'] : '';
		$state = isset( $snap['state'] ) ? (string) $snap['state'] : 'normal';
		$title = esc_html( $badge );
		if ( 'normal' !== $state ) {
			$title = '<span style="color:#d63638">' . $title . '</span>';
		}

		$wp_admin_bar->add_node(
			array(
				'id'    => self::NODE_ID,
				'title' => $title,
				'href'  => isset( $snap['activity_url'] ) ? (string) $snap['activity_url'] : '',
				'meta'  => array(
					'class' => 'handl-aicac-adminbar handl-aicac-adminbar--' . sanitize_key( $state ),
				),
			)
		);

		$denies = isset( $snap['denies'] ) && is_array( $snap['denies'] ) ? $snap['denies'] : array();
		$i      = 0;
		foreach ( $denies as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$label = isset( $row['label'] ) ? (string) $row['label'] : '';
			$when  = isset( $row['when'] ) ? (string) $row['when'] : '';
			$line  = $label;
			if ( '' !== $when ) {
				$line = '' !== $label ? $label . ' · ' . $when : $when;
			}
			$href  = '';
			if ( isset( $row['plugin'] ) && is_string( $row['plugin'] ) && '' !== $row['plugin'] && class_exists( Plugin_Profile::class ) ) {
				$href = Plugin_Profile::activity_url( $row['plugin'] );
			}
			$wp_admin_bar->add_node(
				array(
					'id'     => self::NODE_ID . '-deny-' . $i,
					'parent' => self::NODE_ID,
					'title'  => esc_html( $line ),
					'href'   => $href,
				)
			);
			++$i;
		}

		$wp_admin_bar->add_node(
			array(
				'id'     => self::NODE_ID . '-activity',
				'parent' => self::NODE_ID,
				'title'  => esc_html__( 'Activity', 'handl-ai-connector-access-control' ),
				'href'   => isset( $snap['activity_url'] ) ? (string) $snap['activity_url'] : '',
			)
		);
		$wp_admin_bar->add_node(
			array(
				'id'     => self::NODE_ID . '-protections',
				'parent' => self::NODE_ID,
				'title'  => esc_html__( 'Protections', 'handl-ai-connector-access-control' ),
				'href'   => isset( $snap['protections_url'] ) ? (string) $snap['protections_url'] : '',
			)
		);
		$wp_admin_bar->add_node(
			array(
				'id'     => self::NODE_ID . '-freeze',
				'parent' => self::NODE_ID,
				'title'  => esc_html__( 'Panic freeze', 'handl-ai-connector-access-control' ),
				'href'   => isset( $snap['freeze_url'] ) ? (string) $snap['freeze_url'] : '',
			)
		);
	}

	/**
	 * @param array<string,mixed> $row
	 */
	public static function is_today_deny( array $row, int $day_start ): bool {
		if ( 'deny' !== (string) ( $row['decision'] ?? '' ) ) {
			return false;
		}
		$ts = isset( $row['ts'] ) ? (int) $row['ts'] : 0;
		if ( $ts < $day_start ) {
			return false;
		}
		if ( class_exists( Selftest::class ) && Selftest::is_synthetic_row( $row ) ) {
			return false;
		}
		if ( ! empty( $row['share_action'] ) ) {
			return false;
		}
		$channel = isset( $row['channel'] ) ? (string) $row['channel'] : '';
		if ( in_array( $channel, self::SKIP_CHANNELS, true ) ) {
			return false;
		}
		if ( class_exists( Usage_Trends::class ) && ! Usage_Trends::is_activity_row( $row ) ) {
			return false;
		}

		return true;
	}

	/**
	 * @param array<string,mixed> $row
	 */
	public static function deny_attempts( array $row ): int {
		if ( class_exists( Retry_Storm::class ) && ! empty( $row['retry_storm'] ) ) {
			$n = Retry_Storm::storm_count_from_row( $row );

			return $n > 0 ? $n : 1;
		}
		$n = isset( $row['count'] ) ? (int) $row['count'] : 1;

		return $n > 0 ? $n : 1;
	}

	public static function today_start( int $now ): int {
		$day = defined( 'DAY_IN_SECONDS' ) ? (int) DAY_IN_SECONDS : 86400;

		return $now - ( $now % $day );
	}

	/**
	 * @param array<string,mixed> $policy
	 * @param array<string,mixed> $storm_state
	 */
	public static function storm_is_live( array $policy, array $storm_state, int $now ): bool {
		$window  = class_exists( Retry_Storm::class )
			? Retry_Storm::sanitize_window_seconds( $policy['retry_storm_window_seconds'] ?? Retry_Storm::DEFAULT_WINDOW_SECONDS )
			: 30;
		$buckets = isset( $storm_state['buckets'] ) && is_array( $storm_state['buckets'] ) ? $storm_state['buckets'] : array();
		foreach ( $buckets as $bucket ) {
			if ( ! is_array( $bucket ) || empty( $bucket['storm'] ) ) {
				continue;
			}
			$start = isset( $bucket['window_start'] ) ? (int) $bucket['window_start'] : 0;
			if ( $start > 0 && ( $now - $start ) <= $window ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * @return array{buckets:array<string,array<string,mixed>>,alerts:array<string,int>}
	 */
	private static function read_storm_state(): array {
		if ( class_exists( Retry_Storm::class ) ) {
			return Retry_Storm::get_state();
		}

		return array(
			'buckets' => array(),
			'alerts'  => array(),
		);
	}

	/**
	 * Read-only freeze check — does not close an expired window.
	 */
	private static function read_freeze_active( int $now ): bool {
		if ( ! class_exists( Freeze::class ) ) {
			return false;
		}
		$state = Freeze::get_state();
		if ( empty( $state['active'] ) ) {
			return false;
		}

		return $now < (int) ( $state['expires_ts'] ?? 0 );
	}

	private static function plugin_label( string $plugin ): string {
		if ( '' === $plugin ) {
			return __( 'Unknown plugin', 'handl-ai-connector-access-control' );
		}
		$slash = strrpos( $plugin, '/' );
		if ( false === $slash ) {
			return $plugin;
		}
		$dir = substr( $plugin, 0, $slash );

		return '' !== $dir ? $dir : $plugin;
	}

	private static function time_label( int $ts, int $now ): string {
		if ( $ts <= 0 ) {
			return '';
		}
		$delta = $now - $ts;
		if ( $delta < 0 ) {
			$delta = 0;
		}
		if ( $delta < 60 ) {
			return __( 'just now', 'handl-ai-connector-access-control' );
		}
		if ( $delta < 3600 ) {
			$mins = (int) floor( $delta / 60 );

			return sprintf(
				/* translators: %d: minutes */
				_n( '%d min ago', '%d min ago', $mins, 'handl-ai-connector-access-control' ),
				$mins
			);
		}
		if ( $delta < 86400 ) {
			$hours = (int) floor( $delta / 3600 );

			return sprintf(
				/* translators: %d: hours */
				_n( '%d hour ago', '%d hours ago', $hours, 'handl-ai-connector-access-control' ),
				$hours
			);
		}

		return gmdate( 'Y-m-d', $ts );
	}
}
