<?php
/**
 * AICAC-RESCAN-SCHEDULE (#310): weekly change-only re-scan of installed plugins/themes.
 *
 * Runs the #305 bulk scanner. First run after enable stores a silent baseline.
 * Later runs alert only on NEW providers or newly flagged plugins. Never writes rules.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Weekly change-only re-scan scheduler.
 */
final class Rescan_Schedule {

	public const OPTION_KEY = 'handl_aicac_rescan_schedule';

	public const CRON_HOOK = 'handl_aicac_rescan_weekly';

	public const FILTER_DISABLED = 'handl_aicac_rescan_disabled';

	public const DISABLE_CONSTANT = 'HANDL_AICAC_DISABLE_RESCAN';

	public const ALERT_KIND = 'rescan_schedule';

	public const SITE_HEALTH_SLUG = 'handl_aicac_rescan_schedule';

	public const ALERTED_CAP = 200;

	/** @var bool */
	private static $registered = false;

	/** @var int */
	private static $option_reads = 0;

	public static function init(): void {
		if ( self::$registered ) {
			return;
		}
		self::$registered = true;
		add_action( self::CRON_HOOK, array( self::class, 'cron_run' ) );
		add_filter( 'site_status_tests', array( self::class, 'register_site_health' ) );
		self::maybe_schedule();
	}

	public static function reset_for_tests(): void {
		self::$registered    = false;
		self::$option_reads  = 0;
		delete_option( self::OPTION_KEY );
	}

	public static function option_reads(): int {
		return self::$option_reads;
	}

	public static function maybe_schedule(): void {
		if ( self::is_disabled() ) {
			self::clear_schedule();
			return;
		}
		if ( ! function_exists( 'wp_next_scheduled' ) || ! function_exists( 'wp_schedule_event' ) ) {
			return;
		}
		if ( ! wp_next_scheduled( self::CRON_HOOK ) ) {
			wp_schedule_event( time() + WEEK_IN_SECONDS, 'weekly', self::CRON_HOOK );
		}
	}

	public static function clear_schedule(): void {
		if ( function_exists( 'wp_clear_scheduled_hook' ) ) {
			wp_clear_scheduled_hook( self::CRON_HOOK );
		}
	}

	public static function cron_run(): void {
		self::run();
	}

	public static function is_disabled(): bool {
		$constant = defined( self::DISABLE_CONSTANT ) && constant( self::DISABLE_CONSTANT );

		return (bool) apply_filters( self::FILTER_DISABLED, $constant );
	}

	/**
	 * @return array<string,mixed>
	 */
	public static function get_state(): array {
		++self::$option_reads;

		return self::sanitize_state( get_option( self::OPTION_KEY, array() ) );
	}

	/**
	 * @param array<string,mixed> $state
	 */
	public static function put_state( array $state ): void {
		update_option( self::OPTION_KEY, self::sanitize_state( $state ), false );
	}

	/**
	 * @return array{disabled:bool,seeded:bool,alerted:int,new_findings:int,scanned:int,error:string}
	 */
	public static function run( ?int $now = null ): array {
		$now = null !== $now && $now > 0 ? $now : time();
		$out = array(
			'disabled'     => false,
			'seeded'       => false,
			'alerted'      => 0,
			'new_findings' => 0,
			'scanned'      => 0,
			'error'        => '',
		);
		if ( self::is_disabled() ) {
			$out['disabled'] = true;
			$out['error']    = 'disabled';
			return $out;
		}

		$scan           = Preflight_Scan::scan_all( false );
		$out['scanned'] = isset( $scan['scanned'] ) ? (int) $scan['scanned'] : 0;
		$current        = self::findings_from_run( $scan );
		$state          = self::get_state();

		if ( empty( $state['seeded'] ) ) {
			$state['seeded']       = true;
			$state['last_run_at']  = $now;
			$state['new_findings'] = 0;
			$state['summary']      = self::summary_flags( $current );
			$state['alerted']      = array();
			self::put_state( $state );
			$out['seeded'] = true;
			return $out;
		}

		$new = array();
		foreach ( $current as $fid => $row ) {
			if ( isset( $state['summary'][ $fid ] ) ) {
				continue;
			}
			$new[ $fid ] = $row;
		}

		if ( empty( $new ) ) {
			$state['last_run_at']  = $now;
			$state['new_findings'] = 0;
			self::put_state( $state );
			$out['seeded'] = true;
			return $out;
		}

		$policy = Policy::get_policy();
		foreach ( $new as $fid => $row ) {
			if ( isset( $state['alerted'][ $fid ] ) ) {
				$state['summary'][ $fid ] = 1;
				continue;
			}
			self::fire_alert( $policy, $row, $now, $fid );
			$state['alerted'][ $fid ] = $now;
			$state['summary'][ $fid ] = 1;
			++$out['alerted'];
		}

		$state['alerted']      = self::cap_alerted( $state['alerted'] );
		$state['last_run_at']  = $now;
		$state['new_findings'] = $out['alerted'];
		$state['seeded']       = true;
		self::put_state( $state );
		$out['seeded']       = true;
		$out['new_findings'] = $out['alerted'];

		return $out;
	}

	/**
	 * @return array<string,mixed>
	 */
	public static function status(): array {
		if ( self::is_disabled() ) {
			return array(
				'disabled'     => true,
				'seeded'       => false,
				'last_run_at'  => 0,
				'new_findings' => 0,
				'scheduled'    => false,
			);
		}
		$state = self::get_state();
		$next  = function_exists( 'wp_next_scheduled' ) ? wp_next_scheduled( self::CRON_HOOK ) : false;

		return array(
			'disabled'     => false,
			'seeded'       => ! empty( $state['seeded'] ),
			'last_run_at'  => (int) $state['last_run_at'],
			'new_findings' => (int) $state['new_findings'],
			'scheduled'    => false !== $next && (int) $next > 0,
		);
	}

	/**
	 * @param mixed $raw
	 * @return array<string,mixed>
	 */
	public static function sanitize_state( $raw ): array {
		if ( ! is_array( $raw ) ) {
			$raw = array();
		}
		$summary = array();
		if ( isset( $raw['summary'] ) && is_array( $raw['summary'] ) ) {
			foreach ( $raw['summary'] as $id => $_flag ) {
				$id = sanitize_text_field( (string) $id );
				if ( '' !== $id ) {
					$summary[ $id ] = 1;
				}
			}
		}
		ksort( $summary );
		$alerted = array();
		if ( isset( $raw['alerted'] ) && is_array( $raw['alerted'] ) ) {
			foreach ( $raw['alerted'] as $id => $ts ) {
				$id = sanitize_text_field( (string) $id );
				$ts = (int) $ts;
				if ( '' === $id || $ts <= 0 ) {
					continue;
				}
				$alerted[ $id ] = $ts;
			}
		}
		ksort( $alerted );

		return array(
			'seeded'       => ! empty( $raw['seeded'] ),
			'last_run_at'  => max( 0, (int) ( $raw['last_run_at'] ?? 0 ) ),
			'new_findings' => max( 0, (int) ( $raw['new_findings'] ?? 0 ) ),
			'summary'      => $summary,
			'alerted'      => $alerted,
		);
	}

	/**
	 * @param array<string,mixed> $tests
	 * @return array<string,mixed>
	 */
	public static function register_site_health( array $tests ): array {
		if ( ! isset( $tests['direct'] ) || ! is_array( $tests['direct'] ) ) {
			$tests['direct'] = array();
		}
		$tests['direct'][ self::SITE_HEALTH_SLUG ] = array(
			'label' => __( 'Weekly AI plugin re-scan', 'handl-ai-connector-access-control' ),
			'test'  => array( self::class, 'run_site_health' ),
		);

		return $tests;
	}

	/**
	 * @return array<string,mixed>
	 */
	public static function run_site_health(): array {
		return self::format_site_health_result( self::site_health_snapshot() );
	}

	/**
	 * @return array{disabled:bool,seeded:bool,last_run_at:int,new_findings:int}
	 */
	public static function site_health_snapshot(): array {
		if ( self::is_disabled() ) {
			return array(
				'disabled'     => true,
				'seeded'       => false,
				'last_run_at'  => 0,
				'new_findings' => 0,
			);
		}
		$state = self::get_state();

		return array(
			'disabled'     => false,
			'seeded'       => ! empty( $state['seeded'] ),
			'last_run_at'  => (int) $state['last_run_at'],
			'new_findings' => (int) $state['new_findings'],
		);
	}

	/**
	 * @param array{disabled:bool,seeded:bool,last_run_at:int,new_findings:int} $snap
	 * @return array<string,mixed>
	 */
	public static function format_site_health_result( array $snap ): array {
		$line = self::site_health_line( $snap );

		return array(
			'label'       => __( 'Weekly AI plugin re-scan', 'handl-ai-connector-access-control' ),
			'status'      => 'good',
			'badge'       => array(
				'label' => __( 'Security', 'handl-ai-connector-access-control' ),
				'color' => 'blue',
			),
			'description' => '<p>' . esc_html( $line ) . '</p>',
			'actions'     => '',
			'test'        => self::SITE_HEALTH_SLUG,
		);
	}

	/**
	 * @param array{disabled?:bool,seeded?:bool,last_run_at?:int,new_findings?:int} $snap
	 */
	public static function site_health_line( array $snap ): string {
		if ( ! empty( $snap['disabled'] ) ) {
			return __( 'Weekly plugin re-scan is turned off.', 'handl-ai-connector-access-control' );
		}
		$when = (int) ( $snap['last_run_at'] ?? 0 );
		$n    = (int) ( $snap['new_findings'] ?? 0 );
		$when_label = $when > 0
			? gmdate( 'Y-m-d H:i:s', $when ) . ' UTC'
			: __( 'never', 'handl-ai-connector-access-control' );

		return sprintf(
			/* translators: 1: last scan timestamp or "never", 2: new-finding count */
			_n( 'Last scan: %1$s. %2$d new finding.', 'Last scan: %1$s. %2$d new findings.', $n, 'handl-ai-connector-access-control' ),
			$when_label,
			$n
		);
	}

	public static function finding_id( string $kind, string $id, string $provider ): string {
		$kind     = sanitize_key( $kind );
		$provider = sanitize_key( $provider );
		if ( 'plugin' === $kind ) {
			$id = Plugin_Profile::sanitize_plugin( $id );
		} else {
			$id = sanitize_key( $id );
		}
		if ( '' === $kind || '' === $id || '' === $provider ) {
			return '';
		}

		return $kind . ':' . $id . ':' . $provider;
	}

	/**
	 * @param array<string,mixed> $run
	 * @return array<string,array<string,string>>
	 */
	public static function findings_from_run( array $run ): array {
		$out  = array();
		$hits = isset( $run['hits'] ) && is_array( $run['hits'] ) ? $run['hits'] : array();
		foreach ( $hits as $hit ) {
			if ( ! is_array( $hit ) ) {
				continue;
			}
			$kind      = isset( $hit['kind'] ) ? (string) $hit['kind'] : 'plugin';
			$id        = isset( $hit['id'] ) ? (string) $hit['id'] : '';
			$label     = isset( $hit['label'] ) ? (string) $hit['label'] : $id;
			$providers = isset( $hit['providers'] ) && is_array( $hit['providers'] )
				? array_map( 'strval', $hit['providers'] )
				: array();
			foreach ( $providers as $provider ) {
				$fid = self::finding_id( $kind, $id, $provider );
				if ( '' === $fid ) {
					continue;
				}
				$out[ $fid ] = array(
					'kind'     => $kind,
					'id'       => $id,
					'provider' => $provider,
					'label'    => $label,
				);
			}
		}
		ksort( $out );

		return $out;
	}

	public static function build_subject( string $label ): string {
		$site = function_exists( 'get_bloginfo' )
			? wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES )
			: 'WordPress';

		return sprintf(
			/* translators: 1: site name, 2: plugin or theme name */
			__( '[%1$s] HandL: New AI provider reference (%2$s)', 'handl-ai-connector-access-control' ),
			$site,
			$label
		);
	}

	/**
	 * @param array<string,string> $row
	 */
	public static function build_body( array $row ): string {
		$label    = isset( $row['label'] ) && '' !== (string) $row['label'] ? (string) $row['label'] : (string) ( $row['id'] ?? '' );
		$provider = Provider_Map::signature_label( (string) ( $row['provider'] ?? '' ) );
		if ( '' === $provider ) {
			$provider = (string) ( $row['provider'] ?? '' );
		}
		$lines   = array();
		$lines[] = __( 'HandL AI Connector Access Control: a weekly re-scan listed a new AI provider reference.', 'handl-ai-connector-access-control' );
		$lines[] = '';
		$lines[] = sprintf(
			/* translators: %s: plugin or theme name */
			__( 'Plugin or theme: %s', 'handl-ai-connector-access-control' ),
			$label
		);
		$lines[] = sprintf(
			/* translators: %s: provider name */
			__( 'Provider: %s', 'handl-ai-connector-access-control' ),
			$provider
		);
		$lines[] = '';
		$lines[] = __( 'This scan does not change rules and does not confirm that data was sent.', 'handl-ai-connector-access-control' );

		return implode( "\n", $lines );
	}

	/**
	 * @param array<string,array<string,string>> $current
	 * @return array<string,int>
	 */
	private static function summary_flags( array $current ): array {
		$out = array();
		foreach ( array_keys( $current ) as $fid ) {
			$out[ $fid ] = 1;
		}
		ksort( $out );

		return $out;
	}

	/**
	 * @param array<string,int> $alerted
	 * @return array<string,int>
	 */
	private static function cap_alerted( array $alerted ): array {
		if ( count( $alerted ) <= self::ALERTED_CAP ) {
			ksort( $alerted );
			return $alerted;
		}
		asort( $alerted );
		$alerted = array_slice( $alerted, -1 * self::ALERTED_CAP, null, true );
		ksort( $alerted );

		return $alerted;
	}

	/**
	 * @param array<string,mixed>  $policy
	 * @param array<string,string> $row
	 */
	private static function fire_alert( array $policy, array $row, int $now, string $fid ): void {
		$plugin = (string) ( $row['id'] ?? '' );
		$label  = isset( $row['label'] ) && '' !== (string) $row['label'] ? (string) $row['label'] : $plugin;
		$to     = Alert_Routing::resolve_email( $policy, '' );
		if ( '' !== $to ) {
			Alerts::safe_wp_mail(
				$to,
				self::build_subject( $label ),
				self::build_body( $row )
			);
		}

		$hook_url = Alerts::resolve_webhook( $policy );
		if ( '' !== $hook_url ) {
			Alerts::safe_wp_remote_post(
				$hook_url,
				array(
					'type'        => 'handl_aicac_rescan_alert',
					'finding_id'  => $fid,
					'plugin'      => $plugin,
					'provider'    => (string) ( $row['provider'] ?? '' ),
					'site'        => function_exists( 'home_url' ) ? home_url( '/' ) : '',
				),
				self::ALERT_KIND
			);
		}

		Policy::append_log_event(
			array(
				'ts'            => $now,
				'decision'      => 'observe',
				'channel'       => self::ALERT_KIND,
				'plugin'        => $plugin,
				'denial_reason' => 'rescan_schedule',
				'operation'     => 'rescan_schedule',
				'finding_id'    => $fid,
				'providers'     => array( (string) ( $row['provider'] ?? '' ) ),
				'user_id'       => function_exists( 'get_current_user_id' ) ? get_current_user_id() : 0,
			)
		);
	}
}
