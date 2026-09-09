<?php
/**
 * AICAC-WENT-AI: one-time alert when a plugin that never used AI starts (#207).
 *
 * Distinct from review-first (new install) and drift (provider/model change).
 * Tracks first_ai_call_at per plugin. Observability only — never allow/deny.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * First-ever AI Client call per plugin: stamp + one email/webhook.
 */
final class Went_AI {

	/** @var string plugin => { ts, version, provider, model, context } */
	public const STAMP_OPTION_KEY = 'handl_aicac_first_ai_call_at';

	public const WINDOW_SECONDS = 2592000; // 30 days.

	/**
	 * @param mixed $raw
	 * @return array<string,array{ts:int,version:string,provider:string,model:string,context:string}>
	 */
	public static function sanitize_stamps( $raw ): array {
		if ( ! is_array( $raw ) ) {
			return array();
		}
		$out = array();
		foreach ( $raw as $plugin => $row ) {
			$plugin = Plugin_Profile::sanitize_plugin( (string) $plugin );
			if ( '' === $plugin || ! is_array( $row ) ) {
				continue;
			}
			$ts = isset( $row['ts'] ) ? (int) $row['ts'] : 0;
			if ( $ts <= 0 ) {
				continue;
			}
			$out[ $plugin ] = array(
				'ts'       => $ts,
				'version'  => sanitize_text_field( (string) ( $row['version'] ?? '' ) ),
				'provider' => sanitize_text_field( (string) ( $row['provider'] ?? '' ) ),
				'model'    => sanitize_text_field( (string) ( $row['model'] ?? '' ) ),
				'context'  => sanitize_key( (string) ( $row['context'] ?? '' ) ),
			);
		}

		return $out;
	}

	/**
	 * @return array<string,array{ts:int,version:string,provider:string,model:string,context:string}>
	 */
	public static function get_stamps(): array {
		return self::sanitize_stamps( get_option( self::STAMP_OPTION_KEY, array() ) );
	}

	/**
	 * @param array<string,array{ts:int,version:string,provider:string,model:string,context:string}> $map
	 */
	public static function save_stamps( array $map ): void {
		$map = self::sanitize_stamps( $map );
		if ( empty( $map ) ) {
			delete_option( self::STAMP_OPTION_KEY );
			return;
		}
		update_option( self::STAMP_OPTION_KEY, $map, false );
	}

	/**
	 * Plugins whose first AI call was at or after $since_ts.
	 *
	 * @return list<string>
	 */
	public static function plugins_started_since( int $since_ts ): array {
		$out = array();
		foreach ( self::get_stamps() as $plugin => $row ) {
			if ( (int) $row['ts'] >= $since_ts ) {
				$out[] = $plugin;
			}
		}
		sort( $out );

		return $out;
	}

	/**
	 * @param array<string,mixed> $event  Log row (may be mutated).
	 * @param array<string,mixed> $policy Current policy.
	 * @return array{tagged:bool,alerted:bool,reason:string}
	 */
	public static function observe( array &$event, array $policy ): array {
		$empty = array(
			'tagged'  => false,
			'alerted' => false,
			'reason'  => '',
		);

		$channel = isset( $event['channel'] ) ? (string) $event['channel'] : '';
		if ( in_array( $channel, array( 'direct_http', 'anomaly', 'spend_threshold', 'drift', 'alert_snooze', 'budget', 'went_ai', 'temp_allow' ), true ) ) {
			$empty['reason'] = 'skip_channel';
			return $empty;
		}

		$plugin = isset( $event['plugin'] ) ? Plugin_Profile::sanitize_plugin( (string) $event['plugin'] ) : '';
		if ( '' === $plugin || ( class_exists( Analytics::class ) && Analytics::UNKNOWN_KEY === $plugin ) ) {
			$empty['reason'] = 'no_plugin';
			return $empty;
		}

		$map = self::get_stamps();
		if ( isset( $map[ $plugin ] ) ) {
			$empty['reason'] = 'known';
			return $empty;
		}

		$ts = isset( $event['ts'] ) ? (int) $event['ts'] : Clock::now();
		if ( $ts <= 0 ) {
			$ts = Clock::now();
		}

		$provider = isset( $event['provider'] ) ? sanitize_text_field( (string) $event['provider'] ) : '';
		$model    = isset( $event['model'] ) ? sanitize_text_field( (string) $event['model'] ) : '';
		if ( '' === $model && isset( $event['model_id'] ) ) {
			$model = sanitize_text_field( (string) $event['model_id'] );
		}
		if ( '' === $provider && '' === $model ) {
			$empty['reason'] = 'no_pair';
			return $empty;
		}
		$context = self::event_context( $event );
		$version = self::plugin_version( $plugin );
		$prior   = self::last_activity_version( $plugin );

		$map[ $plugin ] = array(
			'ts'       => $ts,
			'version'  => $version,
			'provider' => $provider,
			'model'    => $model,
			'context'  => $context,
		);
		self::save_stamps( $map );

		$event['went_ai_first'] = true;

		if ( in_array( $plugin, New_Plugin::pending_plugins( $policy ), true ) ) {
			return array(
				'tagged'  => true,
				'alerted' => false,
				'reason'  => 'new_plugin',
			);
		}

		if ( null !== Quiet_Hours::active_window( $policy, $ts ) ) {
			return array(
				'tagged'  => true,
				'alerted' => false,
				'reason'  => 'quiet_hours',
			);
		}

		if ( Alert_Snooze::should_suppress( $plugin, 'went_ai', $ts ) ) {
			return array(
				'tagged'  => true,
				'alerted' => false,
				'reason'  => 'suppressed',
			);
		}

		$fired = self::maybe_fire( $policy, $plugin, $version, $prior, $provider, $model, $context, $ts );

		return array(
			'tagged'  => true,
			'alerted' => $fired,
			'reason'  => $fired ? 'alerted' : 'no_recipient',
		);
	}

	/**
	 * @param array<string,mixed> $event
	 */
	public static function event_context( array $event ): string {
		if ( isset( $event['context'] ) && is_string( $event['context'] ) && '' !== $event['context'] ) {
			return sanitize_key( $event['context'] );
		}
		if ( function_exists( 'wp_doing_cron' ) && wp_doing_cron() ) {
			return 'cron';
		}
		if ( function_exists( 'is_admin' ) && is_admin() ) {
			return 'admin';
		}

		return 'frontend';
	}

	public static function plugin_version( string $basename ): string {
		if ( function_exists( 'get_plugins' ) ) {
			$plugins = get_plugins();
			if ( isset( $plugins[ $basename ]['Version'] ) ) {
				return sanitize_text_field( (string) $plugins[ $basename ]['Version'] );
			}
		}

		return '';
	}

	/**
	 * Version from the latest Activity row for this plugin, if stored.
	 */
	public static function last_activity_version( string $plugin ): string {
		$log = get_option( Plugin::LOG_OPTION_KEY, array() );
		if ( ! is_array( $log ) ) {
			return '';
		}
		$last = '';
		foreach ( $log as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$row_plugin = isset( $row['plugin'] ) ? Plugin_Profile::sanitize_plugin( (string) $row['plugin'] ) : '';
			if ( $row_plugin !== $plugin ) {
				continue;
			}
			if ( isset( $row['plugin_version'] ) && is_scalar( $row['plugin_version'] ) ) {
				$last = sanitize_text_field( (string) $row['plugin_version'] );
			}
		}

		return $last;
	}

	/**
	 * @param array<string,mixed> $policy
	 */
	private static function maybe_fire(
		array $policy,
		string $plugin,
		string $version,
		string $prior_version,
		string $provider,
		string $model,
		string $context,
		int $now
	): bool {
		$to = Alerts::resolve_email( $policy );
		if ( '' === $to ) {
			return false;
		}

		$subject = self::build_subject( $plugin );
		$body    = self::build_body( $plugin, $version, $prior_version, $provider, $model, $context );
		$ok      = Alerts::safe_wp_mail( $to, $subject, $body );

		$hook_url = Alerts::resolve_webhook( $policy );
		if ( '' !== $hook_url ) {
			Alerts::safe_wp_remote_post(
				$hook_url,
				array(
					'type'          => 'handl_aicac_went_ai_alert',
					'plugin'        => $plugin,
					'version'       => $version,
					'prior_version' => $prior_version,
					'provider'      => $provider,
					'model'         => $model,
					'context'       => $context,
					'site'          => function_exists( 'home_url' ) ? home_url( '/' ) : '',
				)
			);
		}

		return $ok;
	}

	public static function build_subject( string $plugin ): string {
		$site  = function_exists( 'get_bloginfo' )
			? wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES )
			: 'WordPress';
		$label = self::plugin_label( $plugin );

		return sprintf(
			/* translators: 1: site name, 2: plugin name */
			__( '[%1$s] HandL: %2$s started using AI', 'handl-ai-connector-access-control' ),
			$site,
			$label
		);
	}

	public static function build_body(
		string $plugin,
		string $version,
		string $prior_version,
		string $provider,
		string $model,
		string $context
	): string {
		$lines   = array();
		$lines[] = __( 'HandL AI Connector Access Control — first AI use', 'handl-ai-connector-access-control' );
		$lines[] = '';
		$lines[] = sprintf(
			/* translators: %s: plugin display name or basename */
			__( 'Plugin: %s', 'handl-ai-connector-access-control' ),
			self::plugin_label( $plugin )
		);
		if ( '' !== $version || '' !== $prior_version ) {
			$lines[] = sprintf(
				/* translators: 1: current plugin version, 2: version from last Activity row or "none" */
				__( 'Version now: %1$s. Version at last Activity: %2$s.', 'handl-ai-connector-access-control' ),
				'' !== $version ? $version : __( 'unknown', 'handl-ai-connector-access-control' ),
				'' !== $prior_version ? $prior_version : __( 'none', 'handl-ai-connector-access-control' )
			);
		}
		$pair = trim( $provider . ( '' !== $model ? ' / ' . $model : '' ) );
		if ( '' !== $pair ) {
			$lines[] = sprintf(
				/* translators: %s: provider / model */
				__( 'Provider: %s', 'handl-ai-connector-access-control' ),
				$pair
			);
		}
		if ( '' !== $context ) {
			$lines[] = sprintf(
				/* translators: %s: frontend, admin, or cron */
				__( 'Context: %s', 'handl-ai-connector-access-control' ),
				$context
			);
		}
		$lines[] = '';
		$lines[] = __( 'This plugin had no earlier AI Client calls. This alert is sent once. It does not change Allow or Deny rules.', 'handl-ai-connector-access-control' );
		$lines[] = '';
		$lines[] = __( 'View this plugin’s activity:', 'handl-ai-connector-access-control' );
		$lines[] = Admin::screen_url( 'activity', array(
					'handl_aicac_plugin' => $plugin,
				) );

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
