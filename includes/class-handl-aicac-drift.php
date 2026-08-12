<?php
/**
 * AICAC-DRIFT: alert when a plugin's AI provider or model changes (#157).
 *
 * Tracks per-plugin last-seen provider+model pairs from the activity log.
 * First activity for a plugin is baseline (no alert). A genuinely new pair
 * alerts once via the existing alert email/webhook paths and respects snooze.
 *
 * Observability only — never changes allow/deny.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Provider/model drift detection + opt-in alerts.
 */
final class Drift {

	/** Per-plugin seen pairs: plugin => [ "provider|model" => first_ts, ... ]. */
	public const SEEN_OPTION_KEY = 'handl_aicac_drift_seen';

	/** Recent drift alert rows for Dashboard (capped). */
	public const RECENT_OPTION_KEY = 'handl_aicac_drift_recent';

	public const RECENT_MAX = 20;

	/** Modes: off | provider (default) | model. */
	public const MODE_OFF      = 'off';
	public const MODE_PROVIDER = 'provider';
	public const MODE_MODEL    = 'model';

	/**
	 * @param mixed $raw
	 * @return 'off'|'provider'|'model'
	 */
	public static function sanitize_mode( $raw ): string {
		$key = sanitize_key( (string) $raw );
		if ( self::MODE_MODEL === $key ) {
			return self::MODE_MODEL;
		}
		if ( self::MODE_OFF === $key ) {
			return self::MODE_OFF;
		}
		// Default: new provider only.
		return self::MODE_PROVIDER;
	}

	/**
	 * Normalize a provider or model id for pair keys (lowercase, stripped).
	 */
	public static function normalize_id( string $id ): string {
		$id = strtolower( trim( $id ) );
		$id = preg_replace( '/\s+/', '-', $id ) ?? '';
		return preg_replace( '/[^a-z0-9._\-]/', '', $id ) ?? '';
	}

	/**
	 * Pair key: provider|model (empty segments allowed when unknown).
	 */
	public static function pair_key( string $provider, string $model ): string {
		return self::normalize_id( $provider ) . '|' . self::normalize_id( $model );
	}

	/**
	 * @param mixed $raw
	 * @return array<string,array<string,int>>
	 */
	public static function sanitize_seen_map( $raw ): array {
		if ( ! is_array( $raw ) ) {
			return array();
		}
		$out = array();
		foreach ( $raw as $plugin => $pairs ) {
			$plugin = Plugin_Profile::sanitize_plugin( (string) $plugin );
			if ( '' === $plugin || ! is_array( $pairs ) ) {
				continue;
			}
			$clean = array();
			foreach ( $pairs as $pair => $ts ) {
				$pair = (string) $pair;
				if ( ! preg_match( '/^[a-z0-9._\-]*\|[a-z0-9._\-]*$/', $pair ) ) {
					continue;
				}
				$ts = (int) $ts;
				if ( $ts <= 0 ) {
					continue;
				}
				$clean[ $pair ] = $ts;
			}
			if ( ! empty( $clean ) ) {
				$out[ $plugin ] = $clean;
			}
		}

		return $out;
	}

	/**
	 * @return array<string,array<string,int>>
	 */
	public static function get_seen_map(): array {
		return self::sanitize_seen_map( get_option( self::SEEN_OPTION_KEY, array() ) );
	}

	/**
	 * @param array<string,array<string,int>> $map
	 */
	public static function save_seen_map( array $map ): void {
		$map = self::sanitize_seen_map( $map );
		if ( empty( $map ) ) {
			delete_option( self::SEEN_OPTION_KEY );
			return;
		}
		update_option( self::SEEN_OPTION_KEY, $map, false );
	}

	/** @var list<array{policy:array<string,mixed>,plugin:string,prev:array{provider:string,model:string,pair:string}|null,provider:string,model:string,pair:string,now:int}> */
	private static array $deferred_alerts = array();

	/**
	 * Flush alerts stashed while appending a log row (avoids nested overwrite).
	 */
	public static function flush_deferred_alerts(): void {
		$queue = self::$deferred_alerts;
		self::$deferred_alerts = array();
		foreach ( $queue as $item ) {
			self::maybe_fire(
				$item['policy'],
				$item['plugin'],
				$item['prev'],
				$item['provider'],
				$item['model'],
				$item['pair'],
				$item['now']
			);
		}
	}

	/**
	 * Decide whether this AI Client log row is new-pair / should alert.
	 *
	 * Mutates the event with drift_first_seen when the pair is newly recorded.
	 * Sends alert when mode says so and this is not the plugin baseline.
	 *
	 * @param array<string,mixed> $event  Log row (may be mutated).
	 * @param array<string,mixed> $policy Current policy.
	 * @param bool                $defer_alerts When true, stash alerts for flush_deferred_alerts().
	 * @return array{tagged:bool,alerted:bool,baseline:bool,reason:string}
	 */
	public static function observe( array &$event, array $policy, bool $defer_alerts = false ): array {
		$empty = array(
			'tagged'   => false,
			'alerted'  => false,
			'baseline' => false,
			'reason'   => '',
		);

		$mode = self::sanitize_mode( $policy['drift_alert_mode'] ?? self::MODE_PROVIDER );

		$channel = isset( $event['channel'] ) ? (string) $event['channel'] : '';
		if ( in_array( $channel, array( 'direct_http', 'anomaly', 'spend_threshold', 'drift', 'alert_snooze' ), true ) ) {
			$empty['reason'] = 'skip_channel';
			return $empty;
		}

		$plugin = isset( $event['plugin'] ) ? Plugin_Profile::sanitize_plugin( (string) $event['plugin'] ) : '';
		if ( '' === $plugin ) {
			$empty['reason'] = 'no_plugin';
			return $empty;
		}

		$provider = isset( $event['provider'] ) ? (string) $event['provider'] : '';
		$model    = isset( $event['model'] ) ? (string) $event['model'] : '';
		// Prefer explicit model; fall back to common alternate keys used in older rows.
		if ( '' === $model && isset( $event['model_id'] ) ) {
			$model = (string) $event['model_id'];
		}
		$provider_n = self::normalize_id( $provider );
		$model_n    = self::normalize_id( $model );
		// Need at least one of provider/model to track.
		if ( '' === $provider_n && '' === $model_n ) {
			$empty['reason'] = 'no_pair';
			return $empty;
		}

		$pair = self::pair_key( $provider, $model );
		$map  = self::get_seen_map();
		$seen = isset( $map[ $plugin ] ) && is_array( $map[ $plugin ] ) ? $map[ $plugin ] : array();

		$is_baseline = empty( $seen );
		$pair_known  = isset( $seen[ $pair ] );

		if ( $pair_known ) {
			$empty['reason'] = 'known_pair';
			return $empty;
		}

		// Record the new pair (baseline or drift).
		$ts = isset( $event['ts'] ) ? (int) $event['ts'] : time();
		if ( $ts <= 0 ) {
			$ts = time();
		}
		$seen[ $pair ]   = $ts;
		$map[ $plugin ]  = $seen;
		self::save_seen_map( $map );

		$event['drift_first_seen'] = true;

		if ( $is_baseline ) {
			return array(
				'tagged'   => true,
				'alerted'  => false,
				'baseline' => true,
				'reason'   => 'baseline',
			);
		}

		// Track pairs even when alerts are off so re-enabling does not flood.
		if ( self::MODE_OFF === $mode ) {
			return array(
				'tagged'   => true,
				'alerted'  => false,
				'baseline' => false,
				'reason'   => 'disabled',
			);
		}

		// Decide alert eligibility from mode.
		$should_alert = false;
		if ( self::MODE_MODEL === $mode ) {
			$should_alert = true;
		} elseif ( self::MODE_PROVIDER === $mode ) {
			$should_alert = ! self::provider_previously_seen( $seen, $provider_n, $pair );
		}

		if ( ! $should_alert ) {
			return array(
				'tagged'   => true,
				'alerted'  => false,
				'baseline' => false,
				'reason'   => 'mode_skip',
			);
		}

		$prev = self::pick_previous_pair( $seen, $pair );
		if ( $defer_alerts ) {
			self::$deferred_alerts[] = array(
				'policy'   => $policy,
				'plugin'   => $plugin,
				'prev'     => $prev,
				'provider' => $provider_n,
				'model'    => $model_n,
				'pair'     => $pair,
				'now'      => $ts,
			);
			return array(
				'tagged'   => true,
				'alerted'  => false,
				'baseline' => false,
				'reason'   => 'deferred',
			);
		}

		$fired = self::maybe_fire( $policy, $plugin, $prev, $provider_n, $model_n, $pair, $ts );

		return array(
			'tagged'   => true,
			'alerted'  => $fired,
			'baseline' => false,
			'reason'   => $fired ? 'alerted' : 'suppressed',
		);
	}

	/**
	 * True when this provider already appears in another recorded pair (excluding $exclude_pair).
	 *
	 * @param array<string,int> $seen
	 */
	public static function provider_previously_seen( array $seen, string $provider_n, string $exclude_pair ): bool {
		if ( '' === $provider_n ) {
			// Unknown provider: treat each empty-provider pair as distinct; alert on new model only in model mode.
			return false;
		}
		foreach ( $seen as $pair => $ts ) {
			if ( $pair === $exclude_pair ) {
				continue;
			}
			$parts = explode( '|', (string) $pair, 2 );
			$prev_p = $parts[0] ?? '';
			if ( $prev_p === $provider_n ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Most recently recorded pair other than $exclude (for cost-multiple context).
	 *
	 * @param array<string,int> $seen
	 * @return array{provider:string,model:string,pair:string}|null
	 */
	public static function pick_previous_pair( array $seen, string $exclude ): ?array {
		$best_pair = '';
		$best_ts   = 0;
		foreach ( $seen as $pair => $ts ) {
			if ( (string) $pair === $exclude ) {
				continue;
			}
			$ts = (int) $ts;
			if ( $ts >= $best_ts ) {
				$best_ts   = $ts;
				$best_pair = (string) $pair;
			}
		}
		if ( '' === $best_pair ) {
			return null;
		}
		$parts = explode( '|', $best_pair, 2 );

		return array(
			'provider' => $parts[0] ?? '',
			'model'    => $parts[1] ?? '',
			'pair'     => $best_pair,
		);
	}

	/**
	 * Estimated cost multiple when both providers have configured rate overrides.
	 *
	 * Uses (input+output) blended $/1M. Returns null when either provider lacks
	 * an explicit override, providers match, or multiple is not > 1.
	 *
	 * @param array<string,mixed> $policy
	 */
	public static function cost_multiple( string $old_provider, string $new_provider, array $policy ): ?float {
		$old_id = Cost::normalize_provider_id( $old_provider );
		$new_id = Cost::normalize_provider_id( $new_provider );
		if ( '' === $old_id || '' === $new_id || $old_id === $new_id ) {
			return null;
		}
		$map = Cost::sanitize_provider_rates( $policy['est_usd_provider_rates'] ?? array() );
		if ( ! isset( $map[ $old_id ], $map[ $new_id ] ) ) {
			return null;
		}
		$old_blend = (float) $map[ $old_id ]['input_per_m'] + (float) $map[ $old_id ]['output_per_m'];
		$new_blend = (float) $map[ $new_id ]['input_per_m'] + (float) $map[ $new_id ]['output_per_m'];
		if ( $old_blend <= 0.0 ) {
			return null;
		}
		$mult = $new_blend / $old_blend;
		if ( $mult <= 1.0001 ) {
			return null;
		}

		return round( $mult, 2 );
	}

	/**
	 * @param array<string,mixed>                          $policy
	 * @param array{provider:string,model:string,pair:string}|null $prev
	 */
	private static function maybe_fire(
		array $policy,
		string $plugin,
		?array $prev,
		string $provider,
		string $model,
		string $pair,
		int $now
	): bool {
		if ( Alert_Snooze::should_suppress( $plugin, 'drift', $now ) ) {
			return false;
		}

		$to = Alerts::resolve_email( $policy );
		if ( '' === $to ) {
			return false;
		}

		$prev_provider = is_array( $prev ) ? (string) $prev['provider'] : '';
		$prev_model    = is_array( $prev ) ? (string) $prev['model'] : '';
		$multiple      = self::cost_multiple( $prev_provider, $provider, $policy );

		$subject = self::build_subject( $plugin, $provider, $model );
		$body    = self::build_body( $plugin, $prev_provider, $prev_model, $provider, $model, $multiple );
		$ok      = Alerts::safe_wp_mail( $to, $subject, $body );

		$hook_url = Alerts::resolve_webhook( $policy );
		if ( '' !== $hook_url ) {
			Alerts::safe_wp_remote_post(
				$hook_url,
				array(
					'type'          => 'handl_aicac_drift_alert',
					'plugin'        => $plugin,
					'provider'      => $provider,
					'model'         => $model,
					'prev_provider' => $prev_provider,
					'prev_model'    => $prev_model,
					'cost_multiple' => $multiple,
					'activity'      => self::activity_url_for_plugin( $plugin ),
					'site'          => function_exists( 'home_url' ) ? home_url( '/' ) : '',
				)
			);
		}

		if ( ! $ok ) {
			return false;
		}

		self::push_recent(
			array(
				'ts'            => $now,
				'plugin'        => $plugin,
				'provider'      => $provider,
				'model'         => $model,
				'prev_provider' => $prev_provider,
				'prev_model'    => $prev_model,
				'cost_multiple' => $multiple,
				'pair'          => $pair,
			)
		);

		// Audit row (channel=drift) — skipped by observe via channel filter.
		Policy::append_log_event(
			array(
				'ts'            => $now,
				'decision'      => 'drift_alert',
				'channel'       => 'drift',
				'plugin'        => $plugin,
				'provider'      => $provider,
				'model'         => $model,
				'prev_provider' => $prev_provider,
				'prev_model'    => $prev_model,
				'cost_multiple' => $multiple,
			)
		);

		return true;
	}

	public static function build_subject( string $plugin, string $provider, string $model ): string {
		$site  = function_exists( 'get_bloginfo' )
			? wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES )
			: 'WordPress';
		$label = self::plugin_label( $plugin );
		$pair  = self::format_pair_label( $provider, $model );

		return sprintf(
			/* translators: 1: site name, 2: plugin name, 3: provider/model label */
			__( '[%1$s] HandL: %2$s started using %3$s', 'handl-ai-connector-access-control' ),
			$site,
			$label,
			$pair
		);
	}

	/**
	 * @param ?float $cost_multiple
	 */
	public static function build_body(
		string $plugin,
		string $prev_provider,
		string $prev_model,
		string $provider,
		string $model,
		?float $cost_multiple
	): string {
		$lines   = array();
		$lines[] = __( 'HandL AI Connector Access Control — provider/model change', 'handl-ai-connector-access-control' );
		$lines[] = '';
		$lines[] = sprintf(
			/* translators: %s: plugin display name or basename */
			__( 'Plugin: %s', 'handl-ai-connector-access-control' ),
			self::plugin_label( $plugin )
		);
		if ( '' !== $prev_provider || '' !== $prev_model ) {
			$lines[] = sprintf(
				/* translators: %s: previous provider/model */
				__( 'Previously seen: %s', 'handl-ai-connector-access-control' ),
				self::format_pair_label( $prev_provider, $prev_model )
			);
		}
		$lines[] = sprintf(
			/* translators: %s: new provider/model */
			__( 'Newly seen: %s', 'handl-ai-connector-access-control' ),
			self::format_pair_label( $provider, $model )
		);

		if ( null !== $cost_multiple && $cost_multiple > 1.0 ) {
			$lines[] = '';
			$lines[] = sprintf(
				/* translators: %s: estimated cost multiple, e.g. 2.5 */
				__( 'Based on your saved provider rates, the new provider’s estimated cost is about %sx the previous one. Estimated spend is not billing.', 'handl-ai-connector-access-control' ),
				self::format_multiple( $cost_multiple )
			);
		}

		$lines[] = '';
		$lines[] = __( 'This alert fires once per new provider/model pair for this plugin. It does not change allow or deny rules.', 'handl-ai-connector-access-control' );
		$lines[] = '';
		$lines[] = __( 'View this plugin’s activity:', 'handl-ai-connector-access-control' );
		$lines[] = self::activity_url_for_plugin( $plugin );
		$lines[] = '';
		$lines[] = __( 'Manage provider/model change alerts:', 'handl-ai-connector-access-control' );
		$lines[] = admin_url( 'options-general.php?page=handl-ai-connector-access-control&handl_aicac_tab=activity' );

		return implode( "\n", $lines ) . "\n";
	}

	public static function format_pair_label( string $provider, string $model ): string {
		$provider = trim( $provider );
		$model    = trim( $model );
		if ( '' !== $provider && '' !== $model ) {
			return $provider . ' / ' . $model;
		}
		if ( '' !== $provider ) {
			return $provider;
		}
		if ( '' !== $model ) {
			return $model;
		}

		return __( 'unknown', 'handl-ai-connector-access-control' );
	}

	public static function format_multiple( float $mult ): string {
		if ( abs( $mult - round( $mult ) ) < 0.05 ) {
			return (string) (int) round( $mult );
		}

		return function_exists( 'number_format_i18n' )
			? number_format_i18n( $mult, 1 )
			: number_format( $mult, 1, '.', '' );
	}

	/**
	 * @param array<string,mixed> $row
	 */
	public static function push_recent( array $row ): void {
		$list = get_option( self::RECENT_OPTION_KEY, array() );
		if ( ! is_array( $list ) ) {
			$list = array();
		}
		array_unshift( $list, $row );
		$list = array_slice( $list, 0, self::RECENT_MAX );
		update_option( self::RECENT_OPTION_KEY, $list, false );
	}

	/**
	 * @return list<array<string,mixed>>
	 */
	public static function get_recent(): array {
		$list = get_option( self::RECENT_OPTION_KEY, array() );
		if ( ! is_array( $list ) ) {
			return array();
		}
		$out = array();
		foreach ( $list as $row ) {
			if ( is_array( $row ) ) {
				$out[] = $row;
			}
		}

		return $out;
	}

	private static function plugin_label( string $basename ): string {
		if ( '' === $basename || Analytics::UNKNOWN_KEY === $basename ) {
			return __( 'Unknown plugin', 'handl-ai-connector-access-control' );
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

	private static function activity_url_for_plugin( string $plugin ): string {
		return add_query_arg(
			array(
				'page'                 => 'handl-ai-connector-access-control',
				'handl_aicac_tab'      => 'activity',
				'handl_aicac_plugin'   => $plugin,
			),
			admin_url( 'options-general.php' )
		);
	}
}
