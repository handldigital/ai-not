<?php
/**
 * WP Dashboard at-a-glance governance widget (AICAC-WIDGET / #110).
 *
 * Read-only. Activity numbers reuse Rest::build_activity_summary /
 * filter_log_by_window (same paths as the Activity / REST surface).
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Native dashboard widget for manage_options users.
 */
final class Dashboard_Widget {
	public const WIDGET_ID = 'handl_aicac_governance';

	/** Cache transient for activity aggregates (not a policy option). */
	public const CACHE_KEY = 'handl_aicac_dash_widget';

	/** Cache TTL in seconds (~5 min). */
	public const CACHE_TTL = 300;

	/** Activity window token — same Rest catalog (1d = last 24 hours). */
	public const WINDOW = '1d';

	private static ?Dashboard_Widget $instance = null;

	public static function instance(): Dashboard_Widget {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	public function init(): void {
		add_action( 'wp_dashboard_setup', array( $this, 'register' ) );
	}

	/**
	 * Register only for manage_options — other roles get no empty shell.
	 */
	public function register(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		if ( ! function_exists( 'wp_add_dashboard_widget' ) ) {
			return;
		}

		wp_add_dashboard_widget(
			self::WIDGET_ID,
			__( 'HandL AI Access', 'handl-ai-connector-access-control' ),
			array( $this, 'render' )
		);
	}

	/**
	 * Render callback for wp_add_dashboard_widget.
	 */
	public function render(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		$policy   = Policy::get_policy();
		$snapshot = self::get_snapshot( $policy );
		self::render_html( $snapshot, $policy );
	}

	/**
	 * Build (or return cached) activity snapshot for the widget.
	 *
	 * Mode / Emergency stop always come from live $policy at render time.
	 * Activity aggregates are cached ~5 min.
	 *
	 * @param array<string,mixed> $policy
	 * @return array<string,mixed>
	 */
	public static function get_snapshot( array $policy, ?int $now = null ): array {
		$now = null === $now ? time() : $now;
		$cached = get_transient( self::CACHE_KEY );
		if ( is_array( $cached ) && isset( $cached['activity'] ) && is_array( $cached['activity'] ) ) {
			return array(
				'activity' => $cached['activity'],
				'top'      => isset( $cached['top'] ) && is_array( $cached['top'] ) ? $cached['top'] : array(),
				'cached'   => true,
			);
		}

		$built = self::build_snapshot( $policy, Policy::get_retained_log( $now ), $now );
		set_transient(
			self::CACHE_KEY,
			array(
				'activity' => $built['activity'],
				'top'      => $built['top'],
			),
			self::CACHE_TTL
		);

		return array(
			'activity' => $built['activity'],
			'top'      => $built['top'],
			'cached'   => false,
		);
	}

	/**
	 * Pure builder for tests — no transient I/O.
	 *
	 * @param array<string,mixed> $policy
	 * @param array<int,mixed>    $log
	 * @return array{activity:array<string,mixed>,top:list<array{plugin:?string,calls:int,label:string}>}
	 */
	public static function build_snapshot( array $policy, array $log, int $now ): array {
		$activity = Rest::build_activity_summary( $policy, $log, self::WINDOW, $now );
		$top      = self::top_plugins_by_calls( $policy, $log, $now, 3 );

		return array(
			'activity' => $activity,
			'top'      => $top,
		);
	}

	/**
	 * Top N AI Client plugins by call count in the same Rest 1d window.
	 *
	 * @param array<string,mixed> $policy
	 * @param array<int,mixed>    $log
	 * @return list<array{plugin:?string,calls:int,label:string}>
	 */
	public static function top_plugins_by_calls( array $policy, array $log, int $now, int $limit = 3 ): array {
		$logging = ! empty( $policy['log_enabled'] ) || ! empty( $policy['audit_only'] );
		if ( ! $logging || $limit < 1 ) {
			return array();
		}

		$filtered = Rest::filter_log_by_window( $log, self::WINDOW, $now );
		$counts   = array();
		foreach ( $filtered as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			if ( isset( $row['channel'] ) && 'direct_http' === (string) $row['channel'] ) {
				continue;
			}
			$plugin = isset( $row['plugin'] ) ? trim( (string) $row['plugin'] ) : '';
			if ( '' === $plugin ) {
				$plugin = Analytics::UNKNOWN_KEY;
			}
			if ( ! isset( $counts[ $plugin ] ) ) {
				$counts[ $plugin ] = 0;
			}
			++$counts[ $plugin ];
		}
		arsort( $counts, SORT_NUMERIC );

		$plugins = function_exists( 'get_plugins' ) ? get_plugins() : array();
		if ( ! is_array( $plugins ) ) {
			$plugins = array();
		}

		$out = array();
		$i   = 0;
		foreach ( $counts as $plugin => $calls ) {
			if ( $i >= $limit ) {
				break;
			}
			++$i;
			$label = Analytics::UNKNOWN_KEY === $plugin
				? __( 'Unknown plugin', 'handl-ai-connector-access-control' )
				: ( isset( $plugins[ $plugin ]['Name'] ) ? (string) $plugins[ $plugin ]['Name'] : $plugin );
			$out[] = array(
				'plugin' => Analytics::UNKNOWN_KEY === $plugin ? null : $plugin,
				'calls'  => (int) $calls,
				'label'  => $label,
			);
		}

		return $out;
	}

	/**
	 * Drop the activity cache (e.g. after policy saves that affect alerts).
	 */
	public static function bust_cache(): void {
		delete_transient( self::CACHE_KEY );
	}

	/**
	 * @param array<string,mixed> $snapshot
	 * @param array<string,mixed> $policy
	 */
	public static function render_html( array $snapshot, array $policy ): void {
		$activity = isset( $snapshot['activity'] ) && is_array( $snapshot['activity'] ) ? $snapshot['activity'] : array();
		$top      = isset( $snapshot['top'] ) && is_array( $snapshot['top'] ) ? $snapshot['top'] : array();

		$observe = ! empty( $policy['audit_only'] );
		$kill    = ! empty( $policy['kill_switch'] );
		$mode    = $observe
			? __( 'Observe', 'handl-ai-connector-access-control' )
			: __( 'Enforce', 'handl-ai-connector-access-control' );

		$rules_url = add_query_arg(
			array(
				'page'            => 'handl-ai-connector-access-control',
				'handl_aicac_tab' => 'rules',
			),
			admin_url( 'options-general.php' )
		);
		$activity_url = add_query_arg(
			array(
				'page'            => 'handl-ai-connector-access-control',
				'handl_aicac_tab' => 'activity',
			),
			admin_url( 'options-general.php' )
		);

		echo '<div class="handl-aicac-dash-widget">';

		if ( $kill ) {
			echo '<div class="notice notice-warning inline" style="margin:0 0 12px;"><p><strong>';
			echo esc_html__( 'Emergency stop is on. All AI Client calls are blocked except listed plugins.', 'handl-ai-connector-access-control' );
			echo '</strong></p></div>';
		}

		echo '<p style="margin:0 0 10px;">';
		echo '<strong>' . esc_html__( 'Mode', 'handl-ai-connector-access-control' ) . ':</strong> ';
		$mode_color = $kill ? '#b32d2e' : ( $observe ? '#996800' : '#00a32a' );
		echo '<span style="color:' . esc_attr( $mode_color ) . ';font-weight:600;">' . esc_html( $mode ) . '</span>';
		if ( $kill ) {
			echo ' · <span style="color:#b32d2e;font-weight:600;">' . esc_html__( 'Emergency stop', 'handl-ai-connector-access-control' ) . '</span>';
		}
		echo '</p>';

		$status = isset( $activity['status'] ) ? (string) $activity['status'] : '';
		if ( 'logging_disabled' === $status ) {
			echo '<p class="description">' . esc_html__( 'Activity logging is off, so there are no last-24-hour totals yet.', 'handl-ai-connector-access-control' ) . '</p>';
		} elseif ( 'no_data' === $status ) {
			echo '<p class="description">' . esc_html__( 'No AI activity in the last 24 hours.', 'handl-ai-connector-access-control' ) . '</p>';
		} elseif ( 'ok' === $status ) {
			$calls   = (int) ( $activity['ai_client_call_count'] ?? 0 );
			$denies  = (int) ( $activity['calls_by_decision']['deny'] ?? 0 );
			$blocks  = (int) ( $activity['shadow_ai_block_count'] ?? 0 );
			$shadow  = (int) ( $activity['shadow_ai_observation_count'] ?? 0 );
			$est     = array_key_exists( 'estimated_spend_usd', $activity ) ? (float) $activity['estimated_spend_usd'] : null;
			$thresh  = Spend_Threshold::sanitize_threshold( $policy['spend_threshold_site'] ?? null );

			echo '<p style="margin:0 0 8px;"><strong>' . esc_html__( 'Last 24 hours', 'handl-ai-connector-access-control' ) . '</strong></p>';
			echo '<ul style="margin:0 0 12px 1.2em;list-style:disc;">';
			echo '<li>' . esc_html(
				sprintf(
					/* translators: %d: AI Client call count */
					_n( '%d AI Client call', '%d AI Client calls', $calls, 'handl-ai-connector-access-control' ),
					$calls
				)
			) . '</li>';
			echo '<li>' . esc_html(
				sprintf(
					/* translators: %d: denied call count */
					_n( '%d blocked call', '%d blocked calls', $denies, 'handl-ai-connector-access-control' ),
					$denies
				)
			) . '</li>';
			echo '<li>' . esc_html(
				sprintf(
					/* translators: 1: blocked direct connections, 2: observed direct connections */
					__( '%1$d direct AI blocks (%2$d observed)', 'handl-ai-connector-access-control' ),
					$blocks,
					$shadow
				)
			) . '</li>';
			if ( null !== $est ) {
				$est_label = '$' . number_format_i18n( $est, 2 );
				if ( null !== $thresh ) {
					echo '<li>' . esc_html(
						sprintf(
							/* translators: 1: estimated spend, 2: site threshold */
							__( 'Estimated spend %1$s (alert at %2$s)', 'handl-ai-connector-access-control' ),
							$est_label,
							'$' . number_format_i18n( $thresh, 2 )
						)
					) . '</li>';
				} else {
					echo '<li>' . esc_html(
						sprintf(
							/* translators: %s: estimated spend amount */
							__( 'Estimated spend %s', 'handl-ai-connector-access-control' ),
							$est_label
						)
					) . '</li>';
				}
			}
			echo '</ul>';
		}

		if ( ! empty( $top ) ) {
			echo '<p style="margin:0 0 6px;"><strong>' . esc_html__( 'Top plugins', 'handl-ai-connector-access-control' ) . '</strong></p>';
			echo '<ol style="margin:0 0 12px 1.2em;">';
			foreach ( $top as $row ) {
				if ( ! is_array( $row ) ) {
					continue;
				}
				$label  = (string) ( $row['label'] ?? '' );
				$calls  = (int) ( $row['calls'] ?? 0 );
				$plugin = isset( $row['plugin'] ) && is_string( $row['plugin'] ) ? $row['plugin'] : '';
				$url    = '' !== $plugin ? Plugin_Profile::profile_url( $plugin ) : $activity_url;
				echo '<li>';
				if ( '' !== $url ) {
					echo '<a href="' . esc_url( $url ) . '">' . esc_html( $label ) . '</a>';
				} else {
					echo esc_html( $label );
				}
				echo ' <span class="description">(' . esc_html( (string) $calls ) . ')</span>';
				echo '</li>';
			}
			echo '</ol>';
		}

		echo '<p style="margin:0;">';
		echo '<a class="button button-secondary" href="' . esc_url( $rules_url ) . '">' . esc_html__( 'Review policy', 'handl-ai-connector-access-control' ) . '</a>';
		echo ' <a href="' . esc_url( $activity_url ) . '">' . esc_html__( 'Open Activity', 'handl-ai-connector-access-control' ) . '</a>';
		echo '</p>';

		echo '</div>';
	}
}
