<?php
/**
 * Printable audit evidence report (AICAC-EVIDENCE / #118).
 *
 * Self-contained HTML for browser print → PDF. Data paths match Rest (#95) and
 * the Activity admin tab — no parallel counting logic.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Audit_Evidence {

	/**
	 * Build structured report data for HTML rendering and tests.
	 *
	 * @param array<string,mixed>               $policy
	 * @param array<int,mixed>                  $log      Retained log (same as Policy::get_retained_log()).
	 * @param string                            $window   Rest window token (1d|7d|30d|all).
	 * @param int                               $now      Unix timestamp.
	 * @param array<string,array<string,mixed>> $plugins  get_plugins()-shaped map.
	 * @return array<string,mixed>
	 */
	public static function build_report_data( array $policy, array $log, string $window, int $now, array $plugins ): array {
		$window = Rest::sanitize_window( $window );
		$summary = Rest::build_activity_summary( $policy, $log, $window, $now );
		$filtered = Rest::filter_log_by_window( $log, $window, $now );

		$family_counts = self::family_counts_from_rows( $filtered );
		$plugin_rules  = self::plugin_rules_snapshot( $policy, $plugins, $now );
		$thresholds    = self::threshold_snapshot( $policy, $summary );

		$site_name = function_exists( 'get_bloginfo' )
			? (string) get_bloginfo( 'name' )
			: '';
		if ( '' === $site_name ) {
			$site_name = __( '(unnamed site)', 'handl-ai-connector-access-control' );
		}

		$version = defined( 'HANDL_AICAC_VERSION' ) ? (string) HANDL_AICAC_VERSION : '';

		return array(
			'meta'              => array(
				'site_name'       => $site_name,
				'generated_at'    => $now,
				'generated_label' => $now > 0 ? wp_date( 'Y-m-d H:i:s T', $now ) : '',
				'plugin_version'  => $version,
				'window'          => $window,
				'window_label'    => self::window_label( $window ),
			),
			'policy'            => self::policy_mode_snapshot( $policy ),
			'plugin_rules'      => $plugin_rules,
			'denied_tools'      => self::denied_tools_snapshot( $policy ),
			'activity'          => $summary,
			'family_counts'     => $family_counts,
			'thresholds'        => $thresholds,
			'change_history'    => self::change_history_snapshot(),
			'csv_export_note'   => __( 'For row-level activity, use Download CSV on the Activity tab (same retained log and filters).', 'handl-ai-connector-access-control' ),
		);
	}

	/**
	 * AICAC-HISTORY (#107): recent policy change rows for the printable report.
	 *
	 * @return array{available:bool,entries:list<array{when:string,who:string,summary:string,changes:list<string>}>}
	 */
	private static function change_history_snapshot(): array {
		$rows = Policy_Snapshots::history();
		if ( empty( $rows ) ) {
			return array(
				'available' => false,
				'entries'   => array(),
			);
		}

		$entries = array();
		foreach ( array_slice( $rows, 0, 25 ) as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$ts = (int) ( $row['ts'] ?? 0 );
			$when = $ts > 0
				? ( function_exists( 'wp_date' ) ? wp_date( 'Y-m-d H:i:s T', $ts ) : gmdate( 'Y-m-d H:i:s', $ts ) . ' UTC' )
				: '';
			$changes = isset( $row['changes'] ) && is_array( $row['changes'] ) ? $row['changes'] : array();
			$clean   = array();
			foreach ( $changes as $line ) {
				if ( is_string( $line ) && '' !== trim( $line ) ) {
					$clean[] = $line;
				}
			}
			$entries[] = array(
				'when'    => $when,
				'who'     => Policy_Snapshots::actor_display( is_array( $row['actor'] ?? null ) ? $row['actor'] : array() ),
				'summary' => (string) ( $row['summary'] ?? '' ),
				'changes' => $clean,
			);
		}

		return array(
			'available' => ! empty( $entries ),
			'entries'   => $entries,
		);
	}

	/**
	 * Render a complete HTML document (inline CSS only, print-friendly).
	 *
	 * @param array<string,mixed> $data From build_report_data().
	 */
	public static function build_html( array $data ): string {
		$meta     = is_array( $data['meta'] ?? null ) ? $data['meta'] : array();
		$policy   = is_array( $data['policy'] ?? null ) ? $data['policy'] : array();
		$activity = is_array( $data['activity'] ?? null ) ? $data['activity'] : array();
		$rules    = is_array( $data['plugin_rules'] ?? null ) ? $data['plugin_rules'] : array();
		$families = is_array( $data['family_counts'] ?? null ) ? $data['family_counts'] : array();
		$tools    = is_array( $data['denied_tools'] ?? null ) ? $data['denied_tools'] : array();
		$thresh   = is_array( $data['thresholds'] ?? null ) ? $data['thresholds'] : array();
		$history  = is_array( $data['change_history'] ?? null ) ? $data['change_history'] : array();

		$title = sprintf(
			/* translators: %s: site name */
			__( 'AI governance report: %s', 'handl-ai-connector-access-control' ),
			(string) ( $meta['site_name'] ?? '' )
		);

		ob_start();
		?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title><?php echo esc_html( $title ); ?></title>
<style>
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;font-size:12px;line-height:1.45;color:#1d2327;margin:24px;max-width:900px;}
h1{font-size:20px;margin:0 0 8px;}
h2{font-size:15px;margin:24px 0 8px;border-bottom:1px solid #c3c4c7;padding-bottom:4px;page-break-after:avoid;}
h3{font-size:13px;margin:16px 0 6px;}
.meta{color:#50575e;margin-bottom:20px;}
table{border-collapse:collapse;width:100%;margin:8px 0 16px;}
th,td{border:1px solid #c3c4c7;padding:6px 8px;text-align:left;vertical-align:top;}
th{background:#f0f0f1;}
.num{text-align:right;font-variant-numeric:tabular-nums;}
.muted{color:#646970;}
.section{page-break-inside:avoid;margin-bottom:16px;}
.section-major{page-break-before:always;}
.section-major:first-of-type{page-break-before:auto;}
@media print{
  body{margin:12mm;}
  .no-print{display:none !important;}
}
</style>
</head>
<body>
<p class="no-print muted"><?php echo esc_html__( 'Use your browser’s Print dialog and choose Save as PDF. This page stays on your site. Nothing is sent elsewhere.', 'handl-ai-connector-access-control' ); ?></p>

<h1><?php echo esc_html__( 'HandL AI governance report', 'handl-ai-connector-access-control' ); ?></h1>
<div class="meta section">
<p><strong><?php echo esc_html__( 'Site', 'handl-ai-connector-access-control' ); ?>:</strong> <?php echo esc_html( (string) ( $meta['site_name'] ?? '' ) ); ?></p>
<p><strong><?php echo esc_html__( 'Generated', 'handl-ai-connector-access-control' ); ?>:</strong> <?php echo esc_html( (string) ( $meta['generated_label'] ?? '' ) ); ?></p>
<p><strong><?php echo esc_html__( 'Plugin version', 'handl-ai-connector-access-control' ); ?>:</strong> <?php echo esc_html( (string) ( $meta['plugin_version'] ?? '' ) ); ?></p>
<p><strong><?php echo esc_html__( 'Activity window', 'handl-ai-connector-access-control' ); ?>:</strong> <?php echo esc_html( (string) ( $meta['window_label'] ?? '' ) ); ?></p>
</div>

<div class="section section-major">
<h2><?php echo esc_html__( 'Policy snapshot', 'handl-ai-connector-access-control' ); ?></h2>
<table>
<tbody>
<?php self::render_kv_row( __( 'Default for plugins', 'handl-ai-connector-access-control' ), (string) ( $policy['default_label'] ?? '' ) ); ?>
<?php self::render_kv_row( __( 'Learn mode (observe only)', 'handl-ai-connector-access-control' ), (string) ( $policy['audit_only_label'] ?? '' ) ); ?>
<?php self::render_kv_row( __( 'Activity logging', 'handl-ai-connector-access-control' ), (string) ( $policy['log_enabled_label'] ?? '' ) ); ?>
<?php self::render_kv_row( __( 'Emergency stop', 'handl-ai-connector-access-control' ), (string) ( $policy['kill_switch_label'] ?? '' ) ); ?>
<?php self::render_kv_row( __( 'Block direct AI connections', 'handl-ai-connector-access-control' ), (string) ( $policy['shadow_block_label'] ?? '' ) ); ?>
<?php self::render_kv_row( __( 'User role restrictions', 'handl-ai-connector-access-control' ), (string) ( $policy['role_gate_label'] ?? '' ) ); ?>
<?php self::render_kv_row( __( 'Unknown AI operations', 'handl-ai-connector-access-control' ), (string) ( $policy['unknown_operation_label'] ?? '' ) ); ?>
</tbody>
</table>
</div>

<div class="section section-major">
<h2><?php echo esc_html__( 'Plugin rules', 'handl-ai-connector-access-control' ); ?></h2>
<?php if ( empty( $rules ) ) : ?>
<p class="muted"><?php echo esc_html__( 'No explicit plugin rules. All plugins follow the site default.', 'handl-ai-connector-access-control' ); ?></p>
<?php else : ?>
<table>
<?php
$show_reason = false;
foreach ( $rules as $rcheck ) {
	if ( is_array( $rcheck ) && '' !== trim( (string) ( $rcheck['note'] ?? '' ) ) ) {
		$show_reason = true;
		break;
	}
}
?>
<thead><tr>
<th><?php echo esc_html__( 'Plugin', 'handl-ai-connector-access-control' ); ?></th>
<th><?php echo esc_html__( 'Access', 'handl-ai-connector-access-control' ); ?></th>
<th><?php echo esc_html__( 'AI type rules', 'handl-ai-connector-access-control' ); ?></th>
<th><?php echo esc_html__( 'Allow expiry', 'handl-ai-connector-access-control' ); ?></th>
<?php if ( $show_reason ) : ?>
<th><?php echo esc_html__( 'Rule note', 'handl-ai-connector-access-control' ); ?></th>
<?php endif; ?>
</tr></thead>
<tbody>
<?php foreach ( $rules as $row ) : ?>
<?php if ( ! is_array( $row ) ) { continue; } ?>
<tr>
<td><?php echo esc_html( (string) ( $row['label'] ?? '' ) ); ?><br /><span class="muted"><code><?php echo esc_html( (string) ( $row['basename'] ?? '' ) ); ?></code></span></td>
<td><?php echo esc_html( (string) ( $row['rule_label'] ?? '' ) ); ?></td>
<td><?php echo esc_html( (string) ( $row['families_label'] ?? '' ) ); ?></td>
<td><?php echo esc_html( (string) ( $row['expires_label'] ?? '' ) ); ?></td>
<?php if ( $show_reason ) : ?>
<td><?php echo esc_html( (string) ( $row['note'] ?? '' ) ); ?></td>
<?php endif; ?>
</tr>
<?php endforeach; ?>
</tbody>
</table>
<?php endif; ?>
</div>

<div class="section section-major">
<h2><?php echo esc_html__( 'Blocked AI tools', 'handl-ai-connector-access-control' ); ?></h2>
<p><?php echo esc_html( (string) ( $tools['summary'] ?? '' ) ); ?></p>
<?php if ( ! empty( $tools['items'] ) && is_array( $tools['items'] ) ) : ?>
<ul><?php foreach ( $tools['items'] as $tool ) : ?><li><code><?php echo esc_html( (string) $tool ); ?></code></li><?php endforeach; ?></ul>
<?php endif; ?>
</div>

<div class="section section-major">
<h2><?php echo esc_html__( 'Activity summary', 'handl-ai-connector-access-control' ); ?></h2>
<?php echo self::render_activity_section( $activity, $families, $thresh ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- internally escaped ?>
<p class="muted"><?php echo esc_html( (string) ( $data['csv_export_note'] ?? '' ) ); ?></p>
</div>

<div class="section section-major">
<h2><?php echo esc_html__( 'Policy change history', 'handl-ai-connector-access-control' ); ?></h2>
<?php if ( ! empty( $history['available'] ) && ! empty( $history['entries'] ) && is_array( $history['entries'] ) ) : ?>
<table>
<thead><tr>
<th><?php echo esc_html__( 'When', 'handl-ai-connector-access-control' ); ?></th>
<th><?php echo esc_html__( 'Who', 'handl-ai-connector-access-control' ); ?></th>
<th><?php echo esc_html__( 'What changed', 'handl-ai-connector-access-control' ); ?></th>
</tr></thead>
<tbody>
<?php foreach ( $history['entries'] as $entry ) : ?>
<?php if ( ! is_array( $entry ) ) { continue; } ?>
<tr>
<td><?php echo esc_html( (string) ( $entry['when'] ?? '' ) ); ?></td>
<td><?php echo esc_html( (string) ( $entry['who'] ?? '' ) ); ?></td>
<td>
<?php
$lines = isset( $entry['changes'] ) && is_array( $entry['changes'] ) ? $entry['changes'] : array();
if ( empty( $lines ) ) {
	echo esc_html( (string) ( $entry['summary'] ?? '' ) );
} else {
	echo '<ul>';
	foreach ( $lines as $line ) {
		echo '<li>' . esc_html( (string) $line ) . '</li>';
	}
	echo '</ul>';
}
?>
</td>
</tr>
<?php endforeach; ?>
</tbody>
</table>
<?php else : ?>
<p class="muted"><?php echo esc_html__( 'No policy changes were recorded for this report.', 'handl-ai-connector-access-control' ); ?></p>
<?php endif; ?>
</div>

</body>
</html>
		<?php
		$html = ob_get_clean();
		return is_string( $html ) ? $html : '';
	}

	/**
	 * @param array<int,mixed> $filtered Rows from Rest::filter_log_by_window().
	 * @return list<array{family:string,label:string,calls:int}>
	 */
	public static function family_counts_from_rows( array $filtered ): array {
		$labels = Operations::family_labels();
		$counts = array();

		foreach ( $filtered as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			if ( isset( $row['channel'] ) && 'direct_http' === (string) $row['channel'] ) {
				continue;
			}
			$family = isset( $row['capability_family'] ) ? (string) $row['capability_family'] : '';
			$op     = isset( $row['operation'] ) ? (string) $row['operation'] : '';
			if ( '' === $family && '' !== $op ) {
				$family = Operations::family_from_operation( $op );
			}
			if ( '' === $family ) {
				$family = Operations::FAMILY_UNKNOWN;
			}
			if ( ! isset( $counts[ $family ] ) ) {
				$counts[ $family ] = 0;
			}
			++$counts[ $family ];
		}

		arsort( $counts );
		$out = array();
		foreach ( $counts as $family => $calls ) {
			$label = isset( $labels[ $family ] ) ? (string) $labels[ $family ] : $family;
			if ( Operations::FAMILY_UNKNOWN === $family ) {
				$label = __( 'Unknown', 'handl-ai-connector-access-control' );
			}
			$out[] = array(
				'family' => (string) $family,
				'label'  => $label,
				'calls'  => (int) $calls,
			);
		}

		return $out;
	}

	/**
	 * @param array<string,mixed>               $policy
	 * @param array<string,array<string,mixed>> $plugins
	 * @return list<array<string,string>>
	 */
	public static function plugin_rules_snapshot( array $policy, array $plugins, int $now ): array {
		$explicit = is_array( $policy['plugins'] ?? null ) ? (array) $policy['plugins'] : array();
		$ops      = is_array( $policy['operations'] ?? null ) ? (array) $policy['operations'] : array();
		$expires  = is_array( $policy['plugin_expires'] ?? null ) ? (array) $policy['plugin_expires'] : array();
		$notes    = Rule_Notes::sanitize_plugin_notes( $policy['plugin_notes'] ?? array() );
		$labels   = Operations::family_labels();
		$out      = array();

		foreach ( $explicit as $basename => $rule ) {
			$basename = sanitize_text_field( (string) $basename );
			$rule     = sanitize_text_field( (string) $rule );
			if ( '' === $basename || ( 'allow' !== $rule && 'deny' !== $rule ) ) {
				continue;
			}

			$name = $basename;
			if ( isset( $plugins[ $basename ]['Name'] ) && '' !== (string) $plugins[ $basename ]['Name'] ) {
				$name = (string) $plugins[ $basename ]['Name'];
			}

			$family_bits = array();
			if ( isset( $ops[ $basename ] ) && is_array( $ops[ $basename ] ) ) {
				foreach ( $ops[ $basename ] as $family => $family_rule ) {
					if ( 'allow' !== $family_rule && 'deny' !== $family_rule ) {
						continue;
					}
					$fl = isset( $labels[ $family ] ) ? (string) $labels[ $family ] : (string) $family;
					$family_bits[] = $fl . ': ' . $family_rule;
				}
			}

			$expires_label = '';
			if ( 'allow' === $rule && isset( $expires[ $basename ] ) ) {
				$ts = (int) $expires[ $basename ];
				if ( $ts > 0 ) {
					if ( $ts <= $now ) {
						$expires_label = __( 'Expired', 'handl-ai-connector-access-control' );
					} else {
						$expires_label = wp_date( 'Y-m-d H:i', $ts );
					}
				}
			}

			$out[] = array(
				'basename'       => $basename,
				'label'          => $name,
				'rule_label'     => 'allow' === $rule
					? __( 'Allow', 'handl-ai-connector-access-control' )
					: __( 'Deny', 'handl-ai-connector-access-control' ),
				'families_label' => empty( $family_bits )
					? __( 'Follow plugin rule', 'handl-ai-connector-access-control' )
					: implode( '; ', $family_bits ),
				'expires_label'  => $expires_label,
				'note'           => isset( $notes[ $basename ] ) ? (string) $notes[ $basename ] : '',
			);
		}

		usort(
			$out,
			static function ( $a, $b ) {
				return strcasecmp( (string) ( $a['label'] ?? '' ), (string) ( $b['label'] ?? '' ) );
			}
		);

		return $out;
	}

	/**
	 * @param array<string,mixed> $policy
	 * @return array{summary:string,items:list<string>}
	 */
	public static function denied_tools_snapshot( array $policy ): array {
		$tools = is_array( $policy['denied_tools'] ?? null ) ? (array) $policy['denied_tools'] : array();
		$items = array();
		foreach ( $tools as $tool ) {
			$tool = sanitize_text_field( (string) $tool );
			if ( '' !== $tool ) {
				$items[] = $tool;
			}
		}
		sort( $items );

		if ( empty( $items ) ) {
			return array(
				'summary' => __( 'None configured.', 'handl-ai-connector-access-control' ),
				'items'   => array(),
			);
		}

		return array(
			'summary' => sprintf(
				/* translators: %d: number of blocked tools */
				_n( '%d blocked tool configured.', '%d blocked tools configured.', count( $items ), 'handl-ai-connector-access-control' ),
				count( $items )
			),
			'items'   => $items,
		);
	}

	/**
	 * @param array<string,mixed> $policy
	 * @return array<string,string>
	 */
	public static function policy_mode_snapshot( array $policy ): array {
		$default = ( $policy['default'] ?? 'allow' ) === 'deny' ? 'deny' : 'allow';
		$unknown = Policy::sanitize_unknown_operation( $policy['unknown_operation'] ?? 'inherit' );

		$unknown_labels = array(
			'inherit' => __( 'Follow plugin rule', 'handl-ai-connector-access-control' ),
			'allow'   => __( 'Allow', 'handl-ai-connector-access-control' ),
			'deny'    => __( 'Deny', 'handl-ai-connector-access-control' ),
		);

		$allowed = Policy::sanitize_allowed_roles( $policy['allowed_roles'] ?? array() );
		$role_label = ! empty( $policy['role_gate_enabled'] )
			? sprintf(
				/* translators: %d: number of allowed roles */
				_n( 'On (%d role allowed)', 'On (%d roles allowed)', count( $allowed ), 'handl-ai-connector-access-control' ),
				count( $allowed )
			)
			: __( 'Off', 'handl-ai-connector-access-control' );

		return array(
			'default_label'           => 'deny' === $default
				? __( 'Deny', 'handl-ai-connector-access-control' )
				: __( 'Allow', 'handl-ai-connector-access-control' ),
			'audit_only_label'        => ! empty( $policy['audit_only'] )
				? __( 'On', 'handl-ai-connector-access-control' )
				: __( 'Off', 'handl-ai-connector-access-control' ),
			'log_enabled_label'       => ( ! empty( $policy['log_enabled'] ) || ! empty( $policy['audit_only'] ) )
				? __( 'On', 'handl-ai-connector-access-control' )
				: __( 'Off', 'handl-ai-connector-access-control' ),
			'kill_switch_label'       => ! empty( $policy['kill_switch'] )
				? __( 'On', 'handl-ai-connector-access-control' )
				: __( 'Off', 'handl-ai-connector-access-control' ),
			'shadow_block_label'      => ! empty( $policy['shadow_block_enabled'] )
				? __( 'On', 'handl-ai-connector-access-control' )
				: __( 'Off', 'handl-ai-connector-access-control' ),
			'role_gate_label'         => $role_label,
			'unknown_operation_label' => $unknown_labels[ $unknown ] ?? $unknown_labels['inherit'],
		);
	}

	/**
	 * Compare estimated spend from REST summary to configured thresholds.
	 *
	 * @param array<string,mixed> $policy
	 * @param array<string,mixed> $summary Rest::build_activity_summary result.
	 * @return list<array<string,mixed>>
	 */
	public static function threshold_snapshot( array $policy, array $summary ): array {
		$est = isset( $summary['estimated_spend_usd'] ) ? (float) $summary['estimated_spend_usd'] : null;
		$out = array();

		$site = Spend_Threshold::sanitize_threshold( $policy['spend_threshold_site'] ?? null );
		if ( null !== $site ) {
			$out[] = array(
				'scope'     => 'site',
				'label'     => __( 'Site-wide', 'handl-ai-connector-access-control' ),
				'threshold' => $site,
				'estimated' => $est,
				'crossed'   => null !== $est && $est >= $site,
			);
		}

		$plugin_thresholds = Spend_Threshold::sanitize_plugin_thresholds( $policy['spend_threshold_plugins'] ?? array() );
		$top             = is_array( $summary['top_plugins'] ?? null ) ? (array) $summary['top_plugins'] : array();
		foreach ( $plugin_thresholds as $basename => $threshold ) {
			$plugin_est = null;
			foreach ( $top as $row ) {
				if ( ! is_array( $row ) ) {
					continue;
				}
				if ( isset( $row['plugin'] ) && (string) $row['plugin'] === $basename ) {
					if ( isset( $row['estimated_usd'] ) ) {
						$plugin_est = (float) $row['estimated_usd'];
					}
					break;
				}
			}
			$out[] = array(
				'scope'     => 'plugin',
				'label'     => $basename,
				'threshold' => $threshold,
				'estimated' => $plugin_est,
				'crossed'   => null !== $plugin_est && $plugin_est >= $threshold,
			);
		}

		return $out;
	}

	/**
	 * @param array<string,mixed> $activity
	 * @param list<array<string,mixed>> $families
	 * @param list<array<string,mixed>> $thresholds
	 */
	private static function render_activity_section( array $activity, array $families, array $thresholds ): string {
		$status = isset( $activity['status'] ) ? (string) $activity['status'] : '';

		if ( 'logging_disabled' === $status ) {
			return '<p class="muted">' . esc_html__( 'Activity logging and Learn mode are both off. Turn on logging or Learn mode to populate this section.', 'handl-ai-connector-access-control' ) . '</p>';
		}
		if ( 'no_data' === $status ) {
			return '<p class="muted">' . esc_html__( 'No saved activity in this window.', 'handl-ai-connector-access-control' ) . '</p>';
		}

		ob_start();
		echo '<table><tbody>';
		if ( isset( $activity['ai_client_call_count'] ) ) {
			self::render_kv_row(
				__( 'AI Client calls', 'handl-ai-connector-access-control' ),
				number_format_i18n( (int) $activity['ai_client_call_count'] )
			);
		}
		if ( isset( $activity['shadow_ai_observation_count'] ) ) {
			self::render_kv_row(
				__( 'Direct AI connections detected', 'handl-ai-connector-access-control' ),
				number_format_i18n( (int) $activity['shadow_ai_observation_count'] )
			);
		}
		if ( isset( $activity['estimated_spend_usd'] ) ) {
			self::render_kv_row(
				__( 'Estimated spend (window)', 'handl-ai-connector-access-control' ),
				'$' . Cost::format_usd( (float) $activity['estimated_spend_usd'] )
			);
		}
		echo '</tbody></table>';

		$by_decision = is_array( $activity['calls_by_decision'] ?? null ) ? $activity['calls_by_decision'] : array();
		if ( ! empty( $by_decision ) ) {
			echo '<h3>' . esc_html__( 'Calls by decision', 'handl-ai-connector-access-control' ) . '</h3>';
			echo '<table><thead><tr><th>' . esc_html__( 'Decision', 'handl-ai-connector-access-control' ) . '</th><th class="num">' . esc_html__( 'Calls', 'handl-ai-connector-access-control' ) . '</th></tr></thead><tbody>';
			foreach ( $by_decision as $decision => $count ) {
				echo '<tr><td>' . esc_html( (string) $decision ) . '</td><td class="num">' . esc_html( number_format_i18n( (int) $count ) ) . '</td></tr>';
			}
			echo '</tbody></table>';
		}

		if ( ! empty( $families ) ) {
			echo '<h3>' . esc_html__( 'Calls by AI type', 'handl-ai-connector-access-control' ) . '</h3>';
			echo '<table><thead><tr><th>' . esc_html__( 'AI type', 'handl-ai-connector-access-control' ) . '</th><th class="num">' . esc_html__( 'Calls', 'handl-ai-connector-access-control' ) . '</th></tr></thead><tbody>';
			foreach ( $families as $row ) {
				if ( ! is_array( $row ) ) {
					continue;
				}
				echo '<tr><td>' . esc_html( (string) ( $row['label'] ?? '' ) ) . '</td><td class="num">' . esc_html( number_format_i18n( (int) ( $row['calls'] ?? 0 ) ) ) . '</td></tr>';
			}
			echo '</tbody></table>';
		}

		$top = is_array( $activity['top_plugins'] ?? null ) ? $activity['top_plugins'] : array();
		if ( ! empty( $top ) ) {
			echo '<h3>' . esc_html__( 'Top plugins (window)', 'handl-ai-connector-access-control' ) . '</h3>';
			echo '<table><thead><tr><th>' . esc_html__( 'Plugin', 'handl-ai-connector-access-control' ) . '</th><th class="num">' . esc_html__( 'Calls', 'handl-ai-connector-access-control' ) . '</th><th class="num">' . esc_html__( 'Est. spend', 'handl-ai-connector-access-control' ) . '</th></tr></thead><tbody>';
			foreach ( $top as $row ) {
				if ( ! is_array( $row ) ) {
					continue;
				}
				$plugin = isset( $row['plugin'] ) ? (string) $row['plugin'] : __( '(unknown)', 'handl-ai-connector-access-control' );
				$est_cell = isset( $row['estimated_usd'] )
					? '$' . Cost::format_usd( (float) $row['estimated_usd'] )
					: '—';
				echo '<tr><td><code>' . esc_html( $plugin ) . '</code></td><td class="num">' . esc_html( number_format_i18n( (int) ( $row['calls'] ?? 0 ) ) ) . '</td><td class="num">' . esc_html( $est_cell ) . '</td></tr>';
			}
			echo '</tbody></table>';
		}

		if ( ! empty( $thresholds ) ) {
			echo '<h3>' . esc_html__( 'Estimated spend vs alerts', 'handl-ai-connector-access-control' ) . '</h3>';
			echo '<table><thead><tr><th>' . esc_html__( 'Scope', 'handl-ai-connector-access-control' ) . '</th><th class="num">' . esc_html__( 'Alert at', 'handl-ai-connector-access-control' ) . '</th><th class="num">' . esc_html__( 'Estimated', 'handl-ai-connector-access-control' ) . '</th><th>' . esc_html__( 'Crossed', 'handl-ai-connector-access-control' ) . '</th></tr></thead><tbody>';
			foreach ( $thresholds as $row ) {
				if ( ! is_array( $row ) ) {
					continue;
				}
				$est = isset( $row['estimated'] ) && null !== $row['estimated']
					? '$' . Cost::format_usd( (float) $row['estimated'] )
					: '—';
				$crossed = ! empty( $row['crossed'] )
					? __( 'Yes', 'handl-ai-connector-access-control' )
					: __( 'No', 'handl-ai-connector-access-control' );
				echo '<tr><td>' . esc_html( (string) ( $row['label'] ?? '' ) ) . '</td><td class="num">$' . esc_html( Cost::format_usd( (float) ( $row['threshold'] ?? 0 ) ) ) . '</td><td class="num">' . esc_html( $est ) . '</td><td>' . esc_html( $crossed ) . '</td></tr>';
			}
			echo '</tbody></table>';
		}

		return (string) ob_get_clean();
	}

	private static function render_kv_row( string $label, string $value ): void {
		echo '<tr><th scope="row">' . esc_html( $label ) . '</th><td>' . esc_html( $value ) . '</td></tr>';
	}

	private static function window_label( string $window ): string {
		$labels = array(
			'1d'  => __( 'Last 24 hours', 'handl-ai-connector-access-control' ),
			'7d'  => __( 'Last 7 days', 'handl-ai-connector-access-control' ),
			'30d' => __( 'Last 30 days', 'handl-ai-connector-access-control' ),
			'all' => __( 'All saved activity', 'handl-ai-connector-access-control' ),
		);
		return $labels[ $window ] ?? $labels['7d'];
	}
}
