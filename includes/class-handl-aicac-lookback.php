<?php
/**
 * AICAC-LOOKBACK (#503): provider incident exposure report.
 *
 * Read-only over retained Activity. No new collection, no retention change,
 * no outbound calls, no policy writes. Own submenu + Insights footer inject.
 * PII-WARN / Luggage / Incident / Cost are class_exists-guarded reads.
 * CSV reuses Audit_Export::build_csv with a lookback context tag.
 *
 * README-FREE. Zero edits to admin.php, pii-warn.php, luggage.php,
 * incident.php, cost.php, or readme.txt.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * One-screen scoped exposure report: what this site sent a provider in a window.
 */
final class Lookback {

	public const PAGE_SLUG = 'handl-aicac-lookback';

	public const ACTION_EXPORT = 'handl_aicac_lookback_export';

	public const CONTEXT_TAG = 'lookback';

	public const HEADER_CONTEXT = 'X-AICAC-Export-Context';

	public const FRAMING = 'report_only_never_collects';

	public const MAX_CONTENT_REFS = 20;

	/** @var bool */
	private static $registered = false;

	/** @var list<array<string,mixed>>|null */
	private static $test_log = null;

	/** @var list<array<string,mixed>>|null */
	private static $test_shipments = null;

	/** @var int|null */
	private static $test_now = null;

	/** @var array<string,mixed>|null */
	private static $test_policy = null;

	/** @var array<string,array<string,mixed>>|null */
	private static $test_incidents = null;

	public static function init(): void {
		if ( self::$registered ) {
			return;
		}
		self::$registered = true;
		add_action( 'admin_menu', array( self::class, 'register_menu' ), 20 );
		add_action( 'admin_post_' . self::ACTION_EXPORT, array( self::class, 'handle_export' ) );
		add_action( 'admin_footer', array( self::class, 'maybe_inject_provider_map' ), 40 );
	}

	public static function reset_for_tests(): void {
		self::$registered     = false;
		self::$test_log       = null;
		self::$test_shipments = null;
		self::$test_now       = null;
		self::$test_policy    = null;
		self::$test_incidents = null;
	}

	/**
	 * @param list<array<string,mixed>>|null $log Injected activity rows.
	 */
	public static function set_test_log( ?array $log ): void {
		self::$test_log = $log;
	}

	/**
	 * @param list<array<string,mixed>>|null $rows Injected Luggage shipments.
	 */
	public static function set_test_shipments( ?array $rows ): void {
		self::$test_shipments = $rows;
	}

	public static function set_test_now( ?int $now ): void {
		self::$test_now = $now;
	}

	/**
	 * @param array<string,mixed>|null $policy
	 */
	public static function set_test_policy( ?array $policy ): void {
		self::$test_policy = $policy;
	}

	/**
	 * @param array<string,array<string,mixed>>|null $incidents id => incident.
	 */
	public static function set_test_incidents( ?array $incidents ): void {
		self::$test_incidents = $incidents;
	}

	public static function now(): int {
		if ( null !== self::$test_now ) {
			return (int) self::$test_now;
		}
		if ( class_exists( Clock::class, false ) && method_exists( Clock::class, 'now' ) ) {
			return (int) Clock::now();
		}

		return time();
	}

	public static function register_menu(): void {
		if ( ! class_exists( Caps::class, false ) || ! Caps::user_can_view() ) {
			return;
		}
		if ( ! function_exists( 'add_submenu_page' ) || ! class_exists( Admin::class, false ) ) {
			return;
		}
		add_submenu_page(
			Admin::MENU_SLUG,
			__( 'Exposure lookback', 'handl-ai-connector-access-control' ),
			__( 'Exposure lookback', 'handl-ai-connector-access-control' ),
			Caps::VIEW,
			self::PAGE_SLUG,
			array( self::class, 'render_page' )
		);
	}

	public static function render_page(): void {
		if ( ! class_exists( Caps::class, false ) || ! Caps::user_can_view() ) {
			return;
		}

		$input = self::request_input();

		echo '<div class="wrap">';
		echo '<h1>' . esc_html__( 'Exposure lookback', 'handl-ai-connector-access-control' ) . '</h1>';
		echo '<p class="description">' . esc_html__( 'See what this site sent one AI provider in a date window. This report only reads saved Activity. It does not collect new data or change policy.', 'handl-ai-connector-access-control' ) . '</p>';

		self::render_form( $input );

		if ( ! $input['ready'] ) {
			echo '<p>' . esc_html__( 'Choose a provider and date window.', 'handl-ai-connector-access-control' ) . '</p>';
			echo '</div>';

			return;
		}

		$report = self::report( $input['provider'], $input['from_ts'], $input['to_ts'], $input['plugin'] );
		self::render_report( $report, $input );
		echo '</div>';
	}

	public static function handle_export(): void {
		if ( ! class_exists( Caps::class, false ) || ! Caps::user_can_view() ) {
			self::die_forbidden();

			return;
		}
		if ( function_exists( 'check_admin_referer' ) ) {
			check_admin_referer( self::ACTION_EXPORT );
		}

		$provider = self::normalize_provider( isset( $_POST['provider'] ) ? (string) wp_unslash( $_POST['provider'] ) : '' ); // phpcs:ignore WordPress.Security.NonceVerification.Missing
		$from_raw = isset( $_POST['from'] ) ? sanitize_text_field( wp_unslash( (string) $_POST['from'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing
		$to_raw   = isset( $_POST['to'] ) ? sanitize_text_field( wp_unslash( (string) $_POST['to'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing
		$plugin   = self::sanitize_plugin( isset( $_POST['plugin'] ) ? (string) wp_unslash( $_POST['plugin'] ) : '' ); // phpcs:ignore WordPress.Security.NonceVerification.Missing
		$from_ts  = self::day_start_ts( $from_raw );
		$to_ts    = self::day_end_ts( $to_raw );
		if ( '' === $provider || $from_ts <= 0 || $to_ts <= 0 || $from_ts > $to_ts ) {
			self::die_forbidden();

			return;
		}

		$csv = self::csv( $provider, $from_ts, $to_ts, $plugin );
		$name = self::export_filename( $provider, $from_ts, $to_ts );
		if ( function_exists( 'nocache_headers' ) ) {
			nocache_headers();
		}
		header( 'Content-Type: text/csv; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename=' . $name );
		header( self::HEADER_CONTEXT . ': ' . self::CONTEXT_TAG );
		echo $csv; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- CSV download.
		exit;
	}

	/**
	 * Insights "Who talks to whom" table: add Run exposure lookback per provider.
	 * Zero edits to admin.php — Detour-style admin_footer inject.
	 */
	public static function maybe_inject_provider_map(): void {
		if ( ! class_exists( Caps::class, false ) || ! Caps::user_can_view() ) {
			return;
		}
		if ( ! self::is_insights_screen() ) {
			return;
		}
		$base = admin_url( 'admin.php?page=' . self::PAGE_SLUG );
		$payload = function_exists( 'wp_json_encode' )
			? wp_json_encode(
				array(
					'url'   => $base,
					'label' => __( 'Run exposure lookback', 'handl-ai-connector-access-control' ),
				)
			)
			: '';
		if ( ! is_string( $payload ) || '' === $payload ) {
			return;
		}

		echo '<script id="handl-aicac-lookback-map">(function(){';
		echo 'var cfg=' . $payload . ';'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- JSON.
		echo 'if(!cfg||!cfg.url)return;';
		echo 'var table=document.querySelector(".handl-aicac-provider-map-table");if(!table)return;';
		echo 'var seen={};';
		echo 'var trs=table.querySelectorAll("tbody tr");';
		echo 'for(var i=0;i<trs.length;i++){';
		echo 'var tds=trs[i].querySelectorAll("td");if(tds.length<2)continue;';
		echo 'var cell=tds[1];';
		echo 'if(cell.querySelector(".handl-aicac-lookback-run"))continue;';
		echo 'var a=cell.querySelector("a");';
		echo 'var provider="";';
		echo 'if(a&&a.href){var m=a.href.match(/handl_aicac_log_provider=([^&#]+)/);if(m){try{provider=decodeURIComponent(m[1]);}catch(e){provider=m[1];}}}';
		echo 'if(!provider&&a){provider=(a.textContent||"").replace(/\\s+/g," ").trim();}';
		echo 'if(!provider)continue;';
		echo 'if(seen[provider])continue;seen[provider]=true;';
		echo 'var sep=document.createTextNode(" ");';
		echo 'var link=document.createElement("a");';
		echo 'link.className="handl-aicac-lookback-run";';
		echo 'link.href=cfg.url+(cfg.url.indexOf("?")>=0?"&":"?")+"provider="+encodeURIComponent(provider);';
		echo 'link.textContent=cfg.label;';
		echo 'cell.appendChild(sep);cell.appendChild(link);';
		echo '}';
		echo '})();</script>';
	}

	/**
	 * Scoped exposure totals for one provider + window.
	 *
	 * @return array{
	 *   provider:string,
	 *   from_ts:int,
	 *   to_ts:int,
	 *   plugin:string,
	 *   call_count:int,
	 *   plugins:list<string>,
	 *   operations:array<string,int>,
	 *   families:array<string,int>,
	 *   pii_hits:array<string,int>,
	 *   media_grades:array<string,array{plugin:string,grade:string,label:string}>,
	 *   spend_usd:?float,
	 *   content_refs:list<array{kind:string,label:string}>,
	 *   retention_precede_days:int,
	 *   retention_notice:string
	 * }
	 */
	public static function report( string $provider, int $from_ts, int $to_ts, string $plugin = '' ): array {
		$provider = self::normalize_provider( $provider );
		$plugin   = self::sanitize_plugin( $plugin );
		$rows     = self::scoped_rows( $provider, $from_ts, $to_ts, $plugin );

		$plugins    = array();
		$operations = array();
		$families   = array();
		$pii_hits   = array();
		$spend      = 0.0;
		$spend_any  = false;
		$refs       = array();
		$policy     = self::live_policy();

		foreach ( $rows as $row ) {
			$plug = trim( (string) ( $row['plugin'] ?? '' ) );
			if ( '' !== $plug ) {
				$plugins[ $plug ] = true;
			}
			$op = trim( (string) ( $row['operation'] ?? '' ) );
			if ( '' !== $op ) {
				$operations[ $op ] = ( $operations[ $op ] ?? 0 ) + 1;
			}
			$family = trim( (string) ( $row['capability_family'] ?? '' ) );
			if ( '' === $family && '' !== $op && class_exists( Operations::class, false ) && method_exists( Operations::class, 'family_from_operation' ) ) {
				$family = (string) Operations::family_from_operation( $op );
			}
			if ( '' !== $family ) {
				$families[ $family ] = ( $families[ $family ] ?? 0 ) + 1;
			}

			self::accumulate_pii( $row, $pii_hits );

			$usd = self::row_spend( $row, $policy );
			if ( null !== $usd ) {
				$spend    += $usd;
				$spend_any = true;
			}

			$preview = trim( (string) ( $row['prompt_preview'] ?? '' ) );
			if ( '' !== $preview && count( $refs ) < self::MAX_CONTENT_REFS ) {
				$refs[] = array(
					'kind'  => 'prompt',
					'label' => self::truncate_ref( $preview ),
				);
			}
		}

		$plugin_list = array_keys( $plugins );
		sort( $plugin_list, SORT_STRING );
		ksort( $operations, SORT_STRING );
		ksort( $families, SORT_STRING );
		ksort( $pii_hits, SORT_STRING );

		$media = self::media_grades( $provider, $from_ts, $to_ts, $plugin, $plugin_list );
		foreach ( $media as $item ) {
			$file = (string) ( $item['filename'] ?? '' );
			if ( '' !== $file && count( $refs ) < self::MAX_CONTENT_REFS ) {
				$refs[] = array(
					'kind'  => 'file',
					'label' => $file,
				);
			}
		}

		$precede = self::retention_precede_days( $from_ts, $to_ts );
		$notice  = '';
		if ( $precede > 0 ) {
			$notice = sprintf(
				/* translators: %d: number of days that fall before retained Activity. */
				__( '%d days of this window precede retention.', 'handl-ai-connector-access-control' ),
				$precede
			);
		}

		return array(
			'provider'                => $provider,
			'from_ts'                 => $from_ts,
			'to_ts'                   => $to_ts,
			'plugin'                  => $plugin,
			'call_count'              => count( $rows ),
			'plugins'                 => $plugin_list,
			'operations'              => $operations,
			'families'                => $families,
			'pii_hits'                => $pii_hits,
			'media_grades'            => $media,
			'spend_usd'               => $spend_any ? $spend : null,
			'content_refs'            => $refs,
			'retention_precede_days'  => $precede,
			'retention_notice'        => $notice,
		);
	}

	/**
	 * CSV of scoped rows via Audit_Export. Empty string when the helper is missing.
	 */
	public static function csv( string $provider, int $from_ts, int $to_ts, string $plugin = '' ): string {
		if ( ! class_exists( Audit_Export::class, false ) || ! method_exists( Audit_Export::class, 'build_csv' ) ) {
			return '';
		}
		$rows    = self::scoped_rows( $provider, $from_ts, $to_ts, $plugin );
		$plugins = function_exists( 'get_plugins' ) ? get_plugins() : array();
		if ( ! is_array( $plugins ) ) {
			$plugins = array();
		}
		$empty = array(
			'decision'  => '',
			'operation' => '',
			'provider'  => '',
			'model'     => '',
			'plugin'    => '',
			'source'    => '',
		);

		return Audit_Export::build_csv( $rows, $empty, $plugins, self::live_policy() );
	}

	public static function export_filename( string $provider, int $from_ts, int $to_ts ): string {
		$provider = self::normalize_provider( $provider );
		if ( '' === $provider ) {
			$provider = 'provider';
		}

		return sprintf(
			'aicac-lookback-%s-%s-%s.csv',
			$provider,
			gmdate( 'Ymd', max( 0, $from_ts ) ),
			gmdate( 'Ymd', max( 0, $to_ts ) )
		);
	}

	/**
	 * @return list<array<string,mixed>>
	 */
	public static function scoped_rows( string $provider, int $from_ts, int $to_ts, string $plugin = '' ): array {
		$provider = self::normalize_provider( $provider );
		$plugin   = self::sanitize_plugin( $plugin );
		$out      = array();
		if ( '' === $provider || $from_ts <= 0 || $to_ts <= 0 || $from_ts > $to_ts ) {
			return $out;
		}
		foreach ( self::log_rows() as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$ts = isset( $row['ts'] ) ? (int) $row['ts'] : 0;
			if ( $ts < $from_ts || $ts > $to_ts ) {
				continue;
			}
			if ( ! self::row_matches_provider( $row, $provider ) ) {
				continue;
			}
			if ( '' !== $plugin && trim( (string) ( $row['plugin'] ?? '' ) ) !== $plugin ) {
				continue;
			}
			$out[] = $row;
		}

		return $out;
	}

	public static function page_url( string $provider = '', string $from = '', string $to = '', string $plugin = '' ): string {
		$args = array( 'page' => self::PAGE_SLUG );
		if ( '' !== $provider ) {
			$args['provider'] = self::normalize_provider( $provider );
		}
		if ( '' !== $from ) {
			$args['from'] = $from;
		}
		if ( '' !== $to ) {
			$args['to'] = $to;
		}
		if ( '' !== $plugin ) {
			$args['plugin'] = $plugin;
		}

		return add_query_arg( $args, admin_url( 'admin.php' ) );
	}

	/**
	 * @return array{provider:string,from:string,to:string,plugin:string,incident:string,from_ts:int,to_ts:int,ready:bool}
	 */
	public static function request_input(): array {
		$provider = self::normalize_provider( isset( $_GET['provider'] ) ? (string) wp_unslash( $_GET['provider'] ) : '' ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$from     = isset( $_GET['from'] ) ? sanitize_text_field( wp_unslash( (string) $_GET['from'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$to       = isset( $_GET['to'] ) ? sanitize_text_field( wp_unslash( (string) $_GET['to'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$plugin   = self::sanitize_plugin( isset( $_GET['plugin'] ) ? (string) wp_unslash( $_GET['plugin'] ) : '' ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$incident = isset( $_GET['incident'] ) ? sanitize_key( wp_unslash( (string) $_GET['incident'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended

		if ( '' !== $incident ) {
			$inc = self::incident_by_id( $incident );
			if ( is_array( $inc ) ) {
				$started = isset( $inc['started_ts'] ) ? (int) $inc['started_ts'] : 0;
				$ended   = isset( $inc['ended_ts'] ) ? (int) $inc['ended_ts'] : 0;
				if ( $started > 0 && '' === $from ) {
					$from = gmdate( 'Y-m-d', $started );
				}
				if ( $ended > 0 && '' === $to ) {
					$to = gmdate( 'Y-m-d', $ended );
				}
			}
		}

		$from_ts = self::day_start_ts( $from );
		$to_ts   = self::day_end_ts( $to );

		return array(
			'provider' => $provider,
			'from'     => $from,
			'to'       => $to,
			'plugin'   => $plugin,
			'incident' => $incident,
			'from_ts'  => $from_ts,
			'to_ts'    => $to_ts,
			'ready'    => ( '' !== $provider && $from_ts > 0 && $to_ts > 0 && $from_ts <= $to_ts ),
		);
	}

	/**
	 * @param array{provider:string,from:string,to:string,plugin:string,incident:string} $input
	 */
	private static function render_form( array $input ): void {
		echo '<form method="get" action="' . esc_url( admin_url( 'admin.php' ) ) . '" class="handl-aicac-lookback-form">';
		echo '<input type="hidden" name="page" value="' . esc_attr( self::PAGE_SLUG ) . '" />';
		echo '<table class="form-table" role="presentation"><tbody>';

		echo '<tr><th scope="row"><label for="handl-aicac-lookback-provider">' . esc_html__( 'Provider', 'handl-ai-connector-access-control' ) . '</label></th><td>';
		echo '<select id="handl-aicac-lookback-provider" name="provider">';
		echo '<option value="">' . esc_html__( 'Choose a provider', 'handl-ai-connector-access-control' ) . '</option>';
		foreach ( self::provider_choices() as $id ) {
			echo '<option value="' . esc_attr( $id ) . '"' . selected( $input['provider'], $id, false ) . '>' . esc_html( $id ) . '</option>';
		}
		echo '</select></td></tr>';

		echo '<tr><th scope="row"><label for="handl-aicac-lookback-from">' . esc_html__( 'From', 'handl-ai-connector-access-control' ) . '</label></th><td>';
		echo '<input type="date" id="handl-aicac-lookback-from" name="from" value="' . esc_attr( $input['from'] ) . '" />';
		echo '</td></tr>';

		echo '<tr><th scope="row"><label for="handl-aicac-lookback-to">' . esc_html__( 'To', 'handl-ai-connector-access-control' ) . '</label></th><td>';
		echo '<input type="date" id="handl-aicac-lookback-to" name="to" value="' . esc_attr( $input['to'] ) . '" />';
		echo '</td></tr>';

		echo '<tr><th scope="row"><label for="handl-aicac-lookback-plugin">' . esc_html__( 'Connector (optional)', 'handl-ai-connector-access-control' ) . '</label></th><td>';
		echo '<input type="text" id="handl-aicac-lookback-plugin" name="plugin" value="' . esc_attr( $input['plugin'] ) . '" class="regular-text" />';
		echo '</td></tr>';

		echo '</tbody></table>';
		if ( function_exists( 'submit_button' ) ) {
			submit_button( __( 'Run lookback', 'handl-ai-connector-access-control' ), 'primary', 'submit', false );
		} else {
			echo '<p><button type="submit" class="button button-primary">' . esc_html__( 'Run lookback', 'handl-ai-connector-access-control' ) . '</button></p>';
		}
		echo '</form>';
	}

	/**
	 * @param array<string,mixed> $report
	 * @param array{provider:string,from:string,to:string,plugin:string} $input
	 */
	private static function render_report( array $report, array $input ): void {
		$notice = (string) ( $report['retention_notice'] ?? '' );
		if ( '' !== $notice ) {
			echo '<div class="notice notice-warning inline"><p>' . esc_html( $notice ) . '</p></div>';
		}

		echo '<h2>' . esc_html__( 'Exposure in this window', 'handl-ai-connector-access-control' ) . '</h2>';
		echo '<table class="widefat striped handl-aicac-lookback-summary" style="max-width:52em;"><tbody>';

		echo '<tr><th scope="row">' . esc_html__( 'Calls', 'handl-ai-connector-access-control' ) . '</th><td>' . esc_html( (string) (int) $report['call_count'] ) . '</td></tr>';

		$plugin_cell = empty( $report['plugins'] )
			? '—'
			: implode( ', ', array_map( 'strval', $report['plugins'] ) );
		echo '<tr><th scope="row">' . esc_html__( 'Plugins', 'handl-ai-connector-access-control' ) . '</th><td>' . esc_html( $plugin_cell ) . '</td></tr>';

		$op_bits = array();
		foreach ( (array) $report['operations'] as $op => $count ) {
			$op_bits[] = $op . ' (' . (int) $count . ')';
		}
		$fam_bits = array();
		foreach ( (array) $report['families'] as $fam => $count ) {
			$fam_bits[] = self::family_label( (string) $fam ) . ' (' . (int) $count . ')';
		}
		$ops_cell = empty( $op_bits ) && empty( $fam_bits ) ? '—' : implode( ', ', array_merge( $op_bits, $fam_bits ) );
		echo '<tr><th scope="row">' . esc_html__( 'Operations', 'handl-ai-connector-access-control' ) . '</th><td>' . esc_html( $ops_cell ) . '</td></tr>';

		$pii_bits = array();
		foreach ( (array) $report['pii_hits'] as $type => $count ) {
			$pii_bits[] = self::pii_label( (string) $type ) . ' (' . (int) $count . ')';
		}
		$pii_cell = empty( $pii_bits ) ? '—' : implode( ', ', $pii_bits );
		echo '<tr><th scope="row">' . esc_html__( 'Personal information pattern hits', 'handl-ai-connector-access-control' ) . '</th><td>' . esc_html( $pii_cell ) . '</td></tr>';

		$media_bits = array();
		foreach ( (array) $report['media_grades'] as $item ) {
			$media_bits[] = (string) $item['plugin'] . ': ' . (string) $item['label'];
		}
		$media_cell = empty( $media_bits ) ? '—' : implode( '; ', $media_bits );
		echo '<tr><th scope="row">' . esc_html__( 'Outbound media', 'handl-ai-connector-access-control' ) . '</th><td>' . esc_html( $media_cell ) . '</td></tr>';

		$spend = $report['spend_usd'];
		if ( null === $spend ) {
			$spend_cell = __( 'Spend unknown', 'handl-ai-connector-access-control' );
		} elseif ( class_exists( Cost::class, false ) && method_exists( Cost::class, 'format_usd' ) ) {
			$spend_cell = Cost::format_usd( (float) $spend );
		} else {
			$spend_cell = '$' . number_format( (float) $spend, 2, '.', ',' );
		}
		echo '<tr><th scope="row">' . esc_html__( 'Estimated spend', 'handl-ai-connector-access-control' ) . '</th><td>' . esc_html( $spend_cell ) . '</td></tr>';
		echo '</tbody></table>';

		if ( ! empty( $report['content_refs'] ) ) {
			echo '<h3>' . esc_html__( 'Content still in the saved log', 'handl-ai-connector-access-control' ) . '</h3>';
			echo '<ul class="ul-disc">';
			foreach ( $report['content_refs'] as $ref ) {
				echo '<li>' . esc_html( (string) ( $ref['label'] ?? '' ) ) . '</li>';
			}
			echo '</ul>';
		}

		if ( (int) $report['call_count'] < 1 ) {
			echo '<p>' . esc_html__( 'No matching calls in this window.', 'handl-ai-connector-access-control' ) . '</p>';
		}

		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" class="handl-aicac-lookback-export">';
		echo '<input type="hidden" name="action" value="' . esc_attr( self::ACTION_EXPORT ) . '" />';
		echo '<input type="hidden" name="provider" value="' . esc_attr( $input['provider'] ) . '" />';
		echo '<input type="hidden" name="from" value="' . esc_attr( $input['from'] ) . '" />';
		echo '<input type="hidden" name="to" value="' . esc_attr( $input['to'] ) . '" />';
		echo '<input type="hidden" name="plugin" value="' . esc_attr( $input['plugin'] ) . '" />';
		if ( function_exists( 'wp_nonce_field' ) ) {
			wp_nonce_field( self::ACTION_EXPORT );
		}
		if ( function_exists( 'submit_button' ) ) {
			submit_button( __( 'Download CSV', 'handl-ai-connector-access-control' ), 'secondary', 'submit', false );
		} else {
			echo '<p><button type="submit" class="button">' . esc_html__( 'Download CSV', 'handl-ai-connector-access-control' ) . '</button></p>';
		}
		echo '</form>';
	}

	/**
	 * @return list<array<string,mixed>>
	 */
	private static function log_rows(): array {
		if ( null !== self::$test_log ) {
			return array_values( self::$test_log );
		}
		$key = class_exists( Plugin::class, false ) ? Plugin::LOG_OPTION_KEY : 'handl_aicac_recent_calls';
		$raw = get_option( $key, array() );
		if ( ! is_array( $raw ) ) {
			return array();
		}
		$out = array();
		foreach ( $raw as $row ) {
			if ( is_array( $row ) ) {
				$out[] = $row;
			}
		}

		return $out;
	}

	/**
	 * @return array<string,mixed>
	 */
	private static function live_policy(): array {
		if ( is_array( self::$test_policy ) ) {
			return self::$test_policy;
		}
		if ( class_exists( Policy::class, false ) && method_exists( Policy::class, 'get_policy' ) ) {
			$policy = Policy::get_policy();

			return is_array( $policy ) ? $policy : array();
		}

		return array();
	}

	/**
	 * @param array<string,mixed> $row
	 */
	private static function row_matches_provider( array $row, string $want ): bool {
		if ( '' === $want ) {
			return false;
		}
		$ids = array(
			self::normalize_provider( (string) ( $row['provider'] ?? '' ) ),
			self::normalize_provider( (string) ( $row['shadow_provider'] ?? '' ) ),
		);

		return in_array( $want, $ids, true );
	}

	/**
	 * @param array<string,mixed> $row
	 * @param array<string,int>   $hits
	 */
	private static function accumulate_pii( array $row, array &$hits ): void {
		$match = isset( $row['pii_match'] ) && is_array( $row['pii_match'] ) ? $row['pii_match'] : null;
		if ( null === $match ) {
			return;
		}
		$types = isset( $match['types'] ) && is_array( $match['types'] ) ? $match['types'] : array();
		foreach ( $types as $type => $count ) {
			$key = sanitize_key( (string) $type );
			if ( '' === $key ) {
				continue;
			}
			$hits[ $key ] = ( $hits[ $key ] ?? 0 ) + max( 0, (int) $count );
		}
	}

	/**
	 * @param array<string,mixed> $row
	 * @param array<string,mixed> $policy
	 */
	private static function row_spend( array $row, array $policy ): ?float {
		if ( ! class_exists( Cost::class, false ) || ! method_exists( Cost::class, 'estimate_usd' ) ) {
			return null;
		}
		$in  = array_key_exists( 'input_tokens', $row ) ? (int) $row['input_tokens'] : null;
		$out = array_key_exists( 'output_tokens', $row ) ? (int) $row['output_tokens'] : null;
		$prov = (string) ( $row['provider'] ?? '' );
		if ( '' === $prov && ! empty( $row['shadow_provider'] ) ) {
			$prov = (string) $row['shadow_provider'];
		}
		$rates = method_exists( Cost::class, 'rates_from_policy' )
			? Cost::rates_from_policy( $policy, $prov )
			: null;

		return Cost::estimate_usd( $in, $out, $rates );
	}

	/**
	 * Luggage grades for plugins in this window. HOMEBODY when a plugin had
	 * calls and no matching shipment kinds.
	 *
	 * @param list<string> $plugins
	 * @return list<array{plugin:string,grade:string,label:string,filename?:string}>
	 */
	private static function media_grades( string $provider, int $from_ts, int $to_ts, string $plugin_filter, array $plugins ): array {
		if ( ! class_exists( Luggage::class, false ) ) {
			return array();
		}
		$kinds_by_plugin = array();
		$file_by_plugin  = array();
		foreach ( self::shipments() as $ship ) {
			if ( ! is_array( $ship ) ) {
				continue;
			}
			$ts = isset( $ship['ts'] ) ? (int) $ship['ts'] : 0;
			if ( $ts > 0 && ( $ts < $from_ts || $ts > $to_ts ) ) {
				continue;
			}
			$ship_provider = self::normalize_provider( (string) ( $ship['provider'] ?? '' ) );
			if ( '' !== $ship_provider && $ship_provider !== $provider ) {
				continue;
			}
			$plug = trim( (string) ( $ship['plugin'] ?? '' ) );
			if ( '' === $plug ) {
				continue;
			}
			if ( '' !== $plugin_filter && $plug !== $plugin_filter ) {
				continue;
			}
			$kind = (string) ( $ship['kind'] ?? '' );
			if ( '' === $kind ) {
				$kind = Luggage::KIND_URL;
			}
			if ( ! isset( $kinds_by_plugin[ $plug ] ) ) {
				$kinds_by_plugin[ $plug ] = array();
			}
			$kinds_by_plugin[ $plug ][ $kind ] = true;
			$filename = trim( (string) ( $ship['filename'] ?? '' ) );
			if ( '' !== $filename && ! isset( $file_by_plugin[ $plug ] ) ) {
				$file_by_plugin[ $plug ] = $filename;
			}
		}

		$out = array();
		$seen = array();
		foreach ( $plugins as $plug ) {
			$seen[ $plug ] = true;
			$kinds = $kinds_by_plugin[ $plug ] ?? array();
			$grade = method_exists( Luggage::class, 'grade_for_kinds' )
				? Luggage::grade_for_kinds( $kinds )
				: '';
			$label = ( class_exists( Luggage::class, false ) && method_exists( Luggage::class, 'display_grade' ) )
				? Luggage::display_grade( $grade )
				: $grade;
			$item  = array(
				'plugin' => $plug,
				'grade'  => $grade,
				'label'  => $label,
			);
			if ( isset( $file_by_plugin[ $plug ] ) ) {
				$item['filename'] = $file_by_plugin[ $plug ];
			}
			$out[] = $item;
		}
		foreach ( $kinds_by_plugin as $plug => $kinds ) {
			if ( isset( $seen[ $plug ] ) ) {
				continue;
			}
			$grade = method_exists( Luggage::class, 'grade_for_kinds' )
				? Luggage::grade_for_kinds( $kinds )
				: '';
			$label = method_exists( Luggage::class, 'display_grade' )
				? Luggage::display_grade( $grade )
				: $grade;
			$item  = array(
				'plugin' => $plug,
				'grade'  => $grade,
				'label'  => $label,
			);
			if ( isset( $file_by_plugin[ $plug ] ) ) {
				$item['filename'] = $file_by_plugin[ $plug ];
			}
			$out[] = $item;
		}

		return $out;
	}

	/**
	 * @return list<array<string,mixed>>
	 */
	private static function shipments(): array {
		if ( null !== self::$test_shipments ) {
			return array_values( self::$test_shipments );
		}
		if ( class_exists( Luggage::class, false ) && method_exists( Luggage::class, 'read_shipments' ) ) {
			$rows = Luggage::read_shipments();

			return is_array( $rows ) ? $rows : array();
		}

		return array();
	}

	private static function retention_precede_days( int $from_ts, int $to_ts ): int {
		if ( $from_ts <= 0 || $to_ts < $from_ts ) {
			return 0;
		}
		$now    = self::now();
		$cutoff = 0;
		$policy = self::live_policy();
		if ( class_exists( Policy::class, false ) && method_exists( Policy::class, 'sanitize_log_max_age_days' ) ) {
			$max_age = Policy::sanitize_log_max_age_days( $policy['log_max_age_days'] ?? null );
			if ( null !== $max_age && $max_age > 0 ) {
				$day    = class_exists( Policy::class, false ) && method_exists( Policy::class, 'day_in_seconds' )
					? Policy::day_in_seconds()
					: 86400;
				$cutoff = $now - ( $max_age * $day );
			}
		}
		$oldest = 0;
		foreach ( self::log_rows() as $row ) {
			$ts = isset( $row['ts'] ) ? (int) $row['ts'] : 0;
			if ( $ts <= 0 ) {
				continue;
			}
			if ( 0 === $oldest || $ts < $oldest ) {
				$oldest = $ts;
			}
		}
		$knowable = max( $cutoff, $oldest );
		if ( $knowable <= 0 || $from_ts >= $knowable ) {
			return 0;
		}
		$gap_end = min( $knowable, $to_ts + 1 );
		if ( $gap_end <= $from_ts ) {
			return 0;
		}
		$seconds = $gap_end - $from_ts;

		return (int) ceil( $seconds / 86400 );
	}

	/**
	 * @return array<string,mixed>|null
	 */
	private static function incident_by_id( string $id ): ?array {
		$id = sanitize_key( $id );
		if ( '' === $id ) {
			return null;
		}
		if ( is_array( self::$test_incidents ) && isset( self::$test_incidents[ $id ] ) && is_array( self::$test_incidents[ $id ] ) ) {
			return self::$test_incidents[ $id ];
		}
		if ( class_exists( Incident::class, false ) && method_exists( Incident::class, 'get' ) ) {
			$found = Incident::get( $id, self::log_rows(), self::live_policy() );

			return is_array( $found ) ? $found : null;
		}

		return null;
	}

	/**
	 * @return list<string>
	 */
	private static function provider_choices(): array {
		$ids = array();
		if ( class_exists( Cost::class, false ) && defined( Cost::class . '::KNOWN_PROVIDERS' ) ) {
			foreach ( Cost::KNOWN_PROVIDERS as $id ) {
				$norm = self::normalize_provider( (string) $id );
				if ( '' !== $norm ) {
					$ids[ $norm ] = true;
				}
			}
		}
		foreach ( self::log_rows() as $row ) {
			foreach ( array( 'provider', 'shadow_provider' ) as $field ) {
				$norm = self::normalize_provider( (string) ( $row[ $field ] ?? '' ) );
				if ( '' !== $norm ) {
					$ids[ $norm ] = true;
				}
			}
		}
		$out = array_keys( $ids );
		sort( $out, SORT_STRING );

		return $out;
	}

	private static function normalize_provider( string $provider ): string {
		if ( class_exists( Cost::class, false ) && method_exists( Cost::class, 'normalize_provider_id' ) ) {
			return Cost::normalize_provider_id( $provider );
		}

		return strtolower( trim( $provider ) );
	}

	private static function sanitize_plugin( string $raw ): string {
		if ( class_exists( Plugin_Profile::class, false ) && method_exists( Plugin_Profile::class, 'sanitize_plugin' ) ) {
			return Plugin_Profile::sanitize_plugin( $raw );
		}
		$raw = trim( str_replace( '\\', '/', $raw ) );

		return $raw;
	}

	private static function day_start_ts( string $ymd ): int {
		$ymd = trim( $ymd );
		if ( ! preg_match( '/^\d{4}-\d{2}-\d{2}$/', $ymd ) ) {
			return 0;
		}
		$ts = strtotime( $ymd . ' 00:00:00 UTC' );

		return false === $ts ? 0 : (int) $ts;
	}

	private static function day_end_ts( string $ymd ): int {
		$ymd = trim( $ymd );
		if ( ! preg_match( '/^\d{4}-\d{2}-\d{2}$/', $ymd ) ) {
			return 0;
		}
		$ts = strtotime( $ymd . ' 23:59:59 UTC' );

		return false === $ts ? 0 : (int) $ts;
	}

	private static function truncate_ref( string $text ): string {
		$text = preg_replace( '/\s+/', ' ', $text ) ?? $text;
		$text = trim( $text );
		if ( strlen( $text ) <= 80 ) {
			return $text;
		}

		return substr( $text, 0, 77 ) . '...';
	}

	private static function pii_label( string $type ): string {
		if ( class_exists( Pii_Warn::class, false ) && method_exists( Pii_Warn::class, 'pattern_label' ) ) {
			return (string) Pii_Warn::pattern_label( $type );
		}

		return $type;
	}

	private static function family_label( string $family ): string {
		if ( class_exists( Operations::class, false ) && method_exists( Operations::class, 'family_labels' ) ) {
			$labels = Operations::family_labels();
			if ( isset( $labels[ $family ] ) ) {
				return (string) $labels[ $family ];
			}
		}

		return $family;
	}

	private static function is_insights_screen(): bool {
		$page = isset( $_GET['page'] ) ? sanitize_key( (string) wp_unslash( $_GET['page'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( '' === $page ) {
			return false;
		}
		if ( class_exists( Admin::class, false ) && method_exists( Admin::class, 'screen_slug' ) ) {
			return $page === Admin::screen_slug( 'insights' ) || 'handl-aicac-insights' === $page;
		}

		return 'handl-aicac-insights' === $page;
	}

	private static function die_forbidden(): void {
		$message = __( 'You do not have permission to download this report.', 'handl-ai-connector-access-control' );
		if ( function_exists( 'wp_die' ) ) {
			wp_die( esc_html( $message ) );
		}
	}
}
