<?php
/**
 * Admin UI.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Admin {
	private const LOG_FILTER_UNKNOWN = '__unknown__';

	/**
	 * @var array{decision:string,operation:string,provider:string,model:string,plugin:string}
	 */
	private array $log_filters = array(
		'decision'  => '',
		'operation' => '',
		'provider'  => '',
		'model'     => '',
		'plugin'    => '',
	);

	private static ?Admin $instance = null;

	public static function instance(): Admin {
		if ( null === self::$instance ) {
			self::$instance = new Admin();
		}
		return self::$instance;
	}

	public function init(): void {
		if ( ! is_admin() ) {
			return;
		}

		add_action( 'admin_menu', array( $this, 'register_menu' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_assets' ) );
	}

	public function enqueue_assets( string $hook_suffix ): void {
		if ( 'settings_page_handl-ai-connector-access-control' !== $hook_suffix ) {
			return;
		}

		wp_enqueue_style(
			'handl-aicac-admin',
			HANDL_AICAC_URL . 'assets/admin.css',
			array(),
			HANDL_AICAC_VERSION
		);
	}

	public function register_menu(): void {
		add_options_page(
			__( 'HandL AI Connector Access Control', 'handl-ai-connector-access-control' ),
			__( 'HandL AI Connector Access Control', 'handl-ai-connector-access-control' ),
			'manage_options',
			'handl-ai-connector-access-control',
			array( $this, 'render_page' )
		);
	}

	public function render_page(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to access this page.', 'handl-ai-connector-access-control' ) );
		}

		$tab = 'rules';
		if ( isset( $_REQUEST['handl_aicac_tab'] ) ) {
			$tab = sanitize_key( wp_unslash( (string) $_REQUEST['handl_aicac_tab'] ) );
		}
		if ( ! in_array( $tab, array( 'rules', 'log', 'insights' ), true ) ) {
			$tab = 'rules';
		}

		$plugin_status_filter = 'all';
		if ( isset( $_REQUEST['handl_aicac_status'] ) ) {
			$plugin_status_filter = sanitize_text_field( wp_unslash( (string) $_REQUEST['handl_aicac_status'] ) );
		}
		if ( 'active' !== $plugin_status_filter && 'inactive' !== $plugin_status_filter ) {
			$plugin_status_filter = 'all';
		}

		$plugin_access_filter = 'all';
		if ( isset( $_REQUEST['handl_aicac_access'] ) ) {
			$plugin_access_filter = sanitize_text_field( wp_unslash( (string) $_REQUEST['handl_aicac_access'] ) );
		}
		if ( 'effective-allow' !== $plugin_access_filter && 'effective-deny' !== $plugin_access_filter && 'default-only' !== $plugin_access_filter ) {
			$plugin_access_filter = 'all';
		}

		$this->log_filters = $this->parse_log_filters();

		if ( isset( $_POST['handl_aicac_action'] ) ) {
			$posted_action = sanitize_key( wp_unslash( (string) $_POST['handl_aicac_action'] ) );
			if ( 'quick_rule' === $posted_action ) {
				check_admin_referer( 'handl_aicac_quick_rule', 'handl_aicac_nonce' );
				$this->handle_quick_rule_redirect( $this->log_filters );
			}
		}

		$saved       = false;
		$quick_saved = isset( $_GET['handl_aicac_quick_saved'] ) && '1' === (string) $_GET['handl_aicac_quick_saved'];

		if ( isset( $_POST['handl_aicac_action'] ) && 'save' === $_POST['handl_aicac_action'] ) {
			check_admin_referer( 'handl_aicac_save_policy', 'handl_aicac_nonce' );
			if ( 'log' === $tab ) {
				$this->handle_save_log();
			} else {
				$this->handle_save_rules();
			}
			$saved = true;
		}

		$policy = Policy::get_policy();

		require_once ABSPATH . 'wp-admin/includes/plugin.php';
		$plugins = get_plugins();
		$active  = array_flip( (array) get_option( 'active_plugins', array() ) );

		$log = get_option( Plugin::LOG_OPTION_KEY );
		if ( ! is_array( $log ) ) {
			$log = array();
		}

		$icon_src = add_query_arg( 'ver', HANDL_AICAC_VERSION, HANDL_AICAC_URL . 'assets/icon-128x128.png' );

		echo '<div class="wrap">';
		echo '<h1 style="display:flex;align-items:center;gap:12px;">';
		echo '<img src="' . esc_url( $icon_src ) . '" alt="" width="40" height="40" style="border-radius:8px;" loading="lazy" decoding="async" />';
		echo esc_html__( 'HandL AI Connector Access Control', 'handl-ai-connector-access-control' );
		echo '</h1>';
		echo '<p>' . esc_html__( 'Allow/deny which plugins may execute prompts via the WordPress AI Client. Default policy is allow.', 'handl-ai-connector-access-control' ) . '</p>';

		$this->render_tabs( $tab, $plugin_status_filter, $plugin_access_filter, $this->log_filters );

		if ( $saved ) {
			echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__( 'Saved.', 'handl-ai-connector-access-control' ) . '</p></div>';
		}
		if ( $quick_saved ) {
			echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__( 'Plugin rule updated.', 'handl-ai-connector-access-control' ) . '</p></div>';
		}

		if ( ! empty( $policy['audit_only'] ) ) {
			$audit_notice = esc_html__( 'Learn mode is on: calls are logged and never blocked. Per-plugin rules show as “would enforce” only. Turn off learn mode on the Audit & log tab when you are ready to enforce.', 'handl-ai-connector-access-control' );
			if ( 'log' !== $tab ) {
				$audit_notice .= ' <a href="' . esc_url( admin_url( 'options-general.php?page=handl-ai-connector-access-control&handl_aicac_tab=log' ) ) . '">' . esc_html__( 'Open Audit & log', 'handl-ai-connector-access-control' ) . '</a>';
			}
			echo '<div class="notice notice-info"><p>' . wp_kses_post( $audit_notice ) . '</p></div>';
		} elseif ( ! empty( $policy['kill_switch'] ) ) {
			echo '<div class="notice notice-warning"><p>' . esc_html__( 'Emergency kill switch is on: all AI Client calls are blocked except plugins listed as exceptions.', 'handl-ai-connector-access-control' ) . '</p></div>';
		}

		if ( 'log' === $tab ) {
			$this->render_log_tab( $log, $policy, $plugins );
			echo '</div>';
			return;
		}

		if ( 'insights' === $tab ) {
			$this->render_insights_tab( $log, $policy, $plugins );
			echo '</div>';
			return;
		}

		echo '<div class="handl-aicac-tab-panel">';

		$rules_form_id = 'handl-aicac-rules-save';

		echo '<form method="post" id="' . esc_attr( $rules_form_id ) . '" class="handl-aicac-rules-save-form">';
		wp_nonce_field( 'handl_aicac_save_policy', 'handl_aicac_nonce' );
		echo '<input type="hidden" name="handl_aicac_action" value="save" />';
		echo '<input type="hidden" name="handl_aicac_tab" value="rules" />';
		echo '<input type="hidden" name="handl_aicac_status" value="' . esc_attr( $plugin_status_filter ) . '" />';
		echo '<input type="hidden" name="handl_aicac_access" value="' . esc_attr( $plugin_access_filter ) . '" />';
		echo '</form>';

		echo '<table class="form-table" role="presentation">';
		echo '<tr>';
		echo '<th scope="row">' . esc_html__( 'Default policy', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<td>';
		echo '<select name="handl_aicac_default" form="' . esc_attr( $rules_form_id ) . '">';
		$this->render_option( 'allow', $policy['default'] ?? 'allow', __( 'Allow', 'handl-ai-connector-access-control' ) );
		$this->render_option( 'deny', $policy['default'] ?? 'allow', __( 'Deny', 'handl-ai-connector-access-control' ) );
		echo '</select>';
		echo '<p class="description">' . esc_html__( 'Used when the calling plugin cannot be resolved or has no explicit rule.', 'handl-ai-connector-access-control' ) . '</p>';
		echo '</td>';
		echo '</tr>';
		echo '<tr>';
		echo '<th scope="row">' . esc_html__( 'Unknown operations', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<td>';
		$unknown = $policy['unknown_operation'] ?? 'inherit';
		echo '<select name="handl_aicac_unknown_operation" form="' . esc_attr( $rules_form_id ) . '">';
		$this->render_option( 'inherit', (string) $unknown, __( 'Inherit plugin rule', 'handl-ai-connector-access-control' ) );
		$this->render_option( 'allow', (string) $unknown, __( 'Allow', 'handl-ai-connector-access-control' ) );
		$this->render_option( 'deny', (string) $unknown, __( 'Deny', 'handl-ai-connector-access-control' ) );
		echo '</select>';
		echo '<p class="description">' . esc_html__( 'When an AI Client method does not map to Text / Image / Speech / TTS / Video (including music, embeddings, and generic is_supported). Support checks and matching generate_* methods always share the same family rule.', 'handl-ai-connector-access-control' ) . '</p>';
		echo '</td>';
		echo '</tr>';
		$this->render_kill_switch_settings_rows( $policy, $rules_form_id, $plugins );
		echo '</table>';

		$this->render_ability_arming_settings( $policy, $rules_form_id );

		$family_labels = Operations::family_labels();

		echo '<h2>' . esc_html__( 'Plugin rules', 'handl-ai-connector-access-control' ) . '</h2>';
		echo '<p class="description">' . esc_html__( 'Plugin access is the outer gate. Capability columns refine what an allowed plugin may do (e.g. allow text, deny image). Inherit follows the plugin AI access rule. A plugin-level Deny blocks every family.', 'handl-ai-connector-access-control' ) . '</p>';
		$this->render_plugin_rules_filters( $plugin_status_filter, $plugin_access_filter );
		echo '<table class="widefat striped handl-aicac-rules-matrix">';
		echo '<thead><tr>';
		echo '<th>' . esc_html__( 'Plugin', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Status', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'AI access', 'handl-ai-connector-access-control' ) . '</th>';
		foreach ( $family_labels as $family_id => $family_label ) {
			echo '<th class="handl-aicac-col-family">' . esc_html( $family_label ) . '</th>';
		}
		echo '<th>' . esc_html__( 'Plugin file', 'handl-ai-connector-access-control' ) . '</th>';
		echo '</tr></thead>';
		echo '<tbody>';

		$operations = is_array( $policy['operations'] ?? null ) ? (array) $policy['operations'] : array();

		foreach ( $plugins as $basename => $data ) {
			$name    = isset( $data['Name'] ) ? (string) $data['Name'] : $basename;
			$rule    = $policy['plugins'][ $basename ] ?? '';
			$enabled = isset( $active[ $basename ] );

			if ( 'active' === $plugin_status_filter && ! $enabled ) {
				continue;
			}
			if ( 'inactive' === $plugin_status_filter && $enabled ) {
				continue;
			}

			$explicit = ( 'allow' === $rule || 'deny' === $rule ) ? $rule : '';
			$effective = $explicit ? $explicit : ( ( $policy['default'] ?? 'allow' ) === 'deny' ? 'deny' : 'allow' );

			if ( 'default-only' === $plugin_access_filter && '' !== $explicit ) {
				continue;
			}
			if ( 'effective-allow' === $plugin_access_filter && 'allow' !== $effective ) {
				continue;
			}
			if ( 'effective-deny' === $plugin_access_filter && 'deny' !== $effective ) {
				continue;
			}

			$plugin_ops = isset( $operations[ $basename ] ) && is_array( $operations[ $basename ] )
				? $operations[ $basename ]
				: array();

			echo '<tr>';
			echo '<td><strong>' . esc_html( $name ) . '</strong></td>';
			echo '<td>' . ( $enabled ? '<span class="dashicons dashicons-yes"></span> ' . esc_html__( 'Active', 'handl-ai-connector-access-control' ) : esc_html__( 'Inactive', 'handl-ai-connector-access-control' ) ) . '</td>';
			echo '<td>';
			echo '<select name="handl_aicac_rule[' . esc_attr( $basename ) . ']" form="' . esc_attr( $rules_form_id ) . '">';
			$this->render_option( '', (string) $rule, __( 'Default', 'handl-ai-connector-access-control' ) );
			$this->render_option( 'allow', (string) $rule, __( 'Allow', 'handl-ai-connector-access-control' ) );
			$this->render_option( 'deny', (string) $rule, __( 'Deny', 'handl-ai-connector-access-control' ) );
			echo '</select>';
			echo '</td>';
			foreach ( $family_labels as $family_id => $family_label ) {
				$family_rule = isset( $plugin_ops[ $family_id ] ) ? (string) $plugin_ops[ $family_id ] : '';
				echo '<td class="handl-aicac-col-family">';
				echo '<select name="handl_aicac_operation[' . esc_attr( $basename ) . '][' . esc_attr( $family_id ) . ']" form="' . esc_attr( $rules_form_id ) . '" aria-label="' . esc_attr( sprintf(
					/* translators: 1: plugin name, 2: capability family */
					__( '%1$s — %2$s', 'handl-ai-connector-access-control' ),
					$name,
					$family_label
				) ) . '">';
				$this->render_option( '', $family_rule, __( 'Inherit', 'handl-ai-connector-access-control' ) );
				$this->render_option( 'allow', $family_rule, __( 'Allow', 'handl-ai-connector-access-control' ) );
				$this->render_option( 'deny', $family_rule, __( 'Deny', 'handl-ai-connector-access-control' ) );
				echo '</select>';
				echo '</td>';
			}
			echo '<td><code>' . esc_html( $basename ) . '</code></td>';
			echo '</tr>';
		}

		echo '</tbody>';
		echo '</table>';

		submit_button(
			__( 'Save changes', 'handl-ai-connector-access-control' ),
			'primary',
			'submit',
			false,
			array( 'form' => $rules_form_id )
		);
		echo '</div>'; // .handl-aicac-tab-panel
		echo '</div>'; // .wrap
	}

	private function render_plugin_rules_filters( string $plugin_status_filter, string $plugin_access_filter ): void {
		$base_url = add_query_arg(
			array(
				'page'            => 'handl-ai-connector-access-control',
				'handl_aicac_tab' => 'rules',
			),
			admin_url( 'options-general.php' )
		);

		$status_views = array(
			'all'      => __( 'All', 'handl-ai-connector-access-control' ),
			'active'   => __( 'Active', 'handl-ai-connector-access-control' ),
			'inactive' => __( 'Inactive', 'handl-ai-connector-access-control' ),
		);

		echo '<div class="handl-aicac-table-filters handl-aicac-rules-filters">';
		echo '<ul class="subsubsub">';
		$view_index = 0;
		foreach ( $status_views as $status_key => $status_label ) {
			if ( $view_index > 0 ) {
				echo ' | ';
			}
			++$view_index;

			$view_url = add_query_arg(
				array(
					'handl_aicac_status' => $status_key,
					'handl_aicac_access' => $plugin_access_filter,
				),
				$base_url
			);

			$is_current = $plugin_status_filter === $status_key;
			printf(
				'<li><a href="%1$s"%2$s>%3$s</a></li>',
				esc_url( $view_url ),
				$is_current ? ' class="current" aria-current="page"' : '',
				esc_html( $status_label )
			);
		}
		echo '</ul>';

		echo '<form method="get">';
		echo '<input type="hidden" name="page" value="handl-ai-connector-access-control" />';
		echo '<input type="hidden" name="handl_aicac_tab" value="rules" />';
		echo '<input type="hidden" name="handl_aicac_status" value="' . esc_attr( $plugin_status_filter ) . '" />';
		echo '<div class="tablenav top">';
		echo '<div class="alignleft actions">';
		echo '<label for="handl-aicac-access-filter" class="screen-reader-text">' . esc_html__( 'Filter by AI access', 'handl-ai-connector-access-control' ) . '</label>';
		echo '<select id="handl-aicac-access-filter" name="handl_aicac_access" onchange="if (this.form) { if (this.form.requestSubmit) { this.form.requestSubmit(); } else { HTMLFormElement.prototype.submit.call(this.form); } }">';
		$this->render_option( 'all', $plugin_access_filter, __( 'All AI access', 'handl-ai-connector-access-control' ) );
		$this->render_option( 'effective-allow', $plugin_access_filter, __( 'Plugin-level allow', 'handl-ai-connector-access-control' ) );
		$this->render_option( 'effective-deny', $plugin_access_filter, __( 'Plugin-level deny', 'handl-ai-connector-access-control' ) );
		$this->render_option( 'default-only', $plugin_access_filter, __( 'Default only', 'handl-ai-connector-access-control' ) );
		echo '</select>';
		echo '</div>';
		echo '<br class="clear" />';
		echo '</div>';
		echo '</form>';
		echo '</div>';
	}

	/**
	 * @param 'rules'|'log'|'insights' $active_tab
	 * @param array{decision:string,operation:string,provider:string,model:string,plugin:string} $log_filters
	 */
	private function render_tabs( string $active_tab, string $plugin_status_filter, string $plugin_access_filter, array $log_filters ): void {
		$base_args = array(
			'page' => 'handl-ai-connector-access-control',
		);

		$rules_url = add_query_arg(
			array_merge(
				$base_args,
				array(
					'handl_aicac_tab'    => 'rules',
					'handl_aicac_status' => $plugin_status_filter,
					'handl_aicac_access' => $plugin_access_filter,
				)
			),
			admin_url( 'options-general.php' )
		);

		$log_url = add_query_arg(
			array_merge( $base_args, array( 'handl_aicac_tab' => 'log' ), $this->log_filters_to_query_args( $log_filters ) ),
			admin_url( 'options-general.php' )
		);

		$insights_url = add_query_arg(
			array_merge( $base_args, array( 'handl_aicac_tab' => 'insights' ) ),
			admin_url( 'options-general.php' )
		);

		echo '<nav class="nav-tab-wrapper wp-clearfix" aria-label="' . esc_attr__( 'Settings sections', 'handl-ai-connector-access-control' ) . '">';
		printf(
			'<a href="%1$s" class="nav-tab%2$s">%3$s</a>',
			esc_url( $rules_url ),
			'rules' === $active_tab ? ' nav-tab-active' : '',
			esc_html__( 'Plugin rules', 'handl-ai-connector-access-control' )
		);
		printf(
			'<a href="%1$s" class="nav-tab%2$s">%3$s</a>',
			esc_url( $log_url ),
			'log' === $active_tab ? ' nav-tab-active' : '',
			esc_html__( 'Audit & log', 'handl-ai-connector-access-control' )
		);
		printf(
			'<a href="%1$s" class="nav-tab%2$s handl-aicac-nav-tab--insights">%3$s</a>',
			esc_url( $insights_url ),
			'insights' === $active_tab ? ' nav-tab-active' : '',
			esc_html__( 'Usage insights', 'handl-ai-connector-access-control' )
		);
		echo '</nav>';
	}

	/**
	 * @param array<int,mixed> $log
	 * @param array<string,mixed> $policy
	 * @param array<string,array<string,mixed>> $plugins
	 */
	private function render_insights_tab( array $log, array $policy, array $plugins ): void {
		$log_limit_policy = (int) ( $policy['log_limit'] ?? 200 );
		$stored_count     = count( $log );
		$aggregated       = Analytics::aggregate_from_log( $log, $plugins );
		$summary          = $aggregated['summary'];

		$dimension = 'plugin';
		if ( isset( $_REQUEST['handl_aicac_insights_dim'] ) ) {
			$dimension = sanitize_key( wp_unslash( (string) $_REQUEST['handl_aicac_insights_dim'] ) );
		}
		if ( ! isset( $aggregated['dimensions'][ $dimension ] ) ) {
			$dimension = 'plugin';
		}

		$metric = 'calls';
		if ( isset( $_REQUEST['handl_aicac_insights_metric'] ) ) {
			$metric = sanitize_key( wp_unslash( (string) $_REQUEST['handl_aicac_insights_metric'] ) );
		}
		if ( 'tokens' !== $metric ) {
			$metric = 'calls';
		}

		$rows = $aggregated['dimensions'][ $dimension ];
		$base_url = add_query_arg(
			array(
				'page'            => 'handl-ai-connector-access-control',
				'handl_aicac_tab' => 'insights',
			),
			admin_url( 'options-general.php' )
		);

		echo '<div class="handl-aicac-tab-panel handl-aicac-insights-wrap">';

		echo '<div class="handl-aicac-insights-hero">';
		echo '<div class="handl-aicac-insights-hero__copy">';
		echo '<h2 class="handl-aicac-insights-title">' . esc_html__( 'Usage insights', 'handl-ai-connector-access-control' ) . '</h2>';
		echo '<p class="handl-aicac-insights-lead">';
		echo esc_html__( 'Aggregated peaks and totals from your retained call log — grouped by plugin, provider, model, or operation.', 'handl-ai-connector-access-control' );
		echo '</p>';
		if ( 0 === $stored_count ) {
			echo '<p class="handl-aicac-insights-empty-note">';
			echo esc_html__( 'No data yet. Turn on learn mode or logging on Audit & log, then trigger a few AI Client requests.', 'handl-ai-connector-access-control' );
			echo ' <a href="' . esc_url( admin_url( 'options-general.php?page=handl-ai-connector-access-control&handl_aicac_tab=log' ) ) . '">';
			echo esc_html__( 'Open Audit & log', 'handl-ai-connector-access-control' );
			echo '</a></p>';
		} else {
			printf(
				'<p class="handl-aicac-insights-meta">%s</p>',
				esc_html(
					sprintf(
						/* translators: 1: stored count, 2: retention limit */
						__( 'Based on %1$d of %2$d stored calls (count-based retention; no TTL).', 'handl-ai-connector-access-control' ),
						$stored_count,
						$log_limit_policy
					)
				)
			);
		}
		echo '</div>';
		echo '</div>';

		if ( $stored_count > 0 ) {
			echo '<div class="handl-aicac-insights-summary" role="group" aria-label="' . esc_attr__( 'Overall totals', 'handl-ai-connector-access-control' ) . '">';
			$this->render_insights_stat_card(
				__( 'Total calls', 'handl-ai-connector-access-control' ),
				number_format_i18n( $summary['calls'] ),
				''
			);
			$this->render_insights_stat_card(
				__( 'Calls with tokens', 'handl-ai-connector-access-control' ),
				number_format_i18n( $summary['calls_with_tokens'] ),
				$summary['calls'] > 0
					? sprintf(
						/* translators: %s: percentage */
						__( '%s%% of calls', 'handl-ai-connector-access-control' ),
						number_format_i18n( (int) round( 100 * $summary['calls_with_tokens'] / max( 1, $summary['calls'] ) ) )
					)
					: ''
			);
			$this->render_insights_stat_card(
				__( 'Token sum (in + out)', 'handl-ai-connector-access-control' ),
				$this->format_insights_token_total( $summary['sum_input'], $summary['sum_output'] ),
				$summary['sum_total'] > 0
					? sprintf(
						/* translators: %s: formatted total token count */
						__( '%s reported total', 'handl-ai-connector-access-control' ),
						number_format_i18n( $summary['sum_total'] )
					)
					: __( 'Filled after model responds', 'handl-ai-connector-access-control' )
			);
			$this->render_insights_stat_card(
				__( 'Peak single call', 'handl-ai-connector-access-control' ),
				$summary['max_total'] > 0 ? number_format_i18n( $summary['max_total'] ) : '—',
				$summary['max_total'] > 0
					? sprintf(
						/* translators: 1: input tokens, 2: output tokens */
						__( '%1$s in · %2$s out', 'handl-ai-connector-access-control' ),
						number_format_i18n( $summary['max_input'] ),
						number_format_i18n( $summary['max_output'] )
					)
					: ''
			);
			echo '</div>';
		}

		$dimensions = array(
			'plugin'    => __( 'Plugins', 'handl-ai-connector-access-control' ),
			'provider'  => __( 'Providers', 'handl-ai-connector-access-control' ),
			'model'     => __( 'Models', 'handl-ai-connector-access-control' ),
			'operation' => __( 'Operations', 'handl-ai-connector-access-control' ),
		);

		echo '<div class="handl-aicac-insights-toolbar">';
		echo '<nav class="handl-aicac-insights-pills" aria-label="' . esc_attr__( 'Group by', 'handl-ai-connector-access-control' ) . '">';
		foreach ( $dimensions as $dim_key => $dim_label ) {
			$pill_url = add_query_arg(
				array(
					'handl_aicac_insights_dim'    => $dim_key,
					'handl_aicac_insights_metric' => $metric,
				),
				$base_url
			);
			printf(
				'<a href="%1$s" class="handl-aicac-insights-pill%2$s">%3$s</a>',
				esc_url( $pill_url ),
				$dimension === $dim_key ? ' is-active' : '',
				esc_html( $dim_label )
			);
		}
		echo '</nav>';

		echo '<nav class="handl-aicac-insights-metric-toggle" aria-label="' . esc_attr__( 'Chart metric', 'handl-ai-connector-access-control' ) . '">';
		foreach ( array(
			'calls'  => __( 'By calls', 'handl-ai-connector-access-control' ),
			'tokens' => __( 'By token sum', 'handl-ai-connector-access-control' ),
		) as $metric_key => $metric_label ) {
			$metric_url = add_query_arg(
				array(
					'handl_aicac_insights_dim'    => $dimension,
					'handl_aicac_insights_metric' => $metric_key,
				),
				$base_url
			);
			printf(
				'<a href="%1$s" class="handl-aicac-insights-metric%2$s">%3$s</a>',
				esc_url( $metric_url ),
				$metric === $metric_key ? ' is-active' : '',
				esc_html( $metric_label )
			);
		}
		echo '</nav>';
		echo '</div>';

		if ( empty( $rows ) ) {
			echo '<p class="handl-aicac-insights-table-empty">' . esc_html__( 'Nothing to chart for this dimension yet.', 'handl-ai-connector-access-control' ) . '</p>';
			echo '</div>';
			return;
		}

		$chart_max = 0;
		foreach ( $rows as $row ) {
			$chart_max = max( $chart_max, $this->insights_row_metric_value( $row, $metric ) );
		}

		echo '<div class="handl-aicac-insights-panel">';
		echo '<table class="widefat handl-aicac-insights-table">';
		echo '<thead><tr>';
		echo '<th class="column-rank">' . esc_html__( '#', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th class="column-label">' . esc_html( $dimensions[ $dimension ] ) . '</th>';
		echo '<th class="column-chart">' . esc_html__( 'Share', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th class="column-num">' . esc_html__( 'Calls', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th class="column-num">' . esc_html__( 'Σ tokens', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th class="column-num">' . esc_html__( 'Peak call', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th class="column-num">' . esc_html__( 'Peak in', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th class="column-num">' . esc_html__( 'Peak out', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th class="column-time">' . esc_html__( 'Last seen', 'handl-ai-connector-access-control' ) . '</th>';
		echo '</tr></thead><tbody>';

		$rank = 0;
		foreach ( $rows as $row ) {
			++$rank;
			$this->render_insights_table_row( $row, $rank, $dimension, $metric, $chart_max );
		}

		echo '</tbody></table>';
		echo '</div>';
		echo '</div>';
	}

	/**
	 * @param array<string,mixed> $row
	 */
	private function insights_row_metric_value( array $row, string $metric ): int {
		if ( 'tokens' === $metric ) {
			return (int) ( $row['sum_total'] ?? 0 );
		}

		return (int) ( $row['calls'] ?? 0 );
	}

	private function format_insights_token_total( int $input, int $output ): string {
		if ( 0 === $input && 0 === $output ) {
			return '—';
		}

		return number_format_i18n( $input + $output );
	}

	private function render_insights_stat_card( string $label, string $value, string $hint ): void {
		echo '<div class="handl-aicac-insights-stat">';
		echo '<span class="handl-aicac-insights-stat__label">' . esc_html( $label ) . '</span>';
		echo '<span class="handl-aicac-insights-stat__value">' . esc_html( $value ) . '</span>';
		if ( '' !== $hint ) {
			echo '<span class="handl-aicac-insights-stat__hint">' . esc_html( $hint ) . '</span>';
		}
		echo '</div>';
	}

	/**
	 * @param array<string,mixed> $row
	 */
	private function render_insights_table_row( array $row, int $rank, string $dimension, string $metric, int $chart_max ): void {
		$key         = (string) ( $row['key'] ?? '' );
		$label       = (string) ( $row['label'] ?? $key );
		$calls       = (int) ( $row['calls'] ?? 0 );
		$sum_total   = (int) ( $row['sum_total'] ?? 0 );
		$max_total   = (int) ( $row['max_total'] ?? 0 );
		$max_input   = (int) ( $row['max_input'] ?? 0 );
		$max_output  = (int) ( $row['max_output'] ?? 0 );
		$last_ts     = (int) ( $row['last_ts'] ?? 0 );
		$bar_value   = $this->insights_row_metric_value( $row, $metric );
		$bar_percent = $chart_max > 0 ? (int) round( 100 * $bar_value / $chart_max ) : 0;
		if ( $bar_percent > 0 && $bar_value > 0 && $bar_percent < 4 ) {
			$bar_percent = 4;
		}

		$is_peak_row = 1 === $rank;

		echo '<tr' . ( $is_peak_row ? ' class="handl-aicac-insights-row--leader"' : '' ) . '>';
		echo '<td class="column-rank">';
		if ( $is_peak_row ) {
			echo '<span class="handl-aicac-insights-rank-badge" title="' . esc_attr__( 'Highest in this view', 'handl-ai-connector-access-control' ) . '">★</span> ';
		}
		echo esc_html( (string) $rank );
		echo '</td>';
		echo '<td class="column-label">';
		echo '<strong>' . esc_html( $label ) . '</strong>';
		if ( Analytics::UNKNOWN_KEY !== $key && $key !== $label ) {
			echo '<br /><code class="handl-aicac-insights-key">' . esc_html( $key ) . '</code>';
		}
		echo '</td>';
		echo '<td class="column-chart">';
		echo '<div class="handl-aicac-insights-bar" role="img" aria-label="' . esc_attr(
			sprintf(
				/* translators: %d: percentage of chart maximum */
				__( '%d%% of chart maximum', 'handl-ai-connector-access-control' ),
				$bar_percent
			)
		) . '">';
		printf(
			'<span class="handl-aicac-insights-bar__fill" style="width:%d%%;"></span>',
			(int) $bar_percent
		);
		echo '<span class="handl-aicac-insights-bar__value">' . esc_html( number_format_i18n( $bar_value ) ) . '</span>';
		echo '</div>';
		echo '</td>';
		echo '<td class="column-num">' . esc_html( number_format_i18n( $calls ) ) . '</td>';
		echo '<td class="column-num">' . esc_html( $sum_total > 0 ? number_format_i18n( $sum_total ) : '—' ) . '</td>';
		echo '<td class="column-num handl-aicac-insights-peak">' . esc_html( $max_total > 0 ? number_format_i18n( $max_total ) : '—' ) . '</td>';
		echo '<td class="column-num">' . esc_html( $max_input > 0 ? number_format_i18n( $max_input ) : '—' ) . '</td>';
		echo '<td class="column-num">' . esc_html( $max_output > 0 ? number_format_i18n( $max_output ) : '—' ) . '</td>';
		echo '<td class="column-time">' . esc_html( $last_ts ? wp_date( 'Y-m-d H:i', $last_ts ) : '—' ) . '</td>';
		echo '</tr>';
	}

	/**
	 * @param array<int,mixed> $log
	 * @param array<string,mixed> $policy
	 * @param array<string,array<string,mixed>> $plugins
	 */
	private function render_log_tab( array $log, array $policy, array $plugins ): void {
		$log_limit_policy = (int) ( $policy['log_limit'] ?? 200 );
		$stored_count     = count( $log );
		$log_filters      = $this->log_filters;
		$filter_options   = $this->collect_log_filter_options( $log, $plugins );

		echo '<div class="handl-aicac-tab-panel handl-aicac-log-wrap">';

		echo '<form method="post" style="margin-bottom:1.5em;">';
		wp_nonce_field( 'handl_aicac_save_policy', 'handl_aicac_nonce' );
		echo '<input type="hidden" name="handl_aicac_action" value="save" />';
		echo '<input type="hidden" name="handl_aicac_tab" value="log" />';
		$this->render_log_filter_hiddens( $log_filters );
		$this->render_logging_settings( $policy );
		submit_button( __( 'Save audit settings', 'handl-ai-connector-access-control' ) );
		echo '</form>';

		if ( ! empty( $policy['audit_only'] ) ) {
			$this->render_suggested_rules( $log, $policy, $plugins, $log_filters );
		}

		echo '<h2>' . esc_html__( 'Recent calls', 'handl-ai-connector-access-control' ) . '</h2>';
		$this->render_log_filters( $log_filters, $filter_options, $plugins );

		$log_newest_first = array_reverse( $log );
		$matching_count   = 0;
		$rows_to_show     = array();
		foreach ( $log_newest_first as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			if ( ! $this->log_row_matches_filters( $row, $log_filters ) ) {
				continue;
			}
			++$matching_count;
			if ( count( $rows_to_show ) < 50 ) {
				$rows_to_show[] = $row;
			}
		}

		echo '<p class="handl-aicac-log-meta">';
		if ( $this->log_filters_active( $log_filters ) ) {
			printf(
				/* translators: 1: rows shown, 2: matching count, 3: stored count, 4: retention limit */
				esc_html__( 'Showing %1$d of %2$d matching calls (newest first, up to 50). %3$d of %4$d stored entries retained (count-based; no TTL).', 'handl-ai-connector-access-control' ),
				count( $rows_to_show ),
				$matching_count,
				(int) $stored_count,
				(int) $log_limit_policy
			);
		} else {
			printf(
				/* translators: 1: stored count, 2: retention limit, 3: rows shown in table */
				esc_html__( 'Showing up to %3$d newest rows. %1$d of %2$d stored entries retained (count-based; no TTL). Provider/model are read from the prompt builder when available. Input/output tokens are filled after the model responds (allowed generate_* calls only).', 'handl-ai-connector-access-control' ),
				(int) $stored_count,
				(int) $log_limit_policy,
				count( $rows_to_show )
			);
		}
		echo '</p>';
		echo '<table class="widefat striped handl-aicac-log-table">';
		echo '<thead><tr>';
		echo '<th class="column-time">' . esc_html__( 'Time', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Decision', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th class="column-operation">' . esc_html__( 'Operation / family', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th class="column-provider">' . esc_html__( 'Provider', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th class="column-model">' . esc_html__( 'Model', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th class="column-tokens">' . esc_html__( 'Input tokens', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th class="column-tokens">' . esc_html__( 'Output tokens', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Plugin', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Prompt', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'User', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'URI', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th class="column-actions">' . esc_html__( 'Actions', 'handl-ai-connector-access-control' ) . '</th>';
		echo '</tr></thead><tbody>';

		foreach ( $rows_to_show as $row ) {
			$this->render_log_row( $row, $plugins, $policy, $log_filters );
		}

		if ( 0 === count( $rows_to_show ) ) {
			if ( 0 === $stored_count ) {
				$empty_message = ! empty( $policy['audit_only'] )
					? __( 'No calls logged yet. Trigger an AI Client request while audit-only mode is on.', 'handl-ai-connector-access-control' )
					: __( 'No calls logged yet. Enable logging above and trigger an AI Client request.', 'handl-ai-connector-access-control' );
			} elseif ( $this->log_filters_active( $log_filters ) ) {
				$empty_message = __( 'No calls match the current filters.', 'handl-ai-connector-access-control' );
			} else {
				$empty_message = __( 'No calls to display.', 'handl-ai-connector-access-control' );
			}
			echo '<tr><td colspan="12">' . esc_html( $empty_message ) . '</td></tr>';
		}

		echo '</tbody></table>';
		echo '</div>';
	}

	/**
	 * @return array{decision:string,operation:string,provider:string,model:string,plugin:string}
	 */
	private function parse_log_filters(): array {
		$filters = array(
			'decision'  => '',
			'operation' => '',
			'provider'  => '',
			'model'     => '',
			'plugin'    => '',
		);

		if ( isset( $_REQUEST['handl_aicac_log_decision'] ) ) {
			$decision = sanitize_key( wp_unslash( (string) $_REQUEST['handl_aicac_log_decision'] ) );
			if ( 'allow' === $decision || 'deny' === $decision ) {
				$filters['decision'] = $decision;
			}
		}

		$text_fields = array(
			'operation' => 'handl_aicac_log_operation',
			'provider'  => 'handl_aicac_log_provider',
			'model'     => 'handl_aicac_log_model',
			'plugin'    => 'handl_aicac_log_plugin',
		);

		foreach ( $text_fields as $key => $request_key ) {
			if ( ! isset( $_REQUEST[ $request_key ] ) ) {
				continue;
			}
			$value = sanitize_text_field( wp_unslash( (string) $_REQUEST[ $request_key ] ) );
			if ( '' === $value ) {
				continue;
			}
			if ( self::LOG_FILTER_UNKNOWN === $value ) {
				$filters[ $key ] = self::LOG_FILTER_UNKNOWN;
				continue;
			}
			$filters[ $key ] = $value;
		}

		return $filters;
	}

	/**
	 * @param array{decision:string,operation:string,provider:string,model:string,plugin:string} $filters
	 * @return array<string,string>
	 */
	private function log_filters_to_query_args( array $filters ): array {
		$args = array();
		foreach ( $filters as $key => $value ) {
			if ( '' === $value ) {
				continue;
			}
			$args[ 'handl_aicac_log_' . $key ] = $value;
		}
		return $args;
	}

	/**
	 * @param array{decision:string,operation:string,provider:string,model:string,plugin:string} $filters
	 */
	private function log_filters_active( array $filters ): bool {
		foreach ( $filters as $value ) {
			if ( '' !== $value ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * @param array<int,mixed> $log
	 * @param array<string,array<string,mixed>> $plugins
	 * @return array{decision:array<string,string>,operation:array<string,string>,provider:array<string,string>,model:array<string,string>,plugin:array<string,string>}
	 */
	private function collect_log_filter_options( array $log, array $plugins ): array {
		$options = array(
			'decision'  => array(),
			'operation' => array(),
			'provider'  => array(),
			'model'     => array(),
			'plugin'    => array(),
		);

		$has_unknown = array(
			'operation' => false,
			'provider'  => false,
			'model'     => false,
			'plugin'    => false,
		);

		foreach ( $log as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}

			$decision = $this->get_log_row_field( $row, 'decision' );
			if ( 'allow' === $decision || 'deny' === $decision ) {
				$options['decision'][ $decision ] = $decision;
			}

			foreach ( array( 'operation', 'provider' ) as $field ) {
				$value = $this->get_log_row_field( $row, $field );
				if ( '' === $value ) {
					$has_unknown[ $field ] = true;
					continue;
				}
				$options[ $field ][ $value ] = $value;
			}

			$model = $this->get_log_row_model( $row );
			if ( '' === $model ) {
				$has_unknown['model'] = true;
			} else {
				$options['model'][ $model ] = $model;
			}

			$plugin = $this->get_log_row_field( $row, 'plugin' );
			if ( '' === $plugin ) {
				$has_unknown['plugin'] = true;
				continue;
			}
			$label = $plugin;
			if ( isset( $plugins[ $plugin ]['Name'] ) ) {
				$label = (string) $plugins[ $plugin ]['Name'];
			}
			$options['plugin'][ $plugin ] = $label;
		}

		foreach ( array( 'operation', 'provider', 'model', 'plugin' ) as $field ) {
			if ( $has_unknown[ $field ] ) {
				$options[ $field ][ self::LOG_FILTER_UNKNOWN ] = __( '(unknown)', 'handl-ai-connector-access-control' );
			}
			natcasesort( $options[ $field ] );
			if ( isset( $options[ $field ][ self::LOG_FILTER_UNKNOWN ] ) ) {
				$unknown_label = $options[ $field ][ self::LOG_FILTER_UNKNOWN ];
				unset( $options[ $field ][ self::LOG_FILTER_UNKNOWN ] );
				$options[ $field ] = array( self::LOG_FILTER_UNKNOWN => $unknown_label ) + $options[ $field ];
			}
		}

		return $options;
	}

	/**
	 * @param array{decision:string,operation:string,provider:string,model:string,plugin:string} $filters
	 * @param array{decision:array<string,string>,operation:array<string,string>,provider:array<string,string>,model:array<string,string>,plugin:array<string,string>} $filter_options
	 * @param array<string,array<string,mixed>> $plugins
	 */
	private function render_log_filters( array $filters, array $filter_options, array $plugins ): void {
		unset( $plugins );

		$base_url = add_query_arg(
			array(
				'page'            => 'handl-ai-connector-access-control',
				'handl_aicac_tab' => 'log',
			),
			admin_url( 'options-general.php' )
		);

		$decision_views = array(
			''      => __( 'All', 'handl-ai-connector-access-control' ),
			'allow' => __( 'Allow', 'handl-ai-connector-access-control' ),
			'deny'  => __( 'Deny', 'handl-ai-connector-access-control' ),
		);

		$other_filters = $filters;
		$other_filters['decision'] = '';

		echo '<div class="handl-aicac-table-filters handl-aicac-log-filters">';
		echo '<ul class="subsubsub">';
		$view_index = 0;
		foreach ( $decision_views as $decision_key => $decision_label ) {
			if ( $view_index > 0 ) {
				echo ' | ';
			}
			++$view_index;

			$view_filters           = $other_filters;
			$view_filters['decision'] = $decision_key;
			$view_url               = add_query_arg( $this->log_filters_to_query_args( $view_filters ), $base_url );

			$is_current = $filters['decision'] === $decision_key;
			printf(
				'<li><a href="%1$s"%2$s>%3$s</a></li>',
				esc_url( $view_url ),
				$is_current ? ' class="current" aria-current="page"' : '',
				esc_html( $decision_label )
			);
		}
		echo '</ul>';

		echo '<form method="get">';
		echo '<input type="hidden" name="page" value="handl-ai-connector-access-control" />';
		echo '<input type="hidden" name="handl_aicac_tab" value="log" />';
		if ( '' !== $filters['decision'] ) {
			echo '<input type="hidden" name="handl_aicac_log_decision" value="' . esc_attr( $filters['decision'] ) . '" />';
		}
		echo '<div class="tablenav top">';
		echo '<div class="alignleft actions">';
		$this->render_log_filter_select(
			'handl-aicac-log-operation-filter',
			'handl_aicac_log_operation',
			__( 'All operations', 'handl-ai-connector-access-control' ),
			__( 'Filter by operation', 'handl-ai-connector-access-control' ),
			$filters['operation'],
			$filter_options['operation']
		);
		$this->render_log_filter_select(
			'handl-aicac-log-provider-filter',
			'handl_aicac_log_provider',
			__( 'All providers', 'handl-ai-connector-access-control' ),
			__( 'Filter by provider', 'handl-ai-connector-access-control' ),
			$filters['provider'],
			$filter_options['provider']
		);
		$this->render_log_filter_select(
			'handl-aicac-log-model-filter',
			'handl_aicac_log_model',
			__( 'All models', 'handl-ai-connector-access-control' ),
			__( 'Filter by model', 'handl-ai-connector-access-control' ),
			$filters['model'],
			$filter_options['model']
		);
		$this->render_log_filter_select(
			'handl-aicac-log-plugin-filter',
			'handl_aicac_log_plugin',
			__( 'All plugins', 'handl-ai-connector-access-control' ),
			__( 'Filter by plugin', 'handl-ai-connector-access-control' ),
			$filters['plugin'],
			$filter_options['plugin']
		);
		submit_button( __( 'Filter', 'handl-ai-connector-access-control' ), '', 'filter_action', false );
		if ( $this->log_filters_active( $filters ) ) {
			echo ' <a class="button" href="' . esc_url( $base_url ) . '">' . esc_html__( 'Clear filters', 'handl-ai-connector-access-control' ) . '</a>';
		}
		echo '</div>';
		echo '<br class="clear" />';
		echo '</div>';
		echo '</form>';
		echo '</div>';
	}

	/**
	 * @param array<string,string> $options
	 */
	private function render_log_filter_select(
		string $id,
		string $name,
		string $all_label,
		string $screen_reader_label,
		string $current,
		array $options
	): void {
		echo '<label for="' . esc_attr( $id ) . '" class="screen-reader-text">' . esc_html( $screen_reader_label ) . '</label>';
		echo '<select id="' . esc_attr( $id ) . '" name="' . esc_attr( $name ) . '">';
		$this->render_option( '', $current, $all_label );
		foreach ( $options as $value => $label ) {
			$this->render_option( (string) $value, $current, (string) $label );
		}
		echo '</select> ';
	}

	/**
	 * @param array{decision:string,operation:string,provider:string,model:string,plugin:string} $filters
	 */
	private function render_log_filter_hiddens( array $filters ): void {
		foreach ( $this->log_filters_to_query_args( $filters ) as $key => $value ) {
			echo '<input type="hidden" name="' . esc_attr( $key ) . '" value="' . esc_attr( $value ) . '" />';
		}
	}

	/**
	 * @param array<string,mixed> $row
	 * @param array{decision:string,operation:string,provider:string,model:string,plugin:string} $filters
	 */
	private function log_row_matches_filters( array $row, array $filters ): bool {
		foreach ( array( 'decision', 'operation', 'provider', 'model', 'plugin' ) as $field ) {
			if ( '' === $filters[ $field ] ) {
				continue;
			}

			$value = $this->get_log_row_field( $row, $field );
			if ( self::LOG_FILTER_UNKNOWN === $filters[ $field ] ) {
				if ( '' !== $value ) {
					return false;
				}
				continue;
			}

			if ( $filters[ $field ] !== $value ) {
				return false;
			}
		}

		return true;
	}

	/**
	 * @param array<string,mixed> $row
	 */
	private function get_log_row_field( array $row, string $field ): string {
		if ( 'model' === $field ) {
			return $this->get_log_row_model( $row );
		}

		return isset( $row[ $field ] ) ? (string) $row[ $field ] : '';
	}

	/**
	 * @param array<string,mixed> $row
	 */
	private function get_log_row_model( array $row ): string {
		$model = isset( $row['model'] ) ? (string) $row['model'] : '';
		if ( '' === $model && ! empty( $row['model_preferences'] ) && is_array( $row['model_preferences'] ) ) {
			$model = implode( ', ', array_map( 'strval', $row['model_preferences'] ) );
		}

		return $model;
	}

	/**
	 * @param array<string,mixed> $policy
	 */
	private function render_logging_settings( array $policy ): void {
		$audit_only  = ! empty( $policy['audit_only'] );
		$log_enabled = ! empty( $policy['log_enabled'] );
		$log_limit   = (int) ( $policy['log_limit'] ?? 200 );

		echo '<p class="description" style="max-width:52em;margin-bottom:1em;">';
		echo esc_html__( 'Use this tab to observe AI Client usage. Learn mode logs every call without blocking. When learn mode is off, you can still log calls for troubleshooting. Enforcement lives on the Plugin rules tab.', 'handl-ai-connector-access-control' );
		echo '</p>';

		echo '<table class="form-table" role="presentation">';
		echo '<tr>';
		echo '<th scope="row">' . esc_html__( 'Learn mode', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<td>';
		echo '<label><input type="checkbox" name="handl_aicac_audit_only" value="1" ' . checked( $audit_only, true, false ) . ' /> ';
		echo esc_html__( 'Log every call and never block (recommended while discovering callers)', 'handl-ai-connector-access-control' ) . '</label>';
		echo '<p class="description">' . esc_html__( 'Shows which plugins use the AI Client and what your rules would do (“would enforce”). Use Allow/Deny below or on the Plugin rules tab, then turn learn mode off to enforce.', 'handl-ai-connector-access-control' ) . '</p>';
		echo '</td>';
		echo '</tr>';

		if ( ! $audit_only ) {
			echo '<tr>';
			echo '<th scope="row">' . esc_html__( 'Logging only', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<td>';
			echo '<label><input type="checkbox" name="handl_aicac_log_enabled" value="1" ' . checked( $log_enabled, true, false ) . ' /> ';
			echo esc_html__( 'Log calls while enforcing rules', 'handl-ai-connector-access-control' ) . '</label>';
			echo '<p class="description">' . esc_html__( 'Optional audit trail after learn mode. Nothing is sent off-site; data stays in the options table.', 'handl-ai-connector-access-control' ) . '</p>';
			echo '</td>';
			echo '</tr>';
		} else {
			echo '<tr class="handl-aicac-log-implied">';
			echo '<th scope="row">' . esc_html__( 'Logging only', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<td><p class="description" style="margin:0;">' . esc_html__( 'On automatically while learn mode is active.', 'handl-ai-connector-access-control' ) . '</p></td>';
			echo '</tr>';
		}

		echo '<tr>';
		echo '<th scope="row"><label for="handl-aicac-log-limit">' . esc_html__( 'Retain entries', 'handl-ai-connector-access-control' ) . '</label></th>';
		echo '<td>';
		echo '<input type="number" id="handl-aicac-log-limit" name="handl_aicac_log_limit" value="' . esc_attr( (string) $log_limit ) . '" min="20" max="1000" step="1" class="small-text" />';
		echo ' <span class="description">' . esc_html__( '(20–1000). Oldest entries drop when full. No time-based expiry.', 'handl-ai-connector-access-control' ) . '</span>';
		echo '</td>';
		echo '</tr>';
		echo '</table>';
	}

	private function handle_save_rules(): void {
		$policy = Policy::get_policy();

		$posted_default = filter_input( INPUT_POST, 'handl_aicac_default', FILTER_UNSAFE_RAW );
		$policy['default'] = ( 'deny' === sanitize_text_field( (string) $posted_default ) ) ? 'deny' : 'allow';

		$posted_unknown = filter_input( INPUT_POST, 'handl_aicac_unknown_operation', FILTER_UNSAFE_RAW );
		$policy['unknown_operation'] = Policy::sanitize_unknown_operation( $posted_unknown );

		$rules        = array();
		$posted_rules = filter_input( INPUT_POST, 'handl_aicac_rule', FILTER_UNSAFE_RAW, FILTER_REQUIRE_ARRAY );
		if ( is_array( $posted_rules ) ) {
			foreach ( $posted_rules as $basename => $rule ) {
				$basename = sanitize_text_field( (string) $basename );
				$rule     = sanitize_text_field( (string) $rule );
				if ( '' === $basename ) {
					continue;
				}
				if ( 'allow' === $rule || 'deny' === $rule ) {
					$rules[ $basename ] = $rule;
				}
			}
		}
		$policy['plugins'] = $rules;

		$posted_ops = filter_input( INPUT_POST, 'handl_aicac_operation', FILTER_UNSAFE_RAW, FILTER_REQUIRE_ARRAY );
		$policy['operations'] = Policy::sanitize_operations( is_array( $posted_ops ) ? $posted_ops : array() );

		// Accept new field name; also read legacy POST key during transition.
		$posted_tools = filter_input( INPUT_POST, 'handl_aicac_denied_tools', FILTER_UNSAFE_RAW );
		if ( null === $posted_tools || false === $posted_tools || '' === $posted_tools ) {
			$posted_tools = filter_input( INPUT_POST, 'handl_aicac_denied_abilities', FILTER_UNSAFE_RAW );
		}
		$policy['denied_tools'] = Policy::sanitize_denied_tools( (string) $posted_tools );

		$this->apply_kill_switch_settings_from_post( $policy );

		Policy::save_policy( $policy );
	}

	/**
	 * Caller-intent tool deny-at-arming (F2). Distinct from MCP visibility.
	 *
	 * Matches any armed tool name — WordPress abilities (wpab__) and custom
	 * FunctionDeclarations. The registered-abilities checklist is a helper subset.
	 *
	 * @param array<string,mixed> $policy
	 */
	private function render_ability_arming_settings( array $policy, string $form_id ): void {
		$denied      = Policy::get_denied_tools( $policy );
		$denied_text = implode( "\n", $denied );
		$registered  = $this->list_registered_ability_names();

		echo '<h2>' . esc_html__( 'AI tool arming (caller intent)', 'handl-ai-connector-access-control' ) . '</h2>';
		echo '<div class="notice notice-info inline handl-aicac-ability-axis-notice"><p>';
		echo esc_html__( 'This controls which tools a model may be offered when a plugin calls the AI Client (functionDeclarations on the prompt). It covers WordPress abilities (using_abilities / wpab__) and custom FunctionDeclarations. It is not MCP visibility, and it does not unregister abilities for the rest of the site. Denials block the entire prompt at arming time and are logged under this plugin’s name so you can tell a blocked tool call from an upstream plugin bug. Matching is case-insensitive.', 'handl-ai-connector-access-control' );
		echo '</p></div>';

		echo '<table class="form-table" role="presentation">';
		echo '<tr>';
		echo '<th scope="row"><label for="handl-aicac-denied-tools">' . esc_html__( 'Denied tools', 'handl-ai-connector-access-control' ) . '</label></th>';
		echo '<td>';
		echo '<textarea name="handl_aicac_denied_tools" id="handl-aicac-denied-tools" form="' . esc_attr( $form_id ) . '" rows="6" cols="50" class="large-text code" placeholder="namespace/tool-name">' . esc_textarea( $denied_text ) . '</textarea>';
		echo '<p class="description">' . esc_html__( 'One tool name per line (example: mainwp/add-site-v1). If a prompt arms any listed tool, the call is denied before the model runs. Leave empty to allow all tools that plugins choose to arm. Custom tool names (not just registered abilities) may be listed.', 'handl-ai-connector-access-control' ) . '</p>';

		// Flag deny-list entries that match nothing currently registered (helper only).
		if ( ! empty( $denied ) ) {
			$inert = array();
			foreach ( $denied as $entry ) {
				if ( ! Policy::deny_entry_matches_registered( $entry, $registered ) ) {
					$inert[] = $entry;
				}
			}
			if ( ! empty( $inert ) ) {
				echo '<div class="notice notice-warning inline handl-aicac-inert-tools"><p>';
				echo esc_html__( 'Not currently registered — will apply if a plugin registers it later (or if a custom tool uses this name):', 'handl-ai-connector-access-control' );
				echo ' <code>' . esc_html( implode( ', ', $inert ) ) . '</code>';
				echo '</p></div>';
			}
		}

		if ( ! empty( $registered ) ) {
			echo '<p class="description"><strong>' . esc_html__( 'Registered abilities (helper subset — custom tool names may also be listed above):', 'handl-ai-connector-access-control' ) . '</strong></p>';
			echo '<ul class="handl-aicac-registered-abilities">';
			foreach ( $registered as $name ) {
				// Case-insensitive check so checkbox reflects normalized matching.
				$checked = Policy::deny_entry_matches_registered( $name, $denied ) ? ' checked="checked"' : '';
				echo '<li><label>';
				echo '<input type="checkbox" class="handl-aicac-tool-quick-add" data-tool="' . esc_attr( $name ) . '"' . $checked . ' /> ';
				echo '<code>' . esc_html( $name ) . '</code>';
				echo '</label></li>';
			}
			echo '</ul>';
			echo '<p class="description">' . esc_html__( 'Checkboxes only help fill the list above — save still uses the textarea. Click a box to add or remove that name from the list before saving. This list is not an enumeration of everything the deny list can match.', 'handl-ai-connector-access-control' ) . '</p>';
			echo '<script>';
			echo '(function(){var ta=document.getElementById("handl-aicac-denied-tools");if(!ta)return;';
			echo 'function lines(){return ta.value.split(/\\r\\n|\\r|\\n/).map(function(s){return s.trim();}).filter(Boolean);}';
			echo 'function write(arr){ta.value=arr.join("\\n");}';
			echo 'function idx(cur,n){var nl=n.toLowerCase();for(var i=0;i<cur.length;i++){if(cur[i].toLowerCase()===nl)return i;}return -1;}';
			echo 'document.querySelectorAll(".handl-aicac-tool-quick-add").forEach(function(cb){cb.addEventListener("change",function(){var n=cb.getAttribute("data-tool");var cur=lines();var i=idx(cur,n);if(cb.checked&&i<0)cur.push(n);if(!cb.checked&&i>=0)cur.splice(i,1);write(cur);});});';
			echo '})();';
			echo '</script>';
		} else {
			echo '<p class="description">' . esc_html__( 'No abilities are registered via the Abilities API on this site right now. You can still pre-list ability or custom tool names that plugins may arm later.', 'handl-ai-connector-access-control' ) . '</p>';
		}

		echo '</td>';
		echo '</tr>';
		echo '</table>';
	}

	/**
	 * @return list<string>
	 */
	private function list_registered_ability_names(): array {
		if ( ! function_exists( 'wp_get_abilities' ) ) {
			return array();
		}

		try {
			$abilities = wp_get_abilities();
		} catch ( \Throwable $e ) { // phpcs:ignore Generic.CodeAnalysis.EmptyStatement.DetectedCatch
			return array();
		}

		if ( ! is_array( $abilities ) ) {
			return array();
		}

		$names = array();
		foreach ( $abilities as $ability ) {
			if ( is_object( $ability ) && method_exists( $ability, 'get_name' ) ) {
				$name = (string) $ability->get_name();
			} elseif ( is_string( $ability ) ) {
				$name = $ability;
			} else {
				continue;
			}
			if ( '' !== $name ) {
				$names[] = $name;
			}
		}

		$names = array_values( array_unique( $names ) );
		sort( $names, SORT_STRING );
		return $names;
	}

	/**
	 * @param array<string,mixed> $policy
	 */
	private function apply_kill_switch_settings_from_post( array &$policy ): void {
		$posted_kill = filter_input( INPUT_POST, 'handl_aicac_kill_switch', FILTER_UNSAFE_RAW );
		$policy['kill_switch'] = ! empty( $posted_kill );

		$exceptions = array();
		$posted_exceptions = filter_input( INPUT_POST, 'handl_aicac_kill_exceptions', FILTER_UNSAFE_RAW, FILTER_REQUIRE_ARRAY );
		if ( is_array( $posted_exceptions ) ) {
			foreach ( $posted_exceptions as $basename ) {
				$basename = sanitize_text_field( (string) $basename );
				if ( '' !== $basename ) {
					$exceptions[] = $basename;
				}
			}
		}
		$policy['kill_switch_exceptions'] = array_values( array_unique( $exceptions ) );
	}

	/**
	 * @param array<string,mixed> $policy
	 */
	private function apply_log_settings_from_post( array &$policy ): void {
		$posted_audit = filter_input( INPUT_POST, 'handl_aicac_audit_only', FILTER_UNSAFE_RAW );
		$policy['audit_only'] = ! empty( $posted_audit );

		if ( $policy['audit_only'] ) {
			$policy['log_enabled'] = true;
		} else {
			$posted_log_enabled = filter_input( INPUT_POST, 'handl_aicac_log_enabled', FILTER_UNSAFE_RAW );
			$policy['log_enabled'] = ! empty( $posted_log_enabled );
		}

		$posted_log_limit = filter_input( INPUT_POST, 'handl_aicac_log_limit', FILTER_VALIDATE_INT );
		if ( false !== $posted_log_limit && null !== $posted_log_limit ) {
			$policy['log_limit'] = (int) $posted_log_limit;
		}
	}

	/**
	 * @param array{decision:string,operation:string,provider:string,model:string,plugin:string} $log_filters
	 */
	private function handle_quick_rule_redirect( array $log_filters ): void {
		$plugin = filter_input( INPUT_POST, 'handl_aicac_quick_plugin', FILTER_UNSAFE_RAW );
		$rule   = filter_input( INPUT_POST, 'handl_aicac_quick_rule', FILTER_UNSAFE_RAW );

		$plugin = sanitize_text_field( (string) $plugin );
		$rule   = sanitize_text_field( (string) $rule );

		if ( Policy::set_plugin_rule( $plugin, $rule ) ) {
			$redirect = add_query_arg(
				array_merge(
					array(
						'page'                    => 'handl-ai-connector-access-control',
						'handl_aicac_tab'         => 'log',
						'handl_aicac_quick_saved' => '1',
					),
					$this->log_filters_to_query_args( $log_filters )
				),
				admin_url( 'options-general.php' )
			);
			wp_safe_redirect( $redirect );
			exit;
		}
	}

	/**
	 * @param array<string,mixed> $policy
	 * @param array<string,array<string,mixed>> $plugins
	 */
	private function render_kill_switch_settings_rows( array $policy, string $form_id, array $plugins ): void {
		$kill_switch = ! empty( $policy['kill_switch'] );
		$exceptions  = Policy::get_kill_switch_exceptions( $policy );

		echo '<tr>';
		echo '<th scope="row">' . esc_html__( 'Emergency kill switch', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<td>';
		echo '<label><input type="checkbox" name="handl_aicac_kill_switch" value="1" form="' . esc_attr( $form_id ) . '" ' . checked( $kill_switch, true, false ) . ' id="handl-aicac-kill-switch" /> ';
		echo esc_html__( 'Block all AI Client calls', 'handl-ai-connector-access-control' ) . '</label>';
		echo '<p class="description">' . esc_html__( 'Blocks every AI Client call except plugins listed as exceptions. Unresolved callers are blocked too.', 'handl-ai-connector-access-control' ) . '</p>';

		echo '<div class="handl-aicac-kill-exceptions" style="margin-top:12px;">';
		echo '<label for="handl-aicac-kill-exceptions"><strong>' . esc_html__( 'Exceptions (normal rules still apply)', 'handl-ai-connector-access-control' ) . '</strong></label><br />';
		echo '<select id="handl-aicac-kill-exceptions" name="handl_aicac_kill_exceptions[]" form="' . esc_attr( $form_id ) . '" multiple size="8" style="min-width:28em;max-width:100%;margin-top:6px;">';
		foreach ( $plugins as $basename => $data ) {
			$name = isset( $data['Name'] ) ? (string) $data['Name'] : $basename;
			printf(
				'<option value="%1$s" %2$s>%3$s (%4$s)</option>',
				esc_attr( $basename ),
				selected( in_array( $basename, $exceptions, true ), true, false ),
				esc_html( $name ),
				esc_html( $basename )
			);
		}
		echo '</select>';
		echo '<p class="description">' . esc_html__( 'Excepted plugins are not killed site-wide — they still follow their normal plugin allow/deny and capability-family rules. Hold Cmd (Mac) or Ctrl (Windows) to select multiple. Ignored when the kill switch is off.', 'handl-ai-connector-access-control' ) . '</p>';
		echo '</div>';
		echo '</td>';
		echo '</tr>';
	}

	/**
	 * @param array<int,mixed> $log
	 * @param array<string,mixed> $policy
	 * @param array<string,array<string,mixed>> $plugins
	 * @param array{decision:string,operation:string,provider:string,model:string,plugin:string} $log_filters
	 */
	private function render_suggested_rules( array $log, array $policy, array $plugins, array $log_filters ): void {
		$suggested = Policy::suggested_rules_from_log( $log, $policy, $plugins );

		echo '<h2>' . esc_html__( 'Suggested rules', 'handl-ai-connector-access-control' ) . '</h2>';
		echo '<p class="description handl-aicac-log-meta" style="margin-top:0;">';
		echo esc_html__( 'Plugins seen in the log during learn mode. “Plugin-level would enforce” is the outer plugin gate only (kill switch + plugin allow/deny) — it does not include capability-family rules. Per-family effective decisions come later.', 'handl-ai-connector-access-control' );
		echo '</p>';

		if ( empty( $suggested ) ) {
			echo '<p>' . esc_html__( 'No attributed plugin calls in the log yet.', 'handl-ai-connector-access-control' ) . '</p>';
			return;
		}

		echo '<table class="widefat striped handl-aicac-suggested-rules">';
		echo '<thead><tr>';
		echo '<th>' . esc_html__( 'Plugin', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Calls', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Last seen', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Rule', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Plugin-level would enforce', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Actions', 'handl-ai-connector-access-control' ) . '</th>';
		echo '</tr></thead><tbody>';

		foreach ( array_slice( $suggested, 0, 30 ) as $row ) {
			echo '<tr>';
			echo '<td><strong>' . esc_html( $row['label'] ) . '</strong><br /><code>' . esc_html( $row['plugin'] ) . '</code></td>';
			echo '<td>' . esc_html( number_format_i18n( (int) $row['calls'] ) ) . '</td>';
			echo '<td>' . esc_html( ! empty( $row['last_ts'] ) ? wp_date( 'Y-m-d H:i:s', (int) $row['last_ts'] ) : '—' ) . '</td>';
			echo '<td>' . esc_html( $this->format_explicit_rule_label( (string) $row['explicit'] ) ) . '</td>';
			echo '<td>' . $this->render_decision_badge( (string) $row['effective'] ) . '</td>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			echo '<td class="handl-aicac-quick-actions">';
			$this->render_quick_rule_buttons( (string) $row['plugin'], $log_filters );
			echo '</td>';
			echo '</tr>';
		}

		echo '</tbody></table>';
	}

	private function format_explicit_rule_label( string $explicit ): string {
		if ( 'allow' === $explicit ) {
			return __( 'Allow', 'handl-ai-connector-access-control' );
		}
		if ( 'deny' === $explicit ) {
			return __( 'Deny', 'handl-ai-connector-access-control' );
		}
		return __( 'Default', 'handl-ai-connector-access-control' );
	}

	/**
	 * @param array{decision:string,operation:string,provider:string,model:string,plugin:string} $log_filters
	 */
	private function render_quick_rule_buttons( string $plugin_basename, array $log_filters ): void {
		if ( '' === $plugin_basename ) {
			return;
		}

		foreach ( array( 'allow', 'deny' ) as $rule ) {
			echo '<form method="post" class="handl-aicac-quick-rule-form">';
			wp_nonce_field( 'handl_aicac_quick_rule', 'handl_aicac_nonce' );
			echo '<input type="hidden" name="handl_aicac_action" value="quick_rule" />';
			echo '<input type="hidden" name="handl_aicac_quick_plugin" value="' . esc_attr( $plugin_basename ) . '" />';
			echo '<input type="hidden" name="handl_aicac_quick_rule" value="' . esc_attr( $rule ) . '" />';
			$this->render_log_filter_hiddens( $log_filters );
			$label = 'allow' === $rule
				? __( 'Allow', 'handl-ai-connector-access-control' )
				: __( 'Deny', 'handl-ai-connector-access-control' );
			$attrs = array( 'class' => 'button button-small' );
			if ( 'deny' === $rule ) {
				$attrs['class'] .= ' button-link-delete';
			}
			submit_button( $label, 'secondary', 'submit', false, $attrs );
			echo '</form>';
		}
	}

	private function handle_save_log(): void {
		$policy = Policy::get_policy();

		$this->apply_log_settings_from_post( $policy );

		Policy::save_policy( $policy );
	}

	private function render_option( string $value, string $current, string $label ): void {
		echo '<option value="' . esc_attr( $value ) . '" ' . selected( $current, $value, false ) . '>' . esc_html( $label ) . '</option>';
	}

	/**
	 * @param array<string,mixed> $row
	 * @param array<string,array<string,mixed>> $plugins
	 * @param array<string,mixed> $policy
	 * @param array{decision:string,operation:string,provider:string,model:string,plugin:string} $log_filters
	 */
	private function render_log_row( array $row, array $plugins, array $policy, array $log_filters ): void {
		$ts        = isset( $row['ts'] ) ? (int) $row['ts'] : 0;
		$decision  = isset( $row['decision'] ) ? (string) $row['decision'] : '';
		$operation = isset( $row['operation'] ) ? (string) $row['operation'] : '';
		$provider  = isset( $row['provider'] ) ? (string) $row['provider'] : '';
		$plugin    = isset( $row['plugin'] ) ? (string) $row['plugin'] : '';
		$file      = isset( $row['file'] ) ? (string) $row['file'] : '';
		$user_id   = isset( $row['user_id'] ) ? (int) $row['user_id'] : 0;
		$uri       = isset( $row['uri'] ) ? (string) $row['uri'] : '';
		$prompt        = isset( $row['prompt_preview'] ) ? (string) $row['prompt_preview'] : '';
		$input_tokens  = array_key_exists( 'input_tokens', $row ) ? (int) $row['input_tokens'] : null;
		$output_tokens = array_key_exists( 'output_tokens', $row ) ? (int) $row['output_tokens'] : null;
		$thought_tokens = array_key_exists( 'thought_tokens', $row ) ? (int) $row['thought_tokens'] : null;

		$model          = $this->get_log_row_model( $row );
		$model_inferred = ! empty( $row['model_inferred'] );

		$plugin_label = $plugin;
		if ( $plugin && isset( $plugins[ $plugin ]['Name'] ) ) {
			$plugin_label = (string) $plugins[ $plugin ]['Name'];
		}

		echo '<tr>';
		echo '<td class="column-time">' . esc_html( $ts ? wp_date( 'Y-m-d H:i:s', $ts ) : '—' ) . '</td>';
		echo '<td>';
		echo $this->render_decision_badge( $decision ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		if ( ! empty( $policy['audit_only'] ) ) {
			$would = isset( $row['would_decision'] ) ? (string) $row['would_decision'] : '';
			if ( '' === $would && $plugin ) {
				$would = Policy::effective_decision_label( $policy, $plugin );
			}
			if ( '' !== $would && $would !== $decision ) {
				echo '<br /><span class="description" style="font-size:11px;">';
				echo esc_html__( 'would', 'handl-ai-connector-access-control' ) . ' ';
				echo wp_kses_post( $this->render_decision_badge( $would ) );
				echo '</span>';
			}
		}
		$reason = isset( $row['denial_reason'] ) ? (string) $row['denial_reason'] : '';
		if ( '' !== $reason && ( 'deny' === $decision || ( ! empty( $policy['audit_only'] ) && 'deny' === ( $row['would_decision'] ?? '' ) ) ) ) {
			echo '<br /><span class="description handl-aicac-denial-reason">' . esc_html( $this->format_denial_reason_label( $reason ) ) . '</span>';
		}
		$matched = array();
		if ( isset( $row['matched_tools'] ) && is_array( $row['matched_tools'] ) ) {
			$matched = $row['matched_tools'];
		} elseif ( isset( $row['matched_abilities'] ) && is_array( $row['matched_abilities'] ) ) {
			$matched = $row['matched_abilities'];
		}
		if ( ! empty( $matched ) ) {
			echo '<br /><span class="description handl-aicac-matched-tools"><code>' . esc_html( implode( ', ', array_map( 'strval', $matched ) ) ) . '</code></span>';
		}
		$armed = array();
		if ( isset( $row['armed_tools'] ) && is_array( $row['armed_tools'] ) ) {
			$armed = $row['armed_tools'];
		} elseif ( isset( $row['armed_abilities'] ) && is_array( $row['armed_abilities'] ) ) {
			$armed = $row['armed_abilities'];
		}
		if ( ! empty( $armed ) && empty( $matched ) ) {
			echo '<br /><span class="description handl-aicac-armed-tools">' . esc_html__( 'armed:', 'handl-ai-connector-access-control' ) . ' <code>' . esc_html( implode( ', ', array_map( 'strval', $armed ) ) ) . '</code></span>';
		}
		echo '</td>';
		$family = isset( $row['capability_family'] ) ? (string) $row['capability_family'] : '';
		if ( '' === $family && '' !== $operation ) {
			$family = Operations::family_from_operation( $operation );
		}
		$family_labels = Operations::family_labels();
		$family_label  = $family_labels[ $family ] ?? ( Operations::FAMILY_UNKNOWN === $family ? __( 'Unknown', 'handl-ai-connector-access-control' ) : $family );
		echo '<td class="column-operation"><code>' . esc_html( $operation ?: '—' ) . '</code>';
		if ( '' !== $family ) {
			echo '<br /><span class="description handl-aicac-family-label">' . esc_html( $family_label ) . '</span>';
		}
		echo '</td>';
		echo '<td class="column-provider"><code>' . esc_html( $provider ?: '—' ) . '</code></td>';
		echo '<td class="column-model"><code>' . esc_html( $model ?: '—' ) . '</code>';
		if ( $model_inferred && $model ) {
			echo '<br /><span class="description" style="font-size:11px;">' . esc_html__( 'auto-resolved', 'handl-ai-connector-access-control' ) . '</span>';
		}
		echo '</td>';
		echo '<td class="column-tokens">' . $this->render_token_count( $input_tokens ) . '</td>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		echo '<td class="column-tokens">' . $this->render_token_count( $output_tokens, $thought_tokens ) . '</td>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		echo '<td>';
		if ( $plugin ) {
			echo '<strong>' . esc_html( $plugin_label ) . '</strong><br /><code>' . esc_html( $plugin ) . '</code>';
			if ( $file ) {
				echo '<br /><span class="description" style="font-size:11px;">' . esc_html( wp_basename( $file ) ) . '</span>';
			}
		} else {
			echo '<span class="handl-aicac-muted">' . esc_html__( 'unknown', 'handl-ai-connector-access-control' ) . '</span>';
		}
		echo '</td>';
		echo '<td>' . $this->render_prompt_cell( $prompt, $row ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		echo '</td>';
		echo '<td>';
		if ( $user_id > 0 ) {
			$user      = get_userdata( $user_id );
			$edit_link = get_edit_user_link( $user_id );
			if ( $user && is_string( $edit_link ) && '' !== $edit_link ) {
				echo '<a href="' . esc_url( $edit_link ) . '">' . esc_html( $user->display_name ) . '</a>';
			} elseif ( $user ) {
				echo esc_html( $user->display_name );
			} else {
				echo esc_html( sprintf( '#%d', $user_id ) );
			}
		} else {
			echo '<span class="handl-aicac-muted">—</span>';
		}
		echo '</td>';
		echo '<td><code>' . esc_html( $uri ?: '—' ) . '</code></td>';
		echo '<td class="column-actions handl-aicac-quick-actions">';
		if ( $plugin ) {
			$this->render_quick_rule_buttons( $plugin, $log_filters );
		} else {
			echo '<span class="handl-aicac-muted">—</span>';
		}
		echo '</td>';
		echo '</tr>';
	}

	private function render_token_count( ?int $count, ?int $thought_tokens = null ): string {
		if ( null === $count ) {
			return '<span class="handl-aicac-muted">—</span>';
		}

		$html = '<span class="handl-aicac-token-count">' . esc_html( number_format_i18n( $count ) ) . '</span>';

		if ( null !== $thought_tokens && $thought_tokens > 0 ) {
			$html .= '<br /><span class="description" style="font-size:11px;">' . esc_html(
				sprintf(
					/* translators: %s: formatted thought token count */
					__( '%s thought', 'handl-ai-connector-access-control' ),
					number_format_i18n( $thought_tokens )
				)
			) . '</span>';
		}

		return $html;
	}

	/**
	 * Human label for denial_reason codes (loud denials — admin blames this plugin).
	 */
	private function format_denial_reason_label( string $reason ): string {
		$map = array(
			'kill_switch'         => __( 'Denied by HandL AICAC: emergency kill switch', 'handl-ai-connector-access-control' ),
			'plugin'              => __( 'Denied by HandL AICAC: plugin rule', 'handl-ai-connector-access-control' ),
			'capability_family'   => __( 'Denied by HandL AICAC: capability family rule', 'handl-ai-connector-access-control' ),
			'unknown_operation'   => __( 'Denied by HandL AICAC: unknown operation fallback', 'handl-ai-connector-access-control' ),
			'tool_armed'          => __( 'Denied by HandL AICAC: prompt armed a blocked tool (caller intent)', 'handl-ai-connector-access-control' ),
			// Legacy reason code from pre-rename log rows.
			'ability_armed'       => __( 'Denied by HandL AICAC: prompt armed a blocked tool (caller intent)', 'handl-ai-connector-access-control' ),
		);
		return $map[ $reason ] ?? sprintf(
			/* translators: %s: internal denial reason code */
			__( 'Denied by HandL AICAC: %s', 'handl-ai-connector-access-control' ),
			$reason
		);
	}

	private function render_decision_badge( string $decision ): string {
		if ( 'allow' === $decision ) {
			return '<span class="handl-aicac-badge handl-aicac-badge--allow">' . esc_html__( 'allow', 'handl-ai-connector-access-control' ) . '</span>';
		}
		if ( 'deny' === $decision ) {
			return '<span class="handl-aicac-badge handl-aicac-badge--deny">' . esc_html__( 'deny', 'handl-ai-connector-access-control' ) . '</span>';
		}
		return '<span class="handl-aicac-muted">' . esc_html( $decision ?: '—' ) . '</span>';
	}

	/**
	 * @param array<string,mixed> $row
	 */
	private function render_prompt_cell( string $prompt, array $row ): string {
		if ( '' === $prompt ) {
			return '<span class="handl-aicac-muted">—</span>';
		}

		$config_note = '';
		if ( ! empty( $row['config'] ) && is_array( $row['config'] ) ) {
			$parts = array();
			foreach ( $row['config'] as $key => $value ) {
				if ( 'systemInstruction' === $key ) {
					continue;
				}
				$parts[] = $key . '=' . ( is_scalar( $value ) ? (string) $value : wp_json_encode( $value ) );
			}
			if ( ! empty( $parts ) ) {
				$config_note = '<p class="description" style="margin:4px 0 0;font-size:11px;">' . esc_html( implode( ', ', $parts ) ) . '</p>';
			}
		}

		$html  = '<details class="handl-aicac-prompt-details">';
		$html .= '<summary>' . esc_html__( 'View preview', 'handl-ai-connector-access-control' ) . '</summary>';
		$html .= '<pre>' . esc_html( $prompt ) . '</pre>';
		$html .= $config_note;
		$html .= '</details>';

		return $html;
	}
}
