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

		if ( isset( $_POST['handl_aicac_action'] ) && 'save' === $_POST['handl_aicac_action'] ) {
			check_admin_referer( 'handl_aicac_save_policy', 'handl_aicac_nonce' );
			$this->handle_save();
			echo '<div class="notice notice-success"><p>' . esc_html__( 'Saved.', 'handl-ai-connector-access-control' ) . '</p></div>';
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

		echo '<form method="get" style="margin: 0 0 12px 0;">';
		echo '<input type="hidden" name="page" value="handl-ai-connector-access-control" />';
		echo '<p style="margin: 0;">';
		echo '<label for="handl-aicac-status-filter"><strong>' . esc_html__( 'Show', 'handl-ai-connector-access-control' ) . '</strong></label> ';
		echo '<select id="handl-aicac-status-filter" name="handl_aicac_status" onchange="if (this.form) { if (this.form.requestSubmit) { this.form.requestSubmit(); } else { HTMLFormElement.prototype.submit.call(this.form); } }">';
		$this->render_option( 'all', $plugin_status_filter, __( 'All plugins', 'handl-ai-connector-access-control' ) );
		$this->render_option( 'active', $plugin_status_filter, __( 'Active only', 'handl-ai-connector-access-control' ) );
		$this->render_option( 'inactive', $plugin_status_filter, __( 'Inactive only', 'handl-ai-connector-access-control' ) );
		echo '</select>';
		echo ' ';
		echo '<label for="handl-aicac-access-filter"><strong>' . esc_html__( 'AI access', 'handl-ai-connector-access-control' ) . '</strong></label> ';
		echo '<select id="handl-aicac-access-filter" name="handl_aicac_access" onchange="if (this.form) { if (this.form.requestSubmit) { this.form.requestSubmit(); } else { HTMLFormElement.prototype.submit.call(this.form); } }">';
		$this->render_option( 'all', $plugin_access_filter, __( 'All', 'handl-ai-connector-access-control' ) );
		$this->render_option( 'effective-allow', $plugin_access_filter, __( 'Effective allow', 'handl-ai-connector-access-control' ) );
		$this->render_option( 'effective-deny', $plugin_access_filter, __( 'Effective deny', 'handl-ai-connector-access-control' ) );
		$this->render_option( 'default-only', $plugin_access_filter, __( 'Default only', 'handl-ai-connector-access-control' ) );
		echo '</select>';
		echo '</p>';
		echo '</form>';

		echo '<form method="post">';
		wp_nonce_field( 'handl_aicac_save_policy', 'handl_aicac_nonce' );
		echo '<input type="hidden" name="handl_aicac_action" value="save" />';
		echo '<input type="hidden" name="handl_aicac_status" value="' . esc_attr( $plugin_status_filter ) . '" />';
		echo '<input type="hidden" name="handl_aicac_access" value="' . esc_attr( $plugin_access_filter ) . '" />';

		echo '<table class="form-table" role="presentation">';
		echo '<tr>';
		echo '<th scope="row">' . esc_html__( 'Default policy', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<td>';
		echo '<select name="handl_aicac_default">';
		$this->render_option( 'allow', $policy['default'] ?? 'allow', __( 'Allow', 'handl-ai-connector-access-control' ) );
		$this->render_option( 'deny', $policy['default'] ?? 'allow', __( 'Deny', 'handl-ai-connector-access-control' ) );
		echo '</select>';
		echo '<p class="description">' . esc_html__( 'Used when the calling plugin cannot be resolved or has no explicit rule.', 'handl-ai-connector-access-control' ) . '</p>';
		echo '</td>';
		echo '</tr>';

		echo '<tr>';
		echo '<th scope="row">' . esc_html__( 'Logging', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<td>';
		echo '<label><input type="checkbox" name="handl_aicac_log_enabled" value="1" ' . checked( ! empty( $policy['log_enabled'] ), true, false ) . ' /> ' . esc_html__( 'Enable recent-call logging', 'handl-ai-connector-access-control' ) . '</label>';
		echo '<p class="description">' . esc_html__( 'Stores a local ring buffer in the options table (nothing is sent off-site). Entries may include provider, model, operation, a truncated prompt preview, attribution, decision, user id, and request URI.', 'handl-ai-connector-access-control' ) . '</p>';
		$log_limit = (int) ( $policy['log_limit'] ?? 200 );
		echo '<p style="margin-top:10px;">';
		echo '<label for="handl-aicac-log-limit"><strong>' . esc_html__( 'Retain entries', 'handl-ai-connector-access-control' ) . '</strong></label> ';
		echo '<input type="number" id="handl-aicac-log-limit" name="handl_aicac_log_limit" value="' . esc_attr( (string) $log_limit ) . '" min="20" max="1000" step="1" class="small-text" />';
		echo ' <span class="description">' . esc_html__( '(20–1000). Oldest entries drop when full. There is no time-based expiry.', 'handl-ai-connector-access-control' ) . '</span>';
		echo '</p>';
		echo '</td>';
		echo '</tr>';
		echo '</table>';

		echo '<h2>' . esc_html__( 'Plugin rules', 'handl-ai-connector-access-control' ) . '</h2>';
		echo '<table class="widefat striped">';
		echo '<thead><tr>';
		echo '<th>' . esc_html__( 'Plugin', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Status', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'AI access', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Plugin file', 'handl-ai-connector-access-control' ) . '</th>';
		echo '</tr></thead>';
		echo '<tbody>';

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

			echo '<tr>';
			echo '<td><strong>' . esc_html( $name ) . '</strong></td>';
			echo '<td>' . ( $enabled ? '<span class="dashicons dashicons-yes"></span> ' . esc_html__( 'Active', 'handl-ai-connector-access-control' ) : esc_html__( 'Inactive', 'handl-ai-connector-access-control' ) ) . '</td>';
			echo '<td>';
			echo '<select name="handl_aicac_rule[' . esc_attr( $basename ) . ']">';
			$this->render_option( '', (string) $rule, __( 'Default', 'handl-ai-connector-access-control' ) );
			$this->render_option( 'allow', (string) $rule, __( 'Allow', 'handl-ai-connector-access-control' ) );
			$this->render_option( 'deny', (string) $rule, __( 'Deny', 'handl-ai-connector-access-control' ) );
			echo '</select>';
			echo '</td>';
			echo '<td><code>' . esc_html( $basename ) . '</code></td>';
			echo '</tr>';
		}

		echo '</tbody>';
		echo '</table>';

		submit_button( __( 'Save changes', 'handl-ai-connector-access-control' ) );
		echo '</form>';

		$log_limit_policy = (int) ( $policy['log_limit'] ?? 200 );
		$stored_count     = count( $log );

		echo '<div class="handl-aicac-log-wrap">';
		echo '<h2>' . esc_html__( 'Recent AI calls (best-effort)', 'handl-ai-connector-access-control' ) . '</h2>';
		echo '<p class="handl-aicac-log-meta">';
		printf(
			/* translators: 1: stored count, 2: retention limit, 3: rows shown in table */
			esc_html__( 'Showing up to %3$d newest rows. %1$d of %2$d stored entries retained (count-based; no TTL). Provider/model are read from the prompt builder when available.', 'handl-ai-connector-access-control' ),
			(int) $stored_count,
			(int) $log_limit_policy,
			50
		);
		echo '</p>';
		echo '<table class="widefat striped handl-aicac-log-table">';
		echo '<thead><tr>';
		echo '<th class="column-time">' . esc_html__( 'Time', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Decision', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th class="column-operation">' . esc_html__( 'Operation', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th class="column-provider">' . esc_html__( 'Provider', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th class="column-model">' . esc_html__( 'Model', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Plugin', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Prompt', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'User', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'URI', 'handl-ai-connector-access-control' ) . '</th>';
		echo '</tr></thead><tbody>';

		$log   = array_reverse( $log );
		$shown = 0;
		foreach ( $log as $row ) {
			if ( $shown >= 50 ) {
				break;
			}
			if ( ! is_array( $row ) ) {
				continue;
			}
			$shown++;
			$this->render_log_row( $row, $plugins );
		}

		if ( 0 === $shown ) {
			echo '<tr><td colspan="9">' . esc_html__( 'No calls logged yet. Enable logging above and trigger an AI Client request.', 'handl-ai-connector-access-control' ) . '</td></tr>';
		}

		echo '</tbody></table>';
		echo '</div>';
		echo '</div>';
	}

	private function handle_save(): void {
		check_admin_referer( 'handl_aicac_save_policy', 'handl_aicac_nonce' );

		$policy = Policy::get_policy();

		$posted_default = filter_input( INPUT_POST, 'handl_aicac_default', FILTER_UNSAFE_RAW );
		$policy['default'] = ( 'deny' === sanitize_text_field( (string) $posted_default ) ) ? 'deny' : 'allow';

		$posted_log_enabled = filter_input( INPUT_POST, 'handl_aicac_log_enabled', FILTER_UNSAFE_RAW );
		$policy['log_enabled'] = ! empty( $posted_log_enabled );

		$posted_log_limit = filter_input( INPUT_POST, 'handl_aicac_log_limit', FILTER_VALIDATE_INT );
		if ( false !== $posted_log_limit && null !== $posted_log_limit ) {
			$policy['log_limit'] = (int) $posted_log_limit;
		}

		$rules = array();
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

		Policy::save_policy( $policy );
	}

	private function render_option( string $value, string $current, string $label ): void {
		echo '<option value="' . esc_attr( $value ) . '" ' . selected( $current, $value, false ) . '>' . esc_html( $label ) . '</option>';
	}

	/**
	 * @param array<string,mixed> $row
	 * @param array<string,array<string,mixed>> $plugins
	 */
	private function render_log_row( array $row, array $plugins ): void {
		$ts        = isset( $row['ts'] ) ? (int) $row['ts'] : 0;
		$decision  = isset( $row['decision'] ) ? (string) $row['decision'] : '';
		$operation = isset( $row['operation'] ) ? (string) $row['operation'] : '';
		$provider  = isset( $row['provider'] ) ? (string) $row['provider'] : '';
		$model     = isset( $row['model'] ) ? (string) $row['model'] : '';
		$plugin    = isset( $row['plugin'] ) ? (string) $row['plugin'] : '';
		$file      = isset( $row['file'] ) ? (string) $row['file'] : '';
		$user_id   = isset( $row['user_id'] ) ? (int) $row['user_id'] : 0;
		$uri       = isset( $row['uri'] ) ? (string) $row['uri'] : '';
		$prompt    = isset( $row['prompt_preview'] ) ? (string) $row['prompt_preview'] : '';

		if ( '' === $model && ! empty( $row['model_preferences'] ) && is_array( $row['model_preferences'] ) ) {
			$model = implode( ', ', array_map( 'strval', $row['model_preferences'] ) );
		}

		$model_inferred = ! empty( $row['model_inferred'] );

		$plugin_label = $plugin;
		if ( $plugin && isset( $plugins[ $plugin ]['Name'] ) ) {
			$plugin_label = (string) $plugins[ $plugin ]['Name'];
		}

		echo '<tr>';
		echo '<td class="column-time">' . esc_html( $ts ? wp_date( 'Y-m-d H:i:s', $ts ) : '—' ) . '</td>';
		echo '<td>' . $this->render_decision_badge( $decision ) . '</td>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		echo '<td class="column-operation"><code>' . esc_html( $operation ?: '—' ) . '</code></td>';
		echo '<td class="column-provider"><code>' . esc_html( $provider ?: '—' ) . '</code></td>';
		echo '<td class="column-model"><code>' . esc_html( $model ?: '—' ) . '</code>';
		if ( $model_inferred && $model ) {
			echo '<br /><span class="description" style="font-size:11px;">' . esc_html__( 'auto-resolved', 'handl-ai-connector-access-control' ) . '</span>';
		}
		echo '</td>';
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
		echo '</tr>';
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
