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

	/** Set when Activity save rejects an invalid webhook URL (AC6). */
	private bool $webhook_url_rejected = false;

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

		// F5: Dashboard is default (board Q2). "log" aliases Activity for old bookmarks.
		$tab = 'dashboard';
		if ( isset( $_REQUEST['handl_aicac_tab'] ) ) {
			$tab = sanitize_key( wp_unslash( (string) $_REQUEST['handl_aicac_tab'] ) );
		}
		if ( 'log' === $tab ) {
			$tab = 'activity';
		}
		if ( ! in_array( $tab, array( 'dashboard', 'rules', 'activity', 'insights' ), true ) ) {
			$tab = 'dashboard';
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
			if ( 'send_denial_digest' === $posted_action ) {
				check_admin_referer( 'handl_aicac_send_digest', 'handl_aicac_nonce' );
				Alerts::instance()->send_digest();
				$redirect = add_query_arg(
					array(
						'page'                    => 'handl-ai-connector-access-control',
						'handl_aicac_tab'         => 'activity',
						'handl_aicac_digest_sent' => '1',
					),
					admin_url( 'options-general.php' )
				);
				wp_safe_redirect( $redirect );
				exit;
			}
			if ( 'send_test_webhook' === $posted_action ) {
				check_admin_referer( 'handl_aicac_send_test_webhook', 'handl_aicac_nonce' );
				$ok = Alerts::send_test_webhook( Policy::get_policy() );
				$redirect = add_query_arg(
					array(
						'page'                       => 'handl-ai-connector-access-control',
						'handl_aicac_tab'            => 'activity',
						'handl_aicac_webhook_tested' => $ok ? '1' : '0',
					),
					admin_url( 'options-general.php' )
				);
				wp_safe_redirect( $redirect );
				exit;
			}
			if ( 'send_test_email' === $posted_action ) {
				check_admin_referer( 'handl_aicac_send_test_email', 'handl_aicac_nonce' );
				$channel = Alerts::sanitize_test_email_channel(
					isset( $_POST['handl_aicac_test_email_channel'] )
						? wp_unslash( (string) $_POST['handl_aicac_test_email_channel'] )
						: 'denial_alert'
				);
				if ( '' === $channel ) {
					$channel = 'denial_alert';
				}
				$result = Alerts::send_test_email( Policy::get_policy(), $channel );
				$redirect = add_query_arg(
					array(
						'page'                       => 'handl-ai-connector-access-control',
						'handl_aicac_tab'            => 'activity',
						'handl_aicac_test_email'     => (string) $result['status'],
						'handl_aicac_test_email_to'  => (string) $result['to'],
					),
					admin_url( 'options-general.php' )
				);
				wp_safe_redirect( $redirect );
				exit;
			}
			if ( 'undo_quick_rule' === $posted_action ) {
				check_admin_referer( 'handl_aicac_undo_quick_rule', 'handl_aicac_nonce' );
				$this->handle_undo_quick_rule();
			}
			if ( 'export_rules' === $posted_action ) {
				check_admin_referer( 'handl_aicac_export_rules', 'handl_aicac_nonce' );
				$this->handle_export_rules();
			}
			if ( 'import_rules_preview' === $posted_action ) {
				check_admin_referer( 'handl_aicac_import_rules', 'handl_aicac_nonce' );
				$this->handle_import_rules_preview();
			}
			if ( 'import_rules_confirm' === $posted_action ) {
				check_admin_referer( 'handl_aicac_import_rules_confirm', 'handl_aicac_nonce' );
				$this->handle_import_rules_confirm();
			}
		}

		$saved       = false;
		$quick_saved = isset( $_GET['handl_aicac_quick_saved'] ) && '1' === (string) $_GET['handl_aicac_quick_saved'];
		$digest_sent = isset( $_GET['handl_aicac_digest_sent'] ) && '1' === (string) $_GET['handl_aicac_digest_sent'];
		$webhook_tested = isset( $_GET['handl_aicac_webhook_tested'] ) ? sanitize_text_field( wp_unslash( (string) $_GET['handl_aicac_webhook_tested'] ) ) : '';
		$test_email_status = isset( $_GET['handl_aicac_test_email'] ) ? sanitize_key( wp_unslash( (string) $_GET['handl_aicac_test_email'] ) ) : '';
		$test_email_to     = isset( $_GET['handl_aicac_test_email_to'] )
			? Alerts::sanitize_email( wp_unslash( (string) $_GET['handl_aicac_test_email_to'] ) )
			: '';
		$blocked_ok  = isset( $_GET['handl_aicac_blocked'] ) ? sanitize_text_field( wp_unslash( (string) $_GET['handl_aicac_blocked'] ) ) : '';
		$undo_rule   = isset( $_GET['handl_aicac_undo_rule'] ) ? sanitize_text_field( wp_unslash( (string) $_GET['handl_aicac_undo_rule'] ) ) : '';
		$undone      = isset( $_GET['handl_aicac_undone'] ) && '1' === (string) $_GET['handl_aicac_undone'];
		$imported_ok = isset( $_GET['handl_aicac_imported'] ) && '1' === (string) $_GET['handl_aicac_imported'];
		$import_err  = isset( $_GET['handl_aicac_import_error'] ) ? sanitize_key( wp_unslash( (string) $_GET['handl_aicac_import_error'] ) ) : '';
		$import_ignored_q = isset( $_GET['handl_aicac_import_ignored'] ) ? sanitize_text_field( wp_unslash( (string) $_GET['handl_aicac_import_ignored'] ) ) : '';
		$show_import_preview = isset( $_GET['handl_aicac_import_preview'] ) && '1' === (string) $_GET['handl_aicac_import_preview'];

		if ( isset( $_POST['handl_aicac_action'] ) && 'save' === $_POST['handl_aicac_action'] ) {
			check_admin_referer( 'handl_aicac_save_policy', 'handl_aicac_nonce' );
			if ( 'activity' === $tab ) {
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
		echo '<p>' . esc_html__( 'See whether AI activity is governed, what is spending, and block a plugin in one click. Default policy is allow.', 'handl-ai-connector-access-control' ) . '</p>';

		$this->render_tabs( $tab, $plugin_status_filter, $plugin_access_filter, $this->log_filters );

		if ( $saved ) {
			echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__( 'Saved.', 'handl-ai-connector-access-control' ) . '</p></div>';
		}
		if ( $this->webhook_url_rejected ) {
			echo '<div class="notice notice-error is-dismissible"><p>' . esc_html__( 'Webhook URL was not saved: enter a valid http:// or https:// URL (or leave blank to disable).', 'handl-ai-connector-access-control' ) . '</p></div>';
		}
		if ( $quick_saved ) {
			echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__( 'Plugin rule updated.', 'handl-ai-connector-access-control' ) . '</p></div>';
		}
		if ( $digest_sent ) {
			echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__( 'Denial digest send attempted (queue cleared only if mail succeeded).', 'handl-ai-connector-access-control' ) . '</p></div>';
		}
		if ( '1' === $webhook_tested ) {
			echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__( 'Test webhook accepted (HTTP 2xx).', 'handl-ai-connector-access-control' ) . '</p></div>';
		} elseif ( '0' === $webhook_tested ) {
			echo '<div class="notice notice-error is-dismissible"><p>' . esc_html__( 'Test webhook failed (non-2xx, timeout, or missing URL). The sample payload is labeled as a test and does not count toward rate limits.', 'handl-ai-connector-access-control' ) . '</p></div>';
		}
		if ( 'sent' === $test_email_status ) {
			echo '<div class="notice notice-success is-dismissible"><p>';
			if ( '' !== $test_email_to ) {
				echo esc_html(
					sprintf(
						/* translators: %s: recipient email address */
						__( 'Test email sent to %s. This confirms wp_mail accepted the message; it does not prove inbox delivery.', 'handl-ai-connector-access-control' ),
						$test_email_to
					)
				);
			} else {
				echo esc_html__( 'Test email sent to the configured recipient. This confirms wp_mail accepted the message; it does not prove inbox delivery.', 'handl-ai-connector-access-control' );
			}
			echo '</p></div>';
		} elseif ( 'failed' === $test_email_status ) {
			echo '<div class="notice notice-error is-dismissible"><p>' . esc_html__( 'Test email failed: wp_mail returned false. Delivery was not claimed — check your site mail / SMTP configuration.', 'handl-ai-connector-access-control' ) . '</p></div>';
		} elseif ( 'rate_limited' === $test_email_status ) {
			echo '<div class="notice notice-warning is-dismissible"><p>' . esc_html__( 'Please wait before sending another test email (rate limited).', 'handl-ai-connector-access-control' ) . '</p></div>';
		} elseif ( 'no_recipient' === $test_email_status || 'invalid_channel' === $test_email_status ) {
			echo '<div class="notice notice-error is-dismissible"><p>' . esc_html__( 'Test email could not be sent: no valid recipient is available (configure a denial-alert recipient or set the site admin email).', 'handl-ai-connector-access-control' ) . '</p></div>';
		}
		if ( $undone ) {
			echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__( 'Plugin rule restored.', 'handl-ai-connector-access-control' ) . '</p></div>';
		}
		if ( $imported_ok ) {
			echo '<div class="notice notice-success is-dismissible"><p>';
			echo esc_html__( 'Rules imported. The policy option was fully replaced with the uploaded configuration.', 'handl-ai-connector-access-control' );
			echo ' <a href="' . esc_url(
				add_query_arg(
					array(
						'page'            => 'handl-ai-connector-access-control',
						'handl_aicac_tab' => 'rules',
					),
					admin_url( 'options-general.php' )
				)
			) . '">' . esc_html__( 'Back to Rules', 'handl-ai-connector-access-control' ) . '</a>';
			echo '</p></div>';
			if ( '' !== $import_ignored_q ) {
				$ignored_list = array_filter( array_map( 'trim', explode( ',', $import_ignored_q ) ) );
				if ( ! empty( $ignored_list ) ) {
					echo '<div class="notice notice-warning is-dismissible"><p>';
					echo esc_html__( 'Ignored unknown fields from a newer export:', 'handl-ai-connector-access-control' );
					echo ' <code>' . esc_html( implode( ', ', $ignored_list ) ) . '</code>';
					echo '</p></div>';
				}
			}
		}
		if ( '' !== $import_err ) {
			echo '<div class="notice notice-error is-dismissible"><p>' . esc_html( $this->import_error_message( $import_err ) ) . '</p></div>';
		}
		if ( '' !== $blocked_ok ) {
			$blocked_label = isset( $plugins[ $blocked_ok ]['Name'] ) ? (string) $plugins[ $blocked_ok ]['Name'] : $blocked_ok;
			echo '<div class="notice notice-success is-dismissible"><p>';
			echo esc_html(
				sprintf(
					/* translators: %s: plugin display name */
					__( 'Blocked %s at the plugin level. New AI Client calls from this plugin will be denied.', 'handl-ai-connector-access-control' ),
					$blocked_label
				)
			);
			// Board Q3: single-click block + undo notice (no confirm dialog).
			echo ' ';
			echo '<form method="post" class="handl-aicac-inline-undo" style="display:inline;">';
			wp_nonce_field( 'handl_aicac_undo_quick_rule', 'handl_aicac_nonce' );
			echo '<input type="hidden" name="handl_aicac_action" value="undo_quick_rule" />';
			echo '<input type="hidden" name="handl_aicac_quick_plugin" value="' . esc_attr( $blocked_ok ) . '" />';
			echo '<input type="hidden" name="handl_aicac_undo_rule" value="' . esc_attr( $undo_rule ) . '" />';
			submit_button( __( 'Undo', 'handl-ai-connector-access-control' ), 'link', 'submit', false );
			echo '</form>';
			echo '</p></div>';
		}

		// Honesty banner: core skips our filter when AI is disabled site-wide.
		if ( function_exists( 'wp_supports_ai' ) && ! wp_supports_ai() ) {
			$why = defined( 'WP_AI_SUPPORT' ) && ! WP_AI_SUPPORT
				? __( 'WP_AI_SUPPORT is defined as false (or equivalent).', 'handl-ai-connector-access-control' )
				: __( 'The wp_supports_ai filter is returning false.', 'handl-ai-connector-access-control' );
			echo '<div class="notice notice-warning"><p><strong>' . esc_html__( 'AI is disabled site-wide via wp_supports_ai.', 'handl-ai-connector-access-control' ) . '</strong> ';
			echo esc_html( $why ) . ' ';
			echo esc_html__( 'WordPress short-circuits prompts before HandL AICAC’s prevent filter runs, so this plugin’s audit log will be empty or incomplete for those calls — that is expected, not a broken install.', 'handl-ai-connector-access-control' );
			echo '</p></div>';
		}

		if ( ! empty( $policy['audit_only'] ) ) {
			$audit_notice = esc_html__( 'Learn mode is on: calls are logged and never blocked. Per-plugin rules show as “would enforce” only. Turn off learn mode on the Activity tab when you are ready to enforce.', 'handl-ai-connector-access-control' );
			if ( 'activity' !== $tab ) {
				$audit_notice .= ' <a href="' . esc_url( admin_url( 'options-general.php?page=handl-ai-connector-access-control&handl_aicac_tab=activity' ) ) . '">' . esc_html__( 'Open Activity', 'handl-ai-connector-access-control' ) . '</a>';
			}
			echo '<div class="notice notice-info"><p>' . wp_kses_post( $audit_notice ) . '</p></div>';
		} elseif ( ! empty( $policy['kill_switch'] ) ) {
			echo '<div class="notice notice-warning"><p>' . esc_html__( 'Emergency kill switch is on: all AI Client calls are blocked except plugins listed as exceptions.', 'handl-ai-connector-access-control' ) . '</p></div>';
		}

		if ( 'dashboard' === $tab ) {
			$this->render_dashboard_tab( $log, $policy, $plugins );
			echo '</div>';
			return;
		}

		if ( 'activity' === $tab ) {
			$this->render_log_tab( $log, $policy, $plugins );
			echo '</div>';
			return;
		}

		if ( 'insights' === $tab ) {
			$this->render_insights_tab( $log, $policy, $plugins );
			echo '</div>';
			return;
		}

		// --- Rules tab ---
		echo '<div class="handl-aicac-tab-panel">';

		$rules_form_id = 'handl-aicac-rules-save';

		echo '<form method="post" id="' . esc_attr( $rules_form_id ) . '" class="handl-aicac-rules-save-form">';
		wp_nonce_field( 'handl_aicac_save_policy', 'handl_aicac_nonce' );
		echo '<input type="hidden" name="handl_aicac_action" value="save" />';
		echo '<input type="hidden" name="handl_aicac_tab" value="rules" />';
		echo '<input type="hidden" name="handl_aicac_status" value="' . esc_attr( $plugin_status_filter ) . '" />';
		echo '<input type="hidden" name="handl_aicac_access" value="' . esc_attr( $plugin_access_filter ) . '" />';
		echo '</form>';

		// Settings demoted: collapsible panel, not the first thing you see (F5 IA).
		echo '<details class="handl-aicac-settings-panel">';
		echo '<summary><strong>' . esc_html__( 'Settings', 'handl-ai-connector-access-control' ) . '</strong> — ';
		echo esc_html__( 'site default, unknown operations, kill switch, tool arming, model force', 'handl-ai-connector-access-control' );
		echo '</summary>';
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
		$this->render_model_force_settings( $policy, $rules_form_id, $log );
		echo '</details>';

		$family_labels = Operations::family_labels();
		$force_map     = Model_Force::force_map( $policy );
		$unforced_n    = Model_Force::count_unforced_unattributed( $log );

		echo '<h2>' . esc_html__( 'Plugin rules', 'handl-ai-connector-access-control' ) . '</h2>';
		echo '<p class="description">' . esc_html__( 'Plugin access is the outer gate. Capability columns refine what an allowed plugin may do (e.g. allow text, deny image). Inherit follows the plugin AI access rule. A plugin-level Deny blocks every family. EXPERIMENTAL force columns pin the detected caller’s provider/model (best-effort nearest plugin frame — not a spend guarantee). Leave force fields empty for no pin.', 'handl-ai-connector-access-control' ) . '</p>';
		if ( $unforced_n > 0 && ! empty( $force_map ) ) {
			echo '<div class="notice notice-warning inline"><p>';
			echo esc_html(
				sprintf(
					/* translators: %d: count of unattributed unforced calls in retained log */
					_n(
						'%d call in the retained log could not be attributed and ran unforced.',
						'%d calls in the retained log could not be attributed and ran unforced.',
						$unforced_n,
						'handl-ai-connector-access-control'
					),
					$unforced_n
				)
			);
			echo ' ' . esc_html__( 'Pins follow the detected caller only; unattributed traffic is not a spend guarantee for any row below.', 'handl-ai-connector-access-control' );
			echo '</p></div>';
		}
		$this->render_plugin_rules_filters( $plugin_status_filter, $plugin_access_filter );
		echo '<table class="widefat striped handl-aicac-rules-matrix">';
		echo '<thead><tr>';
		echo '<th>' . esc_html__( 'Plugin', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Status', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'AI access', 'handl-ai-connector-access-control' ) . '</th>';
		foreach ( $family_labels as $family_id => $family_label ) {
			echo '<th class="handl-aicac-col-family">' . esc_html( $family_label ) . '</th>';
		}
		echo '<th class="handl-aicac-col-force">' . esc_html__( 'EXPERIMENTAL force provider', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th class="handl-aicac-col-force">' . esc_html__( 'EXPERIMENTAL force model', 'handl-ai-connector-access-control' ) . '</th>';
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

			$force_row = $force_map[ $basename ] ?? array( 'provider' => '', 'model' => '' );
			$force_p   = (string) ( $force_row['provider'] ?? '' );
			$force_m   = (string) ( $force_row['model'] ?? '' );

			echo '<tr>';
			echo '<td><strong>' . esc_html( $name ) . '</strong>';
			if ( '' !== $force_p && '' !== $force_m && $unforced_n > 0 ) {
				echo '<br /><span class="description handl-aicac-unforced-hint" style="font-size:11px;">';
				echo esc_html(
					sprintf(
						/* translators: %d: unattributed unforced call count */
						_n(
							'%d call could not be attributed and ran unforced',
							'%d calls could not be attributed and ran unforced',
							$unforced_n,
							'handl-ai-connector-access-control'
						),
						$unforced_n
					)
				);
				echo '</span>';
			}
			echo '</td>';
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
			echo '<td class="handl-aicac-col-force">';
			echo '<input type="text" class="regular-text code" style="max-width:9em;" name="handl_aicac_model_force[' . esc_attr( $basename ) . '][provider]" form="' . esc_attr( $rules_form_id ) . '" value="' . esc_attr( $force_p ) . '" placeholder="openai" autocomplete="off" aria-label="' . esc_attr( sprintf(
				/* translators: %s: plugin name */
				__( '%s force provider', 'handl-ai-connector-access-control' ),
				$name
			) ) . '" />';
			echo '</td>';
			echo '<td class="handl-aicac-col-force">';
			echo '<input type="text" class="regular-text code" style="max-width:11em;" name="handl_aicac_model_force[' . esc_attr( $basename ) . '][model]" form="' . esc_attr( $rules_form_id ) . '" value="' . esc_attr( $force_m ) . '" placeholder="gpt-4o-mini" autocomplete="off" aria-label="' . esc_attr( sprintf(
				/* translators: %s: plugin name */
				__( '%s force model', 'handl-ai-connector-access-control' ),
				$name
			) ) . '" />';
			echo '</td>';
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

		$this->render_rules_transfer_section( $policy, $show_import_preview );

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
	 * @param 'dashboard'|'rules'|'activity'|'insights' $active_tab
	 * @param array{decision:string,operation:string,provider:string,model:string,plugin:string} $log_filters
	 */
	private function render_tabs( string $active_tab, string $plugin_status_filter, string $plugin_access_filter, array $log_filters ): void {
		$base_args = array(
			'page' => 'handl-ai-connector-access-control',
		);

		$dashboard_url = add_query_arg(
			array_merge( $base_args, array( 'handl_aicac_tab' => 'dashboard' ) ),
			admin_url( 'options-general.php' )
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

		$activity_url = add_query_arg(
			array_merge( $base_args, array( 'handl_aicac_tab' => 'activity' ), $this->log_filters_to_query_args( $log_filters ) ),
			admin_url( 'options-general.php' )
		);

		$insights_url = add_query_arg(
			array_merge( $base_args, array( 'handl_aicac_tab' => 'insights' ) ),
			admin_url( 'options-general.php' )
		);

		echo '<nav class="nav-tab-wrapper wp-clearfix" aria-label="' . esc_attr__( 'Settings sections', 'handl-ai-connector-access-control' ) . '">';
		printf(
			'<a href="%1$s" class="nav-tab%2$s">%3$s</a>',
			esc_url( $dashboard_url ),
			'dashboard' === $active_tab ? ' nav-tab-active' : '',
			esc_html__( 'Dashboard', 'handl-ai-connector-access-control' )
		);
		printf(
			'<a href="%1$s" class="nav-tab%2$s">%3$s</a>',
			esc_url( $rules_url ),
			'rules' === $active_tab ? ' nav-tab-active' : '',
			esc_html__( 'Rules', 'handl-ai-connector-access-control' )
		);
		printf(
			'<a href="%1$s" class="nav-tab%2$s">%3$s</a>',
			esc_url( $activity_url ),
			'activity' === $active_tab ? ' nav-tab-active' : '',
			esc_html__( 'Activity', 'handl-ai-connector-access-control' )
		);
		printf(
			'<a href="%1$s" class="nav-tab%2$s handl-aicac-nav-tab--insights">%3$s</a>',
			esc_url( $insights_url ),
			'insights' === $active_tab ? ' nav-tab-active' : '',
			esc_html__( 'Insights', 'handl-ai-connector-access-control' )
		);
		echo '</nav>';
	}

	/**
	 * F5 Dashboard — answers: Am I safe? What's spending? Block that one.
	 *
	 * @param array<int,mixed> $log
	 * @param array<string,mixed> $policy
	 * @param array<string,array<string,mixed>> $plugins
	 */
	private function render_dashboard_tab( array $log, array $policy, array $plugins ): void {
		$coverage = $this->compute_coverage_buckets( $log, $policy );
		$pin      = Model_Force::pin_hold_stats( $log );
		$unforced = Model_Force::count_unforced_unattributed( $log );
		$has_pins = Model_Force::has_any_force_rules( $policy );
		$rates    = Cost::rates_from_policy( $policy );

		// Spend over retained log (AI Client rows with tokens only; direct_http has none).
		$est_total   = 0.0;
		$est_any     = false;
		$deny_n      = 0;
		$plugin_spend = array();
		foreach ( $log as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$is_direct = isset( $row['channel'] ) && 'direct_http' === (string) $row['channel'];
			if ( ! $is_direct && 'deny' === (string) ( $row['decision'] ?? '' ) ) {
				++$deny_n;
			}
			if ( $is_direct ) {
				continue;
			}
			$in  = array_key_exists( 'input_tokens', $row ) ? (int) $row['input_tokens'] : null;
			$out = array_key_exists( 'output_tokens', $row ) ? (int) $row['output_tokens'] : null;
			$usd = Cost::estimate_usd( $in, $out, $rates );
			if ( null === $usd ) {
				continue;
			}
			$est_any    = true;
			$est_total += $usd;
			$p          = isset( $row['plugin'] ) ? (string) $row['plugin'] : '';
			if ( '' === $p ) {
				$p = '__unknown__';
			}
			if ( ! isset( $plugin_spend[ $p ] ) ) {
				$plugin_spend[ $p ] = array( 'usd' => 0.0, 'calls' => 0 );
			}
			$plugin_spend[ $p ]['usd']   += $usd;
			$plugin_spend[ $p ]['calls'] += 1;
		}
		uasort(
			$plugin_spend,
			static function ( $a, $b ) {
				return $b['usd'] <=> $a['usd'];
			}
		);

		// Top attributed offenders for block-that-one (AI Client only; calls by plugin).
		$offenders = array();
		foreach ( $log as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			if ( isset( $row['channel'] ) && 'direct_http' === (string) $row['channel'] ) {
				continue;
			}
			$p = isset( $row['plugin'] ) ? (string) $row['plugin'] : '';
			if ( '' === $p ) {
				continue;
			}
			if ( ! isset( $offenders[ $p ] ) ) {
				$offenders[ $p ] = 0;
			}
			++$offenders[ $p ];
		}
		arsort( $offenders );

		// Shadow top callers (observe only — not governable here).
		$shadow_top = array();
		foreach ( $log as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			if ( ! isset( $row['channel'] ) || 'direct_http' !== (string) $row['channel'] ) {
				continue;
			}
			$p = isset( $row['plugin'] ) ? (string) $row['plugin'] : '';
			$c = isset( $row['count'] ) ? max( 1, (int) $row['count'] ) : 1;
			$key = '' !== $p ? $p : ( '__host__:' . (string) ( $row['host'] ?? '' ) );
			if ( ! isset( $shadow_top[ $key ] ) ) {
				$shadow_top[ $key ] = array(
					'calls'  => 0,
					'plugin' => $p,
					'host'   => (string) ( $row['host'] ?? '' ),
				);
			}
			$shadow_top[ $key ]['calls'] += $c;
		}
		uasort(
			$shadow_top,
			static function ( $a, $b ) {
				return $b['calls'] <=> $a['calls'];
			}
		);

		echo '<div class="handl-aicac-tab-panel handl-aicac-dashboard">';

		// --- Coverage tile (Δ1 + Δ5) ---
		echo '<div class="postbox handl-aicac-tile handl-aicac-tile--coverage">';
		echo '<div class="postbox-header"><h2 class="hndle">' . esc_html__( 'Coverage', 'handl-ai-connector-access-control' ) . '</h2></div>';
		echo '<div class="inside">';
		if ( $coverage['D'] > 0 ) {
			// Q4 defaulted headline — one string, changeable at haktan F5 review.
			echo '<p class="handl-aicac-coverage-headline"><strong>';
			echo esc_html__( 'Some AI activity on this site is outside what these rules can control', 'handl-ai-connector-access-control' );
			echo '</strong></p>';
		} elseif ( $coverage['M'] > 0 ) {
			echo '<p class="handl-aicac-coverage-headline"><strong>';
			echo esc_html__( 'Known AI activity in this log is flowing through the AI Client', 'handl-ai-connector-access-control' );
			echo '</strong></p>';
		} else {
			echo '<p class="handl-aicac-coverage-headline"><strong>';
			echo esc_html__( 'No AI activity retained in the log yet', 'handl-ai-connector-access-control' );
			echo '</strong></p>';
		}

		echo '<p class="description handl-aicac-coverage-window">';
		echo esc_html(
			sprintf(
				/* translators: 1: log_limit (row slots), 2: human span or em dash */
				__( 'from the last %1$s log entries · spanning %2$s', 'handl-ai-connector-access-control' ),
				number_format_i18n( $coverage['log_limit'] ),
				$coverage['span_label']
			)
		);
		echo '</p>';

		echo '<p class="handl-aicac-coverage-buckets">';
		echo '<strong>' . esc_html__( 'Known AI activity:', 'handl-ai-connector-access-control' ) . '</strong> ';
		echo esc_html(
			sprintf(
				/* translators: %s: formatted call count M */
				__( '%s calls', 'handl-ai-connector-access-control' ),
				number_format_i18n( $coverage['M'] )
			)
		);
		echo '<br />';
		echo esc_html(
			sprintf(
				/* translators: 1: N through AI Client, 2: A attributed, 3: U unattributed */
				__( '— Through the AI Client: %1$s (attributed %2$s · unattributed %3$s)', 'handl-ai-connector-access-control' ),
				number_format_i18n( $coverage['N'] ),
				number_format_i18n( $coverage['A'] ),
				number_format_i18n( $coverage['U'] )
			)
		);
		echo '<br />';
		echo esc_html(
			sprintf(
				/* translators: %s: D outside AI Client call count */
				__( '— Outside the AI Client: %s — seen, not governed by these rules', 'handl-ai-connector-access-control' ),
				number_format_i18n( $coverage['D'] )
			)
		);
		echo '</p>';
		// Calls (M) can exceed log_limit entries when direct_http rows collapse multiple HTTP calls.
		echo '<p class="description">' . esc_html__( 'One log entry can represent many calls from the same plugin.', 'handl-ai-connector-access-control' ) . '</p>';

		if ( $coverage['saturated'] ) {
			echo '<div class="notice notice-warning inline"><p>';
			echo esc_html(
				sprintf(
					/* translators: %d: log_limit (row slots) */
					__( 'Log is at its %d-entry limit; older entries have aged out. Raise the limit in Settings (Activity tab) for a longer window.', 'handl-ai-connector-access-control' ),
					$coverage['log_limit']
				)
			);
			echo '</p></div>';
		}

		echo '<p class="description">';
		echo esc_html__( 'Not counted here (named blind spots, not false precision): site-wide wp_supports_ai short-circuit; raw curl / external workers that never touch WordPress HTTP or the AI Client.', 'handl-ai-connector-access-control' );
		echo '</p>';
		echo '</div></div>';

		// Secondary tiles: 2-col on wide viewports (CSS); coverage stays full-width above.
		echo '<div class="handl-aicac-dashboard-grid">';

		// --- Safety / control ---
		echo '<div class="postbox handl-aicac-tile handl-aicac-tile--safety">';
		echo '<div class="postbox-header"><h2 class="hndle">' . esc_html__( 'Safety & control', 'handl-ai-connector-access-control' ) . '</h2></div>';
		echo '<div class="inside">';
		$default = ( $policy['default'] ?? 'allow' ) === 'deny' ? __( 'Deny', 'handl-ai-connector-access-control' ) : __( 'Allow', 'handl-ai-connector-access-control' );
		$learn   = ! empty( $policy['audit_only'] )
			? __( 'Learn mode on (observation only — no deny/force)', 'handl-ai-connector-access-control' )
			: __( 'Learn mode off (enforcing)', 'handl-ai-connector-access-control' );
		echo '<p><strong>' . esc_html__( 'Default:', 'handl-ai-connector-access-control' ) . '</strong> ' . esc_html( $default );
		echo ' · <strong>' . esc_html( $learn ) . '</strong></p>';
		if ( ! empty( $policy['kill_switch'] ) ) {
			echo '<p class="handl-aicac-danger"><strong>' . esc_html__( 'Emergency kill switch is on.', 'handl-ai-connector-access-control' ) . '</strong></p>';
		}
		echo '<p>' . esc_html(
			sprintf(
				/* translators: %d: deny count in retained log */
				_n( '%d deny in this log window.', '%d denies in this log window.', $deny_n, 'handl-ai-connector-access-control' ),
				$deny_n
			)
		) . '</p>';
		echo '</div></div>';

		// --- Spend ---
		echo '<div class="postbox handl-aicac-tile handl-aicac-tile--spend">';
		echo '<div class="postbox-header"><h2 class="hndle">' . esc_html__( 'Spend (estimated)', 'handl-ai-connector-access-control' ) . '</h2></div>';
		echo '<div class="inside">';
		if ( $est_any ) {
			echo '<p class="handl-aicac-spend-total"><strong>$' . esc_html( number_format_i18n( $est_total, 2 ) ) . '</strong> ';
			echo '<span class="description">' . esc_html__( 'est. · default rates', 'handl-ai-connector-access-control' );
			if ( ! Cost::using_default_rates( $policy ) ) {
				echo ' ' . esc_html__( '(custom rates)', 'handl-ai-connector-access-control' );
			}
			echo '</span></p>';
			echo '<table class="widefat striped handl-aicac-tile-table"><thead><tr>';
			echo '<th>' . esc_html__( 'Plugin', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th class="column-num">' . esc_html__( 'Est. $', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th class="column-num">' . esc_html__( 'Calls', 'handl-ai-connector-access-control' ) . '</th>';
			echo '</tr></thead><tbody>';
			$i = 0;
			foreach ( $plugin_spend as $p => $row ) {
				if ( $i >= 8 ) {
					break;
				}
				++$i;
				$label = '__unknown__' === $p
					? __( 'unknown', 'handl-ai-connector-access-control' )
					: ( isset( $plugins[ $p ]['Name'] ) ? (string) $plugins[ $p ]['Name'] : $p );
				echo '<tr><td>' . esc_html( $label ) . '</td>';
				echo '<td class="column-num">$' . esc_html( number_format_i18n( $row['usd'], 2 ) ) . '</td>';
				echo '<td class="column-num">' . esc_html( number_format_i18n( $row['calls'] ) ) . '</td></tr>';
			}
			echo '</tbody></table>';
		} else {
			echo '<p class="description">' . esc_html__( 'No token-backed estimates in the retained log yet.', 'handl-ai-connector-access-control' ) . '</p>';
		}
		echo '</div></div>';

		// --- Pin-hold (Δ2): quiet when no force rules ---
		if ( $has_pins ) {
			echo '<div class="postbox handl-aicac-tile handl-aicac-tile--pins">';
			echo '<div class="postbox-header"><h2 class="hndle">' . esc_html__( 'Did my pins hold?', 'handl-ai-connector-access-control' ) . '</h2></div>';
			echo '<div class="inside">';
			echo '<p><strong>';
			echo esc_html(
				sprintf(
					/* translators: 1: X held, 2: Y attempted */
					__( 'Pins held for %1$s of %2$s attempted forces', 'handl-ai-connector-access-control' ),
					number_format_i18n( $pin['held'] ),
					number_format_i18n( $pin['attempted'] )
				)
			);
			echo '</strong></p>';
			if ( $unforced > 0 ) {
				echo '<p>';
				echo esc_html(
					sprintf(
						/* translators: %d: unattributed never-evaluated count */
						_n(
							'%d call could not be attributed; pins were never evaluated for it.',
							'%d calls could not be attributed; pins were never evaluated for them.',
							$unforced,
							'handl-ai-connector-access-control'
						),
						$unforced
					)
				);
				echo '</p>';
			}
			if ( ! empty( $pin['by_skip'] ) ) {
				echo '<ul class="ul-disc">';
				foreach ( $pin['by_skip'] as $reason => $n ) {
					echo '<li><code>' . esc_html( $reason ) . '</code>: ' . esc_html( number_format_i18n( $n ) ) . '</li>';
				}
				echo '</ul>';
			}
			echo '</div></div>';
		}

		// --- Block that one ---
		echo '<div class="postbox handl-aicac-tile handl-aicac-tile--block">';
		echo '<div class="postbox-header"><h2 class="hndle">' . esc_html__( 'Block that one', 'handl-ai-connector-access-control' ) . '</h2></div>';
		echo '<div class="inside">';
		echo '<p class="description">' . esc_html__( 'Top attributed AI Client callers in this log. One click sets a plugin-level Deny (undo from the success notice).', 'handl-ai-connector-access-control' ) . '</p>';
		if ( empty( $offenders ) ) {
			echo '<p class="description">' . esc_html__( 'No attributed AI Client callers in the retained log.', 'handl-ai-connector-access-control' ) . '</p>';
		} else {
			echo '<table class="widefat striped handl-aicac-tile-table"><thead><tr>';
			echo '<th>' . esc_html__( 'Plugin', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th class="column-num">' . esc_html__( 'Calls', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Rule', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Actions', 'handl-ai-connector-access-control' ) . '</th>';
			echo '</tr></thead><tbody>';
			$i = 0;
			foreach ( $offenders as $p => $calls ) {
				if ( $i >= 10 ) {
					break;
				}
				++$i;
				$label    = isset( $plugins[ $p ]['Name'] ) ? (string) $plugins[ $p ]['Name'] : $p;
				$explicit = isset( $policy['plugins'][ $p ] ) ? (string) $policy['plugins'][ $p ] : '';
				echo '<tr>';
				echo '<td><strong>' . esc_html( $label ) . '</strong><br /><code>' . esc_html( $p ) . '</code></td>';
				echo '<td class="column-num">' . esc_html( number_format_i18n( $calls ) ) . '</td>';
				echo '<td>' . esc_html( $this->format_explicit_rule_label( $explicit ) ) . '</td>';
				echo '<td class="handl-aicac-quick-actions">';
				// Single-click deny (board Q3); return to dashboard with undo notice.
				echo '<form method="post" class="handl-aicac-quick-rule-form">';
				wp_nonce_field( 'handl_aicac_quick_rule', 'handl_aicac_nonce' );
				echo '<input type="hidden" name="handl_aicac_action" value="quick_rule" />';
				echo '<input type="hidden" name="handl_aicac_quick_plugin" value="' . esc_attr( $p ) . '" />';
				echo '<input type="hidden" name="handl_aicac_quick_rule" value="deny" />';
				echo '<input type="hidden" name="handl_aicac_return_tab" value="dashboard" />';
				submit_button( __( 'Block', 'handl-ai-connector-access-control' ), 'secondary', 'submit', false, array( 'class' => 'button button-small button-link-delete' ) );
				echo '</form>';
				echo '</td></tr>';
			}
			echo '</tbody></table>';
		}

		// Shadow rows: explicit not-governable state (F5 item 5 / standing rule).
		if ( ! empty( $shadow_top ) ) {
			echo '<h3 style="margin-top:1.25em;">' . esc_html__( 'Outside AI Client (observe only)', 'handl-ai-connector-access-control' ) . '</h3>';
			echo '<p class="description">' . esc_html__( 'These callers bypass the AI Client. Allow/Deny rules cannot reach them.', 'handl-ai-connector-access-control' ) . '</p>';
			echo '<table class="widefat striped handl-aicac-tile-table"><thead><tr>';
			echo '<th>' . esc_html__( 'Caller', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th class="column-num">' . esc_html__( 'Calls', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Actions', 'handl-ai-connector-access-control' ) . '</th>';
			echo '</tr></thead><tbody>';
			$i = 0;
			foreach ( $shadow_top as $row ) {
				if ( $i >= 8 ) {
					break;
				}
				++$i;
				$p     = (string) ( $row['plugin'] ?? '' );
				$label = '' !== $p && isset( $plugins[ $p ]['Name'] )
					? (string) $plugins[ $p ]['Name']
					: ( '' !== $p ? $p : (string) ( $row['host'] ?? __( 'unknown', 'handl-ai-connector-access-control' ) ) );
				echo '<tr>';
				echo '<td><strong>' . esc_html( $label ) . '</strong>';
				if ( '' !== (string) ( $row['host'] ?? '' ) ) {
					echo '<br /><code>' . esc_html( (string) $row['host'] ) . '</code>';
				}
				echo '</td>';
				echo '<td class="column-num">' . esc_html( number_format_i18n( (int) $row['calls'] ) ) . '</td>';
				echo '<td><span class="description handl-aicac-not-governable">';
				echo esc_html__( 'not governed by these rules', 'handl-ai-connector-access-control' );
				echo '</span></td></tr>';
			}
			echo '</tbody></table>';
		}
		echo '</div></div>';

		echo '</div>'; // .handl-aicac-dashboard-grid
		echo '</div>'; // .handl-aicac-dashboard
	}

	/**
	 * Coverage buckets — delegates to Analytics so Dashboard and weekly email share one implementation.
	 *
	 * @param array<int,mixed>    $log
	 * @param array<string,mixed> $policy
	 * @return array{A:int,U:int,N:int,D:int,M:int,log_limit:int,saturated:bool,span_label:string,min_ts:int,max_ts:int}
	 */
	private function compute_coverage_buckets( array $log, array $policy ): array {
		return Analytics::coverage_from_log( $log, $policy );
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
			echo esc_html__( 'No data yet. Turn on learn mode or logging on Activity, then trigger a few AI Client requests.', 'handl-ai-connector-access-control' );
			echo ' <a href="' . esc_url( admin_url( 'options-general.php?page=handl-ai-connector-access-control&handl_aicac_tab=activity' ) ) . '">';
			echo esc_html__( 'Open Activity', 'handl-ai-connector-access-control' );
			echo '</a></p>';
		} else {
			printf(
				'<p class="handl-aicac-insights-meta">%s</p>',
				esc_html(
					sprintf(
						/* translators: 1: stored entry count, 2: retention limit (entries) */
						__( 'Based on %1$d of %2$d stored entries (entry-based retention; no TTL).', 'handl-ai-connector-access-control' ),
						$stored_count,
						$log_limit_policy
					)
				)
			);
			// F6: one-line count only — not a second coverage %. Charts below are AI Client rows.
			// Sum of `count` on collapsed clusters (chatty-host collapse); missing count = 1.
			$direct_http_count = 0;
			foreach ( $log as $log_row ) {
				if ( is_array( $log_row ) && isset( $log_row['channel'] ) && 'direct_http' === (string) $log_row['channel'] ) {
					$cluster = isset( $log_row['count'] ) ? (int) $log_row['count'] : 1;
					$direct_http_count += $cluster > 0 ? $cluster : 1;
				}
			}
			if ( $direct_http_count > 0 ) {
				printf(
					'<p class="handl-aicac-insights-meta handl-aicac-insights-shadow">%s</p>',
					esc_html(
						sprintf(
							/* translators: %d: sum of direct_http row counts (HTTP calls) outside the AI Client */
							_n(
								'%d AI HTTP call outside the AI Client (seen, not governed by these rules).',
								'%d AI HTTP calls outside the AI Client (seen, not governed by these rules).',
								$direct_http_count,
								'handl-ai-connector-access-control'
							),
							$direct_http_count
						)
					)
				);
			}
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

		// Detached POST forms so "Send test email" can sit next to fields without nesting forms.
		echo '<form method="post" id="handl-aicac-test-email-denial" style="display:none;" hidden>';
		wp_nonce_field( 'handl_aicac_send_test_email', 'handl_aicac_nonce' );
		echo '<input type="hidden" name="handl_aicac_action" value="send_test_email" />';
		echo '<input type="hidden" name="handl_aicac_tab" value="activity" />';
		echo '<input type="hidden" name="handl_aicac_test_email_channel" value="denial_alert" />';
		echo '</form>';
		echo '<form method="post" id="handl-aicac-test-email-weekly" style="display:none;" hidden>';
		wp_nonce_field( 'handl_aicac_send_test_email', 'handl_aicac_nonce' );
		echo '<input type="hidden" name="handl_aicac_action" value="send_test_email" />';
		echo '<input type="hidden" name="handl_aicac_tab" value="activity" />';
		echo '<input type="hidden" name="handl_aicac_test_email_channel" value="weekly_report" />';
		echo '</form>';

		echo '<form method="post" style="margin-bottom:1.5em;">';
		wp_nonce_field( 'handl_aicac_save_policy', 'handl_aicac_nonce' );
		echo '<input type="hidden" name="handl_aicac_action" value="save" />';
		echo '<input type="hidden" name="handl_aicac_tab" value="activity" />';
		$this->render_log_filter_hiddens( $log_filters );
		$this->render_logging_settings( $policy );
		submit_button( __( 'Save audit settings', 'handl-ai-connector-access-control' ) );
		echo '</form>';

		$webhook_saved = Alerts::resolve_webhook( $policy );
		if ( '' !== $webhook_saved ) {
			echo '<form method="post" style="margin-bottom:1.5em;">';
			wp_nonce_field( 'handl_aicac_send_test_webhook', 'handl_aicac_nonce' );
			echo '<input type="hidden" name="handl_aicac_action" value="send_test_webhook" />';
			echo '<input type="hidden" name="handl_aicac_tab" value="activity" />';
			submit_button(
				__( 'Send test webhook', 'handl-ai-connector-access-control' ),
				'secondary',
				'submit',
				false
			);
			echo '<p class="description" style="display:inline;margin-left:8px;">' . esc_html__( 'POSTs a sample JSON payload labeled as a test to the saved Webhook URL immediately (bypasses rate limiting). Not a real denial.', 'handl-ai-connector-access-control' ) . '</p>';
			echo '</form>';
		}

		$pending_digest = count( Alerts::pending_digest_rows() );
		if ( $pending_digest > 0 && ! empty( $policy['alert_on_deny'] ) ) {
			echo '<form method="post" style="margin-bottom:1.5em;">';
			wp_nonce_field( 'handl_aicac_send_digest', 'handl_aicac_nonce' );
			echo '<input type="hidden" name="handl_aicac_action" value="send_denial_digest" />';
			echo '<input type="hidden" name="handl_aicac_tab" value="activity" />';
			submit_button(
				sprintf(
					/* translators: %d: queued denial count */
					__( 'Send denial digest now (%d queued)', 'handl-ai-connector-access-control' ),
					$pending_digest
				),
				'secondary',
				'submit',
				false
			);
			echo '</form>';
		}

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
				/* translators: 1: entries shown, 2: matching-entry count, 3: stored entry count, 4: retention limit */
				esc_html__( 'Showing %1$d of %2$d matching entries (newest first, up to 50). %3$d of %4$d stored entries retained (entry-based; no TTL).', 'handl-ai-connector-access-control' ),
				count( $rows_to_show ),
				$matching_count,
				(int) $stored_count,
				(int) $log_limit_policy
			);
		} else {
			printf(
				/* translators: 1: stored entry count, 2: retention limit, 3: rows shown in table */
				esc_html__( 'Showing up to %3$d newest rows. %1$d of %2$d stored entries retained (entry-based; no TTL). Provider/model are read from the prompt builder when available. Input/output tokens are filled after the model responds (allowed generate_* calls only).', 'handl-ai-connector-access-control' ),
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
		echo '<th class="column-tokens">' . esc_html__( 'Est. $', 'handl-ai-connector-access-control' ) . '</th>';
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
			echo '<tr><td colspan="13">' . esc_html( $empty_message ) . '</td></tr>';
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
			if ( 'allow' === $decision || 'deny' === $decision || 'observe' === $decision ) {
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
			if ( 'allow' === $decision || 'deny' === $decision || 'observe' === $decision ) {
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
				'handl_aicac_tab' => 'activity',
			),
			admin_url( 'options-general.php' )
		);

		$decision_views = array(
			''         => __( 'All', 'handl-ai-connector-access-control' ),
			'allow'    => __( 'Allow', 'handl-ai-connector-access-control' ),
			'deny'     => __( 'Deny', 'handl-ai-connector-access-control' ),
			'observe'  => __( 'Outside AI Client', 'handl-ai-connector-access-control' ),
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
		echo '<input type="hidden" name="handl_aicac_tab" value="activity" />';
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
		echo esc_html__( 'Use this tab to observe AI Client and direct-HTTP AI activity. Learn mode logs every call without blocking. When learn mode is off, you can still log calls for troubleshooting. Enforcement lives on the Rules and Dashboard tabs.', 'handl-ai-connector-access-control' );
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

		// F3: denial alerts.
		$alert_on    = ! empty( $policy['alert_on_deny'] );
		$alert_mode  = Alerts::sanitize_mode( $policy['alert_mode'] ?? 'immediate' );
		$alert_email = Alerts::sanitize_email( $policy['alert_email'] ?? '' );
		$alert_hook  = Alerts::sanitize_webhook_url( $policy['alert_webhook_url'] ?? '' );
		$pending     = count( Alerts::pending_digest_rows() );

		echo '<tr>';
		echo '<th scope="row">' . esc_html__( 'Denial email alerts', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<td>';
		echo '<label><input type="checkbox" name="handl_aicac_alert_on_deny" value="1" ' . checked( $alert_on, true, false ) . ' /> ';
		echo esc_html__( 'Email when a prompt is denied (enforcement only — not learn mode)', 'handl-ai-connector-access-control' ) . '</label>';
		echo '<p class="description">' . esc_html__( 'Messages are attributed to HandL AICAC so you can tell a blocked tool call from an upstream plugin bug. Uses wp_mail only.', 'handl-ai-connector-access-control' ) . '</p>';
		echo '<p style="margin-top:8px;"><label for="handl-aicac-alert-email">' . esc_html__( 'Recipient', 'handl-ai-connector-access-control' ) . '</label><br />';
		echo '<input type="email" class="regular-text" id="handl-aicac-alert-email" name="handl_aicac_alert_email" value="' . esc_attr( $alert_email ) . '" placeholder="' . esc_attr( (string) get_option( 'admin_email' ) ) . '" />';
		echo ' ';
		submit_button(
			__( 'Send test email', 'handl-ai-connector-access-control' ),
			'secondary',
			'submit',
			false,
			array(
				'form'  => 'handl-aicac-test-email-denial',
				'id'    => 'handl-aicac-send-test-denial-email',
			)
		);
		echo '<br /><span class="description">' . esc_html__( 'Leave empty to use the site admin email. Test sends use the already-saved recipient (or admin email) — not an unsaved value typed above.', 'handl-ai-connector-access-control' ) . '</span></p>';
		echo '<p style="margin-top:8px;"><label for="handl-aicac-alert-webhook">' . esc_html__( 'Webhook URL', 'handl-ai-connector-access-control' ) . '</label><br />';
		echo '<input type="url" class="regular-text" id="handl-aicac-alert-webhook" name="handl_aicac_alert_webhook_url" value="' . esc_attr( $alert_hook ) . '" placeholder="https://" pattern="https?://.*" inputmode="url" autocomplete="off" />';
		echo '<br /><span class="description">' . esc_html__( 'Optional. When set, denial alerts that would email also POST JSON to this http(s) URL (Slack/Teams-compatible incoming webhook). Same trigger, rate limit, and digest mode as email — path-only fields, no prompt preview or user identity. Leave empty to disable.', 'handl-ai-connector-access-control' ) . '</span></p>';
		echo '<p style="margin-top:8px;">';
		echo '<label><input type="radio" name="handl_aicac_alert_mode" value="immediate" ' . checked( $alert_mode, 'immediate', false ) . ' /> ';
		echo esc_html__( 'Immediate (rate-limited to 20/hour; overflow and failed sends drain via hourly cron)', 'handl-ai-connector-access-control' ) . '</label><br />';
		echo '<label><input type="radio" name="handl_aicac_alert_mode" value="digest" ' . checked( $alert_mode, 'digest', false ) . ' /> ';
		echo esc_html__( 'Hourly digest (cron; primary delivery)', 'handl-ai-connector-access-control' ) . '</label>';
		echo '</p>';
		if ( $pending > 0 ) {
			echo '<p class="description"><strong>' . esc_html(
				sprintf(
					/* translators: %d: queued denial count */
					_n( '%d denial queued for the next digest.', '%d denials queued for the next digest.', $pending, 'handl-ai-connector-access-control' ),
					$pending
				)
			) . '</strong></p>';
		}
		echo '</td>';
		echo '</tr>';

		// F7: weekly aggregate report email (Dashboard mailed).
		// Checked-but-inactive when no explicit preference: always render checked; delivery is
		// gated by logging/learn (is_active). Provenance field records what the operator saw.
		$weekly_on = ! empty( $policy['weekly_report_enabled'] );
		echo '<tr>';
		echo '<th scope="row">' . esc_html__( 'Weekly report email', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<td>';
		// Hidden provenance: "what the UI presented as the untouched state" (board re-tip).
		echo '<input type="hidden" name="handl_aicac_weekly_report_rendered" value="' . ( $weekly_on ? '1' : '0' ) . '" />';
		echo '<label><input type="checkbox" name="handl_aicac_weekly_report_enabled" value="1" ' . checked( $weekly_on, true, false ) . ' /> ';
		echo esc_html__( 'Email a weekly summary of Dashboard stats (coverage, denials, estimated spend, pins)', 'handl-ai-connector-access-control' ) . '</label>';
		echo '<p class="description">' . esc_html__( 'Selected by default. Reports are sent only while logging or learn mode is on. Uncheck and save to opt out.', 'handl-ai-connector-access-control' ) . '</p>';
		echo '<p class="description">' . esc_html__( 'Uses the same recipient as denial alerts (or the site admin email). Aggregates and plugin names only — no prompt text, user names, or request paths. Delivered by weekly WP-cron via wp_mail; the email dates its own window so a late send stays honest.', 'handl-ai-connector-access-control' ) . '</p>';
		echo '<p style="margin-top:8px;">';
		submit_button(
			__( 'Send test email', 'handl-ai-connector-access-control' ),
			'secondary',
			'submit',
			false,
			array(
				'form' => 'handl-aicac-test-email-weekly',
				'id'   => 'handl-aicac-send-test-weekly-email',
			)
		);
		echo ' <span class="description">' . esc_html__( 'Sends a clearly labeled test message to the saved denial-alert recipient (or site admin email). Rate-limited against rapid repeats.', 'handl-ai-connector-access-control' ) . '</span>';
		echo '</p>';
		echo '</td>';
		echo '</tr>';

		// F3: estimated $ rates (observability only).
		$rates = Cost::rates_from_policy( $policy );
		echo '<tr>';
		echo '<th scope="row">' . esc_html__( 'Estimated cost rates', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<td>';
		echo '<p class="description" style="margin-top:0;">' . esc_html__( 'Rough USD per 1M tokens for the audit “est. $” column only. Not billing, not enforcement — placeholders so you can scan spend-ish signal from retained logs.', 'handl-ai-connector-access-control' ) . '</p>';
		echo '<label for="handl-aicac-est-in">' . esc_html__( 'Input (prompt) $/1M', 'handl-ai-connector-access-control' ) . '</label> ';
		echo '<input type="number" step="0.01" min="0" max="10000" class="small-text" id="handl-aicac-est-in" name="handl_aicac_est_usd_input_per_m" value="' . esc_attr( (string) $rates['input_per_m'] ) . '" /> ';
		echo '<label for="handl-aicac-est-out" style="margin-left:12px;">' . esc_html__( 'Output (completion) $/1M', 'handl-ai-connector-access-control' ) . '</label> ';
		echo '<input type="number" step="0.01" min="0" max="10000" class="small-text" id="handl-aicac-est-out" name="handl_aicac_est_usd_output_per_m" value="' . esc_attr( (string) $rates['output_per_m'] ) . '" />';
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
		$this->apply_model_force_settings_from_post( $policy );

		Policy::save_policy( $policy );
	}

	/**
	 * @param array<string,mixed> $policy
	 */
	private function apply_model_force_settings_from_post( array &$policy ): void {
		$posted_map = filter_input( INPUT_POST, 'handl_aicac_model_force', FILTER_UNSAFE_RAW, FILTER_REQUIRE_ARRAY );
		$policy['model_force_plugins'] = Model_Force::sanitize_force_map( is_array( $posted_map ) ? $posted_map : array() );

		$posted_ua = filter_input( INPUT_POST, 'handl_aicac_model_force_unattributed', FILTER_UNSAFE_RAW );
		$policy['model_force_unattributed']          = Model_Force::sanitize_unattributed_mode( $posted_ua );
		$policy['model_force_unattributed_provider'] = Model_Force::sanitize_id( filter_input( INPUT_POST, 'handl_aicac_model_force_unattributed_provider', FILTER_UNSAFE_RAW ) );
		$policy['model_force_unattributed_model']    = Model_Force::sanitize_id( filter_input( INPUT_POST, 'handl_aicac_model_force_unattributed_model', FILTER_UNSAFE_RAW ) );

		// Legacy site-wide fields must not reappear.
		unset( $policy['model_force_enabled'], $policy['model_force_provider'], $policy['model_force_model'] );
	}

	/**
	 * EXPERIMENTAL per-plugin model force / downgrade (F4).
	 *
	 * Labeled experimental in words (not fine print). Relies on unsupported
	 * clone-sharing; final-route verification fail-closes on mismatch.
	 * Pins follow the detected caller (best-effort) — not a spend guarantee.
	 *
	 * @param array<string,mixed> $policy
	 * @param array<int,mixed>    $log
	 */
	private function render_model_force_settings( array $policy, string $form_id, array $log = array() ): void {
		$ua_mode  = Model_Force::sanitize_unattributed_mode( $policy['model_force_unattributed'] ?? 'none' );
		$ua_prov  = (string) ( $policy['model_force_unattributed_provider'] ?? '' );
		$ua_model = (string) ( $policy['model_force_unattributed_model'] ?? '' );
		$compat   = Model_Force::clone_compat_status();
		$health   = Model_Force::get_health();
		$force_n  = count( Model_Force::force_map( $policy ) );
		$unforced = Model_Force::count_unforced_unattributed( $log );

		echo '<h2>' . esc_html__( 'EXPERIMENTAL: Per-plugin force provider / model', 'handl-ai-connector-access-control' ) . '</h2>';
		echo '<div class="notice notice-warning inline"><p>';
		echo '<strong>' . esc_html__( 'EXPERIMENTAL — not a supported production control.', 'handl-ai-connector-access-control' ) . '</strong> ';
		echo esc_html__( 'Set provider + model on a Plugin rules row to pin that detected caller’s allowed AI Client generations. Empty force fields = no pin for that plugin. Pins follow the nearest plugin frame on the PHP backtrace (best-effort) — not who initiated the call, and not a spend guarantee. Cron, REST bootstraps, shared libraries, and MU plugins may resolve unknown or to a helper plugin; misattribution can apply the wrong pin without tripping fail-closed. Mechanism mutates a prevent-hook clone WordPress documents as read-only. Clone-compat detection is a cheap pre-check for one failure mode only — final-route verification (exact provider + model ids, no substring near-match) is the real safety. Mismatch throws so generation becomes a WP_Error before any provider call. Does not change allow/deny. Upstream routing filter draft is reviewed with the plugin author before filing.', 'handl-ai-connector-access-control' );
		echo '</p></div>';

		if ( $force_n > 0 || 'force' === $ua_mode ) {
			echo '<div class="notice notice-info inline"><p>';
			echo esc_html(
				sprintf(
					/* translators: %d: number of plugins with a force row */
					_n( '%d plugin has a force pin configured.', '%d plugins have a force pin configured.', $force_n, 'handl-ai-connector-access-control' ),
					$force_n
				)
			);
			if ( $unforced > 0 ) {
				echo ' <strong>' . esc_html(
					sprintf(
						/* translators: %d: unattributed unforced count */
						_n(
							'%d call could not be attributed and ran unforced (from retained log).',
							'%d calls could not be attributed and ran unforced (from retained log).',
							$unforced,
							'handl-ai-connector-access-control'
						),
						$unforced
					)
				) . '</strong>';
			} else {
				echo ' ' . esc_html__( 'No unattributed unforced calls in the retained log yet.', 'handl-ai-connector-access-control' );
			}
			echo '</p></div>';
		}

		echo '<table class="form-table" role="presentation">';
		echo '<tr>';
		echo '<th scope="row">' . esc_html__( 'Unattributed calls', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<td>';
		echo '<select name="handl_aicac_model_force_unattributed" id="handl-aicac-model-force-unattributed" form="' . esc_attr( $form_id ) . '">';
		$this->render_option( 'none', $ua_mode, __( 'Don’t force (recommended)', 'handl-ai-connector-access-control' ) );
		$this->render_option( 'force', $ua_mode, __( 'Force to explicit provider/model below', 'handl-ai-connector-access-control' ) );
		echo '</select>';
		echo '<p class="description">' . esc_html__( 'When the caller cannot be resolved to a plugin frame. Same idiom as Unknown operations: choose visibly. Default is don’t force — never force on a guess. The opt-in target is only the pair you enter here; it is not a site-wide default pin for attributed plugins.', 'handl-ai-connector-access-control' ) . '</p>';
		echo '<p style="margin-top:8px;">';
		echo '<label for="handl-aicac-model-force-ua-provider">' . esc_html__( 'Provider', 'handl-ai-connector-access-control' ) . '</label> ';
		echo '<input type="text" class="regular-text code" id="handl-aicac-model-force-ua-provider" name="handl_aicac_model_force_unattributed_provider" form="' . esc_attr( $form_id ) . '" value="' . esc_attr( $ua_prov ) . '" placeholder="openai" autocomplete="off" /> ';
		echo '<label for="handl-aicac-model-force-ua-model">' . esc_html__( 'Model', 'handl-ai-connector-access-control' ) . '</label> ';
		echo '<input type="text" class="regular-text code" id="handl-aicac-model-force-ua-model" name="handl_aicac_model_force_unattributed_model" form="' . esc_attr( $form_id ) . '" value="' . esc_attr( $ua_model ) . '" placeholder="gpt-4o-mini" autocomplete="off" />';
		echo '</p>';
		echo '<p class="description">' . esc_html__( 'Required only when “Force to explicit…” is selected. Incomplete force falls back to don’t force.', 'handl-ai-connector-access-control' ) . '</p>';
		echo '</td>';
		echo '</tr>';

		echo '<tr>';
		echo '<th scope="row">' . esc_html__( 'Runtime health', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<td>';
		if ( $compat['compatible'] ) {
			echo '<p style="margin:0;"><span class="dashicons dashicons-yes-alt" style="color:#00a32a;"></span> ';
			echo esc_html__( 'Clone-compat pre-check: OK (cheap check — does not prove the force will land). Final-route verification is the safety.', 'handl-ai-connector-access-control' );
			echo '</p>';
		} else {
			echo '<p style="margin:0;"><span class="dashicons dashicons-warning" style="color:#d63638;"></span> ';
			echo esc_html(
				sprintf(
					/* translators: %s: reason code */
					__( 'Clone-compat pre-check: FAIL (%s). Force will not be applied. Final-route verification remains the safety when force is active.', 'handl-ai-connector-access-control' ),
					$compat['reason']
				)
			);
			echo '</p>';
		}
		$status = isset( $health['status'] ) ? (string) $health['status'] : '';
		if ( '' !== $status ) {
			echo '<p class="description" style="margin-top:6px;">';
			echo esc_html(
				sprintf(
					/* translators: %s: health status code */
					__( 'Last force status: %s', 'handl-ai-connector-access-control' ),
					$status
				)
			);
			echo '</p>';
		}
		echo '</td>';
		echo '</tr>';
		echo '</table>';
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

		$posted_alert = filter_input( INPUT_POST, 'handl_aicac_alert_on_deny', FILTER_UNSAFE_RAW );
		$policy['alert_on_deny'] = ! empty( $posted_alert );
		$policy['alert_mode']    = Alerts::sanitize_mode( filter_input( INPUT_POST, 'handl_aicac_alert_mode', FILTER_UNSAFE_RAW ) );
		$policy['alert_email']   = Alerts::sanitize_email( filter_input( INPUT_POST, 'handl_aicac_alert_email', FILTER_UNSAFE_RAW ) );

		$webhook_check = Alerts::validate_webhook_url_input(
			filter_input( INPUT_POST, 'handl_aicac_alert_webhook_url', FILTER_UNSAFE_RAW )
		);
		if ( $webhook_check['ok'] ) {
			$policy['alert_webhook_url'] = $webhook_check['url'];
		} else {
			// AC6: reject invalid values inline — do not store; keep prior sanitized URL.
			$this->webhook_url_rejected  = true;
			$policy['alert_webhook_url'] = Alerts::sanitize_webhook_url( $policy['alert_webhook_url'] ?? '' );
		}

		// F7: persist weekly preference only on divergence from the rendered state.
		// Provenance = what the checkbox showed; unchecked checkbox posts absence.
		$posted_weekly    = ! empty( filter_input( INPUT_POST, 'handl_aicac_weekly_report_enabled', FILTER_UNSAFE_RAW ) );
		$rendered_weekly  = ! empty( filter_input( INPUT_POST, 'handl_aicac_weekly_report_rendered', FILTER_UNSAFE_RAW ) );
		$raw_opt          = get_option( Plugin::OPTION_KEY );
		$had_weekly_key   = is_array( $raw_opt ) && array_key_exists( 'weekly_report_enabled', $raw_opt );

		if ( $posted_weekly !== $rendered_weekly ) {
			// Operator diverged from what was shown → store explicit choice.
			$policy['weekly_report_enabled']  = $posted_weekly;
			$policy['_weekly_report_write']   = 'set';
		} elseif ( $had_weekly_key ) {
			// No divergence; keep the already-stored explicit choice.
			$policy['weekly_report_enabled']  = ! empty( $raw_opt['weekly_report_enabled'] );
			$policy['_weekly_report_write']   = 'set';
		} else {
			// No divergence and never stored → leave key absent (staged default re-derives).
			// In-memory true so maybe_schedule sees preference selected after logging turns on.
			$policy['weekly_report_enabled']  = true;
			$policy['_weekly_report_write']   = 'omit';
		}

		$policy['est_usd_input_per_m']  = Cost::sanitize_rate(
			filter_input( INPUT_POST, 'handl_aicac_est_usd_input_per_m', FILTER_UNSAFE_RAW ),
			Cost::DEFAULT_INPUT_PER_M
		);
		$policy['est_usd_output_per_m'] = Cost::sanitize_rate(
			filter_input( INPUT_POST, 'handl_aicac_est_usd_output_per_m', FILTER_UNSAFE_RAW ),
			Cost::DEFAULT_OUTPUT_PER_M
		);
	}

	/**
	 * @param array{decision:string,operation:string,provider:string,model:string,plugin:string} $log_filters
	 */
	private function handle_quick_rule_redirect( array $log_filters ): void {
		$plugin = filter_input( INPUT_POST, 'handl_aicac_quick_plugin', FILTER_UNSAFE_RAW );
		$rule   = filter_input( INPUT_POST, 'handl_aicac_quick_rule', FILTER_UNSAFE_RAW );
		$return = filter_input( INPUT_POST, 'handl_aicac_return_tab', FILTER_UNSAFE_RAW );

		$plugin = sanitize_text_field( (string) $plugin );
		$rule   = sanitize_text_field( (string) $rule );
		$return = sanitize_key( (string) $return );
		if ( ! in_array( $return, array( 'dashboard', 'activity', 'rules' ), true ) ) {
			$return = 'activity';
		}

		// set_plugin_rule() also accepts '' (clear) for undo — this caller must not.
		// Widening the shared validator for undo must not relax Allow/Deny posts into
		// silent rule-deletes (Lisa F5 should-fix).
		if ( 'allow' !== $rule && 'deny' !== $rule ) {
			return;
		}

		// Capture previous explicit rule for undo (empty string = Default).
		$policy   = Policy::get_policy();
		$prev     = '';
		if ( isset( $policy['plugins'][ $plugin ] ) && is_string( $policy['plugins'][ $plugin ] ) ) {
			$prev = (string) $policy['plugins'][ $plugin ];
			if ( 'allow' !== $prev && 'deny' !== $prev ) {
				$prev = '';
			}
		}

		if ( Policy::set_plugin_rule( $plugin, $rule ) ) {
			$args = array(
				'page'            => 'handl-ai-connector-access-control',
				'handl_aicac_tab' => $return,
			);
			if ( 'dashboard' === $return && 'deny' === $rule ) {
				$args['handl_aicac_blocked']   = $plugin;
				$args['handl_aicac_undo_rule'] = $prev;
			} else {
				$args['handl_aicac_quick_saved'] = '1';
				$args                           = array_merge( $args, $this->log_filters_to_query_args( $log_filters ) );
			}
			wp_safe_redirect( add_query_arg( $args, admin_url( 'options-general.php' ) ) );
			exit;
		}
	}

	/**
	 * Restore a previous plugin rule after dashboard single-click block (board Q3 undo).
	 */
	private function handle_undo_quick_rule(): void {
		$plugin = sanitize_text_field( (string) filter_input( INPUT_POST, 'handl_aicac_quick_plugin', FILTER_UNSAFE_RAW ) );
		$prev   = sanitize_text_field( (string) filter_input( INPUT_POST, 'handl_aicac_undo_rule', FILTER_UNSAFE_RAW ) );
		if ( 'allow' !== $prev && 'deny' !== $prev ) {
			$prev = '';
		}
		if ( '' !== $plugin && Policy::set_plugin_rule( $plugin, $prev ) ) {
			wp_safe_redirect(
				add_query_arg(
					array(
						'page'               => 'handl-ai-connector-access-control',
						'handl_aicac_tab'    => 'dashboard',
						'handl_aicac_undone' => '1',
					),
					admin_url( 'options-general.php' )
				)
			);
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
		// Dimmed + state note when kill is off; list stays fully operable (no pointer-events
		// block, no disabled checkboxes) so staging exceptions before enabling kill still POSTs.
		$ex_class = 'handl-aicac-kill-exceptions' . ( $kill_switch ? '' : ' is-muted' );

		echo '<tr>';
		echo '<th scope="row">' . esc_html__( 'Emergency kill switch', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<td>';
		echo '<label><input type="checkbox" name="handl_aicac_kill_switch" value="1" form="' . esc_attr( $form_id ) . '" ' . checked( $kill_switch, true, false ) . ' id="handl-aicac-kill-switch" /> ';
		echo esc_html__( 'Block all AI Client calls', 'handl-ai-connector-access-control' ) . '</label>';
		echo '<p class="description">' . esc_html__( 'Blocks every AI Client call except plugins listed as exceptions. Unresolved callers are blocked too.', 'handl-ai-connector-access-control' ) . '</p>';

		echo '<div class="' . esc_attr( $ex_class ) . '" id="handl-aicac-kill-exceptions-wrap">';
		echo '<p class="handl-aicac-kill-exceptions__heading" id="handl-aicac-kill-exceptions-heading"><strong>' . esc_html__( 'Exceptions', 'handl-ai-connector-access-control' ) . '</strong></p>';
		// Load-bearing: "exception" ≠ unconditionally allowed.
		echo '<p class="description">' . esc_html__( 'Excepted plugins still follow their normal allow/deny and capability-family rules.', 'handl-ai-connector-access-control' ) . '</p>';
		// Visible only while kill is off; same listener toggles hidden with is-muted.
		echo '<p class="description handl-aicac-kill-exceptions__state" id="handl-aicac-kill-exceptions-state"' . ( $kill_switch ? ' hidden' : '' ) . '>' . esc_html__( 'Not in effect while the kill switch is off.', 'handl-ai-connector-access-control' ) . '</p>';
		// #16: announce the kill-off state line on group focus (sibling of aria-labelledby).
		echo '<div class="handl-aicac-kill-exceptions__list" role="group" aria-labelledby="handl-aicac-kill-exceptions-heading" aria-describedby="handl-aicac-kill-exceptions-state">';
		$i = 0;
		foreach ( $plugins as $basename => $data ) {
			++$i;
			$name = isset( $data['Name'] ) ? (string) $data['Name'] : $basename;
			$id   = 'handl-aicac-kill-ex-' . (string) $i;
			$on   = in_array( $basename, $exceptions, true );
			echo '<label class="handl-aicac-kill-exceptions__item" for="' . esc_attr( $id ) . '">';
			echo '<input type="checkbox" id="' . esc_attr( $id ) . '" name="handl_aicac_kill_exceptions[]" value="' . esc_attr( $basename ) . '" form="' . esc_attr( $form_id ) . '" ' . checked( $on, true, false ) . ' />';
			echo '<span class="handl-aicac-kill-exceptions__text">';
			echo '<span class="handl-aicac-kill-exceptions__name">' . esc_html( $name ) . '</span>';
			echo '<code class="handl-aicac-kill-exceptions__slug">' . esc_html( $basename ) . '</code>';
			echo '</span>';
			echo '</label>';
		}
		echo '</div>';
		echo '</div>';
		// Live mute + state-note toggle before save (does not change policy until form submit).
		echo '<script>';
		echo '(function(){var k=document.getElementById("handl-aicac-kill-switch"),w=document.getElementById("handl-aicac-kill-exceptions-wrap"),n=document.getElementById("handl-aicac-kill-exceptions-state");';
		echo 'if(!k||!w)return;function s(){w.classList.toggle("is-muted",!k.checked);if(n)n.hidden=k.checked;}k.addEventListener("change",s);s();})();';
		echo '</script>';
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
		$is_direct_http = isset( $row['channel'] ) && 'direct_http' === (string) $row['channel'];
		$host           = isset( $row['host'] ) ? (string) $row['host'] : '';
		if ( $is_direct_http && '' === $provider && ! empty( $row['shadow_provider'] ) ) {
			$provider = (string) $row['shadow_provider'];
		}

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
		if ( $is_direct_http ) {
			echo '<br /><span class="description handl-aicac-shadow-label" style="font-size:11px;">';
			echo esc_html__( 'outside AI Client — not governed by these rules', 'handl-ai-connector-access-control' );
			echo '</span>';
			$cluster_count = isset( $row['count'] ) ? (int) $row['count'] : 1;
			if ( $cluster_count > 1 ) {
				echo '<br /><span class="description handl-aicac-shadow-count" style="font-size:11px;">';
				// count = HTTP calls (not page loads). Span from first_ts..ts when collapsed.
				$first_ts = isset( $row['first_ts'] ) ? (int) $row['first_ts'] : 0;
				$last_ts  = $ts > 0 ? $ts : ( isset( $row['ts'] ) ? (int) $row['ts'] : 0 );
				if ( $first_ts > 0 && $last_ts > 0 && $last_ts !== $first_ts ) {
					echo esc_html(
						sprintf(
							/* translators: 1: call count, 2: first time, 3: last time */
							_n(
								'seen %1$d call between %2$s and %3$s',
								'seen %1$d calls between %2$s and %3$s',
								$cluster_count,
								'handl-ai-connector-access-control'
							),
							$cluster_count,
							wp_date( 'Y-m-d H:i:s', $first_ts ),
							wp_date( 'Y-m-d H:i:s', $last_ts )
						)
					);
				} else {
					echo esc_html(
						sprintf(
							/* translators: %d: number of HTTP calls in this cluster */
							_n(
								'seen %d call',
								'seen %d calls',
								$cluster_count,
								'handl-ai-connector-access-control'
							),
							$cluster_count
						)
					);
				}
				echo '</span>';
			}
		}
		// Learn-mode "would" is AI Client only — direct_http is observe-only (no would-enforce).
		if ( ! $is_direct_http && ! empty( $policy['audit_only'] ) ) {
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
		if ( '' === $family && '' !== $operation && ! $is_direct_http ) {
			$family = Operations::family_from_operation( $operation );
		}
		$family_labels = Operations::family_labels();
		$family_label  = $family_labels[ $family ] ?? ( Operations::FAMILY_UNKNOWN === $family ? __( 'Unknown', 'handl-ai-connector-access-control' ) : $family );
		echo '<td class="column-operation"><code>' . esc_html( $operation ?: '—' ) . '</code>';
		if ( $is_direct_http && '' !== $host ) {
			echo '<br /><span class="description handl-aicac-shadow-host" style="font-size:11px;"><code>' . esc_html( $host ) . '</code></span>';
		} elseif ( '' !== $family ) {
			echo '<br /><span class="description handl-aicac-family-label">' . esc_html( $family_label ) . '</span>';
		}
		echo '</td>';
		echo '<td class="column-provider"><code>' . esc_html( $provider ?: '—' ) . '</code>';
		if ( $is_direct_http ) {
			echo '<br /><span class="description" style="font-size:11px;">' . esc_html__( 'direct HTTP', 'handl-ai-connector-access-control' ) . '</span>';
		}
		if ( ! empty( $row['pin_matched'] ) ) {
			$pp = isset( $row['pin_provider'] ) ? (string) $row['pin_provider'] : '';
			$pm = isset( $row['pin_model'] ) ? (string) $row['pin_model'] : '';
			echo '<br /><span class="description handl-aicac-pin-matched" style="font-size:11px;">';
			echo esc_html__( 'pin matched', 'handl-ai-connector-access-control' );
			if ( '' !== $pp || '' !== $pm ) {
				echo ' → <code>' . esc_html( $pp . ( '' !== $pp && '' !== $pm ? '/' : '' ) . $pm ) . '</code>';
			}
			echo '</span>';
		}
		if ( ! empty( $row['model_forced'] ) ) {
			$fp = isset( $row['forced_provider'] ) ? (string) $row['forced_provider'] : '';
			$fm = isset( $row['forced_model'] ) ? (string) $row['forced_model'] : '';
			echo '<br /><span class="description handl-aicac-forced-label" style="font-size:11px;">' . esc_html__( 'forced', 'handl-ai-connector-access-control' );
			if ( '' !== $fp || '' !== $fm ) {
				echo ' → <code>' . esc_html( trim( $fp . '/' . $fm, '/' ) ) . '</code>';
			}
			$src = isset( $row['forced_source'] ) ? (string) $row['forced_source'] : '';
			if ( 'unattributed' === $src ) {
				echo ' <em>' . esc_html__( '(unattributed rule)', 'handl-ai-connector-access-control' ) . '</em>';
			}
			echo '</span>';
		} elseif ( ! empty( $row['model_force_unforced'] ) || ( isset( $row['model_force_skipped'] ) && 'unattributed' === (string) $row['model_force_skipped'] ) ) {
			echo '<br /><span class="description handl-aicac-unforced-label" style="font-size:11px;">' . esc_html__( 'unforced (unattributed)', 'handl-ai-connector-access-control' ) . '</span>';
		}
		// Observability honesty: inferred provider/model must not look like builder-set facts.
		if ( $model_inferred && $provider ) {
			echo '<br /><span class="description handl-aicac-inferred-label" style="font-size:11px;">' . esc_html__( 'inferred', 'handl-ai-connector-access-control' ) . '</span>';
		}
		echo '</td>';
		echo '<td class="column-model"><code>' . esc_html( $model ?: '—' ) . '</code>';
		if ( $model_inferred && $model ) {
			echo '<br /><span class="description handl-aicac-inferred-label" style="font-size:11px;">' . esc_html__( 'inferred', 'handl-ai-connector-access-control' ) . '</span>';
		}
		echo '</td>';
		echo '<td class="column-tokens">' . $this->render_token_count( $input_tokens ) . '</td>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		echo '<td class="column-tokens">' . $this->render_token_count( $output_tokens, $thought_tokens ) . '</td>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		echo '<td class="column-tokens">' . $this->render_est_cost_cell( $input_tokens, $output_tokens, $policy ) . '</td>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
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
			// M4 keeps first user_id on collapse; same "first of N" honesty as path (F6 known limit).
			$user_cluster = $is_direct_http && isset( $row['count'] ) ? (int) $row['count'] : 1;
			if ( $is_direct_http && $user_cluster > 1 ) {
				echo '<br /><span class="description" style="font-size:11px;">';
				echo esc_html(
					sprintf(
						/* translators: %d: total HTTP calls in this cluster */
						_n( 'first of %d', 'first of %d', $user_cluster, 'handl-ai-connector-access-control' ),
						$user_cluster
					)
				);
				echo '</span>';
			}
		} else {
			echo '<span class="handl-aicac-muted">—</span>';
		}
		echo '</td>';
		echo '<td><code>' . esc_html( $uri ?: '—' ) . '</code>';
		// M4 keeps the first path on collapse; label it when the cluster has multiple calls.
		if ( $is_direct_http && '' !== $uri ) {
			$uri_cluster = isset( $row['count'] ) ? (int) $row['count'] : 1;
			if ( $uri_cluster > 1 ) {
				echo '<br /><span class="description" style="font-size:11px;">';
				echo esc_html(
					sprintf(
						/* translators: %d: total HTTP calls in this cluster */
						_n( 'first of %d', 'first of %d', $uri_cluster, 'handl-ai-connector-access-control' ),
						$uri_cluster
					)
				);
				echo '</span>';
			}
		}
		echo '</td>';
		echo '<td class="column-actions handl-aicac-quick-actions">';
		// direct_http is observe-only: Allow/Deny write AI Client rules that cannot
		// govern this traffic. A live button that is a no-op for the row shown is a
		// false enforcement surface (F6 live gate / F5 item 5 / standing rule: the PR
		// that introduces a row type owns every control that renders on that type).
		// Wording matches the decision-column label — one concept, one phrase.
		if ( $is_direct_http ) {
			echo '<span class="description handl-aicac-not-governable" style="font-size:11px;">';
			echo esc_html__( 'not governed by these rules', 'handl-ai-connector-access-control' );
			echo '</span>';
		} elseif ( $plugin ) {
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
	 * Estimated USD cell — observability only; never enforcement.
	 *
	 * @param array<string,mixed> $policy
	 */
	private function render_est_cost_cell( ?int $input_tokens, ?int $output_tokens, array $policy ): string {
		if ( null === $input_tokens && null === $output_tokens ) {
			return '<span class="handl-aicac-muted">—</span>';
		}

		$usd = Cost::estimate_usd( $input_tokens, $output_tokens, Cost::rates_from_policy( $policy ) );
		if ( null === $usd ) {
			return '<span class="handl-aicac-muted">—</span>';
		}

		$using_defaults = Cost::using_default_rates( $policy );
		$title          = $using_defaults
			? __( 'Rough estimate using built-in default placeholder rates × tokens. Not a bill — set rates under Estimated cost rates.', 'handl-ai-connector-access-control' )
			: __( 'Rough estimate from configured rates × tokens. Not a bill.', 'handl-ai-connector-access-control' );
		$label          = $using_defaults
			? __( 'est. · default rates', 'handl-ai-connector-access-control' )
			: __( 'est.', 'handl-ai-connector-access-control' );

		return '<span class="handl-aicac-est-cost" title="' . esc_attr( $title ) . '">'
			. esc_html( Cost::format_usd( $usd ) )
			. '<br /><span class="description" style="font-size:11px;">' . esc_html( $label ) . '</span>'
			. '</span>';
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
		if ( 'observe' === $decision ) {
			return '<span class="handl-aicac-badge handl-aicac-badge--observe">' . esc_html__( 'observe', 'handl-ai-connector-access-control' ) . '</span>';
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

	/**
	 * Rules-tab export / import (AICAC-102).
	 *
	 * @param array<string,mixed> $policy
	 */
	private function render_rules_transfer_section( array $policy, bool $show_preview ): void {
		echo '<hr />';
		echo '<h2>' . esc_html__( 'Export / import rules', 'handl-ai-connector-access-control' ) . '</h2>';
		echo '<p class="description">' . esc_html__( 'Download the current policy option as JSON, or upload a previous export. Import fully replaces the live policy option (default, plugin rules, capability families, kill switch, denied tools, model-force pins, and other fields stored in the same option). The audit log is not included.', 'handl-ai-connector-access-control' ) . '</p>';

		echo '<form method="post" style="margin-bottom:1em;">';
		wp_nonce_field( 'handl_aicac_export_rules', 'handl_aicac_nonce' );
		echo '<input type="hidden" name="handl_aicac_action" value="export_rules" />';
		echo '<input type="hidden" name="handl_aicac_tab" value="rules" />';
		submit_button( __( 'Download rules (JSON)', 'handl-ai-connector-access-control' ), 'secondary', 'submit', false );
		echo '</form>';

		echo '<form method="post" enctype="multipart/form-data" style="margin-bottom:1em;">';
		wp_nonce_field( 'handl_aicac_import_rules', 'handl_aicac_nonce' );
		echo '<input type="hidden" name="handl_aicac_action" value="import_rules_preview" />';
		echo '<input type="hidden" name="handl_aicac_tab" value="rules" />';
		echo '<p>';
		echo '<label for="handl-aicac-import-file"><strong>' . esc_html__( 'Import rules (JSON)', 'handl-ai-connector-access-control' ) . '</strong></label><br />';
		echo '<input type="file" id="handl-aicac-import-file" name="handl_aicac_import_file" accept="application/json,.json" required />';
		echo '</p>';
		echo '<p class="description">' . esc_html__( 'Upload only (max ~1MB). You will preview added/changed/removed rules before anything is written.', 'handl-ai-connector-access-control' ) . '</p>';
		submit_button( __( 'Upload and preview', 'handl-ai-connector-access-control' ), 'secondary', 'submit', false );
		echo '</form>';

		if ( ! $show_preview ) {
			return;
		}

		$user_id = get_current_user_id();
		$pending = get_transient( Policy_Transfer::preview_transient_key( $user_id ) );
		if ( ! is_array( $pending ) || ! isset( $pending['policy'] ) || ! is_array( $pending['policy'] ) ) {
			echo '<div class="notice notice-warning inline"><p>' . esc_html__( 'Import preview expired or was not found. Upload the file again.', 'handl-ai-connector-access-control' ) . '</p></div>';
			return;
		}

		$incoming = $pending['policy'];
		$ignored  = isset( $pending['ignored'] ) && is_array( $pending['ignored'] ) ? $pending['ignored'] : array();
		$diff     = Policy_Transfer::diff_policies( $policy, $incoming );
		$lines    = Policy_Transfer::format_diff_lines( $diff );

		echo '<div class="handl-aicac-import-preview" style="border:1px solid #c3c4c7;padding:12px 16px;background:#fff;max-width:52em;">';
		echo '<h3>' . esc_html__( 'Import preview', 'handl-ai-connector-access-control' ) . '</h3>';
		echo '<p><strong>' . esc_html__( 'Mode: full replace', 'handl-ai-connector-access-control' ) . '</strong> — ';
		echo esc_html__( 'Confirming will atomically replace the entire policy option with the uploaded configuration (after the same sanitization used when saving Rules).', 'handl-ai-connector-access-control' );
		echo '</p>';

		if ( ! empty( $ignored ) ) {
			echo '<div class="notice notice-warning inline"><p>';
			echo esc_html__( 'Unknown fields from a newer export will be ignored:', 'handl-ai-connector-access-control' );
			echo ' <code>' . esc_html( implode( ', ', array_map( 'strval', $ignored ) ) ) . '</code>';
			echo '</p></div>';
		}

		echo '<ul style="margin-left:1.2em;list-style:disc;">';
		foreach ( $lines as $line ) {
			echo '<li>' . esc_html( $line ) . '</li>';
		}
		echo '</ul>';

		$empty_ruleset = empty( $incoming['plugins'] )
			&& empty( $incoming['operations'] )
			&& empty( $incoming['denied_tools'] )
			&& empty( $incoming['denied_abilities'] )
			&& empty( $incoming['model_force_plugins'] )
			&& empty( $incoming['kill_switch'] );
		if ( $empty_ruleset ) {
			echo '<div class="notice notice-info inline"><p>' . esc_html__( 'This export has an empty ruleset (no per-plugin rules, family settings, denied tools, model-force pins, or kill switch). Confirming is a legitimate reset path.', 'handl-ai-connector-access-control' ) . '</p></div>';
		}

		echo '<form method="post">';
		wp_nonce_field( 'handl_aicac_import_rules_confirm', 'handl_aicac_nonce' );
		echo '<input type="hidden" name="handl_aicac_action" value="import_rules_confirm" />';
		echo '<input type="hidden" name="handl_aicac_tab" value="rules" />';
		submit_button( __( 'Confirm import (full replace)', 'handl-ai-connector-access-control' ), 'primary', 'submit', false );
		echo '</form>';
		echo '</div>';
	}

	/**
	 * Stream current policy as a JSON download (AC1).
	 */
	private function handle_export_rules(): void {
		$policy  = Policy::get_policy();
		$export  = Policy_Transfer::build_export(
			$policy,
			defined( 'HANDL_AICAC_VERSION' ) ? (string) HANDL_AICAC_VERSION : '',
			gmdate( 'c' )
		);
		$payload = Policy_Transfer::encode_export( $export );
		$filename = 'handl-aicac-rules-' . gmdate( 'Ymd-His' ) . '.json';

		nocache_headers();
		header( 'Content-Type: application/json; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename="' . $filename . '"' );
		header( 'Content-Length: ' . (string) strlen( $payload ) );
		// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- raw JSON download body.
		echo $payload;
		exit;
	}

	/**
	 * Validate upload and stash preview; no policy write (AC2/AC4).
	 */
	private function handle_import_rules_preview(): void {
		$redirect_base = array(
			'page'            => 'handl-ai-connector-access-control',
			'handl_aicac_tab' => 'rules',
		);

		if ( empty( $_FILES['handl_aicac_import_file'] ) || ! is_array( $_FILES['handl_aicac_import_file'] ) ) {
			wp_safe_redirect(
				add_query_arg(
					array_merge( $redirect_base, array( 'handl_aicac_import_error' => 'no_file' ) ),
					admin_url( 'options-general.php' )
				)
			);
			exit;
		}

		$file = $_FILES['handl_aicac_import_file'];
		$err  = isset( $file['error'] ) ? (int) $file['error'] : UPLOAD_ERR_NO_FILE;
		if ( UPLOAD_ERR_NO_FILE === $err ) {
			wp_safe_redirect(
				add_query_arg(
					array_merge( $redirect_base, array( 'handl_aicac_import_error' => 'empty' ) ),
					admin_url( 'options-general.php' )
				)
			);
			exit;
		}
		if ( UPLOAD_ERR_OK !== $err ) {
			wp_safe_redirect(
				add_query_arg(
					array_merge( $redirect_base, array( 'handl_aicac_import_error' => 'upload_failed' ) ),
					admin_url( 'options-general.php' )
				)
			);
			exit;
		}

		$size = isset( $file['size'] ) ? (int) $file['size'] : 0;
		if ( $size <= 0 ) {
			wp_safe_redirect(
				add_query_arg(
					array_merge( $redirect_base, array( 'handl_aicac_import_error' => 'empty' ) ),
					admin_url( 'options-general.php' )
				)
			);
			exit;
		}
		if ( $size > Policy_Transfer::MAX_UPLOAD_BYTES ) {
			wp_safe_redirect(
				add_query_arg(
					array_merge( $redirect_base, array( 'handl_aicac_import_error' => 'too_large' ) ),
					admin_url( 'options-general.php' )
				)
			);
			exit;
		}

		$tmp = isset( $file['tmp_name'] ) ? (string) $file['tmp_name'] : '';
		if ( '' === $tmp || ! is_uploaded_file( $tmp ) ) {
			wp_safe_redirect(
				add_query_arg(
					array_merge( $redirect_base, array( 'handl_aicac_import_error' => 'upload_failed' ) ),
					admin_url( 'options-general.php' )
				)
			);
			exit;
		}

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- local upload tmp only.
		$raw = file_get_contents( $tmp );
		if ( ! is_string( $raw ) ) {
			wp_safe_redirect(
				add_query_arg(
					array_merge( $redirect_base, array( 'handl_aicac_import_error' => 'upload_failed' ) ),
					admin_url( 'options-general.php' )
				)
			);
			exit;
		}

		$parsed = Policy_Transfer::parse_import( $raw );
		if ( empty( $parsed['ok'] ) ) {
			$code = isset( $parsed['error'] ) ? (string) $parsed['error'] : 'invalid_json';
			wp_safe_redirect(
				add_query_arg(
					array_merge( $redirect_base, array( 'handl_aicac_import_error' => $code ) ),
					admin_url( 'options-general.php' )
				)
			);
			exit;
		}

		$user_id = get_current_user_id();
		set_transient(
			Policy_Transfer::preview_transient_key( $user_id ),
			array(
				'policy'         => $parsed['policy'],
				'ignored'        => $parsed['ignored'],
				'plugin_version' => $parsed['plugin_version'],
				'exported_at'    => $parsed['exported_at'],
			),
			Policy_Transfer::PREVIEW_TTL
		);

		wp_safe_redirect(
			add_query_arg(
				array_merge( $redirect_base, array( 'handl_aicac_import_preview' => '1' ) ),
				admin_url( 'options-general.php' )
			)
		);
		exit;
	}

	/**
	 * Confirm pending import: full replace via Policy::save_policy (AC3).
	 */
	private function handle_import_rules_confirm(): void {
		$redirect_base = array(
			'page'            => 'handl-ai-connector-access-control',
			'handl_aicac_tab' => 'rules',
		);

		$user_id = get_current_user_id();
		$key     = Policy_Transfer::preview_transient_key( $user_id );
		$pending = get_transient( $key );
		if ( ! is_array( $pending ) || ! isset( $pending['policy'] ) || ! is_array( $pending['policy'] ) ) {
			wp_safe_redirect(
				add_query_arg(
					array_merge( $redirect_base, array( 'handl_aicac_import_error' => 'preview_expired' ) ),
					admin_url( 'options-general.php' )
				)
			);
			exit;
		}

		$for_save = Policy_Transfer::policy_for_save( $pending['policy'] );
		Policy::save_policy( $for_save );
		delete_transient( $key );

		$args = array( 'handl_aicac_imported' => '1' );
		$ignored = isset( $pending['ignored'] ) && is_array( $pending['ignored'] ) ? $pending['ignored'] : array();
		if ( ! empty( $ignored ) ) {
			$args['handl_aicac_import_ignored'] = implode( ',', array_map( 'strval', $ignored ) );
		}

		wp_safe_redirect(
			add_query_arg(
				array_merge( $redirect_base, $args ),
				admin_url( 'options-general.php' )
			)
		);
		exit;
	}

	/**
	 * Map import error codes to admin-facing messages (AC4).
	 */
	private function import_error_message( string $code ): string {
		$messages = array(
			'empty'                => __( 'Import rejected: the uploaded file was empty. Live policy was not changed.', 'handl-ai-connector-access-control' ),
			'no_file'              => __( 'Import rejected: no file was uploaded. Live policy was not changed.', 'handl-ai-connector-access-control' ),
			'upload_failed'        => __( 'Import rejected: the upload failed. Live policy was not changed.', 'handl-ai-connector-access-control' ),
			'too_large'            => __( 'Import rejected: file exceeds the 1MB size limit. Live policy was not changed.', 'handl-ai-connector-access-control' ),
			'invalid_json'         => __( 'Import rejected: the file is not valid JSON. Live policy was not changed.', 'handl-ai-connector-access-control' ),
			'missing_required_keys'=> __( 'Import rejected: required keys plugin_version and exported_at are missing. Live policy was not changed.', 'handl-ai-connector-access-control' ),
			'preview_expired'      => __( 'Import rejected: the preview expired. Upload the file again. Live policy was not changed.', 'handl-ai-connector-access-control' ),
		);

		return $messages[ $code ] ?? __( 'Import rejected. Live policy was not changed.', 'handl-ai-connector-access-control' );
	}
}

