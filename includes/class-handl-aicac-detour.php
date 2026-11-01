<?php
/**
 * AICAC-DETOUR (#489): smallest single settings change that would have allowed a deny.
 *
 * Pure read-only counterfactual at render time. Re-evaluates the recorded ask
 * against one-toggle variants of the live policy via Policy_Simulator (or
 * Policy::evaluate). Never auto-applies; never writes options. Surfaces a
 * "What would allow this" line next to Why / deny-receipt lookup via
 * admin_footer injection — zero edits to why.php, deny-receipt.php, or
 * policy-simulator.php.
 *
 * README-FREE.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Counterfactual "open route" for denied AI Client calls.
 */
final class Detour {

	public const LABEL = 'What would allow this';

	public const NONE_COPY = 'No single change allows this.';

	/** @var bool */
	private static $registered = false;

	/** @var array<string,mixed>|null Injected policy for tests. */
	private static $test_policy = null;

	/** @var bool|null Injected manage-cap override for tests. */
	private static $test_can_manage = null;

	public static function init(): void {
		if ( self::$registered ) {
			return;
		}
		self::$registered = true;

		add_action( 'admin_footer', array( self::class, 'maybe_inject_activity' ), 40 );
		add_action( 'admin_footer', array( self::class, 'maybe_inject_deny_receipt' ), 40 );
	}

	public static function reset_for_tests(): void {
		self::$registered      = false;
		self::$test_policy     = null;
		self::$test_can_manage = null;
	}

	/**
	 * @param array<string,mixed>|null $policy
	 */
	public static function set_test_policy( $policy ): void {
		self::$test_policy = is_array( $policy ) ? $policy : null;
	}

	public static function set_test_can_manage( ?bool $can ): void {
		self::$test_can_manage = $can;
	}

	public static function viewer_can_apply(): bool {
		if ( null !== self::$test_can_manage ) {
			return (bool) self::$test_can_manage;
		}
		if ( class_exists( Caps::class, false ) ) {
			return Caps::user_can_manage();
		}

		return function_exists( 'current_user_can' ) && current_user_can( 'manage_options' );
	}

	/**
	 * @return array<string,mixed>
	 */
	public static function live_policy(): array {
		if ( is_array( self::$test_policy ) ) {
			return self::$test_policy;
		}
		if ( class_exists( Policy::class, false ) ) {
			return Policy::get_policy();
		}

		return array();
	}

	/**
	 * @param array<string,mixed> $event Activity / deny row.
	 * @return array{kind:string,message:string,url:string}|null Null when not a deny or viewer cannot manage.
	 */
	public static function suggest( array $event ): ?array {
		if ( ! self::viewer_can_apply() ) {
			return null;
		}

		$decision = isset( $event['decision'] ) ? (string) $event['decision'] : '';
		if ( 'deny' !== $decision ) {
			return null;
		}

		$policy = self::live_policy();
		$plugin = isset( $event['plugin'] ) ? (string) $event['plugin'] : '';
		$op     = isset( $event['operation'] ) ? (string) $event['operation'] : '';
		$family = isset( $event['capability_family'] ) ? (string) $event['capability_family'] : '';
		if ( '' === $family && '' !== $op && class_exists( Operations::class, false ) ) {
			$family = Operations::family_from_operation( $op );
		}
		$armed = array();
		if ( isset( $event['armed_tools'] ) && is_array( $event['armed_tools'] ) ) {
			$armed = $event['armed_tools'];
		} elseif ( isset( $event['armed_abilities'] ) && is_array( $event['armed_abilities'] ) ) {
			$armed = $event['armed_abilities'];
		}

		if ( self::call_allowed( $policy, $plugin, $op, $armed, $family ) ) {
			return null;
		}

		$candidates = self::candidates_for_event( $event, $policy, $plugin, $op, $family );
		$winners    = array();
		foreach ( $candidates as $candidate ) {
			$variant = self::apply_candidate( $policy, $candidate );
			if ( self::call_allowed( $variant, $plugin, $op, $armed, $family ) ) {
				$winners[] = $candidate;
			}
		}

		if ( empty( $winners ) ) {
			return array(
				'kind'    => 'none',
				'message' => __( 'No single change allows this.', 'handl-ai-connector-access-control' ),
				'url'     => '',
			);
		}

		$pick = $winners[0];

		return array(
			'kind'    => (string) $pick['kind'],
			'message' => (string) $pick['message'],
			'url'     => (string) ( $pick['url'] ?? '' ),
		);
	}

	/**
	 * Escaped HTML fragment (label + message + optional settings link). Empty when gated out.
	 *
	 * @param array<string,mixed> $event
	 */
	public static function render_line( array $event ): string {
		$suggestion = self::suggest( $event );
		if ( null === $suggestion ) {
			return '';
		}

		$html  = '<p class="description handl-aicac-detour" style="margin:4px 0 0;">';
		$html .= '<strong>' . esc_html__( 'What would allow this', 'handl-ai-connector-access-control' ) . ':</strong> ';
		$html .= esc_html( (string) $suggestion['message'] );
		$url   = (string) ( $suggestion['url'] ?? '' );
		if ( '' !== $url && 'none' !== (string) $suggestion['kind'] ) {
			$html .= ' <a href="' . esc_url( $url ) . '">' . esc_html__( 'Open this setting', 'handl-ai-connector-access-control' ) . '</a>';
		}
		$html .= '</p>';

		return $html;
	}

	/**
	 * Append detour line after a Why expander HTML blob.
	 *
	 * @param array<string,mixed> $event
	 */
	public static function append_to_why_html( string $why_html, array $event ): string {
		$line = self::render_line( $event );
		if ( '' === $line ) {
			return $why_html;
		}

		return $why_html . $line;
	}

	public static function maybe_inject_activity(): void {
		if ( ! self::viewer_can_apply() || ! self::is_activity_screen() ) {
			return;
		}
		$log = self::read_activity_log();
		if ( empty( $log ) ) {
			return;
		}

		$payload = array();
		foreach ( $log as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			if ( 'deny' !== (string) ( $row['decision'] ?? '' ) ) {
				continue;
			}
			$line = self::render_line( $row );
			if ( '' === $line ) {
				continue;
			}
			$payload[] = array(
				'plugin'    => (string) ( $row['plugin'] ?? '' ),
				'operation' => (string) ( $row['operation'] ?? '' ),
				'ts'        => (int) ( $row['ts'] ?? 0 ),
				'html'      => $line,
			);
		}
		if ( empty( $payload ) ) {
			return;
		}

		$json = wp_json_encode( $payload );
		if ( ! is_string( $json ) || '' === $json ) {
			return;
		}

		echo '<script id="handl-aicac-detour-activity">(function(){';
		echo 'var rows=' . $json . ';'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- JSON payload of escaped HTML.
		echo 'if(!rows||!rows.length)return;';
		echo 'var table=document.querySelector(".handl-aicac-log-table");if(!table)return;';
		echo 'var trs=table.querySelectorAll("tbody tr");';
		echo 'function txt(el){return (el&&el.textContent||"").replace(/\s+/g," ").trim();}';
		echo 'for(var i=0;i<trs.length;i++){';
		echo 'var tr=trs[i];var why=tr.querySelector(".handl-aicac-why");if(!why)continue;';
		echo 'var pluginCode=tr.querySelector("td.column-plugin code, td code");';
		echo 'var opCode=tr.querySelector("td.column-operation code");';
		echo 'var plugin=txt(pluginCode);var op=txt(opCode);if(op==="—")op="";';
		echo 'for(var j=0;j<rows.length;j++){';
		echo 'var r=rows[j];if(r.plugin&&plugin.indexOf(r.plugin)===-1&&plugin!==r.plugin)continue;';
		echo 'if(r.operation&&op&&op!==r.operation)continue;';
		echo 'if(why.parentNode.querySelector(".handl-aicac-detour"))break;';
		echo 'why.insertAdjacentHTML("afterend", r.html);rows.splice(j,1);break;';
		echo '}}';
		echo '})();</script>';
	}

	public static function maybe_inject_deny_receipt(): void {
		if ( ! self::viewer_can_apply() ) {
			return;
		}
		if ( ! class_exists( Deny_Receipt::class, false ) ) {
			return;
		}
		$page = isset( $_GET['page'] ) ? sanitize_key( (string) wp_unslash( $_GET['page'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( Deny_Receipt::PAGE_SLUG !== $page ) {
			return;
		}
		$code = isset( $_GET['receipt'] ) ? (string) wp_unslash( $_GET['receipt'] ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( '' === trim( $code ) ) {
			return;
		}
		$row = Deny_Receipt::lookup( $code );
		if ( null === $row ) {
			return;
		}
		$line = self::render_line( $row );
		if ( '' === $line ) {
			return;
		}

		echo '<div id="handl-aicac-detour-receipt" style="max-width:52em;margin:8px 0 16px;">' . $line . '</div>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped in render_line.
		echo '<script>(function(){var n=document.getElementById("handl-aicac-detour-receipt");var t=document.querySelector(".wrap table.widefat");if(n&&t&&t.parentNode){t.parentNode.insertBefore(n,t.nextSibling);}})();</script>';
	}

	/**
	 * @param array<string,mixed> $policy
	 * @param list<string>        $armed
	 */
	private static function call_allowed( array $policy, string $plugin, string $op, array $armed, string $family ): bool {
		$plugin_arg = '' !== $plugin ? $plugin : null;
		$op_arg     = '' !== $op ? $op : null;
		$family_arg = '' !== $family ? $family : null;

		if ( class_exists( Policy_Simulator::class, false ) ) {
			$eval = Policy_Simulator::evaluate_call( $policy, $plugin_arg, $op_arg, $armed, $family_arg );
		} elseif ( class_exists( Policy::class, false ) ) {
			$eval = Policy::evaluate( $policy, $plugin_arg, $op_arg, $armed, $family_arg );
		} else {
			return false;
		}

		return empty( $eval['prevent'] );
	}

	/**
	 * Ordered one-toggle candidates. First winner wins (reason-aligned first).
	 *
	 * @param array<string,mixed> $event
	 * @param array<string,mixed> $policy
	 * @return list<array{kind:string,message:string,url:string,patch:array<string,mixed>}>
	 */
	private static function candidates_for_event( array $event, array $policy, string $plugin, string $op, string $family ): array {
		$reason = isset( $event['denial_reason'] ) ? (string) $event['denial_reason'] : '';
		$source = isset( $event['decision_source'] ) ? (string) $event['decision_source'] : '';
		$label  = self::connector_label( $plugin );
		$url_rules = self::rules_url( $plugin );
		$url_prot  = self::protections_url();

		$out = array();

		$family_denied = ( 'capability_family' === $reason || 'capability_family' === $source
			|| ( '' !== $family && Operations::FAMILY_UNKNOWN !== $family && isset( $policy['operations'][ $plugin ][ $family ] )
				&& 'deny' === (string) $policy['operations'][ $plugin ][ $family ] ) );

		if ( $family_denied && '' !== $plugin && '' !== $family && Operations::FAMILY_UNKNOWN !== $family ) {
			$fam_labels = class_exists( Operations::class, false ) ? Operations::family_labels() : array();
			$fam_label  = isset( $fam_labels[ $family ] ) ? (string) $fam_labels[ $family ] : $family;
			$op_name    = '' !== $op ? $op : $family;
			$out[]      = array(
				'kind'    => 'operation',
				'message' => sprintf(
					/* translators: 1: AI Client operation or family label, 2: connector/plugin name */
					__( 'Enable operation %1$s for connector %2$s', 'handl-ai-connector-access-control' ),
					$op_name,
					$label
				),
				'url'     => $url_rules,
				'patch'   => array(
					'type'   => 'operation_allow',
					'plugin' => $plugin,
					'family' => $family,
				),
			);
			unset( $fam_label );
		}

		if ( 'budget' === $reason || 'budget:hard' === $source || 'budget' === $source ) {
			$ask   = self::ask_cost_usd( $event, $policy );
			$cap   = class_exists( Budget::class, false ) ? Budget::get_budget( $policy, $plugin ) : null;
			$spend = class_exists( Budget::class, false ) ? Budget::current_period_spend( $plugin ) : 0.0;
			if ( null !== $cap && $ask > 0.0 && '' !== $plugin ) {
				$raise = round( $ask, 4 );
				$new   = round( max( (float) $cap, (float) $spend ) + $raise, 4 );
				$out[] = array(
					'kind'    => 'budget',
					'message' => sprintf(
						/* translators: 1: currency raise amount, 2: connector/plugin name */
						__( 'Raise the estimated budget for %2$s by $%1$s', 'handl-ai-connector-access-control' ),
						self::format_money( $raise ),
						$label
					),
					'url'     => $url_rules,
					'patch'   => array(
						'type'   => 'budget_raise',
						'plugin' => $plugin,
						'amount' => $new,
					),
				);
			}
		}

		if ( 'plugin' === $reason || 'rule:explicit-deny' === $source || ( '' !== $plugin && isset( $policy['plugins'][ $plugin ] ) && 'deny' === (string) $policy['plugins'][ $plugin ] ) ) {
			if ( '' !== $plugin ) {
				$out[] = array(
					'kind'    => 'plugin_allow',
					'message' => sprintf(
						/* translators: %s: connector/plugin name */
						__( 'Set connector %s to Allow', 'handl-ai-connector-access-control' ),
						$label
					),
					'url'     => $url_rules,
					'patch'   => array(
						'type'   => 'plugin_allow',
						'plugin' => $plugin,
					),
				);
			}
		}

		if ( 'kill_switch' === $reason || 'kill_switch' === $source || ! empty( $policy['kill_switch'] ) ) {
			$out[] = array(
				'kind'    => 'kill_switch',
				'message' => __( 'Turn off Emergency stop', 'handl-ai-connector-access-control' ),
				'url'     => $url_prot . '#handl-aicac-kill-switch',
				'patch'   => array( 'type' => 'kill_switch_off' ),
			);
		}

		if ( 'default:deny' === $source || ( ( $policy['default'] ?? 'allow' ) === 'deny' && ( ! isset( $policy['plugins'][ $plugin ] ) || 'allow' !== (string) $policy['plugins'][ $plugin ] ) ) ) {
			if ( '' !== $plugin ) {
				$out[] = array(
					'kind'    => 'plugin_allow',
					'message' => sprintf(
						/* translators: %s: connector/plugin name */
						__( 'Set connector %s to Allow', 'handl-ai-connector-access-control' ),
						$label
					),
					'url'     => $url_rules,
					'patch'   => array(
						'type'   => 'plugin_allow',
						'plugin' => $plugin,
					),
				);
			}
			$out[] = array(
				'kind'    => 'default_allow',
				'message' => __( 'Change the site default policy to Allow', 'handl-ai-connector-access-control' ),
				'url'     => $url_prot . '#handl-aicac-default',
				'patch'   => array( 'type' => 'default_allow' ),
			);
		}

		if ( 'unknown_operation' === $reason || 'unknown_operation' === $source ) {
			$out[] = array(
				'kind'    => 'unknown_operation',
				'message' => __( 'Allow unknown operations', 'handl-ai-connector-access-control' ),
				'url'     => $url_rules,
				'patch'   => array( 'type' => 'unknown_operation_allow' ),
			);
		}

		// De-dupe by kind+message while preserving order.
		$seen = array();
		$uniq = array();
		foreach ( $out as $row ) {
			$key = $row['kind'] . '|' . $row['message'];
			if ( isset( $seen[ $key ] ) ) {
				continue;
			}
			$seen[ $key ] = true;
			$uniq[]       = $row;
		}

		return $uniq;
	}

	/**
	 * @param array<string,mixed>                              $policy
	 * @param array{kind:string,message:string,url:string,patch:array<string,mixed>} $candidate
	 * @return array<string,mixed>
	 */
	private static function apply_candidate( array $policy, array $candidate ): array {
		$patch = isset( $candidate['patch'] ) && is_array( $candidate['patch'] ) ? $candidate['patch'] : array();
		$type  = isset( $patch['type'] ) ? (string) $patch['type'] : '';
		$clone = $policy;

		switch ( $type ) {
			case 'operation_allow':
				$p = (string) ( $patch['plugin'] ?? '' );
				$f = (string) ( $patch['family'] ?? '' );
				if ( '' !== $p && '' !== $f ) {
					if ( ! isset( $clone['operations'] ) || ! is_array( $clone['operations'] ) ) {
						$clone['operations'] = array();
					}
					if ( ! isset( $clone['operations'][ $p ] ) || ! is_array( $clone['operations'][ $p ] ) ) {
						$clone['operations'][ $p ] = array();
					}
					$clone['operations'][ $p ][ $f ] = 'allow';
				}
				break;
			case 'plugin_allow':
				$p = (string) ( $patch['plugin'] ?? '' );
				if ( '' !== $p ) {
					if ( ! isset( $clone['plugins'] ) || ! is_array( $clone['plugins'] ) ) {
						$clone['plugins'] = array();
					}
					$clone['plugins'][ $p ] = 'allow';
				}
				break;
			case 'budget_raise':
				$p = (string) ( $patch['plugin'] ?? '' );
				$a = isset( $patch['amount'] ) ? (float) $patch['amount'] : 0.0;
				if ( '' !== $p && $a > 0.0 ) {
					if ( ! isset( $clone['plugin_budgets'] ) || ! is_array( $clone['plugin_budgets'] ) ) {
						$clone['plugin_budgets'] = array();
					}
					$clone['plugin_budgets'][ $p ] = $a;
				}
				break;
			case 'kill_switch_off':
				$clone['kill_switch'] = false;
				break;
			case 'default_allow':
				$clone['default'] = 'allow';
				break;
			case 'unknown_operation_allow':
				$clone['unknown_operation'] = 'allow';
				break;
		}

		return $clone;
	}

	/**
	 * @param array<string,mixed> $event
	 * @param array<string,mixed> $policy
	 */
	private static function ask_cost_usd( array $event, array $policy ): float {
		foreach ( array( 'estimated_usd', 'est_usd', 'cost_usd' ) as $key ) {
			if ( isset( $event[ $key ] ) && is_numeric( $event[ $key ] ) ) {
				$v = (float) $event[ $key ];
				if ( $v > 0.0 ) {
					return $v;
				}
			}
		}
		$in  = array_key_exists( 'input_tokens', $event ) ? (int) $event['input_tokens'] : null;
		$out = array_key_exists( 'output_tokens', $event ) ? (int) $event['output_tokens'] : null;
		if ( ( null === $in || $in <= 0 ) && ( null === $out || $out <= 0 ) ) {
			return 0.0;
		}
		if ( class_exists( Cost::class, false ) ) {
			$provider = isset( $event['provider'] ) ? (string) $event['provider'] : null;
			$rates    = Cost::rates_from_policy( $policy, $provider !== '' ? $provider : null );
			$est      = Cost::estimate_usd( $in, $out, $rates );
			if ( null !== $est && $est > 0.0 ) {
				return (float) $est;
			}
		}

		return 0.0;
	}

	private static function format_money( float $amount ): string {
		$rounded = round( $amount, 4 );
		$s       = rtrim( rtrim( number_format( $rounded, 4, '.', '' ), '0' ), '.' );

		return '' !== $s ? $s : '0';
	}

	private static function connector_label( string $plugin ): string {
		if ( '' === $plugin ) {
			return __( 'this connector', 'handl-ai-connector-access-control' );
		}
		if ( function_exists( 'get_plugins' ) ) {
			$all = get_plugins();
			if ( isset( $all[ $plugin ]['Name'] ) && is_string( $all[ $plugin ]['Name'] ) && '' !== $all[ $plugin ]['Name'] ) {
				return (string) $all[ $plugin ]['Name'];
			}
		}

		return $plugin;
	}

	private static function rules_url( string $plugin ): string {
		if ( class_exists( Why::class, false ) && method_exists( Why::class, 'settings_url' ) ) {
			$url = Why::settings_url( 'rule:explicit-deny', array( 'plugin' => $plugin ) );
			if ( is_string( $url ) && '' !== $url ) {
				return $url;
			}
		}
		if ( class_exists( Plugin_Profile::class, false ) && method_exists( Plugin_Profile::class, 'rules_url' ) ) {
			return (string) Plugin_Profile::rules_url( $plugin );
		}
		if ( class_exists( Admin::class, false ) ) {
			return Admin::screen_url( 'rules' );
		}

		return '';
	}

	private static function protections_url(): string {
		if ( class_exists( Admin::class, false ) ) {
			return Admin::screen_url( 'protections' );
		}

		return '';
	}

	private static function is_activity_screen(): bool {
		$page = isset( $_GET['page'] ) ? sanitize_key( (string) wp_unslash( $_GET['page'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( '' === $page ) {
			return false;
		}
		if ( class_exists( Admin::class, false ) && method_exists( Admin::class, 'screen_slug' ) ) {
			return $page === Admin::screen_slug( 'activity' ) || 'handl-aicac-activity' === $page;
		}

		return false !== strpos( $page, 'activity' ) || 'handl-aicac' === $page;
	}

	/**
	 * @return list<array<string,mixed>>
	 */
	private static function read_activity_log(): array {
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
}
