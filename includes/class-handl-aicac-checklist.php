<?php
/**
 * Post-wizard getting-started checklist (AICAC-CHECKLIST / #190).
 *
 * Items self-check real configuration state (not click-tracking). The panel
 * hides when every applicable item is done, or when dismissed. It returns if
 * a saved setting later regresses (dismiss stays hidden).
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Checklist {
	public const OPTION_KEY = 'handl_aicac_checklist';

	/**
	 * @return array{dismissed:bool,simulator_tried:bool}
	 */
	public static function get_state(): array {
		$raw = get_option( self::OPTION_KEY, null );
		if ( ! is_array( $raw ) ) {
			$raw = array();
		}
		return self::sanitize_state( $raw );
	}

	/**
	 * @param array<string,mixed> $state
	 */
	public static function save_state( array $state ): void {
		update_option( self::OPTION_KEY, self::sanitize_state( $state ), false );
	}

	public static function dismiss(): void {
		$state              = self::get_state();
		$state['dismissed'] = true;
		self::save_state( $state );
	}

	public static function mark_simulator_tried(): void {
		$state                      = self::get_state();
		$state['simulator_tried'] = true;
		self::save_state( $state );
	}

	/**
	 * @param array<string,mixed> $raw
	 * @return array{dismissed:bool,simulator_tried:bool}
	 */
	public static function sanitize_state( array $raw ): array {
		return array(
			'dismissed'        => ! empty( $raw['dismissed'] ),
			'simulator_tried'  => ! empty( $raw['simulator_tried'] ),
		);
	}

	/**
	 * @param array<string,mixed> $policy
	 * @param array<int,mixed>    $log
	 * @return array{
	 *   dismissed: bool,
	 *   all_applicable_done: bool,
	 *   items: list<array{
	 *     id: string,
	 *     label: string,
	 *     detail: string,
	 *     applicable: bool,
	 *     done: bool,
	 *     tab: string,
	 *     anchor: string
	 *   }>
	 * }
	 */
	public static function compute( array $policy, array $log ): array {
		$state = self::get_state();
		$items = array(
			self::item_plugins( $policy, $log ),
			self::item_pack( $policy ),
			self::item_alert_email( $policy ),
			self::item_simulator( $state ),
			self::item_digest( $policy ),
		);

		$all_done = true;
		$any_applicable = false;
		foreach ( $items as $item ) {
			if ( empty( $item['applicable'] ) ) {
				continue;
			}
			$any_applicable = true;
			if ( empty( $item['done'] ) ) {
				$all_done = false;
				break;
			}
		}
		if ( ! $any_applicable ) {
			$all_done = true;
		}

		return array(
			'dismissed'           => ! empty( $state['dismissed'] ),
			'all_applicable_done' => $all_done,
			'items'               => $items,
		);
	}

	/**
	 * @param array<string,mixed> $policy
	 * @param array<int,mixed>    $log
	 */
	public static function should_render( array $policy, array $log, ?array $onboard_state = null, bool $force_wizard = false ): bool {
		if ( Onboarding::should_render_wizard( $onboard_state ?? Onboarding::ensure_initialized(), $force_wizard ) ) {
			return false;
		}
		$report = self::compute( $policy, $log );
		if ( ! empty( $report['dismissed'] ) ) {
			return false;
		}
		return empty( $report['all_applicable_done'] );
	}

	/**
	 * @param array{tab?:string,anchor?:string} $item
	 */
	public static function item_url( array $item ): string {
		$tab = isset( $item['tab'] ) ? sanitize_key( (string) $item['tab'] ) : 'dashboard';
		if ( ! in_array( $tab, array( 'dashboard', 'rules', 'activity', 'insights', 'protections', 'policy-tools', 'alerts' ), true ) ) {
			$tab = 'dashboard';
		}
		$url = function_exists( 'admin_url' )
			? (string) Admin::screen_url( $tab )
			: '';
		$anchor = isset( $item['anchor'] ) ? (string) $item['anchor'] : '';
		if ( '' !== $url && '' !== $anchor && preg_match( '/^[a-z0-9\-]+$/', $anchor ) ) {
			$url .= '#' . $anchor;
		}
		return $url;
	}

	/**
	 * @param array<string,mixed> $policy
	 * @param array<int,mixed>    $log
	 * @return array{id:string,label:string,detail:string,applicable:bool,done:bool,tab:string,anchor:string}
	 */
	private static function item_plugins( array $policy, array $log ): array {
		$pending = New_Plugin::pending_plugins( $policy );
		$active  = Governance_Coverage::ai_active_plugins( $log );
		$rules   = is_array( $policy['plugins'] ?? null ) ? (array) $policy['plugins'] : array();

		$unruled = array();
		foreach ( $active as $basename ) {
			$rule = isset( $rules[ $basename ] ) ? (string) $rules[ $basename ] : '';
			if ( 'allow' !== $rule && 'deny' !== $rule ) {
				$unruled[] = $basename;
			}
		}

		$waiting = count( $pending ) + count( $unruled );
		$applicable = $waiting > 0 || count( $active ) > 0;
		$done       = $applicable && 0 === $waiting;

		if ( ! $applicable ) {
			$detail = __( 'No plugin has used AI yet.', 'handl-ai-connector-access-control' );
		} elseif ( $done ) {
			$detail = __( 'Every plugin that used AI has an Allow or Deny rule.', 'handl-ai-connector-access-control' );
		} else {
			$detail = sprintf(
				/* translators: %d: plugins still missing an explicit Allow/Deny */
				_n(
					'%d plugin still needs an Allow or Deny rule.',
					'%d plugins still need an Allow or Deny rule.',
					$waiting,
					'handl-ai-connector-access-control'
				),
				$waiting
			);
		}

		return array(
			'id'         => 'plugins',
			'label'      => __( 'Review plugins that used AI', 'handl-ai-connector-access-control' ),
			'detail'     => $detail,
			'applicable' => $applicable,
			'done'       => $done,
			'tab'        => 'rules',
			'anchor'     => '',
		);
	}

	/**
	 * @param array<string,mixed> $policy
	 * @return array{id:string,label:string,detail:string,applicable:bool,done:bool,tab:string,anchor:string}
	 */
	private static function item_pack( array $policy ): array {
		$done = false;
		foreach ( Policy_Packs::definitions() as $id => $def ) {
			unset( $def );
			if ( Policy_Packs::is_active( (string) $id, $policy ) ) {
				$done = true;
				break;
			}
		}

		return array(
			'id'         => 'pack',
			'label'      => __( 'Choose a starter policy pack', 'handl-ai-connector-access-control' ),
			'detail'     => $done
				? __( 'A starter pack is applied.', 'handl-ai-connector-access-control' )
				: __( 'Apply Strict, Balanced, or Observe-first on Policy Tools.', 'handl-ai-connector-access-control' ),
			'applicable' => true,
			'done'       => $done,
			'tab'        => 'policy-tools',
			'anchor'     => 'handl-aicac-packs',
		);
	}

	/**
	 * @param array<string,mixed> $policy
	 * @return array{id:string,label:string,detail:string,applicable:bool,done:bool,tab:string,anchor:string}
	 */
	private static function item_alert_email( array $policy ): array {
		$email = Alerts::sanitize_email( $policy['alert_email'] ?? '' );
		$done  = '' !== $email;
		return array(
			'id'         => 'alert_email',
			'label'      => __( 'Save an alert email', 'handl-ai-connector-access-control' ),
			'detail'     => $done
				? __( 'Alert email is saved.', 'handl-ai-connector-access-control' )
				: __( 'Save an alert email on Alerts & Settings.', 'handl-ai-connector-access-control' ),
			'applicable' => true,
			'done'       => $done,
			'tab'        => 'alerts',
			'anchor'     => 'handl-aicac-alert-email',
		);
	}

	/**
	 * @param array{simulator_tried?:bool} $state
	 * @return array{id:string,label:string,detail:string,applicable:bool,done:bool,tab:string,anchor:string}
	 */
	private static function item_simulator( array $state ): array {
		$done = ! empty( $state['simulator_tried'] );
		return array(
			'id'         => 'simulator',
			'label'      => __( 'Try the policy tester', 'handl-ai-connector-access-control' ),
			'detail'     => $done
				? __( 'You have run the policy tester.', 'handl-ai-connector-access-control' )
				: __( 'Run Test this policy on Policy Tools.', 'handl-ai-connector-access-control' ),
			'applicable' => true,
			'done'       => $done,
			'tab'        => 'policy-tools',
			'anchor'     => 'handl-aicac-sim-panel',
		);
	}

	/**
	 * @param array<string,mixed> $policy
	 * @return array{id:string,label:string,detail:string,applicable:bool,done:bool,tab:string,anchor:string}
	 */
	private static function item_digest( array $policy ): array {
		$done = ! empty( $policy['governance_digest_enabled'] );
		return array(
			'id'         => 'digest',
			'label'      => __( 'Turn on the weekly digest', 'handl-ai-connector-access-control' ),
			'detail'     => $done
				? __( 'Weekly digest is on.', 'handl-ai-connector-access-control' )
				: __( 'Turn on the weekly governance digest on Alerts & Settings.', 'handl-ai-connector-access-control' ),
			'applicable' => true,
			'done'       => $done,
			'tab'        => 'alerts',
			'anchor'     => 'handl-aicac-governance-digest',
		);
	}
}
