<?php
/**
 * Starter policy pack definitions (AICAC-TEMPLATES / #173).
 *
 * Data only — UI reads this catalog via Policy_Packs::definitions().
 * Each pack: id, label, description, patch (scalar settings), optional plugins map.
 *
 * @package HandL_AICAC
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

return array(
	'strict'        => array(
		'id'          => 'strict',
		'label'       => __( 'Strict', 'handl-ai-connector-access-control' ),
		'description' => __( 'Deny by default. Review new plugins before they can use AI. Currently active plugins get an Allow rule so the site keeps working.', 'handl-ai-connector-access-control' ),
		'patch'       => array(
			'default'                   => 'deny',
			'audit_only'                => false,
			'log_enabled'               => true,
			'kill_switch'               => false,
			'shadow_block_enabled'      => true,
			'unknown_operation'         => 'deny',
			'alert_on_deny'             => true,
			'alert_on_shadow'           => true,
			'alert_mode'                => 'immediate',
			'new_plugin_review_enabled' => true,
			'new_plugin_interim'        => 'deny',
		),
		// Seed Allow for currently active plugins at apply time (see Policy_Packs::build_target).
		'seed_active_plugins_allow' => true,
	),
	'balanced'      => array(
		'id'          => 'balanced',
		'label'       => __( 'Balanced', 'handl-ai-connector-access-control' ),
		'description' => __( 'Keep the site default Allow. New plugins start in Observe-only mode until you decide. Block direct AI connections outside the AI Client.', 'handl-ai-connector-access-control' ),
		'patch'       => array(
			'default'                   => 'allow',
			'audit_only'                => false,
			'log_enabled'               => true,
			'kill_switch'               => false,
			'shadow_block_enabled'      => true,
			'unknown_operation'         => 'inherit',
			'alert_on_deny'             => true,
			'alert_on_shadow'           => true,
			'alert_mode'                => 'immediate',
			'new_plugin_review_enabled' => true,
			'new_plugin_interim'        => 'observe',
		),
		'seed_active_plugins_allow' => false,
	),
	'observe_first' => array(
		'id'          => 'observe_first',
		'label'       => __( 'Observe-first', 'handl-ai-connector-access-control' ),
		'description' => __( 'Turn on Observe-only mode for everything. Log AI Client activity without blocking while you learn what each plugin does.', 'handl-ai-connector-access-control' ),
		'patch'       => array(
			'default'                   => 'allow',
			'audit_only'                => true,
			'log_enabled'               => true,
			'kill_switch'               => false,
			'shadow_block_enabled'      => false,
			'unknown_operation'         => 'inherit',
			'alert_on_deny'             => true,
			'alert_on_shadow'           => true,
			'alert_mode'                => 'immediate',
			'new_plugin_review_enabled' => false,
			'new_plugin_interim'        => 'deny',
		),
		'seed_active_plugins_allow' => false,
	),
);
