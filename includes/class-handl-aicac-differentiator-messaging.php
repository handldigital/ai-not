<?php
/**
 * In-product copy differentiating HandL AICAC from WordPress AI Connector Approvals (AICAC-11).
 *
 * Evidence (research open question 1):
 * - Official WordPress AI plugin: https://wordpress.org/plugins/ai/ (40k+ installs, ~4.6/5).
 * - Connector Approvals docs: caller (plugin/theme) × connector credentials at HTTP time
 *   via pre_http_request — see WordPress/ai docs/experiments/connector-approval.md and PR #467.
 * - HandL gates wp_ai_client_prevent_prompt with capability families, tool arming, shadow observe, spend/alerts.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Centralizes comparison strings so admin UI, FAQ alignment, and unit tests share one source.
 */
final class Differentiator_Messaging {

	/**
	 * Short callout heading (Dashboard).
	 */
	public static function headline(): string {
		return __( 'Beyond Connector Approvals', 'handl-ai-connector-access-control' );
	}

	/**
	 * One-line page subtitle addition (settings wrap).
	 */
	public static function page_subtitle_addition(): string {
		return __( 'Goes beyond the WordPress AI plugin’s Connector Approvals (caller × connector credentials) with a capability-family matrix, tool-arming denial, shadow-AI detection, and spend/alerting.', 'handl-ai-connector-access-control' );
	}

	/**
	 * Primary body explaining granularity and HandL differentiators.
	 */
	public static function body(): string {
		return __( 'The WordPress AI plugin’s Connector Approvals experiment decides which plugins or themes may use which configured AI connector credentials, enforced when outbound HTTP carries those credentials. HandL AICAC governs AI Client prompts instead: a per-plugin × capability-family matrix (Text / Image / Speech / TTS / Video), tool-arming denial, shadow-AI detection for direct HTTP outside the AI Client, and estimated spend with denial alerting.', 'handl-ai-connector-access-control' );
	}

	/**
	 * Explicit coexistence line (not a replacement).
	 */
	public static function coexistence(): string {
		return __( 'Both can run together — they govern different layers.', 'handl-ai-connector-access-control' );
	}

	/**
	 * Rules-tab pointer to the same differentiators (keeps matrix context).
	 */
	public static function rules_note(): string {
		return __( 'Unlike Connector Approvals (caller × connector credentials at HTTP time), these Rules refine AI Client access by capability family and can deny tool arming; Dashboard/Activity add shadow-AI observation and spend/alerting.', 'handl-ai-connector-access-control' );
	}

	/**
	 * Differentiator labels required by AICAC-11 (stable keys for tests).
	 *
	 * @return array{capability_family:string,tool_arming:string,shadow_ai:string,spend_alerting:string}
	 */
	public static function differentiator_phrases(): array {
		return array(
			'capability_family' => 'capability-family matrix',
			'tool_arming'       => 'tool-arming denial',
			'shadow_ai'         => 'shadow-AI detection',
			'spend_alerting'    => 'spend/alerting',
		);
	}
}
