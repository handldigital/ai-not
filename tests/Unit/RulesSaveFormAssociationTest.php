<?php
/**
 * AICAC-P0-SAVE (#209): Save must stay form-associated when nested
 * pack/preset/restore/check forms close the Rules form in the parsed DOM.
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use PHPUnit\Framework\TestCase;

final class RulesSaveFormAssociationTest extends TestCase {

	private function admin_source(): string {
		$src = file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-admin.php' );
		$this->assertNotFalse( $src );
		return (string) $src;
	}

	/**
	 * Save is associated via form= (the same pattern as matrix controls),
	 * not by DOM containment.
	 */
	public function test_save_button_is_form_associated(): void {
		$src = $this->admin_source();

		$this->assertMatchesRegularExpression(
			'/<button type="submit" name="handl_aicac_action" value="save" class="button button-primary" form="\' \. esc_attr\( \$rules_form_id \) \. \'" data-aicac-action="save">/',
			$src,
			'Save changes must set form= to the Rules form id'
		);
		$this->assertSame(
			'handl-aicac-rules-save',
			$this->rules_form_id( $src )
		);
	}

	/**
	 * Nonce and the empty action hidden must render before the first nested
	 * <form> section so they stay inside the parsed Rules form.
	 */
	public function test_nonce_and_action_hidden_precede_first_nested_form_section(): void {
		$src = $this->admin_source();

		$this->assertTrue(
			(bool) preg_match(
				'/echo \'<form method="post" id="\' \. esc_attr\( \$rules_form_id \) \. \'">\';(?P<body>[\s\S]*?)\$this->render_policy_packs_section\(/',
				$src,
				$m
			),
			'Rules form must open immediately before nonce/action, then packs'
		);

		$body = $m['body'];
		$this->assertStringContainsString(
			"wp_nonce_field( 'handl_aicac_save_policy', 'handl_aicac_nonce' )",
			$body,
			'Save nonce must render before the first nested-form section'
		);
		$this->assertStringContainsString(
			'id="handl-aicac-action"',
			$body,
			'Empty action hidden must render before the first nested-form section'
		);
		$this->assertMatchesRegularExpression(
			'/name="handl_aicac_action"[^>]*id="handl-aicac-action"[^>]*value=""/',
			$body,
			'Early action hidden must stay empty so submitter can populate it'
		);
		$this->assertDoesNotMatchRegularExpression(
			'/echo\s+[\'"]<form\b/',
			$body,
			'No nested <form> may be echoed between Rules form open and packs'
		);
		$this->assertStringContainsString(
			'e.submitter',
			$body,
			'Submit listener must still populate the action from e.submitter'
		);
	}

	/**
	 * Bulk apply, renew, and snooze stay on sibling shells with form=
	 * association — they must not nest inside the Rules form.
	 */
	public function test_bulk_renew_snooze_remain_sibling_form_shells(): void {
		$src = $this->admin_source();

		$this->assertTrue(
			(bool) preg_match(
				'/id="\' \. esc_attr\( \$bulk_form_id \)[\s\S]*?value="bulk_plugin_rules"[\s\S]*?<\/form>[\s\S]*?id="handl-aicac-renew-form"[\s\S]*?value="renew_temp_allow"[\s\S]*?<\/form>[\s\S]*?id="handl-aicac-snooze-form"[\s\S]*?value="snooze_alerts"[\s\S]*?<\/form>[\s\S]*?id="handl-aicac-cancel-snooze-form"[\s\S]*?value="cancel_alert_snooze"[\s\S]*?<\/form>[\s\S]*?id="\' \. esc_attr\( \$rules_form_id \)/',
				$src
			),
			'Bulk, renew, and snooze shells must close before the Rules form opens'
		);

		$this->assertMatchesRegularExpression(
			'/form="\' \. esc_attr\( \$bulk_form_id \) \. \'"/',
			$src,
			'Bulk Apply still associates via form= to the bulk shell'
		);
		$this->assertStringContainsString(
			'form="handl-aicac-renew-form"',
			$src,
			'Renew still associates via form= to the renew shell'
		);
		$this->assertStringContainsString(
			'form="handl-aicac-snooze-form"',
			$src,
			'Snooze still associates via form= to the snooze shell'
		);
	}

	/**
	 * Packs, presets, restore, and checks still emit their own POST forms
	 * with their own actions so those controls keep firing.
	 */
	public function test_packs_presets_restore_checks_still_emit_own_forms(): void {
		$src = $this->admin_source();

		$this->assert_section_emits_form_action(
			$src,
			'render_policy_packs_section',
			'pack_preview'
		);
		$this->assert_section_emits_form_action(
			$src,
			'render_presets_section',
			'preset_preview'
		);
		$this->assert_section_emits_form_action(
			$src,
			'render_policy_restore_section',
			'policy_restore_preview'
		);
		$this->assert_section_emits_form_action(
			$src,
			'render_policy_checks_section',
			'policy_check_add'
		);
	}

	private function rules_form_id( string $src ): string {
		$this->assertTrue(
			(bool) preg_match(
				'/\$rules_form_id = \'(handl-aicac-rules-save)\';/',
				$src,
				$m
			),
			'Rules form id must stay handl-aicac-rules-save'
		);
		return $m[1];
	}

	private function assert_section_emits_form_action( string $src, string $fn, string $action ): void {
		$this->assertTrue(
			(bool) preg_match(
				'/function ' . preg_quote( $fn, '/' ) . '\(.*?\n\t\}/s',
				$src,
				$m
			),
			$fn . ' must exist'
		);
		$this->assertMatchesRegularExpression(
			'/echo\s+[\'"]<form\b/',
			$m[0],
			$fn . ' must still emit its own <form>'
		);
		$this->assertStringContainsString(
			'name="handl_aicac_action" value="' . $action . '"',
			$m[0],
			$fn . ' must still post ' . $action
		);
	}
}
