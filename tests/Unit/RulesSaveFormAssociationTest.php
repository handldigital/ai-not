<?php
/**
 * AICAC-P0-SAVE (#209) + AICAC-FORM-NEST (#213): Save stays form-associated,
 * and pack/preset/restore/check forms are siblings of the Rules form so they
 * cannot poison the save nonce/action.
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

	private function rules_form_body( string $src ): string {
		$this->assertTrue(
			(bool) preg_match(
				'/echo \'<form method="post" id="\' \. esc_attr\( \$rules_form_id \) \. \'">\';(?P<body>[\s\S]*?)echo \'<\/form>\';\s*\$this->render_rules_transfer_section\(/',
				$src,
				$m
			),
			'Rules form must open, then close immediately before the transfer section'
		);
		return $m['body'];
	}

	/**
	 * Save is associated via form= (the same pattern as matrix controls),
	 * not by DOM containment alone.
	 */
	public function test_save_button_is_form_associated(): void {
		$src = $this->admin_source();

		$this->assertMatchesRegularExpression(
			'/<button type="submit" name="handl_aicac_action" value="save" class="button button-primary" form="\' \. esc_attr\( \$rules_form_id \) \. \'" data-aicac-action="save">/',
			$src,
			'Visible Save changes must set form= to the Rules form id'
		);
		$this->assertSame(
			'handl-aicac-rules-save',
			$this->rules_form_id( $src )
		);
	}

	/**
	 * Nested-form sections render before the Rules form opens so their </form>
	 * cannot close it. Visual order on the tab stays packs → presets → restore
	 * → history → checks → settings.
	 */
	public function test_nested_form_sections_are_siblings_before_rules_form(): void {
		$src = $this->admin_source();

		$open = strpos( $src, 'echo \'<form method="post" id="\' . esc_attr( $rules_form_id ) . \'">\';' );
		$this->assertNotFalse( $open, 'Rules form open must exist' );

		foreach ( array(
			'$this->render_policy_packs_section(',
			'$this->render_presets_section(',
			'$this->render_policy_restore_section(',
			'$this->render_policy_change_history_section(',
			'$this->render_policy_checks_section(',
		) as $call ) {
			$pos = strpos( $src, $call );
			$this->assertNotFalse( $pos, $call . ' must exist' );
			$this->assertLessThan(
				$open,
				$pos,
				$call . ' must render before the Rules form opens'
			);
		}
	}

	/**
	 * The Rules form body has one save nonce, one action hidden, no nested
	 * <form>, and no calls to the pack/preset/restore/check sections.
	 */
	public function test_rules_form_body_has_single_nonce_action_and_no_nested_form(): void {
		$src  = $this->admin_source();
		$body = $this->rules_form_body( $src );

		$this->assertSame(
			1,
			substr_count( $body, "wp_nonce_field( 'handl_aicac_save_policy', 'handl_aicac_nonce' )" ),
			'Rules form must emit exactly one save-policy nonce'
		);
		$this->assertSame(
			1,
			substr_count( $body, 'id="handl-aicac-action"' ),
			'Rules form must emit exactly one action hidden'
		);
		$this->assertMatchesRegularExpression(
			'/name="handl_aicac_action"[^>]*id="handl-aicac-action"[^>]*value=""/',
			$body,
			'Early action hidden must stay empty so submitter can populate it'
		);
		$this->assertDoesNotMatchRegularExpression(
			'/echo\s+[\'"]<form\b/',
			$body,
			'No nested <form> may be echoed inside the Rules form'
		);
		foreach ( array(
			'render_policy_packs_section',
			'render_presets_section',
			'render_policy_restore_section',
			'render_policy_change_history_section',
			'render_policy_checks_section',
		) as $fn ) {
			$this->assertStringNotContainsString(
				'$this->' . $fn . '(',
				$body,
				$fn . ' must not be called inside the Rules form'
			);
		}
		$this->assertStringContainsString(
			'e.submitter',
			$body,
			'Submit listener must still populate the action from e.submitter'
		);
	}

	/**
	 * Enter in a Rules-owned field must submit Save, not Run test. The first
	 * submit owned by the form is a clipped Save (not display:none).
	 */
	public function test_save_is_first_submit_owned_by_rules_form(): void {
		$body = $this->rules_form_body( $this->admin_source() );

		$this->assertTrue(
			(bool) preg_match(
				'/<button type="submit"(?P<attrs>[^>]*)>/',
				$body,
				$m
			),
			'Rules form must contain a submit button'
		);
		$attrs = $m['attrs'];
		$this->assertStringContainsString( 'name="handl_aicac_action"', $attrs );
		$this->assertStringContainsString( 'value="save"', $attrs );
		$this->assertStringContainsString( 'data-aicac-action="save"', $attrs );
		$this->assertStringContainsString( 'form="\' . esc_attr( $rules_form_id ) . \'"', $attrs );
		$this->assertStringContainsString(
			'class="screen-reader-text"',
			$attrs,
			'Default Save must stay clipped (Enter target) rather than display:none'
		);
		$this->assertStringContainsString(
			'tabindex="-1"',
			$attrs,
			'Clipped Save must stay out of the tab order so only the visible Save is announced'
		);
		$this->assertStringNotContainsString(
			'aria-hidden',
			$attrs,
			'Do not aria-hide a focusable control'
		);
		$this->assertStringNotContainsString(
			'simulate_policy',
			$attrs,
			'First submit must not be Run test'
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
				'/id="\' \. esc_attr\( \$bulk_form_id \)[\s\S]*?value="bulk_plugin_rules"[\s\S]*?<\/form>[\s\S]*?id="handl-aicac-renew-form"[\s\S]*?value="renew_temp_allow"[\s\S]*?<\/form>[\s\S]*?id="handl-aicac-snooze-form"[\s\S]*?value="snooze_alerts"[\s\S]*?<\/form>[\s\S]*?id="handl-aicac-cancel-snooze-form"[\s\S]*?value="cancel_alert_snooze"[\s\S]*?<\/form>[\s\S]*?render_policy_packs_section/',
				$src
			),
			'Bulk, renew, and snooze shells must close before packs (and the Rules form) open'
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

	/**
	 * Permanent guard (#212 shape): every <form> echoed in the Rules-tab
	 * helpers posts exactly one handl_aicac_nonce and one handl_aicac_action.
	 */
	public function test_each_rules_tab_form_posts_single_nonce_and_action(): void {
		$src = $this->admin_source();

		$fns = array(
			'render_policy_packs_section',
			'render_presets_section',
			'render_policy_restore_section',
			'render_policy_checks_section',
			'render_policy_checks_save_confirm',
		);
		foreach ( $fns as $fn ) {
			$this->assertTrue(
				(bool) preg_match(
					'/function ' . preg_quote( $fn, '/' ) . '\(.*?\n\t\}/s',
					$src,
					$m
				),
				$fn . ' must exist'
			);
			$forms = preg_split( '/echo\s+[\'"]<form\b/', $m[0] );
			$this->assertIsArray( $forms );
			// First chunk is the function preamble (no form yet).
			array_shift( $forms );
			$this->assertNotEmpty( $forms, $fn . ' must emit at least one <form>' );
			foreach ( $forms as $i => $form ) {
				$nonce = preg_match_all( '/wp_nonce_field\s*\(/', $form );
				$action = preg_match_all( '/name="handl_aicac_action"/', $form );
				$this->assertSame(
					1,
					$nonce,
					$fn . ' form #' . ( $i + 1 ) . ' must post exactly one nonce'
				);
				$this->assertSame(
					1,
					$action,
					$fn . ' form #' . ( $i + 1 ) . ' must post exactly one handl_aicac_action'
				);
			}
		}

		$body   = $this->rules_form_body( $src );
		$nonce  = preg_match_all( '/wp_nonce_field\s*\(/', $body );
		$hidden = preg_match_all( '/<input type="hidden" name="handl_aicac_action"/', $body );
		$this->assertSame( 1, $nonce, 'Rules form must post exactly one nonce' );
		$this->assertSame( 1, $hidden, 'Rules form must post exactly one action hidden' );
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
