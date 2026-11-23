<?php
/**
 * AICAC-PHRASEBOOK (#514): owner-defined confidential-term screen.
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Alert_Snooze;
use HandL\AICAC\Phrasebook;
use HandL\AICAC\Plugin;
use HandL\AICAC\Policy;
use HandL\AICAC\Tripwire;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../stubs/wp-admin-escape.php';

final class PhrasebookTest extends TestCase {

	private const PLUGIN = 'acme/acme.php';

	private const OTHER = 'other/other.php';

	private const TERM = 'Project Nimbus';

	private const LABEL = 'Launch codename';

	private const CONTEXT = 'Please announce ZX-CONTEXT-9 the board pricing sheet for';

	private const SECRET = 'tw-db-s3cret-ZX9qK2mL';

	/** @var list<array{to:string,subject:string,message:string}> */
	private static array $mails = array();

	protected function setUp(): void {
		parent::setUp();
		self::$mails = array();
		$GLOBALS['handl_aicac_test_current_user_can'] = true;
		$GLOBALS['handl_aicac_test_plugins']          = array(
			self::PLUGIN => array(
				'Name'    => 'Acme AI',
				'Version' => '1.0.0',
			),
			self::OTHER  => array(
				'Name'    => 'Other AI',
				'Version' => '1.0.0',
			),
		);
		$GLOBALS['handl_aicac_wp_mail'] = static function ( $to, $subject, $message ) {
			self::$mails[] = array(
				'to'      => (string) $to,
				'subject' => (string) $subject,
				'message' => (string) $message,
			);
			return true;
		};
		Phrasebook::reset_for_tests();
		Tripwire::reset_for_tests();
		delete_option( Plugin::OPTION_KEY );
		delete_option( Plugin::LOG_OPTION_KEY );
		delete_option( Phrasebook::OPTION_KEY );
		delete_option( Alert_Snooze::OPTION_KEY );
		update_option( 'admin_email', 'admin@example.com' );
	}

	protected function tearDown(): void {
		unset( $GLOBALS['handl_aicac_wp_mail'], $GLOBALS['handl_aicac_test_plugins'] );
		delete_option( Plugin::OPTION_KEY );
		delete_option( Plugin::LOG_OPTION_KEY );
		delete_option( Phrasebook::OPTION_KEY );
		delete_option( Alert_Snooze::OPTION_KEY );
		Phrasebook::reset_for_tests();
		Tripwire::reset_for_tests();
		parent::tearDown();
	}

	public function test_plugin_bootstrap_wires_phrasebook_keep_both(): void {
		$plugin = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-plugin.php' );
		$this->assertStringContainsString( 'class-handl-aicac-phrasebook.php', $plugin );
		$this->assertStringContainsString( 'Phrasebook::init()', $plugin );
		$this->assertGreaterThan(
			(int) strrpos( $plugin, 'Tripwire::init()' ),
			(int) strrpos( $plugin, 'Phrasebook::init()' )
		);
		$boot = (string) file_get_contents( HANDL_AICAC_DIR . '/tests/bootstrap.php' );
		$this->assertStringContainsString( 'class-handl-aicac-phrasebook.php', $boot );
		$readme = (string) file_get_contents( HANDL_AICAC_DIR . '/readme.txt' );
		$this->assertStringNotContainsString( 'phrasebook', strtolower( $readme ) );
		$admin = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-admin.php' );
		$this->assertStringNotContainsString( 'Phrasebook', $admin );
		$trip = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-tripwire.php' );
		$this->assertStringNotContainsString( 'Phrasebook', $trip );
		$pii = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-pii-warn.php' );
		$this->assertStringNotContainsString( 'Phrasebook', $pii );
	}

	public function test_policy_wire_after_tripwire_in_source(): void {
		$body = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-policy.php' );
		$tw   = strpos( $body, 'Tripwire::apply_to_event' );
		$pb   = strpos( $body, 'Phrasebook::apply_to_event' );
		$this->assertNotFalse( $tw );
		$this->assertNotFalse( $pb );
		$this->assertGreaterThan( $tw, $pb );
		$this->assertNotFalse( strpos( $body, 'Phrasebook::sanitize_plugin_modes' ) );
		$this->assertNotFalse( strpos( $body, 'Phrasebook::maybe_alert' ) );
		$this->assertNotFalse( strpos( $body, 'Phrasebook::REASON' ) );
		$this->assertSame( 'Confidential term', \HandL\AICAC\Policy_Simulator::reason_label( Phrasebook::REASON ) );
	}

	public function test_fresh_install_screen_on_empty_list_has_zero_effect(): void {
		$this->assertSame( array(), Phrasebook::terms() );
		$this->assertSame( Phrasebook::MODE_WARN, Phrasebook::global_mode() );
		$event  = array(
			'plugin'         => self::PLUGIN,
			'decision'       => 'allow',
			'prompt_preview' => self::CONTEXT . ' ' . self::TERM,
		);
		$before = $event;
		$result = Phrasebook::apply_to_event( $event, array(), null );
		$this->assertTrue( $result['active'] );
		$this->assertFalse( $result['prevent'] );
		$this->assertSame( array(), $result['matches'] );
		$this->assertSame( $before, $event );
		$this->assertArrayNotHasKey( 'phrasebook_match', $event );
	}

	public function test_warn_match_allows_alerts_label_and_count_and_stores_no_context(): void {
		$this->save_term();
		update_option(
			Plugin::OPTION_KEY,
			array(
				'log_enabled' => true,
				'alert_email' => 'admin@example.com',
			),
			false
		);
		$policy = Policy::get_policy();
		$this->assertSame( Phrasebook::MODE_WARN, Phrasebook::mode_for_plugin( $policy, self::PLUGIN ) );
		$event  = array(
			'ts'             => 1_700_000_000,
			'plugin'         => self::PLUGIN,
			'decision'       => 'allow',
			'prompt_preview' => self::CONTEXT . ' ' . self::TERM . ' twice ' . self::TERM,
			'config'         => array(
				'systemInstruction' => 'hidden ' . self::TERM,
			),
		);
		$result = Phrasebook::apply_to_event( $event, $policy, null );
		$this->assertTrue( $result['active'] );
		$this->assertFalse( $result['prevent'] );
		$this->assertSame( Phrasebook::MODE_WARN, $result['mode'] );
		$this->assertSame( 2, $result['matches'][ self::LABEL ] ?? 0 );
		$this->assertSame( 'allow', $event['decision'] );
		$this->assertSame( '', $event['prompt_preview'] );
		$this->assertSame( '', $event['config']['systemInstruction'] );
		$this->assertArrayNotHasKey( 'term', $event['phrasebook_match'] );
		$this->assertArrayNotHasKey( 'context', $event['phrasebook_match'] );
		$this->assertArrayNotHasKey( 'snippet', $event['phrasebook_match'] );

		Policy::append_log_event( $event );
		$blob = wp_json_encode(
			array(
				'log'   => get_option( Plugin::LOG_OPTION_KEY ),
				'mails' => self::$mails,
			)
		);
		$this->assertIsString( $blob );
		$this->assertStringNotContainsString( self::TERM, (string) $blob );
		$this->assertStringNotContainsString( 'ZX-CONTEXT-9', (string) $blob );
		$this->assertCount( 1, self::$mails );
		$this->assertStringContainsString( self::LABEL, self::$mails[0]['message'] );
		$this->assertStringContainsString( self::LABEL . ' (2)', self::$mails[0]['message'] );
		$this->assertStringContainsString( 'Phrasebook setting: Warn. This check does not block the request. Other rules still apply.', self::$mails[0]['message'] );
		$this->assertStringNotContainsString( self::TERM, self::$mails[0]['subject'] );
		$this->assertStringNotContainsString( self::TERM, self::$mails[0]['message'] );
	}

	public function test_deny_mode_blocks_matching_call_and_leaves_non_match_alone(): void {
		Phrasebook::save_list(
			Phrasebook::MODE_DENY,
			array(
				array(
					'label'    => self::LABEL,
					'term'     => self::TERM,
					'boundary' => true,
				),
			)
		);
		$policy = array();
		$hit    = array(
			'plugin'         => self::PLUGIN,
			'decision'       => 'allow',
			'prompt_preview' => 'Draft the note about ' . self::TERM . '.',
		);
		$result = Phrasebook::apply_to_event( $hit, $policy, null );
		$this->assertTrue( $result['prevent'] );
		$this->assertSame( Phrasebook::MODE_DENY, $result['mode'] );
		$this->assertSame( Phrasebook::REASON, 'phrasebook' );
		$this->assertSame( '', $hit['prompt_preview'] );

		$miss = array(
			'plugin'         => self::PLUGIN,
			'decision'       => 'allow',
			'prompt_preview' => 'Summarize the garden tomato post.',
		);
		$before = $miss;
		$clean  = Phrasebook::apply_to_event( $miss, $policy, null );
		$this->assertFalse( $clean['prevent'] );
		$this->assertSame( array(), $clean['matches'] );
		$this->assertSame( $before, $miss );
	}

	public function test_per_plugin_override_and_per_term_deny_escalation(): void {
		$this->save_term();
		$warn_policy = array(
			Phrasebook::POLICY_KEY => array( self::PLUGIN => Phrasebook::MODE_WARN ),
		);
		Phrasebook::save_list( Phrasebook::MODE_DENY, $this->one_term() );
		$this->assertSame( Phrasebook::MODE_WARN, Phrasebook::mode_for_plugin( $warn_policy, self::PLUGIN ) );
		$event  = $this->matching_event();
		$result = Phrasebook::apply_to_event( $event, $warn_policy, null );
		$this->assertFalse( $result['prevent'] );
		$this->assertSame( Phrasebook::MODE_WARN, $result['mode'] );

		$deny_policy = array(
			Phrasebook::POLICY_KEY => array( self::PLUGIN => Phrasebook::MODE_DENY ),
		);
		Phrasebook::save_list( Phrasebook::MODE_WARN, $this->one_term() );
		$this->assertSame( Phrasebook::MODE_DENY, Phrasebook::mode_for_plugin( $deny_policy, self::PLUGIN ) );
		$blocked = $this->matching_event();
		$deny    = Phrasebook::apply_to_event( $blocked, $deny_policy, null );
		$this->assertTrue( $deny['prevent'] );

		$other = array(
			'plugin'         => self::OTHER,
			'decision'       => 'allow',
			'prompt_preview' => 'Note on ' . self::TERM,
		);
		$other_result = Phrasebook::apply_to_event( $other, $deny_policy, null );
		$this->assertFalse( $other_result['prevent'] );
		$this->assertSame( Phrasebook::MODE_WARN, $other_result['mode'] );

		Phrasebook::save_list(
			Phrasebook::MODE_WARN,
			array(
				array(
					'label'    => self::LABEL,
					'term'     => self::TERM,
					'boundary' => true,
					'deny'     => true,
				),
			)
		);
		$escalated_event = $this->matching_event();
		$escalated       = Phrasebook::apply_to_event( $escalated_event, array(), null );
		$this->assertTrue( $escalated['prevent'] );
		$this->assertSame( Phrasebook::MODE_DENY, $escalated['mode'] );
	}

	public function test_case_insensitive_and_optional_word_boundary(): void {
		Phrasebook::save_list(
			Phrasebook::MODE_WARN,
			array(
				array(
					'label'    => self::LABEL,
					'term'     => 'nimbus',
					'boundary' => false,
				),
			)
		);
		$hits = Phrasebook::screen( 'See Nimbus and nimbus-plan.' );
		$this->assertSame( 2, $hits[ self::LABEL ] ?? 0 );

		Phrasebook::save_list(
			Phrasebook::MODE_WARN,
			array(
				array(
					'label'    => 'Ticker',
					'term'     => 'NM',
					'boundary' => true,
				),
			)
		);
		$this->assertSame( 1, Phrasebook::screen( 'Ship NM today.' )['Ticker'] ?? 0 );
		$this->assertArrayNotHasKey( 'Ticker', Phrasebook::screen( 'ENUM only' ) );

		Phrasebook::save_list(
			Phrasebook::MODE_WARN,
			array(
				array(
					'label'    => 'Vehicle',
					'term'     => 'bus',
					'boundary' => true,
				),
			)
		);
		$this->assertSame( array(), Phrasebook::screen( 'business hours' ) );
		$this->assertSame( 1, Phrasebook::screen( 'the bus left' )['Vehicle'] ?? 0 );
	}

	public function test_coexists_with_tripwire_one_alert_each(): void {
		$this->save_term();
		Tripwire::set_test_secrets(
			array(
				array(
					'kind'  => Tripwire::KIND_DB,
					'value' => self::SECRET,
				),
			)
		);
		update_option(
			Plugin::OPTION_KEY,
			array(
				'log_enabled'     => true,
				'alert_email'     => 'admin@example.com',
				'tripwire_screen' => array( self::PLUGIN => 'warn' ),
			),
			false
		);
		$policy = Policy::get_policy();
		$event  = array(
			'ts'             => 1_700_000_000,
			'plugin'         => self::PLUGIN,
			'decision'       => 'allow',
			'prompt_preview' => self::CONTEXT . ' ' . self::TERM . ' key ' . self::SECRET,
		);
		$trip = Tripwire::apply_to_event( $event, $policy, null );
		$book = Phrasebook::apply_to_event( $event, $policy, null );
		$this->assertFalse( $trip['prevent'] );
		$this->assertFalse( $book['prevent'] );
		$this->assertSame( 1, $trip['matches'][ Tripwire::KIND_DB ] ?? 0 );
		$this->assertSame( 1, $book['matches'][ self::LABEL ] ?? 0 );
		$this->assertArrayHasKey( 'tripwire_match', $event );
		$this->assertArrayHasKey( 'phrasebook_match', $event );
		$this->assertSame( 1, $event['tripwire_match']['kinds'][ Tripwire::KIND_DB ] ?? 0 );
		$this->assertSame( '', $event['prompt_preview'] );

		Policy::append_log_event( $event );
		$this->assertCount( 2, self::$mails );
		$joined = self::$mails[0]['message'] . "\n" . self::$mails[1]['message'];
		$this->assertStringContainsString( 'Database password', $joined );
		$this->assertStringContainsString( self::LABEL, $joined );
		$this->assertStringNotContainsString( self::SECRET, $joined );
		$this->assertStringNotContainsString( self::TERM, $joined );
		$this->assertStringNotContainsString( 'ZX-CONTEXT-9', $joined );
		$log = wp_json_encode( get_option( Plugin::LOG_OPTION_KEY ) );
		$this->assertIsString( $log );
		$this->assertStringNotContainsString( self::SECRET, (string) $log );
		$this->assertStringNotContainsString( self::TERM, (string) $log );
		$this->assertStringContainsString( 'tripwire_match', (string) $log );
		$this->assertStringContainsString( 'phrasebook_match', (string) $log );
	}

	public function test_page_copy_is_plain_and_save_label_present(): void {
		Phrasebook::init();
		ob_start();
		Phrasebook::render_page();
		$html = (string) ob_get_clean();
		$this->assertStringContainsString( 'Phrasebook', $html );
		$this->assertStringContainsString( 'Checks AI requests for words only you know are sensitive. On by default. An empty list does nothing.', $html );
		$this->assertStringContainsString( 'Alerts name the label and the count. They do not include the word or the request text.', $html );
		$this->assertStringContainsString( 'Save phrasebook', $html );
		$this->assertStringContainsString( 'Warn (allow and alert)', $html );
		$this->assertStringContainsString( 'Follow site default', $html );
		$this->assertStringContainsString( 'Block this term', $html );
	}

	public function test_sanitize_drops_short_terms_and_keeps_plugin_overrides(): void {
		$terms = Phrasebook::sanitize_terms(
			array(
				array(
					'label' => self::LABEL,
					'term'  => 'a',
				),
				array(
					'label'    => self::LABEL,
					'term'     => self::TERM,
					'boundary' => '1',
					'deny'     => '1',
				),
				array(
					'label' => 'Dup',
					'term'  => 'project nimbus',
				),
			)
		);
		$this->assertCount( 1, $terms );
		$this->assertSame( self::TERM, $terms[0]['term'] );
		$this->assertTrue( $terms[0]['boundary'] );
		$this->assertTrue( $terms[0]['deny'] );

		$map = Phrasebook::sanitize_plugin_modes(
			array(
				self::PLUGIN => 'deny',
				self::OTHER  => 'warn',
				'bad'        => 'deny',
				'nope.php'   => 'follow',
			)
		);
		$this->assertSame(
			array(
				self::PLUGIN => 'deny',
				self::OTHER  => 'warn',
			),
			$map
		);
	}

	/**
	 * @return list<array{label:string,term:string,boundary:bool}>
	 */
	private function one_term(): array {
		return array(
			array(
				'label'    => self::LABEL,
				'term'     => self::TERM,
				'boundary' => true,
			),
		);
	}

	private function save_term(): void {
		Phrasebook::save_list( Phrasebook::MODE_WARN, $this->one_term() );
	}

	/**
	 * @return array<string,mixed>
	 */
	private function matching_event(): array {
		return array(
			'plugin'         => self::PLUGIN,
			'decision'       => 'allow',
			'prompt_preview' => 'Draft ' . self::TERM . ' notes.',
		);
	}
}
