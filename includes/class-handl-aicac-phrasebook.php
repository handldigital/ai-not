<?php
/**
 * AICAC-PHRASEBOOK (#514): owner-defined confidential-term screen.
 *
 * Screens outbound AI payloads for words only this site knows are sensitive.
 * The term list lives in its own option. Empty list is fully inert. Default
 * is Warn (allow + alert). Global Deny, a per-term Deny flag, or a per-plugin
 * override can block with reason phrasebook. Alerts and Activity rows carry
 * the term label and count only — never the term or surrounding request text.
 *
 * README-FREE. Own admin surface. Tripwire and PII-WARN are read-only.
 * No quarantine, policy internals, or admin.php edits beyond the sanctioned
 * hook points. plugin.php require + init are keep-both.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Case-insensitive screen of outbound prompt text against an owner term list.
 */
final class Phrasebook {

	public const MODE_WARN = 'warn';
	public const MODE_DENY = 'deny';

	public const REASON = 'phrasebook';

	public const CHANNEL = 'phrasebook';

	public const OPTION_KEY = 'handl_aicac_phrasebook';

	public const POLICY_KEY = 'phrasebook_screen';

	public const PAGE_SLUG = 'handl-aicac-phrasebook';

	public const ACTION_SAVE = 'handl_aicac_phrasebook_save';

	public const MAX_TERMS = 50;

	public const LABEL_MAX = 80;

	public const TERM_MIN = 2;

	public const TERM_MAX = 120;

	/** @var bool */
	private static $registered = false;

	/**
	 * @return list<string>
	 */
	public static function modes(): array {
		return array(
			self::MODE_WARN,
			self::MODE_DENY,
		);
	}

	/**
	 * @param mixed $raw
	 */
	public static function sanitize_mode( $raw ): string {
		$mode = sanitize_key( (string) $raw );
		if ( self::MODE_DENY === $mode ) {
			return self::MODE_DENY;
		}

		return self::MODE_WARN;
	}

	/**
	 * Per-plugin overrides. Absent means follow the site default.
	 * Both warn and deny are kept so a plugin can override either way.
	 *
	 * @param mixed $raw
	 * @return array<string,string> plugin => warn|deny
	 */
	public static function sanitize_plugin_modes( $raw ): array {
		if ( ! is_array( $raw ) ) {
			return array();
		}
		$out = array();
		foreach ( $raw as $plugin => $mode ) {
			$plugin = self::sanitize_plugin( (string) $plugin );
			if ( '' === $plugin ) {
				continue;
			}
			$mode = sanitize_key( (string) $mode );
			if ( self::MODE_WARN !== $mode && self::MODE_DENY !== $mode ) {
				continue;
			}
			$out[ $plugin ] = $mode;
		}

		return $out;
	}

	/**
	 * Site default from the own option. Missing option = Warn.
	 */
	public static function global_mode(): string {
		$stored = self::stored();

		return self::sanitize_mode( $stored['mode'] ?? self::MODE_WARN );
	}

	/**
	 * Plugin override wins. Otherwise the site default (Warn on a fresh install).
	 *
	 * @param array<string,mixed> $policy
	 */
	public static function mode_for_plugin( array $policy, ?string $plugin ): string {
		$plugin = self::sanitize_plugin( (string) $plugin );
		$map    = self::sanitize_plugin_modes( $policy[ self::POLICY_KEY ] ?? array() );
		if ( '' !== $plugin && isset( $map[ $plugin ] ) ) {
			return $map[ $plugin ];
		}

		return self::global_mode();
	}

	/**
	 * @param mixed $raw
	 * @return list<array{label:string,term:string,boundary:bool,deny:bool}>
	 */
	public static function sanitize_terms( $raw ): array {
		if ( ! is_array( $raw ) ) {
			return array();
		}
		$out  = array();
		$seen = array();
		foreach ( $raw as $row ) {
			if ( count( $out ) >= self::MAX_TERMS ) {
				break;
			}
			if ( ! is_array( $row ) ) {
				continue;
			}
			$label = self::sanitize_label( $row['label'] ?? '' );
			$term  = self::sanitize_term( $row['term'] ?? '' );
			if ( '' === $label || '' === $term ) {
				continue;
			}
			$key = self::term_key( $term );
			if ( isset( $seen[ $key ] ) ) {
				continue;
			}
			$seen[ $key ] = true;
			$out[]        = array(
				'label'    => $label,
				'term'     => $term,
				'boundary' => ! empty( $row['boundary'] ),
				'deny'     => ! empty( $row['deny'] ),
			);
		}

		return $out;
	}

	/**
	 * @return list<array{label:string,term:string,boundary:bool,deny:bool}>
	 */
	public static function terms(): array {
		$stored = self::stored();

		return self::sanitize_terms( $stored['terms'] ?? array() );
	}

	/**
	 * Replace the own option. Does not touch policy.
	 *
	 * @param mixed $mode
	 * @param mixed $terms
	 */
	public static function save_list( $mode, $terms ): void {
		update_option(
			self::OPTION_KEY,
			array(
				'mode'  => self::sanitize_mode( $mode ),
				'terms' => self::sanitize_terms( $terms ),
			),
			false
		);
	}

	/**
	 * Screen text. Returns label => count. Never includes the term.
	 * Empty list returns an empty array without scanning.
	 *
	 * @return array<string,int>
	 */
	public static function screen( string $text ): array {
		$detail = self::screen_detail( $text );

		return $detail['labels'];
	}

	/**
	 * @return array{labels:array<string,int>,deny:bool}
	 */
	public static function screen_detail( string $text ): array {
		$empty = array(
			'labels' => array(),
			'deny'   => false,
		);
		$terms = self::terms();
		if ( empty( $terms ) || '' === $text ) {
			return $empty;
		}
		$labels = array();
		$deny   = false;
		foreach ( $terms as $row ) {
			$count = self::count_term( $text, $row['term'], $row['boundary'] );
			if ( $count < 1 ) {
				continue;
			}
			$label            = $row['label'];
			$labels[ $label ] = ( $labels[ $label ] ?? 0 ) + $count;
			if ( ! empty( $row['deny'] ) ) {
				$deny = true;
			}
		}

		return array(
			'labels' => $labels,
			'deny'   => $deny,
		);
	}

	/**
	 * Apply the screen to an Activity event.
	 *
	 * Empty list: screen is on, but the call is unchanged.
	 * A match stores label + count only and clears stored request text so the
	 * surrounding payload is not kept. Does not remove another screen's match.
	 *
	 * @param array<string,mixed> $event
	 * @param array<string,mixed> $policy
	 * @param mixed               $builder Optional builder for full-text screen.
	 * @return array{active:bool,prevent:bool,mode:string,matches:array<string,int>}
	 */
	public static function apply_to_event( array &$event, array $policy, $builder = null ): array {
		$plugin = isset( $event['plugin'] ) ? (string) $event['plugin'] : '';
		$mode   = self::mode_for_plugin( $policy, $plugin );
		$terms  = self::terms();
		if ( empty( $terms ) ) {
			return array(
				'active'  => true,
				'prevent' => false,
				'mode'    => $mode,
				'matches' => array(),
			);
		}

		$text = self::payload_text( $builder );
		if ( '' === $text && isset( $event['prompt_preview'] ) && is_string( $event['prompt_preview'] ) ) {
			$text = (string) $event['prompt_preview'];
		}
		if ( '' === $text ) {
			return array(
				'active'  => true,
				'prevent' => false,
				'mode'    => $mode,
				'matches' => array(),
			);
		}

		$detail = self::screen_detail( $text );
		$labels = $detail['labels'];
		if ( empty( $labels ) ) {
			return array(
				'active'  => true,
				'prevent' => false,
				'mode'    => $mode,
				'matches' => array(),
			);
		}

		$effective = $mode;
		if ( self::MODE_DENY === $mode || ! empty( $detail['deny'] ) ) {
			$effective = self::MODE_DENY;
		}

		self::strip_payload_context( $event );

		$event['phrasebook_match'] = array(
			'labels' => $labels,
			'mode'   => $effective,
		);

		return array(
			'active'  => true,
			'prevent' => ( self::MODE_DENY === $effective ),
			'mode'    => $effective,
			'matches' => $labels,
		);
	}

	/**
	 * Alert after the row is retained. Label and count only.
	 *
	 * @param array<string,mixed> $event
	 * @param array<string,mixed> $policy
	 * @return array{alerted:bool,reason:string}
	 */
	public static function maybe_alert( array $event, array $policy ): array {
		$match = isset( $event['phrasebook_match'] ) && is_array( $event['phrasebook_match'] ) ? $event['phrasebook_match'] : null;
		if ( null === $match ) {
			return array( 'alerted' => false, 'reason' => 'no_match' );
		}

		$channel = isset( $event['channel'] ) ? (string) $event['channel'] : '';
		if ( self::CHANNEL === $channel ) {
			return array( 'alerted' => false, 'reason' => 'skip_channel' );
		}

		$labels = isset( $match['labels'] ) && is_array( $match['labels'] ) ? $match['labels'] : array();
		$labels = self::sanitize_match_labels( $labels );
		if ( empty( $labels ) ) {
			return array( 'alerted' => false, 'reason' => 'empty_labels' );
		}

		$plugin = isset( $event['plugin'] ) ? self::sanitize_plugin( (string) $event['plugin'] ) : '';
		$ts     = isset( $event['ts'] ) ? (int) $event['ts'] : time();
		if ( $ts <= 0 ) {
			$ts = time();
		}

		if ( class_exists( Quiet_Hours::class, false ) && null !== Quiet_Hours::active_window( $policy, $ts ) ) {
			return array( 'alerted' => false, 'reason' => 'quiet_hours' );
		}

		if ( '' !== $plugin && class_exists( Alert_Snooze::class, false ) && Alert_Snooze::should_suppress( $plugin, self::CHANNEL, $ts ) ) {
			return array( 'alerted' => false, 'reason' => 'suppressed' );
		}

		if ( ! class_exists( Alerts::class, false ) ) {
			return array( 'alerted' => false, 'reason' => 'no_alerts' );
		}

		$to = Alerts::resolve_email( $policy );
		if ( '' === $to ) {
			return array( 'alerted' => false, 'reason' => 'no_recipient' );
		}

		$mode    = self::sanitize_mode( $match['mode'] ?? '' );
		$subject = self::build_subject( $plugin );
		$body    = self::build_body( $plugin, $labels, $mode );
		$ok      = Alerts::safe_wp_mail( $to, $subject, $body );

		$webhook = isset( $policy['alert_webhook_url'] ) ? Alerts::sanitize_webhook_url( (string) $policy['alert_webhook_url'] ) : '';
		if ( '' !== $webhook ) {
			$hook_ok = Alerts::safe_wp_remote_post(
				$webhook,
				array(
					'type'   => 'handl_aicac_phrasebook',
					'plugin' => $plugin,
					'mode'   => $mode,
					'labels' => $labels,
					'site'   => function_exists( 'home_url' ) ? home_url( '/' ) : '',
				),
				'phrasebook'
			);
			$ok = $ok || $hook_ok;
		}

		if ( ! $ok ) {
			return array( 'alerted' => false, 'reason' => 'delivery_failed' );
		}

		return array( 'alerted' => true, 'reason' => 'alerted' );
	}

	/**
	 * @param array<string,mixed> $labels
	 * @return array<string,int>
	 */
	public static function sanitize_match_labels( array $labels ): array {
		$out = array();
		foreach ( $labels as $label => $count ) {
			$label = self::sanitize_label( $label );
			$count = (int) $count;
			if ( '' === $label || $count < 1 ) {
				continue;
			}
			$out[ $label ] = $count;
		}

		return $out;
	}

	/**
	 * @param array<string,int> $labels
	 */
	public static function receipt_summary( array $labels ): string {
		$labels = self::sanitize_match_labels( $labels );
		if ( empty( $labels ) ) {
			return '';
		}
		$parts = array();
		foreach ( $labels as $label => $count ) {
			$parts[] = sprintf( '%s (%d)', $label, (int) $count );
		}

		return implode( ', ', $parts );
	}

	public static function build_subject( string $plugin ): string {
		$site  = function_exists( 'get_bloginfo' )
			? wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES )
			: 'WordPress';
		$label = self::plugin_label( $plugin );

		return sprintf(
			/* translators: 1: site name, 2: plugin label */
			__( '[%1$s] Confidential term detected in an AI call by %2$s', 'handl-ai-connector-access-control' ),
			$site,
			$label
		);
	}

	/**
	 * @param array<string,int> $labels
	 */
	public static function build_body( string $plugin, array $labels, string $mode ): string {
		$lines   = array();
		$lines[] = __( 'HandL AI Connector Access Control found a confidential term in this plugin\'s AI request.', 'handl-ai-connector-access-control' );
		$lines[] = '';
		$lines[] = sprintf(
			/* translators: %s: plugin basename or label */
			__( 'Plugin: %s', 'handl-ai-connector-access-control' ),
			self::plugin_label( $plugin )
		);
		if ( self::MODE_DENY === self::sanitize_mode( $mode ) ) {
			$lines[] = __( 'Phrasebook setting: Deny. This check blocks matching requests except in Learn mode.', 'handl-ai-connector-access-control' );
		} else {
			$lines[] = __( 'Phrasebook setting: Warn. This check does not block the request. Other rules still apply.', 'handl-ai-connector-access-control' );
		}
		$lines[] = __( 'Labels and counts (the word and the request text are not included):', 'handl-ai-connector-access-control' );
		$summary = self::receipt_summary( $labels );
		if ( '' !== $summary ) {
			$lines[] = $summary;
		}
		$lines[] = '';
		$lines[] = __( 'Review this plugin\'s AI request. This alert does not include the word or the request text.', 'handl-ai-connector-access-control' );

		return implode( "\n", $lines );
	}

	public static function init(): void {
		if ( self::$registered ) {
			return;
		}
		self::$registered = true;
		add_action( 'admin_menu', array( self::class, 'register_menu' ), 20 );
		add_action( 'admin_post_' . self::ACTION_SAVE, array( self::class, 'handle_save' ) );
	}

	public static function reset_for_tests(): void {
		self::$registered = false;
	}

	public static function register_menu(): void {
		if ( ! class_exists( Caps::class, false ) || ! Caps::user_can_view() ) {
			return;
		}
		if ( ! function_exists( 'add_submenu_page' ) || ! class_exists( Admin::class, false ) ) {
			return;
		}
		add_submenu_page(
			Admin::MENU_SLUG,
			__( 'Phrasebook', 'handl-ai-connector-access-control' ),
			__( 'Phrasebook', 'handl-ai-connector-access-control' ),
			Caps::VIEW,
			self::PAGE_SLUG,
			array( self::class, 'render_page' )
		);
	}

	public static function render_page(): void {
		if ( ! class_exists( Caps::class, false ) || ! Caps::user_can_view() ) {
			return;
		}
		$policy     = class_exists( Policy::class, false ) ? Policy::get_policy() : array();
		$modes      = self::sanitize_plugin_modes( $policy[ self::POLICY_KEY ] ?? array() );
		$can_manage = class_exists( Caps::class, false ) && Caps::user_can_manage();
		$plugins    = self::candidate_plugins( $policy );
		$terms      = self::terms();
		$global     = self::global_mode();
		$rows       = $terms;
		$blanks     = 3;
		for ( $i = 0; $i < $blanks; $i++ ) {
			$rows[] = array(
				'label'    => '',
				'term'     => '',
				'boundary' => false,
				'deny'     => false,
			);
		}

		echo '<div class="wrap">';
		echo '<h1>' . esc_html__( 'Phrasebook', 'handl-ai-connector-access-control' ) . '</h1>';
		echo '<p class="description">' . esc_html__( 'Checks AI requests for words only you know are sensitive. On by default. An empty list does nothing.', 'handl-ai-connector-access-control' ) . '</p>';
		echo '<p class="description">' . esc_html__( 'Alerts name the label and the count. They do not include the word or the request text.', 'handl-ai-connector-access-control' ) . '</p>';

		if ( $can_manage ) {
			echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
			echo '<input type="hidden" name="action" value="' . esc_attr( self::ACTION_SAVE ) . '" />';
			if ( function_exists( 'wp_nonce_field' ) ) {
				wp_nonce_field( self::ACTION_SAVE );
			}
		}

		echo '<h2>' . esc_html__( 'Site default', 'handl-ai-connector-access-control' ) . '</h2>';
		echo '<p>';
		if ( $can_manage ) {
			echo '<select name="handl_aicac_phrasebook_mode">';
			foreach ( self::global_mode_choices() as $value => $choice_label ) {
				$sel = ( $global === $value ) ? ' selected="selected"' : '';
				echo '<option value="' . esc_attr( $value ) . '"' . $sel . '>' . esc_html( $choice_label ) . '</option>';
			}
			echo '</select>';
		} else {
			echo esc_html( self::global_mode_choices()[ $global ] ?? $global );
		}
		echo '</p>';
		echo '<p class="description">' . esc_html__( 'Warn allows the request and sends an alert. Deny blocks it unless Learn mode is on.', 'handl-ai-connector-access-control' ) . '</p>';

		echo '<h2>' . esc_html__( 'Terms', 'handl-ai-connector-access-control' ) . '</h2>';
		echo '<p class="description">' . esc_html__( 'Label is what the alert says. Term is the word to look for. At least 2 characters. Up to 50 terms.', 'handl-ai-connector-access-control' ) . '</p>';
		echo '<table class="widefat striped" style="max-width:64em;"><thead><tr>';
		echo '<th>' . esc_html__( 'Label', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Term', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Whole word', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Block this term', 'handl-ai-connector-access-control' ) . '</th>';
		echo '</tr></thead><tbody>';
		foreach ( $rows as $index => $row ) {
			$label    = isset( $row['label'] ) ? (string) $row['label'] : '';
			$term     = isset( $row['term'] ) ? (string) $row['term'] : '';
			$boundary = ! empty( $row['boundary'] );
			$deny     = ! empty( $row['deny'] );
			echo '<tr><td>';
			if ( $can_manage ) {
				echo '<input type="text" class="regular-text" name="handl_aicac_phrasebook_terms[' . esc_attr( (string) $index ) . '][label]" value="' . esc_attr( $label ) . '" maxlength="' . esc_attr( (string) self::LABEL_MAX ) . '" />';
			} else {
				echo esc_html( $label );
			}
			echo '</td><td>';
			if ( $can_manage ) {
				echo '<input type="text" class="regular-text" name="handl_aicac_phrasebook_terms[' . esc_attr( (string) $index ) . '][term]" value="' . esc_attr( $term ) . '" maxlength="' . esc_attr( (string) self::TERM_MAX ) . '" />';
			} else {
				echo esc_html( $term );
			}
			echo '</td><td>';
			if ( $can_manage ) {
				echo '<input type="checkbox" name="handl_aicac_phrasebook_terms[' . esc_attr( (string) $index ) . '][boundary]" value="1"' . ( $boundary ? ' checked="checked"' : '' ) . ' />';
			} else {
				echo esc_html( $boundary ? __( 'Yes', 'handl-ai-connector-access-control' ) : __( 'No', 'handl-ai-connector-access-control' ) );
			}
			echo '</td><td>';
			if ( $can_manage ) {
				echo '<input type="checkbox" name="handl_aicac_phrasebook_terms[' . esc_attr( (string) $index ) . '][deny]" value="1"' . ( $deny ? ' checked="checked"' : '' ) . ' />';
			} else {
				echo esc_html( $deny ? __( 'Yes', 'handl-ai-connector-access-control' ) : __( 'No', 'handl-ai-connector-access-control' ) );
			}
			echo '</td></tr>';
		}
		echo '</tbody></table>';
		echo '<p class="description">' . esc_html__( 'Whole word skips matches inside other words. Block this term stops the request even when the site default is Warn.', 'handl-ai-connector-access-control' ) . '</p>';

		if ( ! empty( $plugins ) ) {
			echo '<h2>' . esc_html__( 'Per plugin', 'handl-ai-connector-access-control' ) . '</h2>';
			echo '<table class="widefat striped" style="max-width:52em;"><thead><tr>';
			echo '<th>' . esc_html__( 'Plugin', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Screen', 'handl-ai-connector-access-control' ) . '</th>';
			echo '</tr></thead><tbody>';
			foreach ( $plugins as $basename => $plugin_label ) {
				$current = $modes[ $basename ] ?? '';
				echo '<tr><td>' . esc_html( $plugin_label ) . '<br /><code>' . esc_html( $basename ) . '</code></td><td>';
				if ( $can_manage ) {
					echo '<select name="handl_aicac_phrasebook_modes[' . esc_attr( $basename ) . ']">';
					foreach ( self::plugin_mode_choices() as $value => $choice_label ) {
						$sel = ( $current === $value ) ? ' selected="selected"' : '';
						echo '<option value="' . esc_attr( $value ) . '"' . $sel . '>' . esc_html( $choice_label ) . '</option>';
					}
					echo '</select>';
				} else {
					echo esc_html( self::plugin_mode_choices()[ $current ] ?? self::plugin_mode_choices()[''] );
				}
				echo '</td></tr>';
			}
			echo '</tbody></table>';
			echo '<p class="description">' . esc_html__( 'Follow site default uses the setting above. Warn or Deny overrides it for that plugin.', 'handl-ai-connector-access-control' ) . '</p>';
		}

		if ( $can_manage ) {
			if ( function_exists( 'submit_button' ) ) {
				submit_button( __( 'Save phrasebook', 'handl-ai-connector-access-control' ) );
			} else {
				echo '<p><button type="submit" class="button button-primary">' . esc_html__( 'Save phrasebook', 'handl-ai-connector-access-control' ) . '</button></p>';
			}
			echo '</form>';
		}

		echo '</div>';
	}

	public static function handle_save(): void {
		if ( ! class_exists( Caps::class, false ) || ! Caps::user_can_manage() ) {
			self::die_forbidden();
		}
		if ( function_exists( 'check_admin_referer' ) ) {
			check_admin_referer( self::ACTION_SAVE );
		}
		$mode_raw = isset( $_POST['handl_aicac_phrasebook_mode'] ) // phpcs:ignore WordPress.Security.NonceVerification.Missing
			? wp_unslash( $_POST['handl_aicac_phrasebook_mode'] ) // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
			: self::MODE_WARN;
		$terms_raw = isset( $_POST['handl_aicac_phrasebook_terms'] ) && is_array( $_POST['handl_aicac_phrasebook_terms'] ) // phpcs:ignore WordPress.Security.NonceVerification.Missing
			? wp_unslash( $_POST['handl_aicac_phrasebook_terms'] ) // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
			: array();
		self::save_list( $mode_raw, is_array( $terms_raw ) ? $terms_raw : array() );

		$modes_raw = isset( $_POST['handl_aicac_phrasebook_modes'] ) && is_array( $_POST['handl_aicac_phrasebook_modes'] ) // phpcs:ignore WordPress.Security.NonceVerification.Missing
			? wp_unslash( $_POST['handl_aicac_phrasebook_modes'] ) // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
			: array();
		$modes = self::sanitize_plugin_modes( is_array( $modes_raw ) ? $modes_raw : array() );

		if ( class_exists( Policy::class, false ) && method_exists( Policy::class, 'get_policy' ) && method_exists( Policy::class, 'save_policy' ) ) {
			$policy                      = Policy::get_policy();
			$policy[ self::POLICY_KEY ]  = $modes;
			Policy::save_policy( $policy );
		}

		self::redirect();
	}

	/**
	 * @param array<string,mixed> $event
	 */
	private static function strip_payload_context( array &$event ): void {
		if ( isset( $event['prompt_preview'] ) ) {
			$event['prompt_preview'] = '';
		}
		if ( isset( $event['config'] ) && is_array( $event['config'] ) && isset( $event['config']['systemInstruction'] ) ) {
			$event['config']['systemInstruction'] = '';
		}
	}

	/**
	 * @return array{mode:string,terms:array<int,mixed>}
	 */
	private static function stored(): array {
		$raw = get_option( self::OPTION_KEY, array() );
		if ( ! is_array( $raw ) ) {
			return array(
				'mode'  => self::MODE_WARN,
				'terms' => array(),
			);
		}

		return $raw;
	}

	private static function count_term( string $text, string $term, bool $boundary ): int {
		$pattern = self::term_pattern( $term, $boundary );
		if ( '' === $pattern ) {
			return 0;
		}
		$count = preg_match_all( $pattern, $text, $found );
		if ( false === $count ) {
			return 0;
		}

		return (int) $count;
	}

	private static function term_pattern( string $term, bool $boundary ): string {
		$quoted = preg_quote( $term, '/' );
		if ( '' === $quoted ) {
			return '';
		}
		if ( $boundary ) {
			return '/(?<![\p{L}\p{N}_])' . $quoted . '(?![\p{L}\p{N}_])/iu';
		}

		return '/' . $quoted . '/iu';
	}

	/**
	 * @param mixed $raw
	 */
	private static function sanitize_label( $raw ): string {
		$label = sanitize_text_field( (string) $raw );
		if ( function_exists( 'mb_substr' ) ) {
			$label = mb_substr( $label, 0, self::LABEL_MAX );
		} else {
			$label = substr( $label, 0, self::LABEL_MAX );
		}

		return trim( $label );
	}

	/**
	 * @param mixed $raw
	 */
	private static function sanitize_term( $raw ): string {
		$term = sanitize_text_field( (string) $raw );
		$term = trim( $term );
		$len  = function_exists( 'mb_strlen' ) ? mb_strlen( $term ) : strlen( $term );
		if ( $len < self::TERM_MIN ) {
			return '';
		}
		if ( $len > self::TERM_MAX ) {
			$term = function_exists( 'mb_substr' ) ? mb_substr( $term, 0, self::TERM_MAX ) : substr( $term, 0, self::TERM_MAX );
		}

		return $term;
	}

	private static function term_key( string $term ): string {
		if ( function_exists( 'mb_strtolower' ) ) {
			return mb_strtolower( $term );
		}

		return strtolower( $term );
	}

	/**
	 * @return array<string,string>
	 */
	private static function global_mode_choices(): array {
		return array(
			self::MODE_WARN => __( 'Warn (allow and alert)', 'handl-ai-connector-access-control' ),
			self::MODE_DENY => __( 'Deny (block and alert)', 'handl-ai-connector-access-control' ),
		);
	}

	/**
	 * @return array<string,string>
	 */
	private static function plugin_mode_choices(): array {
		return array(
			''              => __( 'Follow site default', 'handl-ai-connector-access-control' ),
			self::MODE_WARN => __( 'Warn', 'handl-ai-connector-access-control' ),
			self::MODE_DENY => __( 'Deny', 'handl-ai-connector-access-control' ),
		);
	}

	/**
	 * @param array<string,mixed> $policy
	 * @return array<string,string>
	 */
	private static function candidate_plugins( array $policy ): array {
		$out = array();
		if ( function_exists( 'get_plugins' ) ) {
			foreach ( get_plugins() as $basename => $info ) {
				$plugin = self::sanitize_plugin( $basename );
				if ( '' === $plugin ) {
					continue;
				}
				$label          = is_array( $info ) && isset( $info['Name'] ) ? (string) $info['Name'] : $plugin;
				$out[ $plugin ] = '' !== $label ? $label : $plugin;
			}
		}
		$plugins = isset( $policy['plugins'] ) && is_array( $policy['plugins'] ) ? $policy['plugins'] : array();
		foreach ( array_keys( $plugins ) as $basename ) {
			$plugin = self::sanitize_plugin( (string) $basename );
			if ( '' !== $plugin && ! isset( $out[ $plugin ] ) ) {
				$out[ $plugin ] = $plugin;
			}
		}
		ksort( $out );

		return $out;
	}

	/**
	 * @param mixed $builder
	 */
	private static function payload_text( $builder ): string {
		if ( class_exists( Pii_Warn::class, false ) && method_exists( Pii_Warn::class, 'payload_text_from_builder' ) ) {
			return (string) Pii_Warn::payload_text_from_builder( $builder );
		}

		return '';
	}

	private static function plugin_label( string $plugin ): string {
		$plugin = self::sanitize_plugin( $plugin );
		if ( '' === $plugin ) {
			return __( '(unattributed)', 'handl-ai-connector-access-control' );
		}
		if ( function_exists( 'get_plugins' ) ) {
			$plugins = get_plugins();
			if ( isset( $plugins[ $plugin ]['Name'] ) ) {
				return (string) $plugins[ $plugin ]['Name'] . ' (' . $plugin . ')';
			}
		}

		return $plugin;
	}

	/**
	 * @param mixed $raw
	 */
	private static function sanitize_plugin( $raw ): string {
		if ( class_exists( Plugin_Profile::class, false ) && method_exists( Plugin_Profile::class, 'sanitize_plugin' ) ) {
			return Plugin_Profile::sanitize_plugin( $raw );
		}
		$plugin = sanitize_text_field( (string) $raw );

		return preg_match( '/^[A-Za-z0-9._\-]+(?:\/[A-Za-z0-9._\-]+)*\.php$/', $plugin ) ? $plugin : '';
	}

	private static function die_forbidden(): void {
		$message = __( 'You do not have permission to save these settings.', 'handl-ai-connector-access-control' );
		if ( function_exists( 'wp_die' ) ) {
			wp_die( esc_html( $message ) );
		}
	}

	private static function redirect(): void {
		$url = admin_url( 'admin.php?page=' . self::PAGE_SLUG );
		if ( function_exists( 'wp_safe_redirect' ) ) {
			wp_safe_redirect( $url );
			exit;
		}
	}
}
