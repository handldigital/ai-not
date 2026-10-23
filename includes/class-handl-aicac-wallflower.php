<?php
/**
 * AICAC-WALLFLOWER (#469): unused AI capability census.
 *
 * Joins preflight findings (capability) against Activity / Dead_Rules last-matched
 * stamps (usage) and policy rule state. Suggestion text only — never writes rules.
 *
 * README-FREE. Own options only (handl_aicac_wallflower_*). Own admin screen.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Read-only unused-capability census.
 */
final class Wallflower {

	public const PAGE_SLUG = 'handl-aicac-wallflower';

	public const OPTION_KEY = 'handl_aicac_wallflower';

	public const CENSUS_OPTION = 'handl_aicac_wallflower_census';

	public const GENERATED_OPTION = 'handl_aicac_wallflower_generated_at';

	public const ACTION_SAVE = 'handl_aicac_wallflower_save';

	public const POST_PRESENT = 'handl_aicac_wallflower_present';

	public const POST_DAYS = 'handl_aicac_wallflower_days';

	public const DEFAULT_DAYS = 60;

	/** @var list<int> */
	public const DAY_OPTIONS = array( 30, 60, 90 );

	public const FLAG_WALLFLOWER         = 'WALLFLOWER';
	public const FLAG_COVERED            = 'COVERED';
	public const FLAG_ACTIVE             = 'ACTIVE';
	public const FLAG_INSUFFICIENT_DATA  = 'INSUFFICIENT-DATA';

	public const MAX_ROWS = 200;

	/** @var bool */
	private static $registered = false;

	/** @var bool */
	private static $skip_cache = false;

	/** @var int|null */
	private static $test_now = null;

	/** @var array<string,array<string,mixed>>|null basename => finding row */
	private static $test_findings = null;

	/** @var list<array<string,mixed>>|null */
	private static $test_log = null;

	/** @var array<string,int>|null */
	private static $test_matched = null;

	/** @var array<string,string>|null basename => allow|deny|'' */
	private static $test_rules = null;

	public static function init(): void {
		if ( self::$registered ) {
			return;
		}
		self::$registered = true;
		add_action( 'admin_menu', array( self::class, 'register_menu' ), 20 );
		add_action( 'admin_post_' . self::ACTION_SAVE, array( self::class, 'handle_save' ) );
	}

	public static function reset_for_tests(): void {
		self::$registered    = false;
		self::$skip_cache    = false;
		self::$test_now      = null;
		self::$test_findings = null;
		self::$test_log      = null;
		self::$test_matched  = null;
		self::$test_rules    = null;
		delete_option( self::OPTION_KEY );
		delete_option( self::CENSUS_OPTION );
		delete_option( self::GENERATED_OPTION );
	}

	public static function set_skip_cache( bool $skip ): void {
		self::$skip_cache = $skip;
	}

	public static function set_test_now( ?int $now ): void {
		self::$test_now = $now;
	}

	/**
	 * @param array<string,array<string,mixed>>|null $findings Basename => finding.
	 */
	public static function set_test_findings( ?array $findings ): void {
		self::$test_findings = $findings;
	}

	/**
	 * @param list<array<string,mixed>>|null $log Injected activity rows.
	 */
	public static function set_test_log( ?array $log ): void {
		self::$test_log = $log;
	}

	/**
	 * @param array<string,int>|null $matched Injected Dead_Rules last_matched map.
	 */
	public static function set_test_matched( ?array $matched ): void {
		self::$test_matched = $matched;
	}

	/**
	 * @param array<string,string>|null $rules Basename => allow|deny|''.
	 */
	public static function set_test_rules( ?array $rules ): void {
		self::$test_rules = $rules;
	}

	public static function now(): int {
		if ( null !== self::$test_now ) {
			return (int) self::$test_now;
		}
		if ( class_exists( Clock::class, false ) && method_exists( Clock::class, 'now' ) ) {
			return (int) Clock::now();
		}

		return time();
	}

	/**
	 * @param mixed $raw
	 */
	public static function sanitize_days( $raw ): int {
		$days = is_numeric( $raw ) ? (int) $raw : self::DEFAULT_DAYS;
		if ( ! in_array( $days, self::DAY_OPTIONS, true ) ) {
			// Mirror Dead_Rules::DAY_OPTIONS: accept their 0/30/60/90 sanitizer, then clamp to our window set.
			if ( class_exists( Dead_Rules::class, false ) && method_exists( Dead_Rules::class, 'sanitize_days' ) ) {
				$days = Dead_Rules::sanitize_days( $raw );
			}
		}
		if ( ! in_array( $days, self::DAY_OPTIONS, true ) ) {
			return self::DEFAULT_DAYS;
		}

		return $days;
	}

	/**
	 * @return array{days:int}
	 */
	public static function defaults(): array {
		return array(
			'days' => self::DEFAULT_DAYS,
		);
	}

	/**
	 * @return array{days:int}
	 */
	public static function get_settings(): array {
		return self::sanitize_settings( get_option( self::OPTION_KEY, array() ) );
	}

	/**
	 * @param mixed $raw
	 * @return array{days:int}
	 */
	public static function sanitize_settings( $raw ): array {
		$out = self::defaults();
		if ( ! is_array( $raw ) ) {
			return $out;
		}
		$out['days'] = self::sanitize_days( $raw['days'] ?? self::DEFAULT_DAYS );

		return $out;
	}

	/**
	 * @return array<string,array<string,mixed>>
	 */
	public static function preflight_plugin_findings(): array {
		if ( null !== self::$test_findings ) {
			$out = array();
			foreach ( self::$test_findings as $basename => $row ) {
				$basename = self::sanitize_plugin( (string) $basename );
				if ( '' === $basename || ! is_array( $row ) ) {
					continue;
				}
				$out[ $basename ] = $row;
			}

			return $out;
		}
		if ( ! class_exists( Preflight_Scan::class, false ) || ! method_exists( Preflight_Scan::class, 'get_state' ) ) {
			return array();
		}
		$state = Preflight_Scan::get_state();
		$items = isset( $state['items']['plugin'] ) && is_array( $state['items']['plugin'] )
			? $state['items']['plugin']
			: array();
		$out   = array();
		foreach ( $items as $basename => $row ) {
			$basename = self::sanitize_plugin( (string) $basename );
			if ( '' === $basename || ! is_array( $row ) ) {
				continue;
			}
			$out[ $basename ] = $row;
		}

		return $out;
	}

	/**
	 * @return array<string,int> basename => newest activity ts
	 */
	public static function activity_last_ts(): array {
		if ( null !== self::$test_log ) {
			$log = self::$test_log;
		} else {
			$raw = get_option( Plugin::LOG_OPTION_KEY, array() );
			$log = is_array( $raw ) ? $raw : array();
		}
		$out = array();
		foreach ( $log as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$plugin = self::sanitize_plugin( (string) ( $row['plugin'] ?? '' ) );
			if ( '' === $plugin ) {
				continue;
			}
			$ts = isset( $row['ts'] ) ? (int) $row['ts'] : 0;
			if ( $ts <= 0 ) {
				continue;
			}
			if ( ! isset( $out[ $plugin ] ) || $ts > $out[ $plugin ] ) {
				$out[ $plugin ] = $ts;
			}
		}

		return $out;
	}

	/**
	 * @return array<string,int>
	 */
	public static function dead_rules_matched(): array {
		if ( null !== self::$test_matched ) {
			$out = array();
			foreach ( self::$test_matched as $basename => $ts ) {
				$basename = self::sanitize_plugin( (string) $basename );
				$ts       = (int) $ts;
				if ( '' === $basename || $ts <= 0 ) {
					continue;
				}
				$out[ $basename ] = $ts;
			}

			return $out;
		}
		if ( class_exists( Dead_Rules::class, false ) && method_exists( Dead_Rules::class, 'get_matched' ) ) {
			return Dead_Rules::get_matched();
		}

		return array();
	}

	/**
	 * @return array<string,string> basename => allow|deny|''
	 */
	public static function plugin_rules(): array {
		if ( null !== self::$test_rules ) {
			$out = array();
			foreach ( self::$test_rules as $basename => $rule ) {
				$basename = self::sanitize_plugin( (string) $basename );
				if ( '' === $basename ) {
					continue;
				}
				$rule = (string) $rule;
				$out[ $basename ] = ( 'allow' === $rule || 'deny' === $rule ) ? $rule : '';
			}

			return $out;
		}
		$policy  = class_exists( Policy::class, false ) ? Policy::get_policy() : array();
		$plugins = isset( $policy['plugins'] ) && is_array( $policy['plugins'] ) ? $policy['plugins'] : array();
		$out     = array();
		foreach ( $plugins as $basename => $rule ) {
			$basename = self::sanitize_plugin( (string) $basename );
			if ( '' === $basename ) {
				continue;
			}
			$rule = (string) $rule;
			$out[ $basename ] = ( 'allow' === $rule || 'deny' === $rule ) ? $rule : '';
		}

		return $out;
	}

	public static function sanitize_plugin( string $basename ): string {
		if ( class_exists( Plugin_Profile::class, false ) && method_exists( Plugin_Profile::class, 'sanitize_plugin' ) ) {
			return Plugin_Profile::sanitize_plugin( $basename );
		}
		$basename = str_replace( '\\', '/', $basename );
		$basename = ltrim( $basename, '/' );

		return sanitize_text_field( $basename );
	}

	/**
	 * @param array<string,mixed> $finding
	 * @return list<string>
	 */
	public static function providers_from_finding( array $finding ): array {
		$raw = isset( $finding['providers'] ) && is_array( $finding['providers'] )
			? $finding['providers']
			: array();
		$out = array();
		foreach ( $raw as $provider ) {
			$provider = sanitize_key( (string) $provider );
			if ( '' !== $provider ) {
				$out[] = $provider;
			}
		}
		$out = array_values( array_unique( $out ) );
		sort( $out );

		return $out;
	}

	/**
	 * @param array<string,int> $activity
	 * @param array<string,int> $matched
	 */
	public static function last_call_ts( string $basename, array $activity, array $matched ): int {
		$a = isset( $activity[ $basename ] ) ? (int) $activity[ $basename ] : 0;
		$m = isset( $matched[ $basename ] ) ? (int) $matched[ $basename ] : 0;

		return max( $a, $m );
	}

	/**
	 * @return 'allow'|'deny'|'none'
	 */
	public static function rule_state( string $basename, array $rules ): string {
		$rule = isset( $rules[ $basename ] ) ? (string) $rules[ $basename ] : '';
		if ( 'allow' === $rule || 'deny' === $rule ) {
			return $rule;
		}

		return 'none';
	}

	/**
	 * @param 'allow'|'deny'|'none' $rule
	 * @return self::FLAG_*
	 */
	public static function classify( string $rule, int $last_ts, int $now, int $days ): string {
		if ( 'deny' === $rule ) {
			return self::FLAG_COVERED;
		}
		$day = defined( 'DAY_IN_SECONDS' ) ? (int) DAY_IN_SECONDS : 86400;
		if ( $last_ts > 0 && ( $now - $last_ts ) <= ( $days * $day ) ) {
			return self::FLAG_ACTIVE;
		}

		return self::FLAG_WALLFLOWER;
	}

	/**
	 * Suggestion text only — never mutates policy.
	 */
	public static function suggestion( string $flag ): string {
		if ( self::FLAG_WALLFLOWER === $flag ) {
			return __( 'Recommend deny-by-default on the Rules tab — this plugin can call AI but has not in the selected window.', 'handl-ai-connector-access-control' );
		}
		if ( self::FLAG_COVERED === $flag ) {
			return __( 'Already denied — unused capability is covered.', 'handl-ai-connector-access-control' );
		}
		if ( self::FLAG_ACTIVE === $flag ) {
			return __( 'Recent AI activity in the selected window — no unused-capability action.', 'handl-ai-connector-access-control' );
		}

		return __( 'Run Scan All so preflight can detect AI capability for this plugin.', 'handl-ai-connector-access-control' );
	}

	/**
	 * @return array{days:int,as_of:int,rows:list<array<string,mixed>>,empty_preflight:bool}
	 */
	public static function census( ?int $days = null, ?int $now = null ): array {
		$settings = self::get_settings();
		$days     = null === $days ? (int) $settings['days'] : self::sanitize_days( $days );
		$now      = null === $now ? self::now() : (int) $now;
		$findings = self::preflight_plugin_findings();
		$activity = self::activity_last_ts();
		$matched  = self::dead_rules_matched();
		$rules    = self::plugin_rules();
		$rows     = array();

		foreach ( $findings as $basename => $finding ) {
			$providers = self::providers_from_finding( $finding );
			$last_ts   = self::last_call_ts( $basename, $activity, $matched );
			$rule      = self::rule_state( $basename, $rules );
			$flag      = self::classify( $rule, $last_ts, $now, $days );
			$day       = defined( 'DAY_IN_SECONDS' ) ? (int) DAY_IN_SECONDS : 86400;
			$days_since = $last_ts > 0 ? (int) floor( max( 0, $now - $last_ts ) / $day ) : null;
			$rows[]     = array(
				'plugin'     => $basename,
				'providers'  => $providers,
				'last_ts'    => $last_ts,
				'days_since' => $days_since,
				'rule'       => $rule,
				'flag'       => $flag,
				'suggestion' => self::suggestion( $flag ),
			);
			if ( count( $rows ) >= self::MAX_ROWS ) {
				break;
			}
		}

		// Plugins we know from usage/rules but preflight never ran for them.
		if ( count( $rows ) < self::MAX_ROWS ) {
			$known = array_unique( array_merge( array_keys( $activity ), array_keys( $matched ), array_keys( $rules ) ) );
			foreach ( $known as $basename ) {
				$basename = self::sanitize_plugin( (string) $basename );
				if ( '' === $basename || isset( $findings[ $basename ] ) ) {
					continue;
				}
				$rule       = self::rule_state( $basename, $rules );
				$last_ts    = self::last_call_ts( $basename, $activity, $matched );
				$day        = defined( 'DAY_IN_SECONDS' ) ? (int) DAY_IN_SECONDS : 86400;
				$days_since = $last_ts > 0 ? (int) floor( max( 0, $now - $last_ts ) / $day ) : null;
				$rows[]     = array(
					'plugin'     => $basename,
					'providers'  => array(),
					'last_ts'    => $last_ts,
					'days_since' => $days_since,
					'rule'       => $rule,
					'flag'       => self::FLAG_INSUFFICIENT_DATA,
					'suggestion' => self::suggestion( self::FLAG_INSUFFICIENT_DATA ),
				);
				if ( count( $rows ) >= self::MAX_ROWS ) {
					break;
				}
			}
		}

		usort(
			$rows,
			static function ( array $a, array $b ): int {
				$order = array(
					self::FLAG_WALLFLOWER        => 0,
					self::FLAG_INSUFFICIENT_DATA => 1,
					self::FLAG_ACTIVE            => 2,
					self::FLAG_COVERED           => 3,
				);
				$fa = $order[ $a['flag'] ] ?? 9;
				$fb = $order[ $b['flag'] ] ?? 9;
				if ( $fa !== $fb ) {
					return $fa <=> $fb;
				}

				return strcmp( (string) $a['plugin'], (string) $b['plugin'] );
			}
		);

		return array(
			'days'            => $days,
			'as_of'           => $now,
			'rows'            => $rows,
			'empty_preflight' => array() === $findings,
		);
	}

	/**
	 * Cached census for the admin page. Own keys only.
	 *
	 * @return array{days:int,as_of:int,rows:list<array<string,mixed>>,empty_preflight:bool,cached:bool}
	 */
	public static function snapshot( ?int $days = null ): array {
		$settings = self::get_settings();
		$days     = null === $days ? (int) $settings['days'] : self::sanitize_days( $days );

		if ( ! self::$skip_cache ) {
			$cached = get_option( self::CENSUS_OPTION, null );
			$as_of  = (int) get_option( self::GENERATED_OPTION, 0 );
			if ( is_array( $cached )
				&& isset( $cached['rows'] )
				&& is_array( $cached['rows'] )
				&& (int) ( $cached['days'] ?? 0 ) === $days
				&& $as_of > 0 ) {
				return array(
					'days'            => $days,
					'as_of'           => $as_of,
					'rows'            => array_slice( $cached['rows'], 0, self::MAX_ROWS ),
					'empty_preflight' => ! empty( $cached['empty_preflight'] ),
					'cached'          => true,
				);
			}
		}

		$data = self::census( $days );
		if ( ! self::$skip_cache ) {
			update_option(
				self::CENSUS_OPTION,
				array(
					'days'            => $data['days'],
					'rows'            => array_slice( $data['rows'], 0, self::MAX_ROWS ),
					'empty_preflight' => $data['empty_preflight'],
				),
				false
			);
			update_option( self::GENERATED_OPTION, $data['as_of'], false );
		}

		return array(
			'days'            => $data['days'],
			'as_of'           => $data['as_of'],
			'rows'            => $data['rows'],
			'empty_preflight' => $data['empty_preflight'],
			'cached'          => false,
		);
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
			__( 'Wallflower', 'handl-ai-connector-access-control' ),
			__( 'Wallflower', 'handl-ai-connector-access-control' ),
			Caps::VIEW,
			self::PAGE_SLUG,
			array( self::class, 'render_page' )
		);
	}

	public static function handle_save(): void {
		if ( ! class_exists( Caps::class, false ) || ! Caps::user_can_manage() ) {
			wp_die( esc_html__( 'You do not have permission to manage AI access control.', 'handl-ai-connector-access-control' ) );
		}
		check_admin_referer( self::ACTION_SAVE );
		if ( empty( $_POST[ self::POST_PRESENT ] ) ) {
			wp_die( esc_html__( 'Invalid form submission.', 'handl-ai-connector-access-control' ) );
		}
		$days = self::sanitize_days( wp_unslash( $_POST[ self::POST_DAYS ] ?? self::DEFAULT_DAYS ) );
		update_option( self::OPTION_KEY, array( 'days' => $days ), false );
		// Invalidate census cache when the window changes.
		delete_option( self::CENSUS_OPTION );
		delete_option( self::GENERATED_OPTION );
		$redirect = admin_url( 'admin.php?page=' . self::PAGE_SLUG . '&updated=1' );
		wp_safe_redirect( $redirect );
		exit;
	}

	public static function render_page(): void {
		if ( ! class_exists( Caps::class, false ) || ! Caps::user_can_view() ) {
			return;
		}
		$snap = self::snapshot();
		$days = (int) $snap['days'];

		echo '<div class="wrap">';
		echo '<h1>' . esc_html__( 'Wallflower', 'handl-ai-connector-access-control' ) . '</h1>';
		echo '<p class="description">' . esc_html__( 'Plugins that can call AI but have not recently. Report only — create deny rules on the Rules tab.', 'handl-ai-connector-access-control' ) . '</p>';

		if ( Caps::user_can_manage() ) {
			echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
			echo '<input type="hidden" name="action" value="' . esc_attr( self::ACTION_SAVE ) . '" />';
			echo '<input type="hidden" name="' . esc_attr( self::POST_PRESENT ) . '" value="1" />';
			wp_nonce_field( self::ACTION_SAVE );
			echo '<p><label for="' . esc_attr( self::POST_DAYS ) . '">' . esc_html__( 'Unused window', 'handl-ai-connector-access-control' ) . '</label> ';
			echo '<select name="' . esc_attr( self::POST_DAYS ) . '" id="' . esc_attr( self::POST_DAYS ) . '">';
			foreach ( self::DAY_OPTIONS as $option ) {
				printf(
					'<option value="%1$d"%2$s>%3$s</option>',
					(int) $option,
					selected( $days, $option, false ),
					esc_html(
						sprintf(
							/* translators: %d: number of days */
							__( '%d days', 'handl-ai-connector-access-control' ),
							(int) $option
						)
					)
				);
			}
			echo '</select> ';
			submit_button( __( 'Update window', 'handl-ai-connector-access-control' ), 'secondary', 'submit', false );
			echo '</p></form>';
		} else {
			echo '<p>' . esc_html(
				sprintf(
					/* translators: %d: number of days */
					__( 'Unused window: %d days.', 'handl-ai-connector-access-control' ),
					$days
				)
			) . '</p>';
		}

		echo '<ul class="ul-disc">';
		echo '<li><strong>' . esc_html__( 'WALLFLOWER', 'handl-ai-connector-access-control' ) . '</strong> — ' . esc_html__( 'Capable, no calls in the window, no deny rule.', 'handl-ai-connector-access-control' ) . '</li>';
		echo '<li><strong>' . esc_html__( 'COVERED', 'handl-ai-connector-access-control' ) . '</strong> — ' . esc_html__( 'Capable and already denied.', 'handl-ai-connector-access-control' ) . '</li>';
		echo '<li><strong>' . esc_html__( 'ACTIVE', 'handl-ai-connector-access-control' ) . '</strong> — ' . esc_html__( 'Capable with AI calls in the window.', 'handl-ai-connector-access-control' ) . '</li>';
		echo '<li><strong>' . esc_html__( 'INSUFFICIENT-DATA', 'handl-ai-connector-access-control' ) . '</strong> — ' . esc_html__( 'Seen in activity or rules, but preflight never ran for it.', 'handl-ai-connector-access-control' ) . '</li>';
		echo '</ul>';

		if ( ! empty( $snap['empty_preflight'] ) && array() === $snap['rows'] ) {
			$scan_url = class_exists( Admin::class, false )
				? Admin::screen_url( 'dashboard' )
				: admin_url( 'admin.php?page=handl-aicac' );
			echo '<p><strong>' . esc_html__( 'No preflight findings yet.', 'handl-ai-connector-access-control' ) . '</strong> ';
			echo esc_html__( 'Run Scan All so Wallflower can compare capability against usage.', 'handl-ai-connector-access-control' );
			echo ' <a href="' . esc_url( $scan_url ) . '">' . esc_html__( 'Open Scan All', 'handl-ai-connector-access-control' ) . '</a></p>';
			echo '</div>';

			return;
		}

		echo '<table class="widefat striped"><thead><tr>';
		echo '<th>' . esc_html__( 'Plugin', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Providers', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Days since last AI call', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Rule', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Flag', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Suggestion', 'handl-ai-connector-access-control' ) . '</th>';
		echo '</tr></thead><tbody>';

		foreach ( $snap['rows'] as $row ) {
			$providers = isset( $row['providers'] ) && is_array( $row['providers'] ) ? $row['providers'] : array();
			$days_label = null === ( $row['days_since'] ?? null )
				? __( 'never', 'handl-ai-connector-access-control' )
				: (string) (int) $row['days_since'];
			echo '<tr>';
			echo '<td>' . esc_html( (string) $row['plugin'] ) . '</td>';
			echo '<td>' . esc_html( array() === $providers ? '—' : implode( ', ', $providers ) ) . '</td>';
			echo '<td>' . esc_html( $days_label ) . '</td>';
			echo '<td>' . esc_html( (string) $row['rule'] ) . '</td>';
			echo '<td><strong>' . esc_html( (string) $row['flag'] ) . '</strong></td>';
			echo '<td>' . esc_html( (string) $row['suggestion'] ) . '</td>';
			echo '</tr>';
		}

		echo '</tbody></table>';
		echo '</div>';
	}
}
