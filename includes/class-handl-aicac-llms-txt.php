<?php
/**
 * AICAC-LLMS-TXT (#337): opt-in /llms.txt from live AICAC policy.
 *
 * One source of truth: outgoing gate settings + robots.txt crawler
 * allow/deny, served as llmstxt.org plain text. Off by default.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Pretty-permalink front door for generated llms.txt.
 */
final class Llms_Txt {

	public const QUERY_VAR = 'handl_aicac_llms_txt';

	public const PATH = '/llms.txt';

	public const POLICY_KEY = 'llms_txt';

	public const POST_PRESENT = 'handl_aicac_llms_txt_present';

	public const POST_ENABLED = 'handl_aicac_llms_txt';

	public const CACHE_TRANSIENT = 'handl_aicac_llms_txt_body';

	public const CACHE_MAX_AGE = 3600;

	public const FILTER_SECTIONS = 'handl_aicac_llms_txt_sections';

	public const SETTINGS_TITLE = 'llms.txt for AI systems';

	public const SETTINGS_TOGGLE = 'Publish /llms.txt from this policy';

	public const SETTINGS_HELP = 'Off by default. When on, AI crawlers can read the same allow/deny posture you already manage here — no second file to keep in sync.';

	public const SETTINGS_PREVIEW = 'Preview (exact bytes served)';

	/** @var self|null */
	private static $instance = null;

	public static function instance(): self {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}

		return self::$instance;
	}

	public static function reset_for_tests(): void {
		self::$instance = null;
		delete_transient( self::CACHE_TRANSIENT );
	}

	public function init(): void {
		add_action( 'init', array( $this, 'register_rewrite' ) );
		add_filter( 'query_vars', array( $this, 'query_vars' ) );
		add_action( 'template_redirect', array( $this, 'maybe_serve' ), 0 );
		add_action( 'update_option_' . Plugin::OPTION_KEY, array( $this, 'on_policy_updated' ), 10, 2 );
		add_action( 'handl_aicac_protections_settings', array( $this, 'render_settings' ) );
		add_filter( 'pre_update_option_' . Plugin::OPTION_KEY, array( self::class, 'merge_on_policy_save' ), 10, 2 );
		if ( defined( 'HANDL_AICAC_FILE' ) && function_exists( 'register_deactivation_hook' ) ) {
			register_deactivation_hook( HANDL_AICAC_FILE, array( self::class, 'on_deactivate' ) );
		}
	}

	public function register_rewrite(): void {
		if ( ! function_exists( 'add_rewrite_rule' ) ) {
			return;
		}
		add_rewrite_rule( '^llms\.txt$', 'index.php?' . self::QUERY_VAR . '=1', 'top' );
	}

	/**
	 * @param mixed $vars Query vars.
	 * @return array<int|string,mixed>
	 */
	public function query_vars( $vars ) {
		if ( ! is_array( $vars ) ) {
			$vars = array();
		}
		$vars[] = self::QUERY_VAR;

		return $vars;
	}

	/**
	 * Default OFF when the policy key is absent.
	 *
	 * @param array<string,mixed> $policy
	 */
	public static function is_enabled( array $policy ): bool {
		return ! empty( $policy[ self::POLICY_KEY ] );
	}

	/**
	 * @param mixed $value New option value.
	 * @param mixed $old   Previous option value.
	 * @return mixed
	 */
	public static function merge_on_policy_save( $value, $old ) {
		if ( ! is_array( $value ) ) {
			return $value;
		}

		$posted = isset( $_POST[ self::POST_PRESENT ] ); // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Admin save already verified the form nonce.
		if ( $posted ) {
			$value[ self::POLICY_KEY ] = ! empty( $_POST[ self::POST_ENABLED ] ); // phpcs:ignore WordPress.Security.NonceVerification.Missing

			return $value;
		}

		if ( is_array( $old ) && array_key_exists( self::POLICY_KEY, $old ) ) {
			$value[ self::POLICY_KEY ] = ! empty( $old[ self::POLICY_KEY ] );
		}

		return $value;
	}

	/**
	 * @param mixed $old Previous option.
	 * @param mixed $value New option.
	 */
	public function on_policy_updated( $old, $value ): void {
		self::invalidate_cache();

		$old_on = self::is_enabled( is_array( $old ) ? $old : array() );
		$new_on = self::is_enabled( is_array( $value ) ? $value : array() );
		if ( $old_on === $new_on ) {
			return;
		}
		if ( function_exists( 'flush_rewrite_rules' ) ) {
			flush_rewrite_rules( false );
		}
	}

	public static function invalidate_cache(): void {
		delete_transient( self::CACHE_TRANSIENT );
	}

	/**
	 * Drop rewrite residue and body cache on deactivate.
	 */
	public static function on_deactivate(): void {
		self::invalidate_cache();
		if ( function_exists( 'flush_rewrite_rules' ) ) {
			flush_rewrite_rules( false );
		}
	}

	public static function public_url(): string {
		if ( function_exists( 'home_url' ) ) {
			return home_url( self::PATH );
		}

		return self::PATH;
	}

	/**
	 * @return array<string,string>
	 */
	public static function cache_headers(): array {
		return array(
			'Content-Type'  => 'text/plain; charset=UTF-8',
			'Cache-Control' => 'public, max-age=' . self::CACHE_MAX_AGE,
		);
	}

	public static function is_requested(): bool {
		if ( function_exists( 'get_query_var' ) && (string) get_query_var( self::QUERY_VAR ) === '1' ) {
			return true;
		}

		return false;
	}

	/**
	 * Build the plain-text body from live policy + robots crawler state.
	 *
	 * @param array<string,mixed>|null $policy
	 * @param string|null              $robots_text Injected robots.txt for tests.
	 */
	public static function build_body( ?array $policy = null, ?string $robots_text = null ): string {
		if ( null === $policy ) {
			$policy = class_exists( Policy::class ) ? Policy::get_policy() : array();
		}
		$policy = is_array( $policy ) ? $policy : array();

		$site = function_exists( 'get_bloginfo' ) ? (string) get_bloginfo( 'name' ) : 'Site';
		if ( '' === trim( $site ) ) {
			$site = 'Site';
		}

		$default = ( ( $policy['default'] ?? 'allow' ) === 'deny' ) ? 'Deny' : 'Allow';
		$mode    = ! empty( $policy['audit_only'] ) ? 'Learn (observe only)' : 'Enforce';
		$freeze  = ( class_exists( Freeze::class ) && Freeze::is_active() ) ? 'On' : 'Off';
		$demo    = ( class_exists( Demo_Mode::class ) && Demo_Mode::is_active() ) ? 'On' : 'Off';

		$allow = 0;
		$deny  = 0;
		$plugins = isset( $policy['plugins'] ) && is_array( $policy['plugins'] ) ? $policy['plugins'] : array();
		foreach ( $plugins as $rule ) {
			if ( 'deny' === $rule ) {
				++$deny;
			} elseif ( 'allow' === $rule ) {
				++$allow;
			}
		}

		$policy_lines = array(
			'- Default for unknown plugins: ' . $default,
			'- Mode: ' . $mode,
			'- Panic freeze: ' . $freeze,
			'- Explicit allow rules: ' . (string) $allow,
			'- Explicit deny rules: ' . (string) $deny,
			'- Demo mode: ' . $demo,
		);

		$crawler_lines = self::crawler_lines( $robots_text );

		$sections = array(
			'Outgoing AI access' => $policy_lines,
			'AI crawlers'        => $crawler_lines,
			'Optional'           => array(
				'- Generated by HandL AI Connector Access Control from the live site policy.',
				'- Public URL: ' . self::public_url(),
			),
		);

		/**
		 * Filter llms.txt sections before render.
		 *
		 * @param array<string,list<string>> $sections Section title => bullet lines.
		 * @param array<string,mixed>        $policy   Live policy.
		 */
		$filtered = apply_filters( self::FILTER_SECTIONS, $sections, $policy );
		if ( is_array( $filtered ) ) {
			$sections = $filtered;
		}

		$out   = array();
		$out[] = '# ' . self::one_line( $site );
		$out[] = '';
		$out[] = '> This site gates outgoing AI API calls with HandL AI Connector Access Control. Crawler preferences below mirror live robots.txt.';
		$out[] = '';

		foreach ( $sections as $title => $lines ) {
			if ( ! is_string( $title ) || '' === $title || ! is_array( $lines ) ) {
				continue;
			}
			$out[] = '## ' . self::one_line( $title );
			foreach ( $lines as $line ) {
				if ( ! is_string( $line ) || '' === $line ) {
					continue;
				}
				$out[] = self::one_line( $line );
			}
			$out[] = '';
		}

		return rtrim( implode( "\n", $out ) ) . "\n";
	}

	/**
	 * @param string|null $robots_text Injected robots.txt body.
	 * @return list<string>
	 */
	public static function crawler_lines( ?string $robots_text = null ): array {
		$known  = class_exists( Switch_Import::class ) ? Switch_Import::known_agents() : array();
		$text   = self::robots_source( $robots_text );
		$parsed = class_exists( Switch_Import::class )
			? Switch_Import::parse_robots( $text )
			: array( 'mapped' => array() );

		$mapped = array();
		$rows   = isset( $parsed['mapped'] ) && is_array( $parsed['mapped'] ) ? $parsed['mapped'] : array();
		foreach ( $rows as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$agent = isset( $row['agent'] ) ? (string) $row['agent'] : '';
			if ( '' === $agent ) {
				continue;
			}
			$mapped[ strtolower( $agent ) ] = ! empty( $row['disallow'] );
		}

		$lines = array();
		foreach ( $known as $agent => $label ) {
			$lc     = strtolower( (string) $agent );
			$state  = array_key_exists( $lc, $mapped )
				? ( $mapped[ $lc ] ? 'Disallow' : 'Allow' )
				: 'Allow (not listed in robots.txt)';
			$lines[] = '- ' . $agent . ' (' . $label . '): ' . $state;
		}

		if ( empty( $lines ) ) {
			$lines[] = '- No known AI crawler list available.';
		}

		return $lines;
	}

	/**
	 * @param array<string,mixed>|null $policy
	 * @param string|null              $robots_text
	 * @return array{status:int,body:string,headers:array<string,string>}
	 */
	public static function respond( ?array $policy = null, ?string $robots_text = null ): array {
		if ( null === $policy ) {
			$policy = class_exists( Policy::class ) ? Policy::get_policy() : array();
		}
		$policy = is_array( $policy ) ? $policy : array();

		if ( ! self::is_enabled( $policy ) ) {
			return array(
				'status'  => 404,
				'body'    => '',
				'headers' => array(
					'Cache-Control' => 'private, max-age=0',
				),
			);
		}

		$fingerprint = self::fingerprint( $policy, $robots_text );
		$cached      = get_transient( self::CACHE_TRANSIENT );
		if ( is_array( $cached )
			&& isset( $cached['fingerprint'], $cached['body'] )
			&& (string) $cached['fingerprint'] === $fingerprint
			&& is_string( $cached['body'] )
		) {
			$body = $cached['body'];
		} else {
			$body = self::build_body( $policy, $robots_text );
			set_transient(
				self::CACHE_TRANSIENT,
				array(
					'fingerprint' => $fingerprint,
					'body'        => $body,
				),
				self::CACHE_MAX_AGE
			);
		}

		return array(
			'status'  => 200,
			'body'    => $body,
			'headers' => self::cache_headers(),
		);
	}

	/**
	 * @param array<string,mixed> $policy
	 * @param string|null         $robots_text
	 */
	public static function fingerprint( array $policy, ?string $robots_text = null ): string {
		$text    = self::robots_source( $robots_text );
		$payload = array(
			'default'    => ( $policy['default'] ?? 'allow' ) === 'deny' ? 'deny' : 'allow',
			'audit_only' => ! empty( $policy['audit_only'] ),
			'plugins'    => isset( $policy['plugins'] ) && is_array( $policy['plugins'] ) ? $policy['plugins'] : array(),
			'llms_txt'   => ! empty( $policy[ self::POLICY_KEY ] ),
			'freeze'     => class_exists( Freeze::class ) && Freeze::is_active(),
			'demo'       => class_exists( Demo_Mode::class ) && Demo_Mode::is_active(),
			'robots'     => is_string( $text ) ? $text : '',
			'blog'       => function_exists( 'get_current_blog_id' ) ? (int) get_current_blog_id() : 1,
		);

		return md5( (string) wp_json_encode( $payload ) );
	}

	public function maybe_serve(): void {
		if ( ! self::is_requested() ) {
			return;
		}
		$out = self::respond();
		self::emit( $out );
	}

	/**
	 * @param array{status:int,body:string,headers:array<string,string>} $out
	 */
	public static function emit( array $out ): void {
		if ( function_exists( 'status_header' ) ) {
			status_header( (int) $out['status'] );
		}
		$phpunit = defined( 'HANDL_AICAC_PHPUNIT' ) && HANDL_AICAC_PHPUNIT;
		if ( ! $phpunit && isset( $out['headers'] ) && is_array( $out['headers'] ) ) {
			foreach ( $out['headers'] as $name => $value ) {
				header( $name . ': ' . $value );
			}
		}
		if ( $phpunit ) {
			$GLOBALS['handl_aicac_test_llms_txt_emitted'] = $out;
			return;
		}
		echo (string) ( $out['body'] ?? '' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- text/plain body.
		exit;
	}

	/**
	 * Admin toggle + live preview (exact bytes that will be served).
	 *
	 * @param array<string,mixed> $policy
	 */
	public function render_settings( $policy ): void {
		$policy  = is_array( $policy ) ? $policy : array();
		$enabled = self::is_enabled( $policy );
		$preview = self::build_body( $policy );

		echo '<tr>';
		echo '<th scope="row">' . esc_html__( 'llms.txt for AI systems', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<td>';
		echo '<input type="hidden" name="' . esc_attr( self::POST_PRESENT ) . '" value="1" />';
		echo '<label for="handl-aicac-llms-txt">';
		echo '<input type="checkbox" name="' . esc_attr( self::POST_ENABLED ) . '" id="handl-aicac-llms-txt" value="1"' . ( $enabled ? ' checked="checked"' : '' ) . ' /> ';
		echo esc_html__( 'Publish /llms.txt from this policy', 'handl-ai-connector-access-control' );
		echo '</label>';
		echo '<p class="description">' . esc_html__( 'Off by default. When on, AI crawlers can read the same allow/deny posture you already manage here — no second file to keep in sync.', 'handl-ai-connector-access-control' ) . '</p>';
		if ( $enabled ) {
			echo '<p class="description"><a href="' . esc_url( self::public_url() ) . '" target="_blank" rel="noopener noreferrer">' . esc_html( self::public_url() ) . '</a></p>';
		}
		echo '<p><label for="handl-aicac-llms-txt-preview">' . esc_html__( 'Preview (exact bytes served)', 'handl-ai-connector-access-control' ) . '</label></p>';
		echo '<textarea id="handl-aicac-llms-txt-preview" class="large-text code" rows="12" readonly="readonly">';
		echo function_exists( 'esc_textarea' ) ? esc_textarea( $preview ) : htmlspecialchars( $preview, ENT_QUOTES, 'UTF-8' );
		echo '</textarea>';
		echo '</td>';
		echo '</tr>';
	}

	/**
	 * Collapse newlines for a single llmstxt.org line.
	 */
	private static function one_line( string $text ): string {
		$flat = preg_replace( '/\s+/', ' ', $text );
		return is_string( $flat ) ? trim( $flat ) : trim( $text );
	}

	/**
	 * Live robots.txt body, or an injected string for tests.
	 */
	private static function robots_source( ?string $robots_text ): string {
		if ( null !== $robots_text ) {
			return $robots_text;
		}
		if ( class_exists( Switch_Import::class ) && function_exists( 'trailingslashit' ) ) {
			$raw = Switch_Import::read_site_robots();

			return is_string( $raw ) ? $raw : '';
		}

		return '';
	}
}
