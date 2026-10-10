<?php
/**
 * AICAC-SWITCH-IMPORT (#330): import robots.txt / competitor AI-block config
 * into a DRAFT AICAC policy for review (never auto-applies).
 *
 * Distinct from Policy_Transfer (own-format JSON) and Presets/Policy_Packs
 * (generic templates): this reads third-party site config.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * One-click switch importer: robots.txt + Block AI Crawlers → draft policy.
 */
final class Switch_Import {

	public const ACTION_SCAN   = 'handl_aicac_switch_scan';
	public const ACTION_APPLY  = 'handl_aicac_switch_apply';
	public const ACTION_CANCEL = 'handl_aicac_switch_cancel';

	public const PREVIEW_TTL = 900;

	public const COMPETITOR_BLOCK_AI_CRAWLERS = 'block-ai-crawlers/block-ai-crawlers.php';

	public const COMPETITOR_OPTION_DISABLED = 'block_ai_crawlers_disabled';

	public const COMPETITOR_OPTION_CUSTOM = 'block_ai_crawlers_custom_robots_txt';

	/** @var self|null */
	private static $instance = null;

	/**
	 * Documented AI crawler user-agents → short label.
	 * Keys are matched case-insensitively against robots.txt User-agent lines.
	 *
	 * @return array<string,string>
	 */
	public static function known_agents(): array {
		return array(
			'GPTBot'              => 'OpenAI training crawler',
			'ChatGPT-User'        => 'OpenAI user-triggered fetch',
			'OAI-SearchBot'       => 'OpenAI search crawler',
			'Google-Extended'     => 'Google Gemini / AI training',
			'ClaudeBot'           => 'Anthropic Claude crawler',
			'anthropic-ai'        => 'Anthropic legacy crawler',
			'CCBot'               => 'Common Crawl',
			'Bytespider'          => 'ByteDance crawler',
			'cohere-ai'           => 'Cohere crawler',
			'Diffbot'             => 'Diffbot crawler',
			'PerplexityBot'       => 'Perplexity crawler',
			'Amazonbot'           => 'Amazon crawler',
			'meta-externalagent'  => 'Meta AI training crawler',
			'Applebot-Extended'   => 'Apple AI training crawler',
			'FacebookBot'         => 'Meta FacebookBot',
		);
	}

	public static function instance(): self {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}

		return self::$instance;
	}

	public function init(): void {
		add_action( 'admin_post_' . self::ACTION_SCAN, array( $this, 'handle_scan' ) );
		add_action( 'admin_post_' . self::ACTION_APPLY, array( $this, 'handle_apply' ) );
		add_action( 'admin_post_' . self::ACTION_CANCEL, array( $this, 'handle_cancel' ) );
	}

	public static function reset_for_tests(): void {
		self::$instance = null;
		$user_id        = function_exists( 'get_current_user_id' ) ? (int) get_current_user_id() : 0;
		if ( $user_id > 0 ) {
			delete_transient( self::preview_transient_key( $user_id ) );
		}
	}

	public static function preview_transient_key( int $user_id ): string {
		return 'handl_aicac_switch_' . max( 0, $user_id );
	}

	public static function user_can_manage(): bool {
		return class_exists( Caps::class, false )
			? Caps::user_can_manage()
			: current_user_can( 'manage_options' );
	}

	/**
	 * Read physical robots.txt, else WordPress virtual robots_txt filter output.
	 */
	public static function read_site_robots(): string {
		$path = trailingslashit( ABSPATH ) . 'robots.txt';
		if ( is_readable( $path ) ) {
			$raw = file_get_contents( $path );
			if ( is_string( $raw ) && '' !== trim( $raw ) ) {
				return $raw;
			}
		}

		$public = ( '1' === (string) get_option( 'blog_public', '1' ) );
		$out    = apply_filters( 'robots_txt', "User-agent: *\nDisallow:\n", $public );

		return is_string( $out ) ? $out : '';
	}

	/**
	 * Parse robots.txt into mapped / unmapped agent decisions.
	 *
	 * @return array{
	 *   mapped: list<array{agent:string,label:string,disallow:bool}>,
	 *   unmapped: list<array{agent:string,disallow:bool}>,
	 *   blocked_count: int
	 * }
	 */
	public static function parse_robots( string $text ): array {
		$known_lc = array();
		foreach ( self::known_agents() as $agent => $label ) {
			$known_lc[ strtolower( $agent ) ] = array(
				'agent' => $agent,
				'label' => $label,
			);
		}

		$groups   = self::robots_groups( $text );
		$mapped   = array();
		$unmapped = array();
		$seen     = array();

		foreach ( $groups as $group ) {
			$agents   = $group['agents'];
			$disallow = $group['disallow_root'];
			foreach ( $agents as $raw_agent ) {
				$lc = strtolower( $raw_agent );
				if ( '*' === $lc || '' === $lc ) {
					continue;
				}
				if ( isset( $seen[ $lc ] ) ) {
					// Prefer a disallow if any group sets it.
					if ( $disallow && ! $seen[ $lc ]['disallow'] ) {
						$seen[ $lc ]['disallow'] = true;
					}
					continue;
				}
				if ( isset( $known_lc[ $lc ] ) ) {
					$seen[ $lc ] = array(
						'kind'     => 'mapped',
						'agent'    => $known_lc[ $lc ]['agent'],
						'label'    => $known_lc[ $lc ]['label'],
						'disallow' => $disallow,
					);
				} else {
					$seen[ $lc ] = array(
						'kind'     => 'unmapped',
						'agent'    => $raw_agent,
						'disallow' => $disallow,
					);
				}
			}
		}

		$blocked = 0;
		foreach ( $seen as $row ) {
			if ( 'mapped' === $row['kind'] ) {
				$mapped[] = array(
					'agent'    => (string) $row['agent'],
					'label'    => (string) $row['label'],
					'disallow' => ! empty( $row['disallow'] ),
				);
				if ( ! empty( $row['disallow'] ) ) {
					++$blocked;
				}
			} else {
				$unmapped[] = array(
					'agent'    => (string) $row['agent'],
					'disallow' => ! empty( $row['disallow'] ),
				);
			}
		}

		usort(
			$mapped,
			static function ( array $a, array $b ): int {
				return strcasecmp( $a['agent'], $b['agent'] );
			}
		);
		usort(
			$unmapped,
			static function ( array $a, array $b ): int {
				return strcasecmp( $a['agent'], $b['agent'] );
			}
		);

		return array(
			'mapped'        => $mapped,
			'unmapped'      => $unmapped,
			'blocked_count' => $blocked,
		);
	}

	/**
	 * @return list<array{agents:list<string>,disallow_root:bool}>
	 */
	private static function robots_groups( string $text ): array {
		$lines  = preg_split( '/\R/', $text ) ?: array();
		$groups = array();
		$agents = array();
		$rules  = array();

		$flush = static function () use ( &$groups, &$agents, &$rules ): void {
			if ( empty( $agents ) ) {
				$agents = array();
				$rules  = array();
				return;
			}
			$disallow_root = false;
			foreach ( $rules as $rule ) {
				if ( 'disallow' === $rule['type'] && ( '/' === $rule['path'] || '' === $rule['path'] ) ) {
					$disallow_root = true;
					break;
				}
			}
			$groups[] = array(
				'agents'        => $agents,
				'disallow_root' => $disallow_root,
			);
			$agents = array();
			$rules  = array();
		};

		foreach ( $lines as $line ) {
			$line = trim( (string) $line );
			if ( '' === $line || '#' === $line[0] ) {
				continue;
			}
			if ( ! preg_match( '/^([A-Za-z-]+)\s*:\s*(.*)$/', $line, $m ) ) {
				continue;
			}
			$directive = strtolower( $m[1] );
			$value     = trim( $m[2] );

			if ( 'user-agent' === $directive ) {
				if ( ! empty( $rules ) ) {
					$flush();
				}
				if ( '' !== $value ) {
					$agents[] = $value;
				}
				continue;
			}

			if ( empty( $agents ) ) {
				continue;
			}

			if ( 'disallow' === $directive || 'allow' === $directive ) {
				$rules[] = array(
					'type' => $directive,
					'path' => $value,
				);
			}
		}
		$flush();

		return $groups;
	}

	/**
	 * Detect Block AI Crawlers and map its settings into agent decisions.
	 *
	 * @param list<string>|null $active_plugins Plugin basenames (injectable).
	 * @return array{
	 *   id:string,
	 *   label:string,
	 *   active:bool,
	 *   found:bool,
	 *   blocked_agents:list<string>,
	 *   note:string
	 * }
	 */
	public static function detect_block_ai_crawlers( ?array $active_plugins = null ): array {
		$empty = array(
			'id'             => 'block-ai-crawlers',
			'label'          => 'Block AI Crawlers',
			'active'         => false,
			'found'          => false,
			'blocked_agents' => array(),
			'note'           => '',
		);

		if ( null === $active_plugins ) {
			$raw             = get_option( 'active_plugins', array() );
			$active_plugins  = is_array( $raw ) ? $raw : array();
			if ( is_multisite() ) {
				$network = get_site_option( 'active_sitewide_plugins', array() );
				if ( is_array( $network ) ) {
					$active_plugins = array_values( array_unique( array_merge( $active_plugins, array_keys( $network ) ) ) );
				}
			}
		}

		$active = in_array( self::COMPETITOR_BLOCK_AI_CRAWLERS, $active_plugins, true );
		if ( ! $active ) {
			$empty['note'] = 'not_installed';
			return $empty;
		}

		$disabled = get_option( self::COMPETITOR_OPTION_DISABLED, array() );
		if ( ! is_array( $disabled ) ) {
			$disabled = array();
		}
		$disabled_lc = array();
		foreach ( $disabled as $agent ) {
			$disabled_lc[ strtolower( (string) $agent ) ] = true;
		}

		$blocked = array();
		foreach ( array_keys( self::known_agents() ) as $agent ) {
			if ( ! isset( $disabled_lc[ strtolower( $agent ) ] ) ) {
				$blocked[] = $agent;
			}
		}

		$custom = get_option( self::COMPETITOR_OPTION_CUSTOM, '' );
		if ( is_string( $custom ) && '' !== trim( $custom ) ) {
			$parsed = self::parse_robots( $custom );
			foreach ( $parsed['mapped'] as $row ) {
				if ( ! empty( $row['disallow'] ) && ! in_array( $row['agent'], $blocked, true ) ) {
					$blocked[] = $row['agent'];
				}
			}
		}

		sort( $blocked, SORT_STRING );

		return array(
			'id'             => 'block-ai-crawlers',
			'label'          => 'Block AI Crawlers',
			'active'         => true,
			'found'          => ! empty( $blocked ),
			'blocked_agents' => $blocked,
			'note'           => empty( $blocked ) ? 'nothing_to_import' : 'mapped',
		);
	}

	/**
	 * Build a draft policy patch from scan findings (no save).
	 *
	 * @param array<string,mixed> $robots_parse parse_robots() result.
	 * @param array<string,mixed> $competitor   detect_block_ai_crawlers() result.
	 * @return array{
	 *   has_import:bool,
	 *   patch:array<string,mixed>,
	 *   sources:list<string>,
	 *   mapped:list<array{agent:string,label:string,disallow:bool}>,
	 *   unmapped:list<array{agent:string,disallow:bool}>,
	 *   competitor:array<string,mixed>
	 * }
	 */
	public static function build_draft( array $robots_parse, array $competitor ): array {
		$mapped   = isset( $robots_parse['mapped'] ) && is_array( $robots_parse['mapped'] ) ? $robots_parse['mapped'] : array();
		$unmapped = isset( $robots_parse['unmapped'] ) && is_array( $robots_parse['unmapped'] ) ? $robots_parse['unmapped'] : array();
		$blocked  = (int) ( $robots_parse['blocked_count'] ?? 0 );

		$sources = array();
		if ( $blocked > 0 ) {
			$sources[] = 'robots.txt';
		}

		$comp_blocked = isset( $competitor['blocked_agents'] ) && is_array( $competitor['blocked_agents'] )
			? $competitor['blocked_agents']
			: array();
		if ( ! empty( $competitor['active'] ) && ! empty( $competitor['found'] ) ) {
			$sources[] = 'block-ai-crawlers';
			// Merge competitor-blocked known agents into mapped disallow list for display.
			$by_agent = array();
			foreach ( $mapped as $row ) {
				if ( is_array( $row ) ) {
					$by_agent[ (string) $row['agent'] ] = $row;
				}
			}
			$known = self::known_agents();
			foreach ( $comp_blocked as $agent ) {
				$agent = (string) $agent;
				if ( ! isset( $known[ $agent ] ) ) {
					continue;
				}
				if ( ! isset( $by_agent[ $agent ] ) ) {
					$by_agent[ $agent ] = array(
						'agent'    => $agent,
						'label'    => $known[ $agent ],
						'disallow' => true,
					);
				} else {
					$by_agent[ $agent ]['disallow'] = true;
				}
			}
			$mapped = array_values( $by_agent );
			usort(
				$mapped,
				static function ( array $a, array $b ): int {
					return strcasecmp( $a['agent'], $b['agent'] );
				}
			);
			$blocked = 0;
			foreach ( $mapped as $row ) {
				if ( ! empty( $row['disallow'] ) ) {
					++$blocked;
				}
			}
		}

		$has = $blocked > 0;
		// Privacy-first draft: govern outbound AI + show public disclosure.
		$patch = $has
			? array(
				'default'              => 'allow',
				'audit_only'           => false,
				'log_enabled'          => true,
				'kill_switch'          => false,
				'shadow_block_enabled' => true,
				'unknown_operation'    => 'deny',
				'alert_on_deny'        => true,
				'alert_on_shadow'      => true,
				'alert_mode'           => 'queue',
				'disclosure_privacy'   => true,
			)
			: array();

		return array(
			'has_import' => $has,
			'patch'      => $patch,
			'sources'    => $sources,
			'mapped'     => $mapped,
			'unmapped'   => $unmapped,
			'competitor' => $competitor,
		);
	}

	/**
	 * Scan site sources into a draft stored in a per-user transient.
	 *
	 * @param string|null          $robots_text Injected robots.txt body.
	 * @param list<string>|null    $active_plugins
	 * @return array{ok:bool,status:string,draft?:array<string,mixed>}
	 */
	public static function scan( ?string $robots_text = null, ?array $active_plugins = null ): array {
		$text       = null !== $robots_text ? $robots_text : self::read_site_robots();
		$robots     = self::parse_robots( $text );
		$competitor = self::detect_block_ai_crawlers( $active_plugins );
		$draft      = self::build_draft( $robots, $competitor );

		return array(
			'ok'     => true,
			'status' => ! empty( $draft['has_import'] ) ? 'draft' : 'empty',
			'draft'  => $draft,
		);
	}

	/**
	 * Merge draft patch into current policy (no save).
	 *
	 * @param array<string,mixed> $current
	 * @param array<string,mixed> $patch
	 * @return array<string,mixed>
	 */
	public static function build_target( array $current, array $patch ): array {
		$target = $current;
		foreach ( $patch as $key => $value ) {
			$target[ (string) $key ] = $value;
		}
		if ( ! empty( $target['audit_only'] ) ) {
			$target['log_enabled'] = true;
		}

		return $target;
	}

	/**
	 * Human-readable rows for the review screen.
	 *
	 * @param array<string,mixed> $current
	 * @param array<string,mixed> $patch
	 * @return list<array{key:string,label:string,current:string,new:string}>
	 */
	public static function diff_rows( array $current, array $patch ): array {
		$rows = array();
		foreach ( $patch as $key => $new_val ) {
			$key     = (string) $key;
			$cur_val = $current[ $key ] ?? null;
			if ( self::values_equal( $key, $cur_val, $new_val ) ) {
				continue;
			}
			$rows[] = array(
				'key'     => $key,
				'label'   => self::field_label( $key ),
				'current' => self::format_value( $key, $cur_val ),
				'new'     => self::format_value( $key, $new_val ),
			);
		}

		return $rows;
	}

	/**
	 * Apply a stored draft via Policy::save_policy.
	 *
	 * @param array<string,mixed> $current
	 * @param array<string,mixed> $draft
	 * @return array{ok:bool,status:string,error?:string}
	 */
	public static function apply( array $current, array $draft ): array {
		if ( empty( $draft['has_import'] ) || empty( $draft['patch'] ) || ! is_array( $draft['patch'] ) ) {
			return array(
				'ok'     => false,
				'status' => 'error',
				'error'  => 'empty_draft',
			);
		}
		$patch  = $draft['patch'];
		$target = self::build_target( $current, $patch );
		Policy::save_policy( $target );

		// Disclosure::merge_on_policy_save keeps prior disclosure_* keys unless
		// the disclosure settings form posted. Stamp privacy when the draft asks.
		if ( ! empty( $patch['disclosure_privacy'] ) && class_exists( Disclosure::class, false ) ) {
			$stored = get_option( Plugin::OPTION_KEY, array() );
			if ( is_array( $stored ) ) {
				$stored[ Disclosure::POLICY_PRIVACY_KEY ] = true;
				update_option( Plugin::OPTION_KEY, $stored, false );
			}
		}

		return array(
			'ok'     => true,
			'status' => 'applied',
		);
	}

	/**
	 * @param mixed $a
	 * @param mixed $b
	 */
	private static function values_equal( string $key, $a, $b ): bool {
		return self::normalize( $key, $a ) === self::normalize( $key, $b );
	}

	/**
	 * @param mixed $raw
	 * @return mixed
	 */
	private static function normalize( string $key, $raw ) {
		switch ( $key ) {
			case 'default':
				return ( 'deny' === $raw ) ? 'deny' : 'allow';
			case 'audit_only':
			case 'log_enabled':
			case 'kill_switch':
			case 'shadow_block_enabled':
			case 'alert_on_deny':
			case 'alert_on_shadow':
			case 'disclosure_privacy':
				return (bool) $raw;
			case 'unknown_operation':
				$v = (string) $raw;
				return in_array( $v, array( 'inherit', 'allow', 'deny' ), true ) ? $v : 'inherit';
			case 'alert_mode':
				return class_exists( Alerts::class, false )
					? Alerts::sanitize_mode( $raw ?? 'immediate' )
					: (string) $raw;
			default:
				return $raw;
		}
	}

	private static function field_label( string $key ): string {
		$labels = array(
			'default'              => __( 'Default access', 'handl-ai-connector-access-control' ),
			'audit_only'           => __( 'Observe only', 'handl-ai-connector-access-control' ),
			'log_enabled'          => __( 'Activity logging', 'handl-ai-connector-access-control' ),
			'kill_switch'          => __( 'Emergency stop', 'handl-ai-connector-access-control' ),
			'shadow_block_enabled' => __( 'Block direct AI connections', 'handl-ai-connector-access-control' ),
			'unknown_operation'    => __( 'Unknown AI types', 'handl-ai-connector-access-control' ),
			'alert_on_deny'        => __( 'Alert on blocked calls', 'handl-ai-connector-access-control' ),
			'alert_on_shadow'      => __( 'Alert on direct connections', 'handl-ai-connector-access-control' ),
			'alert_mode'           => __( 'Alert delivery', 'handl-ai-connector-access-control' ),
			'disclosure_privacy'   => __( 'Public AI disclosure', 'handl-ai-connector-access-control' ),
		);

		return $labels[ $key ] ?? $key;
	}

	/**
	 * @param mixed $raw
	 */
	private static function format_value( string $key, $raw ): string {
		switch ( $key ) {
			case 'default':
				if ( null === $raw || '' === $raw ) {
					return __( 'Not set', 'handl-ai-connector-access-control' );
				}
				return ( 'deny' === $raw )
					? __( 'Deny', 'handl-ai-connector-access-control' )
					: __( 'Allow', 'handl-ai-connector-access-control' );
			case 'unknown_operation':
				if ( null === $raw || '' === $raw ) {
					return __( 'Not set', 'handl-ai-connector-access-control' );
				}
				if ( 'deny' === $raw ) {
					return __( 'Deny', 'handl-ai-connector-access-control' );
				}
				if ( 'allow' === $raw ) {
					return __( 'Allow', 'handl-ai-connector-access-control' );
				}
				return __( 'Inherit', 'handl-ai-connector-access-control' );
			case 'alert_mode':
				if ( null === $raw || '' === $raw ) {
					return __( 'Not set', 'handl-ai-connector-access-control' );
				}
				return ( 'queue' === $raw )
					? __( 'Queued alerts', 'handl-ai-connector-access-control' )
					: __( 'Immediate alerts', 'handl-ai-connector-access-control' );
			case 'audit_only':
			case 'log_enabled':
			case 'kill_switch':
			case 'shadow_block_enabled':
			case 'alert_on_deny':
			case 'alert_on_shadow':
			case 'disclosure_privacy':
				return ! empty( $raw )
					? __( 'On', 'handl-ai-connector-access-control' )
					: __( 'Off', 'handl-ai-connector-access-control' );
			default:
				if ( null === $raw || '' === $raw ) {
					return __( 'Not set', 'handl-ai-connector-access-control' );
				}
				if ( is_bool( $raw ) ) {
					return $raw
						? __( 'On', 'handl-ai-connector-access-control' )
						: __( 'Off', 'handl-ai-connector-access-control' );
				}
				return (string) $raw;
		}
	}

	/**
	 * Policy Tools UI: scan button + optional draft review.
	 *
	 * @param array<string,mixed> $policy
	 */
	public static function render_policy_tools_section( array $policy, bool $show_preview ): void {
		echo '<div id="handl-aicac-switch-import" class="handl-aicac-switch-import" style="margin:0 0 1.5em;">';
		echo '<h2>' . esc_html__( 'Create a policy from existing AI blocks', 'handl-ai-connector-access-control' ) . '</h2>';
		echo '<p class="description">' . esc_html__( 'Scan robots.txt and Block AI Crawlers settings, then review suggested AI Not settings. Nothing changes until you apply. Original files and plugin settings stay unchanged.', 'handl-ai-connector-access-control' ) . '</p>';

		if ( self::user_can_manage() ) {
			echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" style="margin:0 0 1em;">';
			wp_nonce_field( self::ACTION_SCAN );
			echo '<input type="hidden" name="action" value="' . esc_attr( self::ACTION_SCAN ) . '" />';
			submit_button( __( 'Scan robots.txt and Block AI Crawlers', 'handl-ai-connector-access-control' ), 'secondary', 'submit', false );
			echo '</form>';
		}

		if ( ! $show_preview ) {
			echo '</div>';
			return;
		}

		$user_id = get_current_user_id();
		$pending = get_transient( self::preview_transient_key( $user_id ) );
		if ( ! is_array( $pending ) || empty( $pending['draft'] ) || ! is_array( $pending['draft'] ) ) {
			echo '<div class="notice notice-warning inline"><p>' . esc_html__( 'Import preview expired or was not found. Scan again.', 'handl-ai-connector-access-control' ) . '</p></div>';
			echo '</div>';
			return;
		}

		$draft = $pending['draft'];
		self::render_review( $policy, $draft );
		echo '</div>';
	}

	/**
	 * @param array<string,mixed> $policy
	 * @param array<string,mixed> $draft
	 */
	private static function render_review( array $policy, array $draft ): void {
		echo '<div class="handl-aicac-switch-preview" style="border:1px solid #c3c4c7;padding:12px 16px;background:#fff;max-width:52em;margin-top:0.5em;">';
		echo '<h3 class="handl-aicac-autofocus" tabindex="-1">' . esc_html__( 'Import preview', 'handl-ai-connector-access-control' ) . '</h3>';
		echo '<p class="description">' . esc_html__( 'Crawler rules are shown for reference. Applying this draft changes AI Not settings for outgoing AI connections; it does not copy individual crawler rules.', 'handl-ai-connector-access-control' ) . '</p>';

		if ( empty( $draft['has_import'] ) ) {
			echo '<div class="notice notice-info inline"><p>' . esc_html__( 'No supported AI block rules found. Your policy is unchanged.', 'handl-ai-connector-access-control' ) . '</p></div>';
			self::render_cancel_form();
			echo '</div>';
			return;
		}

		$sources = isset( $draft['sources'] ) && is_array( $draft['sources'] ) ? $draft['sources'] : array();
		if ( ! empty( $sources ) ) {
			echo '<p><strong>' . esc_html__( 'Sources', 'handl-ai-connector-access-control' ) . ':</strong> ' . esc_html( implode( ', ', $sources ) ) . '</p>';
		}

		$mapped = isset( $draft['mapped'] ) && is_array( $draft['mapped'] ) ? $draft['mapped'] : array();
		if ( ! empty( $mapped ) ) {
			echo '<h4>' . esc_html__( 'Known AI crawlers', 'handl-ai-connector-access-control' ) . '</h4>';
			echo '<ul style="margin:0.25em 0 1em 1.25em;">';
			foreach ( $mapped as $row ) {
				if ( ! is_array( $row ) ) {
					continue;
				}
				$state = ! empty( $row['disallow'] )
					? __( 'Disallow rule found', 'handl-ai-connector-access-control' )
					: __( 'No site-wide Disallow rule found', 'handl-ai-connector-access-control' );
				echo '<li><code>' . esc_html( (string) ( $row['agent'] ?? '' ) ) . '</code> — ' . esc_html( (string) ( $row['label'] ?? '' ) ) . ' (' . esc_html( $state ) . ')</li>';
			}
			echo '</ul>';
		}

		$unmapped = isset( $draft['unmapped'] ) && is_array( $draft['unmapped'] ) ? $draft['unmapped'] : array();
		if ( ! empty( $unmapped ) ) {
			echo '<h4>' . esc_html__( 'Unrecognized crawlers', 'handl-ai-connector-access-control' ) . '</h4>';
			echo '<p class="description">' . esc_html__( 'These crawlers are not in our AI list. Shown for reference; their rules are not imported.', 'handl-ai-connector-access-control' ) . '</p>';
			echo '<ul style="margin:0.25em 0 1em 1.25em;">';
			foreach ( $unmapped as $row ) {
				if ( ! is_array( $row ) ) {
					continue;
				}
				$state = ! empty( $row['disallow'] )
					? __( 'Disallow rule found', 'handl-ai-connector-access-control' )
					: __( 'No site-wide Disallow rule found', 'handl-ai-connector-access-control' );
				echo '<li><code>' . esc_html( (string) ( $row['agent'] ?? '' ) ) . '</code> (' . esc_html( $state ) . ')</li>';
			}
			echo '</ul>';
		}

		$competitor = isset( $draft['competitor'] ) && is_array( $draft['competitor'] ) ? $draft['competitor'] : array();
		if ( ! empty( $competitor['active'] ) ) {
			echo '<p><strong>' . esc_html( (string) ( $competitor['label'] ?? 'Block AI Crawlers' ) ) . ':</strong> ';
			if ( ! empty( $competitor['found'] ) ) {
				$count = count( isset( $competitor['blocked_agents'] ) && is_array( $competitor['blocked_agents'] ) ? $competitor['blocked_agents'] : array() );
				echo esc_html(
					sprintf(
						/* translators: %d: number of known AI crawlers with Disallow rules */
						__( 'active — Disallow rules found for %d known AI crawlers.', 'handl-ai-connector-access-control' ),
						$count
					)
				);
			} else {
				echo esc_html__( 'active — no supported AI block rules found in its settings.', 'handl-ai-connector-access-control' );
			}
			echo '</p>';
		}

		$patch = isset( $draft['patch'] ) && is_array( $draft['patch'] ) ? $draft['patch'] : array();
		$rows  = self::diff_rows( $policy, $patch );
		echo '<h4>' . esc_html__( 'Suggested AI Not settings', 'handl-ai-connector-access-control' ) . '</h4>';
		if ( empty( $rows ) ) {
			echo '<div class="notice notice-info inline"><p>' . esc_html__( 'Your policy already matches this draft. Applying will not change settings.', 'handl-ai-connector-access-control' ) . '</p></div>';
		} else {
			echo '<table class="widefat striped" style="max-width:40em;"><thead><tr>';
			echo '<th scope="col">' . esc_html__( 'Setting', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th scope="col">' . esc_html__( 'Current', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th scope="col">' . esc_html__( 'After apply', 'handl-ai-connector-access-control' ) . '</th>';
			echo '</tr></thead><tbody>';
			foreach ( $rows as $row ) {
				echo '<tr>';
				echo '<td>' . esc_html( $row['label'] ) . '</td>';
				echo '<td>' . esc_html( $row['current'] ) . '</td>';
				echo '<td>' . esc_html( $row['new'] ) . '</td>';
				echo '</tr>';
			}
			echo '</tbody></table>';
		}

		if ( self::user_can_manage() ) {
			echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" style="display:inline-block;margin:0 8px 0 0;">';
			wp_nonce_field( self::ACTION_APPLY );
			echo '<input type="hidden" name="action" value="' . esc_attr( self::ACTION_APPLY ) . '" />';
			submit_button( __( 'Apply draft policy', 'handl-ai-connector-access-control' ), 'primary', 'submit', false );
			echo '</form>';
			self::render_cancel_form();
		}

		echo '</div>';
	}

	private static function render_cancel_form(): void {
		if ( ! self::user_can_manage() ) {
			return;
		}
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" style="display:inline-block;margin:0;">';
		wp_nonce_field( self::ACTION_CANCEL );
		echo '<input type="hidden" name="action" value="' . esc_attr( self::ACTION_CANCEL ) . '" />';
		submit_button( __( 'Cancel (keep current policy)', 'handl-ai-connector-access-control' ), 'secondary', 'submit', false );
		echo '</form>';
	}

	public function handle_scan(): void {
		if ( ! self::user_can_manage() ) {
			wp_die( esc_html__( 'Sorry, you are not allowed to do that.', 'handl-ai-connector-access-control' ) );
		}
		check_admin_referer( self::ACTION_SCAN );

		$result = self::scan();
		$user_id = get_current_user_id();
		set_transient(
			self::preview_transient_key( $user_id ),
			array(
				'draft' => $result['draft'] ?? array(),
				'ts'    => time(),
			),
			self::PREVIEW_TTL
		);

		wp_safe_redirect(
			Admin::redirect_url(
				array(
					'handl_aicac_tab'           => 'policy-tools',
					'handl_aicac_switch_preview' => '1',
					'handl_aicac_switch'        => (string) ( $result['status'] ?? 'draft' ),
				)
			)
		);
		exit;
	}

	public function handle_apply(): void {
		if ( ! self::user_can_manage() ) {
			wp_die( esc_html__( 'Sorry, you are not allowed to do that.', 'handl-ai-connector-access-control' ) );
		}
		check_admin_referer( self::ACTION_APPLY );

		$user_id = get_current_user_id();
		$pending = get_transient( self::preview_transient_key( $user_id ) );
		$status  = 'error';
		if ( is_array( $pending ) && isset( $pending['draft'] ) && is_array( $pending['draft'] ) ) {
			$result = self::apply( Policy::get_policy(), $pending['draft'] );
			$status = ! empty( $result['ok'] ) ? 'applied' : (string) ( $result['error'] ?? 'error' );
		}
		delete_transient( self::preview_transient_key( $user_id ) );

		wp_safe_redirect(
			Admin::redirect_url(
				array(
					'handl_aicac_tab'    => 'policy-tools',
					'handl_aicac_switch' => $status,
				)
			)
		);
		exit;
	}

	public function handle_cancel(): void {
		if ( ! self::user_can_manage() ) {
			wp_die( esc_html__( 'Sorry, you are not allowed to do that.', 'handl-ai-connector-access-control' ) );
		}
		check_admin_referer( self::ACTION_CANCEL );

		delete_transient( self::preview_transient_key( get_current_user_id() ) );

		wp_safe_redirect(
			Admin::redirect_url(
				array(
					'handl_aicac_tab'    => 'policy-tools',
					'handl_aicac_switch' => 'cancelled',
				)
			)
		);
		exit;
	}
}
