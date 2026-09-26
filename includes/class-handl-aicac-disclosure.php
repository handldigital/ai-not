<?php
/**
 * AICAC-DISCLOSURE (#282): public AI transparency shortcode/block.
 *
 * Reads the live policy and retained activity log. No new collection.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Public visitor-facing disclosure of providers and capability families.
 */
final class Disclosure {

	public const SHORTCODE = 'handl_ai_disclosure';

	public const BLOCK_NAME = 'handl-aicac/disclosure';

	public const POLICY_PRIVACY_KEY = 'disclosure_privacy';

	public const POLICY_DETAIL_KEY = 'disclosure_detail';

	public const POST_PRESENT = 'handl_aicac_disclosure_present';

	public const POST_PRIVACY = 'handl_aicac_disclosure_privacy';

	public const POST_DETAIL = 'handl_aicac_disclosure_detail';

	public const HEADING = 'AI activity on this site';

	public const MODE_GATED = 'This site\'s AI access control checks the requests it handles before they run.';

	public const MODE_OBSERVE = 'This site\'s AI access control is set to watch requests without blocking them.';

	public const PAUSED = 'This site\'s AI access control is set to pause the requests it handles.';

	public const EMPTY = 'No AI activity is available to show in this disclosure.';

	public const PROVIDERS_PREFIX = 'AI services in the activity log: ';

	public const FAMILIES_PREFIX = 'Request types: ';

	public const FOOTNOTE = 'Based on this site\'s AI access settings and saved activity log. Entries may include blocked requests and checks for available AI features. This is not a complete history of AI use.';

	public const SETTINGS_TITLE = 'Public AI disclosure';

	public const SETTINGS_PRIVACY = 'Show this disclosure on the privacy policy page';

	public const SETTINGS_DETAIL = 'Show request types for each AI service';

	public const SETTINGS_HELP = 'AI service names and request types come from the saved activity log. Turn this on to show request types beside each service.';

	public const SHORTCODE_HINT = 'Or add the [handl_ai_disclosure] shortcode to any page.';

	/** @var array<string,string> */
	private const PROVIDER_LABELS = array(
		'openai'      => 'OpenAI',
		'anthropic'   => 'Anthropic',
		'google'      => 'Google',
		'cohere'      => 'Cohere',
		'mistral'     => 'Mistral',
		'groq'        => 'Groq',
		'together'    => 'Together AI',
		'fireworks'   => 'Fireworks',
		'perplexity'  => 'Perplexity',
		'xai'         => 'xAI',
		'deepseek'    => 'DeepSeek',
		'openrouter'  => 'OpenRouter',
		'azure'       => 'Azure OpenAI',
	);

	/** @var list<string> */
	private const SKIP_CHANNELS = array(
		'direct_http',
		'spend_threshold',
		'budget',
		'drift',
		'alert_snooze',
		'anomaly',
		'forecast_warn',
		'rate_warn',
		'selftest',
		'share',
		'policy_restore',
		'access_request',
		'policy_checks',
		'policy_save',
		'policy_import',
		'email',
		'temp_allow',
		'went_ai',
		'canary',
		'tamper',
		'hardened_guard',
	);

	private static ?Disclosure $instance = null;

	public static function instance(): Disclosure {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}

		return self::$instance;
	}

	public static function reset_for_tests(): void {
		self::$instance = null;
	}

	/**
	 * Hook only. No option reads — render is the first I/O.
	 */
	public function init(): void {
		if ( function_exists( 'add_shortcode' ) ) {
			add_shortcode( self::SHORTCODE, array( $this, 'render_shortcode' ) );
		}
		add_action( 'init', array( $this, 'register_block' ) );
		add_action( 'admin_init', array( $this, 'register_privacy_guide' ) );
		add_action( 'handl_aicac_protections_settings', array( $this, 'render_settings' ) );
		add_filter( 'the_content', array( $this, 'append_privacy' ) );
		add_filter( 'pre_update_option_' . Plugin::OPTION_KEY, array( self::class, 'merge_on_policy_save' ), 10, 2 );
	}

	public function register_block(): void {
		if ( ! function_exists( 'register_block_type' ) ) {
			return;
		}

		register_block_type(
			self::BLOCK_NAME,
			array(
				'api_version'     => 3,
				'title'           => self::HEADING,
				'description'     => self::SETTINGS_HELP,
				'category'        => 'widgets',
				'render_callback' => array( $this, 'render_block' ),
				'attributes'      => array(
					'detail' => array(
						'type'    => 'boolean',
						'default' => true,
					),
				),
			)
		);
	}

	public function register_privacy_guide(): void {
		if ( ! function_exists( 'wp_add_privacy_policy_content' ) ) {
			return;
		}

		wp_add_privacy_policy_content(
			'HandL AI Connector Access Control',
			'<p>' . esc_html( self::HEADING ) . '</p><p>' . esc_html( self::SHORTCODE_HINT ) . '</p>'
		);
	}

	/**
	 * Default ON when the policy key is absent.
	 *
	 * @param array<string,mixed> $policy
	 */
	public static function is_detail_enabled( array $policy ): bool {
		if ( ! array_key_exists( self::POLICY_DETAIL_KEY, $policy ) ) {
			return true;
		}

		return ! empty( $policy[ self::POLICY_DETAIL_KEY ] );
	}

	/**
	 * Default OFF when the policy key is absent.
	 *
	 * @param array<string,mixed> $policy
	 */
	public static function is_privacy_enabled( array $policy ): bool {
		return ! empty( $policy[ self::POLICY_PRIVACY_KEY ] );
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
			$value[ self::POLICY_PRIVACY_KEY ] = ! empty( $_POST[ self::POST_PRIVACY ] ); // phpcs:ignore WordPress.Security.NonceVerification.Missing
			$value[ self::POLICY_DETAIL_KEY ]  = ! empty( $_POST[ self::POST_DETAIL ] ); // phpcs:ignore WordPress.Security.NonceVerification.Missing

			return $value;
		}

		if ( is_array( $old ) ) {
			if ( array_key_exists( self::POLICY_PRIVACY_KEY, $old ) ) {
				$value[ self::POLICY_PRIVACY_KEY ] = ! empty( $old[ self::POLICY_PRIVACY_KEY ] );
			}
			if ( array_key_exists( self::POLICY_DETAIL_KEY, $old ) ) {
				$value[ self::POLICY_DETAIL_KEY ] = ! empty( $old[ self::POLICY_DETAIL_KEY ] );
			}
		}

		return $value;
	}

	/**
	 * @param array<string,mixed> $policy
	 */
	public function render_settings( $policy ): void {
		$policy  = is_array( $policy ) ? $policy : array();
		$privacy = self::is_privacy_enabled( $policy );
		$detail  = self::is_detail_enabled( $policy );

		echo '<tr>';
		echo '<th scope="row">' . esc_html__( 'Public AI disclosure', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<td>';
		echo '<input type="hidden" name="' . esc_attr( self::POST_PRESENT ) . '" value="1" />';
		echo '<label for="handl-aicac-disclosure-privacy">';
		echo '<input type="checkbox" name="' . esc_attr( self::POST_PRIVACY ) . '" id="handl-aicac-disclosure-privacy" value="1"' . ( $privacy ? ' checked="checked"' : '' ) . ' /> ';
		echo esc_html__( 'Show this disclosure on the privacy policy page', 'handl-ai-connector-access-control' );
		echo '</label>';
		echo '<br />';
		echo '<label for="handl-aicac-disclosure-detail">';
		echo '<input type="checkbox" name="' . esc_attr( self::POST_DETAIL ) . '" id="handl-aicac-disclosure-detail" value="1"' . ( $detail ? ' checked="checked"' : '' ) . ' /> ';
		echo esc_html__( 'Show request types for each AI service', 'handl-ai-connector-access-control' );
		echo '</label>';
		echo '<p class="description">' . esc_html__( 'AI service names and request types come from the saved activity log. Turn this on to show request types beside each service.', 'handl-ai-connector-access-control' ) . '</p>';
		echo '<p class="description">' . esc_html__( 'Or add the [handl_ai_disclosure] shortcode to any page.', 'handl-ai-connector-access-control' ) . '</p>';
		echo '</td>';
		echo '</tr>';
	}

	/**
	 * @param mixed $atts Shortcode attributes.
	 */
	public function render_shortcode( $atts = array() ): string {
		$detail = null;
		if ( is_array( $atts ) && array_key_exists( 'detail', $atts ) ) {
			$detail = self::parse_detail_attr( $atts['detail'] );
		}

		return self::render( $detail );
	}

	/**
	 * @param array<string,mixed> $attributes Block attributes.
	 * @param string              $content    Inner content (unused).
	 */
	public function render_block( $attributes = array(), $content = '' ): string {
		unset( $content );
		$detail = null;
		if ( is_array( $attributes ) && array_key_exists( 'detail', $attributes ) ) {
			$detail = (bool) $attributes['detail'];
		}

		return self::render( $detail );
	}

	/**
	 * @param string $content Post content.
	 */
	public function append_privacy( $content ): string {
		$content = (string) $content;
		$policy  = class_exists( Policy::class ) ? Policy::get_policy() : array();
		if ( ! self::is_privacy_enabled( is_array( $policy ) ? $policy : array() ) ) {
			return $content;
		}
		if ( ! function_exists( 'is_privacy_policy' ) || ! is_privacy_policy() ) {
			return $content;
		}
		if ( false !== strpos( $content, 'handl-aicac-disclosure' ) || false !== strpos( $content, '[' . self::SHORTCODE ) ) {
			return $content;
		}

		return $content . self::render();
	}

	/**
	 * @param mixed $raw Attribute value.
	 */
	public static function parse_detail_attr( $raw ): bool {
		$key = strtolower( trim( (string) $raw ) );

		return ! in_array( $key, array( '0', 'off', 'false', 'no' ), true );
	}

	/**
	 * @param bool|null           $detail  Override; null uses the policy default.
	 * @param array<string,mixed>|null $policy
	 * @param array<int,mixed>|null    $log
	 * @param bool|null           $freeze
	 */
	public static function render( ?bool $detail = null, ?array $policy = null, ?array $log = null, ?bool $freeze = null ): string {
		if ( null === $policy ) {
			$policy = class_exists( Policy::class ) ? Policy::get_policy() : array();
		}
		$policy = is_array( $policy ) ? $policy : array();
		if ( null === $log ) {
			$log = class_exists( Policy::class ) ? Policy::get_retained_log() : array();
		}
		$log = is_array( $log ) ? $log : array();
		if ( null === $freeze ) {
			$freeze = class_exists( Freeze::class ) && Freeze::is_active();
		}
		if ( null === $detail ) {
			$detail = self::is_detail_enabled( $policy );
		}

		return self::render_html( self::build_snapshot( $policy, $log, (bool) $freeze, (bool) $detail ) );
	}

	/**
	 * @param array<string,mixed> $policy
	 * @param array<int,mixed>    $log
	 * @return array{
	 *   mode:string,
	 *   paused:bool,
	 *   empty:bool,
	 *   detail:bool,
	 *   heading:string,
	 *   mode_text:string,
	 *   paused_text:string,
	 *   empty_text:string,
	 *   providers_text:string,
	 *   families_text:string,
	 *   footnote:string,
	 *   providers:list<array{id:string,label:string,families:list<array{id:string,label:string}>}>,
	 *   families:list<array{id:string,label:string}>
	 * }
	 */
	public static function build_snapshot( array $policy, array $log, bool $freeze, bool $detail ): array {
		$paused  = $freeze || ! empty( $policy['kill_switch'] );
		$observe = ! empty( $policy['audit_only'] );
		$mode    = $paused ? 'paused' : ( $observe ? 'observe' : 'gated' );

		$family_labels = class_exists( Operations::class ) ? Operations::family_labels() : array();
		$known         = class_exists( Operations::class ) ? Operations::families() : array();

		/** @var array<string,array<string,bool>> $tree */
		$tree = array();
		foreach ( $log as $row ) {
			if ( ! is_array( $row ) || ! self::is_public_row( $row ) ) {
				continue;
			}
			$provider = self::row_provider( $row );
			if ( '' === $provider ) {
				continue;
			}
			$family = self::row_family( $row, $known );
			if ( ! isset( $tree[ $provider ] ) ) {
				$tree[ $provider ] = array();
			}
			if ( '' !== $family ) {
				$tree[ $provider ][ $family ] = true;
			}
		}

		$providers = array();
		$families  = array();
		foreach ( $tree as $id => $fam_map ) {
			$label = self::provider_label( $id );
			if ( '' === $label ) {
				continue;
			}
			$fam_list = array();
			foreach ( array_keys( $fam_map ) as $fid ) {
				$flabel = isset( $family_labels[ $fid ] ) ? (string) $family_labels[ $fid ] : '';
				if ( '' === $flabel || self::is_leaky( $flabel ) ) {
					continue;
				}
				$fam_list[]          = array(
					'id'    => $fid,
					'label' => $flabel,
				);
				$families[ $fid ]    = $flabel;
			}
			$providers[] = array(
				'id'       => $id,
				'label'    => $label,
				'families' => $fam_list,
			);
		}

		$family_list = array();
		foreach ( $known as $fid ) {
			if ( ! isset( $families[ $fid ] ) ) {
				continue;
			}
			$family_list[] = array(
				'id'    => $fid,
				'label' => $families[ $fid ],
			);
		}

		$provider_names = array();
		foreach ( $providers as $row ) {
			$provider_names[] = $row['label'];
		}
		$family_names = array();
		foreach ( $family_list as $row ) {
			$family_names[] = $row['label'];
		}

		$empty = empty( $providers );

		return array(
			'mode'           => $mode,
			'paused'         => $paused,
			'empty'          => $empty,
			'detail'         => $detail,
			'heading'        => self::HEADING,
			'mode_text'      => $paused ? '' : ( $observe ? self::MODE_OBSERVE : self::MODE_GATED ),
			'paused_text'    => self::PAUSED,
			'empty_text'     => self::EMPTY,
			'providers_text' => $empty ? '' : self::PROVIDERS_PREFIX . implode( ', ', $provider_names ),
			'families_text'  => $empty || empty( $family_names ) ? '' : self::FAMILIES_PREFIX . implode( ', ', $family_names ),
			'footnote'       => self::FOOTNOTE,
			'providers'      => $providers,
			'families'       => $family_list,
		);
	}

	/**
	 * @param array<string,mixed> $snap
	 */
	public static function render_html( array $snap ): string {
		$html  = '<section class="handl-aicac-disclosure">';
		$html .= '<h2 class="handl-aicac-disclosure__heading">' . esc_html( (string) ( $snap['heading'] ?? self::HEADING ) ) . '</h2>';
		$mode_text = (string) ( $snap['mode_text'] ?? '' );
		if ( '' !== $mode_text ) {
			$html .= '<p class="handl-aicac-disclosure__mode">' . esc_html( $mode_text ) . '</p>';
		}
		if ( ! empty( $snap['paused'] ) ) {
			$html .= '<p class="handl-aicac-disclosure__paused">' . esc_html( (string) ( $snap['paused_text'] ?? self::PAUSED ) ) . '</p>';
		}
		if ( ! empty( $snap['empty'] ) ) {
			$html .= '<p class="handl-aicac-disclosure__empty">' . esc_html( (string) ( $snap['empty_text'] ?? self::EMPTY ) ) . '</p>';
		} else {
			if ( ! empty( $snap['providers_text'] ) ) {
				$html .= '<p class="handl-aicac-disclosure__providers">' . esc_html( (string) $snap['providers_text'] ) . '</p>';
			}
			if ( ! empty( $snap['families_text'] ) ) {
				$html .= '<p class="handl-aicac-disclosure__families">' . esc_html( (string) $snap['families_text'] ) . '</p>';
			}
			if ( ! empty( $snap['detail'] ) && ! empty( $snap['providers'] ) && is_array( $snap['providers'] ) ) {
				$html .= '<ul class="handl-aicac-disclosure__detail">';
				foreach ( $snap['providers'] as $row ) {
					if ( ! is_array( $row ) ) {
						continue;
					}
					$label = isset( $row['label'] ) ? (string) $row['label'] : '';
					if ( '' === $label || self::is_leaky( $label ) ) {
						continue;
					}
					$bits = array();
					if ( isset( $row['families'] ) && is_array( $row['families'] ) ) {
						foreach ( $row['families'] as $fam ) {
							if ( ! is_array( $fam ) ) {
								continue;
							}
							$fl = isset( $fam['label'] ) ? (string) $fam['label'] : '';
							if ( '' !== $fl && ! self::is_leaky( $fl ) ) {
								$bits[] = $fl;
							}
						}
					}
					$line  = $label;
					if ( ! empty( $bits ) ) {
						$line .= ': ' . implode( ', ', $bits );
					}
					$html .= '<li>' . esc_html( $line ) . '</li>';
				}
				$html .= '</ul>';
			}
		}
		$html .= '<p class="handl-aicac-disclosure__footnote">' . esc_html( (string) ( $snap['footnote'] ?? self::FOOTNOTE ) ) . '</p>';
		$html .= '</section>';

		return $html;
	}

	/**
	 * @param array<string,mixed> $row
	 */
	public static function is_public_row( array $row ): bool {
		if ( ! empty( $row['selftest'] ) ) {
			return false;
		}
		if ( class_exists( Usage_Trends::class ) && ! Usage_Trends::is_activity_row( $row ) ) {
			return false;
		}
		$channel = isset( $row['channel'] ) ? (string) $row['channel'] : '';
		if ( '' !== $channel && in_array( $channel, self::SKIP_CHANNELS, true ) ) {
			return false;
		}

		return true;
	}

	public static function provider_label( string $id ): string {
		$id = class_exists( Cost::class ) ? Cost::normalize_provider_id( $id ) : strtolower( preg_replace( '/[^a-z0-9_-]/', '', strtolower( $id ) ) ?? '' );
		if ( ! self::is_public_provider_id( $id ) ) {
			return '';
		}
		if ( isset( self::PROVIDER_LABELS[ $id ] ) ) {
			return self::PROVIDER_LABELS[ $id ];
		}

		$label = ucwords( str_replace( array( '-', '_' ), ' ', $id ) );
		return self::is_leaky( $label ) ? '' : $label;
	}

	public static function is_public_provider_id( string $id ): bool {
		$id = strtolower( trim( $id ) );
		if ( strlen( $id ) < 2 || strlen( $id ) > 32 ) {
			return false;
		}
		if ( class_exists( Analytics::class ) && Analytics::UNKNOWN_KEY === $id ) {
			return false;
		}
		if ( ! preg_match( '/^[a-z][a-z0-9_-]*$/', $id ) ) {
			return false;
		}

		return ! self::is_leaky( $id );
	}

	public static function is_leaky( string $text ): bool {
		$hay = strtolower( $text );
		if ( '' === $hay ) {
			return true;
		}
		if ( false !== strpos( $hay, '/' ) || false !== strpos( $hay, '\\' ) ) {
			return true;
		}
		if ( false !== strpos( $hay, '.php' ) || false !== strpos( $hay, '.phtml' ) ) {
			return true;
		}
		if ( false !== strpos( $hay, 'handl_aicac' ) || false !== strpos( $hay, 'sk-' ) ) {
			return true;
		}
		if ( false !== strpos( $hay, '@' ) || false !== strpos( $hay, '://' ) ) {
			return true;
		}

		return false;
	}

	/**
	 * @param array<string,mixed> $row
	 */
	private static function row_provider( array $row ): string {
		$raw = '';
		if ( ! empty( $row['provider'] ) && is_string( $row['provider'] ) ) {
			$raw = $row['provider'];
		} elseif ( ! empty( $row['forced_provider'] ) && is_string( $row['forced_provider'] ) ) {
			$raw = $row['forced_provider'];
		}
		$id = class_exists( Cost::class ) ? Cost::normalize_provider_id( $raw ) : strtolower( trim( $raw ) );
		if ( ! self::is_public_provider_id( $id ) ) {
			return '';
		}

		return $id;
	}

	/**
	 * @param array<string,mixed> $row
	 * @param list<string>        $known
	 */
	private static function row_family( array $row, array $known ): string {
		$raw = '';
		if ( ! empty( $row['capability_family'] ) && is_string( $row['capability_family'] ) ) {
			$raw = $row['capability_family'];
		} elseif ( ! empty( $row['family'] ) && is_string( $row['family'] ) ) {
			$raw = $row['family'];
		} elseif ( ! empty( $row['operation'] ) && is_string( $row['operation'] ) && class_exists( Operations::class ) ) {
			$raw = Operations::family_from_operation( $row['operation'] );
		}
		$raw = strtolower( trim( $raw ) );
		if ( '' === $raw || ! in_array( $raw, $known, true ) ) {
			return '';
		}

		return $raw;
	}
}
