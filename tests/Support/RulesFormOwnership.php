<?php
/**
 * Parsed-DOM form-ownership check for the Rules tab (#212).
 *
 * Source-text tests cannot see whether a nested <form> closed
 * #handl-aicac-rules-save before Save / nonce / action reached it.
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Support;

use DOMDocument;
use DOMElement;
use DOMXPath;

final class RulesFormOwnership {

	public const RULES_FORM_ID = 'handl-aicac-rules-save';

	/**
	 * @return list<array{ok:bool,element:string,owner:string,expected:string}>
	 */
	public static function inspect( string $html ): array {
		$dom = new DOMDocument();
		$prev = libxml_use_internal_errors( true );
		$dom->loadHTML( $html );
		libxml_clear_errors();
		libxml_use_internal_errors( $prev );

		$xp = new DOMXPath( $dom );
		$rows = array();

		$save = $xp->query( '//button[@name="handl_aicac_action" and @value="save"] | //button[@data-aicac-action="save"]' );
		if ( 0 === $save->length ) {
			$rows[] = array(
				'ok'       => false,
				'element'  => 'button[name=handl_aicac_action][value=save]',
				'owner'    => '(missing)',
				'expected' => self::RULES_FORM_ID,
			);
		} else {
			foreach ( $save as $el ) {
				if ( ! $el instanceof DOMElement ) {
					continue;
				}
				$rows[] = self::row( $el, self::describe( $el ) );
			}
		}

		$action = $dom->getElementById( 'handl-aicac-action' );
		if ( ! $action instanceof DOMElement ) {
			$rows[] = array(
				'ok'       => false,
				'element'  => 'input#handl-aicac-action',
				'owner'    => '(missing)',
				'expected' => self::RULES_FORM_ID,
			);
		} else {
			$rows[] = self::row( $action, 'input#handl-aicac-action' );
		}

		$nonce = self::save_nonce( $xp, $action instanceof DOMElement ? $action : null );
		if ( ! $nonce instanceof DOMElement ) {
			$rows[] = array(
				'ok'       => false,
				'element'  => 'input[name=handl_aicac_nonce] (Rules save)',
				'owner'    => '(missing)',
				'expected' => self::RULES_FORM_ID,
			);
		} else {
			$rows[] = self::row( $nonce, 'input[name=handl_aicac_nonce]' );
		}

		return $rows;
	}

	/**
	 * @param list<array{ok:bool,element:string,owner:string,expected:string}> $rows
	 */
	public static function failed( array $rows ): array {
		return array_values(
			array_filter(
				$rows,
				static function ( array $row ): bool {
					return ! $row['ok'];
				}
			)
		);
	}

	/**
	 * @param list<array{ok:bool,element:string,owner:string,expected:string}> $rows
	 */
	public static function format_failure( array $rows ): string {
		$failed = self::failed( $rows );
		if ( array() === $failed ) {
			return '';
		}
		$lines = array();
		foreach ( $failed as $row ) {
			$lines[] = sprintf(
				'%s owner=%s expected=%s',
				$row['element'],
				$row['owner'],
				$row['expected']
			);
		}
		return implode( "\n", $lines );
	}

	/**
	 * @return array{ok:bool,element:string,owner:string,expected:string}
	 */
	private static function row( DOMElement $el, string $label ): array {
		$owner = self::owner_id( $el );
		return array(
			'ok'       => self::RULES_FORM_ID === $owner,
			'element'  => $label,
			'owner'    => $owner,
			'expected' => self::RULES_FORM_ID,
		);
	}

	private static function owner_id( DOMElement $el ): string {
		$form_attr = trim( $el->getAttribute( 'form' ) );
		if ( '' !== $form_attr ) {
			$doc = $el->ownerDocument;
			if ( $doc instanceof DOMDocument ) {
				$target = $doc->getElementById( $form_attr );
				if ( ! $target instanceof DOMElement ) {
					return '(missing-form:' . $form_attr . ')';
				}
			}
			return $form_attr;
		}

		$node = $el->parentNode;
		while ( $node ) {
			if ( $node instanceof DOMElement && 'form' === strtolower( $node->tagName ) ) {
				$id = trim( $node->getAttribute( 'id' ) );
				return '' !== $id ? $id : '(anonymous)';
			}
			$node = $node->parentNode;
		}

		return '(none)';
	}

	private static function describe( DOMElement $el ): string {
		$tag = strtolower( $el->tagName );
		$bits = array( $tag );
		$id = $el->getAttribute( 'id' );
		if ( '' !== $id ) {
			$bits[] = '#' . $id;
		}
		$name = $el->getAttribute( 'name' );
		if ( '' !== $name ) {
			$bits[] = '[name=' . $name . ']';
		}
		$value = $el->getAttribute( 'value' );
		if ( '' !== $value ) {
			$bits[] = '[value=' . $value . ']';
		}
		return implode( '', $bits );
	}

	private static function save_nonce( DOMXPath $xp, ?DOMElement $action ): ?DOMElement {
		if ( $action instanceof DOMElement ) {
			$parent = $action->parentNode;
			if ( $parent ) {
				foreach ( $parent->childNodes as $child ) {
					if ( ! $child instanceof DOMElement ) {
						continue;
					}
					if ( 'handl_aicac_nonce' === $child->getAttribute( 'name' ) ) {
						return $child;
					}
				}
			}
		}

		$inside = $xp->query( '//form[@id="' . self::RULES_FORM_ID . '"]//input[@name="handl_aicac_nonce"]' );
		if ( $inside && $inside->length > 0 && $inside->item( 0 ) instanceof DOMElement ) {
			return $inside->item( 0 );
		}

		$any = $xp->query( '//input[@name="handl_aicac_nonce"]' );
		if ( $any && $any->length > 0 && $any->item( 0 ) instanceof DOMElement ) {
			return $any->item( 0 );
		}

		return null;
	}
}
