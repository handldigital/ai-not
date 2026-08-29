<?php
/**
 * AICAC-DOM-TEST (#212): parsed-DOM Rules form ownership.
 *
 * QA checklist — run this on any PR that touches render_page() or adds
 * a section inside the Rules form:
 *
 *   php tests/bin/check-rules-form-ownership.php --html-file path.html
 *   php tests/bin/check-rules-form-ownership.php --url 'https://handl-sandbox/wp-admin/admin.php?page=handl-aicac-rules'
 *
 * Cookie auth for --url: pass a Cookie header via --cookie 'name=value'.
 * Exits 1 and names the element + actual form owner on failure.
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

$root = dirname( __DIR__, 2 );
require $root . '/tests/Support/RulesFormOwnership.php';

use HandL\AICAC\Tests\Support\RulesFormOwnership;

$html = '';
$url  = '';
$cookie = '';

$args = array_slice( $argv, 1 );
for ( $i = 0, $n = count( $args ); $i < $n; $i++ ) {
	$arg = $args[ $i ];
	if ( 0 === strpos( $arg, '--html-file=' ) ) {
		$file = substr( $arg, 12 );
		$html = (string) file_get_contents( $file );
		continue;
	}
	if ( '--html-file' === $arg && isset( $args[ $i + 1 ] ) ) {
		$html = (string) file_get_contents( $args[ ++$i ] );
		continue;
	}
	if ( 0 === strpos( $arg, '--url=' ) ) {
		$url = substr( $arg, 6 );
		continue;
	}
	if ( '--url' === $arg && isset( $args[ $i + 1 ] ) ) {
		$url = $args[ ++$i ];
		continue;
	}
	if ( 0 === strpos( $arg, '--cookie=' ) ) {
		$cookie = substr( $arg, 9 );
		continue;
	}
	if ( '--cookie' === $arg && isset( $args[ $i + 1 ] ) ) {
		$cookie = $args[ ++$i ];
		continue;
	}
	if ( '-' === $arg ) {
		$html = (string) stream_get_contents( STDIN );
	}
}

if ( '' === $html && '' !== $url ) {
	$headers = array();
	if ( '' !== $cookie ) {
		$headers[] = 'Cookie: ' . $cookie;
	}
	$ctx  = stream_context_create(
		array(
			'http' => array(
				'header'          => implode( "\r\n", $headers ),
				'follow_location' => 1,
				'timeout'         => 20,
			),
		)
	);
	$html = (string) file_get_contents( $url, false, $ctx );
}

if ( '' === $html && ! defined( 'STDIN' ) ) {
	fwrite( STDERR, "usage: check-rules-form-ownership.php --html-file FILE | --url URL [--cookie NAME=VALUE] | -\n" );
	exit( 2 );
}

if ( '' === $html ) {
	$html = (string) stream_get_contents( STDIN );
}

if ( '' === trim( $html ) ) {
	fwrite( STDERR, "empty HTML\n" );
	exit( 2 );
}

$rows   = RulesFormOwnership::inspect( $html );
$failed = RulesFormOwnership::failed( $rows );

if ( array() === $failed ) {
	fwrite( STDOUT, "OK: Rules form owners are " . RulesFormOwnership::RULES_FORM_ID . "\n" );
	exit( 0 );
}

fwrite( STDERR, "FAIL: Rules form ownership\n" . RulesFormOwnership::format_failure( $rows ) . "\n" );
exit( 1 );
