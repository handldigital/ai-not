<?php
/**
 * AICAC-LEADS intake endpoint (HandL server only — NOT shipped in the WP.org zip).
 *
 * POST /aicac/leads  JSON body:
 *   { "email", "site_url", "plugin_version", "consented_at" }
 *
 * Auth: header X-HandL-AICAC-Token must match config token.
 * Dedupe: unique (email, site_url). Rate-limited per client IP.
 *
 * Deploy: copy server/leads/ to the HandL host (SSH profile B). See ../README.md.
 */

declare(strict_types=1);

header( 'Content-Type: application/json; charset=utf-8' );
header( 'X-Content-Type-Options: nosniff' );
header( 'Cache-Control: no-store' );

if ( 'POST' !== ( $_SERVER['REQUEST_METHOD'] ?? '' ) ) {
	http_response_code( 405 );
	header( 'Allow: POST' );
	echo json_encode( array( 'ok' => false, 'error' => 'method_not_allowed' ) );
	exit;
}

$config_path = dirname( __DIR__ ) . '/config.php';
if ( ! is_readable( $config_path ) ) {
	http_response_code( 503 );
	echo json_encode( array( 'ok' => false, 'error' => 'not_configured' ) );
	exit;
}

/** @var array{token:string,db_path:string,rate_limit_per_hour:int,data_dir:string} $config */
$config = require $config_path;

$token = (string) ( $config['token'] ?? '' );
if ( '' === $token ) {
	http_response_code( 503 );
	echo json_encode( array( 'ok' => false, 'error' => 'not_configured' ) );
	exit;
}

$presented = (string) ( $_SERVER['HTTP_X_HANDL_AICAC_TOKEN'] ?? '' );
if ( '' === $presented || ! hash_equals( $token, $presented ) ) {
	http_response_code( 401 );
	echo json_encode( array( 'ok' => false, 'error' => 'unauthorized' ) );
	exit;
}

$ip = client_ip();
if ( ! rate_limit_allow( $config, $ip ) ) {
	http_response_code( 429 );
	echo json_encode( array( 'ok' => false, 'error' => 'rate_limited' ) );
	exit;
}

$raw = file_get_contents( 'php://input' );
$data = is_string( $raw ) ? json_decode( $raw, true ) : null;
if ( ! is_array( $data ) ) {
	http_response_code( 400 );
	echo json_encode( array( 'ok' => false, 'error' => 'invalid_json' ) );
	exit;
}

$email = normalize_email( (string) ( $data['email'] ?? '' ) );
$site  = normalize_site_url( (string) ( $data['site_url'] ?? '' ) );
$ver   = substr( preg_replace( '/[^\dA-Za-z.\-+_]/', '', (string) ( $data['plugin_version'] ?? '' ) ) ?? '', 0, 32 );
$at    = normalize_consented_at( (string) ( $data['consented_at'] ?? '' ) );

if ( null === $email || null === $site || null === $at ) {
	http_response_code( 422 );
	echo json_encode( array( 'ok' => false, 'error' => 'validation_failed' ) );
	exit;
}

try {
	$pdo = open_db( $config );
	ensure_schema( $pdo );

	$stmt = $pdo->prepare(
		'INSERT INTO leads (email, site_url, plugin_version, consented_at, created_at, updated_at)
		 VALUES (:email, :site_url, :plugin_version, :consented_at, :created_at, :updated_at)
		 ON CONFLICT(email, site_url) DO UPDATE SET
		   plugin_version = excluded.plugin_version,
		   consented_at   = excluded.consented_at,
		   updated_at     = excluded.updated_at'
	);
	$now = gmdate( 'c' );
	$stmt->execute(
		array(
			':email'          => $email,
			':site_url'       => $site,
			':plugin_version' => $ver,
			':consented_at'   => $at,
			':created_at'     => $now,
			':updated_at'     => $now,
		)
	);

	http_response_code( 200 );
	echo json_encode( array( 'ok' => true ) );
} catch ( Throwable $e ) {
	http_response_code( 500 );
	echo json_encode( array( 'ok' => false, 'error' => 'server_error' ) );
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * @param array{token?:string,db_path:string,rate_limit_per_hour?:int,data_dir?:string} $config
 */
function open_db( array $config ): PDO {
	$db_path = (string) $config['db_path'];
	$dir     = dirname( $db_path );
	if ( ! is_dir( $dir ) && ! mkdir( $dir, 0750, true ) && ! is_dir( $dir ) ) {
		throw new RuntimeException( 'db_dir' );
	}
	$pdo = new PDO( 'sqlite:' . $db_path, null, null, array(
		PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
		PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
	) );
	$pdo->exec( 'PRAGMA journal_mode=WAL;' );
	return $pdo;
}

function ensure_schema( PDO $pdo ): void {
	$pdo->exec(
		'CREATE TABLE IF NOT EXISTS leads (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			email TEXT NOT NULL,
			site_url TEXT NOT NULL,
			plugin_version TEXT NOT NULL DEFAULT \'\',
			consented_at TEXT NOT NULL,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL,
			UNIQUE(email, site_url)
		)'
	);
	$pdo->exec(
		'CREATE TABLE IF NOT EXISTS rate_limits (
			ip TEXT NOT NULL,
			window_start INTEGER NOT NULL,
			hit_count INTEGER NOT NULL DEFAULT 0,
			PRIMARY KEY (ip, window_start)
		)'
	);
}

/**
 * @param array{rate_limit_per_hour?:int} $config
 */
function rate_limit_allow( array $config, string $ip ): bool {
	$limit = (int) ( $config['rate_limit_per_hour'] ?? 30 );
	if ( $limit < 1 ) {
		return true;
	}
	try {
		$pdo   = open_db( $config );
		ensure_schema( $pdo );
		$hour  = (int) floor( time() / 3600 );
		$stmt  = $pdo->prepare(
			'INSERT INTO rate_limits (ip, window_start, hit_count) VALUES (:ip, :w, 1)
			 ON CONFLICT(ip, window_start) DO UPDATE SET hit_count = hit_count + 1'
		);
		$stmt->execute( array( ':ip' => $ip, ':w' => $hour ) );

		$q = $pdo->prepare( 'SELECT hit_count FROM rate_limits WHERE ip = :ip AND window_start = :w' );
		$q->execute( array( ':ip' => $ip, ':w' => $hour ) );
		$row = $q->fetch();
		$count = is_array( $row ) ? (int) $row['hit_count'] : 1;
		return $count <= $limit;
	} catch ( Throwable $e ) {
		// Fail open on rate-limit storage errors so a DB blip does not brick intake.
		return true;
	}
}

function client_ip(): string {
	$ip = (string) ( $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0' );
	// Accept first X-Forwarded-For hop only when behind a known reverse proxy you control.
	if ( ! empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
		$parts = explode( ',', (string) $_SERVER['HTTP_X_FORWARDED_FOR'] );
		$cand  = trim( $parts[0] );
		if ( filter_var( $cand, FILTER_VALIDATE_IP ) ) {
			$ip = $cand;
		}
	}
	return substr( $ip, 0, 64 );
}

function normalize_email( string $raw ): ?string {
	$email = strtolower( trim( $raw ) );
	if ( strlen( $email ) > 254 ) {
		return null;
	}
	if ( ! filter_var( $email, FILTER_VALIDATE_EMAIL ) ) {
		return null;
	}
	return $email;
}

function normalize_site_url( string $raw ): ?string {
	$url = trim( $raw );
	if ( '' === $url || strlen( $url ) > 512 ) {
		return null;
	}
	$parts = parse_url( $url );
	if ( ! is_array( $parts ) ) {
		return null;
	}
	$scheme = strtolower( (string) ( $parts['scheme'] ?? '' ) );
	$host   = strtolower( (string) ( $parts['host'] ?? '' ) );
	if ( ! in_array( $scheme, array( 'http', 'https' ), true ) || '' === $host ) {
		return null;
	}
	$path = (string) ( $parts['path'] ?? '' );
	$path = rtrim( $path, '/' );
	$port = isset( $parts['port'] ) ? ':' . (int) $parts['port'] : '';
	return $scheme . '://' . $host . $port . $path;
}

function normalize_consented_at( string $raw ): ?string {
	$raw = trim( $raw );
	if ( '' === $raw ) {
		return null;
	}
	try {
		$dt = new DateTimeImmutable( $raw );
	} catch ( Exception $e ) {
		return null;
	}
	return $dt->setTimezone( new DateTimeZone( 'UTC' ) )->format( 'c' );
}
