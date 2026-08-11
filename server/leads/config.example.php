<?php
/**
 * Copy to config.php on the HandL server (SSH profile B) and set a real token.
 * config.php is gitignored under server/leads/ — never commit production secrets.
 *
 * Token must match the plugin's HANDL_AICAC_LEADS_TOKEN (or the default in
 * includes/class-handl-aicac-leads.php until rotated).
 */
declare(strict_types=1);

return array(
	// Must match the plugin write token (rotate together).
	'token'               => 'aicac-leads-v1-handl-optin',

	// SQLite file outside the web root when possible.
	'db_path'             => __DIR__ . '/data/leads.sqlite',

	// Max POSTs per client IP per hour (auth still required).
	'rate_limit_per_hour' => 30,

	// Reserved for future use (logs, etc.).
	'data_dir'            => __DIR__ . '/data',
);
