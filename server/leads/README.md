# AICAC-LEADS server intake

**Not part of the WordPress.org plugin package.** This directory is excluded from:

- GitHub Release zip (`.github/workflows/release.yml`)
- Local `deploy.sh` zip + SVN trunk rsync

## What it does

`POST /aicac/leads/` accepts a small JSON body after the admin checks an **unchecked-by-default** consent box in the onboarding wizard:

```json
{
  "email": "admin@example.com",
  "site_url": "https://example.com",
  "plugin_version": "1.2.0",
  "consented_at": "2026-08-11T00:00:00+00:00"
}
```

Header: `X-HandL-AICAC-Token: <shared token>`

Storage: SQLite table `leads` with unique `(email, site_url)` dedupe. Rate-limited per IP.

## Deploy (QA / Frink Luna — SSH profile B)

1. Copy `server/leads/` to the HandL host (outside the WP plugin path).
2. `cp config.example.php config.php` and set `token` + `db_path`.
3. Point the web server so `public/index.php` is served at  
   `https://www.handldigital.com/aicac/leads/` (or update the plugin filter / `HANDL_AICAC_LEADS_URL`).
4. Ensure PHP has `pdo_sqlite`, and the data directory is writable by the PHP user but not web-served.
5. Smoke: consent path inserts a row; no-consent path never hits this host.

## Verify exclusion from WP.org artifact

```bash
# After building a release zip or dry-run rsync:
unzip -l handl-ai-connector-access-control-*.zip | grep -i server && echo FAIL || echo OK
```
