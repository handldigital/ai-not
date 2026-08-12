#!/bin/bash
# Deploy handl-ai-connector-access-control: production ZIP + WordPress.org SVN
# Run from anywhere: ./deploy.sh
# Build only the ZIP for inspection: ./deploy.sh --package-only
# This file is excluded from the zip and SVN trunk packages.
#
# AICAC-LEADS: server/ is HandL-host only — never ship in WP.org zip/SVN.

set -euo pipefail

PLUGIN_SLUG="handl-ai-connector-access-control"
PLUGIN_DIR="$(cd "$(dirname "$0")" && pwd)"
PARENT_DIR="$(dirname "${PLUGIN_DIR}")"
SVN_URL="https://plugins.svn.wordpress.org/${PLUGIN_SLUG}/"
SVN_DIR="${PARENT_DIR}/${PLUGIN_SLUG}-svn"
MAIN_PLUGIN_FILE="${PLUGIN_DIR}/${PLUGIN_SLUG}.php"
ZIP_PATH="${PARENT_DIR}/${PLUGIN_SLUG}.zip"
PACKAGE_ONLY=false

case "${1:-}" in
	"") ;;
	--package-only) PACKAGE_ONLY=true ;;
	*)
		echo "Usage: $0 [--package-only]" >&2
		exit 1
		;;
esac

PLUGIN_VERSION=$(awk '/^[[:space:]]*\*[[:space:]]+Version:[[:space:]]+/ {sub(/^[[:space:]]*\*[[:space:]]+Version:[[:space:]]+/, ""); print; exit}' "${MAIN_PLUGIN_FILE}")

if [ -z "${PLUGIN_VERSION}" ]; then
  echo "Could not detect plugin version from ${MAIN_PLUGIN_FILE}"
  exit 1
fi

echo "Deploying ${PLUGIN_SLUG} version ${PLUGIN_VERSION}"

PACKAGE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/${PLUGIN_SLUG}-package.XXXXXX")"
trap 'rm -rf "${PACKAGE_DIR}"' EXIT

# Keep the distributable intentionally small. Composer's dev-only PHPUnit tree
# (including vendor/sebastian) and every future development directory are out
# by default; a runtime file must be added here deliberately.
PRODUCTION_RSYNC_FILTERS=(
	--include='/assets/'
	--include='/assets/***'
	--include='/includes/'
	--include='/includes/***'
	--include='/languages/'
	--include='/languages/***'
	--include='/handl-ai-connector-access-control.php'
	--include='/uninstall.php'
	--include='/readme.txt'
	--include='/LICENSE.txt'
	--exclude='*'
)

mkdir -p "${PACKAGE_DIR}/${PLUGIN_SLUG}"
rsync -rc --delete "${PRODUCTION_RSYNC_FILTERS[@]}" "${PLUGIN_DIR}/" "${PACKAGE_DIR}/${PLUGIN_SLUG}/"
rm -f "${ZIP_PATH}"
(
	cd "${PACKAGE_DIR}"
	zip -r9 "${ZIP_PATH}" "${PLUGIN_SLUG}"
)

if [ "${PACKAGE_ONLY}" = true ]; then
	echo "Package contents:"
	unzip -Z1 "${ZIP_PATH}"
	exit 0
fi

rm -rf "${SVN_DIR}"
svn checkout "${SVN_URL}" "${SVN_DIR}"

rsync -rc --delete "${PRODUCTION_RSYNC_FILTERS[@]}" "${PLUGIN_DIR}/" "${SVN_DIR}/trunk/"

# WordPress.org plugin directory assets live in SVN assets/ (not trunk).
# https://developer.wordpress.org/plugins/wordpress-org/plugin-assets/
WP_ORG_ASSETS="${PLUGIN_DIR}/wordpress-org/assets"
mkdir -p "${SVN_DIR}/assets"

if [ -f "${PLUGIN_DIR}/assets/icon-128x128.png" ] && [ -f "${PLUGIN_DIR}/assets/icon-256x256.png" ]; then
  cp -f "${PLUGIN_DIR}/assets/icon-128x128.png" "${SVN_DIR}/assets/icon-128x128.png"
  cp -f "${PLUGIN_DIR}/assets/icon-256x256.png" "${SVN_DIR}/assets/icon-256x256.png"
else
  echo "Warning: Missing ${PLUGIN_DIR}/assets/icon-128x128.png or icon-256x256.png; skipping icon copy."
fi

for asset in banner-772x250.png banner-1544x500.png screenshot-1.png screenshot-2.png; do
  if [ -f "${WP_ORG_ASSETS}/${asset}" ]; then
    cp -f "${WP_ORG_ASSETS}/${asset}" "${SVN_DIR}/assets/${asset}"
  else
    echo "Warning: Missing ${WP_ORG_ASSETS}/${asset}; skipping."
  fi
done

(cd "${SVN_DIR}" && svn status | awk '/^\?/ {print substr($0,9)}' | xargs -I {} svn add "{}")
(cd "${SVN_DIR}" && svn status | awk '/^\!/ {print substr($0,9)}' | xargs -I {} svn rm "{}")

# if [ -n "$(cd "${SVN_DIR}" && svn status)" ]; then
#   (cd "${SVN_DIR}" && svn commit -m "Deploy version ${PLUGIN_VERSION}")
# else
#   echo "No SVN trunk changes to commit."
# fi

if [ -z "$(cd "${SVN_DIR}" && svn ls "tags/${PLUGIN_VERSION}" 2>/dev/null)" ]; then
  (cd "${SVN_DIR}" && svn copy trunk "tags/${PLUGIN_VERSION}" && svn commit -m "Tag version ${PLUGIN_VERSION}")
else
  echo "Tag ${PLUGIN_VERSION} already exists. Skipping tag creation."
fi

echo "Done. Zip: ${ZIP_PATH}"
