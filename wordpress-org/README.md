# WordPress.org plugin directory assets

These files are **not** shipped inside the plugin ZIP. Commit them to the plugin SVN `assets/` directory (sibling to `trunk/` and `tags/`):

- `banner-772x250.png`
- `banner-1544x500.png`
- `screenshot-1.png` … `screenshot-5.png`
- `blueprints/blueprint.json` — Live Preview / Playground setup (login, install+activate this plugin, complete onboarding, enable logging, seed Demo Mode Activity, land on the AI Not Dashboard)

Icons (`icon-128x128.png`, `icon-256x256.png`) live in the SVN `assets/` folder only; copies for the admin UI are under `assets/` in the plugin tree.

## Deploying the Live Preview blueprint

1. Copy `wordpress-org/assets/blueprints/blueprint.json` from this repo into the plugin SVN checkout at `assets/blueprints/blueprint.json` (create the `blueprints/` folder if missing).
2. `svn add` the new path if needed, then commit and push to `plugins.svn.wordpress.org/handl-ai-connector-access-control/assets/`.
3. In the plugin’s Advanced view on WordPress.org, a committer can switch Preview from “Test” to “public” once the blueprint loads cleanly.

The blueprint installs the published wordpress.org build (not this git branch). Demo Mode seeding uses the plugin’s existing `\HandL\AICAC\Demo_Mode::seed()` API — no plugin PHP changes required for the preview path.

After copying, commit from the SVN checkout and push. Banners, screenshots, and the blueprint can appear on wordpress.org before the next plugin release.
