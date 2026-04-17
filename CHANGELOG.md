# Changelog

All notable changes to vps-control-mcp.

The format loosely follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning is [SemVer](https://semver.org/spec/v2.0.0.html).

---

## [1.3.1] — 2026-04-17

### Changed
- Moved `.claude-plugin/CLAUDE.md` to `docs/USING_WITH_CLAUDE.md`. The original path implied a plugin auto-load mechanism that Claude Code does not currently provide; the new path is unambiguous and discoverable.
- Restructured repo documentation: added `KNOWN_ISSUES.md` and `CHANGELOG.md` at repo root.
- README gained a "Working with Claude" section and a Known Issues link under Support.

### Why
- Transparency: devs evaluating the repo should be able to see limitations, iteration velocity, and design intent at a glance. Hidden caveats erode trust faster than disclosed ones.
- Accuracy: filenames should describe what they do. A `CLAUDE.md` in a plugin path that isn't actually auto-loaded is a trap for future contributors.

---

## [1.3.0] — 2026-04-17

### Added
- Explicit sensitive-file pattern for AWS config files without leading dots (`/aws/config`, `/aws/credentials`). Catches the common case where users store AWS creds without the `.` prefix.

### Changed
- Repository attribution updated from Anthropic placeholders to SharpEdge across README, `.claude-plugin/plugin.json`, and security contact email.
- Version bump to align `plugin.json` with `package.json`, which had drifted.

### Removed
- `check-failing.mjs` (internal diagnostic script, not intended for distribution).
- `.mcp.json` (personal developer config that contained a hardcoded VPS IP). Added to `.gitignore`.

---

## [1.2.0] — earlier

Baseline: three-tier command security model (RED/AMBER/GREEN), OAuth 2.0 + bearer auth, rate limiting, audit logging, PM2 management tools, streamable HTTP transport with EventStore resumability.
