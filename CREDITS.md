# VM Connector — Credits & Acknowledgments

This document lists the open-source dependencies used by the VM Connector and their respective licenses.

---

## Core Dependencies

### @modelcontextprotocol/sdk
- **Purpose:** MCP server framework and protocol implementation
- **Version:** ^1.10.2
- **License:** MIT
- **Author:** Anthropic
- **Homepage:** https://github.com/anthropics/mcp-sdk

### express
- **Purpose:** HTTP server framework for MCP transport
- **Version:** ^4.18.2
- **License:** MIT
- **Author:** TJ Holowaychuk and Express.js contributors
- **Homepage:** https://expressjs.com

### dotenv
- **Purpose:** Environment variable loading from .env files
- **Version:** ^16.4.5
- **License:** BSD-2-Clause
- **Author:** motdotla
- **Homepage:** https://github.com/motdotla/dotenv

---

## Dev Dependencies

### @types/express
- **Purpose:** TypeScript type definitions for Express
- **Version:** ^4.17.21
- **License:** MIT
- **Author:** DefinitelyTyped Contributors
- **Homepage:** https://github.com/DefinitelyTyped/DefinitelyTyped

### @types/node
- **Purpose:** TypeScript type definitions for Node.js
- **Version:** ^20.11.5
- **License:** MIT
- **Author:** DefinitelyTyped Contributors
- **Homepage:** https://github.com/DefinitelyTyped/DefinitelyTyped

### typescript
- **Purpose:** TypeScript compiler
- **Version:** ^5.3.3
- **License:** Apache 2.0
- **Author:** Microsoft
- **Homepage:** https://www.typescriptlang.org

---

## Transitive Dependencies

The following dependencies are included transitively through direct dependencies:

- **accepts** — MIT
- **array-flatten** — MIT
- **body-parser** — MIT
- **bytes** — MIT
- **call-bind** — MIT
- **content-disposition** — MIT
- **content-type** — MIT
- **cookie** — MIT
- **cookie-signature** — MIT
- **debug** — MIT
- **depd** — MIT
- **destroy** — MIT
- **ee-first** — MIT
- **encodeurl** — MIT
- **escape-html** — MIT
- **etag** — MIT
- **finalhandler** — MIT
- **forwarded** — MIT
- **fresh** — MIT
- **function-bind** — MIT
- **get-intrinsic** — MIT
- **has** — MIT
- **has-property-descriptors** — MIT
- **has-proto** — MIT
- **has-symbols** — MIT
- **http-errors** — MIT
- **iconv-lite** — Apache 2.0
- **inherits** — ISC
- **ipaddr.js** — MIT
- **media-typer** — MIT
- **merge-descriptors** — MIT
- **methods** — MIT
- **mime** — MIT
- **mime-db** — MIT
- **mime-types** — MIT
- **ms** — MIT
- **negotiator** — MIT
- **object-inspect** — MIT
- **on-finished** — MIT
- **parseurl** — MIT
- **path-to-regexp** — MIT
- **proxy-addr** — MIT
- **qs** — BSD-3-Clause
- **range-parser** — MIT
- **raw-body** — MIT
- **safe-buffer** — MIT
- **safer-buffer** — MIT
- **send** — MIT
- **serve-static** — MIT
- **setprototypeof** — ISC
- **side-channel** — MIT
- **statuses** — MIT
- **toidentifier** — MIT
- **unpipe** — MIT
- **vary** — MIT

---

## External Tools & Systems

The VM Connector integrates with the following external tools (not bundled, but required at runtime):

### git
- **Purpose:** Version control and deployment source
- **License:** GPL v2
- **Homepage:** https://git-scm.com/
- **Note:** Pre-installed on most Linux systems

### Node.js
- **Purpose:** Runtime environment
- **License:** MIT (Node.js core)
- **Homepage:** https://nodejs.org/
- **Required version:** v18 or later

### npm
- **Purpose:** Package manager
- **License:** Artistic 2.0
- **Homepage:** https://www.npmjs.com/
- **Note:** Included with Node.js

### PM2
- **Purpose:** Process manager (queried but not bundled)
- **License:** AGPL-3.0 (open-source) / Commercial (PM2+)
- **Homepage:** https://pm2.keymetrics.io/
- **Note:** Assumed to be pre-installed on managed VPS

---

## License Summary

| License | Count |
|---|---|
| MIT | ~85% of bundled dependencies |
| Apache 2.0 | 2 (typescript, iconv-lite) |
| BSD-2-Clause | 1 (dotenv) |
| BSD-3-Clause | 1 (qs) |
| ISC | 3+ (inherits, setprototypeof, others) |
| GPL v2 | 1 (git, external tool) |
| AGPL-3.0 | 1 (PM2, external tool, optional) |
| Artistic 2.0 | 1 (npm, external tool) |

**Note:** GPL and AGPL licenses apply only to external tools, not to the VM Connector itself.

---

## How to View Full Dependency Tree

To see the complete dependency tree with versions, run:

```bash
npm list
```

To export a detailed report:

```bash
npm list --depth=0
npm list --all
```

---

## License Compliance

All **bundled** dependencies (in `node_modules`) are permissively licensed (MIT, Apache 2.0, BSD variants, ISC). No GPL or AGPL licenses are present in the compiled VM Connector itself.

The VM Connector is distributed under the MIT License. See LICENSE file in the repository root.

**External tools** (git, Node.js, npm) may have different licenses, but they are not bundled with the VM Connector and are managed separately by your system administrator.

---

## Special Thanks

ForgeRift extends gratitude to:
- **Anthropic** for the Model Context Protocol specification and SDK
- **Express.js contributors** for a robust, battle-tested HTTP framework
- **Node.js core team** for a powerful JavaScript runtime
- **The Linux community** for providing excellent package management and tooling
- **Git developers** for version control excellence
- **PM2 team** for process management capabilities
- **Open-source contributors** worldwide

---

**ForgeRift LLC 2026**

Last updated: April 15, 2026
