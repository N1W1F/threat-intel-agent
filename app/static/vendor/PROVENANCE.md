# Vendored third-party files

## three.min.js

- Source: `https://unpkg.com/three@0.160.0/build/three.min.js`
- Version: three.js r160
- License: MIT (Three.js Authors, 2010-2023)
- Fetched once at development time (2026-07-21), vendored locally, never fetched over the network at app runtime. Served same-origin (`'self'`) — fully compliant with this app's CSP (`script-src 'self'`), no CDN dependency.
- Used for: the 3D interactive dashboard elements (see docs/PRD-3D-interactive-redesign.md, Tier B).
- To update: re-download from `https://unpkg.com/three@<version>/build/three.min.js`, review the diff, replace this file, re-test the 3D scene manually (no automated coverage for WebGL rendering).
