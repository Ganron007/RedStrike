"""Static cockpit bundle (Phase 11.1) — served by the API at /ui/.

`dist/` holds the pre-built SPA (index.html + styles.css + app.js +
vendored Cytoscape). No Node.js runtime is needed to serve it; FastAPI's
StaticFiles mounts it when present.
"""
