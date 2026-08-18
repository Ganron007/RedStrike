# Standalone product vs CADRE campaign pin

RedStrike is a standalone product. CADRE is an optional lab that can consume it.
Do not mix the two install paths.

## Standalone (this GitHub repo)

- Clone `https://github.com/Ganron007/RedStrike.git`
- Install with `pip install -e ".[dev,mcp]"`
- Bring your own graph, seed, and `scope.yaml` (or use `examples/`)
- You may point at **any authorized lab**, including CADRE VMs, as a **practice** run
- `CADRE_ROOT` is optional glue only; it is **not** CADRE Plan 01

## CADRE Plan 01 (integrated pin)

- Engine: `CADRE/tools/red-strike/` (nested git; ignored by the parent CADRE repo)
- Graph / seeds / scripts: CADRE `attack-matrix/Campaign/automation/` and `04-automation/`
- Workflow: CADRE `attack-matrix/Campaign/Red-Strike-workflow.md`
- After a feature lands **here**, copy it into the pin. The pin does not invent engine features.

## Maintainer sync (after this repo changes)

From a machine that has both checkouts:

1. Land and test the change in **this** repo (`ruff`, `pytest`, `redstrike check`).
2. Copy the engine tree into `CADRE/tools/red-strike/` (exclude `.venv`, `__pycache__`).
3. Re-run `pytest` in the pin.
4. CADRE campaign docs stay in CADRE — do not move lab seeds into this public tree.
