# Contributing

Public setup is in [`docs/SETUP.md`](docs/SETUP.md). Secrets: [`docs/SECURITY.md`](docs/SECURITY.md).

- Do not commit `scope.yaml`, `.env`, API keys, SSH private keys, or engagement passwords.
- Keep `pyproject.toml` version equal to `redstrike/__init__.py`.
- `ruff check .` and `pytest -q` must pass.
- Do not tag or upload to PyPI until the operator asks. See [`docs/RELEASE.md`](docs/RELEASE.md).

CADRE Plan 01 uses a **pin** of this engine, not this clone. After features merge here,
sync them into `CADRE/tools/red-strike/` ([`docs/CADRE-PIN.md`](docs/CADRE-PIN.md)).
