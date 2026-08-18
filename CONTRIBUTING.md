# Contributing

Read [`docs/SETUP.md`](docs/SETUP.md) and [`docs/SECURITY.md`](docs/SECURITY.md) first.

- Do not commit `scope.yaml`, `.env`, API keys, SSH private keys, or engagement passwords.
- Keep the version in `pyproject.toml` equal to `redstrike/__init__.py`.
- `ruff check .` and `pytest -q` must pass (CI installs ruff 0.16).
- Do not tag or upload to PyPI until the operator asks. See [`docs/RELEASE.md`](docs/RELEASE.md).

The public import is `redstrike`. CADRE campaign runs use a pin of this engine
(`CADRE/tools/red-strike/`). After a feature lands here, copy it into that pin.
See [`docs/CADRE-PIN.md`](docs/CADRE-PIN.md).
