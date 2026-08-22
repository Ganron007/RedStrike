# Release

Current version lives in **both** `pyproject.toml` and `redstrike/__init__.py` (keep them equal).

Do not tag or upload to PyPI until the operator asks. Deployment tests come later.

## Public-tree checklist (run before a GitHub push)

1. `ruff check .`
2. `pytest -q`
3. `redstrike check` — core must be `ok`
4. README version badge matches `pyproject.toml`
5. Secret scan on **tracked** files: no lab IPs, no private SSH keys, no live API keys, no real passwords
6. `scope.yaml` is gitignored and untracked
7. Docs: [SETUP.md](SETUP.md) + [SECURITY.md](SECURITY.md) still match the CLIs

## GitHub tag (operator)

```bash
git tag -a v0.6.0 -m "RedStrike 0.6.0"
git push origin v0.6.0
```

Create the GitHub release from that tag.

## PyPI (optional, operator)

Distribution name: `redstrike`. No trusted publisher is configured yet.

```bash
pip install build twine
python -m build
twine check dist/*
# twine upload dist/*   # only with credentials the operator provides
```

Do not commit `dist/` or `.pypirc`.
