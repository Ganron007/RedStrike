# Setup (new users)

This is the full install path for **standalone RedStrike**. Read [SECURITY.md](SECURITY.md)
before you start an API or a live run.

---

## What you will have at the end

1. A Python virtualenv with RedStrike installed.
2. A **local** `scope.yaml` that lists only hosts you are allowed to test (never committed).
3. A passing `redstrike check` (core / dry-run ready).
4. A campaign **dry-run** against the bundled demo graph (no extra tools).
5. (Optional) API on loopback, and later live `--execute` once operator tools are on PATH.

---

## Step 0 — Prerequisites

| Need | Notes |
|---|---|
| Python **3.10 or newer** | `python --version` / `python3 --version` |
| Git | To clone this repository |
| An **authorized** lab | Only systems you have permission to assess |
| (Windows campaign scripts) | Git Bash or WSL so `bash` is on PATH |
| (Live `--execute` later) | NetExec (`nxc`), Certipy, bloodyAD — **not** required for dry-run |

Confirm Python:

```bash
python --version
```

On some Linux installs the binary is `python3`. Use that everywhere below if so.

---

## Step 1 — Clone

```bash
git clone https://github.com/Ganron007/RedStrike.git
cd RedStrike
```

---

## Step 2 — Virtual environment

**Linux / macOS:**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

**Windows (PowerShell):**

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

If PowerShell blocks the script, run `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` once,
or use `.\.venv\Scripts\python.exe -m pip ...` without activating.

`.venv/` is gitignored. Do not commit it.

---

## Step 3 — Install RedStrike

From the repository root, with the venv active:

```bash
python -m pip install --upgrade pip
pip install -e ".[dev,mcp]"
```

- Default extra is enough for the API and campaign CLI.
- `[dev]` adds pytest and ruff.
- `[mcp]` adds the MCP server extra.

Confirm the CLIs exist:

```bash
redstrike --help
redstrike-api --help
redstrike-campaign --help
```

Python import:

```bash
python -c "import redstrike; print(redstrike.__version__)"
```

You should see `0.6.0` (or newer). The Python import is `redstrike`.

---

## Step 4 — `redstrike check`

```bash
redstrike check
```

Read the three blocks:

| Block | Meaning |
|---|---|
| **Core** | Package, demo graph, demo seed, demo scripts. All `ok` → dry-run is possible. |
| **Scope** | `todo` until you copy `scope.yaml` (next step). That is expected on a fresh clone. |
| **Operator tools** | `missing` is fine for dry-run. Required only for live `--execute`. |

Exit code `0` means core is OK. `redstrike check --execute-ready` exits non-zero if PATH tools are missing.

JSON (for scripts):

```bash
redstrike check --json
```

---

## Step 5 — Create **your** scope file

RedStrike will not guess your lab. Copy the example and edit it:

**Linux / macOS:**

```bash
cp examples/scope.example.yaml scope.yaml
```

**Windows (PowerShell):**

```powershell
Copy-Item examples\scope.example.yaml scope.yaml
```

Open `scope.yaml` and set:

- `allowed_targets` — IPs or hostnames you are authorized to hit
- `allowed_domains` — AD DNS names in scope
- keep `allow_high_risk: false` until you deliberately choose a `campaign` profile

`scope.yaml` is **gitignored**. Never commit it. Never put API keys or passwords in it.

Built-in profiles (passed with `--profile`; your YAML overlays them):

| Profile | Default use |
|---|---|
| `gated` | Safe profile (Default). Read-only observe/assess. High-risk jumps pause for HITL approval. **Start here.** |
| `autonomous` | Unrestricted AI agency under `scope.yaml` IP/CIDRs. |
| `standalone` | Alias for `gated`. |
| `campaign` | Alias for `autonomous`. |
| `lab-ungated` | Opt-in fully ungated execution. **Requires** non-empty targets and domains in `scope.yaml` (`--ungated --scope`). |
| `validate-gated` | Like `gated` with longer cooldowns and validation mode enabled. |

After you save `scope.yaml`:

```bash
redstrike check --scope scope.yaml
```

The Scope line should show `ok`.

---

## Step 6 — Campaign dry-run (no extra tools)

This uses only files in `examples/`. It does **not** talk to a real DC if you leave it as dry-run
(the default). It proves the orchestrator, ledger, and graph loader.

```bash
redstrike-campaign run --phase 1-3 --beachhead windows --operator provisioning --engage demo \
  --graph examples/campaign-graph.m1.yaml \
  --seed examples/seed.example.json \
  --automation-root examples/automation
```

You should see `[DRY-RUN]` and `DEMO-RECON` / `DEMO-CREDS` / `DEMO-EXEC` / `DEMO-LATERAL` as `OK`.

The example seed password is the placeholder `CHANGE_ME`. Replace it in a **local** seed file
for a real engagement; do not commit real passwords. See [SECURITY.md](SECURITY.md).

---

## Step 7 — HTTP API (optional)

Generate a **local** API key. Do not reuse the documentation placeholder. Do not commit the key.

**Linux / macOS:**

```bash
export REDSTRIKE_API_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
redstrike-api --scope scope.yaml --profile standalone --api-key "$REDSTRIKE_API_KEY" --host 127.0.0.1 --port 8890
```

**Windows (PowerShell):**

```powershell
$env:REDSTRIKE_API_KEY = python -c "import secrets; print(secrets.token_urlsafe(32))"
redstrike-api --scope scope.yaml --profile standalone --api-key $env:REDSTRIKE_API_KEY --host 127.0.0.1 --port 8890
```

Keep the process bound to `127.0.0.1` unless you have a deliberate exposure plan.

In another terminal (venv active), health:

```bash
curl http://127.0.0.1:8890/health
```

Example call (loopback may omit the key; non-loopback **must** send it):

```bash
curl -X POST http://127.0.0.1:8890/ad/users \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $REDSTRIKE_API_KEY" \
  -d "{\"target\":\"dc.example.lab\",\"domain\":\"example.lab\",\"username\":\"operator_user\",\"password\":\"<REDACTED>\"}"
```

Replace `dc.example.lab` / `example.lab` with hosts already listed in **your** `scope.yaml`.
Live enumeration needs `nxc` on PATH.

MCP (optional), after the API is up:

```bash
redstrike-mcp --api http://127.0.0.1:8890
```

A sample client snippet is in `redstrike/api/redstrike-mcp.json`. Point it at loopback only.

---

## Step 8 — Live `--execute` (optional, HITL)

Dry-run does not need NetExec or Certipy. Live runs do.

1. Install the tools **you** use from upstream (NetExec, Certipy, bloodyAD, OpenSSH, bash).
2. Confirm:

```bash
redstrike check --execute-ready
```

3. Point `--graph`, `--seed`, and `--automation-root` at **your** engagement files, not at
   someone else's lab secrets.
4. Run with `--execute`. Privilege jumps pause until:

```bash
redstrike graph approve --gate dcsync --engage YOUR_ENGAGE_ID
```

Do not bypass HITL on public or shared infrastructure.

Autonomous / Ungated option (scope is mandatory):

```bash
redstrike-api --ungated --scope scope.yaml --host 127.0.0.1 --port 8890
redstrike graph run --profile autonomous --scope scope.yaml --execute ...
```

Optional SSH to a Windows beachhead (no defaults in this repo):

```bash
export REDSTRIKE_WS01_HOST="your-host"
export REDSTRIKE_WS01_USER="your-user"
export REDSTRIKE_WS01_SSH_KEY="/path/to/private-key"
```

---

## Practice on a lab you own

Standalone RedStrike can target **any authorized lab** if **you** write the graph, seed,
and scope. Do not copy lab password files into this git tree.

---

## Docker Quickstart (Containerized)

If you prefer running RedStrike inside a self-contained container with all AD dependencies pre-installed:

```bash
# Build local container
docker build -t redstrike .

# Run diagnostics
docker run --rm -it redstrike check

# Run API service
docker run --rm -it -p 8890:8890 redstrike api --host 0.0.0.0 --port 8890
```

---

## Troubleshooting

| Symptom | What to do |
|---|---|
| `redstrike: command not found` | Activate `.venv` and re-run `pip install -e ".[dev,mcp]"` |
| `Unknown scope policy profile` | Use `standalone` or `campaign` (see Step 5) |
| Scope line stays `todo` | You are not passing `--scope scope.yaml`, or the file is missing |
| Dry-run looks for scripts under cwd | Pass `--automation-root examples/automation` |
| `--execute` pauses immediately | Approve the HITL gate named in `pending_gate` |
| API `401` from another host | Send `X-API-Key` matching `--api-key`; prefer loopback |

---

## Next reading

- [PRACTICE-GUIDE.md](PRACTICE-GUIDE.md) — Comprehensive hands-on field practice & study guide
- [SECURITY.md](SECURITY.md) — keys, gitignore, redaction
- [README.md](../README.md) — product overview, API, safety model
- [RELEASE.md](RELEASE.md) — tagging (maintainers)
