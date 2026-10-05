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

Read the four blocks:

| Block | Meaning |
|---|---|
| **Core (dry-run / API)** | Package, demo graph, demo seed, demo scripts (`ok`/`FAIL`). All `ok` → dry-run is possible. |
| **Scope (create your own policy)** | `todo` until you copy `scope.yaml` (next step). That is expected on a fresh clone. |
| **Operator tools (live `--execute` only)** | `missing` is fine for dry-run. `nxc`/`netexec`, `certipy`, `bloodyAD`, plus `ssh`/`bash` are required only for live `--execute`. |
| **Toolchain manifest** | Per-tool install recipes and version probes (`ok`/`WARN`/`missing`). |

Exit codes: `0` core OK; `1` core fail; `2` `--execute-ready` PATH tools missing; `3` `--version-gated` manifest mismatch. Useful flags: `--json`, `--version-gated`, `--ungated`.

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
| `lab-readonly` | Gated read-only variant. |
| `validate-gated` | `observe`+`assess`+`validate` with high-risk ON (unlike `gated`) and longer cooldowns. |
| `adcs-deep` | ADCS-focused (`assess`+`validate`, high-risk ON). |
| `forest-trust-review` | Cross-forest review (`observe`+`assess`, high-risk OFF). |
| `ungated` | Alias for `lab-ungated`. |

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
redstrike-campaign run --phase 1-3 --beachhead windows --operator linux --engage demo \
  --graph examples/campaign-graph.m1.yaml \
  --seed examples/seed.example.json \
  --automation-root examples/automation
```

You should see `[DRY-RUN]` with `DEMO-RECON` / `DEMO-CREDS` / `DEMO-EXEC` / `DEMO-LATERAL` as `[PLAN]` steps. `[OK]` appears only for live-verified steps (`--execute`); `[GATE]`/`[SKIP]`/`[FAIL]` otherwise.

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
export REDSTRIKE_WINDOWS_HOST="your-host"
export REDSTRIKE_WINDOWS_USER="your-user"
export REDSTRIKE_WINDOWS_SSH_KEY="/path/to/private-key"
```

---

## Step 9 (Optional) — C2-Enabled Mode with C2Stack

For in-memory post-exploitation, lateral movement, and covert egress without dropping binaries to disk, RedStrike natively integrates with **[C2Stack](https://github.com/Ganron007/C2Stack)** across all five of its frameworks: **Sliver** (v1.7.7), **Meridian**, **Mythic** (Apollo), **Havoc**, and **Adaptix**.

### 1. Launch C2Stack
Clone and start the C2 teamservers (Docker-based; the bootstrap copies `.env.example` → `.env`, builds the images, and starts the stack):
```bash
git clone https://github.com/Ganron007/C2Stack.git
cd C2Stack/Docker
./docker-bootstrap.ps1          # Windows: redirector + meridian + sliver + havoc
./docker-bootstrap.ps1 -All     # all five frameworks (Mythic pulls, Adaptix builds ~5 min)
# Linux/macOS: ./docker-bootstrap.sh [--all]
```

### 2. Run RedStrike in C2 Mode
```bash
# Sliver in-memory .NET assembly execution (Rubeus, SharpHound, Seatbelt)
#   requires sliver-client on PATH with the C2Stack operator config imported
redstrike graph run --engage default --beachhead windows --phase 1-3 --c2 --c2-backend sliver --c2-session <sliver-session-id>

# Meridian covert DNS TXT tunneling & HTTP (driven through its container CLI)
redstrike graph run --engage default --beachhead windows --phase 1-3 --c2 --c2-backend meridian \
  --c2-endpoint "docker exec -i c2stack-meridian-1 meridian"

# Mythic (Apollo agents) via REST webhooks (container port 17443, host-published as 7443);
# set MYTHIC_USERNAME / MYTHIC_PASSWORD (defaults mythic_admin / mythic)
redstrike graph run --engage default --beachhead windows --phase 1-3 --c2 --c2-backend mythic --c2-session <callback-id> \
  --c2-endpoint http://127.0.0.1:7443

# Havoc & Adaptix have no direct operator REST API — RedStrike drives them through
# C2Stack's Flight Control portal (http://127.0.0.1:8000, override with C2STACK_PORTAL_URL)
redstrike graph run --engage default --beachhead windows --phase 1-3 --c2 --c2-backend havoc  --c2-endpoint http://127.0.0.1:8000
redstrike graph run --engage default --beachhead windows --phase 1-3 --c2 --c2-backend adaptix --c2-endpoint http://127.0.0.1:8000
```

Notes:
- The Flight Control portal also exposes a unified live session table (`GET /api/ops/sessions`) across all five frameworks — handy for discovering session ids before tasking.
- Havoc in-memory .NET execution (`dotnet`) requires the assembly staged inside the portal container first: `docker cp <assembly> c2stack-portal-1:/tmp/`.
- Mythic task output is read from Mythic's `response` table via the `c2stack-mythic_postgres-1` container; lateral movement goes through `c2.mythic.psexec` (agent command tasking — where the agent lacks it, use `shell` + `sc.exe`).

### 3. (Optional) Entra ID / hybrid tooling

`redstrike check --version-gated` covers the Phase 9 hybrid category. Install what your engagement needs:

- **Azure CLI** — `az rest`/`az login` (any current 2.x).
- **AzureHound v2** (SpectreOps BloodHound CE) — `azurehound list -u <user> -p <pass> -t <tenant> -o out.json` (flags after `list`, per the upstream README); for CLI-auth, acquire a token with `az account get-access-token --resource https://graph.microsoft.com` and pass `--jwt` (there is no `--az-cli-auth` flag).
- **ROADtools** — `pip install roadtools`; `roadrecon auth` (password, `--device-code -c <client-id>` per the CARTP lab, `--access-token`, or `--prt`) writes `.roadtools_auth`; `roadrecon gather` builds `roadrecon.db`. The **roadtx** hybrid flows (cloud-Kerberos-trust chain per the HackTricks/dirkjanm research) are driven by `entra.roadtx_gettokens` (`-r aadgraph`) and `entra.roadtx_prt` (`--key-pem`/`--cert-pem`), with the research's standalone scripts (`modifyuser.py`, `partialtofulltgt.py`) via the `entra.hybrid_script` raw shim.
- **Monkey365 / GraphRunner** — course tools (CARTP LO7 / CARTE device-code phishing): `entra.monkey365` and `entra.graphrunner` wrap the lab-documented invocations; MFASweep.ps1 is manifest-tracked.
- **Token caches** — `entra.token_artifacts` locates Azure/MSAL token caches (filenames per HackTricks' Azure post-exploitation notes) under an operator-supplied root; harvested JWTs land in the ledger as `cred_type: token`.
- **AADInternals** — `Install-Module AADInternals` (PowerShell); probed via `Get-Module -ListAvailable` (verified live at 0.9.7; recommended 0.11.0).
- **ADFS spray** — no canonical tool (forge your own choice); drive it with the raw-args shim `entra.adfs_spray`.

Cloud runs fail closed until `scope.yaml` lists `allowed_tenants` (and/or `allowed_cloud_domains`); the cloud-takeover step (`entra.kerberos_ticket`) is additionally gated by the `cloud_takeover` HITL gate.

### 4. Build, stage, and inspect the stack (`redstrike c2`)

RedStrike drives the whole C2Stack lifecycle through its Flight Control API — implant builds, file staging, fleet view, and redirector checks:

```bash
redstrike c2 status                                        # container health
redstrike c2 sessions                                      # unified fleet (all frameworks)
redstrike c2 build --backend sliver --retrieve --out ./impl.exe
redstrike c2 build --backend havoc --out ./demon.exe
redstrike c2 build --backend adaptix --listener cadre_http --out ./beacon.exe
redstrike c2 build --backend mythic --out ./apollo.exe     # async: polled then downloaded
redstrike c2 stage ./payload.o                             # Mythic agent_file_id for COFF/assembly tasking
redstrike c2 task --backend havoc --session <id> --command "whoami"
```

`--c2` runs can also self-configure: omitting `--c2-session` auto-selects the first live session for the chosen backend, and `--c2-backend auto` picks the first framework in preference order (sliver → havoc → adaptix → mythic → meridian) that has a live session.

---

## Tool provisioning — where tools live and how they get there

RedStrike carries **adapters + pins + recipes**, not vendored binaries. Three execution domains, three provisioning tiers:

| Domain | What runs there | Provisioning |
|---|---|---|
| **Linux operator host** | nxc, certipy, bloodyAD, impacket, kerbrute, az, azurehound, roadtools/roadtx | `redstrike check` shows the manifest `install` recipe per tool (pip/apt/go). Optional: point execution at a **container** (e.g. C2Stack's Kali workstation) with `REDSTRIKE_LINUX_CONTAINER=c2stack-kali` — every Linux tool then runs via `docker exec -i c2stack-kali …`, `redstrike check` probes versions *inside* the container, and `ssh`/`scp`/`bash` are never wrapped. |
| **Windows beachhead (windows target)** | Rubeus.exe, SharpSCCM.exe, mimikatz.exe, SharpHound.exe, AADInternals/GraphRunner/MFASweep PS modules | (1) install manually; (2) **tools-dir autodiscovery** — set `REDSTRIKE_WINDOWS_TOOLS_DIR=C:\Tools` and bare `.exe` names in intents resolve to that directory at run time (multi-dir: `C:\Tools;D:\RedTeam`, first entry wins); `redstrike check` SSH-probes presence there when `REDSTRIKE_WINDOWS_HOST` is set; (3) **`redstrike stage`** — `--plan` shows the tooling plan; `--download` fetches the **sha256-pinned** upstream artifact (SharpHound 2.17.0, mimikatz 2.2.0, SharpSCCM 2.0.14), verifies, extracts from the zip, and scp's it into the tools dir; `--file` stages operator-supplied binaries and **records** their hash (Rubeus has no upstream binary release — compile or verify a mirror). |
| **C2 sessions** | assemblies/BOFs/beacons | `redstrike c2 stage` + the C2 build endpoints (Phase 8) |

Pin semantics, stated plainly: a `sha256` in the manifest covers the **downloaded artifact**; archive-shipped tools (mimikatz, SharpHound) are verified at download time, and a `--file` input is the extracted binary whose hash is recorded (never silently claimed as "verified"). Downloads happen on the operator host (lab VMs often lack egress) and are pushed over SSH.

```bash
redstrike check                                  # recipes + presence (container/windows-target/ssh aware)
redstrike install --plan                         # Linux host: what runs vs what is manual
redstrike install --apply [--only certipy,impacket]   # runs the pip/go recipes on the Linux target
redstrike stage --plan                           # what goes to the beachhead and from where
redstrike stage --tool sharphound --download     # fetch → sha256 verify → extract → scp
redstrike stage --tool rubeus --file ./Rubeus.exe
```

**Linux host provisioning** (`redstrike install`) executes the manifest recipes on whichever Linux target the transport selects — local, `docker exec` container, or the `REDSTRIKE_LINUX_SSH` remote host — using the same CommandRunner dispatch as tool execution (so ssh wrapping/redaction are identical). Prose recipes (Azure CLI installer notes, PowerShell modules, operator-supplied scripts) are listed as *manual* and never guessed at.

### Topology matrix (engine host × tool target)

RedStrike runs on Windows or Linux and reaches tools locally or remotely. `redstrike check --json` reports the active topology under `topology`:

| Engine runs on | Linux tools | Windows tools | Configuration |
|---|---|---|---|
| **Kali (native)** | local PATH | windows target over SSH (or C2 sessions) | `REDSTRIKE_WINDOWS_*` |
| **Kali + C2Stack Kali container** | `docker exec -i c2stack-kali …` | windows target over SSH | `REDSTRIKE_LINUX_CONTAINER=c2stack-kali` |
| **Windows → remote Kali** | ssh to the Kali VM/container | local dir (engine is on the Windows host) or remote windows target | `REDSTRIKE_LINUX_SSH=user@kali` (+`REDSTRIKE_LINUX_SSH_KEY`, `:port`/`REDSTRIKE_LINUX_SSH_PORT`) and/or `REDSTRIKE_LOCAL_TOOLS_DIR=C:\Tools` |
| **Windows (assumed-breach host, e.g. the assumed-breach workstation itself)** | ssh out to Kali if needed | local directory / PATH on that host | `REDSTRIKE_LOCAL_TOOLS_DIR` (or `--operator windows` for campaign steps) |
| **Linux tool-host VM (AD-network-adjacent)** | local — this box IS the tool host; `redstrike install --apply` provisions it | the windows target at its lab address (SSH user per lab config) | run RedStrike on the box, or point `REDSTRIKE_LINUX_SSH=user@prov.vm` at it from Windows; `--operator linux` for campaign scripts |

Environment reference (all optional; exactly one of container/ssh for Linux):

| Variable | Meaning |
|---|---|
| `REDSTRIKE_LOCAL_TOOLS_DIR` | `;`-separated local tool dirs; resolution fallback when a bare name is not on PATH (works on Windows and Linux) |
| `REDSTRIKE_LINUX_CONTAINER` | run Linux tools via `docker exec -i <name>` (e.g. `c2stack-kali`) |
| `REDSTRIKE_LINUX_SSH` | `user@host[:port]` — run Linux tools on a REMOTE host over SSH (ssh/scp/bash are never wrapped); mutually exclusive with the container |
| `REDSTRIKE_LINUX_SSH_KEY` | SSH key for the remote Linux tool host |
| `REDSTRIKE_LINUX_SSH_PORT` / `REDSTRIKE_LINUX_SSH_KNOWN_HOSTS` | SSH port override / strict host-key file for the remote Linux tool host |
| `REDSTRIKE_WINDOWS_HOST` / `_USER` / `_SSH_KEY` | Windows target transport + tool host |
| `REDSTRIKE_WINDOWS_SSH` | SSH-wrap kill-switch for the Windows target (`1` default; `0`/`false`/`no`/`off` disables the SSH wrap) |
| `REDSTRIKE_SSH_BIN` | SSH client binary name/path (default `ssh`) |
| `REDSTRIKE_OPERATOR` | Override operator auto-detect (`linux` / `windows` / `c2`) |
| `REDSTRIKE_WINDOWS_TOOLS_DIR` | Windows tool directory (`;`-separated; first entry used); intents resolve bare `.exe` names there and `redstrike check` probes it over SSH |
| `REDSTRIKE_WINDOWS_KNOWN_HOSTS` | pin the beachhead host key (strict checking) instead of accept-new |
| `REDSTRIKE_LINUX_TOOLS_DIR` | tool directory on the container/ssh Linux target (e.g. an isolated venv bin) — bare names resolve there instead of the host PATH |

**Isolated toolchain (recommended for a dedicated attack box):** `redstrike install --apply --venv /opt/redstrike/venv` creates a venv on the target, installs the pip tools there (go/apt recipes stay system), and prints the `REDSTRIKE_LINUX_TOOLS_DIR=/opt/redstrike/venv/bin` to export — so RedStrike never depends on the host's system packages.

**Running under WSL on Windows:** no special support needed — WSL *is* a Linux host for RedStrike, and Windows tools are reachable through interop by pointing the local tools dir at the mounted drive: `REDSTRIKE_LOCAL_TOOLS_DIR=/mnt/c/Tools`. Bare `.exe` names then resolve to Windows binaries and execute through WSL interop.

Setting up the remote Kali side (once, on the Kali VM): `sudo apt install -y openssh-server && sudo systemctl enable --now ssh`, add your public key to `~/.ssh/authorized_keys`, then confirm: `ssh -i <key> user@kali 'command -v certipy || echo missing'`. `redstrike check` will probe each manifest tool over that SSH session and report versions.

---

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
| `Unknown scope policy profile` | Use a known profile (`gated`, `autonomous`, `lab-ungated`, `validate-gated`, `adcs-deep`, `forest-trust-review`, aliases `standalone`, `campaign`, `ungated`) — see Step 5 |
| Scope line stays `todo` | You are not passing `--scope scope.yaml`, or the file is missing |
| Dry-run looks for scripts under cwd | Pass `--automation-root examples/automation` |
| `--execute` pauses immediately | Approve the HITL gate named in `pending_gate` |
| API `401` from another host | Send `X-API-Key` matching `--api-key`; prefer loopback |

---

## Practice on a lab you own

RedStrike targets operator-owned lab environments: create your own scope policy, seed
credentials, and run the graphs in `examples/` against hosts you are authorized to test.
The C2Stack lab (Sliver/Meridian/Havoc/Adaptix/Mythic behind a redirector) is the reference
practice range — see the C2Stack practice guide for its walkthroughs.

---

## Next reading

- [PRACTICE-GUIDE.md](PRACTICE-GUIDE.md) — Comprehensive hands-on field practice & study guide
- [SECURITY.md](SECURITY.md) — keys, gitignore, redaction
- [README.md](../README.md) — product overview, API, safety model
- [RELEASE.md](RELEASE.md) — tagging (maintainers)
