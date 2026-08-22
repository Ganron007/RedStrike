# Security

Authorized use only. Do not point RedStrike at systems you are not permitted to test.
See the notice at the top of the [README](../README.md).

## Never Commit

These must stay off git (already gitignored where applicable):

| Item | Why |
|---|---|
| `scope.yaml` | Your real target IP/CIDRs and domains |
| Engagement seed JSON with real passwords | Credential material and NT hashes |
| `--api-key` values / `REDSTRIKE_API_KEY` | Access to the API and FastMCP server |
| SSH private keys (`REDSTRIKE_WS01_SSH_KEY`) | Windows beachhead host access |
| `.env`, `.pypirc`, `dist/` | Secrets and build artifacts |
| Custom engagement graphs with real target names | Customer infrastructure data |

The tracked seed `examples/seed.example.json` uses the placeholder password `CHANGE_ME` on
purpose. Replace it only in a **local** copy.

## API Keys & Network Trust

- Generate a key locally (`secrets.token_urlsafe(32)`). See [SETUP.md](SETUP.md).
- Documentation uses `$REDSTRIKE_API_KEY`. That is an environment placeholder, not a committed secret.
- Bind the API to `127.0.0.1` unless you have a deliberate network exposure plan.
- Non-loopback callers must send `X-API-Key` when `--api-key` is configured.
- FastMCP refuses remote plain `http://` API URLs; use HTTPS off-box.

## Public Release Invariants

- No internal lab IPs, domain names, or accounts as engine defaults.
- No hardcoded SSH key filenames or paths in code defaults.
- Subprocess runners automatically redact password and hash flags in logs and evidence argv.

If you find a real secret in git history, rotate it immediately and open an issue **without** pasting the secret.
