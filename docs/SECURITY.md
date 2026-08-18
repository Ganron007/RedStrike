# Security

Authorized use only. RedStrike is an offensive-security tool. Do not point it at systems
you are not permitted to test.

## Never commit

These must stay off git (already gitignored where applicable):

| Item | Why |
|---|---|
| `scope.yaml` | Your real targets |
| Engagement seed JSON with real passwords | Credential material |
| `--api-key` values / `REDSTRIKE_API_KEY` | Access to the API |
| SSH private keys (`REDSTRIKE_WS01_SSH_KEY`) | Beachhead access |
| `.env`, `.pypirc`, `dist/` | Secrets and build artifacts |
| CADRE `lab-seed-creds.json` | Lab secrets belong in CADRE, not this repo |

The tracked seed `examples/seed.example.json` uses the placeholder password `CHANGE_ME` on
purpose. Replace it only in a **local** copy.

## API keys

- Generate a key locally (`secrets.token_urlsafe(32)`). See [SETUP.md](SETUP.md) Step 7.
- Documentation uses `$REDSTRIKE_API_KEY`. That is not a real key.
- Bind the API to `127.0.0.1` unless you have a network exposure plan.
- Non-loopback callers must send `X-API-Key` when `--api-key` is set.
- MCP refuses remote `http://` API URLs; use HTTPS off-box.

## What this repository ships

- No CADRE lab IPs as engine defaults.
- No SSH key filenames as defaults.
- Command runners redact password/hash flags in logs and evidence argv.

If you find a real secret in git history, rotate it and open an issue **without** pasting the secret.
