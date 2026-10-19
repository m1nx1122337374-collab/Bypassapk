# Bypassapk — Telegram APK Static Analyzer

A small English-language Telegram bot that accepts an APK document and returns a static security review: SHA-256, package/app/version details, SDK levels, declared permissions, component counts, DEX/native-library counts, selected sensitive-permission indicators, manifest hardening findings, and a source-project checklist.

This service **does not** unpack or bypass app protections, decrypt protected payloads, recover keys, modify/rebuild/sign or obfuscate APKs, install apps, or execute uploaded code. It is intended for basic review of apps you own or are authorized to inspect. Manifest findings are advisory, and permission indicators are not proof of malicious behavior.

## Features

- Telegram inline-button menu: **Security Review APK**, **Help**, and **About**.
- English prompts and reports.
- APK metadata and manifest inspection through Androguard, including debuggable/cleartext settings and exported components without an explicit permission.
- Safe source-project recommendations such as release R8, secret handling, exported-component restrictions, HTTPS, and backup-rule review.
- Upload size, ZIP entry-count, and expanded-size limits.
- Temporary local file storage only; the downloaded copy is deleted when analysis finishes.
- A responsive English welcome page at `/`, served by Render and suitable for GitHub Pages.
- Dedicated plain-text health endpoints at `/health` and `/healthz` for Render.
- No token or APK is committed to the repository.

Telegram's hosted Bot API typically limits bot downloads to 20 MB. This project defaults to 19 MB; adjust `MAX_UPLOAD_MB` only if your Telegram Bot API setup supports the larger size.

## Deploy on Render

1. **Revoke the bot token that was posted in chat.** Create a replacement token with BotFather. Treat the exposed token as compromised; do not reuse it.
2. Push this repository to GitHub (or connect this repository directly in Render).
3. In Render, create a new Blueprint from the repository and review `render.yaml`.
4. Set `BOT_TOKEN` in the Render service's Environment settings using the replacement token. It is a secret: never put it in `bot.py`, `render.yaml`, GitHub, or chat.
5. Deploy. Render builds the Docker image and starts `python bot.py`.
6. Open the Render service URL to see the welcome page, then open the Telegram bot and use `/start`.

The static welcome page can also be published with GitHub Pages from the `main` branch and repository root. The default site address is `https://m1nx1122337374-collab.github.io/Bypassapk/`; a custom domain can be attached in the GitHub Pages settings if you own one. The Render site and Telegram bot are separate: the bot process still needs `BOT_TOKEN` and a running Render service.

The blueprint uses a free web-service plan to avoid silently selecting a paid instance. Free services can spin down after inactivity; a polling-based bot may then be unavailable until the service wakes. For reliable always-on bot operation, select an always-on Render instance after reviewing Render's current plan and charges. No Render service has been created by this repository change.

## Environment variables

| Variable | Default | Purpose |
|---|---:|---|
| `BOT_TOKEN` | required | Telegram bot token, set as a Render secret |
| `PORT` | `10000` | HTTP health-check port; Render sets this automatically |
| `MAX_UPLOAD_MB` | `19` | Maximum uploaded APK size |
| `MAX_UNPACKED_MB` | `512` | Maximum summed uncompressed ZIP size inspected |
| `MAX_ZIP_ENTRIES` | `100000` | Maximum archive entries |
| `LOG_LEVEL` | `INFO` | Python logging level |

## Run locally for development

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
export BOT_TOKEN='your-new-token'
python bot.py
```

Keep the token in your shell environment or a local ignored `.env` file; never commit it. The welcome page listens at `/`, while health checks use `/healthz` on `PORT` (defaults to `10000`).

## Privacy and safety

- The bot downloads the user's Telegram document to a temporary directory, analyzes it locally, then removes that temporary copy.
- Telegram itself receives and stores files sent through Telegram; this project cannot control Telegram's retention.
- Do not upload apps unless you have permission to inspect them. Do not treat this basic report as a substitute for a full malware analysis or security review.
- The original Termux unpacking/deprotection suite is intentionally not included in this bot repository. This bot provides advisory static inspection only; it cannot make arbitrary APKs unbreakable or apply source-level protections to a compiled binary.
