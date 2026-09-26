# LLama Monitor

A small status page for the model services that power a chat server: which
Ollama/Qwen/DSpark models are assigned, loaded, and reachable, plus the chat
servers themselves. It renders as a card grid with a refresh loop and needs no
database.

## Modes

**Standalone (this repo on its own).** Run it on any machine on the same
network as the target host and it probes that host's services over HTTP.
Authentication is one shared token; job control, provider spend cards, restart
buttons, and the target's system health are not available in this mode.

**Full mode (inside the chatLlama checkout).** When the `src` package (the
chat server) is importable next to this directory, the monitor automatically
enables passkey sign-in, the connection log, active chat-job stop/stale
controls, provider spend cards, model restarts, and local system health.

No code changes are needed to switch: the presence of the chat backend is
detected at import time.

## Standalone quick start

```bash
pip install -r requirements.txt
MONITOR_TOKEN='<long random string>' ./run.sh
```

`run.sh` defaults the target to `llama7.local`; the token prompt is HTTP Basic
(any username, the token as password — browsers will offer to remember it).

### Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `MONITOR_TARGET_HOST` | `llama7.local` in `run.sh` (`127.0.0.1` in the app) | Hostname/IP of the machine running the model services |
| `MONITOR_PORT` | `7779` | Port this monitor listens on |
| `MONITOR_TOKEN` | — | Required shared token (standalone mode) |
| `MONITOR_SECRET_KEY` | derived from the token | Flask session secret; set explicitly if you ever enable sessions |

## What it probes on the target

- Ollama on ports 11434/11435/11436 (`/api/tags`, `/api/ps`) — assigned model,
  loaded model, context, VRAM, unload countdown
- Qwen/MLX-DSpark on 11232/11233 (`/health`)
- Chat servers on 7777/7778 (`/api/models`)

All services must be reachable from the machine running the monitor (they bind
`0.0.0.0` by default). The chat servers use self-signed certificates; the
monitor skips certificate verification for those probes.

## Security notes

- The token is the only barrier in standalone mode; serve it on a trusted LAN
  or behind a VPN/TLS reverse proxy if that matters to you.
- The page is marked `noindex, nofollow` and the monitor never exposes model
  prompts or chat content in standalone mode.
