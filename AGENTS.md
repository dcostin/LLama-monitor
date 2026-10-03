# Assistant notes — LLama Monitor

This repo is a local model-service status page that the owner clones onto a
machine and then configures **with a coding assistant** to match whatever
models run on that machine. When asked to "set up the monitor for this
machine", follow this file.

## How the app picks what to probe

`services.json` (beside this file) is the single source of probe targets in
standalone mode. One card per entry:

```json
{"kind": "ollama", "name": "Ollama 11434", "port": 11434, "model": "llama3:8b"}
```

- `kind` — one of:
  - `ollama`: Ollama server; probes `/api/tags` + `/api/ps`; `model` is the
    assigned model name shown as Assigned/Loaded; optional `log` is a path to
    an Ollama stderr log for prompt-progress lines.
  - `health`: any OpenAI-compatible local server exposing `/health` with
    `{"model": ..., "context_window": ...}` (mlx-dspark style).
  - `chat`: a chat server exposing `/api/models` (the chatLlama backend);
    probed over HTTPS with certificate verification off (self-signed).
  - `http`: plain reachability probe of `url`; any 2xx counts as up.
- `host` — optional; omit it unless the service runs on another machine than
  the monitor (default: `MONITOR_TARGET_HOST`, itself defaulting to
  `127.0.0.1`).
- `port`, `name` — required for the non-`http` kinds (`url` replaces both for
  `http`).
- `launchd` — optional LaunchAgent label (e.g. `local.mlx-qwen38`); adds an
  Agent running/stopped line plus Start/Stop buttons to the card (health cards).
  Stop is `launchctl disable` + `bootout` — the service stays stopped across
  reboots until Start (`enable` + `bootstrap`) is pressed.

The shipped `services.json` is a working example from the original machine
(Ollama ×3, two local inference servers, one chat server) — replace its
entries with what actually runs here.

## Setup loop

1. Inventory the machine: ask or detect what model servers run (`ollama list`,
   `launchctl list | grep -i ollama`, listening ports via `lsof -iTCP -sTCP:LISTEN`).
2. Rewrite `services.json` to match. Keep `kind` semantics above.
3. Validate: `python3 requirements-check || pip3 install -r requirements.txt`,
   then `./check.py` — it exits 1 on config errors and prints an OK/DOWN line
   per service. Iterate until the config is right (DOWN services may simply be
   stopped; confirm with the user before deleting entries).
4. Run: `./run.sh` → `http://<machine>:7779/`. Access is open by default;
   start with `MONITOR_TOKEN='<long random string>'` to require the token
   (HTTP Basic, any username, token as password).

## Things not to do

- Never commit tokens or private addresses; `MONITOR_TOKEN` is environment-only.
- Do not edit `app.py` when a `services.json` change will do; code edits are
  for new probe kinds only, and should stay small and generic.
- Full mode (passkeys, job control, provider spend) activates only when the
  chatLlama `src` package sits beside this directory — it is intentionally not
  part of this repo; don't try to reimplement it here.
