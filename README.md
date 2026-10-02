# Llama Monitor

This is a local model-service status page that allows monitoring of various local AI model services like Ollama, health endpoints, and chat servers.

## Setup

1. First, determine what model servers are running on your machine:
   - Check for Ollama: `ollama list` or `launchctl list | grep -i ollama`
   - Check listening ports: `lsof -iTCP -sTCP:LISTEN`

2. Update `services.json` to match your running services

3. Run the setup validation:
   ```bash
   python3 requirements-check || pip3 install -r requirements.txt
   ./check.py
   ```

4. Finally, run the monitor:
   ```bash
   ./run.sh
   ```

The monitor will be available at `http://<machine>:7779/`. Access is open by
default; to require a shared token again, start it with
`MONITOR_TOKEN='<long random string>' ./run.sh` (HTTP Basic, any username,
token as password).

## Services Configuration

The `services.json` file defines what services to monitor:

- `ollama`: Ollama server; probes `/api/tags` + `/api/ps`; `model` is the assigned model name shown as Assigned/Loaded
- `health`: any OpenAI-compatible local server exposing `/health` with `{"model": ..., "context_window": ...}`
- `chat`: a chat server exposing `/api/models` (the chatLlama backend); probed over HTTPS with certificate verification off
- `http`: plain reachability probe of `url`; any 2xx counts as up

## Files

- `services.json` - Configuration file defining what services to monitor
- `check.py` - Validation script that checks service configuration and connectivity
- `run.sh` - Main run script for the monitor server
- `requirements-check` - Script to check Python dependencies