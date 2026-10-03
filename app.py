from flask import Flask, jsonify, redirect, render_template_string, request, send_from_directory, session
import datetime, fcntl, hmac, json, os, plistlib, re, subprocess, time
from zoneinfo import ZoneInfo
import requests
import psutil
import urllib3
import threading
from functools import wraps

# Full mode: running beside the chat server inside the chatLlama checkout —
# passkey auth, job control, provider spend, and model restarts. Standalone
# mode (this package published on its own): read-only probing of a target
# host over the network with token auth.
try:
    from src import backend as chat_backend
except ImportError:
    chat_backend = None

FULL_MODE = chat_backend is not None
MONITOR_TOKEN = os.getenv('MONITOR_TOKEN', '')
TARGET_HOST = os.getenv('MONITOR_TARGET_HOST', '127.0.0.1')
TARGET_LOCAL = TARGET_HOST in ('127.0.0.1', 'localhost', '::1')
PACKAGE_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(PACKAGE_DIR)
# Full mode keeps its data/secrets beside the chat server; a standalone clone
# keeps them inside itself.
_BASE_DIR = REPO_ROOT if FULL_MODE else PACKAGE_DIR

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
if FULL_MODE:
    app.secret_key = chat_backend.app.secret_key
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Lax',
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_DOMAIN='.77llamas.ai',
    )
else:
    # Sessions are unused in standalone mode (HTTP Basic auth); the key only
    # needs to be stable per deployment.
    app.secret_key = os.getenv('MONITOR_SECRET_KEY') or f'{MONITOR_TOKEN}-standalone-monitor'

@app.after_request
def _no_robots(response):
    response.headers.setdefault('X-Robots-Tag', 'noindex, nofollow')
    return response
def _monitor_auth_login_complete():
    response = chat_backend.auth_login_complete()
    if getattr(response, 'status_code', 500) < 300:
        user = chat_backend._session_user()
        # The first monitor visit is logged before the user has an identity.
        # Carry that visit through the passkey ceremony so the successful
        # authentication is visible as the next monitor-log event.
        had_unauthenticated_visit = bool(session.pop('monitor_unauthenticated_visit', None))
        if user and (had_unauthenticated_visit or _has_blocked_monitor_attempt(user)):
            _monitor_access_log(user, event='successful login')
            if f"{user['username']} (#{user['id']})" in _monitor_allowed_labels():
                session['monitor_access_identity'] = f"{user['username']} (#{user['id']})"
    return response

# Reuse the main server's passkey endpoints and database. The RP ID/origins
# are shared at the parent domain so ceremonies can begin on either host.
if chat_backend:
    for auth_path, auth_endpoint, auth_methods in (
        ('/api/auth/status', 'auth_status', ['GET']),
        ('/api/auth/register/begin', 'auth_register_begin', ['POST']),
        ('/api/auth/register/complete', 'auth_register_complete', ['POST']),
        ('/api/auth/login/begin', 'auth_login_begin', ['POST']),
        ('/api/auth/login/complete', 'auth_login_complete', ['POST']),
        ('/api/auth/logout', 'auth_logout', ['POST']),
    ):
        handler = _monitor_auth_login_complete if auth_endpoint == 'auth_login_complete' else getattr(chat_backend, auth_endpoint)
        app.add_url_rule(auth_path, f'monitor_{auth_endpoint}', handler, methods=auth_methods)
PROJECTS = os.path.dirname(REPO_ROOT)
MONITOR_ALLOWED_USERS = {'Llama Seven (#7)'}
MONITOR_ADMIN_USERS = {'Dan Costin (#10)', 'Llama Seven (#7)'}
MONITOR_IGNORED_USERS = set()
MONITOR_DATA_DIR = os.path.join(_BASE_DIR, 'data')
MONITOR_ALLOWED_PATH = os.path.join(MONITOR_DATA_DIR, 'monitor_allowed_users.json')
MONITOR_ADMIN_PATH = os.path.join(MONITOR_DATA_DIR, 'monitor_admin_users.json')
MONITOR_IGNORED_PATH = os.path.join(MONITOR_DATA_DIR, 'monitor_ignored_users.json')
MONITOR_ACCESS_PATH = os.path.join(MONITOR_DATA_DIR, 'monitor_access.json')
MONITOR_SIGNAL_PATH = os.path.join(MONITOR_DATA_DIR, 'monitor_signal')
_MONITOR_ACCESS_LOCK = threading.Lock()
_OPENAI_USAGE_CACHE = {'expires': 0.0, 'lines': []}
MONITOR_CERT = os.path.join(_BASE_DIR, 'secrets', 'fullchain.pem')
MONITOR_KEY = os.path.join(_BASE_DIR, 'secrets', 'privkey.pem')
try:
    with open(MONITOR_ALLOWED_PATH, encoding='utf-8') as f:
        saved_allowed = json.load(f)
        if isinstance(saved_allowed, list) and saved_allowed:
            MONITOR_ALLOWED_USERS = {str(value) for value in saved_allowed}
except (OSError, ValueError, TypeError):
    pass
try:
    with open(MONITOR_ADMIN_PATH, encoding='utf-8') as f:
        saved_admins = json.load(f)
        if isinstance(saved_admins, list) and saved_admins:
            MONITOR_ADMIN_USERS = {str(value) for value in saved_admins}
except (OSError, ValueError, TypeError):
    pass
try:
    with open(MONITOR_IGNORED_PATH, encoding='utf-8') as f:
        saved_ignored = json.load(f)
        if isinstance(saved_ignored, list):
            MONITOR_IGNORED_USERS = {str(value) for value in saved_ignored}
except (OSError, ValueError, TypeError):
    pass


def _monitor_allowed_labels():
    """Allowed-user labels from disk, so every worker honors Allow clicks."""
    try:
        with open(MONITOR_ALLOWED_PATH, encoding='utf-8') as f:
            saved = json.load(f)
        if isinstance(saved, list) and saved:
            return {str(value) for value in saved}
    except (OSError, ValueError, TypeError):
        pass
    return set(MONITOR_ALLOWED_USERS)


def _monitor_ignored_labels():
    try:
        with open(MONITOR_IGNORED_PATH, encoding='utf-8') as f:
            saved = json.load(f)
        if isinstance(saved, list):
            return {str(value) for value in saved}
    except (OSError, ValueError, TypeError):
        pass
    return set(MONITOR_IGNORED_USERS)


def _atomic_write_json(path, payload, cap=None):
    """Replace a monitor JSON file under a cross-process lock.

    Multiple gunicorn workers append to the access log; a concurrent
    read-modify-write without the lock could reset or corrupt it."""
    records = payload if cap is None else payload[-cap:]
    with open(path + '.lock', 'w') as lock_file:
        fcntl.flock(lock_file, fcntl.LOCK_EX)
        temp_path = path + '.tmp'
        with open(temp_path, 'w', encoding='utf-8') as f:
            json.dump(records, f)
        os.replace(temp_path, path)
DATA_FILES = [os.path.join(PROJECTS, name, 'data', 'monitor_connections.json')
              for name in os.listdir(PROJECTS)
              if os.path.isdir(os.path.join(PROJECTS, name))]
PAGE = '''<!doctype html><title>LLM Connection Monitor</title><meta http-equiv="refresh" content="5"><style>body{font:12px system-ui;margin:1rem;background:#f5f6f8;color:#202124}h1{font-size:18px;margin:0 0 4px}.checked{color:#5f6368;margin:0 0 12px}.status{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:8px;margin-bottom:14px}.chat-start{grid-column:1}.card,table{background:white;border:1px solid #ddd;border-radius:7px}.card{padding:8px}.card b{display:block;margin-bottom:3px}.ok{color:#1b7f39}.warn{color:#b06000}.down{color:#c5221f}.light{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:5px;background:currentColor}.detail{color:#5f6368;overflow-wrap:anywhere;white-space:pre-line}.detail .ok{color:#1b7f39}.detail .warn{color:#b06000}.detail .down{color:#c5221f}table{border-collapse:separate;border-spacing:0}th,td{padding:5px 8px;border-bottom:1px solid #eee;text-align:left}tr:last-child td{border-bottom:0}</style><h1>LLM Connection Monitor</h1><p class="checked">Last checked: {{checked}}</p><section class="status">{% for item in status %}<div class="card {{'chat-start' if item.name == 'Chat 7777 (main)' else ''}}"><b class="{{'down' if item.ollama and not item.available else ('ok' if item.ok else 'down')}}"><span class="light"></span>{{item.name}}</b>{% if item.ollama %}<div class="detail"><div>Assigned: {{item.assigned_model}}</div>{% if item.loaded %}<div><span class="ok">Loaded: {{item.loaded_model}}</span></div>{% else %}<div><span class="warn if item.available else 'down'">Loaded: no</span> • <span class="{{'ok' if item.available else 'down'}}">Available: {{'yes' if item.available else 'no'}}</span></div>{% endif %}</div>{% else %}<div class="detail">{{item.detail}}</div>{% endif %}</div>{% endfor %}</section><table><tr><th>Time (NY)</th><th>ID</th><th>Client</th><th>Port</th><th>Backend</th><th>Model</th><th>Cost</th></tr>{% for e in entries|reverse %}<tr><td>{{time(e.started)}}</td><td>{{e.id or '—'}}</td><td>{{e.ip}}</td><td>{{e.port}}</td><td>{{e.backend}}</td><td>{{e.model or 'auto'}}</td><td>{{e.query_cost if e.query_cost is not none else '—'}}</td></tr>{% endfor %}</table>'''
PAGE = PAGE.replace('<!doctype html><title>', '<!doctype html><link rel="icon" href="/monitor.png" type="image/png" sizes="1254x1254"><link rel="shortcut icon" href="/monitor.png" type="image/png"><link rel="apple-touch-icon" sizes="180x180" href="/apple-touch-icon.png"><link rel="apple-touch-icon-precomposed" sizes="180x180" href="/apple-touch-icon.png"><meta name="apple-mobile-web-app-title" content="LLama Monitor"><title>')
PAGE = PAGE.replace('LLM Connection Monitor', 'LLama Monitor')
PAGE = PAGE.replace('</title>', '</title><meta name="robots" content="noindex, nofollow">', 1)
PAGE = PAGE.replace('<th>Model</th><th>Cost</th>', '<th>Model</th><th>Query cost</th>')
PAGE = PAGE.replace('<table>', '{% if show_log %}<table>')
PAGE = PAGE.replace('</table>', '</table>{% endif %}')
PAGE = PAGE.replace('<table>', '<div class="log-controls"><form method="get"><label for="log-page-size">Rows per page</label><select id="log-page-size" name="per_page" onchange="this.form.submit()">{% for option in page_sizes %}<option value="{{option}}"{% if option == per_page %} selected{% endif %}>{{option}}</option>{% endfor %}</select><input type="hidden" name="page" value="1"><button type="submit">Apply</button></form><span>Page {{page}} of {{page_count}}</span>{% if page > 1 %}<a href="?page={{page - 1}}&amp;per_page={{per_page}}">Previous</a>{% endif %}{% if page < page_count %}<a href="?page={{page + 1}}&amp;per_page={{per_page}}">Next</a>{% endif %}</div><table>')
PAGE = PAGE.replace("{{e.model or 'auto'}}</td></tr>{% endfor %}</table>", "{{e.model or 'auto'}}{% if e.authorized_by %} ({{e.authorized_by}}){% endif %}</td></tr>{% endfor %}</table>")
PAGE = PAGE.replace('<td>{{e.ip}}</td>', '<td title="{{e.user_agent or \'\'}}">{{e.ip}}</td>')
PAGE = PAGE.replace('<div><span class="ok">Loaded: {{item.loaded_model}}</span></div>',
                    '<div><span class="ok">Loaded: {{item.loaded_model}}</span></div>'
                    '{% if item.context %}<div>Context: {{item.context}}</div>{% endif %}'
                    '{% if item.memory %}<div>Memory: {{item.memory}}{% if item.unloads_in == \'never\' %} · Unloads: never{% elif item.unloads_in %} · Unloads in {{item.unloads_in}}{% endif %}</div>{% endif %}'
                    '{% if item.processed %}<div>Tks: {{item.processed}}</div>{% endif %}')
PAGE = PAGE.replace('{% for e in entries|reverse %}', '{% for e in entries %}')
PAGE = PAGE.replace('class="warn if item.available else \'down\'"', 'class="{{\'warn\' if item.available else \'down\'}}"')
PAGE = PAGE.replace('content="5"', 'content="30"')
PAGE = PAGE.replace('<p class="checked">Last checked: {{checked}}</p>', '<p class="checked">Last checked: {{checked}} <button type="button" onclick="location.reload()">Refresh</button></p>')
PAGE = PAGE.replace('<h1>LLama Monitor</h1>', '<header class="topbar"><h1>LLama Monitor</h1><div class="monitor-user">{{monitor_user}}</div></header>')
PAGE = PAGE.replace('<style>', '<style>.topbar{display:flex;align-items:baseline;justify-content:space-between;gap:1rem}.monitor-user{color:#5f6368;font-size:13px}</style><style>')
PAGE = PAGE.replace('<style>', '<style>.external-card{background:#eefbf3!important}.external-label{color:#1b7f39;font-size:11px;font-weight:600;margin-bottom:2px}</style><style>')
PAGE = PAGE.replace('<style>', '<style>.shortcut-name{color:#68737e;font-size:.9em;font-weight:400;margin-left:5px}</style><style>')
PAGE = PAGE.replace('<style>', '<style>.external-status{display:flex;align-items:center;gap:10px;white-space:nowrap}.external-status .external-label{margin:0}.usage-table{display:grid;grid-template-columns:repeat(4,minmax(42px,auto));gap:2px 10px;margin-top:6px;font-size:11px}.usage-row{display:contents}.usage-table span{text-align:center}.usage-table .usage-value{font-weight:400;color:inherit;text-align:center}</style><style>')
PAGE = PAGE.replace('<style>', '<style>.log-controls{display:flex;align-items:center;flex-wrap:wrap;gap:8px;margin:0 0 8px}.log-controls form{display:flex;align-items:center;gap:5px}.log-controls select,.log-controls button{font:inherit}.log-controls a{color:#1a73e8}</style><style>')
PAGE = PAGE.replace('<meta http-equiv="refresh" content="30">', '<meta name="viewport" content="width=device-width, initial-scale=1"><meta http-equiv="refresh" content="{{refresh_seconds}}">')
PAGE = PAGE.replace('</body></html>', '<script>async function restartModel(button,target){if(button.disabled)return;button.disabled=true;button.textContent="Restarting…";try{const response=await fetch("/api/model-services/"+encodeURIComponent(target)+"/restart",{method:"POST",credentials:"same-origin"});if(!response.ok)throw Error(await response.text()||("HTTP "+response.status));setTimeout(()=>location.reload(),3000)}catch(error){button.disabled=false;button.textContent="Restart failed";button.title=error.message||"Could not restart model"}}let monitorSignal="{{monitor_signal}}";setInterval(()=>fetch("/api/monitor/signal-status",{cache:"no-store"}).then(r=>r.text()).then(v=>{if(v!==monitorSignal)location.reload()}).catch(()=>{}),2000)</script></body></html>')
PAGE = PAGE.replace('</style>', '@media (max-width:600px){body{margin:.6rem}.status{grid-template-columns:1fr}.topbar{align-items:flex-start}.topbar h1{font-size:17px}.monitor-user{font-size:11px;text-align:right;overflow-wrap:anywhere}.access-review,.health{display:block;margin-right:0}}</style>', 1)
PAGE = PAGE.replace('{% else %}<div class="detail">{{item.detail}}</div>{% endif %}', '{% elif item.qwen %}{% if item.ok %}<div class="detail"><div class="ok">Loaded: {{item.loaded_model}}</div><div>Context: {{item.context}}</div></div>{% else %}<div class="detail"><span class="down">Available: No</span></div>{% endif %}{% if item.launchd %}<div class="detail"><div>Agent: {{"running" if item.launchd_running else "stopped"}}</div><form method="post" action="/service/power"><input type="hidden" name="label" value="{{item.launchd}}"><input type="hidden" name="action" value="{{"stop" if item.launchd_running else "start"}}"><button type="submit" style="margin-top:4px">{{"Stop service" if item.launchd_running else "Start service"}}</button></form></div>{% endif %}{% else %}<div class="detail">{{item.detail}}</div>{% endif %}')

PAGE = PAGE.replace(
    '{% else %}<div class="detail">{{item.detail}}</div>{% endif %}',
    '{% elif item.chat %}<div class="detail">{% if item.external %}<div class="external-status"><span class="external-label">External</span><span class="down">Available: Admins only</span></div><div class="usage-table"><span>{% for usage in item.usage %}{{usage.days}}d{% if not loop.last %}{% endif %}</span>{% endfor %}<span class="usage-value">{% for usage in item.usage %}{{usage.value}}{% if not loop.last %}</span><span class="usage-value">{% endif %}{% endfor %}</span></div>{% else %}{% for model in item.models %}<div class="{{\'ok\' if model.online else \'down\'}}">{{model.name}}</div>{% endfor %}{% endif %}</div>{% else %}<div class="detail">{{item.detail}}</div>{% endif %}'
)
PAGE = PAGE.replace(
    '{% else %}<div class="detail">{{item.detail}}</div>{% endif %}',
    '{% elif item.openrouter %}<div class="detail"><div class="external-status"><span class="external-label">External</span><span class="down">Available: {{\'Admins only\' if item.ok else \'No\'}}</span></div><div>Model: Auto</div></div>{% else %}<div class="detail">{{item.detail}}</div>{% endif %}'
)
PAGE = PAGE.replace(
    '<div class="usage-table"><span>{% for usage in item.usage %}{{usage.days}}d{% if not loop.last %}{% endif %}</span>{% endfor %}<span class="usage-value">{% for usage in item.usage %}{{usage.value}}{% if not loop.last %}</span><span class="usage-value">{% endif %}{% endfor %}</span></div>',
    '<div class="usage-table"><div class="usage-row">{% for usage in item.usage %}<span>{% if loop.first %}Usage {% endif %}{{usage.days}}d{% if usage.days == 30 %} UTC{% endif %}</span>{% endfor %}</div><div class="usage-row">{% for usage in item.usage %}<span class="usage-value">{{usage.value}}</span>{% endfor %}</div></div>'
)
PAGE = PAGE.replace('onclick="allowMonitorUser({{person.id}}, {{person.username|tojson}})"', 'onclick=\'allowMonitorUser({{person.id}}, {{person.username|tojson}})\'')
PAGE = PAGE.replace('<div>Assigned: {{item.assigned_model}}</div>', '<div>Assigned: {{item.assigned_model}}</div>{% if item.model_details %}<div>{{item.model_details}}</div>{% endif %}')
PAGE = PAGE.replace('<section class="status">', '<section class="access-review"><h2>Authenticated users awaiting monitor access</h2>{% for person in pending %}<div class="access-person"><span>{{person.label}}</span><span><button type="button" onclick="allowMonitorUser({{person.id}}, {{person.username|tojson}})">Allow</button> <button type="button" onclick="ignoreMonitorUser({{person.id}}, {{person.username|tojson}})">Ignore</button></span></div>{% else %}<div class="detail">No pending requests</div>{% endfor %}</section><script>async function monitorAccessAction(path,id,username){const response=await fetch(path,{method:\'POST\',headers:{\'Content-Type\':\'application/json\'},body:JSON.stringify({id:id,username:username})});if(!response.ok){alert(\'Could not update monitor access request\');return}location.reload()}function allowMonitorUser(id,username){return monitorAccessAction(\'/api/monitor/allow\',id,username)}function ignoreMonitorUser(id,username){return monitorAccessAction(\'/api/monitor/ignore\',id,username)}</script><section class="status">')
PAGE = PAGE.replace('<div class="card {{\'chat-start\' if item.name == \'Chat 7777 (main)\' else \'\'}}">', '<div class="card {{\'chat-start\' if item.name == \'Chat 7777 (main)\' else (\'server-down\' if item.chat and item.name.startswith(\'Chat \') and not item.ok else (\'external-card\' if item.external or item.external_card else \'\'))}}">')
PAGE = PAGE.replace('{{model.name}}</div>', '{{model.name}}{% if model.shortcut %} <span class="shortcut-name">{{model.shortcut}}</span>{% endif %}</div>')
PAGE = PAGE.replace('{% elif item.chat %}<div class="detail">{% for model in item.models %}', '{% elif item.chat %}<div class="detail">{% if item.external %}<div class="external-label">External</div>{% endif %}{% for model in item.models %}')
PAGE = PAGE.replace('<span class="light"></span>{{item.name}}</b>', '<span class="light"></span>{{item.name}}{% if show_log and item.restart_target %}<form class="restart-model" method="post" action="/api/model-services/{{item.restart_target}}/restart"><input type="hidden" name="from_monitor" value="1"><button type="submit">Restart</button></form>{% endif %}</b>')
PAGE = PAGE.replace('{% if show_log %}<div class="log-controls">', '{% if show_log %}<section class="job-control"><h2>Active Chat Jobs</h2>{% for job in jobs %}<div class="job-row" data-job-id="{{job.id}}"><div><b>{{job.username}} (#{{job.user_id}})</b> <span>{{job.query}}</span><div class="job-detail">{{job.elapsed}} · {{job.model or job.backend}} · ~{{job.tokens}} tokens · {{job.phase}}</div></div><div class="job-controls">{% if job.stale %}<button type="button" class="stale-job-button" data-job-id="{{job.id}}" onclick="void markStaleChatJob(this,{{job.id|tojson}})">Check stale</button>{% endif %}<button type="button" class="stop-job-button" data-job-id="{{job.id}}" {% if job.cancel_requested %}disabled{% endif %} onclick="void stopChatJob(this,{{job.id|tojson}})">{{"Stopping…" if job.cancel_requested else "Stop"}}</button></div></div>{% else %}<div class="detail">No active jobs</div>{% endfor %}</section><script>async function stopChatJob(button,id){if(button.disabled)return;button.disabled=true;button.textContent="Stopping…";try{const response=await fetch("/api/chat-jobs/"+encodeURIComponent(id)+"/cancel",{method:"POST",credentials:"same-origin"});if(!response.ok){const detail=await response.text();throw Error(detail||("HTTP "+response.status));}const wait=async()=>{try{const r=await fetch("/api/connections",{cache:"no-store",credentials:"same-origin"});if(r.ok){const data=await r.json();if(!(data.jobs||[]).some(job=>job.id===id)){location.reload();return}}}catch(error){button.textContent="Stop check failed";button.disabled=false;return}setTimeout(wait,1000)};wait()}catch(error){button.textContent="Stop failed";button.disabled=false;button.title=error.message||"Could not stop chat job";}}async function markStaleChatJob(button,id){if(button.disabled)return;button.disabled=true;button.textContent="Checking…";try{const response=await fetch("/api/chat-jobs/"+encodeURIComponent(id)+"/stale",{method:"POST",credentials:"same-origin"});if(!response.ok){const detail=await response.text();throw Error(detail||("HTTP "+response.status));}location.reload()}catch(error){button.disabled=false;button.textContent="Check stale";button.title=error.message||"Could not check stale job";}}document.querySelectorAll(".stop-job-button[data-job-id]").forEach(button=>button.addEventListener("click",()=>void stopChatJob(button,button.dataset.jobId)));</script><div class="log-controls">')
PAGE = PAGE.replace('<style>', '<style>.card{position:relative}.card.server-down{background:#ffe5e5;border-color:#d93025}.restart-model{position:absolute;right:8px;bottom:8px;margin:0}.restart-model button{border:0;padding:0;background:transparent;color:#7a838d;font:inherit;font-size:9px;line-height:1.25;text-decoration:underline;cursor:pointer}.restart-model button:hover{color:#38424d}.job-control{display:block;width:min(900px,100%);background:#fff;border:1px solid #ddd;border-radius:7px;padding:10px;margin:0 0 14px}.job-control h2{font-size:14px;margin:0 0 8px}.job-row{display:flex;justify-content:space-between;align-items:center;gap:14px;border-top:1px solid #eee;padding:8px 0}.job-row:first-of-type{border-top:0}.job-query{margin-top:3px;overflow-wrap:anywhere}.job-detail{color:#5f6368;font-size:11px;margin-top:3px}.job-controls{display:flex;align-items:center;justify-content:flex-end;gap:6px;flex-shrink:0}.job-row button{cursor:pointer;color:#c5221f;background:#fff;border:1px solid #c5221f;border-radius:5px;padding:4px 8px;white-space:nowrap}</style><style>')
PAGE = PAGE.replace('onclick="allowMonitorUser({{person.id}}, {{person.username|tojson}})"', 'onclick=\'allowMonitorUser({{person.id}}, {{person.username|tojson}})\'')
PAGE = PAGE.replace('<style>', '<style>.access-review{display:inline-block;vertical-align:top;width:fit-content;max-width:100%;background:#fff8e1;border:1px solid #e6c65c;border-radius:7px;padding:10px;margin:0 10px 14px 0}.access-review[hidden]{display:none}.access-review h2{font-size:14px;margin:0 0 8px}.access-person{display:flex;justify-content:space-between;align-items:center;gap:18px;padding:5px 0;border-top:1px solid #eadca8}.access-person button{cursor:pointer}</style><style>')
PAGE = PAGE.replace('<section class="access-review">', '<section class="health card"><b>{{health_title}}</b><div class="health-grid">{% for item in health %}<div><span class="health-label">{{item.label}}</span> <strong class="{{item.class}}">{{item.value}}</strong></div>{% endfor %}</div></section><section class="access-review">')
PAGE = PAGE.replace('</style>', '.health{display:inline-block;vertical-align:top;width:fit-content;max-width:100%;margin:0 10px 14px 0}.health-grid{display:flex;flex-wrap:wrap;gap:4px 14px;margin-top:7px}.health-grid>div{display:flex;gap:5px;align-items:baseline}.health-label{color:#5f6368}.health strong{font-size:14px}.health .ok{color:#1b7f39}.health .warn{color:#b06000}.health .down{color:#c5221f}@media (max-width:600px){.access-review,.health{display:block;margin-right:0}}</style>', 1)
PAGE = PAGE.replace('<section class="access-review">', '<section class="access-review" {% if not pending %}hidden{% endif %}>')
PAGE += '<script>async function restartModel(link,target){if(link.getAttribute("aria-disabled")==="true")return;link.setAttribute("aria-disabled","true");link.textContent="Restarting…";try{const response=await fetch("/api/model-services/"+encodeURIComponent(target)+"/restart",{method:"POST",credentials:"same-origin"});if(!response.ok)throw Error(await response.text()||("HTTP "+response.status));setTimeout(()=>location.reload(),3000)}catch(error){link.removeAttribute("aria-disabled");link.textContent="Restart failed";link.title=error.message||"Could not restart model"}}</script>'

PAGE = PAGE.replace("('server-down' if item.chat and item.name.startswith('Chat ') and not item.ok else", "('dev-server-down' if item.name == 'Chat 7778 (dev)' and not item.ok else ('server-down' if item.chat and item.name.startswith('Chat ') and not item.ok else")
PAGE = PAGE.replace("item.chat and item.name.startswith('Chat ') and not item.ok", "item.name.startswith('Chat ') and not item.ok")
PAGE = PAGE.replace("{{'chat-start' if item.name == 'Chat 7777 (main)' else", "{{('chat-start ' + ('server-down' if item.chat and item.name.startswith('Chat ') and not item.ok else '')) if item.name == 'Chat 7777 (main)' else")
PAGE = PAGE.replace("item.chat and item.name.startswith('Chat ') and not item.ok", "item.name.startswith('Chat ') and not item.ok")
PAGE = PAGE.replace("else ''))}}", "else '')))}}")
PAGE = PAGE.replace('<style>', '<style>.card.dev-server-down{background:#fff;border-color:#ddd}</style><style>')
PAGE = PAGE.replace('{% elif item.chat %}<div class="detail">{% if item.external %}',
                    '{% elif item.chat %}<div class="detail">'
                    '{% if item.uptime %}<div>Uptime: {{item.uptime}}</div>{% endif %}'
                    '{% if item.workers %}<div class="ok">Gunicorn: {{item.workers}} workers</div>{% endif %}'
                    '{% if item.external %}')

MONITOR_AUTH_PAGE = '''<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Sign in to Chat 77 LLamas</title><meta name="robots" content="noindex, nofollow"><style>
*{box-sizing:border-box}body{margin:0;font:16px system-ui,-apple-system,sans-serif;color:#202124}.auth-gate{position:fixed;inset:0;display:grid;place-items:center;padding:20px;background:rgba(245,246,248,.94)}.auth-card{width:min(390px,100%);padding:28px;border:1px solid #e2e5e9;border-radius:16px;background:#fff;box-shadow:0 12px 35px rgba(0,0,0,.14)}.auth-card h1{font-size:1.3rem;margin:0 0 8px}.auth-message{min-height:2.8em;color:#59636e;font-size:.9rem;line-height:1.45;margin:0 0 16px}.auth-message.error{color:#b42318}.auth-card button{width:100%;padding:10px 12px;border:0;border-radius:8px;cursor:pointer;font:inherit}.auth-primary{background:#0d6efd;color:#fff}.auth-card button:not(.auth-primary){background:#edf0f3;color:#2c333a}.auth-card button:disabled{opacity:.65;cursor:wait}.auth-divider{display:flex;align-items:center;gap:10px;margin:18px 0;color:#7a838d;font-size:.8rem}.auth-divider:before,.auth-divider:after{content:'';height:1px;flex:1;background:#e2e5e9}.auth-card form{display:grid;gap:8px}.auth-card label{color:#4b5560;font-size:.85rem}.auth-card input{padding:10px;border:1px solid #cdd3da;border-radius:8px;font:inherit}
</style></head><body><div class="auth-gate"><section class="auth-card" aria-labelledby="authTitle"><h1 id="authTitle">Sign in to Chat 77 LLamas</h1><p id="authMessage" class="auth-message">Use a passkey from this device or another signed-in device.</p><button id="passkeyLoginBtn" class="auth-primary" type="button">Sign in with passkey</button><div class="auth-divider"><span>or create an account</span></div><form id="passkeyRegisterForm"><label for="passkeyUsername">Account name</label><input id="passkeyUsername" maxlength="80" autocomplete="username" placeholder="Your name or login ID" required><button id="passkeyRegisterBtn" type="submit">Create passkey</button></form></section></div><script>
const message=document.getElementById('authMessage'),loginButton=document.getElementById('passkeyLoginBtn'),form=document.getElementById('passkeyRegisterForm'),registerButton=document.getElementById('passkeyRegisterBtn'),username=document.getElementById('passkeyUsername');
const b64=s=>{const p=String(s).replace(/-/g,'+').replace(/_/g,'/')+'==='.slice((String(s).length+3)%4),r=atob(p);return Uint8Array.from(r,c=>c.charCodeAt(0)).buffer};const b64out=v=>{const a=new Uint8Array(v);let r='';a.forEach(x=>r+=String.fromCharCode(x));return btoa(r).split('+').join('-').split('/').join('_').replace(/=+$/,'')};
const prepare=(o,creation)=>{const p={...o,challenge:b64(o.challenge)};if(creation&&o.user)p.user={...o.user,id:b64(o.user.id)};for(const k of ['excludeCredentials','allowCredentials'])if(Array.isArray(o[k]))p[k]=o[k].map(x=>({...x,id:b64(x.id)}));return p};const serialize=c=>{const r=c.response,d={id:c.id,rawId:b64out(c.rawId),type:c.type,response:{clientDataJSON:b64out(r.clientDataJSON)},clientExtensionResults:c.getClientExtensionResults?c.getClientExtensionResults():{},authenticatorAttachment:c.authenticatorAttachment||null};if(r.attestationObject){d.response.attestationObject=b64out(r.attestationObject);if(r.getTransports)d.response.transports=r.getTransports()}else{d.response.authenticatorData=b64out(r.authenticatorData);d.response.signature=b64out(r.signature);if(r.userHandle)d.response.userHandle=b64out(r.userHandle)}return d};
const requestJson=async(url,body)=>{const response=await fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:body===undefined?undefined:JSON.stringify(body)}),data=await response.json().catch(()=>({}));if(!response.ok)throw Error(data.error||'Passkey request failed');return data};const busy=value=>[loginButton,registerButton].forEach(button=>button.disabled=value);const say=(text,error=false)=>{message.textContent=text;message.classList.toggle('error',error)};
loginButton.onclick=async()=>{busy(true);try{const options=await requestJson('/api/auth/login/begin'),credential=await navigator.credentials.get({publicKey:prepare(options,false)});if(!credential)throw Error('No passkey was selected');await requestJson('/api/auth/login/complete',serialize(credential));location.reload()}catch(error){say(error.message||'Passkey sign-in failed',true)}finally{busy(false)}};form.onsubmit=async event=>{event.preventDefault();const name=username.value.trim().replace(/@/g,'_at_');username.value=name;if(!name){say('Enter a username first.',true);return}busy(true);try{const options=await requestJson('/api/auth/register/begin',{username:name}),credential=await navigator.credentials.create({publicKey:prepare(options,true)});if(!credential)throw Error('No passkey was created');await requestJson('/api/auth/register/complete',serialize(credential));location.reload()}catch(error){say(error.message||'Passkey registration failed',true)}finally{busy(false)}};
fetch('/api/auth/status',{cache:'no-store'}).then(response=>response.json()).then(status=>{if(!status.ready){say('Passkey authentication has not been configured on this server.',true);busy(true)}else if(!window.PublicKeyCredential||!window.isSecureContext){say('Passkeys require a secure browser connection (HTTPS or localhost).',true);busy(true)}}).catch(()=>say('Could not check passkey sign-in status.',true));</script></body></html>'''

def entries():
    if not FULL_MODE:
        return []
    all_entries = []
    for path in DATA_FILES:
        try:
            with open(path, encoding='utf-8') as f: all_entries.extend(json.load(f))
        except (OSError, ValueError, TypeError):
            pass
    try:
        with open(MONITOR_ACCESS_PATH, encoding='utf-8') as f:
            access_records = json.load(f)
        for record in access_records if isinstance(access_records, list) else []:
            all_entries.append({
                'started': record.get('started', ''),
                'id': record.get('label') or 'Unauthenticated',
                'ip': record.get('ip', 'unknown'),
                'port': 'monitor',
                'backend': '',
                'model': 'authorized' if record.get('allowed') else ('blocked' if record.get('authenticated') else 'unauthenticated'),
                'authorized_by': record.get('authorized_by', ''),
                'user_agent': record.get('user_agent', ''),
            })
    except (OSError, ValueError, TypeError):
        pass
    for event in chat_backend.RESEARCH_STORE.list_auth_security_events(
            chat_backend.AUTH_ENVIRONMENT, limit=200):
        details = event.get('details') or {}
        if event.get('event') != 'passkeys_replaced':
            continue
        all_entries.append({
            'started': event.get('created_at'),
            'id': f"{event.get('username')} (#{event.get('user_id')})",
            'ip': details.get('remote_address') or '—',
            'port': 'chat',
            'backend': '',
            'model': (f"passkeys replaced; {details.get('credentials_revoked', 0)} revoked; "
                      f"{details.get('jobs_cancelled', 0)} jobs stopped"),
            'query_cost': None,
        })
    for entry in all_entries:
        if entry.get('port') in {'chat.77llamas.ai', 'chat.77llamas.ai:443'}:
            entry['port'] = 'chat'
    return sorted(all_entries, key=lambda e: e.get('started', ''))

def active_jobs():
    if not FULL_MODE:
        return []
    jobs = chat_backend.RESEARCH_STORE.list_active_chat_jobs_admin(chat_backend.AUTH_ENVIRONMENT)
    now = datetime.datetime.now(datetime.timezone.utc)
    for job in jobs:
        # Attached file contents are part of the model prompt, but must not be
        # rendered in the administrator monitor. Keep only the human question
        # and the attachment name(s).
        query = str(job.get('query') or '')
        attachments = re.findall(r'\[Attached file:\s*([^\]]+)\]', query, flags=re.I)
        query = re.sub(r'\s*\[Attached file:.*?\[/Attached file\]', '', query,
                       flags=re.I | re.S).strip()
        if attachments:
            query = f"{query} {' '.join(f'[{name}]' for name in attachments)}".strip()
        job['query'] = query[:300] + ('…' if len(query) > 300 else '')
        # Use creation time so recovery after a server restart does not reset
        # the elapsed duration shown to administrators.
        started = job.get('created_at') or job.get('started_at')
        try:
            stamp = datetime.datetime.fromisoformat(started)
            if stamp.tzinfo is None: stamp = stamp.replace(tzinfo=datetime.timezone.utc)
            seconds = max(0, int((now - stamp).total_seconds()))
        except (TypeError, ValueError):
            seconds = 0
        if seconds < 60: elapsed = f'{seconds}s'
        elif seconds < 3600: elapsed = f'{seconds // 60}m {seconds % 60}s'
        else: elapsed = f'{seconds // 3600}h {(seconds % 3600) // 60}m'
        job['elapsed'] = elapsed
        try:
            updated = datetime.datetime.fromisoformat(job.get('updated_at'))
            if updated.tzinfo is None: updated = updated.replace(tzinfo=datetime.timezone.utc)
            job['stale'] = (now - updated).total_seconds() >= 300
        except (TypeError, ValueError):
            job['stale'] = False
        job['tokens'] = max(0, (job.get('content_chars', 0) + job.get('reasoning_chars', 0)) // 4)
        job['phase'] = 'Compacting' if 'gemma' in f"{job.get('model', '')} {job.get('backend', '')}".lower() else 'Running'
    return jobs

@app.post('/api/monitor/signal')
def monitor_signal():
    if request.remote_addr not in ('127.0.0.1', '::1'):
        return jsonify({'error': 'local only'}), 403
    os.makedirs(MONITOR_DATA_DIR, exist_ok=True)
    with open(MONITOR_SIGNAL_PATH, 'w', encoding='utf-8') as f:
        f.write(str(datetime.datetime.now(datetime.timezone.utc).timestamp()))
    return jsonify({'ok': True})

def _authenticated_user():
    if not FULL_MODE:
        return None
    user = chat_backend._session_user()
    return user

def _monitor_user():
    user = _authenticated_user()
    if not user or f"{user['username']} (#{user['id']})" not in _monitor_allowed_labels():
        return None
    return user

def _monitor_admin():
    user = _authenticated_user()
    if not user or f"{user['username']} (#{user['id']})" not in MONITOR_ADMIN_USERS:
        return None
    return user

def _has_blocked_monitor_attempt(user):
    with _MONITOR_ACCESS_LOCK:
        try:
            with open(MONITOR_ACCESS_PATH, encoding='utf-8') as f:
                records = json.load(f)
        except (OSError, ValueError, TypeError):
            records = []
    label = f"{user['username']} (#{user['id']})"
    for record in reversed(records if isinstance(records, list) else []):
        if not record.get('authenticated') or not (record.get('id') == user['id'] or record.get('label') == label):
            continue
        return not record.get('allowed')
    return False

def _monitor_access_log(user, event='page visit'):
    label = f"{user['username']} (#{user['id']})" if user else ''
    entry = {
        'started': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'ip': request.remote_addr or 'unknown',
        'path': request.path,
        'user_agent': request.headers.get('User-Agent', ''),
        'authenticated': bool(user),
        'id': user['id'] if user else None,
        'username': user['username'] if user else None,
        'label': label or 'Unauthenticated',
        'allowed': label in MONITOR_ALLOWED_USERS if user else False,
        'event': event,
    }
    with _MONITOR_ACCESS_LOCK:
        try:
            with open(MONITOR_ACCESS_PATH, encoding='utf-8') as f:
                records = json.load(f)
        except (OSError, ValueError, TypeError):
            records = []
        records = records if isinstance(records, list) else []
        records.append(entry)
        os.makedirs(os.path.dirname(MONITOR_ACCESS_PATH), exist_ok=True)
        _atomic_write_json(MONITOR_ACCESS_PATH, records, cap=500)

def _monitor_authorization_log(user_id, username, actor):
    entry = {
        'started': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'ip': request.remote_addr or 'unknown',
        'path': request.path,
        'user_agent': request.headers.get('User-Agent', ''),
        'authenticated': True,
        'id': user_id,
        'username': username,
        'label': f'{username} (#{user_id})',
        'allowed': True,
        'event': 'authorization',
        'authorized_by': f"{actor['username']} (#{actor['id']})",
    }
    with _MONITOR_ACCESS_LOCK:
        try:
            with open(MONITOR_ACCESS_PATH, encoding='utf-8') as f:
                records = json.load(f)
        except (OSError, ValueError, TypeError):
            records = []
        records = records if isinstance(records, list) else []
        records.append(entry)
        os.makedirs(os.path.dirname(MONITOR_ACCESS_PATH), exist_ok=True)
        _atomic_write_json(MONITOR_ACCESS_PATH, records, cap=500)

def _record_monitor_visit_once(user):
    identity = f"{user['username']} (#{user['id']})" if user else 'Unauthenticated'
    blocked = bool(user and identity not in _monitor_allowed_labels())
    if not blocked and session.get('monitor_access_identity') == identity and (not user or not _has_blocked_monitor_attempt(user)):
        return
    if not blocked:
        session['monitor_access_identity'] = identity
    if not user:
        session['monitor_unauthenticated_visit'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    _monitor_access_log(user)

def _pending_monitor_users():
    with _MONITOR_ACCESS_LOCK:
        try:
            with open(MONITOR_ACCESS_PATH, encoding='utf-8') as f:
                records = json.load(f)
        except (OSError, ValueError, TypeError):
            records = []
    pending = {}
    for record in records if isinstance(records, list) else []:
        label = str(record.get('label') or '')
        if record.get('authenticated') and label not in _monitor_allowed_labels() and label not in _monitor_ignored_labels() and record.get('id') is not None:
            pending[str(record['id'])] = {
                'id': int(record['id']), 'username': str(record.get('username') or ''),
                'label': label,
            }
    return list(pending.values())

def _monitor_required(handler):
    @wraps(handler)
    def wrapped(*args, **kwargs):
        if not FULL_MODE:
            # Standalone mode: one shared token via HTTP Basic (any username);
            # with no token configured the monitor is open.
            if not MONITOR_TOKEN:
                return handler(*args, **kwargs)
            supplied = request.authorization.password if request.authorization else ''
            if hmac.compare_digest(supplied, MONITOR_TOKEN):
                return handler(*args, **kwargs)
            return 'Monitor token required', 401, {'WWW-Authenticate': 'Basic realm="LLama Monitor"'}
        user = _authenticated_user()
        if request.path == '/':
            _record_monitor_visit_once(user)
        if user and f"{user['username']} (#{user['id']})" in _monitor_allowed_labels():
            return handler(*args, **kwargs)
        if request.path != '/':
            # Only '/' visits are recorded by _record_monitor_visit_once; log
            # every other denied request so scanner probes against API paths
            # show up in the access log too.
            _monitor_access_log(user, event='denied')
        if request.path.startswith('/api/'):
            return jsonify({'error': 'Monitor access is not authorized'}), 403
        if user:
            return render_template_string(
                '<!doctype html><title>Monitor access not authorized</title><meta name="viewport" content="width=device-width,initial-scale=1">'
                '<style>body{font:16px system-ui;display:grid;place-items:center;min-height:90vh;background:#f5f6f8;color:#202124}.card{background:white;border:1px solid #ddd;border-radius:10px;padding:2rem;max-width:30rem;text-align:center}a{display:inline-block;background:#0d6efd;color:white;padding:.7rem 1rem;border-radius:7px;text-decoration:none}</style>'
                f'<section class="card"><h1>Authenticated, but not authorized</h1><p>You are signed in as <strong>{user["username"]} (#{user["id"]})</strong>, but this account is not allowed to use the monitor.</p><p>An authorized monitor user can approve this account.</p><a href="https://chat.77llamas.ai/">Return to Chat 77 LLamas</a></section>'
            ), 403
        return MONITOR_AUTH_PAGE, 401
    return wrapped

@app.get('/api/monitor/signal-status')
@_monitor_required
def monitor_signal_status():
    try:
        with open(MONITOR_SIGNAL_PATH, encoding='utf-8') as signal_file:
            return signal_file.read().strip() or '0'
    except OSError:
        return '0'

def display_time(value):
    try:
        stamp = datetime.datetime.fromisoformat(value).astimezone(ZoneInfo('America/New_York'))
        return stamp.strftime('%Y-%m-%d %I:%M:%S %p')
    except (TypeError, ValueError):
        return value

def _gpu_usage():
    """Read GPU utilization from macOS or NVIDIA systems when available."""
    try:
        result = subprocess.run(
            ['ioreg', '-r', '-d', '1', '-c', 'IOAccelerator'],
            capture_output=True, text=True, timeout=1, check=False,
        )
        match = re.search(r'"(?:Device|Renderer|Tiler) Utilization %"\s*=\s*(\d+)', result.stdout)
        if match:
            return f'{int(match.group(1))}%'
    except (OSError, subprocess.SubprocessError):
        pass
    try:
        result = subprocess.run(
            ['nvidia-smi', '--query-gpu=utilization.gpu', '--format=csv,noheader,nounits'],
            capture_output=True, text=True, timeout=1, check=False,
        )
        values = [value.strip() for value in result.stdout.splitlines() if value.strip()]
        if values and all(value.isdigit() for value in values):
            return ', '.join(f'{value}%' for value in values)
    except (OSError, subprocess.SubprocessError):
        pass
    return 'Unavailable'

def _mac_memory_used():
    """Approximate Activity Monitor's used memory on macOS."""
    try:
        result = subprocess.run(['vm_stat'], capture_output=True, text=True, timeout=1, check=False)
        page_size = int(re.search(r'page size of (\d+) bytes', result.stdout).group(1))
        values = {}
        for line in result.stdout.splitlines():
            match = re.match(r'([^:]+):\s+(\d+)', line)
            if match:
                values[match.group(1).strip()] = int(match.group(2))
        anonymous = values.get('Anonymous pages')
        wired = values.get('Pages wired down')
        compressed = values.get('Pages occupied by compressor')
        if anonymous is not None and wired is not None and compressed is not None:
            return (anonymous + wired + compressed) * page_size
    except (AttributeError, OSError, ValueError, subprocess.SubprocessError):
        pass
    return None

def _memory_pressure():
    try:
        result = subprocess.run(['memory_pressure', '-Q'], capture_output=True, text=True, timeout=2, check=False)
        match = re.search(r'System-wide memory free percentage:\s*(\d+)%', result.stdout)
        if match:
            free = int(match.group(1))
            level, css = ('Critical', 'down') if free <= 5 else (('Warning', 'warn') if free <= 15 else ('Normal', 'ok'))
            return f'{level} ({free}% free)', css
    except (OSError, subprocess.SubprocessError):
        pass
    return 'Unavailable', 'warn'

def server_identity():
    try:
        result = subprocess.run(
            ['system_profiler', 'SPHardwareDataType'],
            capture_output=True, text=True, timeout=2, check=False,
        )
        values = {}
        for line in result.stdout.splitlines():
            if ':' in line:
                key, value = line.split(':', 1)
                values[key.strip()] = value.strip()
        name = values.get('Model Name')
        chip = values.get('Chip') or values.get('Processor Name')
        if name and chip:
            return f'{name} ({chip})'
        if name:
            return name
    except (OSError, subprocess.SubprocessError):
        pass
    return os.uname().nodename

def system_health():
    memory = psutil.virtual_memory()
    memory_used = _mac_memory_used() or memory.used
    memory_percent = memory_used / memory.total * 100
    cpu = psutil.cpu_percent(interval=0.1)
    gpu = _gpu_usage()
    pressure, pressure_class = _memory_pressure()

    def state(value):
        if value == 'Unavailable':
            return 'warn'
        try:
            number = float(str(value).rstrip('%'))
        except ValueError:
            return 'ok'
        return 'down' if number >= 90 else ('warn' if number >= 70 else 'ok')

    return [
        {'label': 'Mem', 'value': f'{memory_percent:.0f}% ({memory_used / (1024 ** 3):.1f} / {memory.total / (1024 ** 3):.1f} GB)', 'class': state(memory_percent)},
        {'label': 'CPU', 'value': f'{cpu:.0f}%', 'class': state(cpu)},
        {'label': 'GPU', 'value': gpu, 'class': state(gpu)},
        {'label': 'Pressure', 'value': pressure, 'class': pressure_class},
    ]

def _probe(name, url, parser=None, verify=True):
    try:
        response = requests.get(url, timeout=2, verify=verify)
        if not response.ok:
            return {'name': name, 'ok': False, 'detail': f'HTTP {response.status_code}'}
        payload = response.json() if parser else None
        parsed = parser(payload) if parser else 'Responding'
        if isinstance(parsed, dict):
            return {'name': name, 'ok': True, **parsed}
        if isinstance(parsed, tuple):
            name, parsed = parsed
        return {'name': name, 'ok': True, 'detail': parsed}
    except (requests.RequestException, ValueError) as e:
        return {'name': name, 'ok': False, 'detail': str(e).split(':', 1)[0]}

def _last_prompt_progress(log_path):
    """Last 'Prompt processing progress' event from the server's runner log."""
    if not log_path:
        return ''
    try:
        with open(log_path, 'rb') as log_file:
            log_file.seek(0, os.SEEK_END)
            log_file.seek(max(0, log_file.tell() - 65536))
            tail = log_file.read().decode('utf-8', 'ignore')
        matches = re.findall(
            r'time=\d{4}-(\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})(?:\.\d+)?(?:[+-]\d{2}:\d{2}|Z)'
            r'.*?msg="Prompt processing progress" processed=(\d+) total=(\d+)', tail)
        if not matches:
            return ''
        stamp, clock, processed, total = matches[-1]
        return f'{stamp} {clock} {processed}/{total}'
    except OSError:
        return ''


def _probe_ollama(name, host, assigned_model, log_path=None):
    try:
        tags_response = requests.get(f'{host}/api/tags', timeout=3)
        if not tags_response.ok:
            return {'name': name, 'ok': False, 'ollama': True, 'loaded': False, 'available': False, 'assigned_model': assigned_model, 'detail': f'HTTP {tags_response.status_code} from tags'}
        ps_response = requests.get(f'{host}/api/ps', timeout=3)
        available_records = tags_response.json().get('models', [])
        available = [m.get('name') or m.get('model') for m in available_records]
        loaded_records = ps_response.json().get('models', []) if ps_response.ok else []
        loaded = [m.get('name') or m.get('model') for m in loaded_records]
        def has_model(models):
            return any(model == assigned_model or model.startswith(f'{assigned_model}:') for model in models)
        loaded_model = next((model for model in loaded if has_model([model])), '')
        available_match = has_model(available)
        loaded_match = bool(loaded_model)
        loaded_record = next((record for record in loaded_records
                              if (record.get('name') or record.get('model')) == loaded_model), {})
        context = loaded_record.get('context_length') or loaded_record.get('context')
        size_vram = loaded_record.get('size_vram') or loaded_record.get('size')
        memory = f'{size_vram / (1024 ** 3):.1f} GiB' if size_vram else ''
        unloads_in = ''
        try:
            unload_stamp = datetime.datetime.fromisoformat(loaded_record.get('expires_at'))
            if unload_stamp.tzinfo is None:
                unload_stamp = unload_stamp.replace(tzinfo=datetime.timezone.utc)
            if unload_stamp.year <= 1:
                unloads_in = 'never'
            else:
                seconds = max(0, int((unload_stamp - datetime.datetime.now(datetime.timezone.utc)).total_seconds()))
                if seconds > 365 * 24 * 3600:
                    # Ollama's keep_alive=-1 lands far in the future (year 2318+).
                    unloads_in = 'never'
                elif seconds < 60:
                    unloads_in = f'{seconds}s'
                elif seconds < 3600:
                    unloads_in = f'{seconds // 60}m {seconds % 60:02d}s'
                else:
                    unloads_in = f'{seconds // 3600}h {(seconds % 3600) // 60}m'
        except (TypeError, ValueError):
            unloads_in = ''
        assigned_record = next((record for record in available_records
                                if (record.get('name') or record.get('model')) == assigned_model
                                or (record.get('name') or record.get('model', '')).startswith(f'{assigned_model}:')), {})
        details = assigned_record.get('details') or {}
        model_details = ' • '.join(filter(None, [
            f"Size: {details.get('parameter_size')}" if details.get('parameter_size') else '',
            f"Quantization: {details.get('quantization_level')}" if details.get('quantization_level') else '',
        ]))
        return {
            'name': name,
            'ok': True,
            'ollama': True,
            'assigned_model': assigned_model,
            'loaded': loaded_match,
            'loaded_model': loaded_model,
            'context': f'{context:,}' if context else '',
            'memory': memory,
            'unloads_in': unloads_in,
            'processed': _last_prompt_progress(log_path),
            'available': available_match,
            'detail': '',
            'model_details': model_details,
            'restart_target': 'muse' if host.endswith(':11434') else None,
        }
    except (requests.RequestException, ValueError, TypeError) as e:
        return {'name': name, 'ok': False, 'ollama': True, 'loaded': False, 'available': False, 'detail': str(e).split(':', 1)[0]}

def _gunicorn_worker_count(app_target):
    """Count gunicorn workers serving an app (total processes minus the master)."""
    try:
        result = subprocess.run(['pgrep', '-f', f'gunicorn.*{app_target}'],
                                capture_output=True, text=True, timeout=2, check=False)
        pids = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        return max(0, len(pids) - 1)
    except (OSError, subprocess.SubprocessError):
        return 0


def _listener_uptime(port):
    """Seconds since the oldest process listening on a TCP port started —
    the boot moment shared by a gunicorn master and its workers."""
    try:
        result = subprocess.run(['lsof', '-t', f'-iTCP:{port}', '-sTCP:LISTEN'],
                                capture_output=True, text=True, timeout=3, check=False)
        pids = [int(line.strip()) for line in result.stdout.splitlines() if line.strip().isdigit()]
    except (OSError, subprocess.SubprocessError, ValueError):
        return None
    oldest = None
    for pid in pids:
        try:
            created = psutil.Process(pid).create_time()
        except (psutil.Error, ValueError):
            continue
        oldest = created if oldest is None else min(oldest, created)
    return max(0, int(time.time() - oldest)) if oldest is not None else None


def _format_uptime(seconds):
    """Compact uptime in the largest sensible unit: 42s, 5m, 3h 12m, 2d 4h."""
    if seconds is None:
        return ''
    if seconds < 60:
        return f'{seconds}s'
    if seconds < 3600:
        return f'{seconds // 60}m'
    if seconds < 24 * 3600:
        return f'{seconds // 3600}h {(seconds % 3600) // 60}m'
    return f'{seconds // (24 * 3600)}d {(seconds % (24 * 3600)) // 3600}h'


def _load_services_config():
    """Standalone service list from services.json beside this file. Hosts are
    optional per entry: unset means MONITOR_TARGET_HOST, so one variable
    retargets the whole page."""
    try:
        with open(os.path.join(PACKAGE_DIR, 'services.json'), encoding='utf-8') as f:
            config = json.load(f)
    except (OSError, ValueError):
        return []
    services = config.get('services') if isinstance(config, dict) else config
    if not isinstance(services, list):
        return []
    return [service for service in services if isinstance(service, dict)]


def _standalone_health_parser(payload, name):
    # mlx servers name these fields loaded_model/loaded_context_size; the
    # original dspark style used model/context_window — accept both.
    raw = payload.get('loaded_context_size') or payload.get('context_window')
    try:
        tokens = int(raw)
        context = f'{tokens // 1024}K' if tokens % 1024 == 0 else f'{tokens:,}'
    except (TypeError, ValueError):
        context = '—'
    return {'name': name, 'qwen': True,
            'loaded_model': str(payload.get('loaded_model') or payload.get('model') or 'unknown'),
            'context': context}


def _standalone_chat_parser(payload):
    models = payload if isinstance(payload, list) else (
        payload.get('models') if isinstance(payload, dict) else [])
    rows = [{'name': str(m.get('label') or m.get('model') or m.get('id') or 'model'),
             'online': bool(m.get('online', True))}
            for m in models if isinstance(m, dict)]
    return {'chat': True, 'models': rows or [{'name': 'No models reported', 'online': False}]}


def _launchd_loaded(label):
    try:
        result = subprocess.run(['launchctl', 'print', f'gui/{os.getuid()}/{label}'],
                                capture_output=True, timeout=5)
        return result.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _service_power():
    label = str(request.form.get('label') or '').strip()
    action = str(request.form.get('action') or '').strip()
    allowed = {str(s.get('launchd')) for s in _load_services_config()
               if isinstance(s, dict) and s.get('launchd')}
    if action not in ('start', 'stop') or label not in allowed:
        return 'Bad request', 400
    uid = os.getuid()
    if action == 'stop':
        # disable first so KeepAlive cannot relaunch during bootout; the
        # disabled flag persists across reboots until Start is pressed.
        subprocess.run(['launchctl', 'disable', f'gui/{uid}/{label}'],
                       capture_output=True, timeout=15)
        subprocess.run(['launchctl', 'bootout', f'gui/{uid}/{label}'],
                       capture_output=True, timeout=15)
    else:
        subprocess.run(['launchctl', 'enable', f'gui/{uid}/{label}'],
                       capture_output=True, timeout=15)
        plist = os.path.expanduser(f'~/Library/LaunchAgents/{label}.plist')
        subprocess.run(['launchctl', 'bootstrap', f'gui/{uid}', plist],
                       capture_output=True, timeout=15)
    return redirect('/')


app.add_url_rule('/service/power', 'service_power', _monitor_required(_service_power), methods=['POST'])


def _standalone_cards():
    """Standalone mode: one card per entry in services.json."""
    services = _load_services_config()
    if not services:
        return [{'name': 'No services configured', 'ok': False,
                 'detail': 'Describe this machine’s model services in services.json (see AGENTS.md).'}]
    cards = []
    for service in services:
        kind = str(service.get('kind') or 'http').strip().lower()
        host = str(service.get('host') or TARGET_HOST)
        port = service.get('port')
        name = str(service.get('name') or f'{kind} {port or ""}').strip()
        url = str(service.get('url') or '').strip() or (f'http://{host}:{port}' if port else f'http://{host}')
        if kind == 'ollama':
            cards.append(_probe_ollama(name, url, str(service.get('model') or ''), service.get('log')))
        elif kind == 'health':
            probe_url = url if url.endswith('/health') else f'{url}/health'
            cards.append(_probe(url=probe_url, name=name,
                                parser=lambda payload, n=name: _standalone_health_parser(payload, n)))
        elif kind == 'chat':
            cards.append(_probe(url=(f'https://{host}:{port}/api/models' if port else url), name=name,
                                parser=_standalone_chat_parser, verify=False))
        else:
            cards.append(_probe(name=name, url=url))
        label = str(service.get('launchd') or '').strip()
        if label:
            card = cards[-1]
            card['launchd'] = label
            card['launchd_running'] = _launchd_loaded(label)
            # the probe only sets qwen on success; force the branch that
            # carries the Agent status line and Start/Stop buttons when down
            card.setdefault('qwen', True)
    return cards


def system_status():
    if not FULL_MODE:
        return _standalone_cards()
    def chat_health(name, url):
        item = _probe(url=url, name=name, parser=chat_models, verify=False)
        item['chat'] = True
        if TARGET_LOCAL:
            item['uptime'] = _format_uptime(_listener_uptime(url.split('/api/')[0].rsplit(':', 1)[-1]))
        if not item.get('ok'):
            item['models'] = [{'name': 'Available: No', 'online': False}]
        elif ':7777' in url and TARGET_LOCAL:
            workers = _gunicorn_worker_count('backend:app')
            if workers:
                item['workers'] = workers
        return item

    def monitor_health(name):
        """The monitor's own card: it is definitionally up while rendering."""
        detail_lines = []
        if TARGET_LOCAL:
            uptime = _format_uptime(_listener_uptime(7779))
            if uptime:
                detail_lines.append(f'Uptime: {uptime}')
            workers = _gunicorn_worker_count('monitor:app')
            if workers:
                detail_lines.append(f'Gunicorn: {workers} workers')
        return {'name': name, 'ok': True, 'detail': '\n'.join(detail_lines) or 'Responding'}

    def qwen_health(name, url, port):
        item = _probe(url=url, name=name, parser=lambda payload: qwen_model(payload, port))
        item['qwen'] = True
        item['restart_target'] = f'qwen-{port}' if item.get('ok') else None
        if not item['ok']:
            item['detail'] = 'Available: No'
        return item

    def qwen_model(payload, port):
        model = str(payload.get('model', 'unknown'))
        short_model = '-'.join(model.split('-')[:2])
        # The 27B card carries the /qwen shortcut (dropping the DSpark prefix
        # keeps the name short enough to fit); the 14B card has no shortcut.
        name = f'{short_model} {port} /qwen' if port == '11232' else f'MLX-DSpark {port} ({short_model})'
        return {
            'name': name,
            'qwen': True,
            'loaded_model': model,
            'context': payload.get('context_window', '—'),
        }
    def chat_models(payload):
        shortcuts = {'qwen': '/qwen', 'muse-glimmer': '/muse',
                     'openai-luna': '/luna', 'openrouter': '/or',
                     'zai-glm': '/z', 'zai-flash': '/zf'}
        return {
            'chat': True,
            'models': [
                {'name': m.get('label') or m.get('model') or 'unknown', 'shortcut': shortcuts.get(m.get('id')), 'online': bool(m.get('online'))}
                for m in payload
            ],
        }
    def provider_spend_lines(backend_ids):
        """Completed-query spend per provider from the chat_jobs ledger."""
        store = chat_backend.RESEARCH_STORE
        lines = []
        for days in (1, 7, 30):
            total = None
            try:
                with store.connect() as db:
                    row = db.execute("""SELECT COALESCE(SUM(query_cost), 0) FROM chat_jobs
                                      WHERE backend = ANY(%s) AND status = 'complete'
                                      AND completed_at > now() - make_interval(days => %s)""",
                                     (backend_ids, days)).fetchone()
                total = float(row[0] or 0)
            except Exception:
                total = None
            lines.append({'name': f"Spend {days}d: " + (f"${total:.4f}" if total is not None else '—'), 'online': True})
        return lines

    def openrouter_status():
        card = {
            'name': 'OpenRouter API (Auto) /or',
            'openrouter': True,
            'provider_card': True,
            'external_card': True,
            'ok': bool(chat_backend.OPENROUTER_API_KEY),
        }
        if chat_backend.OPENROUTER_API_KEY:
            try:
                response = requests.get('https://openrouter.ai/api/v1/auth/key',
                                        headers={'Authorization': f'Bearer {chat_backend.OPENROUTER_API_KEY}'},
                                        timeout=5)
                if response.ok:
                    data = (response.json() or {}).get('data') or {}
                    used = float(data.get('usage') or 0)
                    limit = data.get('limit')
                    card.setdefault('models', []).append(
                        {'name': f"Credits used: ${used:.2f}" + (f" of ${float(limit):.2f}" if limit is not None else ''),
                         'online': True})
                    if limit is not None:
                        card['models'].append({'name': f"Budget remaining: ${max(0.0, float(limit) - used):.2f}", 'online': True})
            except (requests.RequestException, ValueError, TypeError):
                pass
        card['models'] = (card.get('models') or []) + provider_spend_lines(['openrouter'])
        return card

    def zai_status(model_id, name, shortcut):
        configured = bool(chat_backend.ZAI_API_KEY)
        return {
            'name': f'{name} {shortcut}',
            'chat': True,
            'external': True,
            'provider_card': True,
            'external_card': True,
            'ok': configured,
            'models': [
                {'name': f"Available: {'Admins only' if configured else 'No key'}", 'online': False},
                *provider_spend_lines([model_id]),
            ],
        }
    def openai_status():
        available = bool(chat_backend.OPENAI_API_KEY)
        usage_lines = []
        usage_table = []
        now = datetime.datetime.now(datetime.timezone.utc).timestamp()
        end_time = (int(now) // 86400 + 1) * 86400
        if now >= _OPENAI_USAGE_CACHE['expires']:
            admin_key = chat_backend._keychain_secret('chatLlama', 'openai-admin')
            if admin_key:
                for days in (1, 2, 7, 30):
                    total = 0.0
                    try:
                        response = requests.get(
                            'https://api.openai.com/v1/organization/costs',
                            params={'start_time': end_time - days * 86400, 'end_time': end_time,
                                    'bucket_width': '1d', 'limit': days},
                            headers={'Authorization': f'Bearer {admin_key}'},
                            timeout=5,
                        )
                        if response.ok:
                            for bucket in response.json().get('data', []):
                                for result in bucket.get('results', []):
                                    amount = result.get('amount') or {}
                                    total += float(amount.get('value') or 0)
                            usage_lines.append({'name': f"Usage {days}d{' UTC' if days == 30 else ''}: " + format(total, '.2f'), 'online': True})
                            usage_table.append({'days': days, 'value': format(total, '.2f')})
                        else:
                            usage_lines.append({'name': f"Usage {days}d{' UTC' if days == 30 else ''}: —", 'online': True})
                            usage_table.append({'days': days, 'value': '—'})
                    except (requests.RequestException, ValueError, TypeError):
                        usage_lines.append({'name': f"Usage {days}d{' UTC' if days == 30 else ''}: —", 'online': True})
                        usage_table.append({'days': days, 'value': '—'})
                _OPENAI_USAGE_CACHE.update({'expires': now + 60, 'lines': usage_lines, 'table': usage_table})
            else:
                _OPENAI_USAGE_CACHE.update({'expires': now + 60, 'lines': [], 'table': []})
        usage_lines = list(_OPENAI_USAGE_CACHE['lines'])
        usage_table = list(_OPENAI_USAGE_CACHE.get('table') or [])
        if not usage_lines:
            usage_lines = [{'name': 'Usage: unavailable', 'online': True}]
        if not usage_table:
            usage_table = [{'days': days, 'value': '—'} for days in (1, 2, 7, 30)]
        budget = float((chat_backend.LOCAL_CONFIG.get('openai') or {}).get('monthly_budget') or 0)
        month_spend = next((float(item['value'] or 0) for item in usage_table if item['days'] == 30
                            and str(item.get('value', '—')).replace('.', '').isdigit()), None)
        budget_lines = []
        if budget > 0:
            budget_lines.append({'name': f"Monthly budget: ${budget:,.2f}", 'online': True})
            if month_spend is not None:
                budget_lines.append({'name': f"Budget remaining: ${max(0.0, budget - month_spend):,.2f}", 'online': True})
        return {
            'name': 'OpenAI API (GPT-6 Luna) /luna',
            'chat': True,
            'external': True,
            'ok': available,
            'usage': usage_table,
            'models': [
                {'name': f"Available: {'Admins only' if available else 'No'}", 'online': False},
                *budget_lines,
                *usage_lines,
                *provider_spend_lines(['openai-luna']),
            ],
        }
    cards = [
        _probe_ollama('Ollama 11434 (Muse Glimmer) /muse', f'http://{TARGET_HOST}:11434', 'muse-glimmer:30b-mlx', '/tmp/ollama-glimmer.err'),
        _probe_ollama('Ollama 11435 (Nomic embeddings)', f'http://{TARGET_HOST}:11435', 'nomic-embed-text', '/tmp/ollama-nomic.err'),
        _probe_ollama('Ollama 11436 (Gemma compaction)', f'http://{TARGET_HOST}:11436', 'gemma4:e4b', '/tmp/ollama-gemma.err'),
        qwen_health('Qwen3.8-27B 11232 /qwen', f'http://{TARGET_HOST}:11232/health', '11232'),
        qwen_health('MLX-DSpark 11233 (Qwen3-14B)', f'http://{TARGET_HOST}:11233/health', '11233'),
    ]
    if FULL_MODE:
        # Provider spend and usage cards need the chat server's keys/store.
        cards += [
            openrouter_status(),
            zai_status('zai-glm', 'GLM-5.3 (z.ai)', '/z'),
            zai_status('zai-flash', 'GLM-5.3-Flash (z.ai)', '/zf'),
            openai_status(),
        ]
    cards += [
        chat_health('Chat 7777 (main)', f'https://{TARGET_HOST}:7777/api/models'),
        chat_health('Chat 7778 (dev)', f'https://{TARGET_HOST}:7778/api/models'),
        monitor_health('Monitor 7779'),
    ]
    return cards

@app.get('/robots.txt')
def robots_txt():
    return app.response_class('User-agent: *\nDisallow: /\n', content_type='text/plain; charset=utf-8')

@app.get('/monitor.png')
@app.get('/favicon.ico')
def monitor_icon():
    return send_from_directory(os.path.join(os.path.dirname(__file__), 'web'), 'monitor.png')

@app.get('/apple-touch-icon.png')
@app.get('/apple-touch-icon-precomposed.png')
@app.get('/apple-touch-icon-120x120.png')
@app.get('/apple-touch-icon-120x120-precomposed.png')
def apple_touch_icon():
    return send_from_directory(os.path.join(os.path.dirname(__file__), 'web'), 'monitor.png')

@app.get('/')
@_monitor_required
def index():
    now = datetime.datetime.now(ZoneInfo('America/New_York')).strftime('%Y-%m-%d %I:%M:%S %p %Z')
    user = _monitor_user()
    admin = _monitor_admin()
    try:
        with open(MONITOR_SIGNAL_PATH, encoding='utf-8') as signal_file:
            monitor_signal = signal_file.read().strip() or '0'
    except OSError:
        monitor_signal = '0'
    log_entries = entries() if admin else []
    try:
        per_page = int(request.args.get('per_page', 25))
    except (TypeError, ValueError):
        per_page = 25
    per_page = min((10, 25, 50, 100), key=lambda option: abs(option - per_page))
    page_count = max(1, (len(log_entries) + per_page - 1) // per_page)
    try:
        page = max(1, int(request.args.get('page', 1)))
    except (TypeError, ValueError):
        page = 1
    page = min(page, page_count)
    start = (page - 1) * per_page
    log_entries = list(reversed(log_entries))[start:start + per_page]
    response = app.make_response(render_template_string(PAGE, entries=log_entries, page=page, page_count=page_count, per_page=per_page, page_sizes=(10, 25, 50, 100), jobs=active_jobs() if admin else [], time=display_time, status=system_status(), health=system_health() if TARGET_LOCAL else [], health_title=server_identity() if TARGET_LOCAL else f'Target: {TARGET_HOST}', checked=now, monitor_signal=monitor_signal, refresh_seconds=10 if admin else 30,
                                                        monitor_user=f"{user['username']} (#{user['id']})" if user else f'standalone · {TARGET_HOST}', pending=_pending_monitor_users() if admin else [], show_log=bool(admin)))
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate'
    return response

@app.post('/api/chat-jobs/<job_id>/cancel')
@_monitor_required
def cancel_chat_job_from_monitor(job_id):
    if not _monitor_admin():
        return jsonify({'error': 'Monitor administrator access is required'}), 403
    if not chat_backend.RESEARCH_STORE.cancel_chat_job_admin(job_id, chat_backend.AUTH_ENVIRONMENT):
        return jsonify({'error': 'Chat job not found or already finished'}), 404
    return jsonify({'ok': True})


@app.post('/api/chat-jobs/<job_id>/stale')
@_monitor_required
def mark_stale_chat_job_from_monitor(job_id):
    if not _monitor_admin():
        return jsonify({'error': 'Monitor administrator access is required'}), 403
    if not chat_backend.RESEARCH_STORE.mark_stale_chat_job_admin(job_id, chat_backend.AUTH_ENVIRONMENT):
        return jsonify({'error': 'Job is not stale, not active, or no longer exists'}), 409
    return jsonify({'ok': True, 'status': 'cancelled'})


def _muse_launch_environment(environment):
    """Carry the LaunchAgent's Ollama settings into a monitor-initiated restart."""
    try:
        with open(os.path.expanduser('~/Library/LaunchAgents/com.ollama.glimmer.plist'), 'rb') as plist_file:
            for key, value in (plistlib.load(plist_file).get('EnvironmentVariables') or {}).items():
                environment[str(key)] = str(value)
    except (OSError, ValueError):
        pass
    return environment


def _listener_process(port):
    try:
        result = subprocess.run(
            ['lsof', '-t', f'-iTCP:{port}', '-sTCP:LISTEN'],
            capture_output=True, text=True, timeout=3, check=False,
        )
        pid_text = next((line.strip() for line in result.stdout.splitlines() if line.strip()), '')
        return psutil.Process(int(pid_text)) if pid_text else None
    except (OSError, ValueError, psutil.Error, subprocess.SubprocessError):
        return None


@app.post('/api/model-services/<target>/restart')
@_monitor_required
def restart_model_service(target):
    if not _monitor_admin():
        return jsonify({'error': 'Monitor administrator access is required'}), 403
    target = str(target or '')
    if target == 'muse':
        port = 11434
        process = _listener_process(port)
        command = ['/usr/local/bin/ollama', 'serve']
        environment = _muse_launch_environment(os.environ.copy())
        environment['OLLAMA_HOST'] = '127.0.0.1:11434'
    elif target in {'qwen-11232', 'qwen-11233'}:
        port = int(target.rsplit('-', 1)[1])
        process = _listener_process(port)
        if not process:
            return jsonify({'error': f'Qwen service on port {port} is not running, so its launch command is unavailable'}), 409
        try:
            command = process.cmdline()
        except psutil.Error:
            command = []
        if not command or 'mlx-dspark' not in ' '.join(command):
            return jsonify({'error': f'Could not safely identify the Qwen service on port {port}'}), 409
        environment = os.environ.copy()
    else:
        return jsonify({'error': 'Unknown model service'}), 404
    if process:
        try:
            process.terminate()
            process.wait(timeout=5)
        except psutil.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        except psutil.Error as error:
            return jsonify({'error': f'Could not stop model service: {error}'}), 500
    try:
        subprocess.Popen(command, cwd=PROJECTS, env=environment,
                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, start_new_session=True)
    except OSError as error:
        return jsonify({'error': f'Could not start model service: {error}'}), 500
    if request.form.get('from_monitor') == '1':
        return redirect('/', code=303)
    return jsonify({'ok': True, 'target': target, 'port': port}), 202

@app.get('/api/connections')
@_monitor_required
def api():
    if not _monitor_admin():
        return jsonify({'error': 'Monitor administrator access is required'}), 403
    return jsonify({'checked_at': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'status': system_status(), 'connections': entries(), 'jobs': active_jobs()})

@app.post('/api/monitor/allow')
@_monitor_required
def allow_monitor_user():
    if not _monitor_admin():
        return jsonify({'error': 'Monitor administrator access is required'}), 403
    data = request.get_json(silent=True) or {}
    try:
        user_id = int(data.get('id'))
    except (TypeError, ValueError):
        return jsonify({'error': 'A valid user id is required'}), 400
    username = str(data.get('username') or '').strip()
    label = f'{username} (#{user_id})'
    if not username or len(username) > 80:
        return jsonify({'error': 'A valid username is required'}), 400
    MONITOR_ALLOWED_USERS.add(label)
    os.makedirs(os.path.dirname(MONITOR_ALLOWED_PATH), exist_ok=True)
    _atomic_write_json(MONITOR_ALLOWED_PATH, sorted(MONITOR_ALLOWED_USERS))
    actor = _monitor_user()
    if actor:
        _monitor_authorization_log(user_id, username, actor)
    return jsonify({'ok': True, 'allowed': label})

@app.post('/api/monitor/ignore')
@_monitor_required
def ignore_monitor_user():
    if not _monitor_admin():
        return jsonify({'error': 'Monitor administrator access is required'}), 403
    data = request.get_json(silent=True) or {}
    try:
        user_id = int(data.get('id'))
    except (TypeError, ValueError):
        return jsonify({'error': 'A valid user id is required'}), 400
    username = str(data.get('username') or '').strip()
    label = f'{username} (#{user_id})'
    if not username or len(username) > 80:
        return jsonify({'error': 'A valid username is required'}), 400
    MONITOR_IGNORED_USERS.add(label)
    os.makedirs(os.path.dirname(MONITOR_IGNORED_PATH), exist_ok=True)
    _atomic_write_json(MONITOR_IGNORED_PATH, sorted(MONITOR_IGNORED_USERS))
    return jsonify({'ok': True, 'ignored': label})

if __name__ == '__main__':
    ssl_context = (MONITOR_CERT, MONITOR_KEY) if os.path.isfile(MONITOR_CERT) and os.path.isfile(MONITOR_KEY) else None
    app.run(host='0.0.0.0', port=int(os.getenv('MONITOR_PORT') or 7779), ssl_context=ssl_context)
