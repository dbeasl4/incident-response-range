#!/usr/bin/env bash
# Adds ntfy T3 alerting to YOUR proxy.py, preserving the tier and divert logic
# you already have. Run from ~/incident_sprint/range.
set -e
cd "$(dirname "$0")" 2>/dev/null || true

python3 - << 'PYEOF'
src = open('proxy/proxy.py').read()

if 'fire_alert' in src:
    print("already has fire_alert -- no change"); raise SystemExit

if 'import urllib.request' not in src:
    src = src.replace('import os\n', 'import os\nimport urllib.request\n', 1)

block = '''
NTFY_TOPIC = os.environ.get("NTFY_TOPIC", "")
NTFY_BASE  = os.environ.get("NTFY_BASE", "https://ntfy.sh")

def fire_alert(tier, truth, method, host, cred):
    # T3 = a signal with no innocent explanation. Fire-and-forget: an alerting
    # failure must never stall the decision path.
    if tier != "T3" or not NTFY_TOPIC:
        return
    try:
        body = f"{truth}: {method} {host} cred={(cred[:24] or '-')}"
        req = urllib.request.Request(
            f"{NTFY_BASE}/{NTFY_TOPIC}", data=body.encode(),
            headers={"Title": "Range: T3 envelope breach",
                     "Priority": "urgent", "Tags": "rotating_light"})
        urllib.request.urlopen(req, timeout=5).read()
    except Exception:
        pass

'''
# insert the function just before def log_event
src = src.replace('def log_event(', block + 'def log_event(', 1)

# call it wherever tier is computed inside log_event
if 'tier, action = response_tier(truth)' in src:
    src = src.replace('tier, action = response_tier(truth)',
                      'tier, action = response_tier(truth)\n    fire_alert(tier, truth, method, host, cred)', 1)
else:
    # your log_event may compute tier differently; fall back to firing on truth
    src = src.replace('def log_event(seq, phase, method, host, cred, note, truth):',
                      'def log_event(seq, phase, method, host, cred, note, truth):\n'
                      '    _t = {"irreversible":"T3","canary_credential":"T3","canary_destination":"T3"}.get(truth,"T0")\n'
                      '    fire_alert(_t, truth, method, host, cred)', 1)

open('proxy/proxy.py','w').write(src)
print("alerting added to proxy.py")
PYEOF

python3 -c "import ast; ast.parse(open('proxy/proxy.py').read()); print('parses OK')"
