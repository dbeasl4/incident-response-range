#!/bin/bash
# Run the AI Incident-Response Test Range -- Scenario HF-01
# ---------------------------------------------------------
# Builds all containers, runs the agent through the chain,
# then shows the labeled telemetry.

set -e

echo "=================================================="
echo " AI Incident-Response Test Range -- Scenario HF-01"
echo "=================================================="

# Clean up previous run
rm -f telemetry/events.jsonl telemetry/external_drop.jsonl
mkdir -p telemetry

# Build and run -- abort when agent container exits
docker compose up --build --abort-on-container-exit

echo ""
echo "=================================================="
echo " TELEMETRY (ground-truth labeled events)"
echo "=================================================="

if [ -f telemetry/events.jsonl ]; then
    python3 -c "
import json, sys
events = [json.loads(l) for l in open('telemetry/events.jsonl')]
colors = {'benign': '\033[32m', 'violation': '\033[33m', 'irreversible': '\033[31m'}
reset = '\033[0m'
print(f'  {'seq':>3}  {'phase':<22}  {'action':<6}  {'credential':<30}  {'destination':<25}  truth')
print('-' * 110)
for e in events:
    c = colors.get(e['truth'], '')
    print(f\"  {e['seq']:>3}  {e['phase']:<22}  {e['action']:<6}  {e['credential'] or '-':<30}  {e['destination']:<25}  {c}{e['truth']}{reset}\")
benign = sum(1 for e in events if e['truth'] == 'benign')
viol   = sum(1 for e in events if e['truth'] == 'violation')
irrev  = sum(1 for e in events if e['truth'] == 'irreversible')
print()
print(f'  Total: {len(events)} events -- {benign} benign, {viol} violation, {irrev} irreversible')
first_viol = next((e['seq'] for e in events if e['truth'] == 'violation'), None)
first_irrev = next((e['seq'] for e in events if e['truth'] == 'irreversible'), None)
if first_viol and first_irrev:
    print(f'  First violation at seq {first_viol}, irreversible at seq {first_irrev}')
    print(f'  Lead time: {first_irrev - first_viol} events between first violation and exfiltration')
"
else
    echo "  No telemetry found -- did the proxy start correctly?"
fi

echo ""
echo "=================================================="
echo " EXTERNAL DROP LOG (what the attacker exfiltrated)"
echo "=================================================="
if [ -f telemetry/external_drop.jsonl ]; then
    cat telemetry/external_drop.jsonl | python3 -m json.tool
else
    echo "  Nothing received at external-drop -- exfiltration didn't reach it"
fi

echo ""
echo "Done. Full telemetry in ./telemetry/events.jsonl"
echo "Feed this to the C++ evaluator: ./build/range3 telemetry/events.jsonl"
