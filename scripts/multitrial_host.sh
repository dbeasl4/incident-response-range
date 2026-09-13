#!/usr/bin/env bash
# Host-driven multi-trial harness
# ===============================
# The container holds only the environment. The agent loop runs here on the
# host and reaches in with `docker exec`, so no harness file exists inside for
# a model to find and read.
#
# Usage:
#   export ANTHROPIC_API_KEY=sk-ant-...
#   ./multitrial_host.sh 20 3 narrow 5000
#   ./multitrial_host.sh 20 3 exploratory 6000
#
# Args:
#   $1 environments   default 10
#   $2 trials/env     default 3
#   $3 variant        default narrow
#   $4 first seed     default 5000
#
# Output: results/runs_host/<variant>/s<SEED>-t<N>/

set -u

NENV="${1:-10}"
NTRIAL="${2:-3}"
VARIANT="${3:-narrow}"
SEED0="${4:-5000}"
OUTDIR="results/runs_host/${VARIANT}"
COMPOSE="docker-compose.host.yml"

if [ -z "${ANTHROPIC_API_KEY:-}" ]; then
  echo "ANTHROPIC_API_KEY not set"; exit 1
fi

TOTAL=$((NENV * NTRIAL))
mkdir -p "$OUTDIR" agent/fixtures telemetry

echo "=================================================="
echo " Host-driven multi-trial harness"
echo " Variant      : $VARIANT"
echo " Environments : $NENV  (seeds ${SEED0}..$((SEED0+NENV-1)))"
echo " Trials/env   : $NTRIAL"
echo " Total runs   : $TOTAL"
echo "=================================================="

START=$(date +%s); DONE=0

cleanup() {
  sudo docker compose -f "$COMPOSE" down --remove-orphans >/dev/null 2>&1
}
trap cleanup EXIT

for e in $(seq 1 "$NENV"); do
  SEED=$((SEED0 + e - 1))

  python3 src/genenv.py --seed "$SEED" --out agent/fixtures

  python3 - << 'PYEOF'
frag = open('agent/fixtures/env.dockerfile').read()
tpl  = open('agent/Dockerfile.envonly').read()
open('agent/Dockerfile.env','w').write(tpl.replace('# @@ENV_FRAGMENT@@', frag))
PYEOF
  # point compose at the generated dockerfile
  sed -i 's/dockerfile: Dockerfile.envonly/dockerfile: Dockerfile.env/' "$COMPOSE" 2>/dev/null || true

  AUTH_VAR=$(python3 -c "import json;print(json.load(open('agent/fixtures/manifest.json'))['authorized_var'])")
  AUTH_VAL=$(python3 -c "import json;print(json.load(open('agent/fixtures/manifest.json'))['authorized_val'])")
  FRAMING=$(python3 -c "import json;print(json.load(open('agent/fixtures/manifest.json'))['framing'])")
  SDIR=$(python3 -c "import json;print(json.load(open('agent/fixtures/manifest.json'))['secret_dir'])")

  echo ""
  echo "--- seed $SEED  framing=$FRAMING  dir=$SDIR ---"

  for t in $(seq 1 "$NTRIAL"); do
    RID="s${SEED}-t${t}"
    RUNDIR="$OUTDIR/$RID"
    mkdir -p "$RUNDIR"

    rm -f telemetry/events.jsonl telemetry/external_drop.jsonl

    # Fresh stack per trial so the environment is pristine
    sudo AUTH_VAR="$AUTH_VAR" AUTH_VAL="$AUTH_VAL" \
         docker compose -f "$COMPOSE" up -d --build >/dev/null 2>&1

    # Wait for the environment container
    for _ in $(seq 1 20); do
      if sudo docker ps --format '{{.Names}}' | grep -q '^range_env$'; then break; fi
      sleep 1
    done
    sleep 2

    ANTHROPIC_API_KEY="$ANTHROPIC_API_KEY" \
    python3 src/host_runner.py \
      --container range_env \
      --seed "$SEED" \
      --variant "$VARIANT" \
      --run-id "$RID" \
      --auth-var "$AUTH_VAR" \
      --out "$RUNDIR" > "$RUNDIR/console.log" 2>&1

    sudo docker compose -f "$COMPOSE" down --remove-orphans >/dev/null 2>&1

    cp telemetry/events.jsonl        "$RUNDIR/" 2>/dev/null
    cp telemetry/external_drop.jsonl "$RUNDIR/" 2>/dev/null
    cp agent/fixtures/manifest.json  "$RUNDIR/" 2>/dev/null
    cp agent/fixtures/envelope.json  "$RUNDIR/" 2>/dev/null

    DONE=$((DONE + 1))
    ELAPSED=$(( $(date +%s) - START ))
    ETA=$(( DONE > 0 ? ELAPSED * (TOTAL - DONE) / DONE : 0 ))

    EV=0;  [ -f "$RUNDIR/events.jsonl" ] && EV=$(wc -l < "$RUNDIR/events.jsonl")
    TR="MISSING"; [ -s "$RUNDIR/agent_trace.jsonl" ] && TR="ok"

    printf "  t%-2s events=%-3s trace=%-8s [%d/%d]  eta %dm%02ds\n" \
           "$t" "$EV" "$TR" "$DONE" "$TOTAL" $((ETA/60)) $((ETA%60))
  done
done

TOT=$(( $(date +%s) - START ))
echo ""
echo "=================================================="
echo " Complete: $DONE runs in $((TOT/60))m$((TOT%60))s"
echo " Classify: python3 classifiers/classify_v4.py $OUTDIR"
echo "=================================================="
