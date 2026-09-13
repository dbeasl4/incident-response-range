#!/usr/bin/env bash
# Randomized multi-run harness
# ============================
# Each run gets a FRESH environment generated from a distinct seed: different
# credential name, path, framing, and decoys. The manifest is preserved with
# the telemetry so every run is exactly reproducible and so results can be
# grouped by framing condition afterwards.
#
# Usage:
#   export ANTHROPIC_API_KEY=sk-ant-...
#   ./multirun_rand.sh 20 narrow
#   ./multirun_rand.sh 20 exploratory
#
# Args:
#   $1  number of runs (default 10)
#   $2  task variant: narrow | exploratory (default narrow)
#   $3  starting seed (default 1000)
#
# Output:
#   results/runs_rand/<variant>/run-NNN/{events,agent_trace,manifest}.json(l)

set -u

N="${1:-10}"
VARIANT="${2:-narrow}"
SEED0="${3:-1000}"
OUTDIR="results/runs_rand/${VARIANT}"

if [ -z "${ANTHROPIC_API_KEY:-}" ]; then
  echo "ANTHROPIC_API_KEY not set"; exit 1
fi

mkdir -p "$OUTDIR" agent/fixtures

echo "=================================================="
echo " Randomized multi-run harness"
echo " Variant : $VARIANT"
echo " Runs    : $N   (seeds ${SEED0}..$((SEED0+N-1)))"
echo "=================================================="

for i in $(seq 1 "$N"); do
  RID=$(printf "run-%03d" "$i")
  SEED=$((SEED0 + i - 1))
  RUNDIR="$OUTDIR/$RID"
  mkdir -p "$RUNDIR"

  echo ""
  echo "--- $RID (seed $SEED) ---"

  # 1. Generate this run's environment
  python3 src/genenv.py --seed "$SEED" --out agent/fixtures

  # 2. Splice the fragment into the Dockerfile
  python3 - << 'PYEOF'
frag = open('agent/fixtures/env.dockerfile').read()
tpl  = open('agent/Dockerfile.template').read()
open('agent/Dockerfile.rand','w').write(tpl.replace('# @@ENV_FRAGMENT@@', frag))
PYEOF

  # 3. Extract the authorized credential for this run
  AUTH_VAR=$(python3 -c "import json;print(json.load(open('agent/fixtures/manifest.json'))['authorized_var'])")
  AUTH_VAL=$(python3 -c "import json;print(json.load(open('agent/fixtures/manifest.json'))['authorized_val'])")
  FRAMING=$(python3 -c "import json;print(json.load(open('agent/fixtures/manifest.json'))['framing'])")

  # 4. Fresh telemetry
  rm -f telemetry/events.jsonl telemetry/agent_out/agent_trace.jsonl telemetry/external_drop.jsonl

  # 5. Run
  sudo RUN_ID="$RID" \
       TASK_VARIANT="$VARIANT" \
       ENV_SEED="$SEED" \
       AUTH_VAR="$AUTH_VAR" \
       AUTH_VAL="$AUTH_VAL" \
       ANTHROPIC_API_KEY="$ANTHROPIC_API_KEY" \
       docker compose -f docker-compose.rand.yml up --build \
       --abort-on-container-exit > "$RUNDIR/console.log" 2>&1

  # 6. Preserve everything needed to reproduce and interpret this run
  cp telemetry/events.jsonl        "$RUNDIR/" 2>/dev/null
  cp telemetry/agent_out/agent_trace.jsonl "$RUNDIR/" 2>/dev/null
  cp telemetry/external_drop.jsonl "$RUNDIR/" 2>/dev/null
  cp agent/fixtures/manifest.json  "$RUNDIR/" 2>/dev/null
  cp agent/fixtures/envelope.json  "$RUNDIR/" 2>/dev/null

  if [ -f "$RUNDIR/events.jsonl" ]; then
    E=$(wc -l < "$RUNDIR/events.jsonl")
    V=$(grep -c '"truth": "violation"'    "$RUNDIR/events.jsonl" 2>/dev/null || true)
    I=$(grep -c '"truth": "irreversible"' "$RUNDIR/events.jsonl" 2>/dev/null || true)
    echo "  framing=$FRAMING events=$E violations=${V:-0} irreversible=${I:-0}"
  else
    echo "  framing=$FRAMING  no telemetry produced"
  fi
done

echo ""
echo "Done. Classify with:"
echo "  python3 classifiers/classify_v3.py $OUTDIR"
