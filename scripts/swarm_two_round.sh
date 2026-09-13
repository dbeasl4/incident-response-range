#!/usr/bin/env bash
# Two-Round Swarm
# ===============
# Single-pass swarm showed agents establish a coordination protocol -- they
# discover the shared channel, write structured requests, agree on file paths --
# but never close the loop, because parallel one-shot execution gives no
# opportunity to re-read what a peer wrote.
#
# This runs the swarm TWICE against the same containers and the same /shared
# volume, which persists between invocations. Round 1 populates /shared with
# requests and data fragments. Round 2 runs the same agents again -- now the
# data they asked for already exists in /shared. The question: do the
# revenue-holders read the units files that now exist and complete their
# reports?
#
# If round 2 reaches L4 where round 1 stalled at L3, iteration is the
# demonstrated mechanism that turns an emergent protocol into actual
# coordination -- the arc the real incident traversed over four days,
# compressed to two turns.
#
# Usage:
#   export ANTHROPIC_API_KEY=sk-ant-...
#   ./swarm_two_round.sh 8100

set -u

SEED="${1:-8100}"
BASE="results/runs_swarm_2round"

if [ -z "${ANTHROPIC_API_KEY:-}" ]; then
  echo "ANTHROPIC_API_KEY not set"; exit 1
fi

# Confirm the split swarm is up.
N=$(docker ps --format '{{.Names}}' | grep -c 'range-agent_')
if [ "$N" -lt 5 ]; then
  echo "Need 5 split-swarm agents up. Bring them up with:"
  echo "  docker compose -f docker-compose.swarm2.yml up -d --build --scale agent_rev=3 --scale agent_units=2"
  exit 1
fi

echo "=================================================="
echo " Two-round swarm, seed $SEED"
echo "=================================================="

# ---- Round 1 --------------------------------------------------------------
echo ""
echo "### ROUND 1 -- protocol establishment ###"
R1="$BASE/round1"
python3 src/swarm.py --arm B --agents 5 --seed "$SEED" --out "$R1/armB/seed$SEED"

echo ""
echo "--- /shared after round 1 ---"
FIRST=$(docker ps --format '{{.Names}}' | grep 'range-agent_' | sort | head -1)
docker exec "$FIRST" ls -1a /shared

# ---- Round 2 --------------------------------------------------------------
# Same containers, same /shared (now populated). No teardown between rounds.
echo ""
echo "### ROUND 2 -- loop closure ###"
echo "(same agents, /shared now contains round-1 requests and data)"
R2="$BASE/round2"
python3 src/swarm.py --arm B --agents 5 --seed "$SEED" --out "$R2/armB/seed$SEED"

# ---- Snapshot and compare -------------------------------------------------
echo ""
echo "--- /shared after round 2 ---"
docker exec "$FIRST" ls -1a /shared

echo ""
echo "=================================================="
echo " ROUND 1 (protocol)"
echo "=================================================="
python3 classifiers/classify_swarm.py "$R1"

echo ""
echo "=================================================="
echo " ROUND 2 (loop closure)"
echo "=================================================="
python3 classifiers/classify_swarm.py "$R2"

echo ""
echo "Compare the L4 column: if round 2 reaches L4 where round 1 stalled at"
echo "L3, iteration closed the loop. Read the round-2 reports to confirm a"
echo "revenue-holder actually produced units figures it did not hold locally:"
echo "  docker exec $FIRST sh -c 'for f in /shared/*.md; do echo \"== \$f ==\"; head -40 \"\$f\"; done'"
