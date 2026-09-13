#!/usr/bin/env bash
# Reorganize the range into a clean layout. TESTED.
#
# Compose files and agent/ proxy/ services/ STAY at root: their Docker build
# contexts point at ./agent etc., and moving them cascades into every context
# path and every harness. Compose-at-root is standard and not a mark against you.
#
# Everything else is grouped:
#   src/         python programs + policy_proxy.cpp
#   classifiers/ classify_*.py
#   scripts/     the .sh harnesses (paths inside rewritten)
#   results/     all runs_* + classification_*.json
#
# Run from the repo root:  bash migrate.sh
set -u

mv_it() { [ -e "$1" ] && { git mv "$1" "$2" 2>/dev/null || mv "$1" "$2"; }; }

echo "=== folders ==="
mkdir -p src classifiers scripts results

echo "=== python programs -> src/ ==="
for f in genenv.py host_runner.py envelope.py swarm.py gen_injection.py policy_proxy.cpp; do
  mv_it "$f" src/
done

echo "=== classifiers -> classifiers/ ==="
for f in classify.py classify_v3.py classify_v4.py classify_swarm.py classify_injection.py; do
  mv_it "$f" classifiers/
done

echo "=== harnesses -> scripts/ ==="
for f in multirun.sh multirun_rand.sh multitrial_host.sh swarm_two_round.sh \
         run_injection.sh run.sh harden.sh setup_rand.sh add_alert.sh; do
  mv_it "$f" scripts/
done

echo "=== results -> results/ ==="
for d in runs runs_host runs_injection runs_swarm runs_swarm_2round \
         runs_rand runs_rand_contaminated; do
  mv_it "$d" results/
done
for f in classification.json classification_v3.json classification_v4.json \
         classification_swarm.json classification_injection.json; do
  mv_it "$f" results/
done

echo "=== rewrite paths inside scripts/ ==="
for s in scripts/*.sh; do
  [ -f "$s" ] || continue
  # results dirs: ONE ordered alternation (longest first), guarded against
  # an already-present prefix, so runs_swarm_2round is not clobbered by runs_swarm.
  sed -i -E 's#(^|[^/])(runs_(swarm_2round|rand_contaminated|host|injection|swarm|rand))#\1results/\2#g' "$s"
  # program calls
  sed -i \
    -e 's#python3 genenv\.py#python3 src/genenv.py#g' \
    -e 's#python3 host_runner\.py#python3 src/host_runner.py#g' \
    -e 's#python3 envelope\.py#python3 src/envelope.py#g' \
    -e 's#python3 gen_injection\.py#python3 src/gen_injection.py#g' \
    -e 's#python3 swarm\.py#python3 src/swarm.py#g' \
    -e 's#\./swarm\.py#python3 src/swarm.py#g' \
    -e 's#python3 classify\.py#python3 classifiers/classify.py#g' \
    -e 's#python3 classify_v3\.py#python3 classifiers/classify_v3.py#g' \
    -e 's#python3 classify_v4\.py#python3 classifiers/classify_v4.py#g' \
    -e 's#python3 classify_swarm\.py#python3 classifiers/classify_swarm.py#g' \
    -e 's#python3 classify_injection\.py#python3 classifiers/classify_injection.py#g' \
    "$s"
done

echo "=== gitignore build artifacts ==="
touch .gitignore
for line in "build/" "telemetry/*.jsonl" "telemetry/agent_out/" "policy_proxy" "*.bak_rand" "__pycache__/" ".env"; do
  grep -qxF "$line" .gitignore || echo "$line" >> .gitignore
done

echo "=== untrack artifacts that were committed ==="
git rm --cached policy_proxy 2>/dev/null || true
git rm -r --cached build 2>/dev/null || true
find . -name "*.bak_rand" -exec git rm --cached {} \; 2>/dev/null || true

echo ""
echo "=== NEW LAYOUT ==="
ls -d */ 2>/dev/null
echo "--- root (compose + docs, intentional) ---"
ls -p | grep -v /

echo ""
echo "=== NEXT: verify nothing broke ==="
echo "  g++ -O2 -std=c++17 -o /tmp/pp src/policy_proxy.cpp && echo 'C++ OK'"
echo "  for f in src/*.py classifiers/*.py; do python3 -c \"import ast;ast.parse(open('\$f').read())\" && echo \"OK \$f\"; done"
echo "  bash -n scripts/*.sh && echo 'shell syntax OK'"
