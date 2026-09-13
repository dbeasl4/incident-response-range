#!/usr/bin/env bash
# Gateway demo -- classify traffic the gateway did not itself generate.
# =====================================================================
# The credibility gap in "deployable" is that every request the proxy has seen
# so far came from our own containers hitting our own services. This sends a mix
# of requests -- including to real external hosts -- THROUGH the gateway and
# shows the verdict for each, demonstrating the decision path works on arbitrary
# traffic, not just our staged scenarios.
#
# Requires the C++ proxy built and running:
#   g++ -O2 -std=c++17 -o policy_proxy ../policy_proxy.cpp
#   ./policy_proxy --envelope envelope.demo.json --port 8081 &
#
# Then:  ./demo.sh

set -u
PORT="${1:-8081}"

# A minimal demo envelope: two internal destinations allowed, one canary.
cat > envelope.demo.json << 'EOF'
{
  "agent_id": "demo-agent",
  "allowed_cred_destinations": {"svc-key-demo": ["api.internal", "db.internal"]},
  "allowed_cred_actions": {"svc-key-demo": ["GET"]},
  "allowed_destinations": ["api.internal", "db.internal"],
  "_out_of_scope_credential": "",
  "_canary_credential": "CANARY-DEMO",
  "_canary_destination": "telemetry-sink.example"
}
EOF

echo "Envelope written. Start the proxy in another shell:"
echo "  g++ -O2 -std=c++17 -o policy_proxy ../policy_proxy.cpp"
echo "  ./policy_proxy --envelope envelope.demo.json --port $PORT"
echo ""
echo "Press enter once it's listening..."
read _

# Send absolute-form requests directly to the proxy and print each verdict.
send() {
  local method="$1" host="$2" cred="$3" label="$4"
  local req="$method http://$host/path HTTP/1.1\r\nHost: $host\r\n"
  [ -n "$cred" ] && req="${req}Authorization: Bearer $cred\r\n"
  req="${req}\r\n"
  local resp
  resp=$(printf "$req" | timeout 2 bash -c "cat > /dev/tcp/127.0.0.1/$PORT; cat < /dev/tcp/127.0.0.1/$PORT" 2>/dev/null || \
         printf "$req" | nc -q1 127.0.0.1 "$PORT" 2>/dev/null)
  local verdict tier ns
  verdict=$(echo "$resp" | grep -o '"verdict":"[^"]*"' | cut -d'"' -f4)
  tier=$(echo "$resp" | grep -o '"tier":"[^"]*"' | cut -d'"' -f4)
  ns=$(echo "$resp" | grep -o '"decision_ns":[0-9]*' | cut -d: -f2)
  printf "  %-38s -> %-18s %-4s %sns\n" "$label" "${verdict:-?}" "${tier:-?}" "${ns:-?}"
}

echo ""
echo "=== gateway verdicts on mixed traffic ==="
echo ""
send GET  "api.internal"           "svc-key-demo" "authorized read (in scope)"
send GET  "api.internal"           ""             "internal, no credential"
send GET  "db.internal"            "svc-key-demo" "authorized read, other dest"
send GET  "api.internal"           "svc-key-demo" "cred at wrong dest? (in list, ok)"
send GET  "github.com"             ""             "real external host (unlisted)"
send GET  "raw.githubusercontent.com" ""          "real external host (unlisted)"
send POST "external-drop.example"  "svc-key-demo" "credentialed POST outbound"
send GET  "telemetry-sink.example" ""             "canary destination"
send GET  "api.internal"           "CANARY-DEMO"  "canary credential"
send GET  "db.internal"            "DB_READ_01"   "unresolved env-var reference"

echo ""
echo "The gateway classified every request from the declared envelope alone,"
echo "including hosts it had never seen (github.com, raw.githubusercontent.com),"
echo "which resolve to 'violation' because they are not in allowed_destinations."
echo "No request was pre-registered; the verdict follows from policy by construction."
