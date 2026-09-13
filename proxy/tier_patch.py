# Response-tier patch for proxy.py
# =================================
# Add this AFTER get_truth / infer_phase, then wire `tier` into log_event.
#
# Motivation. The July 2026 failure was not that nothing was detected -- it was
# that detection never escalated to action. Elastic Security Labs found signals
# correlated but never paged a responder; Hugging Face's own remediation list
# resolves to make high-severity signals page "in minutes, any day of the week,"
# which tells you what did not happen.
#
# A detector is only useful if its output maps to a decision. This patch makes
# that mapping explicit: every event carries not just what happened, but what
# a security team should do about it.
#
# The tiers are ordered by confidence, not by severity. T3 (automated
# containment, no human in the loop) is reserved for signals that cannot fire
# on legitimate traffic -- because the cost of a false positive at T3 is
# blocking real work, and the cost of a false negative at T0 is another
# four-day intrusion.

RESPONSE_TIERS = {
    # label                 tier  action
    "benign":              ("T0", "log only"),
    "unresolved_ref":      ("T0", "log only -- client error, not policy"),
    "violation":           ("T2", "automated containment + digest"),
    "irreversible":        ("T3", "page responder immediately"),
    "canary_credential":   ("T3", "page responder immediately -- canary"),
    "canary_destination":  ("T3", "page responder immediately -- canary"),
}

TIER_RATIONALE = {
    "T0": "No action. Retained for forensic reconstruction only.",
    "T1": "Daily digest. Reviewed in business hours.",
    "T2": "Automated containment. Session isolated; no human required. "
          "Safe to automate because the envelope check cannot fire on "
          "in-scope credential use.",
    "T3": "Immediate page. Reserved for signals with no innocent "
          "explanation: exfiltration, or a canary with no legitimate use "
          "anywhere in the environment.",
}


def response_tier(truth):
    return RESPONSE_TIERS.get(truth, ("T0", "log only"))


# ── Wire into log_event ──────────────────────────────────────────────────────
# Replace the existing log_event with this version.

def log_event(seq, phase, method, host, cred, note, truth):
    tier, action = response_tier(truth)
    event = {
        "seq":         seq,
        "timestamp":   time.time(),
        "phase":       phase,
        "action":      method,
        "credential":  cred,
        "destination": host,
        "note":        note,
        "truth":       truth,
        "tier":        tier,
        "response":    action,
    }
    with _file_lock:
        with open(TELEMETRY_PATH, "a") as f:
            f.write(json.dumps(event) + "\n")

    colour = {
        "T0": "\033[32m",   # green
        "T1": "\033[36m",   # cyan
        "T2": "\033[33m",   # yellow
        "T3": "\033[31m",   # red
    }.get(tier, "")
    reset = "\033[0m"
    print(f"{colour}[{tier} {truth:<20}]{reset} "
          f"seq={seq:3} {method:4} {host} cred={cred or '-'}")
