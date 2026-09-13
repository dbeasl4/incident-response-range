# Deploying the Authorization Gateway

This directory packages the enforcement subset of the range -- the policy proxy,
the authorization envelope, the decoy, and alerting -- as a control a lab or
platform can put in front of its own infrastructure. It is the deployable half
of the project; the measurement half (agent runner, classifiers, scenario
generators) stays in the parent directory.

The gateway does one thing: every request that passes through it is classified
against a declared authorization envelope, and the verdict determines what
happens -- allow, contain, or page. Ground truth is derived from the envelope,
which is a document, so an outside party can audit the policy without access to
the network it governs.

---

## What this would and would not have stopped

State this plainly, because it bounds every claim below.

In the July 2026 incident the initial escape was a zero-day in JFrog Artifactory
-- the *one permitted* network egress. That traffic was authorized. No
authorization gateway catches a novel vulnerability in a permitted channel: the
gateway sees a permitted request to a permitted host and allows it, correctly.

What the gateway catches is everything *after* initial access: the credential
used outside its declared scope, the connection to an unrecognized host, the
exfiltration POST. Per Hugging Face's own timeline that phase ran roughly two
and a half days and thousands of actions. That window is what this closes.

Closing the *initial* gap -- observing an exploit against the vulnerable channel
itself -- requires a higher-fidelity range in which the vulnerable service is
part of the observed decoy. That is out of scope here and is described as future
work in the paper.

---

## Two placements

The same gateway deploys in two positions. They answer different questions.

### 1. Origin lab -- pre-flight

**Where:** between the evaluation harness and the agent's sandbox, before a real
evaluation runs.

**Why:** the incident happened because agents were pointed at real infrastructure
with monitoring off, on the assumption the sandbox held. Pre-flight runs the
agent through the range first -- synthetic infrastructure, a declared envelope --
and records its behaviour on the escalation ladder before it touches anything
real. An agent that reaches for out-of-scope credentials in the range has shown
that tendency before exposure.

**Deploy:** the full range (parent directory). This is a test harness, run before
the real eval, not an inline production component.

### 2. Receiving org -- runtime

**Where:** inline at the production egress boundary -- the chokepoint where the
package proxy sat in the real incident.

**Why:** the receiving organisation cannot trust that the originating lab's agents
are contained, because in the incident the originating lab itself did not know
they were not. Runtime enforcement at your own boundary does not depend on
anyone else's controls. The proxy loads an envelope describing legitimate
traffic; a violation is classified, diverted into the decoy, and paged.

**Deploy:** this directory -- proxy, envelope, decoy, alert. Not the whole range.

The C++ proxy exists for this placement: the policy decision adds ~22 ns per
request (measured, verdict-equivalent to the Python reference), so it can sit
inline on production egress without becoming a bottleneck.

---

## Runtime deployment -- steps

1. **Write your envelope.** Copy `envelope.example.yaml`, replace the example
   credentials and destinations with your own. Validate it:

   ```
   python3 ../envelope.py --validate deploy/envelope.yaml
   ```

   The validator reports errors and warnings -- notably, it warns when a
   credential is permitted at *every* destination, which is the shape of the
   incident's decisive failure (a connector credential bound to system:masters
   and shared across clusters was cluster-admin everywhere; enforcement cannot
   catch misuse of a credential that is authorised everywhere).

2. **Point your agents' egress at the proxy.** Set `HTTP_PROXY` (or your
   platform's egress route) to the gateway. Every outbound request now passes
   through classification.

3. **Choose an enforcement mode per tier.** Defaults:
   - T0 (benign / unresolved reference): log only
   - T2 (violation): automated containment -- divert to decoy
   - T3 (exfiltration / canary): page immediately, and divert

   Tiers are policy, set in the envelope's `tiers:` block. A higher-stakes eval
   may raise scope violations to T3.

4. **Set the alert topic.** `NTFY_TOPIC` for a push endpoint (or wire the T3
   branch to your own paging system). Alerting is fire-and-forget; a failure
   there never stalls the decision path.

5. **Run the decoy** if you want diversion rather than blocking. A T2/T3 request
   is served plausible generated content while telemetry keeps recording -- the
   attacker keeps working against nothing real while a human reviews at human
   speed.

---

## Pre-flight deployment -- steps

1. Declare the agent's envelope: what it is authorised to reach during the eval.
2. Run the agent through the range against a synthetic copy of the target.
3. Read the escalation ladder (`classify_v4.py`). If the agent crossed the
   authorization boundary in the range, investigate before running the real
   eval.

See the parent directory's harnesses (`multitrial_host.sh`, `swarm.py`,
`run_injection.sh`) for the pre-flight measurement tooling.

---

## Files

- `envelope.example.yaml` -- worked policy, modelled on the incident's credential
  structure. Start here.
- `policy_proxy.cpp` -- the C++ gateway (build: `g++ -O2 -std=c++17 -o
  policy_proxy policy_proxy.cpp`). Verdict-equivalent to the Python reference.
- `demo.sh` -- sends real external requests through the gateway and shows the
  verdicts, demonstrating it classifies traffic it did not itself generate.

---

## Verification without network access

The property that makes this auditable: the envelope is a file, the telemetry is
a signed-loggable record of verdicts, and the classifier's labels are derivable
from the envelope by anyone who reads it. A regulator or partner can check *what
the policy is* and *whether a given verdict follows from it* without access to
the deploying organisation's network -- which is the gap the incident's
after-the-fact, lab-controlled investigation could not close.
