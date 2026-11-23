# Write-up: known gaps, proposed fixes and open decisions

Author: Heywood Geblomi. This is where the project stands after v2, what is
still broken, and what would fix it. Nothing marked "proposed" below is built
or tested yet.

## What works

- Provenance first. Privileged calls run only when their targets trace back
  to the user's own words. On the AgentDojo v1.2.2 ground-truth replay, 608 of
  609 scored attack pairs were not auto-executed.
- No evidence means ask. Empty controlling arguments, unknown tools and
  undeclared arguments never pass silently.
- A yes is a one-use permit bound to one exact call.
- Fail closed everywhere: malformed input, a broken log chain or a failed log
  write all refuse.

## Known gaps

### 1. Sensitive data to a recipient the user named (open leak)

An injection can ask the agent to email passport and credit card numbers to
the same address the user asked to email. The recipient is legitimately
trusted, and the content check only looks for URLs, emails and IBANs. This is
the one attack pair the replay let through. Value matching alone cannot close
it.

**Proposed fix: protected data classes.** Mark values such as passport,
card, bank account and government ID numbers as protected, by pattern and by
the tool field they came from. Sending a protected value anywhere, even to a
trusted recipient, needs a confirm whose prompt names the class ("This sends
your passport number to jane@example.com. Allow?"). Not built.

### 2. Too many prompts on harmless tasks

28.9% of benign tasks prompt the user at least once, against a 1% target.
Most come from tasks that legitimately take a target from tool data: pay the
IBAN on a bill, reply to whoever sent a message, open a URL from a page. At
that rate users learn to click yes, which defeats the gate.

**Proposed fix: a separate small judge, not self-checking.** For confirm cases
only, ask a separate small model one narrow question: "Does the user's own
request support this action?" It sees the user's words and the proposed call,
not the tool output that may contain the injection, and it is not the model
that proposed the call. Clear yes: allow. Anything else: ask the user as now.
It must pass a fresh preregistered test, scored once, before any claim is
made: benign prompt rate well down, and no drop in the 608/609 block count.
Not built.

Other options worth testing: user-signed targets ("pay this bill" approves the
payee on that bill and nothing else) and a proper data-flow graph instead of
value matching.

### 3. No live-model or adaptive-attacker evaluation

All numbers come from replaying the benchmark's ground-truth calls. No model
ran, so model errors and behavior after a confirm are not measured. Attack
calls copy the attacker's values verbatim, which is the easiest case. A
white-box attacker would aim at trusted recipients, attacker-creatable names
and content arguments. This is the most important missing evaluation.

### 4. Attacker-creatable names trusted as IDs

The scored policy treated Slack channel names as system-generated IDs. They
are not: anyone can create a channel, and AgentDojo hides an injection in one.
The block count held only because that name exceeded a length limit. With
channel names untrusted, every Slack attack is still blocked but auto utility
falls from 71.1% to 63.9%. Message senders carry the same risk wherever an
attacker can post. Rule of thumb: only treat a field as a system ID if no
outside party can choose its value.

### 5. Smaller limits

- Short values can match by coincidence.
- Choosing among trusted values is not caught.
- Exfiltration through bodies and subjects to a trusted recipient is only
  partly covered by the content scan.
- One benchmark, one attack template.

## Open decisions

1. Build v3 (protected data classes plus a separate judge) behind one fresh
   preregistered test, or keep v2 as the reference and let contributors
   propose v3 designs.
2. Which live-model evaluation to run first, and with which adaptive attack.
3. Whether to ship a policy pack for common agent frameworks, or keep the
   policy format minimal and framework-neutral.

## Contributions welcome

Most useful: an adaptive attack that gets past the gate, a live-model run,
policies for real tool sets, and implementations of the proposed fixes with
their own preregistered tests. Please report misses as plainly as hits.
