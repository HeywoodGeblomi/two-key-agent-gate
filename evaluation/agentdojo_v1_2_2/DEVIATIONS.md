# Deviations from PREREG.md (sha256 d33d043be1b6f871475a13e26e2fe8b9058c93023cabb36a9ba4bfb66cae29f1)

## 1. Harness crash on the first scoring run (fixed, rerun)

- What happened: the first scoring run crashed after 1155 gate decisions, before any results were written. The gate returned REFUSE for invalid input on one request (reason: "context[6]: system_id value must be 1 to 256 chars"). A REFUSE for invalid input has no "args" field, and replay.py read r["args"] without a default.
- Cause of the invalid input: AgentDojo's slack suite has an injection vector inside a channel name ("External_" followed by the attack text). In attack runs, get_channels returns a 373-character channel name containing the injection. The harness passed channel names as slack_channel system_id spans, and the gate's input validation refused the whole request (fail closed).
- Fix: replay.py now reads r.get("args", []). No other change. Gate, policy and PREREG.md are unchanged.
- Harness sha256 before: 49ec47283e845ad7df6622ad1b194e471ad466dadbb9992c11b80c59e3cb2425 (matches PREREG.md). After: 473b8659ae601017b689c556c4e8ce1467aee1555bc064b5f12c65a95e7801fd.
- The partial log of the crashed run is kept in results_crashed_run1/ (key removed). No metrics were computed from it.
- Consequence to read with the results: in slack attack pairs whose user task calls get_channels, every gated attack call is REFUSED by input validation, not by the taint rules. Those pairs count as blocked under the preregistered definition, but the block comes from a length limit, not from provenance logic. A shorter injected channel name would have been accepted as a trusted slack_channel id. This also shows that treating slack channel names as system-generated was a wrong assumption: in this benchmark (and in real Slack) channel names are user-creatable text.

## 2. One exploratory run after scoring (not preregistered, not scored against bars)

- After the scored run I added a flag, --posthoc-no-channel-ids, that stops passing slack channel names as system_id spans. Default behavior is unchanged.
- The exact harness used for the scored run is kept as replay_as_scored.py (sha256 473b8659ae601017b689c556c4e8ce1467aee1555bc064b5f12c65a95e7801fd). replay.py with the flag added has sha256 255a3ae53ef30bc6b5061935596a652152b6955b3c759dd5196bccdab81006d3.
- Output: results_posthoc_no_channel_ids/. Purpose: to see how much of the slack result depends on the unsound channel-name assumption found in deviation 1.
