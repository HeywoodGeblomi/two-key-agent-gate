# Evaluation

One preregistered evaluation so far: a gate-only replay of the AgentDojo
v1.2.2 benchmark (AgentDojo 0.1.35; suites workspace, travel, banking and
slack; 97 user tasks, 35 injection tasks, 949 attack pairs). No language model
ran. The harness feeds AgentDojo's ground-truth tool calls through the gate,
with the user prompt labeled trusted and every tool output labeled untrusted.

| File | What it is |
|---|---|
| `agentdojo_v1_2_2/PREREG.md` | The preregistration, written before the single scoring run. |
| `agentdojo_v1_2_2/PREREG.sha256` | The sha256 of PREREG.md recorded before scoring. |
| `agentdojo_v1_2_2/RESULTS.md` | Results against the preregistered bars, per suite, with caveats. |
| `agentdojo_v1_2_2/DEVIATIONS.md` | One harness crash and rerun, and one exploratory run after scoring. |
| `agentdojo_v1_2_2/replay_as_scored.py` | The harness as it was used for the scored run. |
| `agentdojo_v1_2_2/replay.py` | Same harness plus the `--posthoc-no-channel-ids` flag, with paths set for this repo. |
| `agentdojo_v1_2_2/results/results.json` | Scored metrics. |
| `agentdojo_v1_2_2/results_posthoc_no_channel_ids/results.json` | Exploratory metrics (not preregistered). |
| `../policies/agentdojo_v1_2_2_policy2.json` | The policy used for the run. |

The per-call row files and the 1444-entry decision log (about 1.6 MB per run)
are not included to keep the repo small. Running `replay.py` regenerates them.
The partial log of the crashed first run mentioned in DEVIATIONS.md is not
included either.

## Edits made for publication (read this before checking hashes)

The files were written in a private working tree and lightly edited before
publishing. The edits do not touch any rule, number or result:

- The author line in PREREG.md, RESULTS.md, both harness docstrings and the
  policy `notes` field now reads Heywood Geblomi.
- In PREREG.md, a reference to an internal brief ID was replaced with "the
  original project brief". The bars themselves are unchanged.
- The crate was renamed from `rust_gate` to `two-key-agent-gate` (library
  `two_key_gate`, binary `two-key-gate`), and two code comments that pointed
  at unpublished earlier prototypes were reworded. No logic changed.
- `replay.py` now points at `../../target/release/two-key-gate` and
  `../../policies/`. `replay_as_scored.py` keeps the original paths.

Because of these edits, the published files do **not** hash to the values
recorded in PREREG.md, PREREG.sha256 and DEVIATIONS.md. Those values are kept
as the historical record. For this repo's copies:

| File | Recorded before scoring | Published copy |
|---|---|---|
| PREREG.md | d33d043be1b6f871475a13e26e2fe8b9058c93023cabb36a9ba4bfb66cae29f1 | 205915a96bc6205ccdfa036c5ddb76297f9c95fd4231d3ace4b2e6a0d5988ef8 |
| policy file | d88e67d91fb73dd097901828892aec4872ae94fd33ccf66b7b1829efb90b5ce5 | b7b60f1c78d37dab02f29648e196927305dd0175b0a377271b308e5c12b6202b |

If you rerun the replay you will get a different `policy_sha256` in
results.json for the same reason. The decisions should be identical, since the
gate ignores the `notes` field when deciding.

## Reproduce

    cargo build --release
    python -m venv .venv && . .venv/bin/activate
    pip install agentdojo==0.1.35 pyyaml
    cd evaluation/agentdojo_v1_2_2
    python replay.py --dry-run                         # plumbing check
    python replay.py --out /tmp/rerun                  # full replay
    python replay.py --out /tmp/rerun_nochan --posthoc-no-channel-ids

The harness refuses to overwrite an existing results.json.
