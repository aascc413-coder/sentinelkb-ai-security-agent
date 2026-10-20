# Frozen PowerShell family rubric

`powershell-v1.json` defines operational obligations for G0–G4 and B1–B3.
Each gate has five columns: required observations, mechanical checks, model
explanation, conflict handling, and unverifiable information. This is a shared
specification, **not an implemented sufficiency evaluator**. M7 must implement
runtime checks; M5 must independently score the trace using the same frozen
version. The model cannot grant itself a passing gate.

`state.rubric.load_rubric(path)` validates closed structure and the frozen
canonical SHA-256. It returns immutable descriptions, the canonical digest, and
the original file digest. Whitespace/object-order changes leave the semantic
digest unchanged; callers can additionally require exact file bytes with
`expected_sha256`. Semantic changes require a newly reviewed rubric version.

The Suspicious patterns require real grounded observations. A known execution
mismatch against positive approval is different from a missing approval archive.
A new external connection requires source evidence of newness; unavailable
history cannot establish it. Hard budget stops without sufficient verified
evidence take precedence and return Abstain with grounded risk flags.

## Frozen paired-input normalization

`state.normalization` defines `visible-metadata-v1`; its whitelist digest is
included in every report. Only these exact paths are eligible:

| Surface | Paths | Treatment |
|---|---|---|
| public | `/alert/alert_id`, `/alert/raw_reference/record_id` | Opaque ID bijection |
| environment | `/environment_id` | Opaque ID bijection |
| tool_result | `/call_id` | Opaque ID bijection |
| tool_result | `/actual_duration_ms` | Normalize measured wall duration |
| message | `/call_id`, `/run_id` | Opaque ID bijection |
| message | `/returned_at`, `/usage/wall_time_ms` | Normalize actual return time/measured wall duration |

Repeated identities retain their same/different relationship. An identity used
in a business field, including a cross-document reference, remains exact.
Object key order and array order are checked. No recursive matching by field
name is allowed. Host, user, event/publication/as-of time, process instances,
payload, content hash, record IDs, source quality, coverage, fixture/snapshot
version, simulated cost and simulated latency are never removed.

`compare_static(public1, env1, public2, env2)` reports full normalized static
equivalence, differences and every normalized path with its reason. Passing
this M2 check does not prove equivalence of actual tool responses (M3) or actual
model requests (M5). Shared physical environment identity is additionally
checked by dataset assembly; normalization does not replace that requirement.
