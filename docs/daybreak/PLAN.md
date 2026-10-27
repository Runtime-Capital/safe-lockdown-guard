# Daybreak adversarial audit plan

## Outcome

Find a transaction or sequence accepted by Runtime Lockdown V1 whose execution on the pinned genuine Safe v1.5.0 produces an effect the guard should forbid, or return an evidence-backed kill list showing why the highest-value constructions fail.

## Fixed target

- Audit candidate: `v1.0.0-audit-candidate.3` at `6b85a4c2bae4c98bdf8a143bd4fdfa44d70498a7`.
- The current checkout may be used only after confirming that `src`, `lib`, `test`, `foundry.toml`, and `remappings.txt` are unchanged from that tag.
- Production code, dependencies, specifications, and existing tests remain read-only.

## Resource allocation

- Lead orchestrator: synthesis, independent challenge, reproduction, and final triage.
- Parser/executor worker: highest ROI, approximately 55% of delegated effort.
- Stateful hooks/tickets worker: approximately 30%.
- Supported signer/verifier liveness worker: approximately 15%.
- No worker may spawn additional agents.

## Execution phases

1. Blind construction: each worker reads production code and the pinned execution dependency relevant to its lane, then records six concrete attack constructions without reading `test/poc` or prior adversarial reports.
2. Focused proof: each worker selects at most two highest-value constructions for deterministic Foundry proof or a decisive executable refutation.
3. Late deduplication: only after the constructions are frozen, search existing PoCs and assurance documents for semantic duplicates.
4. Lead review: independently inspect every claimed finding, rerun its exact command, and reject anything mock-only, out of threat model, already known, or lacking a material effect.
5. Final disposition: `NEW_AND_PROVED`, `KNOWN_OR_ACCEPTED`, `REFUTED_BY_EXECUTION`, `OUT_OF_SCOPE`, or `ENVIRONMENT_BLOCKED`.

## Completion bar

- A finding requires an executed PoC on the genuine pinned integration, an explicit attacker capability, a material effect, exact reproduction instructions, and a novelty check.
- A zero-finding result requires six concrete constructions per lane and an evidence-backed kill list.
- No fixes are implemented during this pass.
