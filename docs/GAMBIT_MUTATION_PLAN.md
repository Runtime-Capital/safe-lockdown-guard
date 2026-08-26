# Gambit Mutation Plan

> **Current (2026-07-04):** sampled mutation campaign refreshed on
> `src/Lockdown.sol` and `src/LockdownTimelock.sol` at solc 0.8.35; see the
> campaign record below and `docs/V1_ADVERSARIAL_COVERAGE_2026-07-04.md`.
> Older records are kept as superseded history.

This is an optional pre-audit mutation pass. The helper script defaults to
`src/Lockdown.sol`; set `GAMBIT_TARGET_FILE=src/LockdownTimelock.sol` to cover
the singleton/timelock layer as a separate campaign.

It is deliberately not part of `make audit-check`: mutation testing is slow and
depends on a local Gambit install. The goal is to catch tests that assert happy
paths but fail to kill small, security-relevant source changes.

## Command

```bash
make mutation-gambit
GAMBIT_TARGET_FILE=src/LockdownTimelock.sol make mutation-gambit
```

If Gambit is not installed, the target exits cleanly and prints this file path.

## Scope

Target scope for the next current campaign:

- `src/Lockdown.sol`
- `src/LockdownTimelock.sol`

Do not mutate:

- tests;
- deployment helpers;
- docs;
- generated artifacts.

## Targeted Surfaces

Auditors and maintainers should pay special attention to surviving mutants in:

- recovery-state whitelisting in `_isRecoveryCall`;
- `safeTxGas`, `baseGas`, `gasPrice`, `gasToken`, and `refundReceiver` checks;
- `lockdownUntil + resumeDelay` timing;
- module-path operation checks and returned `moduleTxHash`;
- `MultiSendCallOnly` recursive payload parsing in `_checkCall` (inner
  delegatecall-escape and `setFallbackHandler`-binding rejection at every
  depth);
- `removeRecoveryOwner` fail-closed cardinality (`EmptyAllowlist`) checks.

## Expected Outcome

Every mutant that weakens these invariants should be killed by the test suite.

A surviving mutant is acceptable only when it is semantically equivalent or
outside the documented threat model. Record any accepted survivor with:

- mutant id;
- diff;
- why it is equivalent or accepted;
- reviewer initials/date.

## Notes

Gambit (the Certora/ToB CLI) only GENERATES mutants; it has no `--test-command`,
and it cannot compile this contract under the exact production settings
(`Lockdown.sol` needs `--via-ir`, which the gambit CLI cannot pass).
`scripts/mutation-gambit.sh` therefore generates with `--skip_validate`
(gambit only needs the AST, which compiles without via-ir) and kills each mutant
with `forge test` (which DOES use via-ir):

```bash
GAMBIT_TARGET_FILE=src/Lockdown.sol GAMBIT_SAMPLE_EVERY=10 make mutation-gambit
GAMBIT_TARGET_FILE=src/LockdownTimelock.sol GAMBIT_SAMPLE_EVERY=10 make mutation-gambit

gambit mutate --filename "$GAMBIT_TARGET_FILE" --outdir mutation-work/gambit-<target> \
  --skip_validate --solc_evm_version prague \
  --solc_remappings @openzeppelin/contracts/=lib/openzeppelin-contracts/contracts/ \
    openzeppelin-contracts/=lib/openzeppelin-contracts/ \
    @safe-global/safe-smart-account/=lib/safe-smart-account/contracts/
# then, per sampled mutant: cp mutant over "$GAMBIT_TARGET_FILE" && forge test
```

`solc` / `solc-select` ship in the slither uv-tool venv
(`~/.local/share/uv/tools/slither-analyzer/bin`); the wrapper adds it to PATH.
Set `GAMBIT_SAMPLE_EVERY=1` for the full multi-hour campaign. The script treats
`0` generated mutants as a failed campaign so missing remappings cannot produce
a false "0 survivors" result.

## Campaign record: 2026-07-04 (current split model)

Setup: isolated workspace, Gambit CLI, solc
0.8.35+commit.47b9dedd, Foundry 1.5.1-stable. Both targets used
`GAMBIT_SAMPLE_EVERY=10`; each sampled mutant was copied over the target file
and killed with the full `forge test` suite.

Results:

| Target | Generated mutants | Sampled | Killed | Survived |
| --- | ---: | ---: | ---: | ---: |
| `src/Lockdown.sol` | `598` | `60` | `60` | `0` |
| `src/LockdownTimelock.sol` | `341` | `35` | `35` | `0` |

Detailed evidence and remote artifact paths:
`docs/V1_ADVERSARIAL_COVERAGE_2026-07-04.md`.

## Campaign record: 2026-06-28 (SUPERSEDED - pre-split bytes-identity model)

Setup: Gambit (Certora CLI), solc 0.8.35, pre-split bytes-identity `src/`.
`gambit mutate --skip_validate` generated **1583 mutants** for `src/Lockdown.sol`
(1125 `BinaryOpMutation`, 140 `RequireMutation`, 111 `DeleteExpressionMutation`,
68 `AssignmentMutation`, 50 `SwapArgumentsOperatorMutation`, 50
`IfStatementMutation`, 39 `UnaryOperatorMutation`). Kill loop: deterministic
1-in-40 sample (40 mutants), each copied over `src/Lockdown.sol` and killed with
`forge test` (a mutant survives only if the full suite still passes).

Results: **40 sampled, 39 killed, 1 survivor -> 0 survivors after fixing the
gap.**

- **Survivor (mutant 241, `IfStatementMutation`)**: in `initialize`,
  `if (nSigners == 0) emit SafeDormant(...)` mutated to `if (true) ...`. It
  survived because no test asserted that `SafeDormant` is NOT emitted when the
  Safe is armed with signers. **Fixed** by
  `test_initializeEmitsSafeDormantOnlyWhenZeroSigners`, which records logs and
  asserts the H.15 dormancy event fires IFF `nSigners == 0` (verified to kill
  mutant 241). The sampled kill rate is now 40/40.

Re-run with `make mutation-gambit` (or `GAMBIT_SAMPLE_EVERY=1` for the full
campaign).

## Campaign record: 2026-06-11 (SUPERSEDED - old id model, solc 0.8.24)

> Superseded by the 2026-06-28 run above; this ran on the removed
> `(verifier, key) + signerId` model. Kept for history. The accepted survivor
> below (`idToLookupKey` / `getSignerById`) no longer exists.

Setup: Gambit v1.0.6 (prebuilt binary), solc 0.8.24, mutants generated with
`--skip_validate` (Gambit cannot drive via-ir validation; non-compiling
mutants are classified by the kill loop instead) and restricted to the
targeted surfaces:

```
gambit mutate --filename src/Lockdown.sol --contract Lockdown \
  --skip_validate --solc <svm solc-0.8.24> -n 100 --seed 0 \
  --functions _isRecoveryCall _validateMultiSendCallOnly \
    checkTransaction checkModuleTransaction checkAfterExecution \
    checkAfterModuleExecution triggerLockdown \
    addRecoveryOwner removeRecoveryOwner \
    _validateRecoveryOwner _verifyOwnerTimelock
```

842 mutants generated over those functions, deterministically downsampled
to 100 (seed 0). Kill loop: per mutant, `forge build` (invalid if it does
not compile) then `forge test --fail-fast` in an isolated copy of the repo.

Results: **71 invalid, 28 killed, 1 survivor. Kill rate on viable mutants:
28/29 (97%).** The high invalid rate is expected: Gambit's untyped binary
operator mutations (e.g. `address == address` to `address * address`) do
not compile under solc 0.8.24.

Accepted survivor:

- **Mutant 12**: `delete cfg.idToLookupKey[signerId]` in the
  `triggerLockdown` burn path replaced by a no-op.
- Why accepted: observationally equivalent through the public ABI. Signer
  ids are never reused (`nextSignerId` is monotone, INV-SIGN-2) and every
  public view (`getSignerById`, `getSignersByIdRange`) resolves through the
  forward map `signers[lk]`, which IS deleted; a stale reverse row at a
  burnt id can never collide with a future signer nor be observed by a
  caller. The delete is storage hygiene plus a gas refund, and the
  INV-SIGN-6 forward/reverse consistency that auditors verify at the
  storage level. A test pinning it would need raw storage-slot reads.
- Reviewer: pre-audit pass, 2026-06-11.

Notable kill: mutant 4 disabled the H.19 `_validateRecoveryOwner` gate in
the recovery-owner add path (`addRecoveryOwner` / `_addRecoveryOwner`) and is
killed by the H.19 registration-validation tests.
