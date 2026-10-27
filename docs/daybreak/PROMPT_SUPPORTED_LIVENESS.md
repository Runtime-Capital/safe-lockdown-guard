# Lane: supported signer and verifier liveness

Read `docs/daybreak/PROMPT_COMMON.md` first and follow it as the controlling contract. Your assigned lane is `supported_liveness`; write only under `test/daybreak/supported_liveness/` and `/tmp/daybreak-lockdown/supported_liveness/`.

Objective: Find a fully supported identity and complete Safe configuration that passes its intended verifier or drill path but cannot trigger lockdown in a realistic incident, or that authorizes an unintended trigger.

Use only native 20-byte EOA/ERC-1271 identities, `PasswordVerifier`, `WebAuthnVerifier`, and `WebAuthnVerifierNoUV` with the pinned OpenZeppelin implementation.

Prioritize these constructions:

- Differences between verifier-level positive vectors and the actual Lockdown EIP-712 digest for `(safe, reasonHash)`.
- ERC-7913 identity splitting, native ERC-1271 versus ERC-7913 dispatch, and exact key encoding.
- WebAuthn flat tuple versus struct encoding, dynamic offsets, `challengeIndex`, `typeIndex`, JSON ordering or extra fields, base64url challenge encoding, authenticator flags, UP/UV policy, DER versus flat `r/s`, high-s behavior, and public-key coordinate encoding.
- Behavioral differences between the P-256 precompile path and OpenZeppelin’s Solidity fallback. If one cannot be faithfully exercised locally, give a precise blocker rather than simulating a finding.
- A signature accepted by a supported preflight or direct verifier call but rejected only in the real Safe-trigger path.
- ERC-1271 behavior during LockedDown and Recovering on a completely installed Safe.

Do not spend time on arbitrary verifier upgrades, codeless verifiers, gas bombs, or PasswordVerifier’s already documented plaintext/hash-ignoring trade-off unless a stronger effect is demonstrated.

Final proof requirements: use the shipped verifier bytecode and a genuine Safe v1.5.0 integration. A verifier unit test alone cannot establish a Lockdown liveness finding.
