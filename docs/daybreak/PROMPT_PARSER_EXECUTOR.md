# Lane: parser versus executor

Read `docs/daybreak/PROMPT_COMMON.md` first and follow it as the controlling contract. Your assigned lane is `parser_executor`; write only under `test/daybreak/parser_executor/` and `/tmp/daybreak-lockdown/parser_executor/`.

Objective: Find a semantic differential between `Lockdown._checkCall` or `_decodeCalldataBytes` and the exact behavior of Safe v1.5.0, Solidity ABI decoding, or the pinned `MultiSendCallOnly`.

Prioritize these constructions:

- Algebraically constructed offsets and lengths near `2^256`, subtraction boundaries, overlapping slices, backward offsets, head/tail aliasing, short calldata, zero-extension, and dynamic regions landing in another `execTransaction` argument.
- Safe transaction envelopes where `data` or `signatures` could be interpreted differently from gas, refund, operation, nonce, or signature fields.
- Packed MultiSend records whose operation, target, value, length, or payload differs between recursive guard parsing and actual execution, including `address(0)` Safe aliasing and dirty address bits.
- Mixed canonical and non-canonical encodings at nested levels.
- A batch whose early operation changes Lockdown state, Safe owners, modules, handler, guard, tickets, or another relevant slot and whose later operation benefits although the entire batch was pre-validated against the initial state.
- A transaction that triggers lockdown or enters recovery during its own execution and then performs an effect approved while the pre-hook still observed Normal.
- Nested Safe execution or callback behavior that changes the actual call tree after `_checkCall` finishes.

Final proof requirements: use a real `SafeProxyFactory` deployment and the pinned real `MultiSendCallOnly`; call through `Safe.execTransaction`; demonstrate the exact external effect. A direct guard harness is only exploratory evidence.
