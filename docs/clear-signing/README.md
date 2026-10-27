# Clear-signing descriptors

These are pre-deployment ERC-7730 v2 templates for the v1.0.0 Solidity ABI:

- `calldata-safe-lockdown-1.json` describes direct calls to the
  `LockdownTimelock` singleton.
- `eip712-lockdown-1.json` describes the `Lockdown(address safe,bytes signer,
  bytes32 reasonHash)` panic authorization.

Both templates deliberately contain an empty `deployments` array. They pass the
published ERC-7730 v2 JSON schema but the official `erc7730 lint` command
rejects them until at least one deployment is present. This is fail-closed:
wallets must not apply a descriptor to an unauthenticated address.

After the release candidate is frozen and deployed:

1. add every supported chain ID and verified singleton address to both files;
2. obtain Sourcify full-match verification for every deployment;
3. run `uvx erc7730 lint docs/clear-signing/*.json`;
4. verify every rendered field, especially operation, refund fields, nested
   calldata, signer identity, and the password signature/cleartext field;
5. submit the descriptors and representative tests to the open ERC-7730
   registry.

Safe self-calls such as `disableModule`, `swapOwner`, `setGuard`,
`setModuleGuard`, and `setFallbackHandler` are intentionally absent: their
target is the Safe proxy, not the Lockdown singleton. They require Safe-aware
decoding in the operator application and must never be mislabeled as Lockdown
contract calls.
