# Architecture Diagrams

This page contains source diagrams for the V1 Safe Lockdown architecture.
The Mermaid version is the audit-facing source of truth. The Excalidraw file is
the presentation-friendly map:

- `docs/safe-lockdown-architecture.excalidraw`

Rendered PNG exports live in `docs/diagrams/`:

- `diagrams/safe-lockdown-solidity-surface-mermaid.png` (Mermaid flowchart below)
- `diagrams/safe-lockdown-state-machine-mermaid.png` (Mermaid state machine below)
- `diagrams/safe-lockdown-architecture-excalidraw.png` (Excalidraw export)

To re-export the Mermaid blocks after editing this file (Chromium sandbox off
for headless environments):

```sh
echo '{"args":["--no-sandbox"]}' > /tmp/puppeteer-no-sandbox.json
awk '/^```mermaid/{n++; f="/tmp/diag" n ".mmd"; next} /^```$/{f=""} f{print > f}' docs/ARCHITECTURE_DIAGRAMS.md
npx --yes @mermaid-js/mermaid-cli -p /tmp/puppeteer-no-sandbox.json \
  -i /tmp/diag1.mmd -o docs/diagrams/safe-lockdown-solidity-surface-mermaid.png -w 2400 -s 3 -b white
npx --yes @mermaid-js/mermaid-cli -p /tmp/puppeteer-no-sandbox.json \
  -i /tmp/diag2.mmd -o docs/diagrams/safe-lockdown-state-machine-mermaid.png -w 1200 -b white
```

## Global Solidity Surface

```mermaid
flowchart LR
    %% Actors
    O1["Owner 1"]
    O2["Owner 2"]
    O3["Owner 3"]
    O4["Owner 4"]
    O5["Owner 5"]
    M["Enabled Safe module"]
    B["Optional bypass signer / HSM"]
    P["Off-site panic holder"]

    %% Safe
    subgraph SAFE["Safe v1.5.0 example: 3-of-5"]
        Q["Owner quorum signs native Safe tx"]
        OP["Owner path: execTransaction"]
        MP["Module path: execTransactionFromModule"]
        GS["TransactionGuard slot: setGuard"]
        MGS["ModuleGuard slot: setModuleGuard"]
        FHS["FallbackHandler slot: setFallbackHandler"]
        NONCE["Safe nonce and Safe tx hash"]
    end

    O1 --> Q
    O2 --> Q
    O3 --> Q
    O4 -.-> Q
    O5 -.-> Q
    Q --> OP
    M --> MP

    %% Singleton
    subgraph LOCKDOWN["Lockdown singleton deployed once per chain"]
        CFG["_configs[safe]: per-Safe config"]
        PRE1["checkTransaction owner pre-hook"]
        POST1["checkAfterExecution owner post-hook"]
        PRE2["checkModuleTransaction module pre-hook"]
        POST2["checkAfterModuleExecution module post-hook"]

        STATE{Safe state via getState}
        DORMANT["Uninitialised: hooks pass through, anti-brick"]
        NORMAL["Normal"]
        LOCKED["LockedDown until lockdownUntil"]
        RECOVERY["Recovering: after lockdownUntil, before resumeDelay elapses; auto-resumes to Normal at lockdownUntil + resumeDelay"]

        TL{timelockDelay > 0?}
        ANN["scheduleTransaction / scheduleModuleTransaction"]
        WAIT["wait delay; ticket matures at executableAt, expires after 90d TTL"]
        BYPASS["bypassTimelock safeTxHash owner path only"]

        WL["Recovery whitelist only"]
        BURN["Burn used signer identity and permanently ban it"]
        DENY["module call to the singleton denied in every state, incl. pre-init"]
    end

    GS --> PRE1
    GS --> POST1
    MGS --> PRE2
    MGS --> POST2
    FHS -.->|"binds LockdownFallbackHandler; freezes ERC-1271 during incident"| CFG
    OP --> PRE1
    MP --> PRE2
    POST1 --> CFG
    POST2 --> CFG

    CFG --> STATE
    STATE --> DORMANT
    STATE --> NORMAL
    STATE --> LOCKED
    STATE --> RECOVERY

    NORMAL --> TL
    TL -->|no: direct execution| OP
    TL -->|yes: schedule first| ANN
    ANN --> WAIT
    WAIT --> OP
    WAIT --> MP
    B --> BYPASS
    BYPASS --> OP

    LOCKED -.->|blocks| PRE1
    LOCKED -.->|blocks| PRE2
    RECOVERY -.->|blocks| PRE2
    PRE2 --> DENY
    RECOVERY --> WL

    WL --> W1["empty Safe self-call nonce burn"]
    WL --> W2["exact swapOwner to allowed recovery owner"]
    WL --> W3["exact disableModule"]
    WL --> W4["removeLockdownSigner"]

    %% Panic identities
    subgraph PANIC["Lockdown signers: 1-of-N panic identities"]
        SID["Registered bytes signer identities per Safe (EnumerableSet.BytesSet)"]
        EIP712["EIP-712 Lockdown(safe, signer, reasonHash)"]
        LSECDSA["20-byte EOA / ERC-1271 lockdown signer"]
        LSPWD["Password commitment signer (verifier||key)"]
        LSWA["WebAuthn passkey signer (verifier||key)"]
    end

    P --> EIP712
    EIP712 --> SID
    LSECDSA --> SID
    LSPWD --> SID
    LSWA --> SID
    SID --> TRIGGER["triggerLockdown(safe, reasonHash, signer, signature)"]
    TRIGGER --> BURN
    TRIGGER --> LOCKED

    %% Signature dispatch
    subgraph VERIFIERS["Signature dispatch: OZ SignatureChecker"]
        SC["SignatureChecker.isValidSignatureNow(signer, hash, signature)"]
        DIRECT["20-byte signer: ECDSA EOA or ERC-1271"]
        V2["PasswordVerifier (verifier||key)"]
        V1["WebAuthnVerifier (verifier||key)"]
        PREFLIGHT["off-chain key-shape preflight"]
        TESTSIG["off-chain drill (DrillSigner script / UI local check): verify without burning or broadcasting"]
        VMAGIC["ERC-7913 verify returns magic 0x024ad318"]
    end

    PREFLIGHT -.-> V2
    PREFLIGHT -.-> V1
    TESTSIG -.-> SC
    TRIGGER --> SC
    SC --> DIRECT
    SC --> VMAGIC
    VMAGIC --> V2
    VMAGIC --> V1

    %% Recovery owners
    subgraph RECOV["Recovery owner allowlist"]
        R1["backup Safe signer A"]
        R2["backup Safe signer B"]
        R3["backup Safe signer C"]
        SWAP["Safe swapOwner exact calldata"]
    end

    RECOVERY --> RECOV
    R1 --> SWAP
    R2 --> SWAP
    R3 --> SWAP
    SWAP --> W2

    %% Audited dependencies
    subgraph OZ["Pinned OpenZeppelin Contracts"]
        OZ1["ECDSA.tryRecover"]
        OZ2["WebAuthn.verify / tryDecodeAuth"]
        OZ3["P256.verify / isValidPublicKey"]
    end

    DIRECT --> OZ1
    V1 --> OZ2
    V1 --> OZ3

    %% Native Safe UX
    OP --> TARGET["Target protocol / DeFi / token"]
    MP --> TARGET
    NONCE --> OP

    classDef safe fill:#e0f2fe,stroke:#0369a1,color:#0f172a;
    classDef guard fill:#fef3c7,stroke:#b45309,color:#0f172a;
    classDef danger fill:#fee2e2,stroke:#b91c1c,color:#0f172a;
    classDef ok fill:#dcfce7,stroke:#15803d,color:#0f172a;
    classDef lib fill:#ede9fe,stroke:#6d28d9,color:#0f172a;
    classDef actor fill:#f8fafc,stroke:#64748b,color:#0f172a;

    class O1,O2,O3,O4,O5,M,B,P actor;
    class Q,OP,MP,GS,MGS,FHS,NONCE safe;
    class CFG,PRE1,POST1,PRE2,POST2,STATE,TL,ANN,WAIT,BYPASS,WL guard;
    class LOCKED,BURN,DENY danger;
    class NORMAL,RECOVERY,RESUMABLE,W1,W2,W3,W4,W5,TRIGGER,RECOV,R1,R2,R3,SWAP ok;
    class OZ1,OZ2,OZ3,DIRECT,SC,V2,V1,KV,SMOKE,VMAGIC lib;
```

## State Machine

```mermaid
stateDiagram-v2
    [*] --> Uninitialised
    Uninitialised --> Normal: initialize
    Normal --> LockedDown: triggerLockdown by registered signer
    LockedDown --> LockedDown: triggerLockdown re-locks (extends the window)
    Recovering --> LockedDown: triggerLockdown re-locks
    LockedDown --> Recovering: block.timestamp >= lockdownUntil
    Recovering --> Normal: block.timestamp >= lockdownUntil + resumeDelay (auto-resume, time-based)

    note right of Uninitialised
        no per-Safe config yet (lockdownDuration == 0)
        guard hooks pass through (anti-brick)
        triggerLockdown reverts InvalidState (only in this state; it is onlyInitialized)
    end note

    note right of Normal
        owner and module txs pass through
        timelockDelay > 0: matured ticket required on both paths
        owner-path ticket can be bypassed by allowlisted bypasser
        all admin setters available
    end note

    note right of LockedDown
        owner path blocked
        module path blocked
        triggerLockdown by a registered signer re-locks (extends the window; onlyInitialized, PR #59)
    end note

    note right of Recovering
        module path blocked
        owner path limited to the recovery whitelist
        removeLockdownSigner, swapOwner, disableModule, nonce burn allowed
        no resume call: auto-resumes to Normal at lockdownUntil + resumeDelay
        no timelock applies in this branch
    end note
```
