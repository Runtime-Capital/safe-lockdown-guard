# WebAuthn Browser Fixtures

This directory is for public WebAuthn assertion fixtures captured from real
browser / OS / authenticator combinations.

The goal is to connect the Solidity verifier contract to real platform output:
Chrome desktop, Chrome Android, Safari iOS, Safari macOS, and hardware FIDO2
keys may differ in `clientDataJSON` key ordering, extra fields, flags, DER
signature shape, and UV behaviour. The Solidity verifier delegates parsing to
OpenZeppelin `WebAuthn`, but the frontend still has to assemble the exact flat
ABI payload that OZ expects.

## Capture

Serve the repo over a secure origin, then open:

```sh
python3 -m http.server 8765
# desktop localhost:
# http://localhost:8765/deploy/webauthn-fixture-recorder.html
```

Do not use `127.0.0.1` for WebAuthn capture. Browsers may treat it as a secure
local context, but it is not a valid relying-party domain for passkeys.

For mobile devices, use HTTPS or a trusted tunnel. Cloudflare quick tunnels are
fine for this fixture capture flow:

```sh
cloudflared tunnel --url http://localhost:8765
```

Open the generated `https://<name>.trycloudflare.com/deploy/webauthn-fixture-recorder.html`
URL on the phone. Keep the same origin for registration and assertion; if the
tunnel URL changes, register a fresh passkey fixture.

On the page:

1. Choose a label such as `chrome-android-15-platform-required`.
2. Choose `preferred`, `required`, or `discouraged` user verification.
3. Choose the authenticator attachment:
   - `platform passkey` for iCloud Keychain, Google Password Manager, Touch ID,
     Android platform passkeys.
   - `cross-platform security key` for YubiKey / FIDO2 USB/NFC keys.
   - `no preference` when testing Chrome's phone / QR hybrid flow.
4. Keep the default digest unless testing a specific digest shape.
5. Click `Register passkey`.
6. Click `Capture assertion` with the same authenticator.
7. Save the JSON as `test/fixtures/webauthn/<label>.json`.

The page keeps only the most recent registration in memory. If you register a
Google Password Manager passkey and then touch a YubiKey during assertion,
Chrome will correctly report that the security key is not registered for this
site. Register and assert one authenticator at a time.

Fixtures contain public test material only: public key, challenge, browser
clientDataJSON, authenticatorData, and one assertion. Do not include private
deployment data or customer identifiers in labels.

## Generate Foundry Tests

```sh
node scripts/webauthn-fixture-to-sol.js
forge test --match-contract WebAuthnCapturedFixtures
```

The generated file is:

```text
test/verifiers/WebAuthnCapturedFixtures.generated.t.sol
```

Commit the JSON fixtures and generated Solidity test when adding a new
browser/device fixture set.

## Minimum Matrix Before Production Approval

| Platform | Browser | Authenticator | UV request |
|---|---|---|---|
| macOS | Chrome stable | platform passkey | preferred |
| macOS | Safari stable | platform passkey | preferred |
| iOS | Safari stable | iCloud Keychain passkey | preferred |
| Android | Chrome stable | Google Password Manager passkey | preferred |
| Desktop | Chrome stable | external FIDO2 key / YubiKey | preferred |
| Any platform | supported browser | platform passkey | required |
| Any platform | supported browser | platform passkey | discouraged |

The `required` row should pass both `WebAuthnVerifier(true)` and
`WebAuthnVerifier(false)` if the authenticator sets the UV flag. The
`discouraged` row should pass only `WebAuthnVerifier(false)` when UV is absent.

## What The Tests Prove

- `clientDataJSON.challenge` is the base64url form of the 32-byte Lockdown
  digest.
- `challengeIndex` and `typeIndex` are correct for that browser's JSON string.
- DER P-256 signatures are decoded into `(r, s)` and normalised to low-s.
- The flat ABI signature is exactly:

```solidity
abi.encode(r, s, challengeIndex, typeIndex, authenticatorData, clientDataJSON)
```

- OpenZeppelin `WebAuthn.tryDecodeAuth` accepts the payload with no outer tuple
  offset.
- `WebAuthnVerifier` enforces UP always and UV only when deployed with
  `REQUIRE_UV = true`.
