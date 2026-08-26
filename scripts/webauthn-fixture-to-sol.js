#!/usr/bin/env node
/* eslint-disable no-console */
const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");

const DEFAULT_INPUT_DIR = "test/fixtures/webauthn";
const DEFAULT_OUTPUT = "test/verifiers/WebAuthnCapturedFixtures.generated.t.sol";

function usage() {
  console.log(`Usage:
  node scripts/webauthn-fixture-to-sol.js [inputDir] [outputSol]

Reads WebAuthn fixture JSON files captured by deploy/webauthn-fixture-recorder.html
and writes a Foundry test contract. If no JSON fixture exists, no output file is
created and the command exits successfully.

Default:
  inputDir  = ${DEFAULT_INPUT_DIR}
  outputSol = ${DEFAULT_OUTPUT}`);
}

function isHex(v, bytes) {
  return typeof v === "string" && new RegExp(`^0x[0-9a-fA-F]{${bytes * 2}}$`).test(v);
}

function isHexBytes(v) {
  return typeof v === "string" && /^0x([0-9a-fA-F]{2})*$/.test(v);
}

function b64urlFromHex32(hex) {
  const b = Buffer.from(hex.slice(2), "hex");
  return b.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function ident(label, fallback) {
  const raw = String(label || fallback || "fixture").toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_+|_+$/g, "");
  const id = raw || fallback || "fixture";
  return /^[0-9]/.test(id) ? `f_${id}` : id;
}

function fixtureIdFromFile(name, i, used) {
  const base = ident(path.basename(name, ".json"), `fixture_${i + 1}`);
  let id = base;
  let n = 2;
  while (used.has(id)) {
    id = `${base}_${n}`;
    n += 1;
  }
  used.add(id);
  return id;
}

// Minimal ABI encoder for the verifier's flat signature tuple:
// (bytes32 r, bytes32 s, uint256 challengeIndex, uint256 typeIndex,
//  bytes authenticatorData, string clientDataJSON).
// Re-encoding from the decomposed fields and comparing against the stored
// `signature` blob guarantees a hand-edited fixture cannot diverge between
// what humans read (the fields) and what the tests exercise (the blob).
function encodeFixtureSignature(f) {
  const word = (hex) => hex.slice(2).toLowerCase();
  const uintWord = (n) => BigInt(n).toString(16).padStart(64, "0");
  const padRight = (hex) => hex + "0".repeat((64 - (hex.length % 64)) % 64);
  const dynamic = (hexNoPrefix) => uintWord(hexNoPrefix.length / 2) + padRight(hexNoPrefix);
  const authEnc = dynamic(f.authenticatorData.slice(2).toLowerCase());
  const clientEnc = dynamic(Buffer.from(f.clientDataJSON, "utf8").toString("hex"));
  const headSize = 6 * 32;
  return "0x"
    + word(f.r) + word(f.s)
    + uintWord(f.challengeIndex) + uintWord(f.typeIndex)
    + uintWord(headSize) + uintWord(headSize + authEnc.length / 2)
    + authEnc + clientEnc;
}

function validateFixture(f, file) {
  const errors = [];
  if (f.fixtureVersion !== 1) errors.push("fixtureVersion must be 1");
  if (!isHex(f.publicKey, 64)) errors.push("publicKey must be 64 bytes qx||qy");
  if (!isHex(f.hash, 32)) errors.push("hash must be bytes32");
  if (!isHexBytes(f.signature)) errors.push("signature must be 0x bytes");
  if (!isHex(f.r, 32)) errors.push("r must be bytes32");
  if (!isHex(f.s, 32)) errors.push("s must be bytes32");
  if (!isHexBytes(f.authenticatorData) || f.authenticatorData.length < 2 + 37 * 2) {
    errors.push("authenticatorData must be at least 37 bytes");
  }
  if (typeof f.clientDataJSON !== "string") errors.push("clientDataJSON must be a string");
  if (!Number.isSafeInteger(f.challengeIndex) || f.challengeIndex < 0) errors.push("challengeIndex must be a non-negative integer");
  if (!Number.isSafeInteger(f.typeIndex) || f.typeIndex < 0) errors.push("typeIndex must be a non-negative integer");
  if (typeof f.clientDataJSON === "string") {
    if (f.clientDataJSON.indexOf('"challenge":"') !== f.challengeIndex) errors.push("challengeIndex does not match clientDataJSON");
    if (f.clientDataJSON.indexOf('"type":"webauthn.get"') !== f.typeIndex) errors.push("typeIndex does not match clientDataJSON");
    try {
      const parsed = JSON.parse(f.clientDataJSON);
      const expected = isHex(f.hash, 32) ? b64urlFromHex32(f.hash) : null;
      if (expected && parsed.challenge !== expected) errors.push(`clientDataJSON.challenge mismatch: expected ${expected}, got ${parsed.challenge}`);
      if (parsed.type !== "webauthn.get") errors.push(`clientDataJSON.type mismatch: ${parsed.type}`);
    } catch (e) {
      errors.push(`clientDataJSON is not JSON: ${e.message}`);
    }
  }
  if (errors.length === 0 && encodeFixtureSignature(f) !== f.signature.toLowerCase()) {
    errors.push("signature blob does not re-encode from (r, s, challengeIndex, typeIndex, authenticatorData, clientDataJSON)");
  }
  if (errors.length) {
    throw new Error(`${file}:\n  - ${errors.join("\n  - ")}`);
  }
}

function readFixtures(inputDir) {
  if (!fs.existsSync(inputDir)) return [];
  return fs.readdirSync(inputDir)
    .filter((f) => f.endsWith(".json"))
    .sort()
    .map((name) => {
      const file = path.join(inputDir, name);
      const fixture = JSON.parse(fs.readFileSync(file, "utf8"));
      validateFixture(fixture, file);
      return { name, file, fixture };
    });
}

function solString(s) {
  return JSON.stringify(s);
}

function render(fixtures) {
  const usedIds = new Set();
  const tests = fixtures.map(({ name, fixture }, i) => {
    const id = fixtureIdFromFile(name, i, usedIds);
    const flags = fixture.flags || {};
    const uv = flags.uv === true;
    const showLabel = fixture.label && fixture.label !== path.basename(name, ".json");
    const label = `${name}${showLabel ? ` (${fixture.label})` : ""}`;
    return `
    function test_${id}() public view {
        bytes memory key = hex"${fixture.publicKey.slice(2)}";
        bytes32 hash = ${fixture.hash};
        bytes memory sig = hex"${fixture.signature.slice(2)}";
        _assert(vNoUV.verify(key, hash, sig) == MAGIC, ${solString(`${label}: no-UV verifier`)});
        _assert(vUV.verify(key, hash, sig) ${uv ? "==" : "!="} MAGIC, ${solString(`${label}: UV policy`)});
    }`;
  }).join("\n");

  return `// SPDX-License-Identifier: MIT
pragma solidity 0.8.35;

import {WebAuthnVerifier} from "../../src/verifiers/WebAuthnVerifier.sol";
import {IERC7913SignatureVerifier} from "@openzeppelin/contracts/interfaces/IERC7913.sol";

/// @notice Generated from test/fixtures/webauthn/*.json by
///         scripts/webauthn-fixture-to-sol.js. Do not edit manually.
contract WebAuthnCapturedFixtures {
    bytes4 constant MAGIC = IERC7913SignatureVerifier.verify.selector;

    WebAuthnVerifier vUV;
    WebAuthnVerifier vNoUV;

    constructor() {
        vUV = new WebAuthnVerifier(true);
        vNoUV = new WebAuthnVerifier(false);
    }

    function _assert(bool cond, string memory what) internal pure {
        require(cond, what);
    }
${tests}
}
`;
}

// The generated file is committed, and the pre-commit hook runs `forge fmt
// --check` over the tree, so the generator must emit forge-fmt output. Skip
// silently when forge is unavailable (the raw output is still valid Solidity).
function formatOutput(output) {
  const res = spawnSync("forge", ["fmt", output], { stdio: "ignore" });
  if (res.error) {
    console.log("forge not found; skipping `forge fmt` on the generated file.");
  }
}

function main() {
  const args = process.argv.slice(2);
  if (args.includes("-h") || args.includes("--help")) {
    usage();
    return;
  }
  const inputDir = args[0] || DEFAULT_INPUT_DIR;
  const output = args[1] || DEFAULT_OUTPUT;
  const fixtures = readFixtures(inputDir);
  if (fixtures.length === 0) {
    if (fs.existsSync(output)) {
      fs.unlinkSync(output);
      console.log(`No WebAuthn JSON fixtures found in ${inputDir}; removed stale ${output}.`);
    } else {
      console.log(`No WebAuthn JSON fixtures found in ${inputDir}; nothing generated.`);
    }
    return;
  }
  fs.mkdirSync(path.dirname(output), { recursive: true });
  fs.writeFileSync(output, render(fixtures));
  formatOutput(output);
  console.log(`Generated ${output} from ${fixtures.length} fixture(s).`);
}

main();
