// @ts-check
const { test, expect } = require("@playwright/test");
const { createServer } = require("node:http");
const { createReadStream, existsSync } = require("node:fs");
const { extname, join, resolve } = require("node:path");

const ROOT = resolve(__dirname, "../..");
const SAFE = "0x000000000000000000000000000000000000cafe";
const SAFE_SINGLETON = "0x0000000000000000000000000000000000005150";
const SINGLETON = "0x0000000000000000000000000000000000001000";
const MULTISEND = "0x000000000000000000000000000000000000a83c";
const FALLBACK_HANDLER = "0x000000000000000000000000000000000000f411";
const BACKUP = "0x000000000000000000000000000000000000c003";
const EOA_A = "0x000000000000000000000000000000000000a11c";
const EOA_B = "0x000000000000000000000000000000000000b0b0";
const BYPASSER = "0x000000000000000000000000000000000000b055";
const PASSWORD_VERIFIER = "0x0000000000000000000000000000000000009001";
const ACCOUNT = "0x0000000000000000000000000000000000000abc";
const MODULE = "0x000000000000000000000000000000000000d00d";
const PREV_MODULE = "0x0000000000000000000000000000000000000001";
const MODULE_TX_HASH = "0x" + "44".repeat(32);

const OPERATOR_MUTATION_CONTROLS = {
  initialize: "#buildInitialize",
  setLockdownDuration: "#buildSetDuration",
  setResumeDelay: "#buildSetResumeDelay",
  addRecoveryOwner: "#buildSetRecoveryOwner",
  removeRecoveryOwner: "#buildSetRecoveryOwner",
  addLockdownSigner: "#buildAddSigner",
  removeLockdownSigner: "#buildRemoveSigner",
  rotateLockdownSigner: "#buildRotateSigner",
  setTimelockDelay: "#buildSetTimelock",
  setTimelockBypasser: "#buildSetBypasser",
  scheduleTransaction: "#buildScheduleOwner",
  cancelTransaction: "#buildCancelOwner",
  scheduleModuleTransaction: "#buildScheduleModule",
  cancelModuleTransaction: "#buildCancelModule",
  bypassTimelock: "#buildBypassTimelock",
  sweepExpiredOwnerTicket: "#buildSweepOwner",
  sweepExpiredModuleTicket: "#buildSweepModule",
  triggerLockdown: "#buildTriggerJson"
};

const SELECTORS = {
  version: "0xffa1ad74",
  multiSend: "0xfdd9ec6f",
  eip712Domain: "0x84b0196e",
  supportsInterface: "0x01ffc9a7",
  getConfigSnapshot: "0x4ac6f336",
  getOwners: "0xa0e67e2b",
  getThreshold: "0xe75235b8",
  nonce: "0xaffed0e0",
  getState: "0x1bab58f5",
  isRecoveryOwner: "0x5a182da3",
  getModulesPaginated: "0xcc2f8452",
  getModuleTransactionHash: "0x3298706e",
  isLockdownSigner: "0xe4e1703d",
  isSignerBurntPermanently: "0xbb10301d",
  testSigner: "0x7b3eb6ca",
  lockdown: "0x08be071c"
};

const SAFE_MASTERCOPY_SLOT = "0x0000000000000000000000000000000000000000000000000000000000000000";
const SAFE_GUARD_SLOT = "0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8";
const SAFE_MODULE_GUARD_SLOT = "0xb104e0b93118902c651344349b610029d694cfdec91c589c91ebafbcd0289947";
const SAFE_FALLBACK_HANDLER_SLOT = "0x6c9a6c4a39284e37ed1cf53d337577d14212a4870fb976a4366c693b939918d5";

function pad(hex) {
  return hex.replace(/^0x/, "").padStart(64, "0");
}

function word(n) {
  return BigInt(n).toString(16).padStart(64, "0");
}

function addressWord(addr) {
  return pad(addr.toLowerCase());
}

function encodeString(value) {
  const bytes = Buffer.from(value, "utf8");
  const padded = Math.ceil(bytes.length / 32) * 32;
  return word(32) + word(bytes.length) + bytes.toString("hex").padEnd(padded * 2, "0");
}

function encodeBool(value) {
  return word(value ? 1 : 0);
}

function encodeAddress(addr) {
  return addressWord(addr);
}

function isZeroSlot(slot) {
  try {
    return BigInt(slot) === 0n;
  } catch (_) {
    return false;
  }
}

function encodeConfigSnapshot(lifecycleMode) {
  const values = lifecycleMode === "recovery"
    ? [3600, 1800, 1700000000, 2, 1]
    : lifecycleMode === "normal" ? [3600, 1800, 0, 2, 1] : [0, 0, 0, 0, 0];
  return values.map(word).join("");
}

function encodeAddressArray(addresses) {
  return word(32) + word(addresses.length) + addresses.map(addressWord).join("");
}

function encodeEip712Domain() {
  const name = dynamicBytes(Buffer.from("RuntimeLockdown", "utf8"));
  const version = dynamicBytes(Buffer.from("1.0.0", "utf8"));
  const extensions = word(0);
  const headSize = 7 * 32;
  const nameOffset = headSize;
  const versionOffset = nameOffset + name.length / 2;
  const extensionsOffset = versionOffset + version.length / 2;
  return [
    "0f".padEnd(64, "0"),
    word(nameOffset),
    word(versionOffset),
    word(1),
    addressWord(SINGLETON),
    word(0),
    word(extensionsOffset),
    name,
    version,
    extensions
  ].join("");
}

function dynamicBytes(buffer) {
  const padded = Math.ceil(buffer.length / 32) * 32;
  return word(buffer.length) + buffer.toString("hex").padEnd(padded * 2, "0");
}

async function startStaticServer() {
  const server = createServer((req, res) => {
    const rawPath = new URL(req.url || "/", "http://127.0.0.1").pathname;
    const filePath = join(ROOT, rawPath === "/" ? "deploy/lockdown-lifecycle.html" : rawPath);
    if (!filePath.startsWith(ROOT) || !existsSync(filePath)) {
      res.writeHead(404);
      res.end("not found");
      return;
    }
    const types = { ".html": "text/html", ".js": "application/javascript", ".json": "application/json" };
    res.writeHead(200, { "content-type": types[extname(filePath)] || "text/plain" });
    createReadStream(filePath).pipe(res);
  });
  await new Promise((resolveListen) => server.listen(0, "127.0.0.1", resolveListen));
  const { port } = server.address();
  return { server, baseURL: `http://127.0.0.1:${port}` };
}

async function parseJsonPre(page, selector) {
  return JSON.parse(await page.locator(selector).innerText());
}

async function preview(page) {
  return parseJsonPre(page, "#previewOut");
}

async function fillBaseFields(page, rpcURL) {
  await page.fill("#chainId", "1");
  await page.fill("#readRpcUrl", rpcURL || "");
  await page.fill("#singleton", SINGLETON);
  await page.fill("#multiSendCallOnly", MULTISEND);
  await page.fill("#fallbackHandler", FALLBACK_HANDLER);
  await page.fill("#safeSingleton", SAFE_SINGLETON);
  await page.fill("#installSafe", SAFE);
  await page.fill("#installSingleton", SINGLETON);
  if (rpcURL) await page.check("#allowUnpinned");
}

async function clickAndWaitForPreview(page, selector) {
  const before = await page.locator("#previewOut").innerText();
  await page.click(selector);
  await expect(page.locator("#previewOut")).not.toHaveText(before);
  return preview(page);
}

async function clickAndWaitForJson(page, buttonSelector, outputSelector) {
  const before = await page.locator(outputSelector).innerText();
  await page.click(buttonSelector);
  await expect(page.locator(outputSelector)).not.toHaveText(before);
  return parseJsonPre(page, outputSelector);
}

function installRpcMock(page, rpcURL) {
  let lifecycleMode = "uninitialised";
  let slotMode = "preinstall";
  let signerBurnt = false;
  let blockMode = "canonical";
  const escaped = rpcURL.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const routePromise = page.route(new RegExp(`^${escaped}/?$`), async (route) => {
    const body = route.request().postDataJSON();
    const calls = Array.isArray(body) ? body : [body];
    const replies = calls.map((call) => ({ jsonrpc: "2.0", id: call.id, result: rpcResult(call.method, call.params || [], lifecycleMode, slotMode, signerBurnt, blockMode) }));
    await route.fulfill({
      contentType: "application/json",
      body: JSON.stringify(Array.isArray(body) ? replies : replies[0])
    });
  });
  return routePromise.then(() => ({
    enableRecovery: () => { lifecycleMode = "recovery"; },
    enableLocked: () => { lifecycleMode = "locked"; signerBurnt = true; },
    disableRecovery: () => { lifecycleMode = "normal"; },
    installLockdownSlots: () => { slotMode = "installed"; },
    deactivateGuards: () => { slotMode = "guards-zero"; },
    restoreFallback: () => { slotMode = "fallback-restored"; },
    useCanonicalBlock: () => { blockMode = "canonical"; },
    useReorgedBlock: () => { blockMode = "reorg"; },
    useUnavailableBlock: () => { blockMode = "unavailable"; }
  }));
}

function rpcResult(method, params, lifecycleMode, slotMode, signerBurnt, blockMode) {
  if (method === "eth_chainId") return "0x1";
  if (method === "eth_getCode") return "0x6000";
  if (method === "eth_getStorageAt") {
    const slot = String(params[1] || "").toLowerCase();
    if (slot === SAFE_GUARD_SLOT || slot === SAFE_MODULE_GUARD_SLOT) {
      return `0x${addressWord(slotMode === "installed" ? SINGLETON : "0x0000000000000000000000000000000000000000")}`;
    }
    if (slot === SAFE_FALLBACK_HANDLER_SLOT) {
      return `0x${addressWord(slotMode === "installed" || slotMode === "guards-zero" ? FALLBACK_HANDLER : "0x0000000000000000000000000000000000000000")}`;
    }
    if (slot === SAFE_MASTERCOPY_SLOT || isZeroSlot(slot)) return `0x${addressWord(SAFE_SINGLETON)}`;
    return `0x${addressWord(SINGLETON)}`;
  }
  if (method === "eth_call") {
    const to = String(params[0].to || "").toLowerCase();
    const data = String(params[0].data || "0x").toLowerCase();
    if (data.startsWith(SELECTORS.version)) return `0x${encodeString(to === SAFE.toLowerCase() ? "1.5.0" : "1.0.0")}`;
    if (data.startsWith(SELECTORS.multiSend)) return `0x${encodeAddress(MULTISEND)}`;
    if (data.startsWith(SELECTORS.lockdown)) return `0x${encodeAddress(SINGLETON)}`;
    if (data.startsWith(SELECTORS.eip712Domain)) return `0x${encodeEip712Domain()}`;
    if (data.startsWith(SELECTORS.supportsInterface)) return `0x${encodeBool(true)}`;
    if (data.startsWith(SELECTORS.getConfigSnapshot)) return `0x${encodeConfigSnapshot(lifecycleMode)}`;
    if (data.startsWith(SELECTORS.getOwners)) return `0x${encodeAddressArray([EOA_A, EOA_B])}`;
    if (data.startsWith(SELECTORS.getThreshold)) return `0x${word(2)}`;
    if (data.startsWith(SELECTORS.nonce)) return `0x${word(7)}`;
    if (data.startsWith(SELECTORS.getState)) {
      if (lifecycleMode === "locked") return `0x${word(2)}${word(900)}`;
      if (lifecycleMode === "recovery") return `0x${word(3)}${word(900)}`;
      if (lifecycleMode === "normal") return `0x${word(1)}${word(0)}`;
      return `0x${word(0)}${word(0)}`;
    }
    if (data.startsWith(SELECTORS.isRecoveryOwner)) return `0x${encodeBool(true)}`;
    if (data.startsWith(SELECTORS.getModulesPaginated)) {
      return `0x${word(64)}${addressWord("0x0000000000000000000000000000000000000001")}${word(0)}`;
    }
    if (data.startsWith(SELECTORS.getModuleTransactionHash)) return MODULE_TX_HASH;
    if (data.startsWith(SELECTORS.isLockdownSigner)) return `0x${encodeBool(true)}`;
    if (data.startsWith(SELECTORS.isSignerBurntPermanently)) return `0x${encodeBool(signerBurnt)}`;
    if (data.startsWith(SELECTORS.testSigner)) return `0x${encodeBool(true)}`;
    return "0x";
  }
  if (method === "eth_blockNumber") return "0x1";
  if (method === "eth_getBlockByNumber") {
    if (blockMode === "unavailable") return null;
    return {
      number: "0x1",
      hash: blockMode === "reorg" ? `0x${"99".repeat(32)}` : `0x${"11".repeat(32)}`,
      parentHash: `0x${"22".repeat(32)}`,
      nonce: "0x0000000000000000",
      sha3Uncles: `0x${"33".repeat(32)}`,
      logsBloom: `0x${"00".repeat(256)}`,
      transactionsRoot: `0x${"44".repeat(32)}`,
      stateRoot: `0x${"55".repeat(32)}`,
      receiptsRoot: `0x${"66".repeat(32)}`,
      miner: "0x0000000000000000000000000000000000000000",
      difficulty: "0x0",
      totalDifficulty: "0x0",
      extraData: "0x",
      size: "0x1",
      gasLimit: "0x1c9c380",
      gasUsed: "0x0",
      timestamp: "0x6553f484",
      transactions: [],
      uncles: [],
      baseFeePerGas: "0x1"
    };
  }
  if (method === "eth_getBalance") return "0x0";
  if (method === "eth_getTransactionCount") return "0x0";
  throw new Error(`Unexpected RPC method ${method}`);
}

async function installWalletMock(page) {
  await page.addInitScript(({ account, selectors }) => {
    const calls = [];
    const txHash = `0x${"77".repeat(32)}`;
    const blockHash = `0x${"88".repeat(32)}`;
    const encodedWord = (value) => BigInt(value).toString(16).padStart(64, "0");
    window.__walletCalls = calls;
    window.__walletChainId = "0x1";
    window.ethereum = {
      async request({ method, params }) {
        calls.push({ method, params });
        if (method === "eth_requestAccounts") return [account];
        if (method === "eth_accounts") return [account];
        if (method === "eth_chainId") return window.__walletChainId;
        if (method === "eth_blockNumber") return "0x1";
        if (method === "eth_estimateGas") return "0x5208";
        if (method === "eth_gasPrice") return "0x3b9aca00";
        if (method === "eth_maxPriorityFeePerGas") return "0x3b9aca00";
        if (method === "eth_getTransactionCount") return "0x0";
        if (method === "eth_call") {
          const data = String(params[0].data || "0x").toLowerCase();
          if (data.startsWith(selectors.getState)) return `0x${encodedWord(2)}${encodedWord(900)}`;
          if (data.startsWith(selectors.isSignerBurntPermanently)) return `0x${encodedWord(1)}`;
          throw new Error(`Unexpected wallet eth_call ${data.slice(0, 10)}`);
        }
        if (method === "eth_sendTransaction") {
          window.__submittedTx = params[0];
          return txHash;
        }
        if (method === "eth_getTransactionReceipt") return {
          transactionHash: txHash,
          transactionIndex: "0x0",
          blockHash,
          blockNumber: "0x1",
          from: account,
          to: window.__submittedTx.to,
          cumulativeGasUsed: "0x5208",
          gasUsed: "0x5208",
          contractAddress: null,
          logs: [],
          logsBloom: `0x${"00".repeat(256)}`,
          status: "0x1",
          effectiveGasPrice: "0x3b9aca00",
          type: "0x2"
        };
        if (method === "eth_getTransactionByHash") return {
          hash: txHash,
          blockHash,
          blockNumber: "0x1",
          transactionIndex: "0x0",
          from: account,
          to: window.__submittedTx.to,
          nonce: "0x0",
          gas: "0x5208",
          gasPrice: "0x3b9aca00",
          maxFeePerGas: "0x3b9aca00",
          maxPriorityFeePerGas: "0x3b9aca00",
          input: window.__submittedTx.data,
          value: "0x0",
          chainId: "0x1",
          type: "0x2",
          accessList: [],
          v: "0x1",
          r: `0x${"01".repeat(32)}`,
          s: `0x${"02".repeat(32)}`
        };
        if (method === "eth_signTypedData_v4") {
          const typed = typeof params[1] === "string" ? JSON.parse(params[1]) : params[1];
          window.__lastTypedData = typed;
          return "0x1b".padEnd(132, "0");
        }
        if (method === "personal_sign" || method === "eth_sign") throw new Error(`${method} must not be used`);
        throw new Error(`Unexpected wallet method ${method}`);
      }
    };
  }, { account: ACCOUNT, selectors: { getState: SELECTORS.getState, isSignerBurntPermanently: SELECTORS.isSignerBurntPermanently } });
}

test.describe("lockdown lifecycle helper browser smoke", () => {
  let server;
  let baseURL;

  test.beforeAll(async () => {
    ({ server, baseURL } = await startStaticServer());
  });

  test.afterAll(async () => {
    await new Promise((resolveClose) => server.close(resolveClose));
  });

  test("operator surface covers every user-facing Lockdown mutator", async ({ page }) => {
    await page.goto(`${baseURL}/deploy/lockdown-lifecycle.html`, { waitUntil: "networkidle" });
    for (const [contractFunction, selector] of Object.entries(OPERATOR_MUTATION_CONTROLS)) {
      await expect(page.locator(selector), `${contractFunction} must have an operator control`).toHaveCount(1);
    }
    // Safe calls these protocol hooks; exposing them as operator actions would be unsafe.
    for (const hook of ["checkTransaction", "checkAfterExecution", "checkModuleTransaction", "checkAfterModuleExecution"]) {
      await expect(page.locator(`[data-contract-function="${hook}"]`)).toHaveCount(0);
    }
  });

  test("phase 1: no-wallet builders produce current bytes-identity calldata", async ({ page }) => {
    const pageErrors = [];
    page.on("pageerror", (err) => pageErrors.push(err.message));
    await page.goto(`${baseURL}/deploy/lockdown-lifecycle.html`, { waitUntil: "networkidle" });

    await expect(page.locator("#reworkBanner")).toBeVisible();
    await expect.poll(() => page.evaluate(() => typeof window.ethers)).toBe("object");

    await fillBaseFields(page);
    await page.fill("#initSafe", SAFE);
    await page.fill("#initRecoveryOwners", BACKUP);
    await page.fill("#initSigners", EOA_A);
    await page.click("#buildInitialize");
    const initOut = await parseJsonPre(page, "#initOut");
    expect(initOut.data).toMatch(/^0x/);
    expect(initOut.data.slice(0, 10)).toBe(await page.evaluate(() => ethers.id("initialize(uint64,uint64,address[],bytes[])").slice(0, 10)));

    await page.fill("#sigSingleton", SINGLETON);
    await page.selectOption("#sigType", "ecdsa");
    await page.fill("#sigMat", EOA_A);
    await page.evaluate(() => { document.getElementById("buildAddSigner").disabled = false; });

    const add = await clickAndWaitForPreview(page, "#buildAddSigner");
    expect(add.decoded.action).toBe("addLockdownSigner");
    expect(add.transactionBuilderJson.transactions[0].data.slice(0, 10)).toBe(await page.evaluate(() => ethers.id("addLockdownSigner(bytes)").slice(0, 10)));
    expect(add.transactionBuilderJson.transactions[0].contractInputsValues.signer.toLowerCase()).toBe(EOA_A);

    const remove = await clickAndWaitForPreview(page, "#buildRemoveSigner");
    expect(remove.decoded.action).toBe("removeLockdownSigner");
    expect(remove.transactionBuilderJson.transactions[0].data.slice(0, 10)).toBe(await page.evaluate(() => ethers.id("removeLockdownSigner(bytes)").slice(0, 10)));

    await page.selectOption("#sigRotType", "ecdsa");
    await page.fill("#sigRotMat", EOA_B);
    const rotate = await clickAndWaitForPreview(page, "#buildRotateSigner");
    expect(rotate.decoded.action).toBe("rotateLockdownSigner");
    expect(rotate.transactionBuilderJson.transactions[0].data.slice(0, 10)).toBe(await page.evaluate(() => ethers.id("rotateLockdownSigner(bytes,bytes)").slice(0, 10)));

    await page.fill("#tlSingleton", SINGLETON);
    await page.fill("#tlDelay", "86400");
    const timelock = await clickAndWaitForPreview(page, "#buildSetTimelock");
    expect(timelock.decoded.action).toBe("setTimelockDelay");

    await page.fill("#tlBypasser", BYPASSER);
    await page.selectOption("#tlBypasserEnabled", "true");
    const bypasser = await clickAndWaitForPreview(page, "#buildSetBypasser");
    expect(bypasser.decoded.action).toBe("setTimelockBypasser");

    expect(pageErrors).toEqual([]);
  });

  test("phase 2: mocked RPC preflight and digest flows fail closed/open correctly", async ({ page }) => {
    const rpcURL = "http://127.0.0.1:9845";
    const rpc = await installRpcMock(page, rpcURL);
    await page.goto(`${baseURL}/deploy/lockdown-lifecycle.html`, { waitUntil: "networkidle" });
    await fillBaseFields(page, rpcURL);

    await page.fill("#initSafe", SAFE);
    await page.fill("#initRecoveryOwners", BACKUP);
    await page.fill("#initSigners", EOA_A);
    await page.click("#buildInitialize");

    const rollbackSnapshot = await clickAndWaitForJson(page, "#captureRollbackSnapshot", "#rollbackOut");
    expect(rollbackSnapshot.snapshot).toMatchObject({
      format: "runtime-capital.safe-lockdown.preinstall-slots.v2",
      blockNumber: "1",
      blockHash: `0x${"11".repeat(32)}`
    });

    rpc.useReorgedBlock();
    const reorgRejected = page.waitForEvent("dialog");
    await page.click("#buildInstall");
    const reorgDialog = await reorgRejected;
    expect(reorgDialog.message()).toContain("no longer matches the canonical chain");
    await reorgDialog.dismiss();

    rpc.useUnavailableBlock();
    await page.waitForTimeout(300); // ethers caches same-block reads briefly
    const unavailableRejected = page.waitForEvent("dialog");
    await page.click("#buildInstall");
    const unavailableDialog = await unavailableRejected;
    expect(unavailableDialog.message()).toContain("unavailable from this RPC");
    await unavailableDialog.dismiss();

    rpc.useCanonicalBlock();
    await page.waitForTimeout(300);
    await page.click("#buildInstall");
    await expect(page.locator("#previewOut")).not.toHaveText("No transaction generated yet.");
    const install = await preview(page);
    expect(install.decoded.action).toBe("install");
    expect(install.transactionBuilderJson.transactions).toHaveLength(4);

    rpc.disableRecovery();
    rpc.installLockdownSlots();
    const rollback1 = await clickAndWaitForPreview(page, "#buildRemove");
    expect(rollback1.decoded.action).toBe("rollback-stage-1-deactivate-lockdown");
    expect(rollback1.transactionBuilderJson.transactions).toHaveLength(2);
    expect(rollback1.transactionBuilderJson.transactions[0].data.slice(0, 10)).toBe(await page.evaluate(() => ethers.id("setModuleGuard(address)").slice(0, 10)));
    expect(rollback1.transactionBuilderJson.transactions[1].data.slice(0, 10)).toBe(await page.evaluate(() => ethers.id("setGuard(address)").slice(0, 10)));

    rpc.deactivateGuards();
    await page.waitForTimeout(300); // ethers briefly caches same-block eth_getStorageAt reads
    const rollback2 = await clickAndWaitForPreview(page, "#buildRestoreFallback");
    expect(rollback2.decoded.action).toBe("rollback-stage-2-restore-fallback");
    expect(rollback2.decoded.fallbackHandler).toBe("0x0000000000000000000000000000000000000000");

    rpc.restoreFallback();
    await page.waitForTimeout(300);
    const rollback3 = await clickAndWaitForPreview(page, "#buildRestoreGuards");
    expect(rollback3.decoded.action).toBe("rollback-stage-3-restore-guards");
    expect(rollback3.decoded.transactionGuardInstalledLast).toBe(true);

    await page.fill("#trigSafe", SAFE);
    await page.fill("#trigSingleton", SINGLETON);
    await page.selectOption("#trigType", "password");
    await page.fill("#trigVerifier", PASSWORD_VERIFIER);
    await page.fill("#trigSecret", "correct horse battery staple");
    await page.fill("#trigReasonText", "incident-smoke");
    const digestOut = await clickAndWaitForJson(page, "#buildDigest", "#triggerOut");
    expect(digestOut.domainOnChainOk).toBe(true);
    expect(digestOut.digestToSign).toMatch(/^0x[0-9a-f]{64}$/);

    await page.click("#buildTriggerJson");
    const trigger = await preview(page);
    expect(trigger.decoded.action).toBe("triggerLockdown");
    expect(trigger.transactionBuilderJson.type).toBe("direct-call");
    expect(trigger.transactionBuilderJson.data.slice(0, 10)).toBe(await page.evaluate(() => ethers.id("triggerLockdown(address,bytes32,bytes,bytes)").slice(0, 10)));
    expect(trigger.transactionBuilderJson.from).toContain("NEVER the Safe");

    await page.fill("#tlSafe", SAFE);
    await page.fill("#tlSingleton", SINGLETON);
    await page.fill("#modModule", MODULE);
    await page.fill("#modTo", BACKUP);
    await page.fill("#modValue", "0");
    await page.fill("#modData", "0x1234");

    await page.fill("#annTo", BACKUP);
    await page.fill("#annValue", "0");
    await page.fill("#annData", "0x1234");
    await page.fill("#annSignatures", `0x${"11".repeat(65)}`);
    const scheduleOwner = await clickAndWaitForPreview(page, "#buildScheduleOwner");
    expect(scheduleOwner.decoded.action).toBe("scheduleTransaction");
    expect(scheduleOwner.transactionBuilderJson.type).toBe("direct-call");
    expect(scheduleOwner.transactionBuilderJson.data.slice(0, 10)).toBe(
      await page.evaluate(() => ethers.id("scheduleTransaction(address,uint256,(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address),bytes)").slice(0, 10))
    );

    const scheduleModule = await clickAndWaitForPreview(page, "#buildScheduleModule");
    expect(scheduleModule.decoded.action).toBe("scheduleModuleTransaction");
    expect(scheduleModule.transactionBuilderJson.transactions[0].data.slice(0, 10)).toBe(
      await page.evaluate(() => ethers.id("scheduleModuleTransaction(address,address,uint256,bytes,uint8)").slice(0, 10))
    );

    const cancelModule = await clickAndWaitForPreview(page, "#buildCancelModule");
    expect(cancelModule.decoded.action).toBe("cancelModuleTransaction");
    expect(cancelModule.decoded.moduleTxHash).toBe(MODULE_TX_HASH);
    expect(cancelModule.transactionBuilderJson.transactions[0].data.slice(0, 10)).toBe(
      await page.evaluate(() => ethers.id("cancelModuleTransaction(bytes32)").slice(0, 10))
    );

    await page.fill("#janSafe", SAFE);
    await page.fill("#janSingleton", SINGLETON);
    await page.fill("#janModModule", MODULE);
    await page.fill("#janModTo", BACKUP);
    await page.fill("#janModValue", "0");
    await page.fill("#janModData", "0x1234");
    const sweepModule = await clickAndWaitForPreview(page, "#buildSweepModule");
    expect(sweepModule.decoded.action).toBe("sweepExpiredModuleTicket");
    expect(sweepModule.decoded.moduleTxHash).toBe(MODULE_TX_HASH);
    expect(sweepModule.transactionBuilderJson.transactions[0].data.slice(0, 10)).toBe(
      await page.evaluate(() => ethers.id("sweepExpiredModuleTicket(address,bytes32)").slice(0, 10))
    );

    await expect(page.locator("#recResume")).toHaveCount(0);
    await expect(page.locator("body")).not.toContainText("resumeAfterLockdownPeriodExpired");
    rpc.enableRecovery();
    await page.fill("#recSafe", SAFE);
    await page.fill("#recSingleton", SINGLETON);
    await page.fill("#recPrevModule", PREV_MODULE);
    await page.fill("#recModule", MODULE);
    const disableModule = await clickAndWaitForPreview(page, "#recDisableModule");
    expect(disableModule.decoded.action).toBe("disableModule");
    expect(disableModule.transactionBuilderJson.transactions[0].to.toLowerCase()).toBe(SAFE);
    expect(disableModule.transactionBuilderJson.transactions[0].data.slice(0, 10)).toBe(
      await page.evaluate(() => ethers.id("disableModule(address,address)").slice(0, 10))
    );

    const previewBeforeStatus = await page.locator("#previewOut").innerText();
    const autoResume = await clickAndWaitForJson(page, "#checkAutoResume", "#recoveryOut");
    expect(autoResume).toMatchObject({ state: "Recovering", transactionRequired: false, automaticallyResumed: false });
    expect(await page.locator("#previewOut").innerText()).toBe(previewBeforeStatus);

    rpc.disableRecovery();
    const normalStatus = await clickAndWaitForJson(page, "#checkAutoResume", "#recoveryOut");
    expect(normalStatus).toMatchObject({ state: "Normal", transactionRequired: false });
    expect(normalStatus.resumeEligibleAt).toBeNull();
  });

  test("production builders reject an unpinned or mismatched verifier codehash", async ({ page }) => {
    const rpcURL = "http://127.0.0.1:9848";
    await installRpcMock(page, rpcURL);
    await page.goto(`${baseURL}/deploy/lockdown-lifecycle.html`, { waitUntil: "networkidle" });
    await fillBaseFields(page, rpcURL);
    await page.uncheck("#allowUnpinned");
    await page.fill("#initSafe", SAFE);
    await page.fill("#initRecoveryOwners", BACKUP);
    await page.fill("#initSigners", `password,${PASSWORD_VERIFIER},throwaway init password`);
    await page.check("#initAckPasswordRisk");
    await page.fill("#expPasswordVerifierCodehash", `0x${"99".repeat(32)}`);

    const rejected = page.waitForEvent("dialog");
    await page.click("#buildInitialize");
    const dialog = await rejected;
    expect(dialog.message()).toContain("does not match expected");
    await dialog.dismiss();

    const actualCodehash = await page.evaluate(() => ethers.keccak256("0x6000"));
    await page.fill("#expPasswordVerifierCodehash", actualCodehash);
    const init = await clickAndWaitForJson(page, "#buildInitialize", "#initOut");
    expect(init.decoded.initialSigners[0].scheme).toBe("password");
  });

  test("phase 3: wallet path uses EIP-712 typed data, never personal_sign", async ({ page }) => {
    const rpcURL = "http://127.0.0.1:9846";
    await installWalletMock(page);
    await installRpcMock(page, rpcURL);
    await page.goto(`${baseURL}/deploy/lockdown-lifecycle.html`, { waitUntil: "networkidle" });
    await fillBaseFields(page, rpcURL);

    await page.fill("#trigSafe", SAFE);
    await page.fill("#trigSingleton", SINGLETON);
    await page.selectOption("#trigType", "ecdsa");
    await page.fill("#trigMat", ACCOUNT);
    await page.fill("#trigReasonText", "incident-wallet-smoke");
    await clickAndWaitForJson(page, "#buildDigest", "#triggerOut");
    await page.click("#signWithWallet");

    await expect.poll(() => page.evaluate(() => Boolean(window.__lastTypedData))).toBe(true);
    const typedData = await page.evaluate(() => window.__lastTypedData);
    expect(typedData.domain).toMatchObject({
      name: "RuntimeLockdown",
      version: "1.0.0",
      verifyingContract: SINGLETON
    });
    expect(["1", "0x1"]).toContain(String(typedData.domain.chainId));
    expect(typedData.types.Lockdown).toEqual([
      { name: "safe", type: "address" },
      { name: "reasonHash", type: "bytes32" }
    ]);
    expect(typedData.message.safe.toLowerCase()).toBe(SAFE);

    const methods = await page.evaluate(() => window.__walletCalls.map((c) => c.method));
    expect(methods).toContain("eth_signTypedData_v4");
    expect(methods).not.toContain("eth_sign");
    expect(methods).not.toContain("personal_sign");

  });

  test("phase 4: panic submit waits for receipt and verifies LockedDown post-conditions", async ({ page }) => {
    const rpcURL = "http://127.0.0.1:9847";
    await installWalletMock(page);
    const rpc = await installRpcMock(page, rpcURL);
    await page.goto(`${baseURL}/deploy/lockdown-lifecycle.html`, { waitUntil: "networkidle" });
    await fillBaseFields(page, rpcURL);

    await page.fill("#trigSafe", SAFE);
    await page.fill("#trigSingleton", SINGLETON);
    await page.selectOption("#trigType", "password");
    await page.fill("#trigVerifier", PASSWORD_VERIFIER);
    await page.fill("#trigSecret", "throwaway browser test password");
    await page.fill("#trigReasonText", "incident-submit-smoke");
    await clickAndWaitForJson(page, "#buildDigest", "#triggerOut");
    await expect(page.locator("#submitTrigger")).toBeEnabled();

    rpc.enableLocked();
    await page.click("#submitTrigger");
    await expect.poll(async () => JSON.parse(await page.locator("#triggerOut").innerText()).step, { timeout: 10000 }).toBe("confirmed");
    const confirmed = await parseJsonPre(page, "#triggerOut");
    expect(confirmed).toMatchObject({ state: "LockedDown", signerBurntPermanently: true, confirmations: 1 });
  });

  test("panic submit rejects a wrong wallet chain before broadcasting the OTP", async ({ page }) => {
    const rpcURL = "http://127.0.0.1:9849";
    await installWalletMock(page);
    await installRpcMock(page, rpcURL);
    await page.goto(`${baseURL}/deploy/lockdown-lifecycle.html`, { waitUntil: "networkidle" });
    await fillBaseFields(page, rpcURL);
    await page.fill("#trigSafe", SAFE);
    await page.fill("#trigSingleton", SINGLETON);
    await page.selectOption("#trigType", "password");
    await page.fill("#trigVerifier", PASSWORD_VERIFIER);
    await page.fill("#trigSecret", "throwaway wrong-chain password");
    await clickAndWaitForJson(page, "#buildDigest", "#triggerOut");
    await page.evaluate(() => { window.__walletChainId = "0x2"; });

    const rejected = page.waitForEvent("dialog");
    await page.click("#submitTrigger");
    const dialog = await rejected;
    expect(dialog.message()).toContain("chain changed since digest creation");
    await dialog.dismiss();
    const methods = await page.evaluate(() => window.__walletCalls.map((call) => call.method));
    expect(methods).not.toContain("eth_sendTransaction");
  });
});
