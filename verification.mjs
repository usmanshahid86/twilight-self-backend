// cosmosVerify.mjs
import { verifyADR36Amino } from "@keplr-wallet/cosmos";
import { toAscii } from "@cosmjs/encoding";

/** Utility: validate base64 input */
function assertBase64(name, b64) {
  if (
    typeof b64 !== "string" ||
    b64.length % 4 !== 0 ||
    !/^[A-Za-z0-9+/]+={0,2}$/.test(b64)
  ) {
    throw new Error(`${name} is not valid base64`);
  }
}

/**
 * Verify a Cosmos ADR-036 signature.
 * @param {string} bech32Address - full bech32 address (e.g. twilight1…)
 * @param {string} signatureB64  - base64-encoded signature (64 bytes r||s)
 * @param {string} pubkeyB64     - base64-encoded compressed secp256k1 pubkey (33 bytes)
 * @param {string} messageString - the exact message string signed
 * @returns {{ok: boolean, error?: string}}
 */
export function verifySignature(bech32Address, signatureB64, pubkeyB64, messageString) {
  try {
    if (typeof bech32Address !== "string") {
      throw new Error("bech32Address must be a string");
    }
    if (typeof messageString !== "string") {
      throw new Error("messageString must be a string");
    }

    // Derive HRP (prefix before the first '1'): e.g., "twilight" from "twilight1..."
    const hrp = bech32Address.split("1")[0] || "cosmos";

    // Decode inputs
    assertBase64("signatureB64", signatureB64);
    assertBase64("pubkeyB64", pubkeyB64);

    const pubKey = Buffer.from(pubkeyB64, "base64");
    const signature = Buffer.from(signatureB64, "base64");
    const messageBytes = toAscii(messageString);

    // Basic sanity checks
    if (pubKey.length !== 33) {
      throw new Error(`pubkey must be 33 bytes (compressed secp256k1). Got ${pubKey.length}`);
    }
    if (signature.length !== 64) {
      // Some wallets may return 65 with recovery byte; ADR-036 expects 64
      throw new Error(`signature must be 64 bytes (r||s). Got ${signature.length}`);
    }

    // Verify (algo is secp256k1 for Keplr ADR-036)
    const ok = verifyADR36Amino(
      hrp,
      bech32Address,
      messageBytes,
      pubKey,
      signature,
      "secp256k1"
    );

    return { ok };
  } catch (err) {
    return { ok: false, error: err?.message || String(err) };
  }
}
