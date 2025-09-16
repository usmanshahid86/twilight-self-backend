function decodeUserDefinedData(input) {
  if (!input) return "";
    const s = String(input);
  console.log("String:", s);
  const hexLike =
    /^(0x)?[0-9a-fA-F]+$/.test(s) && s.replace(/^0x/, "").length % 2 === 0;
  if (hexLike) {
    try {
      return Buffer.from(s.replace(/^0x/, ""), "hex").toString("utf8");
    } catch {
      return s;
    }
  }
  return s;
}

export function extractWalletAddress(userDefinedDataRaw) {
  const text = decodeUserDefinedData(userDefinedDataRaw);
  const lines = text.split(/\r?\n/);
  console.log("Lines:", lines);
  // Find the line that starts with "Wallet:"
  const walletLine = lines.find((l) => l.trim().startsWith("Wallet:"));
  if (!walletLine) return undefined;

  // Remove label and trim
  const wallet = walletLine.replace("Wallet:", "").trim();

  // ✅ Validate format (adjust regex as needed)
  const twilightRegex = /^twilight[0-9a-z]{10,}$/i;
  if (!twilightRegex.test(wallet)) {
    console.warn("⚠️ Extracted wallet did not match Twilight format:", wallet);
    return undefined;
  }

  return wallet;
}
