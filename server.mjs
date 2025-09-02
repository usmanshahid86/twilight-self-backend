/**
 * Self + ZKPassport Backend Server (ESM)
 */
import { saveVerification, checkAttestationExists, saveSelfCheck } from "./database.mjs";
import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import {
  SelfBackendVerifier,
  AllIds,
  DefaultConfigStore,
} from "@selfxyz/core";


import { createRequire } from "module";
const require = createRequire(import.meta.url);
// Prefer the package entry if it resolves to CJS; otherwise target the cjs build directly:
const { ZKPassport } = require("@zkpassport/sdk");

// env
dotenv.config();

const requiredEnvVars = ["SELF_SCOPE", "SELF_PUBLIC_ENDPOINT", "SELF_CALLBACK_URL", "OFAC_CHECK", "EXCLUDED_COUNTRIES"];
const missingEnvVars = requiredEnvVars.filter((k) => !process.env[k]);
if (missingEnvVars.length > 0) {
  console.error("❌ Missing required environment variables:", missingEnvVars);
  process.exit(1);
}

const app = express();
const port = process.env.PORT || 3001;

// allow your dev origins; add any others you use
const allowedOrigins = [
  "http://localhost:4173",
  "http://localhost:5173",
  "http://localhost:3000",
  "http://localhost:3001",
];

const corsMw = cors({
  origin: (origin, cb) => {
    if (!origin) return cb(null, true); // allow curl/server-to-server
    cb(null, allowedOrigins.includes(origin));
  },
  credentials: false,                       // you aren't sending cookies/Authorization
  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: [
    'Content-Type',
    'ngrok-skip-browser-warning',
    'Accept'
  ],
  maxAge: 86400,
});

app.use(corsMw);                             // attach globally
app.options("/api/verify/zkpass", corsMw);   // <-- explicit preflight handler
app.options("/api/verify", corsMw);  

// generous body limits (zk proofs can be large)
app.use(express.json({ limit: "50mb", type: "application/json" }));
app.use(express.urlencoded({ extended: true, limit: "50mb" }));

// size logger
app.use((req, _res, next) => {
  const len = req.headers["content-length"];
  console.log(
    `Incoming ${req.method} ${req.url} ` +
      (len ? `content-length=${len}` : "(chunked/unknown)")
  );
  next();
});

// ---------------------------
// Self Protocol configuration
// ---------------------------
const verification_config = {
  excludedCountries: (() => {
    try {
      return process.env.EXCLUDED_COUNTRIES
        ? JSON.parse(process.env.EXCLUDED_COUNTRIES)
        : [];
    } catch (e) {
      console.warn(
        "❌ Failed to parse EXCLUDED_COUNTRIES, using empty array:",
        e.message
      );
      return [];
    }
  })(),
  // Converting OFAC_CHECK to boolean from string. False by default.
  ofac: process.env.OFAC_CHECK === "true" || false,
  // minimumAge intentionally omitted
};

let selfBackendVerifier = null;
try {
  console.log("🚀 Initializing Self Protocol Backend Verifier...");
  const configStore = new DefaultConfigStore(verification_config);
  selfBackendVerifier = new SelfBackendVerifier(
    process.env.SELF_SCOPE || "twilight-relayer-passport",
    process.env.SELF_PUBLIC_ENDPOINT,
    process.env.SELF_MOCK_MODE === "true",
    AllIds, // accept all doc types
    configStore,
    "uuid" // "hex" for addresses, "uuid" for UUIDs
  );
  console.log("✅ Self Backend Verifier initialized");
  console.log("📋 Configuration:", {
    scope: process.env.SELF_SCOPE || "twilight-relayer-passport",
    isMock: process.env.SELF_MOCK_MODE === "true",
    config: verification_config,
  });
} catch (err) {
  console.error("❌ Failed to initialize Self Backend Verifier:", err);
}

// ----------
// Healthcheck
// ----------
app.get("/health", (_req, res) => {
  res.json({
    status: "ok",
    message: "Backend running",
    timestamp: new Date().toISOString(),
    verifierReady: selfBackendVerifier !== null,
    environment: process.env.NODE_ENV || "development",
  });
});

// ---------------------------------------------
// Self Protocol verification endpoint (existing)
// ---------------------------------------------
app.post("/api/verify", async (req, res) => {
  try {
    if (req.method === "OPTIONS") return res.sendStatus(200);

    console.log("📨 Received Self verification request:", req.body);
    if (!selfBackendVerifier) throw new Error("Self Backend Verifier not initialized");

    const { attestationId, proof, publicSignals, userContextData} = req.body;

    if (!proof || !publicSignals || !attestationId || !userContextData) {
      return res.status(400).json({
        status: "error",
        message:
          "Proof, publicSignals, attestationId, and userContextData are required",
      });
    }

    console.log("🔍 Verifying via Self SDK...", {
      attestationId,
      proofLength: JSON.stringify(proof).length,
      publicSignalsLength: publicSignals.length,
      userContextDataLength: JSON.stringify(userContextData).length,
    });

    const result = await selfBackendVerifier.verify(
      attestationId,
      proof,
      publicSignals,
      userContextData
    );

    console.log("✅ Self verification result:", result);

    if (result.isValidDetails.isValid) {
      // 1. Extract and log user identifier
      console.log("👤 User Identifier:", result.userData.userIdentifier);

      // 2a. Check expiry date of the Passport/ ID document
      const expiryDate = new Date(result.discloseOutput.expiryDate);
      const oneYearFromNow = new Date();
      oneYearFromNow.setFullYear(oneYearFromNow.getFullYear() + 1);
      const isExpiryValid = expiryDate > oneYearFromNow;

      // 2b. Check if the document is from an allowed country
      const allowedCountries = ["CHN", "IDN", "MYS", "USA"];
      const issuingCountry = result.discloseOutput.issuingState;
      const isCountryAllowed = allowedCountries.includes(issuingCountry);

      console.log("📅 Document Expiry:", {
        expiryDate: expiryDate.toISOString().split("T")[0],
        hasOneYearValidity: isExpiryValid,
        message: isExpiryValid
          ? "✅ Document has more than 1 year validity"
          : "❌ Document expires within 1 year",
      });

      console.log("🌍 Issuing country:", {
        country: issuingCountry,
        isAllowed: isCountryAllowed,
        message: isCountryAllowed
          ? "✅ Document is from an allowed country"
          : "❌ Document is not from an allowed country",
      });

      // Save BEFORE responding (fixes prior pattern)
      try {
        // If your DB helper accepts only (identifier, address), use attestationId + cosmosAddress.
        // If you extended it to accept a provider, pass 'self' as third param.
        await saveSelfCheck(result.userData?.userIdentifier, proof);
        console.log("💾 Self check saved");
        // Decode the hex-encoded cosmos address from userDefinedData
        const cosmosAddress = Buffer.from(
          result.userData?.userDefinedData,
          "hex"
        ).toString("utf8");
        console.log("Decoded cosmos address:", cosmosAddress);
        // validation of cosmos address before saving
        if (!cosmosAddress.startsWith("twilight")) {
          throw new Error("Invalid cosmos address format");
        }

        // Save to zkpass table with provider as 'self'
        const savedRecord = await saveVerification(
          result.userData?.userIdentifier,
          cosmosAddress,
          "self"
        );
        console.log("uuid:", result.userData?.userIdentifier);

        console.log("💾 Data saved successfully:", savedRecord);
      } catch (dbErr) {
        console.error("DB save failed (self):", dbErr);
        // continue anyway
      }
      const response = {
        status: "success",
        message: "Verification completed",
        result: true,
        details: result.isValidDetails,
        timestamp: new Date().toISOString(),
      };

      console.log("🎉 Verification successful!");
      res.json(response);
    } else {
      // Verification check failed 
      const response = {
        status: "error",
        result: false,
        message: "Verification failed",
        details: result.isValidDetails,
        timestamp: new Date().toISOString(),
      };
      console.log("❌ Self verification failed:", response);
      return res.status(400).json(response);
    }
  } catch (error) {
    console.error("❌ Self Protocol Verification error:", error);
    return res.status(500).json({
      status: "error",
      message: error?.message || "Internal server error",
      timestamp: new Date().toISOString(),
    });
  }
});

app.post("/api/verify/self", async (req, res) => {
  try {
    console.log("📨 Received Self verification request:", req.body);
    
    const { cosmosAddress, uuid } = req.body;
    
    // Validate required fields
    if (!cosmosAddress || !uuid) {
      return res.status(400).json({
        status: "error",
        message: "cosmosAddress and attestationId are required",
        timestamp: new Date().toISOString(),
      });
    }
    
    console.log("🔍 Checking if attestation ID exists:", uuid);
    
    // Check if attestation ID exists in selfcheck table
    const attestationExists = await checkAttestationExists(uuid);
    
    if (!attestationExists) {
      console.log("❌ Attestation ID not found in selfcheck table");
      return res.status(404).json({
        status: "error",
        message: "Attestation ID not found in selfcheck table",
        uuid,
        timestamp: new Date().toISOString(),
      });
    }
    
    console.log("✅ Attestation ID found, saving to zkpass table");
    
    // Save to zkpass table with provider as 'self'
    const savedRecord = await saveVerification(uuid, cosmosAddress, 'self');
    
    console.log("💾 Data saved successfully:", savedRecord);
    
    return res.json({
      status: "success",
      message: "Verification data saved successfully",
      data: savedRecord,
      timestamp: new Date().toISOString(),
    });
    
  } catch (error) {
    console.error("❌ /api/verify/self error:", error);
    return res.status(500).json({
      status: "error",
      message: error?.message || "Internal server error",
      timestamp: new Date().toISOString(),
    });
  }
});

// ----------------------------------------
// NEW: ZKPassport verification endpoint
// ----------------------------------------
app.post("/api/verify/zkpass", async (req, res) => {
  try {
    // If you enabled express.raw above, you’d parse Buffer here.
    const body = req.body ?? {};

    // Accept either "queryResult" (preferred) or "result" (older FE)
    const {
      proofs,
      queryResult,
      result,
      scope,
      uniqueIdentifier: clientUID,
      cosmosAddress, // optional: wallet address or user address from FE
      devMode, // optional: allow FE to toggle mock/dev mode; fallback below
    } = body;

    const qr = queryResult ?? result;

    if (!proofs || !qr || !scope) {
      return res
        .status(400)
        .json({ error: "missing fields", have: Object.keys(body) });
    }

    console.log("🔑 ZKPass client UID:", clientUID);

    // Verify with SDK (off-chain)
    const zk = new ZKPassport(process.env.ZKPASS_DOMAIN || "localhost:4173");
    const { verified, uniqueIdentifier: serverUID, queryResultErrors } =
      await zk.verify({
        proofs,
        queryResult: qr,
        scope,
        devMode: typeof devMode === "boolean" ? devMode : true, // match your FE defaults
        // validity: 180, // optional: days since last ID scan
      });

    // Save BEFORE responding (best practice)
    if (serverUID == clientUID && verified ==  true){
      try {
        // If your DB helper accepts only (identifier, address), we store (clientUID || serverUID)
        await saveVerification(clientUID || serverUID, cosmosAddress ?? null, "zkpass");
        console.log("💾 ZKPass verification saved");
      } catch (dbErr) {
        console.error("DB save failed (zkpass):", dbErr);
        // continue anyway
      }
    }

    return res.json({
      status: verified ? "success" : "error",
      verified,
      clientUID,
      serverUID,
      match: clientUID ? clientUID === serverUID : null,
      queryResultErrors,
      address: cosmosAddress ?? null,
      timestamp: new Date().toISOString(),
    });
  } catch (e) {
    console.error("❌ /api/verify/zkpass error:", e?.message || e);
    return res.status(500).json({ error: "verification_failed" });
  }
});

// start server
app.listen(port, () => {
  console.log("🚀 Backend Server started");
  console.log(`📡 Public endpoint: ${process.env.SELF_PUBLIC_ENDPOINT}`);
  console.log(`🔍 Self callback:  ${process.env.SELF_CALLBACK_URL}`);
  console.log(`🔧 Env:           ${process.env.NODE_ENV || "development"}`);
  console.log(`🔧 Scope:         "${process.env.SELF_SCOPE }"`);
});

export default app;
