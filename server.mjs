/**
 * Self + ZKPassport Backend Server (ESM)
 */
import {
  saveVerification,
  checkAttestationExists,
  saveSelfCheck,
  checkAddressExists,
} from './database.mjs';
import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { SelfBackendVerifier, AllIds, DefaultConfigStore } from '@selfxyz/core';
//import { countries } from '@selfxyz/common';

import { createRequire } from 'module';
import { extractWalletAddress } from './utils/selfUserData.mjs';
import {
  b64ToBytes,
  extractFirstSecpPubkey,
  pubkeyToTwilightAddress,
} from './utils/decodeTx.mjs';
const require = createRequire(import.meta.url);
// Prefer the package entry if it resolves to CJS; otherwise target the cjs build directly:
const { ZKPassport } = require('@zkpassport/sdk');

// env
dotenv.config();

const requiredEnvVars = [
  'SELF_SCOPE',
  'SELF_PUBLIC_ENDPOINT',
  'SELF_CALLBACK_URL',
  'OFAC_CHECK',
  'SELF_APAC_ALLOWED',
  'SELF_EXCLUDED_COUNTRIES',
];
const missingEnvVars = requiredEnvVars.filter((k) => !process.env[k]);
if (missingEnvVars.length > 0) {
  console.error('❌ Missing required environment variables:', missingEnvVars);
  process.exit(1);
}

const app = express();
const port = process.env.PORT || 3001;

// allow your dev origins; add any others you use
const defaultOrigins = ['http://localhost:3001'];

const additionalOrigins = process.env.ADDITIONAL_CORS_ORIGINS
  ? process.env.ADDITIONAL_CORS_ORIGINS.split(',')
  : [];

const allowedOrigins = [...defaultOrigins, ...additionalOrigins];
console.log('🔍 Allowed Origins:', allowedOrigins);
const corsMw = cors({
  origin: (origin, cb) => {
    if (!origin) return cb(null, true); // allow curl/server-to-server
    cb(null, allowedOrigins.includes(origin));
  },
  credentials: false, // you aren't sending cookies/Authorization
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'ngrok-skip-browser-warning', 'Accept'],
  maxAge: 86400,
});

app.use(corsMw); // attach globally
app.options('/api/verify/zkpass', corsMw); // <-- explicit preflight handler
app.options('/api/verify', corsMw);

// generous body limits (zk proofs can be large)
app.use(express.json({ limit: '50mb', type: 'application/json' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// size logger
app.use((req, _res, next) => {
  const len = req.headers['content-length'];
  console.log(
    `Incoming ${req.method} ${req.url} ` +
      (len ? `content-length=${len}` : '(chunked/unknown)'),
  );
  next();
});

function getExcludedCountries() {
  try {
    return process.env.SELF_EXCLUDED_COUNTRIES
      ? JSON.parse(process.env.SELF_EXCLUDED_COUNTRIES)
      : [];
  } catch (e) {
    console.warn(
      '❌ Failed to parse EXCLUDED_COUNTRIES, using empty array:',
      e.message,
    );
    return [];
  }
}
const excludedCountries = getExcludedCountries();

function getAllowedCountries() {
  return process.env.SELF_APAC_ALLOWED ? JSON.parse(process.env.SELF_APAC_ALLOWED) : [];
}
const allowedCountries = getAllowedCountries();

// create a function to create properly typed disclosure config
function getDisclosureConfig() {
  return {
    // All fields are optional according to SelfAppDisclosureConfig interface
    issuing_state: true,
    name: false,
    passport_number: false,
    nationality: false,
    date_of_birth: false,
    gender: false,
    expiry_date: true,
    ofac: process.env.OFAC_CHECK === 'true' || false,
    excludedCountries: excludedCountries,
    // minimumAge: undefined, // Optional, omit if not needed
  };
}

// ---------------------------
// Self Protocol configuration
// ---------------------------
const verification_config = {
  //excludedCountries: buildExcludedCountriesFromEnv(),
  excludedCountries: excludedCountries, //getExcludedCountries(),
  // Converting OFAC_CHECK to boolean from string. False by default.
  ofac: process.env.OFAC_CHECK === 'true' || false,
  // minimumAge intentionally omitted
};

console.log('🔍 Excluded Countries:', verification_config.excludedCountries);

let selfBackendVerifier = null;
try {
  console.log('🚀 Initializing Self Protocol Backend Verifier...');
  const configStore = new DefaultConfigStore(verification_config);
  selfBackendVerifier = new SelfBackendVerifier(
    process.env.SELF_SCOPE || 'twilight-relayer-passport',
    process.env.SELF_PUBLIC_ENDPOINT,
    process.env.SELF_MOCK_MODE === 'true',
    AllIds, // accept all doc types
    configStore,
    'uuid', // "hex" for addresses, "uuid" for UUIDs
  );
  console.log('✅ Self Backend Verifier initialized');
  console.log('📋 Configuration:', {
    scope: process.env.SELF_SCOPE || 'twilight-relayer-passport',
    isMock: process.env.SELF_MOCK_MODE === 'true',
    config: configStore,
  });
} catch (err) {
  console.error('❌ Failed to initialize Self Backend Verifier:', err);
}

// ----------
// Healthcheck
// ----------
app.get('/health', (_req, res) => {
  res.json({
    status: 'ok',
    message: 'Backend running',
    timestamp: new Date().toISOString(),
    verifierReady: selfBackendVerifier !== null,
    environment: process.env.NODE_ENV || 'development',
  });
});

app.get('/disclosures', (_req, res) => {
  try {
    // Create the disclosure configuration object
    const disclosureConfig = getDisclosureConfig();
    console.log('🔍 Sending disclosure config:', disclosureConfig);
    res.json({
      status: 'success',
      data: disclosureConfig,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    console.error('❌ Error fetching disclosure config:', error);
    res.status(500).json({
      status: 'error',
      message: error?.message || 'Failed to fetch disclosure configuration',
      timestamp: new Date().toISOString(),
    });
  }
});

// ---------------------------------------------
// Self Protocol verification endpoint (existing)
// ---------------------------------------------
app.post('/api/verify', async (req, res) => {
  try {
    if (req.method === 'OPTIONS') return res.sendStatus(200);

    console.log('📨 Received Self verification request:', req.body);
    if (!selfBackendVerifier) throw new Error('Self Backend Verifier not initialized');

    const { attestationId, proof, publicSignals, userContextData } = req.body;

    if (!proof || !publicSignals || !attestationId || !userContextData) {
      return res.status(400).json({
        status: 'error',
        message:
          'Proof, publicSignals, attestationId, and userContextData are required',
      });
    }

    console.log('🔍 Verifying via Self SDK...', {
      attestationId,
      proofLength: JSON.stringify(proof).length,
      publicSignalsLength: publicSignals.length,
      userContextDataLength: JSON.stringify(userContextData).length,
    });

    const result = await selfBackendVerifier.verify(
      attestationId,
      proof,
      publicSignals,
      userContextData,
    );

    console.log('✅ Self verification result:', result);

    if (result.isValidDetails.isValid) {
      // 1. Extract and log user identifier
      console.log('👤 User Identifier:', result.userData.userIdentifier);

      // 2a. Check expiry date of the Passport/ ID document
      const expiryDateStr = result.discloseOutput.expiryDate; // '300911'
      // Parse YYMMDD format
      const year = 2000 + parseInt(expiryDateStr.substring(0, 2)); // 2030
      const month = parseInt(expiryDateStr.substring(2, 4)) - 1; // 09-1=8 (months are 0-based)
      const day = parseInt(expiryDateStr.substring(4, 6)); // 11
      const expiryDate = new Date(year, month, day);

      const sixMonthsFromNow = new Date();
      sixMonthsFromNow.setMonth(sixMonthsFromNow.getMonth() + 6); // Add 6 months instead of a year
      const isExpiryValid = expiryDate > sixMonthsFromNow;

      // 2b. Check if the document is from an allowed country
      const issuingCountry = result.discloseOutput.issuingState;
      const isCountryAllowed = allowedCountries.includes(issuingCountry);

      console.log('📅 Document Expiry:', {
        expiryDateStr,
        parsedDate: expiryDate.toISOString(),
        sixMonthsFromNow: sixMonthsFromNow.toISOString(),
        hasValidityPeriod: isExpiryValid,
        message: isExpiryValid
          ? '✅ Document has more than 6 months validity'
          : '❌ Document expires within 6 months',
      });

      console.log('🌍 Issuing country:', {
        country: issuingCountry,
        isAllowed: isCountryAllowed,
        message: isCountryAllowed
          ? '✅ Document is from an allowed country'
          : '❌ Document is not from an allowed country',
      });
      //    verify if document is expired and the country is allowed
      if (!isExpiryValid || !isCountryAllowed) {
        return res.status(400).json({
          status: 'error',
          result: false,
          message: 'Document is expired or not from an allowed country',
          details: result.isValidDetails,
          timestamp: new Date().toISOString(),
        });
      }
      // Save BEFORE responding (fixes prior pattern)
      try {
        // If your DB helper accepts only (identifier, address), use attestationId + cosmosAddress.
        // If you extended it to accept a provider, pass 'self' as third param.
        await saveSelfCheck(result.userData?.userIdentifier, proof);
        console.log('💾 Self check saved');
        const cosmosAddress = extractWalletAddress(result.userData?.userDefinedData);

        if (!cosmosAddress) {
          return res
            .status(400)
            .json({ error: 'Invalid or missing Twilight wallet address' });
        }

        console.log('✅ Extracted wallet:', cosmosAddress);

        // Save to zkpass table with provider as 'self'
        const savedRecord = await saveVerification(
          result.userData?.userIdentifier,
          cosmosAddress,
          'self',
        );
        console.log('uuid:', result.userData?.userIdentifier);

        console.log('💾 Data saved successfully:', savedRecord);
      } catch (dbErr) {
        console.error('DB save failed (self):', dbErr);
        // continue anyway
      }
      const response = {
        status: 'success',
        message: 'Verification completed',
        result: true,
        details: result.isValidDetails,
        timestamp: new Date().toISOString(),
      };

      console.log('🎉 Verification successful!');
      res.json(response);
    } else {
      // Verification check failed
      const response = {
        status: 'error',
        result: false,
        message: 'Verification failed',
        details: result.isValidDetails,
        timestamp: new Date().toISOString(),
      };
      console.log('❌ Self verification failed:', response);
      return res.status(400).json(response);
    }
  } catch (error) {
    console.error('❌ Self Protocol Verification error:', error);
    return res.status(500).json({
      status: 'error',
      message: error?.message || 'Internal server error',
      timestamp: new Date().toISOString(),
    });
  }
});

// ----------------------------------------
// NEW: ZKPassport verification endpoint
// ----------------------------------------
app.post('/api/verify/zkpass', async (req, res) => {
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
      return res.status(400).json({ error: 'missing fields', have: Object.keys(body) });
    }

    console.log('🔑 ZKPass client UID:', clientUID);

    // Verify with SDK (off-chain)
    const zk = new ZKPassport(process.env.ZKPASS_DOMAIN || 'localhost:4173');
    const {
      verified,
      uniqueIdentifier: serverUID,
      queryResultErrors,
    } = await zk.verify({
      proofs,
      queryResult: qr,
      scope,
      devMode: typeof devMode === 'boolean' ? devMode : true, // match your FE defaults
      // validity: 180, // optional: days since last ID scan
    });

    // Save BEFORE responding (best practice)
    if (serverUID == clientUID && verified == true) {
      try {
        // If your DB helper accepts only (identifier, address), we store (clientUID || serverUID)
        await saveVerification(clientUID || serverUID, cosmosAddress ?? null, 'zkpass');
        console.log('💾 ZKPass verification saved');
      } catch (dbErr) {
        console.error('DB save failed (zkpass):', dbErr);
        // continue anyway
      }
    }

    return res.json({
      status: verified ? 'success' : 'error',
      verified,
      clientUID,
      serverUID,
      match: clientUID ? clientUID === serverUID : null,
      queryResultErrors,
      address: cosmosAddress ?? null,
      timestamp: new Date().toISOString(),
    });
  } catch (e) {
    console.error('❌ /api/verify/zkpass error:', e?.message || e);
    return res.status(500).json({ error: 'verification_failed' });
  }
});

// ----------------------------------------
// Twilight whitelist address check endpoint
// ----------------------------------------
app.post('/api/verify/whitelist', async (req, res) => {
  try {
    const { recipientAddress } = req.body ?? {};
    if (typeof recipientAddress !== 'string' || recipientAddress.trim() === '') {
      return res.status(200).json({
        status: 'failed',
        data: { address: '', whitelisted: false },
        message: 'Invalid address format',
      });
    }

    const whitelisted = await checkAddressExists(recipientAddress.trim());

    return res.status(200).json({
      status: 'success',
      data: {
        address: recipientAddress.trim(),
        whitelisted,
      },
      message: whitelisted ? 'Address is whitelisted' : 'Address is not whitelisted',
    });
  } catch (err) {
    // Preserve exact shape even on DB errors
    return res.status(500).json({
      status: 'failed',
      data: { address: '', whitelisted: false },
      message: err,
    });
  }
});

// ----------------------------------------
// Twilight whitelist address check endpoint
// ----------------------------------------
app.post('/whitelist/status/tx', async (req, res) => {
  const { jsonrpc, id, method, params } = req.body || {};
  const reply = (result, error) => {
    const base = { jsonrpc: '2.0', id: id ?? null };
    return res.json(error ? { ...base, error } : { ...base, result });
  };

  try {
    if (jsonrpc !== '2.0') {
      return reply(null, { code: -32600, message: 'Invalid Request' });
    }
    if (method !== 'broadcast_tx_sync') {
      return reply(null, { code: -32601, message: 'Method not found' });
    }

    // Support both object and array params
    let txB64;
    if (params && typeof params === 'object' && !Array.isArray(params)) {
      txB64 = params.tx;
    } else if (Array.isArray(params)) {
      txB64 = params[0];
    }
    if (typeof txB64 !== 'string' || !txB64.trim()) {
      return reply(null, {
        code: -32602,
        message: 'Invalid params: tx (base64) is required',
      });
    }

    // Decode & extract address
    const txBytes = b64ToBytes(txB64.trim());
    const pubkey33 = extractFirstSecpPubkey(txBytes);
    const address = pubkeyToTwilightAddress(pubkey33);

    console.log('Extracted address from tx:', address);

    // Whitelist check
    const verified = await checkAddressExists(address);

    return reply({ address, verified }, null);
  } catch (err) {
    return reply(null, { code: -32000, message: err?.message || String(err) });
  }
});

// ----------------------------------------
// Start server
// ----------------------------------------
app.listen(port, () => {
  console.log('🚀 Backend Server started');
  console.log(`📡 Public endpoint: ${process.env.SELF_PUBLIC_ENDPOINT}`);
  console.log(`🔍 Self callback:  ${process.env.SELF_CALLBACK_URL}`);
  console.log(`🔧 Env:           ${process.env.NODE_ENV || 'development'}`);
  console.log(`🔧 Scope:         "${process.env.SELF_SCOPE}"`);
});

export default app;
