/**
 * Self Protocol Backend Server with Real SDK Integration
 * Following the quickstart guide: https://docs.self.xyz/use-self/quickstart
 */

import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import {
  SelfBackendVerifier,
  AllIds,
  DefaultConfigStore
} from '@selfxyz/core';

// Load environment variables
dotenv.config();

const requiredEnvVars = [
  'SELF_SCOPE',
  'SELF_PUBLIC_ENDPOINT',
  'SELF_CALLBACK_URL'
];

const missingEnvVars = requiredEnvVars.filter(envVar => !process.env[envVar]);
if (missingEnvVars.length > 0) {
  console.error('❌ Missing required environment variables:', missingEnvVars);
  process.exit(1);
}

const app = express();
const port = process.env.PORT || 3001;

// Parse CORS origins from environment variable
const corsOrigins = process.env.CORS_ORIGINS ? process.env.CORS_ORIGINS.split(',') : [
  "http://localhost:3000",
  "http://localhost:3001",
  "http://localhost:5173"
];

// Middleware
app.use(
  cors({
    origin: corsOrigins,
    credentials: true,
  })
);
app.use(express.json());

// Self Protocol Configuration from environment
const verification_config = {
  excludedCountries: process.env.EXCLUDED_COUNTRIES ? JSON.parse(process.env.EXCLUDED_COUNTRIES) : [],
  ofac: process.env.OFAC_CHECK === 'true',
  minimumAge: parseInt(process.env.MIN_AGE || '18', 10),
};

// Initialize Self Protocol Backend Verifier
let selfBackendVerifier = null;

try {
  console.log('🚀 Initializing Self Protocol Backend Verifier...');
  
  const configStore = new DefaultConfigStore(verification_config);
  
  selfBackendVerifier = new SelfBackendVerifier(
    process.env.SELF_SCOPE || "twilight-relayer-passport",
    process.env.SELF_PUBLIC_ENDPOINT,
    process.env.SELF_MOCK_MODE === 'true',
    AllIds, // Accept all document types
    configStore,
    "hex" // "hex" for addresses, "uuid" for UUIDs
  );
  
  console.log('✅ Self Backend Verifier initialized successfully');
  console.log('📋 Configuration:', {
    scope: process.env.SELF_SCOPE || "twilight-relayer-passport",
    isMock: process.env.SELF_MOCK_MODE === 'true',
    config: verification_config
  });
} catch (error) {
  console.error('❌ Failed to initialize Self Backend Verifier:', error);
}

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    message: 'Self Protocol Backend Server running',
    timestamp: new Date().toISOString(),
    verifierReady: selfBackendVerifier !== null,
    environment: process.env.NODE_ENV || 'development'
  });
});

// Real Self Protocol verification endpoint
app.post('/api/verify', async (req, res) => {
  try {
    if (req.method === 'OPTIONS') {
      res.sendStatus(200);
      return;
    }

    console.log('📨 Received verification request from Self Protocol:', req.body);

    if (!selfBackendVerifier) {
      throw new Error('Self Backend Verifier not initialized');
    }

    // Extract data from the request
    const { attestationId, proof, publicSignals, userContextData } = req.body;

    // Verify all required fields are present
    if (!proof || !publicSignals || !attestationId || !userContextData) {
      return res.status(400).json({
        message: "Proof, publicSignals, attestationId and userContextData are required",
      });
    }

    console.log('🔍 Verifying proof with Self Protocol SDK...', {
      attestationId,
      proofLength: JSON.stringify(proof).length,
      publicSignalsLength: publicSignals.length,
      userContextDataLength: JSON.stringify(userContextData).length
    });

    // Verify the proof using Self Protocol
    const result = await selfBackendVerifier.verify(
      attestationId,
      proof,
      publicSignals,
      userContextData
    );

    console.log('✅ Self Protocol verification result:', result);
    // Check if verification was successful
    if (result.isValidDetails.isValid) {
      const response = {
        status: "success",
        result: true,
        credentialSubject: result.discloseOutput,
        timestamp: new Date().toISOString(),
        attestationId: attestationId
      };
      
      console.log('🎉 Verification successful! Returning:', response);
      res.json(response);
    } else {
      // Verification failed
      const response = {
        status: "error",
        result: false,
        message: "Verification failed",
        details: result.isValidDetails,
        timestamp: new Date().toISOString()
      };
      
      console.log('❌ Verification failed:', response);
      res.status(500).json(response);
    }

  } catch (error) {
    console.error('❌ Verification error:', error);
    res.status(500).json({
      status: "error",
      message: error.message || "Internal server error",
      timestamp: new Date().toISOString()
    });
  }
});

// Start server
app.listen(port, () => {
  console.log('🚀 Self Protocol Backend Server started');
  console.log(`📡 Server running on  ${process.env.SELF_PUBLIC_ENDPOINT}`);
  console.log(`🔍 Verification endpoint: ${process.env.SELF_CALLBACK_URL}`);
  console.log(`🔧 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`🔧 Scope: "${process.env.SELF_SCOPE || 'twilight-relayer-passport'}"`);
});

export default app;
