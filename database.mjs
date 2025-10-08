// database.mjs
import { Pool } from "pg";

// Database configuration
const pool = new Pool({
  user: process.env.DB_USER || "zkpass",
  host: process.env.DB_HOST || "localhost",
  database: process.env.DB_NAME || "zkpass",
  password: process.env.DB_PASSWORD || "zkpass",
  port: parseInt(process.env.DB_PORT || "5432", 10),
});

// Check if the address exists in zkpass table
export async function checkAddressExists(address) {
  if (typeof address !== "string" || address.trim() === "") {
    throw new Error("address must be a non-empty string");
  }

  const sql =
    'SELECT EXISTS(SELECT 1 FROM public.zkpass WHERE address = $1) AS exists, is_real FROM public.zkpass WHERE address = $1 LIMIT 1';
  const params = [address];

  try {
    const { rows } = await pool.query(sql, params);
    const exists = rows?.[0]?.exists === true;
    const isReal = rows?.[0]?.is_real === true;
    return {
      exists,
      documentType: exists ? (isReal ? "real" : "mock") : null, // 1 = real, 0 = mock
    };
  } catch (err) {
    throw new Error(`failed to check address existence: ${err.message}`);
  }
}

// Save verification data
export async function saveVerification(uniqueIdentifier, address, provider, isReal) {
  try {
    const result = await pool.query(
      `INSERT INTO zkpass (address, identifier, provider, is_real)
       VALUES ($1, $2, $3, $4)
       RETURNING *`,
      [address, uniqueIdentifier, provider, isReal] // address -> $1, uniqueIdentifier -> $2, provider -> $3
    );
    return result.rows[0];
  } catch (error) {
    console.error("Error saving verification:", error);
    throw error;
  }
}

export async function saveSelfCheck(attestationId, proof) {
  try {
    const result = await pool.query(
      `INSERT INTO selfcheck (attestationid, proof)
       VALUES ($1, $2)
       RETURNING *`,
      [attestationId, proof] // address -> $1, uniqueIdentifier -> $2, provider -> $3
    );
    return result.rows[0];
  } catch (error) {
    console.error("Error saving verification:", error);
    throw error;
  }
}

// Check if attestation ID exists in selfcheck table
export async function checkAttestationExists(attestationId) {
  try {
    const result = await pool.query(
      `SELECT COUNT(*) as count FROM selfcheck WHERE attestationid = $1`,
      [attestationId]
    );
    return parseInt(result.rows[0].count) > 0;
  } catch (error) {
    console.error("Error checking attestation existence:", error);
    throw error;
  }
}


export { pool };
