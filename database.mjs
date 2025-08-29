// database.mjs
import { Pool } from "pg";

// Database configuration
const pool = new Pool({
  user: process.env.DB_USER || "postgres",
  host: process.env.DB_HOST || "localhost",
  database: process.env.DB_NAME || "zkpassport",
  password: process.env.DB_PASSWORD || "postgres",
  port: parseInt(process.env.DB_PORT || "5432", 10),
});

// Save verification data
export async function saveVerification(uniqueIdentifier, address, provider) {
  try {
    const result = await pool.query(
      `INSERT INTO zkpass (address, identifier, provider)
       VALUES ($1, $2, $3)
       RETURNING *`,
      [address, uniqueIdentifier, provider] // address -> $1, uniqueIdentifier -> $2, provider -> $3
    );
    return result.rows[0];
  } catch (error) {
    console.error("Error saving verification:", error);
    throw error;
  }
}

export { pool };
