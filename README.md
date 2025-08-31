# Twilight Self Protocol Backend

A Node.js backend server for verifying Self Protocol identity proofs in the Twilight Relayer ecosystem. This server provides a verification endpoint for Self Protocol's identity verification system.

## Quick Start

1. Install dependencies:
   ```bash
   npm install
   ```

2. Create `.env` file:
   ```env
   PORT=3001
   SELF_SCOPE=twilight-relayer-passport
   SELF_PUBLIC_ENDPOINT=http://localhost:3001
   SELF_CALLBACK_URL=http://localhost:3001/api/verify
   SELF_MOCK_MODE=true
   CORS_ORIGINS=http://localhost:3000,http://localhost:5173
   ```

3. Setup Database:
   install psql and run the database.sql file to initialize the DB.

4. Start server:
   ```bash
   npm start
   ```

## Environment Variables

Required:
- `SELF_SCOPE` - Your Self Protocol scope
- `SELF_PUBLIC_ENDPOINT` - Public endpoint where server is accessible
- `SELF_CALLBACK_URL` - Callback URL for Self Protocol verification

Optional:
- `PORT` - Server port (default: 3001)
- `SELF_MOCK_MODE` - Enable mock mode for testing
- `CORS_ORIGINS` - Comma-separated list of allowed origins

## API Endpoints

### Health Check
```http
GET /health
```

### Verify Identity
```http
POST /api/verify
Content-Type: application/json

{
  "attestationId": "string",
  "proof": "object",
  "publicSignals": "array",
  "userContextData": "object"
}
```

## Development

Run with hot reload:
```bash
npm run dev
```

## Project Structure

```
twilight-self-backend/
├── server.mjs          # Main server file
├── package.json        # Dependencies and scripts
├── .env               # Environment configuration
└── README.md          # Documentation
```

## License

MIT License - see [LICENSE](LICENSE) file
