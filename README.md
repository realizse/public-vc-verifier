# Web-based Verifiable Credential Verifier

A client-side web application for verifying W3C Verifiable Credentials with Ed25519Signature2018 proofs.

## Quick Start

```bash
npm install
npm run dev
```

Open http://localhost:5173 in your browser.

## Libraries Used

The verification logic uses these open-source libraries:

- `jsonld` - JSON-LD processing
- `jsonld-signatures` - Digital signature verification
- `@digitalbazaar/ed25519-verification-key-2018` - Ed25519 key handling
- `@digitalbazaar/ed25519-signature-2018` - Ed25519 signature verification
