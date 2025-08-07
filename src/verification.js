/**
 * Verification Logic for W3C Verifiable Credentials
 *
 * This file contains the core verification logic for validating
 * W3C Verifiable Credentials with Ed25519Signature2018 proofs.
 *
 * Libraries used:
 * - jsonld: For JSON-LD processing
 * - jsonld-signatures (jsigs): For cryptographic signature verification
 * - @digitalbazaar/ed25519-verification-key-2018: For Ed25519 key handling
 * - @digitalbazaar/ed25519-signature-2018: For Ed25519 signature verification
 *
 * The verification process:
 * 1. Parse the credential and extract the proof
 * 2. Resolve the DID to get the public key
 * 3. Create a verification key from the public key
 * 4. Set up the verification suite with the key
 * 5. Verify the cryptographic signature
 */

import jsonld from "jsonld";
import jsigs from "jsonld-signatures";
import { Ed25519VerificationKey2018 } from "@digitalbazaar/ed25519-verification-key-2018";
import { Ed25519Signature2018 } from "@digitalbazaar/ed25519-signature-2018";

// Progress step percentages for UI updates
export const PROGRESS_STEPS = {
  START: 10,
  CHECK_PROOF: 25,
  RESOLVE_DID: 50,
  CREATE_KEY: 65,
  SETUP_SUITE: 80,
  VERIFY: 100,
};

// Cache for loaded documents to avoid redundant network requests
const documentCache = new Map();

// Predefined contexts to avoid CORS issues
const CONTEXTS = {
  W3C_CREDENTIALS_V1: {
    "@version": 1.1,
    id: "@id",
    type: "@type",
    VerifiableCredential: {
      "@id": "https://www.w3.org/2018/credentials#VerifiableCredential",
      "@context": {
        "@version": 1.1,
        id: "@id",
        type: "@type",
        credentialSubject: {
          "@id": "https://www.w3.org/2018/credentials#credentialSubject",
        },
        issuer: {
          "@id": "https://www.w3.org/2018/credentials#issuer",
        },
        issuanceDate: {
          "@id": "https://www.w3.org/2018/credentials#issuanceDate",
          "@type": "http://www.w3.org/2001/XMLSchema#dateTime",
        },
        proof: {
          "@id": "https://w3id.org/security#proof",
          "@container": "@graph",
        },
      },
    },
  },
  W3C_SECURITY: {
    id: "@id",
    type: "@type",
    dc: "http://purl.org/dc/terms/",
    sec: "https://w3id.org/security#",
    xsd: "http://www.w3.org/2001/XMLSchema#",
    Ed25519Signature2018: "sec:Ed25519Signature2018",
    Ed25519VerificationKey2018: "sec:Ed25519VerificationKey2018",
    assertionMethod: {
      "@id": "sec:assertionMethod",
      "@type": "@id",
      "@container": "@set",
    },
    authentication: {
      "@id": "sec:authentication",
      "@type": "@id",
      "@container": "@set",
    },
    created: { "@id": "dc:created", "@type": "xsd:dateTime" },
    creator: { "@id": "dc:creator", "@type": "@id" },
    domain: "sec:domain",
    expires: { "@id": "sec:expiration", "@type": "xsd:dateTime" },
    jws: "sec:jws",
    nonce: "sec:nonce",
    proof: {
      "@id": "sec:proof",
      "@type": "@id",
      "@container": "@graph",
    },
    proofPurpose: { "@id": "sec:proofPurpose", "@type": "@vocab" },
    proofValue: "sec:proofValue",
    publicKey: { "@id": "sec:publicKey", "@type": "@id" },
    publicKeyBase58: "sec:publicKeyBase58",
    publicKeyPem: "sec:publicKeyPem",
    challenge: "sec:challenge",
    controller: { "@id": "sec:controller", "@type": "@id" },
    verificationMethod: {
      "@id": "sec:verificationMethod",
      "@type": "@id",
    },
  },
  FALLBACK: {
    "@vocab": "https://example.org/undefined#",
  },
};

/**
 * Custom document loader that handles JSON-LD contexts and DID documents
 * Caches results to improve performance and reduce network requests
 *
 * @param {string} url - The URL to load
 * @returns {Promise<Object>} The loaded document with contextUrl and document properties
 */
export async function loadUrlDocument(url) {
  // Handle non-string URLs (already loaded documents)
  if (typeof url !== "string") {
    return {
      contextUrl: null,
      document: url,
      documentUrl: url.id || "",
    };
  }

  // Check cache first
  if (documentCache.has(url)) {
    return documentCache.get(url);
  }

  try {
    // For URNs and non-web DIDs, return the URL as the document ID
    // This prevents null document errors during verification
    if (
      url.startsWith("urn:") ||
      (url.startsWith("did:") && !url.startsWith("did:web:"))
    ) {
      const result = {
        contextUrl: null,
        document: { "@id": url }, // Return minimal document instead of null
        documentUrl: url,
      };
      documentCache.set(url, result);
      return result;
    }

    // Handle did:web URLs by converting to HTTPS
    if (url.startsWith("did:web:")) {
      // Convert to HTTPS and fetch - ensure proper URL format
      const didParts = url.replace("did:web:", "");
      const httpsUrl = `https://${didParts.replace(/:/g, "/")}/did.json`;
      try {
        const response = await fetch(httpsUrl);
        if (!response.ok) {
          throw new Error(
            `Failed to load DID document: ${response.statusText}`
          );
        }
        const document = await response.json();
        const result = {
          contextUrl: null,
          document: document,
          documentUrl: url,
        };
        documentCache.set(url, result);
        return result;
      } catch (error) {
        // Return minimal document on error (likely CORS)
        const result = {
          contextUrl: null,
          document: { "@id": url },
          documentUrl: url,
        };
        documentCache.set(url, result);
        return result;
      }
    }

    const response = await fetch(url);
    if (!response.ok) {
      throw new Error(`Failed to load document: ${response.statusText}`);
    }

    const document = await response.json();
    const result = {
      contextUrl: null,
      document: document,
      documentUrl: url,
    };

    // Cache the result
    documentCache.set(url, result);
    return result;
  } catch (error) {
    // For known contexts, return inline versions to avoid CORS issues
    if (url === "https://www.w3.org/2018/credentials/v1") {
      const result = {
        contextUrl: null,
        document: { "@context": CONTEXTS.W3C_CREDENTIALS_V1 },
        documentUrl: url,
      };
      documentCache.set(url, result);
      return result;
    }

    // Handle W3C security context
    if (
      url === "https://w3id.org/security/v2" ||
      url === "https://w3id.org/security/v1"
    ) {
      const result = {
        contextUrl: null,
        document: { "@context": CONTEXTS.W3C_SECURITY },
        documentUrl: url,
      };
      documentCache.set(url, result);
      return result;
    }

    // For any failed URL, return a simple valid response to prevent hanging
    const result = {
      contextUrl: null,
      document: { "@context": CONTEXTS.FALLBACK },
      documentUrl: url,
    };
    documentCache.set(url, result);
    return result;
  }
}

/**
 * Extract the public key from a DID document for a given verification method
 * Handles both embedded keys and referenced keys
 *
 * @param {string} verificationMethod - The verification method ID from the proof
 * @param {Function} progressCallback - Optional callback for progress updates
 * @returns {Promise<Object|null>} The public key object or null if not found
 */
export async function getPublicKeyFromDID(
  verificationMethod,
  progressCallback
) {
  try {
    if (progressCallback) {
      progressCallback(
        PROGRESS_STEPS.RESOLVE_DID,
        `Resolving verification method: ${verificationMethod}`
      );
    }

    // Extract the DID from the verification method
    const did = verificationMethod.split("#")[0];

    // Resolve the DID document using the document loader
    const response = await loadUrlDocument(did);
    const didDocument = response.document;

    if (!didDocument || didDocument["@id"] === did) {
      // Document couldn't be loaded (likely CORS)
      throw new Error("Failed to fetch DID document");
    }

    // Find the specific verification method in the document
    let publicKey = null;

    // Check in various possible locations
    const possibleArrays = [
      didDocument.verificationMethod,
      didDocument.authentication,
      didDocument.assertionMethod,
      didDocument.publicKey, // Legacy location
    ];

    for (const array of possibleArrays) {
      if (array && Array.isArray(array)) {
        const key = array.find(
          (method) =>
            method.id === verificationMethod ||
            method.id === `#${verificationMethod.split("#")[1]}`
        );
        if (key) {
          publicKey = key;
          break;
        }
      }
    }

    if (!publicKey) {
      throw new Error(
        `Verification method ${verificationMethod} not found in DID document`
      );
    }

    return publicKey;
  } catch (error) {
    // Check if it's a CORS error
    if (error.message.includes("Failed to fetch")) {
      return null;
    }
    throw error;
  }
}

/**
 * Main function to verify a W3C Verifiable Credential
 * @param {Object} credential - The credential object to verify
 * @param {Function} progressCallback - Optional callback for progress updates
 * @returns {Promise<Object>} Verification result object
 */
export async function verifyCredentialSignature(
  credential,
  progressCallback = null
) {
  try {
    // Validate structure
    if (!credential || !credential.proof) {
      return {
        verified: false,
        error: "Invalid credential structure: missing proof",
      };
    }

    if (progressCallback)
      progressCallback(PROGRESS_STEPS.START, "Starting verification");

    const { proof } = credential;

    // Check proof type
    if (proof.type !== "Ed25519Signature2018") {
      return {
        verified: false,
        error: `Unsupported proof type: ${proof.type}. Only Ed25519Signature2018 is supported.`,
      };
    }

    if (progressCallback)
      progressCallback(
        PROGRESS_STEPS.CHECK_PROOF,
        `Checking proof format: ${proof.type}`
      );

    // Resolve the DID
    const publicKey = await getPublicKeyFromDID(
      proof.verificationMethod,
      progressCallback
    );

    if (!publicKey) {
      return {
        verified: false,
        error: "Could not resolve verification method",
        errors: ["CORS"],
      };
    }

    // Create verification key
    if (progressCallback)
      progressCallback(PROGRESS_STEPS.CREATE_KEY, "Creating verification key");

    const verificationKey = new Ed25519VerificationKey2018(publicKey);

    // Set up verification suite
    if (progressCallback)
      progressCallback(
        PROGRESS_STEPS.SETUP_SUITE,
        "Setting up verification suite"
      );

    const suite = new Ed25519Signature2018({
      key: verificationKey,
      verificationMethod: publicKey.id,
    });

    // Perform verification
    if (progressCallback)
      progressCallback(PROGRESS_STEPS.VERIFY, "Verifying signature");

    try {
      // Create a timeout promise
      const timeoutPromise = new Promise((_, reject) => {
        setTimeout(
          () => reject(new Error("Verification timeout after 10 seconds")),
          10000
        );
      });

      // Race between verification and timeout
      const result = await Promise.race([
        jsigs.verify(credential, {
          suite,
          purpose: new jsigs.purposes.AssertionProofPurpose(),
          documentLoader: loadUrlDocument,
        }),
        timeoutPromise,
      ]);

      return result;
    } catch (verifyError) {
      // Check if it's a timeout
      if (verifyError.message.includes("timeout")) {
        return {
          verified: false,
          error:
            "Verification timed out. This may be due to network issues or complex credential processing.",
          errorType: "TIMEOUT",
        };
      }

      throw verifyError;
    }
  } catch (error) {
    // Check for specific error types
    if (
      error.name === "jsonld.ValidationError" &&
      error.message.includes("Safe mode")
    ) {
      // For safe mode errors, return a more informative result
      return {
        verified: false,
        error:
          "JSON-LD safe mode validation error. This typically occurs when the credential contains certain URL patterns that trigger browser security restrictions. In a production environment, this verification would be performed server-side.",
        errorType: "SAFE_MODE",
        originalError: error.message,
      };
    }

    return {
      verified: false,
      error: error.message || error,
    };
  }
}
