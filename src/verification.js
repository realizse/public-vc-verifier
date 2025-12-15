/**
 * Core verification logic for W3C Verifiable Credentials with Ed25519Signature2018 proofs.
 * Uses Digital Bazaar libraries: jsonld-signatures, ed25519-verification-key-2018, ed25519-signature-2018
 */

import jsigs from "jsonld-signatures";
import { Ed25519VerificationKey2018 } from "@digitalbazaar/ed25519-verification-key-2018";
import { Ed25519Signature2018 } from "@digitalbazaar/ed25519-signature-2018";

export const PROGRESS_STEPS = {
  START: 10,
  CHECK_PROOF: 25,
  RESOLVE_DID: 50,
  CREATE_KEY: 65,
  SETUP_SUITE: 80,
  VERIFY: 100,
};

const documentCache = new Map();

function safeDecodeURIComponent(value) {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

export function didWebToHttpsUrls(didWeb) {
  const did = String(didWeb).split("#")[0];
  const didWithoutPrefix = did.replace(/^did:web:/, "");
  const parts = didWithoutPrefix.split(":").map(safeDecodeURIComponent);
  const host = parts[0];
  const path = parts.slice(1);

  if (!host) {
    throw new Error(`Invalid did:web identifier: ${didWeb}`);
  }

  if (path.length === 0) {
    return [`https://${host}/.well-known/did.json`];
  }

  return [`https://${host}/${path.join("/")}/did.json`];
}

// Document loader for JSON-LD contexts and DID documents
export async function loadUrlDocument(url) {
  if (typeof url !== "string") {
    return {
      contextUrl: null,
      document: url,
      documentUrl: url.id || "",
    };
  }

  if (documentCache.has(url)) {
    return documentCache.get(url);
  }

  if (
    url.startsWith("urn:") ||
    (url.startsWith("did:") && !url.startsWith("did:web:"))
  ) {
    throw new Error(
      `Unsupported document URL: ${url}. Only https:// and did:web: are supported.`
    );
  }

  const isDidWeb = url.startsWith("did:web:");
  const requestUrl = isDidWeb ? didWebToHttpsUrls(url)[0] : url;

  try {
    const response = await fetch(requestUrl);
    if (!response.ok) {
      throw new Error(
        `Failed to load document (${response.status} ${response.statusText}): ${requestUrl}`
      );
    }

    const document = await response.json();
    const result = {
      contextUrl: null,
      document: document,
      documentUrl: requestUrl,
    };

    documentCache.set(url, result);
    return result;
  } catch (error) {
    const message =
      error && typeof error === "object" && "message" in error
        ? error.message
        : String(error);
    const hint = isDidWeb
      ? " (CORS or network error)"
      : message.includes("Failed to fetch")
      ? " (possible CORS error)"
      : "";
    const kind = isDidWeb ? "DID document" : "remote document";
    throw new Error(`Failed to fetch ${kind}${hint}: ${requestUrl}. ${message}`);
  }
}

// Extract public key from DID document for a given verification method
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

    const did = verificationMethod.split("#")[0];
    const response = await loadUrlDocument(did);
    const didDocument = response.document;

    if (!didDocument) {
      throw new Error("Resolved DID document is empty");
    }

    let publicKey = null;
    const possibleArrays = [
      didDocument.verificationMethod,
      didDocument.authentication,
      didDocument.assertionMethod,
      didDocument.publicKey,
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
    throw error;
  }
}

// Main verification function
export async function verifyCredentialSignature(
  credential,
  progressCallback = null
) {
  try {
    if (!credential || !credential.proof) {
      return { verified: false, error: "Invalid credential structure: missing proof" };
    }

    if (progressCallback) progressCallback(PROGRESS_STEPS.START, "Starting verification");

    const { proof } = credential;

    if (proof.type !== "Ed25519Signature2018") {
      return { verified: false, error: `Unsupported proof type: ${proof.type}. Only Ed25519Signature2018 is supported.` };
    }

    if (progressCallback) progressCallback(PROGRESS_STEPS.CHECK_PROOF, `Checking proof format: ${proof.type}`);

    const publicKey = await getPublicKeyFromDID(proof.verificationMethod, progressCallback);

    if (progressCallback) progressCallback(PROGRESS_STEPS.CREATE_KEY, "Creating verification key");
    const verificationKey = new Ed25519VerificationKey2018(publicKey);

    if (progressCallback) progressCallback(PROGRESS_STEPS.SETUP_SUITE, "Setting up verification suite");
    const suite = new Ed25519Signature2018({
      key: verificationKey,
      verificationMethod: publicKey.id,
    });

    if (progressCallback) progressCallback(PROGRESS_STEPS.VERIFY, "Verifying signature");

    try {
      const timeoutPromise = new Promise((_, reject) => {
        setTimeout(() => reject(new Error("Verification timeout after 10 seconds")), 10000);
      });

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
      if (verifyError.message.includes("timeout")) {
        return {
          verified: false,
          error: "Verification timed out. This may be due to network issues or complex credential processing.",
          errorType: "TIMEOUT",
        };
      }
      throw verifyError;
    }
  } catch (error) {
    if (
      error.name === "jsonld.ValidationError" &&
      error.message.includes("Safe mode")
    ) {
      const event = error?.details?.event;
      const code = event?.code ? ` (${event.code})` : "";
      const detail = event?.message ? `: ${event.message}` : "";
      return {
        verified: false,
        error: `JSON-LD safe mode validation error${code}${detail}`,
        errorType: "SAFE_MODE",
        details: event,
      };
    }

    return {
      verified: false,
      error: error.message || error,
    };
  }
}
