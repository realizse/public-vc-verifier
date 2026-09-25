/**
 * Core verification logic for W3C Verifiable Credentials with
 * Ed25519Signature2020 proofs.
 */
import { extractErrorMessage, parseResponseBody } from "./response-utils.ts";
import { getCredentialIssuerId } from "./credential-issuer.ts";

// Re-exported so the verifier stays the one place tests reach for it.
export { getCredentialIssuerId };
import {
  Ed25519Signature2020,
  suiteContext,
} from "@digitalbazaar/ed25519-signature-2020";
import jsigs from "jsonld-signatures";

export const PROGRESS_STEPS = {
  START: 10,
  CHECK_PROOF: 25,
  SETUP_SUITE: 80,
  VERIFY: 95,
} as const;

export type ProgressCallback = (progress: number, message: string) => void;

export interface VerificationResult {
  verified: boolean;
  error?: string | Error;
  errorType?: "TIMEOUT" | "SAFE_MODE" | "ISSUER_MISMATCH" | "ISSUER_UNRESOLVED";
  details?: unknown;
}

export interface CredentialProof {
  type: string;
  verificationMethod: string;
  created?: string;
  proofPurpose?: string;
  proofValue?: string;
}

export interface VerifiableCredential {
  "@context"?: unknown;
  id?: string;
  type?: string | string[];
  issuer?: string | { id: string };
  issuanceDate?: string;
  credentialSubject?: unknown;
  proof?: CredentialProof;
}

interface DocumentLoaderResult {
  contextUrl: string | null;
  document: unknown;
  documentUrl: string;
}

const VERIFICATION_TIMEOUT_MS = 10_000;
const ED25519_2020_CONTEXT_URL = suiteContext.constants.CONTEXT_URL;

/*
 * The suite context, served from the installed package instead of the wire.
 *
 * The context document decides canonicalization — what the signature actually
 * covers — and w3id.org was fetched on EVERY verification: a retired or
 * unreachable URL would make every previously-issued credential unverifiable,
 * permanently. The bundled copy is the canonical published document — the lockfile pins the
 * package tarball by integrity hash, and the copy was verified byte-identical
 * to the live w3id.org document on 2026-08-13 — so serving it locally changes
 * no verification result. DID documents and template contexts deliberately stay remote:
 * caching a DID document hides key revocation — the re-request behavior
 * `credential-verifier.test.ts` pins — and the template hosts are not ours to
 * inventory from here (queue row 49 withholds that allowlist).
 */
const LOCAL_CONTEXT_DOCUMENTS: ReadonlyMap<string, unknown> = new Map(
  suiteContext.contexts
);
/*
 * The context a DID document must declare first for its plain `assertionMethod`
 * property to carry its ordinary meaning. Mirrors the condition `jsonld-signatures`
 * itself uses to decide it can skip framing.
 */
const DID_CONTEXT_V1_URL = "https://www.w3.org/ns/did/v1";

/*
 * The contexts an issuer document may declare BESIDE the DID context.
 *
 * Reading `assertionMethod` as a plain property is only sound while every
 * context in force defines it the way the DID context does. Requiring URL
 * strings is not enough — a URL can point at a context that redefines the term,
 * and this code never fetches it, so the document would read as authorizing
 * while meaning something else. These are the contexts observed on the live
 * issuer registries plus their near neighbours; none touches `assertionMethod`.
 * A legitimate issuer using something else is refused visibly, as unreadable,
 * which is the safe direction and a one-line fix when it happens.
 */
const ACCEPTED_ISSUER_CONTEXT_URLS: ReadonlySet<string> = new Set([
  "https://w3id.org/security/multikey/v1",
  "https://w3id.org/security/suites/ed25519-2020/v1",
  "https://w3id.org/security/suites/ed25519-2018/v1",
  "https://w3id.org/security/suites/jws-2020/v1",
  "https://w3id.org/security/suites/x25519-2020/v1",
]);
const DID_VERIFICATION_RELATIONSHIPS = [
  "verificationMethod",
  "assertionMethod",
] as const;

export async function runWithVerificationTimeout<T>(
  verification: () => Promise<T>,
  timeoutMs = VERIFICATION_TIMEOUT_MS
): Promise<T> {
  let timeoutId: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timeoutId = setTimeout(
      () => reject(new Error("Verification timeout after 10 seconds")),
      timeoutMs
    );
  });

  try {
    return await Promise.race([verification(), timeout]);
  } finally {
    if (timeoutId !== undefined) {
      clearTimeout(timeoutId);
    }
  }
}

function safeDecodeURIComponent(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

export function didWebToHttpsUrls(didWeb: string): string[] {
  const did = String(didWeb).split("#")[0];

  if (!did.startsWith("did:web:")) {
    throw new Error(`Invalid did:web identifier: ${didWeb}`);
  }

  const didWithoutPrefix = did.slice("did:web:".length);
  const rawParts = didWithoutPrefix.split(":");
  const host = safeDecodeURIComponent(rawParts[0]);
  const path = rawParts.slice(1).map(safeDecodeURIComponent);

  if (!host) {
    throw new Error(`Invalid did:web identifier: ${didWeb}`);
  }

  // Validate host using URL constructor
  let baseUrl: URL;
  try {
    baseUrl = new URL(`https://${host}`);
  } catch {
    throw new Error(`Invalid did:web identifier: ${didWeb}`);
  }

  // Reject URLs with embedded credentials
  if (baseUrl.username || baseUrl.password) {
    throw new Error(`Invalid did:web identifier: ${didWeb}`);
  }

  // Reject URLs with unexpected components
  if (baseUrl.pathname !== "/" || baseUrl.search || baseUrl.hash) {
    throw new Error(`Invalid did:web identifier: ${didWeb}`);
  }

  const didDocumentUrl = new URL(baseUrl.origin);

  if (path.length === 0) {
    didDocumentUrl.pathname = "/.well-known/did.json";
    return [didDocumentUrl.toString()];
  }

  // Validate path segments
  for (const segment of path) {
    if (!segment) {
      throw new Error(`Invalid did:web identifier: ${didWeb}`);
    }
    // Reject path traversal attempts
    if (segment === "." || segment === "..") {
      throw new Error(`Invalid did:web identifier: ${didWeb}`);
    }
    // Reject dangerous characters
    if (
      segment.includes("/") ||
      segment.includes("\\") ||
      segment.includes("?") ||
      segment.includes("#")
    ) {
      throw new Error(`Invalid did:web identifier: ${didWeb}`);
    }
  }

  didDocumentUrl.pathname = `/${path.map(encodeURIComponent).join("/")}/did.json`;
  return [didDocumentUrl.toString()];
}

/**
 * A response that arrived and could not be read as a document. Kept apart from a
 * fetch that failed, because the two call for different explanations: one is a
 * network problem, the other is the host's problem, and only one of them is
 * cured by trying again.
 */
export class DocumentUnreadableError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DocumentUnreadableError";
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

export function dereferenceVerificationMethod(
  didDocument: unknown,
  verificationMethod: string
): Record<string, unknown> {
  if (!isRecord(didDocument)) {
    throw new Error("Resolved DID document is empty or malformed");
  }

  const fragmentIndex = verificationMethod.indexOf("#");
  if (fragmentIndex === -1 || fragmentIndex === verificationMethod.length - 1) {
    throw new Error(
      `Verification method must identify a DID document fragment: ${verificationMethod}`
    );
  }

  const relativeId = verificationMethod.slice(fragmentIndex);
  for (const relationship of DID_VERIFICATION_RELATIONSHIPS) {
    const methods = didDocument[relationship];
    if (!Array.isArray(methods)) {
      continue;
    }

    const method = methods.find(
      (candidate) =>
        isRecord(candidate) &&
        (candidate.id === verificationMethod || candidate.id === relativeId)
    );
    if (isRecord(method)) {
      if (method.type !== "Ed25519VerificationKey2020") {
        throw new Error(
          `Unsupported verification method type: ${String(method.type)}`
        );
      }

      return {
        ...method,
        "@context": ED25519_2020_CONTEXT_URL,
      };
    }
  }

  throw new Error(
    `Verification method ${verificationMethod} not found in DID document`
  );
}

// Document loader for JSON-LD contexts and DID documents
export async function loadUrlDocument(
  url: string | { id?: string }
): Promise<DocumentLoaderResult> {
  if (typeof url !== "string") {
    return {
      contextUrl: null,
      document: url,
      documentUrl: (url as { id?: string }).id || "",
    };
  }

  const isHttps = /^https:\/\//i.test(url);
  const isDidWeb = url.startsWith("did:web:");

  if (!isHttps && !isDidWeb) {
    throw new Error(
      `Unsupported document URL: ${url}. Only https:// and did:web: are supported.`
    );
  }

  const requestUrl = isDidWeb ? didWebToHttpsUrls(url)[0] : url;
  let response: Response;

  try {
    response = await fetch(requestUrl);
  } catch (error) {
    const message =
      error && typeof error === "object" && "message" in error
        ? (error as Error).message
        : String(error);
    const hint = isDidWeb ? " (CORS or network error)" : "";
    const kind = isDidWeb ? "DID document" : "remote document";
    throw new Error(
      `Failed to fetch ${kind}${hint}: ${requestUrl}. ${message}`
    );
  }

  const body = await parseResponseBody(response);
  if (!response.ok) {
    const message = extractErrorMessage(body);
    throw new Error(
      `Failed to load document (${response.status} ${response.statusText})${
        message ? `: ${message}` : ""
      }: ${requestUrl}`
    );
  }

  if (body.json === null) {
    throw new DocumentUnreadableError(
      `Document response was not valid JSON: ${requestUrl}`
    );
  }

  const document =
    isDidWeb && url.includes("#")
      ? dereferenceVerificationMethod(body.json, url)
      : body.json;
  return {
    contextUrl: null,
    document,
    documentUrl: isDidWeb && url.includes("#") ? url : requestUrl,
  };
}

/**
 * The loader `jsigs.verify` gets: locally-bundled suite contexts first, the
 * network loader for everything else. A separate function rather than a branch
 * inside `loadUrlDocument`, so the network loader's own contract — and the
 * test that pins its no-cache re-request behavior — stays exactly what it was.
 */
export async function loadDocumentWithLocalContexts(
  url: string | { id?: string }
): Promise<DocumentLoaderResult> {
  if (typeof url === "string" && LOCAL_CONTEXT_DOCUMENTS.has(url)) {
    return {
      contextUrl: null,
      document: LOCAL_CONTEXT_DOCUMENTS.get(url),
      documentUrl: url,
    };
  }
  return loadUrlDocument(url);
}

/**
 * The DID whose document we actually fetched to get the signing key.
 *
 * `loadUrlDocument` turns `proof.verificationMethod` into an https URL through
 * `didWebToHttpsUrls`, so the part before the fragment names the host that
 * supplied the key. That makes it the one anchor an attacker cannot restate:
 * a DID document can lie about its own `id` and a verification method can lie
 * about its `controller`, but neither changes where the key was served from.
 * A method with no DID part (a relative `#key-1`) yields null and fails closed.
 */
function getVerificationMethodDid(verificationMethod: unknown): string | null {
  if (typeof verificationMethod !== "string") return null;
  const did = verificationMethod.trim().split("#")[0];
  return did || null;
}

/**
 * A loader that answers every question about the ISSUER from one snapshot.
 *
 * The issuer's document is needed twice over: once to ask whether the issuer
 * authorized this key, and once to get the key itself. Fetched twice, those two
 * questions can be answered by two different documents — and a host that served
 * an authorizing document first and a different key second would have a
 * credential accepted under a key the authorizing document never listed.
 * Reproduced before this existed. An ordinary key rotation landing between the
 * two fetches has the same split, with the answer decided by timing.
 *
 * One fetch, one snapshot, both answers. Safe to serve the key from it because
 * the binding has already required the key's DID to be the issuer's, so the key
 * must come from this document or from nowhere. Everything else — the suite
 * context, anything the credential's own `@context` names — still goes to the
 * ordinary loader.
 */
function createIssuerScopedDocumentLoader(
  issuerId: string,
  issuerDocument: Record<string, unknown>
): typeof loadDocumentWithLocalContexts {
  return async (url: string | { id?: string }) => {
    const requested = typeof url === "string" ? url : (url?.id ?? "");
    if (requested === issuerId) {
      return {
        contextUrl: null,
        document: issuerDocument,
        documentUrl: requested,
      };
    }
    if (
      requested.startsWith(`${issuerId}#`) &&
      getVerificationMethodDid(requested) === issuerId
    ) {
      return {
        contextUrl: null,
        document: dereferenceVerificationMethod(issuerDocument, requested),
        documentUrl: requested,
      };
    }
    return loadDocumentWithLocalContexts(url);
  };
}

/**
 * Ties a signature to the party the credential names, in two parts.
 *
 * `jsigs.verify` proves the signature is real and that the key is authorized for
 * assertions by ITS OWN declared controller. It never looks at
 * `credential.issuer`, so on its own it answers "someone signed this" and not
 * "this issuer signed this" — a credential signed with an attacker's key while
 * naming a trusted issuer verified cleanly before this check existed.
 *
 * Part one, here: the DID of `proof.verificationMethod` must be the issuer.
 * `loadUrlDocument` turns that value into an https URL through
 * `didWebToHttpsUrls` and dereferences the fragment inside whatever it fetches,
 * so this requires the key to have been published in the issuer's own document.
 * It is what refuses a document that lies about its own `id` — the library keeps
 * the controller document it loaded without checking that `id` against the DID
 * it asked for — and a key published under a relative id, where the dereferenced
 * method carries no DID of its own and its `controller` may name anyone.
 *
 * Part two, at the call site: the proof purpose is given the issuer's OWN
 * document as its controller, so the library's assertion check resolves against
 * the issuer rather than against whoever the key names as its controller.
 * Publication is not authorization — DID Core keeps `verificationMethod`
 * separate from the `assertionMethod` relationship — and without this an issuer
 * could publish a key for authentication only, a delegate could authorize it to
 * assert, and the credential would verify as the issuer's. Delegation still
 * works: the issuer lists the key in its own `assertionMethod`, which is what
 * authorizing a delegate means.
 *
 * Both parts rest on the loader deriving its fetch URL from the identifier it is
 * given. A DID method that resolved indirectly would break that link, so adding
 * one means revisiting this function.
 */
function checkIssuerBinding(
  credential: VerifiableCredential,
  issuerId: string
): { bound: true } | { bound: false; error: string } {
  const signingDid = getVerificationMethodDid(
    credential.proof?.verificationMethod
  );
  if (!signingDid) {
    return {
      bound: false,
      error:
        "Signer unstated: the proof does not identify the key that produced the signature, so it cannot be tied to the issuer.",
    };
  }
  if (signingDid !== issuerId) {
    return {
      bound: false,
      error: `Issuer mismatch: the credential names ${issuerId} as its issuer, but it was signed with a key published by ${signingDid}.`,
    };
  }
  return { bound: true };
}

/**
 * The issuer's own DID document, which the proof purpose is then bound to.
 *
 * A failure here is a refusal, not a pass: an issuer whose document cannot be
 * read cannot be shown to have authorized anything. But it is a DIFFERENT
 * refusal from a mismatch, and a reader is owed the actual cause, so there are
 * three words here and not one. A MISMATCH is a check that failed. UNREACHABLE
 * is a check that could not be made — the host is down, or refuses a browser's
 * cross-origin request — and saying the credential is not the issuer's would
 * accuse a genuine record. UNREADABLE is a document that arrived and cannot
 * serve as that issuer's record of its own keys, which is the issuer's problem
 * to fix rather than something waiting will cure.
 */
async function loadIssuerControllerDocument(
  issuerId: string
): Promise<{ document: Record<string, unknown> } | { error: string }> {
  try {
    const loaded = await loadDocumentWithLocalContexts(issuerId);
    if (!isRecord(loaded.document)) {
      return {
        error: `Issuer unreadable: the document at ${issuerId} is not a DID document, so the issuer's authorization of the signing key could not be checked.`,
      };
    }

    /*
     * The document has to actually BE the issuer's. did:web requires a resolved
     * document to carry the DID it was asked for, and nothing else here checks
     * it: without this, a document naming someone else — or naming nobody —
     * was accepted as the issuer's word about its own keys.
     */
    if (loaded.document.id !== issuerId) {
      return {
        error: `Issuer unreadable: the document at ${issuerId} identifies itself as ${
          typeof loaded.document.id === "string"
            ? loaded.document.id
            : "nothing"
        }, so it is not that issuer's record of its own keys.`,
      };
    }

    /*
     * And it has to MEAN what the authorization check reads it to mean. Handing
     * the purpose a controller skips the library's JSON-LD framing entirely, so
     * `assertionMethod` is then read as a plain property — which a document whose
     * own context redefines that term to mean something weaker (authentication,
     * say) would exploit. Checking only the FIRST entry is not enough: JSON-LD
     * applies a context array in order, so a later inline object redefines the
     * term the first entry defined, and a later `null` discards it entirely.
     * Requiring plain URL strings is still not enough, because a URL can name a
     * context that redefines the term and this code never fetches it. So the
     * entries after the DID context must be ones known not to touch it. That is
     * stricter than the condition the library uses to decide it can skip framing
     * — deliberately, because the library still frames the documents it is
     * unsure about and we no longer do.
     */
    const context = loaded.document["@context"];
    const declaresPlainDidContext =
      context === DID_CONTEXT_V1_URL ||
      (Array.isArray(context) &&
        context[0] === DID_CONTEXT_V1_URL &&
        context
          .slice(1)
          .every(
            (entry) =>
              typeof entry === "string" &&
              ACCEPTED_ISSUER_CONTEXT_URLS.has(entry)
          ));
    if (!declaresPlainDidContext) {
      return {
        error: `Issuer unreadable: the document at ${issuerId} is not a DID document in the expected form, so what it authorizes could not be read reliably.`,
      };
    }

    return { document: loaded.document };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (error instanceof DocumentUnreadableError) {
      // The host answered; what it sent cannot be read as a document. Saying it
      // could not be reached would send the reader to retry a network that is fine.
      return {
        error: `Issuer unreadable: ${issuerId} answered, but its response could not be read as a DID document, so the issuer's authorization of the signing key could not be checked. ${message}`,
      };
    }
    return {
      error: `Issuer unreachable: ${issuerId} could not be reached, so its authorization of the signing key could not be checked. ${message}`,
    };
  }
}

// Main verification function
export async function verifyCredentialSignature(
  credential: VerifiableCredential,
  progressCallback: ProgressCallback | null = null
): Promise<VerificationResult> {
  try {
    if (!credential || !credential.proof) {
      return {
        verified: false,
        error: "Invalid credential structure: missing proof",
      };
    }

    if (progressCallback)
      progressCallback(PROGRESS_STEPS.START, "Starting verification");

    const { proof } = credential;

    if (proof.type !== "Ed25519Signature2020") {
      return {
        verified: false,
        error: `Unsupported proof type: ${proof.type}. Only Ed25519Signature2020 is supported.`,
      };
    }

    if (progressCallback)
      progressCallback(
        PROGRESS_STEPS.CHECK_PROOF,
        `Checking proof format: ${proof.type}`
      );

    if (progressCallback)
      progressCallback(
        PROGRESS_STEPS.SETUP_SUITE,
        "Setting up verification suite"
      );
    const suite = new Ed25519Signature2020();

    if (progressCallback)
      progressCallback(PROGRESS_STEPS.VERIFY, "Verifying signature");

    /*
     * A real signature is only half the question. `jsigs.verify` never reads
     * `credential.issuer`, so the credential must be tied to the party it names
     * before this function may report success — otherwise the modal shows a
     * success state beside an issuer nobody checked, which
     * `docs/design/domains/passports.md` forbids. The binding is settled first,
     * so a credential that could never be the issuer's is refused without a
     * signature check and without the fetches one would cost.
     */
    const issuerId = getCredentialIssuerId(credential.issuer);
    if (!issuerId) {
      return {
        verified: false,
        error:
          "Issuer unstated: the credential does not name an issuer, so its signature cannot be tied to anyone.",
        errorType: "ISSUER_MISMATCH",
      };
    }

    const binding = checkIssuerBinding(credential, issuerId);
    if (!binding.bound) {
      return {
        verified: false,
        error: binding.error,
        errorType: "ISSUER_MISMATCH",
      };
    }

    try {
      /*
       * Resolving the issuer and verifying share ONE timeout budget. Both reach
       * the network, and a fetch outside the budget is a fetch that can hang the
       * modal at 95% with nothing to report — which is what an issuer host that
       * never answers would otherwise do.
       */
      const outcome = await runWithVerificationTimeout(async () => {
        const issuerDocument = await loadIssuerControllerDocument(issuerId);
        if ("error" in issuerDocument) {
          return { refusal: issuerDocument.error } as const;
        }
        const verification = (await jsigs.verify(credential, {
          suite,
          // Bound to the ISSUER's document, so the assertion check asks whether
          // the ISSUER authorized this key — not whoever the key names as its
          // controller. Left unset, the library asks the latter.
          purpose: new jsigs.purposes.AssertionProofPurpose({
            controller: issuerDocument.document,
          }),
          // The same snapshot answers for the key, so the document that
          // authorizes and the document that supplies cannot be two documents.
          documentLoader: createIssuerScopedDocumentLoader(
            issuerId,
            issuerDocument.document
          ),
        })) as VerificationResult;
        return { verification } as const;
      });

      if ("refusal" in outcome) {
        return {
          verified: false,
          error: outcome.refusal,
          errorType: "ISSUER_UNRESOLVED",
        };
      }

      return outcome.verification;
    } catch (verifyError) {
      if (
        verifyError instanceof Error &&
        verifyError.message.includes("timeout")
      ) {
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
    const err = error as Error & {
      name?: string;
      details?: { event?: { code?: string; message?: string } };
    };

    if (
      err.name === "jsonld.ValidationError" &&
      err.message?.includes("Safe mode")
    ) {
      const event = err.details?.event;
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
      error: err.message || String(error),
    };
  }
}
