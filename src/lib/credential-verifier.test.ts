import assert from "node:assert/strict";
import test, { mock } from "node:test";

// The budget `runWithVerificationTimeout` defaults to; kept in step with the module.
const VERIFICATION_TIMEOUT_MS = 10_000;
import {
  Ed25519Signature2020,
  suiteContext,
} from "@digitalbazaar/ed25519-signature-2020";
import { Ed25519VerificationKey2020 } from "@digitalbazaar/ed25519-verification-key-2020";
import jsigs from "jsonld-signatures";
import {
  dereferenceVerificationMethod,
  getCredentialIssuerId,
  loadUrlDocument,
  runWithVerificationTimeout,
  type VerifiableCredential,
  verifyCredentialSignature,
  loadDocumentWithLocalContexts,
} from "./credential-verifier.ts";

const TEST_CONTROLLER = "did:web:issuer.example.test:realizse";
const TEST_DID_DOCUMENT_URL = "https://issuer.example.test/realizse/did.json";
const SUITE_CONTEXT_URL = suiteContext.constants.CONTEXT_URL;
const MULTIKEY_CONTEXT_URL = "https://w3id.org/security/multikey/v1";

type CredentialFixture = {
  credential: VerifiableCredential;
  didDocument: Record<string, unknown>;
};

let fixturePromise: Promise<CredentialFixture> | undefined;

function getCredentialFixture(): Promise<CredentialFixture> {
  fixturePromise ??= createCredentialFixture();
  return fixturePromise;
}

async function createCredentialFixture(): Promise<CredentialFixture> {
  const key = await Ed25519VerificationKey2020.generate({
    seed: new Uint8Array(32).fill(7),
    controller: TEST_CONTROLLER,
  });
  const publicKey = await key.export({ publicKey: true });
  const didDocument = {
    "@context": ["https://www.w3.org/ns/did/v1", MULTIKEY_CONTEXT_URL],
    id: TEST_CONTROLLER,
    verificationMethod: [publicKey],
    assertionMethod: [key.id],
  };
  const documentLoader = async (url: string | { id?: string }) => {
    const documentUrl = typeof url === "string" ? url : (url.id ?? "");
    let document: unknown;

    if (documentUrl === TEST_CONTROLLER) {
      document = didDocument;
    } else if (documentUrl === key.id) {
      document = { "@context": SUITE_CONTEXT_URL, ...publicKey };
    } else if (documentUrl === SUITE_CONTEXT_URL) {
      document = suiteContext.contexts.get(SUITE_CONTEXT_URL);
    } else {
      throw new Error(`Unexpected test document URL: ${documentUrl}`);
    }

    return { contextUrl: null, document, documentUrl };
  };
  /*
   * The fixture carries an `issuer`, as every credential this app receives does
   * — the API declares it a string (`api.yaml`), and the five real credentials
   * read off dev on 2026-09-11 all carry the signing DID there. A credential
   * without one is now refused, so a fixture without one would not be testing
   * the verifier this app runs.
   */
  const unsignedCredential = {
    "@context": [
      {
        credentialSubject:
          "https://www.w3.org/2018/credentials#credentialSubject",
        issuer: "https://www.w3.org/2018/credentials#issuer",
        name: "https://schema.org/name",
      },
      SUITE_CONTEXT_URL,
    ],
    "@id": "urn:uuid:00000000-0000-4000-8000-000000000001",
    "@type": "https://www.w3.org/2018/credentials#VerifiableCredential",
    issuer: TEST_CONTROLLER,
    credentialSubject: {
      "@id": "urn:uuid:00000000-0000-4000-8000-000000000002",
      name: "Current credential",
    },
  };
  const suite = new Ed25519Signature2020({ key });
  suite.date = "2026-07-18T12:00:00Z";
  const credential = (await jsigs.sign(unsignedCredential, {
    suite,
    purpose: new jsigs.purposes.AssertionProofPurpose(),
    documentLoader,
  })) as VerifiableCredential;

  return { credential, didDocument };
}

async function withCredentialDocuments<T>(
  didDocument: Record<string, unknown>,
  run: () => Promise<T>
): Promise<T> {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (input) => {
    const url = String(input);
    if (url === TEST_DID_DOCUMENT_URL) {
      return Response.json(didDocument);
    }
    if (url === SUITE_CONTEXT_URL) {
      // The wrapper serves this locally; a roundtrip that fetches it means the
      // wrapper was bypassed or removed.
      throw new Error(
        "the suite context must not be fetched during a roundtrip"
      );
    }
    return Response.json({ message: "Not found" }, { status: 404 });
  }) as typeof fetch;

  try {
    return await run();
  } finally {
    globalThis.fetch = originalFetch;
  }
}

async function countClearTimeoutCalls(
  run: () => Promise<void>
): Promise<number> {
  const originalClearTimeout = globalThis.clearTimeout;
  let clearCalls = 0;

  globalThis.clearTimeout = ((timeoutId) => {
    clearCalls += 1;
    originalClearTimeout(timeoutId);
  }) as typeof clearTimeout;

  try {
    await run();
    return clearCalls;
  } finally {
    globalThis.clearTimeout = originalClearTimeout;
  }
}

test("remote contexts and DID documents are re-requested for HTTP revalidation", async () => {
  const originalFetch = globalThis.fetch;
  const requestedUrls: string[] = [];
  let version = 0;

  globalThis.fetch = (async (input) => {
    requestedUrls.push(String(input));
    version += 1;
    return new Response(JSON.stringify({ version }), {
      status: 200,
      headers: {
        "Cache-Control": "max-age=0",
        "Content-Type": "application/json",
        ETag: `"version-${version}"`,
      },
    });
  }) as typeof fetch;

  try {
    const contextUrl = "https://example.test/context.jsonld";
    const did = "did:web:example.test:issuers:one";
    const didUrl = "https://example.test/issuers/one/did.json";
    const firstContext = await loadUrlDocument(contextUrl);
    const secondContext = await loadUrlDocument(contextUrl);
    const firstDid = await loadUrlDocument(did);
    const secondDid = await loadUrlDocument(did);

    assert.deepEqual(requestedUrls, [contextUrl, contextUrl, didUrl, didUrl]);
    assert.deepEqual(firstContext.document, { version: 1 });
    assert.deepEqual(secondContext.document, { version: 2 });
    assert.deepEqual(firstDid.document, { version: 3 });
    assert.deepEqual(secondDid.document, { version: 4 });
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("DID verification methods are dereferenced by exact full or relative ID", () => {
  const fullId = `${TEST_CONTROLLER}#key-1`;
  const context = ["https://www.w3.org/ns/did/v1", MULTIKEY_CONTEXT_URL];
  const fullMethod = {
    id: fullId,
    type: "Ed25519VerificationKey2020",
    controller: TEST_CONTROLLER,
    publicKeyMultibase: "z6Mktest",
  };
  const relativeMethod = { ...fullMethod, id: "#key-2" };
  const didDocument = {
    "@context": context,
    verificationMethod: [fullMethod],
    assertionMethod: [relativeMethod],
  };

  assert.deepEqual(dereferenceVerificationMethod(didDocument, fullId), {
    ...fullMethod,
    "@context": SUITE_CONTEXT_URL,
  });
  assert.deepEqual(
    dereferenceVerificationMethod(didDocument, `${TEST_CONTROLLER}#key-2`),
    { ...relativeMethod, "@context": SUITE_CONTEXT_URL }
  );
});

test("DID dereferencing rejects missing and non-2020 verification methods", () => {
  const verificationMethod = `${TEST_CONTROLLER}#key-1`;

  assert.throws(
    () => dereferenceVerificationMethod({}, verificationMethod),
    /not found/
  );
  assert.throws(
    () =>
      dereferenceVerificationMethod(
        {
          verificationMethod: [
            {
              id: verificationMethod,
              type: "Ed25519VerificationKey2018",
            },
          ],
        },
        verificationMethod
      ),
    /Unsupported verification method type: Ed25519VerificationKey2018/
  );
});

test("DID contract failures are not mislabeled as network failures", async () => {
  const originalFetch = globalThis.fetch;
  const verificationMethod = `${TEST_CONTROLLER}#legacy-key`;
  globalThis.fetch = (async () =>
    Response.json({
      verificationMethod: [
        {
          id: verificationMethod,
          type: "Ed25519VerificationKey2018",
        },
      ],
    })) as typeof fetch;

  try {
    await assert.rejects(loadUrlDocument(verificationMethod), (error) => {
      assert.match(
        String(error),
        /Unsupported verification method type: Ed25519VerificationKey2018/
      );
      assert.doesNotMatch(String(error), /CORS|network error/);
      return true;
    });
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("a valid Ed25519Signature2020 credential verifies through DID resolution", async () => {
  const fixture = await getCredentialFixture();
  const progress: number[] = [];
  const result = await withCredentialDocuments(fixture.didDocument, () =>
    verifyCredentialSignature(fixture.credential, (value) => {
      progress.push(value);
    })
  );

  assert.equal(result.verified, true);
  assert.deepEqual(progress, [10, 25, 80, 95]);
});

test("credential tampering invalidates an otherwise valid 2020 signature", async () => {
  const fixture = await getCredentialFixture();
  const tampered = structuredClone(
    fixture.credential
  ) as VerifiableCredential & {
    credentialSubject: { name: string };
  };
  tampered.credentialSubject.name = "Tampered credential";

  const result = await withCredentialDocuments(fixture.didDocument, () =>
    verifyCredentialSignature(tampered)
  );

  assert.equal(result.verified, false);
});

/*
 * Issuer binding. `jsigs.verify` proves a signature is real and that the key is
 * authorized by its own declared controller; it never reads `credential.issuer`.
 * Each case below verified cleanly before the binding existed, and each closes a
 * different way of restating who signed.
 */

const ATTACKER_DID = "did:web:attacker.example.test";
const ATTACKER_DID_DOCUMENT_URL =
  "https://attacker.example.test/.well-known/did.json";

async function createAttackerCredential(options: {
  claimedIssuer: unknown;
  didDocumentId?: string;
  assertionMethodIds?: string[];
  keyController?: string;
  keyId?: string;
  methodOverride?: Record<string, unknown>;
}): Promise<{
  credential: VerifiableCredential;
  didDocument: Record<string, unknown>;
}> {
  const key = await Ed25519VerificationKey2020.generate({
    seed: new Uint8Array(32).fill(9),
    controller: options.keyController ?? ATTACKER_DID,
  });
  if (options.keyId) {
    key.id = options.keyId;
  }
  const publicKey = await key.export({ publicKey: true });
  const didDocument = {
    "@context": ["https://www.w3.org/ns/did/v1", MULTIKEY_CONTEXT_URL],
    id: options.didDocumentId ?? ATTACKER_DID,
    verificationMethod: [{ ...publicKey, ...(options.methodOverride ?? {}) }],
    assertionMethod: options.assertionMethodIds ?? [key.id],
  };
  const documentLoader = async (url: string | { id?: string }) => {
    const documentUrl = typeof url === "string" ? url : (url.id ?? "");
    if (documentUrl === (options.keyController ?? ATTACKER_DID)) {
      return { contextUrl: null, document: didDocument, documentUrl };
    }
    if (documentUrl === key.id) {
      return {
        contextUrl: null,
        document: { "@context": SUITE_CONTEXT_URL, ...publicKey },
        documentUrl,
      };
    }
    if (documentUrl === SUITE_CONTEXT_URL) {
      return {
        contextUrl: null,
        document: suiteContext.contexts.get(SUITE_CONTEXT_URL),
        documentUrl,
      };
    }
    throw new Error(`Unexpected test document URL: ${documentUrl}`);
  };
  const unsigned = {
    "@context": [
      {
        credentialSubject:
          "https://www.w3.org/2018/credentials#credentialSubject",
        issuer: "https://www.w3.org/2018/credentials#issuer",
        name: "https://schema.org/name",
      },
      SUITE_CONTEXT_URL,
    ],
    "@id": "urn:uuid:00000000-0000-4000-8000-0000000000aa",
    "@type": "https://www.w3.org/2018/credentials#VerifiableCredential",
    ...(options.claimedIssuer === undefined
      ? {}
      : { issuer: options.claimedIssuer }),
    credentialSubject: {
      "@id": "urn:uuid:00000000-0000-4000-8000-0000000000bb",
      name: "179D Certification",
    },
  };
  const suite = new Ed25519Signature2020({ key });
  suite.date = "2026-09-11T00:00:00Z";
  const credential = (await jsigs.sign(unsigned, {
    suite,
    purpose: new jsigs.purposes.AssertionProofPurpose(),
    documentLoader,
  })) as VerifiableCredential;

  return { credential, didDocument };
}

async function withAttackerDocuments<T>(
  didDocument: Record<string, unknown>,
  run: () => Promise<T>,
  extraDocuments: Record<string, unknown> = {}
): Promise<T> {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (input) => {
    const url = String(input);
    if (url === ATTACKER_DID_DOCUMENT_URL) {
      return Response.json(didDocument);
    }
    if (url in extraDocuments) {
      return Response.json(extraDocuments[url]);
    }
    return Response.json({ message: "Not found" }, { status: 404 });
  }) as typeof fetch;

  try {
    return await run();
  } finally {
    globalThis.fetch = originalFetch;
  }
}

test("a signature by one party cannot be presented as another party's", async () => {
  const { credential, didDocument } = await createAttackerCredential({
    claimedIssuer: TEST_CONTROLLER,
  });

  const result = await withAttackerDocuments(didDocument, () =>
    verifyCredentialSignature(credential)
  );

  assert.equal(result.verified, false);
  assert.equal(result.errorType, "ISSUER_MISMATCH");
  assert.match(String(result.error), /Issuer mismatch/);
});

test("a credential that names no issuer cannot be tied to one, so it fails", async () => {
  const { credential, didDocument } = await createAttackerCredential({
    claimedIssuer: undefined,
  });

  const result = await withAttackerDocuments(didDocument, () =>
    verifyCredentialSignature(credential)
  );

  assert.equal(result.verified, false);
  assert.equal(result.errorType, "ISSUER_MISMATCH");
});

test("a DID document that lies about its own id does not become the issuer", async () => {
  /*
   * The library keeps the controller document it loaded without checking that
   * the `id` inside matches the DID it asked for, so a document served from the
   * attacker's host can call itself the trusted issuer. The DID that was
   * actually dereferenced is what this credential is bound to.
   */
  const { credential, didDocument } = await createAttackerCredential({
    claimedIssuer: TEST_CONTROLLER,
    didDocumentId: TEST_CONTROLLER,
  });

  const result = await withAttackerDocuments(didDocument, () =>
    verifyCredentialSignature(credential)
  );

  assert.equal(result.verified, false);
  assert.equal(result.errorType, "ISSUER_MISMATCH");
});

test("a key published under a relative id is still bound to the host that served it", async () => {
  /*
   * An issuer that lists its keys by relative id (`#key-1`) leaves nothing in the
   * authorization check that names a host: the attacker serves a key under the
   * same relative id and points its `controller` at the trusted issuer, whose
   * document does list `#key-1`. The library authorizes it, and the key's
   * `controller` equals the named issuer, so only the DID that was actually
   * dereferenced separates the two. Latent rather than live — the issuer this
   * app resolves publishes absolute ids — but it is the reason the binding
   * cannot rest on `controller` alone.
   */
  const { credential, didDocument } = await createAttackerCredential({
    claimedIssuer: TEST_CONTROLLER,
    keyId: `${ATTACKER_DID}#key-1`,
    assertionMethodIds: ["#key-1"],
    methodOverride: { id: "#key-1", controller: TEST_CONTROLLER },
  });
  const trustedDocument = {
    "@context": ["https://www.w3.org/ns/did/v1", MULTIKEY_CONTEXT_URL],
    id: TEST_CONTROLLER,
    assertionMethod: ["#key-1"],
  };

  const result = await withAttackerDocuments(
    didDocument,
    () => verifyCredentialSignature(credential),
    { [TEST_DID_DOCUMENT_URL]: trustedDocument }
  );

  assert.equal(result.verified, false);
  assert.equal(result.errorType, "ISSUER_MISMATCH");
});

test("a key in the issuer's own namespace is accepted even when a delegate controls it", async () => {
  /*
   * Delegation within the issuer's own namespace. The issuer lists the key in its
   * OWN `assertionMethod` — that listing is what authorizing a delegate means —
   * while naming the delegate as the key's controller. Refusing this would be a
   * policy about who may hold a key, not a check on who authorized it.
   *
   * This pins the NARROW arrangement, not delegation in general: a key that lives
   * in the delegate's own document is refused by the DID equality check even when
   * the issuer authorizes it, and so is an issuer that authorizes its own key by
   * relative reference. Neither occurs on the registries this app talks to.
   * Queue row 120 carries the decision about whether to support them.
   */
  const key = await Ed25519VerificationKey2020.generate({
    seed: new Uint8Array(32).fill(3),
    controller: "did:web:delegate.example.test",
  });
  key.id = `${TEST_CONTROLLER}#delegated-key`;
  const publicKey = await key.export({ publicKey: true });
  const issuerDocument = {
    "@context": ["https://www.w3.org/ns/did/v1", MULTIKEY_CONTEXT_URL],
    id: TEST_CONTROLLER,
    verificationMethod: [publicKey],
    assertionMethod: [key.id],
  };
  const delegateDocument = {
    "@context": ["https://www.w3.org/ns/did/v1", MULTIKEY_CONTEXT_URL],
    id: "did:web:delegate.example.test",
    verificationMethod: [publicKey],
    assertionMethod: [key.id],
  };
  const documentLoader = async (url: string | { id?: string }) => {
    const documentUrl = typeof url === "string" ? url : (url.id ?? "");
    if (documentUrl === TEST_CONTROLLER) {
      return { contextUrl: null, document: issuerDocument, documentUrl };
    }
    if (documentUrl === "did:web:delegate.example.test") {
      return { contextUrl: null, document: delegateDocument, documentUrl };
    }
    if (documentUrl === key.id) {
      return {
        contextUrl: null,
        document: { "@context": SUITE_CONTEXT_URL, ...publicKey },
        documentUrl,
      };
    }
    if (documentUrl === SUITE_CONTEXT_URL) {
      return {
        contextUrl: null,
        document: suiteContext.contexts.get(SUITE_CONTEXT_URL),
        documentUrl,
      };
    }
    throw new Error(`Unexpected test document URL: ${documentUrl}`);
  };
  const suite = new Ed25519Signature2020({ key });
  suite.date = "2026-09-11T00:00:00Z";
  const credential = (await jsigs.sign(
    {
      "@context": [
        {
          credentialSubject:
            "https://www.w3.org/2018/credentials#credentialSubject",
          issuer: "https://www.w3.org/2018/credentials#issuer",
          name: "https://schema.org/name",
        },
        SUITE_CONTEXT_URL,
      ],
      "@id": "urn:uuid:00000000-0000-4000-8000-0000000000cc",
      "@type": "https://www.w3.org/2018/credentials#VerifiableCredential",
      issuer: TEST_CONTROLLER,
      credentialSubject: {
        "@id": "urn:uuid:00000000-0000-4000-8000-0000000000dd",
        name: "Delegated signing",
      },
    },
    {
      suite,
      purpose: new jsigs.purposes.AssertionProofPurpose(),
      documentLoader,
    }
  )) as VerifiableCredential;

  const result = await withAttackerDocuments(
    issuerDocument,
    () => verifyCredentialSignature(credential),
    {
      [TEST_DID_DOCUMENT_URL]: issuerDocument,
      "https://delegate.example.test/.well-known/did.json": delegateDocument,
    }
  );

  assert.equal(result.verified, true);
});

test("publishing a key is not the same as authorizing it to issue credentials", async () => {
  /*
   * The counterexample that publication alone cannot answer. The issuer lists the
   * key under `authentication` and authorizes NOTHING for assertions; the
   * delegate authorizes it. Checking only where the key was published accepts
   * this, because the library resolves the key's own controller — the delegate —
   * and finds the authorization there. Binding the proof purpose to the issuer's
   * document is what asks the right party.
   */
  const key = await Ed25519VerificationKey2020.generate({
    seed: new Uint8Array(32).fill(5),
    controller: "did:web:delegate.example.test",
  });
  key.id = `${TEST_CONTROLLER}#delegated-key`;
  const publicKey = await key.export({ publicKey: true });
  const issuerDocument = {
    "@context": ["https://www.w3.org/ns/did/v1", MULTIKEY_CONTEXT_URL],
    id: TEST_CONTROLLER,
    verificationMethod: [publicKey],
    authentication: [key.id],
    assertionMethod: [],
  };
  const delegateDocument = {
    "@context": ["https://www.w3.org/ns/did/v1", MULTIKEY_CONTEXT_URL],
    id: "did:web:delegate.example.test",
    verificationMethod: [publicKey],
    assertionMethod: [key.id],
  };
  const documentLoader = async (url: string | { id?: string }) => {
    const documentUrl = typeof url === "string" ? url : (url.id ?? "");
    if (documentUrl === TEST_CONTROLLER) {
      return { contextUrl: null, document: issuerDocument, documentUrl };
    }
    if (documentUrl === "did:web:delegate.example.test") {
      return { contextUrl: null, document: delegateDocument, documentUrl };
    }
    if (documentUrl === key.id) {
      return {
        contextUrl: null,
        document: { "@context": SUITE_CONTEXT_URL, ...publicKey },
        documentUrl,
      };
    }
    if (documentUrl === SUITE_CONTEXT_URL) {
      return {
        contextUrl: null,
        document: suiteContext.contexts.get(SUITE_CONTEXT_URL),
        documentUrl,
      };
    }
    throw new Error(`Unexpected test document URL: ${documentUrl}`);
  };
  const suite = new Ed25519Signature2020({ key });
  suite.date = "2026-09-11T00:00:00Z";
  const credential = (await jsigs.sign(
    {
      "@context": [
        {
          credentialSubject:
            "https://www.w3.org/2018/credentials#credentialSubject",
          issuer: "https://www.w3.org/2018/credentials#issuer",
          name: "https://schema.org/name",
        },
        SUITE_CONTEXT_URL,
      ],
      "@id": "urn:uuid:00000000-0000-4000-8000-0000000000ee",
      "@type": "https://www.w3.org/2018/credentials#VerifiableCredential",
      issuer: TEST_CONTROLLER,
      credentialSubject: {
        "@id": "urn:uuid:00000000-0000-4000-8000-0000000000ff",
        name: "Unauthorized delegate",
      },
    },
    {
      suite,
      purpose: new jsigs.purposes.AssertionProofPurpose(),
      documentLoader,
    }
  )) as VerifiableCredential;

  const result = await withAttackerDocuments(
    issuerDocument,
    () => verifyCredentialSignature(credential),
    {
      [TEST_DID_DOCUMENT_URL]: issuerDocument,
      "https://delegate.example.test/.well-known/did.json": delegateDocument,
    }
  );

  assert.equal(result.verified, false);
});

test("an issuer host that never answers times out instead of hanging", async () => {
  /*
   * Resolving the issuer document is a network fetch, and it was briefly placed
   * outside the timeout budget when the binding was written — which left the
   * modal at 95% with nothing to report for as long as the host stayed silent.
   * Both fetches share one budget now.
   */
  const credential = {
    issuer: "did:web:slow.example.test",
    proof: {
      type: "Ed25519Signature2020",
      verificationMethod: "did:web:slow.example.test#key",
      proofValue: "z1",
      proofPurpose: "assertionMethod",
    },
  } as VerifiableCredential;

  const originalFetch = globalThis.fetch;
  globalThis.fetch = (() => new Promise(() => {})) as unknown as typeof fetch;
  // Fake timers, so proving the budget covers the fetch does not cost the suite
  // the ten seconds the budget is made of.
  mock.timers.enable({ apis: ["setTimeout"] });
  try {
    const pending = verifyCredentialSignature(credential);
    await Promise.resolve();
    mock.timers.tick(VERIFICATION_TIMEOUT_MS);
    const result = await pending;
    assert.equal(result.verified, false);
    assert.equal(result.errorType, "TIMEOUT");
  } finally {
    mock.timers.reset();
    globalThis.fetch = originalFetch;
  }
});

test("an issuer whose records cannot be reached is refused, but not as a mismatch", async () => {
  const credential = {
    issuer: TEST_CONTROLLER,
    proof: {
      type: "Ed25519Signature2020",
      verificationMethod: `${TEST_CONTROLLER}#key`,
      proofValue: "z1",
      proofPurpose: "assertionMethod",
    },
  } as VerifiableCredential;

  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async () =>
    Response.json({ message: "down" }, { status: 503 })) as typeof fetch;
  try {
    const result = await verifyCredentialSignature(credential);
    assert.equal(result.verified, false);
    // Not ISSUER_MISMATCH: the check could not be made, it did not fail.
    assert.equal(result.errorType, "ISSUER_UNRESOLVED");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("the document that authorizes the key and the one that supplies it are the same document", async () => {
  /*
   * The issuer's document answers two questions — did you authorize this key, and
   * what is the key — and fetching it twice let two different documents answer
   * them. A host that served an authorizing document first and different key
   * material second had a credential accepted under a key the authorizing
   * document never listed. Reproduced before the loader took one snapshot; an
   * ordinary key rotation landing between the fetches splits the same way.
   */
  const authorized = await Ed25519VerificationKey2020.generate({
    seed: new Uint8Array(32).fill(1),
    controller: TEST_CONTROLLER,
  });
  authorized.id = `${TEST_CONTROLLER}#key-1`;
  const authorizedPublicKey = await authorized.export({ publicKey: true });
  const other = await Ed25519VerificationKey2020.generate({
    seed: new Uint8Array(32).fill(2),
    controller: TEST_CONTROLLER,
  });
  other.id = `${TEST_CONTROLLER}#key-1`; // the same id, different key material
  const otherPublicKey = await other.export({ publicKey: true });

  const authorizingView = {
    "@context": ["https://www.w3.org/ns/did/v1", MULTIKEY_CONTEXT_URL],
    id: TEST_CONTROLLER,
    verificationMethod: [authorizedPublicKey],
    assertionMethod: [authorized.id],
  };
  const supplyingView = {
    "@context": ["https://www.w3.org/ns/did/v1", MULTIKEY_CONTEXT_URL],
    id: TEST_CONTROLLER,
    verificationMethod: [otherPublicKey],
    assertionMethod: [],
  };

  const documentLoader = async (url: string | { id?: string }) => {
    const documentUrl = typeof url === "string" ? url : (url.id ?? "");
    if (documentUrl === TEST_CONTROLLER) {
      return { contextUrl: null, document: supplyingView, documentUrl };
    }
    if (documentUrl === other.id) {
      return {
        contextUrl: null,
        document: { "@context": SUITE_CONTEXT_URL, ...otherPublicKey },
        documentUrl,
      };
    }
    if (documentUrl === SUITE_CONTEXT_URL) {
      return {
        contextUrl: null,
        document: suiteContext.contexts.get(SUITE_CONTEXT_URL),
        documentUrl,
      };
    }
    throw new Error(`Unexpected test document URL: ${documentUrl}`);
  };
  const suite = new Ed25519Signature2020({ key: other });
  suite.date = "2026-09-13T00:00:00Z";
  const credential = (await jsigs.sign(
    {
      "@context": [
        {
          credentialSubject:
            "https://www.w3.org/2018/credentials#credentialSubject",
          issuer: "https://www.w3.org/2018/credentials#issuer",
          name: "https://schema.org/name",
        },
        SUITE_CONTEXT_URL,
      ],
      "@id": "urn:uuid:00000000-0000-4000-8000-00000000aaaa",
      "@type": "https://www.w3.org/2018/credentials#VerifiableCredential",
      issuer: TEST_CONTROLLER,
      credentialSubject: {
        "@id": "urn:uuid:00000000-0000-4000-8000-00000000bbbb",
        name: "Split view",
      },
    },
    {
      suite,
      purpose: new jsigs.purposes.AssertionProofPurpose(),
      documentLoader,
    }
  )) as VerifiableCredential;

  let fetchCount = 0;
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (input: unknown) => {
    if (String(input) === TEST_DID_DOCUMENT_URL) {
      fetchCount += 1;
      return Response.json(fetchCount === 1 ? authorizingView : supplyingView);
    }
    return Response.json({ message: "Not found" }, { status: 404 });
  }) as typeof fetch;
  try {
    const result = await verifyCredentialSignature(credential);
    assert.equal(result.verified, false);
    assert.equal(fetchCount, 1, "the issuer document is read once, not twice");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("the issuer's document must be the issuer's own, and must mean what it says", async () => {
  /*
   * Two ways a fetched document can fail to be what the authorization check
   * takes it for, both accepted before this: one that carries someone else's
   * DID (or none), and one whose own context redefines `assertionMethod` to
   * something weaker — which matters because handing the purpose a controller
   * skips the framing that would otherwise interpret the term.
   */
  const fixture = await getCredentialFixture();

  const wrongIdentity = { ...fixture.didDocument, id: "did:web:someone.else" };
  const anonymous = { ...fixture.didDocument };
  delete (anonymous as { id?: unknown }).id;
  const redefinedTerm = {
    ...fixture.didDocument,
    "@context": {
      assertionMethod: {
        "@id": "https://w3id.org/security#authentication",
        "@type": "@id",
      },
    },
  };

  /*
   * A context array is applied IN ORDER, so checking only its first entry is not
   * enough: a later inline object redefines what the first entry defined, and a
   * later `null` discards it. Both verified until every entry had to be a URL.
   */
  const redefinedAfterDidContext = {
    ...fixture.didDocument,
    "@context": [
      "https://www.w3.org/ns/did/v1",
      {
        assertionMethod: {
          "@id": "https://w3id.org/security#authentication",
          "@type": "@id",
        },
      },
    ],
  };
  const resetAfterDidContext = {
    ...fixture.didDocument,
    "@context": ["https://www.w3.org/ns/did/v1", null],
  };
  // A URL is a string, and this code never fetches it — so a context it cannot
  // see is a context it cannot rely on.
  const remoteContextAfterDidContext = {
    ...fixture.didDocument,
    "@context": [
      "https://www.w3.org/ns/did/v1",
      "https://unknown.example/redefines.jsonld",
    ],
  };

  for (const [label, document] of [
    ["names another DID", wrongIdentity],
    ["names no DID", anonymous],
    ["redefines the assertion term", redefinedTerm],
    ["redefines it after the DID context", redefinedAfterDidContext],
    ["discards the DID context with null", resetAfterDidContext],
    ["names a context we cannot vouch for", remoteContextAfterDidContext],
  ] as const) {
    const result = await withCredentialDocuments(
      document as Record<string, unknown>,
      () => verifyCredentialSignature(fixture.credential)
    );
    assert.equal(result.verified, false, label);
    assert.equal(result.errorType, "ISSUER_UNRESOLVED", label);
  }
});

test("an issuer that answers 200 with a body that is not a document is unreadable, not unreachable", async () => {
  const credential = {
    issuer: TEST_CONTROLLER,
    proof: {
      type: "Ed25519Signature2020",
      verificationMethod: `${TEST_CONTROLLER}#key`,
      proofValue: "z1",
      proofPurpose: "assertionMethod",
    },
  } as VerifiableCredential;

  const originalFetch = globalThis.fetch;
  try {
    for (const body of ["{broken", "null"]) {
      globalThis.fetch = (async () =>
        new Response(body, {
          status: 200,
          headers: { "content-type": "application/json" },
        })) as typeof fetch;
      const result = await verifyCredentialSignature(credential);
      assert.equal(result.verified, false, body);
      assert.equal(result.errorType, "ISSUER_UNRESOLVED", body);
      // The host answered. The words must not say it did not.
      assert.match(String(result.error), /^Issuer unreadable/, body);
    }
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("the issuer is read from the shapes the data model allows, and no others", () => {
  // The credential the app receives carries a string; the data model also
  // allows `{id}`. Everything else returns null, which fails the binding closed.
  assert.equal(getCredentialIssuerId(TEST_CONTROLLER), TEST_CONTROLLER);
  assert.equal(
    getCredentialIssuerId(`  ${TEST_CONTROLLER}  `),
    TEST_CONTROLLER
  );
  assert.equal(getCredentialIssuerId({ id: TEST_CONTROLLER }), TEST_CONTROLLER);
  assert.equal(getCredentialIssuerId(undefined), null);
  assert.equal(getCredentialIssuerId(""), null);
  assert.equal(getCredentialIssuerId("   "), null);
  assert.equal(getCredentialIssuerId({}), null);
  assert.equal(getCredentialIssuerId({ id: 7 }), null);
  assert.equal(getCredentialIssuerId([TEST_CONTROLLER]), null);
  assert.equal(getCredentialIssuerId(7), null);
});

test("a 2020 key must be authorized for the assertion purpose", async () => {
  const fixture = await getCredentialFixture();
  const unauthorizedDocument = {
    ...fixture.didDocument,
    assertionMethod: [],
  };
  const result = await withCredentialDocuments(unauthorizedDocument, () =>
    verifyCredentialSignature(fixture.credential)
  );

  assert.equal(result.verified, false);
  assert.match(JSON.stringify(result.error), /not authorized/);
});

test("2018 and malformed 2020 proofs fail closed", async () => {
  const fixture = await getCredentialFixture();
  const legacy = structuredClone(fixture.credential);
  assert.ok(legacy.proof);
  legacy.proof.type = "Ed25519Signature2018";

  const legacyResult = await verifyCredentialSignature(legacy);
  assert.equal(legacyResult.verified, false);
  assert.match(String(legacyResult.error), /Unsupported proof type/);

  const malformed = structuredClone(fixture.credential);
  assert.ok(malformed.proof);
  delete malformed.proof.proofValue;
  const malformedResult = await withCredentialDocuments(
    fixture.didDocument,
    () => verifyCredentialSignature(malformed)
  );
  assert.equal(malformedResult.verified, false);
  assert.match(JSON.stringify(malformedResult.error), /proofValue/);
});

test("verification completion clears its pending timeout", async () => {
  const clearCalls = await countClearTimeoutCalls(async () => {
    assert.equal(
      await runWithVerificationTimeout(() => Promise.resolve("verified")),
      "verified"
    );
  });

  assert.equal(clearCalls, 1);
});

test("timeout completion clears the settled timeout handle", async () => {
  const clearCalls = await countClearTimeoutCalls(async () => {
    await assert.rejects(
      runWithVerificationTimeout(() => new Promise<never>(() => undefined), 1),
      /Verification timeout after 10 seconds/
    );
  });

  assert.equal(clearCalls, 1);
});

test("the suite context resolves locally, never over the wire", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (() => {
    throw new Error("the suite context must not be fetched");
  }) as typeof fetch;
  try {
    const result = await loadDocumentWithLocalContexts(
      suiteContext.constants.CONTEXT_URL
    );
    assert.equal(result.documentUrl, suiteContext.constants.CONTEXT_URL);
    assert.ok(result.document, "the bundled context document is served");
    const context = (
      result.document as { "@context"?: Record<string, unknown> }
    )["@context"];
    assert.ok(context, "the served document is a context document");
    assert.ok(
      context["Ed25519Signature2020"] && context["Ed25519VerificationKey2020"],
      "the served context defines the suite's terms"
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});
