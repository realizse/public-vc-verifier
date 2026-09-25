/**
 * The issuer a credential names, in one place.
 *
 * Its own module so that reading an issuer for display does not pull the
 * signature stack in behind it: `passport-presentation.ts` is imported by server
 * routes, and importing the verifier there would load `jsonld-signatures` and
 * the Ed25519 suite into those bundles for an eight-line parser.
 */

/**
 * Accepts the plain string every credential this app receives actually carries
 * (measured on dev: five credentials across an asset and a product passport) and
 * the `{id}` object the VC data model also allows. Anything else — an array of
 * issuers, a bare number, an object with no `id` — is null, and a null issuer
 * fails the binding closed in `credential-verifier.ts`.
 *
 * Both the verifier and the passport display read the issuer through this, so
 * the DID shown beside a verification result is the DID that result was checked
 * against. Two parsers could name one party while the signature was bound to
 * another.
 */
export function getCredentialIssuerId(value: unknown): string | null {
  if (typeof value === "string") {
    return value.trim() || null;
  }
  if (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    typeof (value as { id?: unknown }).id === "string"
  ) {
    return ((value as { id: string }).id.trim() || null) as string | null;
  }
  return null;
}
