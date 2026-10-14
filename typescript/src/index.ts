/**
 * @knownas/verify: read an AI agent's public identity and report what was checked.
 *
 * The verifier side of the Agent Identity Document specification. It reads
 * only public records served by the identity's own host, reports each thing
 * it looked at as a dated check with one of four outcomes, and never produces
 * a trust flag, score or level. A relying party decides for itself, by naming
 * the checks it depends on.
 */

export { VERSION } from "./fetch.ts";
export {
  CachingFetcher,
  DefaultFetcher,
  FetchError,
  Fetched,
  RecordedFetcher,
  checkSubject,
  isGlobal,
  type FetchOptions,
  type Fetcher,
} from "./fetch.ts";
export {
  DIRECTORY_PATH,
  DOCUMENT_PATH,
  SCHEMA_TAG,
  STATEMENT_PATH,
  providerOf,
  readDirectory,
  verifyIdentity,
  type VerifyIdentityOptions,
} from "./identity.ts";
export {
  UNKNOWN,
  UNREACHABLE,
  Verification,
  VerificationFailed,
  assertVerified,
  require,
  type Check,
  type Outcome,
} from "./result.ts";
export { Request, jwkThumbprint, signatureBase, verifyRequest, type VerifyRequestOptions } from "./signatures.ts";
export { FORBIDDEN_WORDS, summarise } from "./words.ts";
