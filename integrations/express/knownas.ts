/**
 * An Express middleware that refuses unverified agents.
 *
 *     import { knownasVerify } from "./knownas.ts";
 *     app.get("/orders", knownasVerify({ require: ["owner.domain"] }), handler);
 *
 * It verifies the request's Web Bot Auth signature against the key its
 * signer publishes, then reads the signer's identity, and refuses with:
 *
 * - 401 when the signature is not `verified` (missing, invalid, or the key
 *   could not be discovered), naming the outcome and why;
 * - 403 when a check the route names is not `verified`, naming each one.
 *
 * The verified identity is on `res.locals.identity`. Copy this file into your
 * project; it is an example, not a package. It needs `@knownas/verify` and
 * `express`. Behind a reverse proxy, set Express's `trust proxy` so
 * `req.protocol` and the Host the signature covers are the ones the agent
 * used.
 */

import type { NextFunction, Request as ExpressRequest, RequestHandler, Response as ExpressResponse } from "express";
import { Request, type Fetcher, type Verification, verifyRequest } from "@knownas/verify";

export interface KnownasVerifyOptions {
  /** Check names the route depends on beyond the signature, e.g. `"owner.domain"`. */
  require?: readonly string[];
  /** For tests; leave at the defaults in production. */
  fetcher?: Fetcher;
  now?: () => Date;
  allowTestKeys?: boolean;
}

export function knownasVerify(options: KnownasVerifyOptions = {}): RequestHandler {
  return async (req: ExpressRequest, res: ExpressResponse, next: NextFunction): Promise<void> => {
    const url = `${req.protocol}://${req.get("host") ?? ""}${req.originalUrl}`;
    const headers: [string, string][] = [];
    for (let i = 0; i + 1 < req.rawHeaders.length; i += 2) {
      headers.push([req.rawHeaders[i]!, req.rawHeaders[i + 1]!]);
    }
    let verification: Verification;
    try {
      const verifyOptions: Parameters<typeof verifyRequest>[1] = {};
      if (options.fetcher) verifyOptions.fetcher = options.fetcher;
      if (options.now) verifyOptions.now = options.now();
      if (options.allowTestKeys !== undefined) verifyOptions.allowTestKeys = options.allowTestKeys;
      verification = await verifyRequest(new Request(req.method, url, headers), verifyOptions);
    } catch (error) {
      next(error);
      return;
    }
    const signature = verification.check("request.signature");
    if (signature === undefined || signature.outcome !== "verified") {
      res
        .status(401)
        .set("WWW-Authenticate", 'Signature realm="knownas"')
        .json({
          error: "request_not_verified",
          check: "request.signature",
          outcome: signature?.outcome ?? "absent",
          why: signature?.detail ?? "",
        });
      return;
    }
    const failed = (options.require ?? [])
      .map((name) => ({ name, check: verification.check(name) }))
      .filter(({ check }) => check === undefined || check.outcome !== "verified")
      .map(({ name, check }) => ({
        check: name,
        outcome: check?.outcome ?? "absent",
        why: check?.detail ?? "the record does not carry it",
      }));
    if (failed.length > 0) {
      res.status(403).json({ error: "identity_check_failed", subject: verification.subject, failed });
      return;
    }
    res.locals["identity"] = verification;
    next();
  };
}
