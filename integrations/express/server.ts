/**
 * An API that serves agents only when it knows who answers for them.
 *
 *     node --experimental-strip-types server.ts     (Node 22)
 *     node server.ts                                (Node 24)
 *
 * `GET /orders` needs a signed request whose signer has a verified identity
 * with a domain check; `GET /` is open and says so.
 */

import express from "express";
import { summarise, type Verification } from "@knownas/verify";
import { knownasVerify } from "./knownas.ts";

export const app = express();

app.get("/", (_req, res) => {
  res.json({
    hello: "Sign your requests with a key your identity publishes; GET /orders then answers.",
    how: "https://github.com/authecity/agent-identity-document",
  });
});

app.get("/orders", knownasVerify({ require: ["owner.domain"] }), (_req, res) => {
  const identity = res.locals["identity"] as Verification;
  res.json({
    agent: identity.subject,
    provider: identity.provider,
    checked: summarise(identity),
    orders: [{ id: "o-1001", status: "shipped" }],
  });
});

if (import.meta.url === `file://${process.argv[1]?.replace(/\\/g, "/")}`) {
  const port = Number(process.env["PORT"] ?? 3000);
  app.listen(port, () => console.log(`listening on http://127.0.0.1:${port}`));
}
