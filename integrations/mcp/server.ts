/**
 * An MCP server that refuses unverified callers.
 *
 *     node server.ts            (Node 24; add --experimental-strip-types on 22)
 *
 * A stateless Streamable HTTP MCP server (the official TypeScript SDK) behind
 * the same middleware the Express example uses: every POST to `/mcp` must
 * carry a Web Bot Auth signature from a key the caller's identity publishes,
 * and the caller's identity record must carry a domain check. A refusal is a
 * plain HTTP 401 or 403 naming the check, before any JSON-RPC is read, so an
 * unverified agent never reaches a tool. The verified identity is passed to
 * tools, so a tool can answer differently for different named agents.
 */

import express, { type Request as ExpressRequest, type Response as ExpressResponse } from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { summarise, type Verification } from "@knownas/verify";
// The same middleware the Express example uses; copy it beside this file in your own project.
import { knownasVerify, type KnownasVerifyOptions } from "../express/knownas.ts";

function serverFor(identity: Verification): McpServer {
  const server = new McpServer({ name: "orders-for-named-agents", version: "0.1.0" });
  server.registerTool(
    "whoami",
    { description: "What this server verified about the calling agent, in words." },
    async () => ({
      content: [{ type: "text", text: [`Calling agent: ${identity.subject}`, ...summarise(identity)].join("\n") }],
    }),
  );
  server.registerTool(
    "list_orders",
    { description: "The calling agent's orders. Only a named agent with a verified owner domain reaches this." },
    async () => ({
      content: [{ type: "text", text: JSON.stringify({ agent: identity.subject, orders: [{ id: "o-1001", status: "shipped" }] }) }],
    }),
  );
  return server;
}

export function makeApp(options: KnownasVerifyOptions = { require: ["owner.domain"] }, path = "/mcp"): express.Express {
  const app = express();
  app.use(express.json());
  app.post(path, knownasVerify(options), async (req: ExpressRequest, res: ExpressResponse) => {
    const identity = res.locals["identity"] as Verification;
    const server = serverFor(identity);
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
    res.on("close", () => {
      void transport.close();
      void server.close();
    });
    try {
      await server.connect(transport);
      await transport.handleRequest(req, res, req.body);
    } catch (error) {
      if (!res.headersSent) {
        res.status(500).json({ jsonrpc: "2.0", error: { code: -32603, message: String(error) }, id: null });
      }
    }
  });
  // Stateless: no sessions to resume or end.
  app.get(path, (_req, res) => res.status(405).set("Allow", "POST").end());
  app.delete(path, (_req, res) => res.status(405).set("Allow", "POST").end());
  return app;
}

if (import.meta.url === `file://${process.argv[1]?.replace(/\\/g, "/")}`) {
  const port = Number(process.env["PORT"] ?? 3001);
  makeApp().listen(port, () => console.log(`MCP at http://127.0.0.1:${port}/mcp`));
}
