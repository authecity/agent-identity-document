# Integrations: refusing unverified agents, in the frameworks people use

Three worked examples of the verifier library in front of something agents
call. Each one verifies the request's Web Bot Auth signature against the key
the caller's identity publishes, reads the caller's identity record, and
refuses with a plain HTTP answer that **names the check that failed**:

- `401` when the signature is not `verified` (missing, invalid, or the key
  could not be discovered), with the outcome and why;
- `403` when a check the route names (for example `owner.domain`) is not
  `verified`, naming each one.

Never a score, never a bare "trusted". The verified identity is handed to
the handler so it can answer differently for different named agents.

| Example | Language | What it protects | Run the tests |
|---|---|---|---|
| [`fastapi/`](fastapi/) | Python, `knownas-verify` | A FastAPI route, through a dependency (`knownas_identity("owner.domain")`) | `cd fastapi && pip install -r requirements.txt && pytest` |
| [`express/`](express/) | TypeScript, `@knownas/verify` | An Express route, through a middleware (`knownasVerify({ require: ["owner.domain"] })`) | `cd express && npm ci && npm test` |
| [`mcp/`](mcp/) | TypeScript, `@knownas/verify` | A stateless Streamable HTTP MCP server (the official SDK), behind the same middleware, so an unverified agent never reaches a tool | `cd mcp && npm ci && npm test` |

The tests run without a network: the caller's provider is recorded, and the
requests are signed with RFC 9421's published test key, which the library
refuses unless a test says `allow_test_keys` / `allowTestKeys`. The Python
example signs fresh requests with `knownas_verify.testing.sign_request`; the
TypeScript examples replay the draft's Appendix E.2.1 vector.

Each example is meant to be copied into a project, not installed: the
middleware or dependency is one file, and the framework's own conventions
(where the proxy terminates TLS, which Host the agent signed over) are the
things to check when you do. Behind a reverse proxy, make sure the authority
your framework reports is the one the agent signed; Express needs
`trust proxy`, FastAPI needs the proxy-headers middleware.

## Where these should also live

The ADR behind this (the reference implementation's ADR 0049 §6, step B4)
asks for a pull request to each framework's own examples where one exists.
None of the three keeps third-party authentication examples: FastAPI's and
Express's documentation cover their own auth primitives, and the MCP SDK's
examples are the protocol's. The better route, which the reference
implementation's prospect list already names, is a documentation pull
request to the agent frameworks that publish agent cards or MCP servers for
their users, offering the verifier as the "who is calling" step. Those are
the owner's conversations.
