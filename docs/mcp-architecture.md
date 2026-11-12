# MCP architecture

The drawing is [docs/diagrams/architecture.svg](diagrams/architecture.svg). The run that the tests assert is [docs/diagrams/executed-path.svg](diagrams/executed-path.svg).

## Identities

Tenant `SYN-TENANT-CEDAR` has three agents.

| Agent | Runtime | Owner | Allowed tools |
| --- | --- | --- | --- |
| `SYN-AGENT-LANGGRAPH` | langgraph | `SYN-USER-ADA` | `inventory.query` |
| `SYN-AGENT-GO` | go | `SYN-USER-JULES` | `inventory.query`, `maintenance.apply` |
| `SYN-AGENT-TESTAUTO` | test-automation | `SYN-USER-KIRAN` | `test.ping` |

`SYN-AGENT-BIRCH` belongs to `SYN-TENANT-BIRCH`. The demo uses it only for `tenant_forbidden`. The agent count in the report is 3.

`SYN-USER-ADA` is `registry-admin`. `SYN-USER-JULES` is `requester`. `SYN-USER-KIRAN` is `approver`. A requester who approves their own request receives `self_approval`, and the request stays pending.

The LangGraph runtime was not started. `examples/agent-readonly` prints a `tools/call` body and does not hold a token.

## Servers

Both servers are in-process. Their endpoints are `inprocess://SYN-MCP-INVENTORY` and `inprocess://SYN-MCP-ADMIN`.

`SYN-MCP-INVENTORY` exposes `inventory.query` (`read`, low, scope `SYN-INV-TEST`) and `test.ping` (`ping`, low, scope `SYN-TEST`).

`SYN-MCP-ADMIN` exposes `inventory.admin` (high, no seed allow) and `maintenance.apply` (high, sensitive, scope `SYN-INV-TEST`).

## Call order

1. Token. Ed25519, issuer `https://syn.lab/mcp-gateway`, expiry on the lab clock. A delegated token presented as the caller is `credential_rejected`.
2. Audience. The token audience must be `mcp://` plus the server id.
3. Registry. An unavailable registry is `registry_unavailable`. Token claims are not treated as an allow.
4. Catalog. The agent tenant must match, the status must be `active`, the server audience must match, and the resource must equal the tool scope.
5. Policy. `SYN-POL-MCP` starts at revision 1. Both `mcp.agent` and `mcp.tool` must allow. An unreviewed tool is `policy_review_required`.
6. Approval. A sensitive tool needs a valid grant. The grant clock is Go, using the lab clock. OPA receives `grant.valid` and does not measure time.
7. Forward. The proxy mints a new JWT: `delegated` true, one server, one tool, 60 seconds. The caller bearer is not the minted value. The mock runs, then the audit record is written.

A miss writes audit and does not call the mock.

## Clocks

The lab clock starts at `2026-11-12T15:00:00Z`. Caller tokens last 1 hour. Grants last 300 seconds. Downstream credentials last 60 seconds. These are configuration limits.
