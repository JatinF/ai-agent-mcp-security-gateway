# Authorization

Policy id `SYN-POL-MCP`. Modules are `policies/agent-access.rego` and `policies/tool-permissions.rego`. Both use `default allow := false`. Empty input denies. `default allow := true` is rejected at validation.

`mcp.agent` allows an active agent whose id is the subject and whose tenant matches the server.

`mcp.tool` allows a reviewed tool with an `allow` permission. A sensitive tool also needs `grant.valid`. The seed allows are:

- `SYN-AGENT-LANGGRAPH` on `inventory.query`
- `SYN-AGENT-GO` on `inventory.query` and `maintenance.apply`
- `SYN-AGENT-TESTAUTO` on `test.ping`

`inventory.admin` has no allow. The demo denial creates no grant.

A capability change of operation, risk, or resource scope sets `review_status` to `review_required`. Calls then return `policy_review_required` until `SYN-USER-ADA` accepts the review. Accepting bumps the policy revision.

Human routes require audience `mcp://gateway`. Agent tokens carry the audience of one MCP server. A downstream credential cannot be replayed as a caller token.

HTTP denies are error envelopes. `401` covers missing and invalid tokens, including `audience_mismatch`. `409` is `policy_review_required`. `503` is gateway, registry, or policy unavailable. Other denials are `403`. An allow is `200` with `"allow":true`.

The request reason and the audit detail pass through redaction. A token-shaped string is stored as `[redacted]`.
