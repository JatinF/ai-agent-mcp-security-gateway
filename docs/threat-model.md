# Threat model

The lab models a gateway in front of tool servers. The assets are agent identity, tool permission, short-lived grants, and the audit record. The trust boundary is the proxy in `internal/mcp`.

## In scope for this lab

A caller can present an expired token, a tampered signature, a token for the wrong server, or a delegated credential as if it were the caller. The tested reasons are `token_expired`, `signature_invalid`, `audience_mismatch`, and `credential_rejected`.

A caller can ask for `inventory.admin` without an allow. The reason is `denied`, the mock call count stays put, and no grant is stored.

A requester can try to approve their own sensitive call. The reason is `self_approval`. A different person can approve a 300-second grant. After the lab clock advances 6 minutes the reason is `grant_expired`.

An operator can revoke `SYN-AGENT-GO`. Later calls are `identity_revoked`. The signature still parses, so revocation is a registry fact.

A tool owner can change `inventory.query` from `read` to `export`. Calls stop with `policy_review_required` until a registry admin accepts the review.

The gateway, the registry, or the policy engine can be marked down. The reasons are `gateway_unavailable`, `registry_unavailable`, and `policy_unavailable`. The mock is not called.

A request body can contain a token-shaped string. Stored text uses `[redacted]`.

## Out of scope

This lab does not model a network attacker on a live MCP socket, a stolen OIDC issuer, a customer tenant, or a production identity provider. Those processes were not started. Project 1 commit `b1294e2` was not contacted.

The in-process mock returns canned JSON. `maintenance.apply` returns `applied:false`. Nothing in the lab mutates an external system.
