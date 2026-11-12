# Security evaluation

The evaluation is the test suite in `tests/` plus `go run ./cmd/gateway demo`. The executed drawing records the same outcomes.

## Controls the tests observe

| Control | Observed reason or result |
| --- | --- |
| Maintenance read of approved inventory | `permit`, new delegated credential |
| Test ping | `permit` |
| Administrative tool without an allow | `denied`, mock unchanged, grants 0 |
| Sensitive tool before approval | `approval_required` |
| Requester approves self | `self_approval` |
| Approver grants 300 seconds | `grant_permit`, then `grant_expired` |
| Token audience for the other server | `audience_mismatch` |
| Tool operation change | `policy_review_required`, then revision 2 `permit` |
| Revoked agent, signature still valid | `identity_revoked` |
| Other tenant | `tenant_forbidden` |
| Policy or gateway marked down | `policy_unavailable`, `gateway_unavailable`, protected calls 0 |
| Registry marked down | `registry_unavailable` |
| Expired or tampered token | `token_expired`, `signature_invalid` |
| Delegated credential as caller | `credential_rejected` |
| HTTP call without a bearer | `401` |
| Standing high-risk allow | `excessive_permission` only after a test adds one. The seed has zero. |
| Token-shaped request text | stored as `[redacted]` |
| Required audit decisions | `audit_missing` 0 |

Audit decisions that must carry principal, server, tool, resource, and a revision above 0 are: `permit`, `denied`, `approval_required`, `grant_permit`, `grant_expired`, `audience_mismatch`, `policy_review_required`, `identity_revoked`, `policy_unavailable`, `gateway_unavailable`. When the gateway is down before parse, the principal is `unknown`.

## What this evaluation is not

It is an in-process lab on one workstation. It is not a customer penetration test, a network service-level objective, or a statement about a deployed gateway. Price is none. Integration gates stay `not-run` while their variables are empty.
