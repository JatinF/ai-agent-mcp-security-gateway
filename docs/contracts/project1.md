# Project 1 contract

Project 1 is `github.com/JatinF/zero-trust-cloud-edge-control-plane` at commit `b1294e269e81faefca77be88b0b7c2dce1e325f9`. This module does not import it. The lab process does not dial it.

`MCP_CONTROL_PLANE_URL` is unset. Project 1 was not contacted. When that variable is set, the gate status is `blocked`, the process does not connect, and the value is not copied into the reason.

The client in `internal/upstream` speaks one request, and only from tests that use `httptest`:

`POST /v1/access-requests`

```json
{"resource":"SYN-MCP-ADMIN/SYN-INV-TEST","action":"maintenance.apply","reason":"text"}
```

Project 1 reads audit with `GET /v1/audit/events` and gates with `GET /v1/gates`. It has no audit ingest route. This gateway keeps its own audit log. Each event uses the Project 1 field names and adds the MCP fields:

`event_id`, `tenant_id`, `principal`, `action`, `decision`, `policy_id`, `policy_revision`, `detail`, `at_unix`, `mcp_server`, `tool`, `target_resource`, `outcome`.

Bearer authentication uses the prefix `Bearer `. Detail text is redacted before it is stored.
