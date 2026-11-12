package mcp.agent

default allow := false

allow if {
	input.agent.status == "active"
	input.agent.tenant_id == input.server.tenant_id
	input.agent.id == input.subject
}
