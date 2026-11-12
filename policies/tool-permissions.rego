package mcp.tool

default allow := false

allow if {
	input.tool.review_status == "approved"
	input.tool.sensitive == false
	input.permission.effect == "allow"
	input.permission.tool == input.tool.name
	input.permission.server_id == input.server.id
}

allow if {
	input.tool.review_status == "approved"
	input.tool.sensitive == true
	input.grant.valid == true
	input.permission.effect == "allow"
	input.permission.tool == input.tool.name
	input.permission.server_id == input.server.id
}
