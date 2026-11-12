package policies

import _ "embed"

//go:embed agent-access.rego
var AgentAccess string

//go:embed tool-permissions.rego
var ToolPermissions string
