package main

import "github.com/aquasecurity/tracee/tracee-ebpf/tests/types"

// ExportedSignatures fulfills the goplugins contract required by the rule-engine
// this is a list of signatures that this plugin exports
var ExportedSignatures []types.Signature = []types.Signature{
	&stdioOverSocket{},
}
