package opautils

import (
	"sync"

	"github.com/open-policy-agent/opa/v1/rego"
)

var registerOnce sync.Once

func RegisterBuiltins() {
	registerOnce.Do(func() {

		rego.RegisterBuiltin1(
			imageNameNormalizeDeclaration,
			imageNameNormalizeDefinition,
		)

	})
}
