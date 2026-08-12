package opautils

import (
	"fmt"

	"github.com/distribution/reference"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/topdown/builtins"
	"github.com/open-policy-agent/opa/v1/types"
)

var imageNameNormalizeDeclaration = &rego.Function{
	Name:    "image.parse_normalized_name",
	Decl:    types.NewFunction(types.Args(types.S), types.S),
	Memoize: true,
}

func normalizeImageName(img string) (string, error) {
	name, err := reference.ParseNormalizedNamed(img)
	if err != nil {
		return "", err
	}
	return name.String(), nil
}

var imageNameNormalizeDefinition = func(
	bctx rego.BuiltinContext,
	a *ast.Term,
) (*ast.Term, error) {

	aStr, err := builtins.StringOperand(a.Value, 1)
	if err != nil {
		return nil, fmt.Errorf("invalid parameter type: %v", err)
	}

	normalizedName, err := normalizeImageName(string(aStr))
	if err != nil {
		return nil, err
	}

	return ast.StringTerm(normalizedName), nil
}
