package terraform

import (
	"github.com/oligocybersecurity/syft/syft/pkg"
	"github.com/oligocybersecurity/syft/syft/pkg/cataloger/generic"
)

func NewLockCataloger() pkg.Cataloger {
	return generic.NewCataloger("terraform-lock-cataloger").
		WithParserByGlobs(parseTerraformLock, "**/.terraform.lock.hcl")
}
