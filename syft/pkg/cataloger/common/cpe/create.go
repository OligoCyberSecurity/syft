package cpe

import (
	"github.com/oligocybersecurity/syft/syft/cpe"
	"github.com/oligocybersecurity/syft/syft/pkg"
	"github.com/oligocybersecurity/syft/syft/pkg/cataloger/internal/cpegenerate"
)

func Generate(p pkg.Package) []cpe.CPE {
	return cpegenerate.FromPackageAttributes(p)
}

func DictionaryFind(p pkg.Package) ([]cpe.CPE, bool) {
	return cpegenerate.FromDictionaryFind(p)
}
