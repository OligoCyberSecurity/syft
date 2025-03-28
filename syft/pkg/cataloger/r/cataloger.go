/*
Package r provides a concrete Cataloger implementation relating to packages within the R language ecosystem.
*/
package r

import (
	"github.com/oligocybersecurity/syft/syft/pkg"
	"github.com/oligocybersecurity/syft/syft/pkg/cataloger/generic"
)

// NewPackageCataloger returns a new R cataloger object based on detection of R package DESCRIPTION files.
func NewPackageCataloger() pkg.Cataloger {
	return generic.NewCataloger("r-package-cataloger").
		WithParserByGlobs(parseDescriptionFile, "**/DESCRIPTION")
}
