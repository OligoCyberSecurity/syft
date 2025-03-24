/*
Package alpine provides a concrete Cataloger implementations for packages relating to the Alpine linux distribution.
*/
package alpine

import (
	"github.com/oligocybersecurity/syft/syft/pkg"
	"github.com/oligocybersecurity/syft/syft/pkg/cataloger/generic"
	"github.com/oligocybersecurity/syft/syft/pkg/cataloger/internal/dependency"
)

// NewDBCataloger returns a new cataloger object initialized for Alpine package DB flat-file stores.
func NewDBCataloger() pkg.Cataloger {
	return generic.NewCataloger("apk-db-cataloger").
		WithParserByGlobs(parseApkDB, pkg.ApkDBGlob).
		WithProcessors(dependency.Processor(dbEntryDependencySpecifier))
}
