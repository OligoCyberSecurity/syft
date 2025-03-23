/*
Package debian provides a concrete Cataloger implementation relating to packages within the Debian linux distribution.
*/
package debian

import (
	"github.com/oligocybersecurity/syft/syft/pkg"
	"github.com/oligocybersecurity/syft/syft/pkg/cataloger/generic"
	"github.com/oligocybersecurity/syft/syft/pkg/cataloger/internal/dependency"
)

// NewDBCataloger returns a new Deb package cataloger capable of parsing DPKG status DB flat-file stores.
func NewDBCataloger() pkg.Cataloger {
	return generic.NewCataloger("dpkg-db-cataloger").
		// note: these globs have been intentionally split up in order to improve search performance,
		// please do NOT combine into: "**/var/lib/dpkg/{status,status.d/*}"
		WithParserByGlobs(parseDpkgDB, "**/var/lib/dpkg/status", "**/var/lib/dpkg/status.d/*", "**/lib/opkg/info/*.control", "**/lib/opkg/status").
		WithProcessors(dependency.Processor(dbEntryDependencySpecifier))
}
