/*
Package swift provides a concrete Cataloger implementation relating to packages within the swift language ecosystem.
*/
package swift

import (
	"github.com/oligocybersecurity/syft/syft/pkg"
	"github.com/oligocybersecurity/syft/syft/pkg/cataloger/generic"
)

// NewSwiftPackageManagerCataloger returns a new Swift package manager cataloger object.
func NewSwiftPackageManagerCataloger() pkg.Cataloger {
	return generic.NewCataloger("swift-package-manager-cataloger").
		WithParserByGlobs(parsePackageResolved, "**/Package.resolved", "**/.package.resolved")
}

// NewCocoapodsCataloger returns a new Swift Cocoapods lock file cataloger object.
func NewCocoapodsCataloger() pkg.Cataloger {
	return generic.NewCataloger("cocoapods-cataloger").
		WithParserByGlobs(parsePodfileLock, "**/Podfile.lock")
}
