/*
Package redhat provides a concrete DBCataloger implementation relating to packages within the RedHat linux distribution.
*/
package redhat

import (
	"database/sql"

	"github.com/oligocybersecurity/syft/internal/log"
	"github.com/oligocybersecurity/syft/syft/artifact"
	"github.com/oligocybersecurity/syft/syft/pkg"
	"github.com/oligocybersecurity/syft/syft/pkg/cataloger/generic"
	"github.com/oligocybersecurity/syft/syft/pkg/cataloger/internal/dependency"
)

// NewDBCataloger returns a new RPM DB cataloger object.
func NewDBCataloger() pkg.Cataloger {
	// check if a sqlite driver is available
	if !isSqliteDriverAvailable() {
		log.Debugf("sqlite driver is not available, newer RPM databases might not be cataloged")
	}

	return generic.NewCataloger("rpm-db-cataloger").
		WithParserByGlobs(parseRpmDB, pkg.RpmDBGlob).
		WithParserByGlobs(parseRpmManifest, pkg.RpmManifestGlob).
		WithProcessors(dependency.Processor(dbEntryDependencySpecifier), denySelfReferences)
}

func denySelfReferences(pkgs []pkg.Package, rels []artifact.Relationship, err error) ([]pkg.Package, []artifact.Relationship, error) {
	// it can be common for dependency evidence to be self-referential (e.g. bash depends on bash), which is not useful
	// for the dependency graph, thus we remove these cases
	for i := 0; i < len(rels); i++ {
		if rels[i].Type != artifact.DependencyOfRelationship {
			continue
		}
		if rels[i].From.ID() == rels[i].To.ID() {
			rels = append(rels[:i], rels[i+1:]...)
			i--
		}
	}
	return pkgs, rels, err
}

// NewArchiveCataloger returns a new RPM file cataloger object.
func NewArchiveCataloger() pkg.Cataloger {
	return generic.NewCataloger("rpm-archive-cataloger").
		WithParserByGlobs(parseRpmArchive, "**/*.rpm")
}

func isSqliteDriverAvailable() bool {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		return false
	}
	_ = db.Close()
	return true
}
