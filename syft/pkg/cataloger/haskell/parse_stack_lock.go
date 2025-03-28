package haskell

import (
	"context"
	"fmt"
	"io"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/oligocybersecurity/syft/internal/log"
	"github.com/oligocybersecurity/syft/internal/unknown"
	"github.com/oligocybersecurity/syft/syft/artifact"
	"github.com/oligocybersecurity/syft/syft/file"
	"github.com/oligocybersecurity/syft/syft/pkg"
	"github.com/oligocybersecurity/syft/syft/pkg/cataloger/generic"
)

var _ generic.Parser = parseStackLock

type stackLock struct {
	Packages  []stackPackage  `yaml:"packages"`
	Snapshots []stackSnapshot `yaml:"snapshots"`
}

type stackPackage struct {
	Completed completedPackage `yaml:"completed"`
}

type completedPackage struct {
	Hackage string `yaml:"hackage"`
}

type stackSnapshot struct {
	Completed completedSnapshot `yaml:"completed"`
}

type completedSnapshot struct {
	URL string `yaml:"url"`
	Sha string `yaml:"sha256"`
}

// parseStackLock is a parser function for stack.yaml.lock contents, returning all packages discovered.
func parseStackLock(_ context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	bytes, err := io.ReadAll(reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load stack.yaml.lock file: %w", err)
	}

	var lockFile stackLock

	if err := yaml.Unmarshal(bytes, &lockFile); err != nil {
		log.WithFields("error", err, "path", reader.RealPath).Trace("failed to parse stack.yaml.lock")
		return nil, nil, fmt.Errorf("failed to parse stack.yaml.lock file")
	}

	var (
		pkgs        []pkg.Package
		snapshotURL string
	)

	for _, snap := range lockFile.Snapshots {
		// TODO: handle multiple snapshots (split the metadata struct into more distinct structs and types)
		snapshotURL = snap.Completed.URL
	}

	for _, pack := range lockFile.Packages {
		if pack.Completed.Hackage == "" {
			continue
		}
		pkgName, pkgVersion, pkgHash := parseStackPackageEncoding(pack.Completed.Hackage)
		pkgs = append(
			pkgs,
			newPackage(
				pkgName,
				pkgVersion,
				pkg.HackageStackYamlLockEntry{
					PkgHash:     pkgHash,
					SnapshotURL: snapshotURL,
				},
				reader.Location,
			),
		)
	}

	return pkgs, nil, unknown.IfEmptyf(pkgs, "unable to determine packages")
}

func parseStackPackageEncoding(pkgEncoding string) (name, version, hash string) {
	lastDashIdx := strings.LastIndex(pkgEncoding, "-")
	if lastDashIdx == -1 {
		name = pkgEncoding
		return
	}
	name = pkgEncoding[:lastDashIdx]
	remainingEncoding := pkgEncoding[lastDashIdx+1:]
	encodingSplits := strings.Split(remainingEncoding, "@")
	version = encodingSplits[0]
	if len(encodingSplits) > 1 {
		startHash, endHash := strings.Index(encodingSplits[1], ":")+1, strings.Index(encodingSplits[1], ",")
		hash = encodingSplits[1][startHash:endHash]
	}
	return
}
