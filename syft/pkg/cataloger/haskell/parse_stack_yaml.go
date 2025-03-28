package haskell

import (
	"context"
	"fmt"
	"io"

	"gopkg.in/yaml.v3"

	"github.com/oligocybersecurity/syft/internal/log"
	"github.com/oligocybersecurity/syft/internal/unknown"
	"github.com/oligocybersecurity/syft/syft/artifact"
	"github.com/oligocybersecurity/syft/syft/file"
	"github.com/oligocybersecurity/syft/syft/pkg"
	"github.com/oligocybersecurity/syft/syft/pkg/cataloger/generic"
)

var _ generic.Parser = parseStackYaml

type stackYaml struct {
	ExtraDeps []string `yaml:"extra-deps"`
}

// parseStackYaml is a parser function for stack.yaml contents, returning all packages discovered.
func parseStackYaml(_ context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	bytes, err := io.ReadAll(reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load stack.yaml file: %w", err)
	}

	var stackFile stackYaml

	if err := yaml.Unmarshal(bytes, &stackFile); err != nil {
		log.WithFields("error", err, "path", reader.RealPath).Trace("failed to parse stack.yaml")
		return nil, nil, fmt.Errorf("failed to parse stack.yaml file")
	}

	var pkgs []pkg.Package
	for _, dep := range stackFile.ExtraDeps {
		pkgName, pkgVersion, pkgHash := parseStackPackageEncoding(dep)
		pkgs = append(
			pkgs,
			newPackage(
				pkgName,
				pkgVersion,
				pkg.HackageStackYamlEntry{
					PkgHash: pkgHash,
				},
				reader.Location,
			),
		)
	}

	return pkgs, nil, unknown.IfEmptyf(pkgs, "unable to determine packages")
}
