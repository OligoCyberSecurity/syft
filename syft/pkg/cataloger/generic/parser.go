package generic

import (
	"context"

	"github.com/oligocybersecurity/syft/syft/artifact"
	"github.com/oligocybersecurity/syft/syft/file"
	"github.com/oligocybersecurity/syft/syft/linux"
	"github.com/oligocybersecurity/syft/syft/pkg"
)

type Environment struct {
	LinuxRelease *linux.Release
}

type Parser func(context.Context, file.Resolver, *Environment, file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error)
