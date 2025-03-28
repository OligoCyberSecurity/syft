package cpp

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/oligocybersecurity/syft/internal/unknown"
	"github.com/oligocybersecurity/syft/syft/artifact"
	"github.com/oligocybersecurity/syft/syft/file"
	"github.com/oligocybersecurity/syft/syft/pkg"
	"github.com/oligocybersecurity/syft/syft/pkg/cataloger/generic"
)

var _ generic.Parser = parseConanfile

// parseConanfile is a parser function for conanfile.txt contents, returning all packages discovered.
func parseConanfile(_ context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	r := bufio.NewReader(reader)
	inRequirements := false
	var pkgs []pkg.Package
	for {
		line, err := r.ReadString('\n')
		switch {
		case errors.Is(err, io.EOF):
			return pkgs, nil, unknown.IfEmptyf(pkgs, "unable to determine packages")
		case err != nil:
			return nil, nil, fmt.Errorf("failed to parse conanfile.txt file: %w", err)
		}

		switch {
		case strings.Contains(line, "[requires]"):
			inRequirements = true
		case strings.ContainsAny(line, "[]") || strings.HasPrefix(strings.TrimSpace(line), "#"):
			inRequirements = false
		}

		m := pkg.ConanfileEntry{
			Ref: strings.TrimSpace(line),
		}

		if !inRequirements {
			continue
		}

		p := newConanfilePackage(
			m,
			reader.Location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
		)
		if p == nil {
			continue
		}

		pkgs = append(pkgs, *p)
	}
}
