package helpers

import "github.com/oligocybersecurity/syft/syft/pkg"

func Homepage(p pkg.Package) string {
	if hasMetadata(p) {
		switch metadata := p.Metadata.(type) {
		case pkg.RubyGemspec:
			return metadata.Homepage
		case pkg.NpmPackage:
			return metadata.Homepage
		}
	}
	return ""
}
