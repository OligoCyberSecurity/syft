package integration

import (
	"testing"

	"github.com/oligocybersecurity/syft/syft/pkg"
	"github.com/oligocybersecurity/syft/syft/source"
)

func TestPhotonPackageRegression(t *testing.T) { // Regression: https://github.com/oligocybersecurity/syft/pull/1997
	sbom, _ := catalogFixtureImage(t, "image-photon-all-layers", source.AllLayersScope)
	var packages []pkg.Package
	for p := range sbom.Artifacts.Packages.Enumerate() {
		packages = append(packages, p)
	}

	if len(packages) < 1 {
		t.Errorf("failed to find packages for photon distro; wanted > 0 got 0")
	}
}
