package integration

import (
	"testing"

	"github.com/oligocybersecurity/syft/syft/source"
)

func TestRegressionJavaNoMainPackage(t *testing.T) { // Regression: https://github.com/oligocybersecurity/syft/issues/252
	catalogFixtureImage(t, "image-java-no-main-package", source.SquashedScope)
}
