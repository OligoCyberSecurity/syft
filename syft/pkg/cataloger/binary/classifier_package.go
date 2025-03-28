package binary

import (
	"reflect"

	"github.com/anchore/packageurl-go"
	"github.com/oligocybersecurity/syft/syft/cpe"
	"github.com/oligocybersecurity/syft/syft/file"
	"github.com/oligocybersecurity/syft/syft/pkg"
)

var emptyPURL = packageurl.PackageURL{}

func newClassifierPackage(classifier Classifier, location file.Location, matchMetadata map[string]string) *pkg.Package {
	version, ok := matchMetadata["version"]
	if !ok {
		return nil
	}

	update := matchMetadata["update"]

	var cpes []cpe.CPE
	for _, c := range classifier.CPEs {
		c.Attributes.Version = version
		c.Attributes.Update = update
		cpes = append(cpes, c)
	}

	p := pkg.Package{
		Name:    classifier.Package,
		Version: version,
		Locations: file.NewLocationSet(
			location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
		),
		Type:    pkg.BinaryPkg,
		CPEs:    cpes,
		FoundBy: catalogerName,
		Metadata: pkg.BinarySignature{
			Matches: []pkg.ClassifierMatch{
				{
					Classifier: classifier.Class,
					Location:   location,
				},
			},
		},
	}

	if !reflect.DeepEqual(classifier.PURL, emptyPURL) {
		purl := classifier.PURL
		purl.Version = version
		p.PURL = purl.ToString()
	}

	p.SetID()

	return &p
}
