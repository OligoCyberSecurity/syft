package cpegenerate

import "github.com/oligocybersecurity/syft/syft/pkg"

func candidateVendorsForRPM(p pkg.Package) fieldCandidateSet {
	metadata, ok := p.Metadata.(pkg.RpmDBEntry)
	if !ok {
		return nil
	}

	vendors := newFieldCandidateSet()

	if metadata.Vendor != "" {
		vendors.add(fieldCandidate{
			value:                 normalizeName(metadata.Vendor),
			disallowSubSelections: true,
		})
	}

	return vendors
}
