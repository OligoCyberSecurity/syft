package helpers

import (
	"crypto/sha256"
	"fmt"
	"strings"

	"github.com/oligocybersecurity/syft/internal/licenses"
	"github.com/oligocybersecurity/syft/internal/spdxlicense"
	"github.com/oligocybersecurity/syft/syft/license"
	"github.com/oligocybersecurity/syft/syft/pkg"
)

func License(p pkg.Package) (concluded, declared string) {
	// source: https://spdx.github.io/spdx-spec/v2.3/package-information/#713-concluded-license-field
	// The options to populate this field are limited to:
	// A valid SPDX License Expression as defined in Annex D;
	// NONE, if the SPDX file creator concludes there is no license available for this package; or
	// NOASSERTION if:
	//   (i) the SPDX file creator has attempted to but cannot reach a reasonable objective determination;
	//   (ii) the SPDX file creator has made no attempt to determine this field; or
	//   (iii) the SPDX file creator has intentionally provided no information (no meaning should be implied by doing so).

	if p.Licenses.Empty() {
		return NOASSERTION, NOASSERTION
	}

	// take all licenses and assume an AND expression;
	// for information about license expressions see:
	// https://spdx.github.io/spdx-spec/v2.3/SPDX-license-expressions/
	pc, pd := ParseLicenses(p.Licenses.ToSlice())

	return joinLicenses(pc), joinLicenses(pd)
}

func joinLicenses(licenses []SPDXLicense) string {
	if len(licenses) == 0 {
		return NOASSERTION
	}

	var newLicenses []string

	for _, l := range licenses {
		v := l.ID
		// check if license does not start or end with parens
		if !strings.HasPrefix(v, "(") && !strings.HasSuffix(v, ")") {
			// if license contains AND, OR, or WITH, then wrap in parens
			if strings.Contains(v, " AND ") ||
				strings.Contains(v, " OR ") ||
				strings.Contains(v, " WITH ") {
				newLicenses = append(newLicenses, "("+v+")")
				continue
			}
		}
		newLicenses = append(newLicenses, v)
	}

	return strings.Join(newLicenses, " AND ")
}

type SPDXLicense struct {
	ID    string
	Value string
}

func ParseLicenses(raw []pkg.License) (concluded, declared []SPDXLicense) {
	for _, l := range raw {
		if l.Value == "" {
			continue
		}

		candidate := SPDXLicense{}
		if l.SPDXExpression != "" && !strings.HasPrefix(l.SPDXExpression, licenses.UnknownLicensePrefix) {
			candidate.ID = l.SPDXExpression
		} else {
			candidate.Value = l.Value
			// we did not find a valid SPDX license ID so treat as separate license
			if strings.HasPrefix(l.SPDXExpression, licenses.UnknownLicensePrefix) {
				candidate.ID = spdxlicense.LicenseRefPrefix + SanitizeElementID(l.SPDXExpression)
				if len(l.Contents) > 0 {
					candidate.Value = l.Contents
				}
			} else {
				if len(l.Value) <= 64 {
					// if the license text is less than the size of the hash,
					// just use it directly so the id is more readable
					candidate.ID = spdxlicense.LicenseRefPrefix + SanitizeElementID(l.Value)
				} else {
					hash := sha256.Sum256([]byte(l.Value))
					candidate.ID = fmt.Sprintf("%s%x", spdxlicense.LicenseRefPrefix, hash)
				}
			}
		}

		switch l.Type {
		case license.Concluded:
			concluded = append(concluded, candidate)
		case license.Declared:
			declared = append(declared, candidate)
		}
	}

	return concluded, declared
}
