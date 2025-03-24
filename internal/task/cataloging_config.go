package task

import (
	"github.com/oligocybersecurity/syft/syft/cataloging"
	"github.com/oligocybersecurity/syft/syft/cataloging/filecataloging"
	"github.com/oligocybersecurity/syft/syft/cataloging/pkgcataloging"
)

type CatalogingFactoryConfig struct {
	ComplianceConfig     cataloging.ComplianceConfig
	SearchConfig         cataloging.SearchConfig
	RelationshipsConfig  cataloging.RelationshipsConfig
	DataGenerationConfig cataloging.DataGenerationConfig
	LicenseConfig        cataloging.LicenseConfig
	PackagesConfig       pkgcataloging.Config
	FilesConfig          filecataloging.Config
}

func DefaultCatalogingFactoryConfig() CatalogingFactoryConfig {
	return CatalogingFactoryConfig{
		ComplianceConfig:     cataloging.DefaultComplianceConfig(),
		SearchConfig:         cataloging.DefaultSearchConfig(),
		RelationshipsConfig:  cataloging.DefaultRelationshipsConfig(),
		DataGenerationConfig: cataloging.DefaultDataGenerationConfig(),
		LicenseConfig:        cataloging.DefaultLicenseConfig(),
		PackagesConfig:       pkgcataloging.DefaultConfig(),
		FilesConfig:          filecataloging.DefaultConfig(),
	}
}
