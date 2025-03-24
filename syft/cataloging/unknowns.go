package cataloging

import "github.com/oligocybersecurity/syft/internal/unknown"

type UnknownsConfig struct {
	RemoveWhenPackagesDefined         bool
	IncludeExecutablesWithoutPackages bool
	IncludeUnexpandedArchives         bool
}

func DefaultUnknownsConfig() UnknownsConfig {
	return UnknownsConfig{
		RemoveWhenPackagesDefined:         true,
		IncludeExecutablesWithoutPackages: true,
		IncludeUnexpandedArchives:         true,
	}
}

func ExtractCoordinateErrors(err error) (coordinateErrors []unknown.CoordinateError, remainingErrors error) {
	return unknown.ExtractCoordinateErrors(err)
}
