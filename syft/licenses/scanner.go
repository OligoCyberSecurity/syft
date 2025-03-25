/*
This file exports certain internal functions in Syft
*/
package licenses

import (
	"context"

	"github.com/oligocybersecurity/syft/internal/licenses"
)

func NewDefaultScanner(o ...licenses.Option) (licenses.Scanner, error) {
	return licenses.NewDefaultScanner(o...)
}

func SetContextLicenseScanner(ctx context.Context, s licenses.Scanner) context.Context {
	return licenses.SetContextLicenseScanner(ctx, s)
}
