package commands

import (
	"github.com/spf13/cobra"

	"github.com/oligocybersecurity/syft/syft/pkg/cataloger/binary/test-fixtures/manager/internal/config"
)

func Root(_ config.Application) *cobra.Command {
	return &cobra.Command{
		Use:   "manager",
		Short: "manager is a tool for managing binaries and snippets",
	}
}
