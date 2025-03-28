package syft

import (
	"context"
	"fmt"
	"sort"

	"github.com/dustin/go-humanize"
	"github.com/scylladb/go-set/strset"

	"github.com/oligocybersecurity/syft/internal/bus"
	"github.com/oligocybersecurity/syft/internal/licenses"
	"github.com/oligocybersecurity/syft/internal/sbomsync"
	"github.com/oligocybersecurity/syft/internal/task"
	"github.com/oligocybersecurity/syft/syft/artifact"
	"github.com/oligocybersecurity/syft/syft/event/monitor"
	"github.com/oligocybersecurity/syft/syft/pkg"
	"github.com/oligocybersecurity/syft/syft/sbom"
	"github.com/oligocybersecurity/syft/syft/source"
)

// CreateSBOM creates a software bill-of-materials from the given source. If the CreateSBOMConfig is nil, then
// default options will be used.
func CreateSBOM(ctx context.Context, src source.Source, cfg *CreateSBOMConfig) (*sbom.SBOM, error) {
	if cfg == nil {
		cfg = DefaultCreateSBOMConfig()
	}
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	srcMetadata := src.Describe()

	taskGroups, audit, err := cfg.makeTaskGroups(srcMetadata)
	if err != nil {
		return nil, err
	}

	resolver, err := src.FileResolver(cfg.Search.Scope)
	if err != nil {
		return nil, fmt.Errorf("unable to get file resolver: %w", err)
	}

	s := sbom.SBOM{
		Source: srcMetadata,
		Descriptor: sbom.Descriptor{
			Name:    cfg.ToolName,
			Version: cfg.ToolVersion,
			Configuration: configurationAuditTrail{
				Search:         cfg.Search,
				Relationships:  cfg.Relationships,
				DataGeneration: cfg.DataGeneration,
				Packages:       cfg.Packages,
				Files:          cfg.Files,
				Licenses:       cfg.Licenses,
				Catalogers:     *audit,
				ExtraConfigs:   cfg.ToolConfiguration,
			},
		},
		Artifacts: sbom.Artifacts{
			Packages: pkg.NewCollection(),
		},
	}

	// inject a single license scanner and content config for all package cataloging tasks into context
	licenseScanner, err := licenses.NewDefaultScanner(
		licenses.WithIncludeLicenseContent(cfg.Licenses.IncludeUnkownLicenseContent),
		licenses.WithCoverage(cfg.Licenses.Coverage),
	)
	if err != nil {
		return nil, fmt.Errorf("could not build licenseScanner for cataloging: %w", err)
	}
	ctx = licenses.SetContextLicenseScanner(ctx, licenseScanner)

	catalogingProgress := monitorCatalogingTask(src.ID(), taskGroups)
	packageCatalogingProgress := monitorPackageCatalogingTask()

	builder := sbomsync.NewBuilder(&s, monitorPackageCount(packageCatalogingProgress))
	for i := range taskGroups {
		err := task.NewTaskExecutor(taskGroups[i], cfg.Parallelism).Execute(ctx, resolver, builder, catalogingProgress)
		if err != nil {
			// TODO: tie this to the open progress monitors...
			return nil, fmt.Errorf("failed to run tasks: %w", err)
		}
	}

	packageCatalogingProgress.SetCompleted()
	catalogingProgress.SetCompleted()

	return &s, nil
}

func monitorPackageCount(prog *monitor.CatalogerTaskProgress) func(s *sbom.SBOM) {
	return func(s *sbom.SBOM) {
		count := humanize.Comma(int64(s.Artifacts.Packages.PackageCount()))
		prog.AtomicStage.Set(fmt.Sprintf("%s packages", count))
	}
}

func monitorPackageCatalogingTask() *monitor.CatalogerTaskProgress {
	info := monitor.GenericTask{
		Title: monitor.Title{
			Default: "Packages",
		},
		ID:            monitor.PackageCatalogingTaskID,
		HideOnSuccess: false,
		ParentID:      monitor.TopLevelCatalogingTaskID,
	}

	return bus.StartCatalogerTask(info, -1, "")
}

func monitorCatalogingTask(srcID artifact.ID, tasks [][]task.Task) *monitor.CatalogerTaskProgress {
	info := monitor.GenericTask{
		Title: monitor.Title{
			Default:      "Catalog contents",
			WhileRunning: "Cataloging contents",
			OnSuccess:    "Cataloged contents",
		},
		ID:            monitor.TopLevelCatalogingTaskID,
		Context:       string(srcID),
		HideOnSuccess: false,
	}

	var length int64
	for _, tg := range tasks {
		length += int64(len(tg))
	}

	return bus.StartCatalogerTask(info, length, "")
}

func formatTaskNames(tasks []task.Task) []string {
	set := strset.New()
	for _, td := range tasks {
		if td == nil {
			continue
		}
		set.Add(td.Name())
	}
	list := set.List()
	sort.Strings(list)
	return list
}
