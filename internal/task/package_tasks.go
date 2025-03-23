package task

import (
	"github.com/oligocybersecurity/syft/syft/cataloging/pkgcataloging"
	"github.com/oligocybersecurity/syft/syft/pkg"
	"github.com/oligocybersecurity/syft/syft/pkg/cataloger/alpine"
	"github.com/oligocybersecurity/syft/syft/pkg/cataloger/arch"
	"github.com/oligocybersecurity/syft/syft/pkg/cataloger/binary"
	"github.com/oligocybersecurity/syft/syft/pkg/cataloger/cpp"
	"github.com/oligocybersecurity/syft/syft/pkg/cataloger/dart"
	"github.com/oligocybersecurity/syft/syft/pkg/cataloger/debian"
	"github.com/oligocybersecurity/syft/syft/pkg/cataloger/dotnet"
	"github.com/oligocybersecurity/syft/syft/pkg/cataloger/elixir"
	"github.com/oligocybersecurity/syft/syft/pkg/cataloger/erlang"
	"github.com/oligocybersecurity/syft/syft/pkg/cataloger/gentoo"
	"github.com/oligocybersecurity/syft/syft/pkg/cataloger/githubactions"
	"github.com/oligocybersecurity/syft/syft/pkg/cataloger/golang"
	"github.com/oligocybersecurity/syft/syft/pkg/cataloger/haskell"
	"github.com/oligocybersecurity/syft/syft/pkg/cataloger/java"
	"github.com/oligocybersecurity/syft/syft/pkg/cataloger/javascript"
	"github.com/oligocybersecurity/syft/syft/pkg/cataloger/kernel"
	"github.com/oligocybersecurity/syft/syft/pkg/cataloger/lua"
	"github.com/oligocybersecurity/syft/syft/pkg/cataloger/nix"
	"github.com/oligocybersecurity/syft/syft/pkg/cataloger/ocaml"
	"github.com/oligocybersecurity/syft/syft/pkg/cataloger/php"
	"github.com/oligocybersecurity/syft/syft/pkg/cataloger/python"
	"github.com/oligocybersecurity/syft/syft/pkg/cataloger/r"
	"github.com/oligocybersecurity/syft/syft/pkg/cataloger/redhat"
	"github.com/oligocybersecurity/syft/syft/pkg/cataloger/ruby"
	"github.com/oligocybersecurity/syft/syft/pkg/cataloger/rust"
	sbomCataloger "github.com/oligocybersecurity/syft/syft/pkg/cataloger/sbom"
	"github.com/oligocybersecurity/syft/syft/pkg/cataloger/swift"
	"github.com/oligocybersecurity/syft/syft/pkg/cataloger/swipl"
	"github.com/oligocybersecurity/syft/syft/pkg/cataloger/wordpress"
)

const (
	// Java ecosystem labels
	Java  = "java"
	Maven = "maven"

	// Go ecosystem labels
	Go     = "go"
	Golang = "golang"

	// JavaScript ecosystem labels
	JavaScript = "javascript"
	Node       = "node"
	NPM        = "npm"
)

//nolint:funlen
func DefaultPackageTaskFactories() PackageTaskFactories {
	return []packageTaskFactory{
		// OS package installed catalogers ///////////////////////////////////////////////////////////////////////////
		newSimplePackageTaskFactory(arch.NewDBCataloger, pkgcataloging.DirectoryTag, pkgcataloging.InstalledTag, pkgcataloging.ImageTag, pkgcataloging.OSTag, "linux", "alpm", "archlinux"),
		newSimplePackageTaskFactory(alpine.NewDBCataloger, pkgcataloging.DirectoryTag, pkgcataloging.InstalledTag, pkgcataloging.ImageTag, pkgcataloging.OSTag, "linux", "apk", "alpine"),
		newSimplePackageTaskFactory(debian.NewDBCataloger, pkgcataloging.DirectoryTag, pkgcataloging.InstalledTag, pkgcataloging.ImageTag, pkgcataloging.OSTag, "linux", "dpkg", "debian"),
		newSimplePackageTaskFactory(gentoo.NewPortageCataloger, pkgcataloging.DirectoryTag, pkgcataloging.InstalledTag, pkgcataloging.ImageTag, pkgcataloging.OSTag, "linux", "portage", "gentoo"),
		newSimplePackageTaskFactory(redhat.NewDBCataloger, pkgcataloging.DirectoryTag, pkgcataloging.InstalledTag, pkgcataloging.ImageTag, pkgcataloging.OSTag, "linux", "rpm", "redhat"),

		// OS package declared catalogers ///////////////////////////////////////////////////////////////////////////
		newSimplePackageTaskFactory(redhat.NewArchiveCataloger, pkgcataloging.DeclaredTag, pkgcataloging.DirectoryTag, pkgcataloging.OSTag, "linux", "rpm", "redhat"),

		// language-specific package installed catalogers ///////////////////////////////////////////////////////////////////////////
		newSimplePackageTaskFactory(cpp.NewConanInfoCataloger, pkgcataloging.InstalledTag, pkgcataloging.ImageTag, pkgcataloging.LanguageTag, "cpp", "conan"),
		newSimplePackageTaskFactory(javascript.NewPackageCataloger, pkgcataloging.InstalledTag, pkgcataloging.ImageTag, pkgcataloging.LanguageTag, JavaScript, Node),
		newSimplePackageTaskFactory(php.NewComposerInstalledCataloger, pkgcataloging.InstalledTag, pkgcataloging.ImageTag, pkgcataloging.LanguageTag, "php", "composer"),
		newSimplePackageTaskFactory(r.NewPackageCataloger, pkgcataloging.InstalledTag, pkgcataloging.ImageTag, pkgcataloging.LanguageTag, "r"),
		newSimplePackageTaskFactory(ruby.NewInstalledGemSpecCataloger, pkgcataloging.InstalledTag, pkgcataloging.ImageTag, pkgcataloging.LanguageTag, "ruby", "gem", "gemspec"),
		newSimplePackageTaskFactory(rust.NewAuditBinaryCataloger, pkgcataloging.InstalledTag, pkgcataloging.ImageTag, pkgcataloging.LanguageTag, "rust", "binary"),

		// language-specific package declared catalogers ///////////////////////////////////////////////////////////////////////////
		newSimplePackageTaskFactory(cpp.NewConanCataloger, pkgcataloging.DeclaredTag, pkgcataloging.DirectoryTag, pkgcataloging.LanguageTag, "cpp", "conan"),
		newSimplePackageTaskFactory(dart.NewPubspecLockCataloger, pkgcataloging.DeclaredTag, pkgcataloging.DirectoryTag, pkgcataloging.LanguageTag, "dart"),
		newSimplePackageTaskFactory(dotnet.NewDotnetDepsCataloger, pkgcataloging.DeclaredTag, pkgcataloging.DirectoryTag, pkgcataloging.LanguageTag, "dotnet", "c#"),
		newSimplePackageTaskFactory(elixir.NewMixLockCataloger, pkgcataloging.DeclaredTag, pkgcataloging.DirectoryTag, pkgcataloging.LanguageTag, "elixir"),
		newSimplePackageTaskFactory(erlang.NewRebarLockCataloger, pkgcataloging.DeclaredTag, pkgcataloging.DirectoryTag, pkgcataloging.LanguageTag, "erlang"),
		newSimplePackageTaskFactory(erlang.NewOTPCataloger, pkgcataloging.DeclaredTag, pkgcataloging.DirectoryTag, pkgcataloging.LanguageTag, "erlang", "otp"),
		newSimplePackageTaskFactory(haskell.NewHackageCataloger, pkgcataloging.DeclaredTag, pkgcataloging.DirectoryTag, pkgcataloging.LanguageTag, "haskell", "hackage", "cabal"),
		newPackageTaskFactory(
			func(cfg CatalogingFactoryConfig) pkg.Cataloger {
				return golang.NewGoModuleFileCataloger(cfg.PackagesConfig.Golang)
			},
			pkgcataloging.DeclaredTag, pkgcataloging.DirectoryTag, pkgcataloging.LanguageTag, Go, Golang, "gomod",
		),
		newSimplePackageTaskFactory(java.NewGradleLockfileCataloger, pkgcataloging.DeclaredTag, pkgcataloging.DirectoryTag, pkgcataloging.LanguageTag, Java, "gradle"),
		newPackageTaskFactory(
			func(cfg CatalogingFactoryConfig) pkg.Cataloger {
				return java.NewPomCataloger(cfg.PackagesConfig.JavaArchive)
			},
			pkgcataloging.DeclaredTag, pkgcataloging.DirectoryTag, pkgcataloging.LanguageTag, Java, Maven,
		),
		newPackageTaskFactory(
			func(cfg CatalogingFactoryConfig) pkg.Cataloger {
				return javascript.NewLockCataloger(cfg.PackagesConfig.JavaScript)
			},
			pkgcataloging.DeclaredTag, pkgcataloging.DirectoryTag, pkgcataloging.LanguageTag, JavaScript, Node, NPM,
		),
		newSimplePackageTaskFactory(php.NewComposerLockCataloger, pkgcataloging.DeclaredTag, pkgcataloging.DirectoryTag, pkgcataloging.LanguageTag, "php", "composer"),
		newSimplePackageTaskFactory(php.NewPeclCataloger, pkgcataloging.DeclaredTag, pkgcataloging.DirectoryTag, pkgcataloging.LanguageTag, pkgcataloging.ImageTag, "php", "pecl"),
		newPackageTaskFactory(
			func(cfg CatalogingFactoryConfig) pkg.Cataloger {
				return python.NewPackageCataloger(cfg.PackagesConfig.Python)
			},
			pkgcataloging.DeclaredTag, pkgcataloging.DirectoryTag, pkgcataloging.LanguageTag, "python",
		),
		newSimplePackageTaskFactory(ruby.NewGemFileLockCataloger, pkgcataloging.DeclaredTag, pkgcataloging.DirectoryTag, pkgcataloging.LanguageTag, "ruby", "gem"),
		newSimplePackageTaskFactory(ruby.NewGemSpecCataloger, pkgcataloging.DeclaredTag, pkgcataloging.DirectoryTag, pkgcataloging.LanguageTag, "ruby", "gem", "gemspec"),
		newSimplePackageTaskFactory(rust.NewCargoLockCataloger, pkgcataloging.DeclaredTag, pkgcataloging.DirectoryTag, pkgcataloging.LanguageTag, "rust", "cargo"),
		newSimplePackageTaskFactory(swift.NewCocoapodsCataloger, pkgcataloging.DeclaredTag, pkgcataloging.DirectoryTag, pkgcataloging.LanguageTag, "swift", "cocoapods"),
		newSimplePackageTaskFactory(swift.NewSwiftPackageManagerCataloger, pkgcataloging.DeclaredTag, pkgcataloging.DirectoryTag, pkgcataloging.LanguageTag, "swift", "spm"),
		newSimplePackageTaskFactory(swipl.NewSwiplPackCataloger, pkgcataloging.DeclaredTag, pkgcataloging.DirectoryTag, pkgcataloging.LanguageTag, "swipl", "pack"),
		newSimplePackageTaskFactory(ocaml.NewOpamPackageManagerCataloger, pkgcataloging.DeclaredTag, pkgcataloging.DirectoryTag, pkgcataloging.LanguageTag, "ocaml", "opam"),

		// language-specific package for both image and directory scans (but not necessarily declared) ////////////////////////////////////////
		newSimplePackageTaskFactory(dotnet.NewDotnetPortableExecutableCataloger, pkgcataloging.DirectoryTag, pkgcataloging.InstalledTag, pkgcataloging.ImageTag, pkgcataloging.LanguageTag, "dotnet", "c#", "binary"),
		newSimplePackageTaskFactory(python.NewInstalledPackageCataloger, pkgcataloging.DirectoryTag, pkgcataloging.InstalledTag, pkgcataloging.ImageTag, pkgcataloging.LanguageTag, "python"),
		newPackageTaskFactory(
			func(cfg CatalogingFactoryConfig) pkg.Cataloger {
				return golang.NewGoModuleBinaryCataloger(cfg.PackagesConfig.Golang)
			},
			pkgcataloging.DirectoryTag, pkgcataloging.InstalledTag, pkgcataloging.ImageTag, pkgcataloging.LanguageTag, Go, Golang, "gomod", "binary",
		),
		newPackageTaskFactory(
			func(cfg CatalogingFactoryConfig) pkg.Cataloger {
				return java.NewArchiveCataloger(cfg.PackagesConfig.JavaArchive)
			},
			pkgcataloging.DirectoryTag, pkgcataloging.InstalledTag, pkgcataloging.ImageTag, pkgcataloging.LanguageTag, Java, Maven,
		),
		newSimplePackageTaskFactory(java.NewNativeImageCataloger, pkgcataloging.DirectoryTag, pkgcataloging.InstalledTag, pkgcataloging.ImageTag, pkgcataloging.LanguageTag, Java),
		newSimplePackageTaskFactory(nix.NewStoreCataloger, pkgcataloging.DirectoryTag, pkgcataloging.InstalledTag, pkgcataloging.ImageTag, pkgcataloging.LanguageTag, "nix"),
		newSimplePackageTaskFactory(lua.NewPackageCataloger, pkgcataloging.DirectoryTag, pkgcataloging.InstalledTag, pkgcataloging.ImageTag, pkgcataloging.LanguageTag, "lua"),

		// other package catalogers ///////////////////////////////////////////////////////////////////////////
		newPackageTaskFactory(
			func(cfg CatalogingFactoryConfig) pkg.Cataloger {
				return binary.NewClassifierCataloger(cfg.PackagesConfig.Binary)
			},
			pkgcataloging.DeclaredTag, pkgcataloging.DirectoryTag, pkgcataloging.InstalledTag, pkgcataloging.ImageTag, "binary",
		),
		newSimplePackageTaskFactory(binary.NewELFPackageCataloger, pkgcataloging.DeclaredTag, pkgcataloging.DirectoryTag, pkgcataloging.InstalledTag, pkgcataloging.ImageTag, "binary", "elf-package"),
		newSimplePackageTaskFactory(githubactions.NewActionUsageCataloger, pkgcataloging.DeclaredTag, pkgcataloging.DirectoryTag, "github", "github-actions"),
		newSimplePackageTaskFactory(githubactions.NewWorkflowUsageCataloger, pkgcataloging.DeclaredTag, pkgcataloging.DirectoryTag, "github", "github-actions"),
		newSimplePackageTaskFactory(java.NewJvmDistributionCataloger, pkgcataloging.DeclaredTag, pkgcataloging.DirectoryTag, pkgcataloging.InstalledTag, pkgcataloging.ImageTag, "java", "jvm", "jdk", "jre"),
		newPackageTaskFactory(
			func(cfg CatalogingFactoryConfig) pkg.Cataloger {
				return kernel.NewLinuxKernelCataloger(cfg.PackagesConfig.LinuxKernel)
			},
			pkgcataloging.DeclaredTag, pkgcataloging.DirectoryTag, pkgcataloging.InstalledTag, pkgcataloging.ImageTag, "linux", "kernel",
		),
		newSimplePackageTaskFactory(sbomCataloger.NewCataloger, "sbom"), // note: not evidence of installed packages
		newSimplePackageTaskFactory(wordpress.NewWordpressPluginCataloger, pkgcataloging.DirectoryTag, pkgcataloging.ImageTag, "wordpress"),
	}
}
