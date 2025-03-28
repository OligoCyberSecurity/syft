package main

import (
	"fmt"
	"os"

	"github.com/dave/jennifer/jen"

	"github.com/oligocybersecurity/syft/syft/internal/sourcemetadata"
)

// This program is invoked from syft/internal and generates sourcemetadata/generated.go

const (
	srcImport = "github.com/oligocybersecurity/syft/syft/source"
	path      = "sourcemetadata/generated.go"
)

func main() {
	typeNames, err := sourcemetadata.DiscoverTypeNames()
	if err != nil {
		panic(fmt.Errorf("unable to get all metadata type names: %w", err))
	}

	fmt.Printf("updating source metadata type list with %+v types\n", len(typeNames))

	f := jen.NewFile("sourcemetadata")
	f.HeaderComment("DO NOT EDIT: generated by syft/internal/sourcemetadata/generate/main.go")
	f.ImportName(srcImport, "source")
	f.Comment("AllTypes returns a list of all source metadata types that syft supports (that are represented in the source.Description.Metadata field).")

	f.Func().Id("AllTypes").Params().Index().Any().BlockFunc(func(g *jen.Group) {
		g.ReturnFunc(func(g *jen.Group) {
			g.Index().Any().ValuesFunc(func(g *jen.Group) {
				for _, typeName := range typeNames {
					g.Qual(srcImport, typeName).Values()
				}
			})
		})
	})

	rendered := fmt.Sprintf("%#v", f)

	fh, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		panic(fmt.Errorf("unable to open file: %w", err))
	}
	_, err = fh.WriteString(rendered)
	if err != nil {
		panic(fmt.Errorf("unable to write file: %w", err))
	}
	if err := fh.Close(); err != nil {
		panic(fmt.Errorf("unable to close file: %w", err))
	}
}
