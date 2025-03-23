package format

import (
	"io"

	"github.com/oligocybersecurity/syft/syft/format/cyclonedxjson"
	"github.com/oligocybersecurity/syft/syft/format/cyclonedxxml"
	"github.com/oligocybersecurity/syft/syft/format/spdxjson"
	"github.com/oligocybersecurity/syft/syft/format/spdxtagvalue"
	"github.com/oligocybersecurity/syft/syft/format/syftjson"
	"github.com/oligocybersecurity/syft/syft/sbom"
)

var staticDecoders sbom.FormatDecoder

func init() {
	staticDecoders = NewDecoderCollection(Decoders()...)
}

func Decoders() []sbom.FormatDecoder {
	return []sbom.FormatDecoder{
		syftjson.NewFormatDecoder(),
		cyclonedxxml.NewFormatDecoder(),
		cyclonedxjson.NewFormatDecoder(),
		spdxtagvalue.NewFormatDecoder(),
		spdxjson.NewFormatDecoder(),
	}
}

// Identify takes a set of bytes and attempts to identify the format of the SBOM.
func Identify(reader io.Reader) (sbom.FormatID, string) {
	return staticDecoders.Identify(reader)
}

// Decode takes a set of bytes and attempts to decode it into an SBOM.
func Decode(reader io.Reader) (*sbom.SBOM, sbom.FormatID, string, error) {
	return staticDecoders.Decode(reader)
}
