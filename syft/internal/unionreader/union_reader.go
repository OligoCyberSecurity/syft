package unionreader

import (
	"bytes"
	"fmt"
	"io"

	macho "github.com/anchore/go-macholibre"
	"github.com/oligocybersecurity/syft/internal/log"
	"github.com/oligocybersecurity/syft/syft/file"
)

// UnionReader is a single interface with all reading functions needed by multi-arch binary catalogers
// cataloger.
type UnionReader interface {
	io.Reader
	io.ReaderAt
	io.Seeker
	io.Closer
}

// GetReaders extracts one or more io.ReaderAt objects representing binaries that can be processed (multiple binaries in the case for multi-architecture binaries).
func GetReaders(f UnionReader) ([]io.ReaderAt, error) {
	if macho.IsUniversalMachoBinary(f) {
		machoReaders, err := macho.ExtractReaders(f)
		if err != nil {
			log.Debugf("extracting readers: %v", err)
			return nil, err
		}

		var readers []io.ReaderAt
		for _, e := range machoReaders {
			readers = append(readers, e.Reader)
		}

		return readers, nil
	}

	return []io.ReaderAt{f}, nil
}

func GetUnionReader(readerCloser io.ReadCloser) (UnionReader, error) {
	reader, ok := readerCloser.(UnionReader)
	if ok {
		return reader, nil
	}

	// file.LocationReadCloser embeds a ReadCloser, which is likely
	// to implement UnionReader. Check whether the embedded read closer
	// implements UnionReader, and just return that if so.
	r, ok := readerCloser.(file.LocationReadCloser)
	if ok {
		ur, ok := r.ReadCloser.(UnionReader)
		if ok {
			return ur, nil
		}
	}

	b, err := io.ReadAll(readerCloser)
	if err != nil {
		return nil, fmt.Errorf("unable to read contents from binary: %w", err)
	}

	bytesReader := bytes.NewReader(b)

	reader = struct {
		io.ReadCloser
		io.ReaderAt
		io.Seeker
	}{
		ReadCloser: io.NopCloser(bytesReader),
		ReaderAt:   bytesReader,
		Seeker:     bytesReader,
	}

	return reader, nil
}
