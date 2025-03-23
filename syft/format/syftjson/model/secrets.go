package model

import (
	"github.com/oligocybersecurity/syft/syft/file"
)

type Secrets struct {
	Location file.Coordinates    `json:"location"`
	Secrets  []file.SearchResult `json:"secrets"`
}
