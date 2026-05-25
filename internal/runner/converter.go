package runner

import (
	"github.com/irify/irify-benchmark/pkg/schema"
)

// Converter transforms a raw engine output (JSON) into the canonical FindingSet.
type Converter interface {
	// Detect quickly checks whether the raw data is in a format this converter handles.
	Detect(data []byte) bool

	// Convert parses the raw data and produces a canonical FindingSet.
	Convert(data []byte) (*schema.FindingSet, error)
}
