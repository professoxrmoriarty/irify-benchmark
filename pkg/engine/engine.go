package engine

import (
	"context"

	"github.com/irify/irify-benchmark/pkg/schema"
)

// Engine is the abstraction for static analysis engines that can scan source code.
type Engine interface {
	// Scan runs the engine against the source code and returns findings.
	Scan(ctx context.Context, req ScanRequest) (*schema.FindingSet, error)

	// Version returns the engine version string.
	Version(ctx context.Context) (string, error)

	// Name returns the engine identifier.
	Name() string
}

// ScanRequest carries the parameters for an engine scan.
type ScanRequest struct {
	SourcePath string            // Path to source file or directory
	Language   string            // Target language
	ConfigPath string            // Optional engine config
	OutputPath string            // Where engine should write its raw output
	ExtraArgs  map[string]string // Engine-specific arguments
}
