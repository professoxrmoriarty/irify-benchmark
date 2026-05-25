// Package runner provides engine implementations that execute static analysis
// tools and adapt their outputs to the canonical schema.FindingSet format.
package runner

import (
	"github.com/irify/irify-benchmark/pkg/engine"
)

// Compile-time interface checks.
var _ engine.Engine = (*YaklangEngine)(nil)
var _ engine.Engine = (*MockEngine)(nil)
