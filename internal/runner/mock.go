package runner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/irify/irify-benchmark/pkg/engine"
	"github.com/irify/irify-benchmark/pkg/schema"
)

// MockEngine is a test-double engine that returns pre-canned findings.
type MockEngine struct {
	FixturePath string // path to a JSON file to return as findings
}

// Name returns the engine identifier.
func (m *MockEngine) Name() string {
	return "mock"
}

// Version returns a static version string.
func (m *MockEngine) Version(ctx context.Context) (string, error) {
	return "1.0.0", nil
}

// Scan returns findings loaded from FixturePath, or an empty FindingSet if
// no fixture is configured.
func (m *MockEngine) Scan(ctx context.Context, req engine.ScanRequest) (*schema.FindingSet, error) {
	if m.FixturePath != "" {
		data, err := os.ReadFile(m.FixturePath)
		if err != nil {
			return nil, fmt.Errorf("mock engine read fixture: %w", err)
		}
		var fs schema.FindingSet
		if err := json.Unmarshal(data, &fs); err != nil {
			return nil, fmt.Errorf("mock engine unmarshal fixture: %w", err)
		}
		if fs.Engine == "" {
			fs.Engine = m.Name()
		}
		if fs.EngineVersion == "" {
			fs.EngineVersion = "1.0.0"
		}
		if fs.ScanTime.IsZero() {
			fs.ScanTime = time.Now().UTC()
		}
		return &fs, nil
	}
	return &schema.FindingSet{
		Engine:        m.Name(),
		EngineVersion: "1.0.0",
		ScanTime:      time.Now().UTC(),
		Findings:      []schema.Finding{},
	}, nil
}
