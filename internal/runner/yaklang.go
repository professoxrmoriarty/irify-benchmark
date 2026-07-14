package runner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/irify/irify-benchmark/pkg/engine"
	"github.com/irify/irify-benchmark/pkg/schema"
)

// YaklangEngine wraps the yak CLI to perform code scans.
type YaklangEngine struct {
	BinaryPath string // path to `yak` binary; defaults to "yak"
}

// NewYaklangEngine creates a YaklangEngine with the given binary path.
// If binaryPath is empty, it attempts to locate a bundled binary or falls
// back to "yak" in PATH.
func NewYaklangEngine(binaryPath string) *YaklangEngine {
	if binaryPath == "" {
		binaryPath = resolveYaklangPath()
	}
	return &YaklangEngine{BinaryPath: binaryPath}
}

// resolveYaklangPath searches for the yak binary in common bundled locations
// relative to the executable, then the current working directory, and finally
// falls back to PATH.
func resolveYaklangPath() string {
	// 1. Check bundled binary relative to executable
	exe, err := os.Executable()
	if err == nil {
		exeDir := filepath.Dir(exe)
		candidates := []string{
			filepath.Join(exeDir, "yak"),
			filepath.Join(exeDir, "..", "bin", "yak"),
			filepath.Join(exeDir, "..", "..", "bin", "yak"),
		}
		for _, c := range candidates {
			if info, err := os.Stat(c); err == nil && !info.IsDir() {
				abs, _ := filepath.Abs(c)
				return abs
			}
		}
	}

	// 2. Check current working directory
	if info, err := os.Stat("bin/yak"); err == nil && !info.IsDir() {
		abs, _ := filepath.Abs("bin/yak")
		return abs
	}

	// 3. Fallback to PATH
	if path, err := exec.LookPath("yak"); err == nil {
		return path
	}

	return "yak"
}

// Name returns the engine identifier.
func (e *YaklangEngine) Name() string {
	return "yaklang"
}

// Version runs `yak --version` and parses the version string.
// If the command fails, it returns "unknown".
func (e *YaklangEngine) Version(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(ctx, e.BinaryPath, "--version")
	out, err := cmd.Output()
	if err != nil {
		return "unknown", nil // Graceful fallback
	}
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "yak version") {
			return line, nil
		}
	}
	// Fallback to last non-empty line that doesn't start with [
	var lastValid string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "[") {
			lastValid = line
		}
	}
	if lastValid != "" {
		return lastValid, nil
	}
	return "unknown", nil
}

// Scan executes `yak code-scan` against the requested source path, reads the
// generated JSON output, and converts it to a canonical FindingSet.
func (e *YaklangEngine) Scan(ctx context.Context, req engine.ScanRequest) (*schema.FindingSet, error) {
	outputPath := req.OutputPath
	if outputPath == "" {
		tempFile, err := os.CreateTemp("", "yak-scan-*.json")
		if err != nil {
			return nil, fmt.Errorf("create temp file: %w", err)
		}
		outputPath = tempFile.Name()
		tempFile.Close()
		defer os.Remove(outputPath)
	} else {
		// Ensure output directory exists.
		if err := os.MkdirAll(filepath.Dir(outputPath), 0755); err != nil {
			return nil, fmt.Errorf("create output directory: %w", err)
		}
	}

	args := []string{"code-scan", "--target", req.SourcePath}
	args = append(args, "--output", outputPath)
	args = append(args, "--format", "irify", "--with-dataflow-path", "--memory")
	if req.Language != "" {
		args = append(args, "--language", req.Language)
	}
	if req.ConfigPath != "" {
		args = append(args, "--config", req.ConfigPath)
	}
	for k, v := range req.ExtraArgs {
		args = append(args, fmt.Sprintf("--%s", k), v)
	}

	cmd := exec.CommandContext(ctx, e.BinaryPath, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("yak scan failed: %w", err)
	}

	data, err := os.ReadFile(outputPath)
	if err != nil {
		return nil, fmt.Errorf("read yak output: %w", err)
	}

	findingSet, err := e.parseOutput(data)
	if err != nil {
		return nil, fmt.Errorf("parse yak output: %w", err)
	}

	// Preserve original report bytes for debugging / download.
	findingSet.RawReport = data

	// Enrich metadata.
	findingSet.Engine = e.Name()
	if findingSet.EngineVersion == "" {
		if v, err := e.Version(ctx); err == nil {
			findingSet.EngineVersion = v
		}
	}
	if findingSet.ScanTime.IsZero() {
		findingSet.ScanTime = time.Now().UTC()
	}
	if findingSet.ProgramName == "" {
		findingSet.ProgramName = filepath.Base(req.SourcePath)
	}

	return findingSet, nil
}

// parseOutput attempts to unmarshal yak output into a FindingSet.
// It tries converters in order: canonical schema → irify format → flexible fallback.
func (e *YaklangEngine) parseOutput(data []byte) (*schema.FindingSet, error) {
	// Attempt 1: direct unmarshal into canonical schema.
	var direct schema.FindingSet
	if err := json.Unmarshal(data, &direct); err == nil && len(direct.Findings) > 0 {
		return &direct, nil
	}

	// Attempt 2: yak --format irify converter.
	irifyConv := &IrifyConverter{}
	if irifyConv.Detect(data) {
		return irifyConv.Convert(data)
	}

	// Attempt 3: flexible parsing via intermediate representation.
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("unmarshal yak output as JSON: %w", err)
	}

	fs := &schema.FindingSet{}
	if v, ok := raw["engine"].(string); ok {
		fs.Engine = v
	}
	if v, ok := raw["engine_version"].(string); ok {
		fs.EngineVersion = v
	}
	if v, ok := raw["program_name"].(string); ok {
		fs.ProgramName = v
	}
	if v, ok := raw["scan_time"].(string); ok {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			fs.ScanTime = t
		}
	}

	findingsRaw, _ := raw["findings"].([]interface{})
	for _, fRaw := range findingsRaw {
		fMap, ok := fRaw.(map[string]interface{})
		if !ok {
			continue
		}
		finding := adaptFinding(fMap)
		fs.Findings = append(fs.Findings, finding)
	}

	return fs, nil
}

// adaptFinding converts a raw map from yak output into a canonical Finding.
func adaptFinding(raw map[string]interface{}) schema.Finding {
	f := schema.Finding{}
	if v, ok := raw["rule_id"].(string); ok {
		f.RuleID = v
	}
	if v, ok := raw["rule_name"].(string); ok {
		f.RuleName = v
	}
	if v, ok := raw["severity"].(string); ok {
		f.Severity = v
	}
	if v, ok := raw["confidence"].(string); ok {
		f.Confidence = v
	}

	// Try to extract flow directly.
	if flowRaw, ok := raw["flow"].(map[string]interface{}); ok {
		f.Flow = adaptFlow(flowRaw)
	} else {
		// Synthesize flow from top-level fields if present.
		f.Flow = synthesizeFlow(raw)
	}

	return f
}

// adaptFlow converts a raw flow map into a canonical Flow.
func adaptFlow(raw map[string]interface{}) *schema.Flow {
	flow := &schema.Flow{}
	if v, ok := raw["source"].(map[string]interface{}); ok {
		flow.Source = adaptLocation(v)
	}
	if v, ok := raw["sink"].(map[string]interface{}); ok {
		flow.Sink = adaptLocation(v)
	}
	if saniRaw, ok := raw["sanitizers"].([]interface{}); ok {
		for _, sRaw := range saniRaw {
			if sMap, ok := sRaw.(map[string]interface{}); ok {
				flow.Sanitizers = append(flow.Sanitizers, adaptSanitizer(sMap))
			}
		}
	}
	return flow
}

// adaptLocation converts a raw location map into a canonical Location.
func adaptLocation(raw map[string]interface{}) *schema.Location {
	loc := &schema.Location{}
	if v, ok := raw["symbol"].(string); ok {
		loc.Symbol = v
	}
	if v, ok := raw["file"].(string); ok {
		loc.File = v
	}
	if v, ok := raw["line"].(float64); ok {
		loc.Line = int(v)
	}
	if v, ok := raw["column"].(float64); ok {
		loc.Column = int(v)
	}
	return loc
}

// adaptSanitizer converts a raw sanitizer map into a canonical Sanitizer.
func adaptSanitizer(raw map[string]interface{}) schema.Sanitizer {
	s := schema.Sanitizer{Location: *adaptLocation(raw)}
	if v, ok := raw["effective"].(bool); ok {
		s.Effective = v
	}
	return s
}

// synthesizeFlow attempts to build a Flow from flat fields commonly present
// in yak output when a structured flow object is not emitted.
func synthesizeFlow(raw map[string]interface{}) *schema.Flow {
	flow := &schema.Flow{}

	// Common field names observed in yak output.
	source := &schema.Location{}
	sink := &schema.Location{}
	hasSource, hasSink := false, false

	if v, ok := raw["source_file"].(string); ok {
		source.File = v
		hasSource = true
	}
	if v, ok := raw["source_line"].(float64); ok {
		source.Line = int(v)
		hasSource = true
	}
	if v, ok := raw["source_column"].(float64); ok {
		source.Column = int(v)
		hasSource = true
	}
	if v, ok := raw["source_symbol"].(string); ok {
		source.Symbol = v
		hasSource = true
	}

	if v, ok := raw["sink_file"].(string); ok {
		sink.File = v
		hasSink = true
	}
	if v, ok := raw["sink_line"].(float64); ok {
		sink.Line = int(v)
		hasSink = true
	}
	if v, ok := raw["sink_column"].(float64); ok {
		sink.Column = int(v)
		hasSink = true
	}
	if v, ok := raw["sink_symbol"].(string); ok {
		sink.Symbol = v
		hasSink = true
	}

	if hasSource {
		flow.Source = source
	}
	if hasSink {
		flow.Sink = sink
	}
	if !hasSource && !hasSink {
		return nil
	}
	return flow
}
