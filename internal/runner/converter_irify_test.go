package runner

import (
	"os"
	"testing"
)

// minimalIrifyFixture is a trimmed yak --format irify JSON that exercises all
// conversion branches (with/without data_flow_paths, with/without rule_id lookup).
const minimalIrifyFixture = `{
  "report_type": "irify",
  "engine_version": "1.4.7-beta1",
  "report_time": "2026-05-22T16:27:40.043091442+08:00",
  "program_name": "vuln-demo",
  "program_lang": "java",
  "RiskNums": 2,
  "Rules": [
    {
      "rule_name": "检测Java路径穿越漏洞",
      "rule_id": "7b798768-13e1-4dcd-8ab5-99a6f9635605",
      "severity": "high",
      "language": "java",
      "risks": ["risk-001"]
    },
    {
      "rule_name": "检测Java SpringBoot RestController XSS漏洞",
      "rule_id": "cad09b46-5b0f-4c43-9b43-2b786b9c625f",
      "severity": "middle",
      "language": "java",
      "risks": ["risk-002"]
    }
  ],
  "Risks": {
    "risk-001": {
      "id": 1,
      "hash": "risk-001",
      "title": "Path Traversal",
      "severity": "high",
      "rule_name": "检测Java路径穿越漏洞",
      "code_source_url": "/src/controllers/FileController.java",
      "line": 15,
      "code_range": {
        "url": "/src/controllers/FileController.java",
        "start_line": 15,
        "start_column": 15,
        "end_line": 15,
        "end_column": 48,
        "source_code_line": 15
      },
      "code_fragment": "return new String(Files.readAllBytes(new File(filename).toPath()));",
      "function_name": "download",
      "program_name": "vuln-demo",
      "data_flow_paths": [
        {
          "description": "Data flow for path traversal",
          "nodes": [
            {
              "node_id": "n1",
              "ir_code": "Parameter-filename",
              "source_code": "String filename",
              "code_range": {
                "url": "/src/controllers/FileController.java",
                "start_line": 13,
                "start_column": 48,
                "end_line": 13,
                "end_column": 56,
                "source_code_line": 13
              },
              "is_entry_node": true
            },
            {
              "node_id": "n2",
              "ir_code": "Function-FileController.download",
              "source_code": "public byte[] download",
              "code_range": {
                "url": "/src/controllers/FileController.java",
                "start_line": 13,
                "start_column": 5,
                "end_line": 16,
                "end_column": 6,
                "source_code_line": 13
              },
              "is_entry_node": false
            },
            {
              "node_id": "n3",
              "ir_code": "Files-readAllBytes",
              "source_code": "Files.readAllBytes",
              "code_range": {
                "url": "/src/controllers/FileController.java",
                "start_line": 15,
                "start_column": 27,
                "end_line": 15,
                "end_column": 43,
                "source_code_line": 15
              },
              "is_entry_node": false
            }
          ]
        }
      ]
    },
    "risk-002": {
      "id": 2,
      "hash": "risk-002",
      "title": "XSS",
      "severity": "middle",
      "rule_name": "检测Java SpringBoot RestController XSS漏洞",
      "code_source_url": "/src/controllers/XssController.java",
      "line": 14,
      "code_range": {
        "url": "/src/controllers/XssController.java",
        "start_line": 14,
        "start_column": 12,
        "end_line": 14,
        "end_column": 32,
        "source_code_line": 14
      },
      "code_fragment": "out.write(content);",
      "function_name": "comment",
      "program_name": "vuln-demo"
    }
  },
  "File": [
    {
      "path": "/src/controllers/FileController.java",
      "length": 500,
      "risks": ["risk-001"]
    },
    {
      "path": "/src/controllers/XssController.java",
      "length": 400,
      "risks": ["risk-002"]
    }
  ]
}`

func TestIrifyConverterDetect(t *testing.T) {
	conv := &IrifyConverter{}
	if !conv.Detect([]byte(minimalIrifyFixture)) {
		t.Fatal("expected Detect to return true for irify fixture")
	}
	if conv.Detect([]byte(`{"findings":[]}`)) {
		t.Fatal("expected Detect to return false for canonical schema")
	}
}

func TestIrifyConverterConvert(t *testing.T) {
	conv := &IrifyConverter{}
	fs, err := conv.Convert([]byte(minimalIrifyFixture))
	if err != nil {
		t.Fatalf("convert failed: %v", err)
	}

	if fs.Engine != "yaklang" {
		t.Errorf("engine = %q, want yaklang", fs.Engine)
	}
	if fs.EngineVersion != "1.4.7-beta1" {
		t.Errorf("engine_version = %q, want 1.4.7-beta1", fs.EngineVersion)
	}
	if fs.ProgramName != "vuln-demo" {
		t.Errorf("program_name = %q, want vuln-demo", fs.ProgramName)
	}
	if fs.ScanTime.IsZero() {
		t.Error("scan_time should be parsed")
	}
	if len(fs.Findings) != 2 {
		t.Fatalf("findings count = %d, want 2", len(fs.Findings))
	}

	// --- Finding 0: Path Traversal (has data_flow_paths) ---
	f0 := fs.Findings[0]
	if f0.RuleID != "7b798768-13e1-4dcd-8ab5-99a6f9635605" {
		t.Errorf("finding[0].rule_id = %q, want 7b798768-13e1-4dcd-8ab5-99a6f9635605", f0.RuleID)
	}
	if f0.RuleName != "检测Java路径穿越漏洞" {
		t.Errorf("finding[0].rule_name = %q", f0.RuleName)
	}
	if f0.Severity != "high" {
		t.Errorf("finding[0].severity = %q, want high", f0.Severity)
	}
	if f0.Flow == nil {
		t.Fatal("finding[0].flow should not be nil")
	}
	if f0.Flow.Source == nil {
		t.Fatal("finding[0].flow.source should not be nil")
	}
	if f0.Flow.Source.Line != 13 {
		t.Errorf("finding[0].flow.source.line = %d, want 13", f0.Flow.Source.Line)
	}
	if f0.Flow.Source.Column != 48 {
		t.Errorf("finding[0].flow.source.column = %d, want 48", f0.Flow.Source.Column)
	}
	if f0.Flow.Source.Symbol != "filename" {
		t.Errorf("finding[0].flow.source.symbol = %q, want filename", f0.Flow.Source.Symbol)
	}
	if f0.Flow.Source.File != "src/controllers/FileController.java" {
		t.Errorf("finding[0].flow.source.file = %q, want src/controllers/FileController.java", f0.Flow.Source.File)
	}
	if f0.Flow.Sink == nil {
		t.Fatal("finding[0].flow.sink should not be nil")
	}
	if f0.Flow.Sink.Line != 15 {
		t.Errorf("finding[0].flow.sink.line = %d, want 15", f0.Flow.Sink.Line)
	}
	if f0.Flow.Sink.Symbol != "readAllBytes" {
		t.Errorf("finding[0].flow.sink.symbol = %q, want readAllBytes", f0.Flow.Sink.Symbol)
	}
	if len(f0.Flow.Sanitizers) != 1 {
		t.Errorf("finding[0].flow.sanitizers count = %d, want 1", len(f0.Flow.Sanitizers))
	}

	// --- Finding 1: XSS (no data_flow_paths, fallback to code_range) ---
	f1 := fs.Findings[1]
	if f1.RuleID != "cad09b46-5b0f-4c43-9b43-2b786b9c625f" {
		t.Errorf("finding[1].rule_id = %q", f1.RuleID)
	}
	if f1.Flow == nil {
		t.Fatal("finding[1].flow should not be nil")
	}
	if f1.Flow.Source == nil || f1.Flow.Sink == nil {
		t.Fatal("finding[1].flow.source and sink should not be nil")
	}
	if f1.Flow.Source.Line != 14 {
		t.Errorf("finding[1].flow.source.line = %d, want 14", f1.Flow.Source.Line)
	}
	if f1.Flow.Sink.Line != 14 {
		t.Errorf("finding[1].flow.sink.line = %d, want 14", f1.Flow.Sink.Line)
	}
}

func TestIrifyConverterEmptyRisks(t *testing.T) {
	conv := &IrifyConverter{}
	fs, err := conv.Convert([]byte(`{"Risks":{},"Rules":[]}`))
	if err != nil {
		t.Fatalf("convert empty failed: %v", err)
	}
	if len(fs.Findings) != 0 {
		t.Errorf("findings count = %d, want 0", len(fs.Findings))
	}
}

func TestIrifyConverterRealScanOutput(t *testing.T) {
	fixturePaths := []string{
		"/tmp/vuln-demo-scan-df.json",
		"/tmp/vuln-demo-scan.json",
	}
	for _, p := range fixturePaths {
		data, err := os.ReadFile(p)
		if err != nil || len(data) == 0 {
			continue
		}
		conv := &IrifyConverter{}
		if !conv.Detect(data) {
			t.Fatalf("Detect failed for real scan output: %s", p)
		}
		fs, err := conv.Convert(data)
		if err != nil {
			t.Fatalf("Convert failed for real scan output %s: %v", p, err)
		}
		if len(fs.Findings) == 0 {
			t.Errorf("expected non-zero findings from real scan output %s", p)
		}
		for i, f := range fs.Findings {
			if f.RuleName == "" {
				t.Errorf("finding[%d] has empty rule_name in %s", i, p)
			}
			if f.Flow == nil {
				t.Errorf("finding[%d] has nil flow in %s", i, p)
			}
		}
		t.Logf("%s: converted %d findings", p, len(fs.Findings))
		return // one successful fixture is enough
	}
	t.Skip("no real scan output fixture available")
}
