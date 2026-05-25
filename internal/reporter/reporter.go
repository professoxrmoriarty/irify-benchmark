// Package reporter generates human- and machine-readable benchmark reports.
package reporter

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io"

	"github.com/irify/irify-benchmark/pkg/schema"
)

// Reporter renders a benchmark Result to an io.Writer.
type Reporter interface {
	Render(result *schema.Result, w io.Writer) error
}

// JSONReporter writes a Result as indented JSON.
type JSONReporter struct{}

// Render encodes result as JSON with indentation.
func (r *JSONReporter) Render(result *schema.Result, w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(result); err != nil {
		return fmt.Errorf("encode JSON: %w", err)
	}
	return nil
}

// HTMLReporter writes a self-contained HTML report.
type HTMLReporter struct{}

// Render generates a simple HTML page with summary and case results.
func (r *HTMLReporter) Render(result *schema.Result, w io.Writer) error {
	tmpl, err := template.New("report").Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("parse HTML template: %w", err)
	}
	if err := tmpl.Execute(w, result); err != nil {
		return fmt.Errorf("execute HTML template: %w", err)
	}
	return nil
}

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>Benchmark Report: {{ .BenchmarkID }}</title>
	<style>
		body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; margin: 2rem; background: #f8f9fa; color: #212529; }
		h1 { font-size: 1.75rem; margin-bottom: 0.5rem; }
		h2 { font-size: 1.25rem; margin-top: 2rem; margin-bottom: 0.75rem; }
		table { width: 100%; border-collapse: collapse; background: #fff; box-shadow: 0 1px 3px rgba(0,0,0,0.1); border-radius: 6px; overflow: hidden; }
		th, td { padding: 0.75rem 1rem; text-align: left; border-bottom: 1px solid #e9ecef; }
		th { background: #e9ecef; font-weight: 600; }
		tr:last-child td { border-bottom: none; }
		.numeric { text-align: right; }
		.status-tp { color: #198754; font-weight: 600; }
		.status-fn { color: #dc3545; font-weight: 600; }
		.status-fp { color: #fd7e14; font-weight: 600; }
		.status-tn { color: #0d6efd; font-weight: 600; }
		.summary-row td { font-size: 1.05rem; }
		.summary-row .numeric { font-weight: 600; }
	</style>
</head>
<body>
	<h1>Benchmark Report: {{ .BenchmarkID }}</h1>
	<p>Engine: {{ .Engine }} {{ .EngineVersion }} &middot; Scan Time: {{ .ScanTime }}</p>

	<h2>Summary</h2>
	<table>
		<thead>
			<tr><th>Metric</th><th class="numeric">Value</th></tr>
		</thead>
		<tbody>
			<tr class="summary-row"><td>Total Cases</td><td class="numeric">{{ .Summary.TotalCases }}</td></tr>
			<tr class="summary-row"><td>True Positives (TP)</td><td class="numeric">{{ .Summary.TP }}</td></tr>
			<tr class="summary-row"><td>False Negatives (FN)</td><td class="numeric">{{ .Summary.FN }}</td></tr>
			<tr class="summary-row"><td>False Positives (FP)</td><td class="numeric">{{ .Summary.FP }}</td></tr>
			<tr class="summary-row"><td>True Negatives (TN)</td><td class="numeric">{{ .Summary.TN }}</td></tr>
			<tr class="summary-row"><td>Recall</td><td class="numeric">{{ printf "%.4f" .Summary.Recall }}</td></tr>
			<tr class="summary-row"><td>Precision</td><td class="numeric">{{ printf "%.4f" .Summary.Precision }}</td></tr>
			<tr class="summary-row"><td>F1 Score</td><td class="numeric">{{ printf "%.4f" .Summary.F1 }}</td></tr>
		</tbody>
	</table>

	<h2>Case Results</h2>
	<table>
		<thead>
			<tr>
				<th>Case ID</th>
				<th>Status</th>
				<th>Match Score</th>
				<th>Source Match</th>
				<th>Sink Match</th>
			</tr>
		</thead>
		<tbody>
			{{ range .CaseResults }}
			<tr>
				<td>{{ .CaseID }}</td>
				<td class="status-{{ .Status }}">{{ .Status }}</td>
				<td class="numeric">{{ printf "%.2f" .MatchScore }}</td>
				<td>{{ if .MatchDetails }}{{ if .MatchDetails.SourceMatch }}Yes{{ else }}No{{ end }}{{ else }}-{{ end }}</td>
				<td>{{ if .MatchDetails }}{{ if .MatchDetails.SinkMatch }}Yes{{ else }}No{{ end }}{{ else }}-{{ end }}</td>
			</tr>
			{{ end }}
		</tbody>
	</table>
</body>
</html>
`
