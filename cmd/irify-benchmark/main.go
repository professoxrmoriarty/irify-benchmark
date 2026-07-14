package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	casepkg "github.com/irify/irify-benchmark/internal/cases"
	"github.com/irify/irify-benchmark/internal/diagnose"
	"github.com/irify/irify-benchmark/internal/matcher"
	"github.com/irify/irify-benchmark/internal/pipeline"
	"github.com/irify/irify-benchmark/internal/project"
	"github.com/irify/irify-benchmark/internal/reporter"
	"github.com/irify/irify-benchmark/internal/reviewer"
	"github.com/irify/irify-benchmark/internal/runner"
	"github.com/irify/irify-benchmark/internal/store"
	"github.com/irify/irify-benchmark/pkg/engine"
	"github.com/irify/irify-benchmark/pkg/schema"
)

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

var rootCmd = &cobra.Command{
	Use:   "irify-benchmark",
	Short: "Benchmark framework for evaluating static analysis engines",
}

var (
	annotationPath string
	sourcePath     string
	engineName     string
	outputDir      string
	findingsPath   string
	port           int
	staticDir      string
	benchmarkID    string
	caseFile       string
	useStdin       bool
	itemID         string
	reviewerName   string
	notes          string
	reason         string
	languageFlag   string
	configPathFlag string
	projectFlag    string
	engineVersion  string
	resultFileFlag string

	// Project command flags
	projectIDFlag       string
	projectNameFlag     string
	projectLangFlag     string
	projectDescFlag     string
	projectSourceFlag   string
	projectFromDirFlag  string
	projectToDirFlag    string
	projectFilePathFlag string
	projectDirPathFlag  string

	// Case command flags
	caseProjectFlag      string
	caseIDFlag           string
	caseNameFlag         string
	caseDescFlag         string
	caseVulnDescFlag     string
	caseLangFlag         string
	caseSourceCodeFlag   string
	caseSourceFileFlag   string
	caseSourceLineFlag   int
	caseSourceSymbolFlag string
	caseSinkFileFlag     string
	caseSinkLineFlag     int
	caseSinkSymbolFlag   string
	caseCWEFlag          string
	caseTagsFlag         []string
)

func init() {
	rootCmd.AddCommand(runCmd, scanCmd, matchCmd, serverCmd, caseCmd, projectCmd, reviewCmd, resultsCmd, findingsCmd, rawScanCmd, analyzeCmd, diagnoseCmd)
	resultsCmd.AddCommand(resultsListCmd, resultsShowCmd)
	findingsCmd.AddCommand(findingsListCmd, findingsShowCmd)
	findingsListCmd.Flags().String("engine", "", "Engine name")
	findingsListCmd.Flags().String("version", "", "Engine version")
	findingsShowCmd.Flags().String("engine", "", "Engine name")
	findingsShowCmd.Flags().String("version", "", "Engine version")
	rawScanCmd.Flags().String("engine", "", "Engine name")
	rawScanCmd.Flags().String("version", "", "Engine version")
	diagnoseCmd.Flags().StringVar(&engineName, "engine", "", "Engine name")
	diagnoseCmd.Flags().StringVar(&engineVersion, "version", "", "Engine version")
	diagnoseCmd.Flags().StringVar(&diagnoseFormat, "format", "json", "Output format: json, bundle, prompt, manifest, markdown")
	diagnoseCmd.Flags().IntVar(&diagnoseMaxPriorities, "max-priorities", 12, "Maximum priority items in bundle output")
	diagnoseCmd.Flags().IntVar(&diagnoseMaxRuleReviews, "max-rule-reviews", 8, "Maximum rule review suggestions in bundle output")
	diagnoseCmd.AddCommand(diagnoseValidateResponseCmd)
	diagnoseValidateResponseCmd.Flags().StringVar(&diagnoseResponseFile, "file", "", "AI response file to validate; reads stdin when omitted")
	caseCmd.AddCommand(caseAddCmd, caseCreateCmd, caseListCmd, caseShowCmd, caseDeleteCmd, caseValidateCmd)
	projectCmd.AddCommand(
		projectCreateCmd, projectImportCmd, projectDescribeCmd,
		projectListCmd, projectDeleteCmd, projectAddFileCmd,
		projectMkdirCmd, projectCpDirCmd, projectFilesCmd,
	)
	reviewCmd.AddCommand(reviewListCmd, reviewApproveCmd, reviewRejectCmd)

	// run flags
	runCmd.Flags().StringVar(&annotationPath, "annotation", "", "Path to annotation JSON file")
	runCmd.Flags().StringVar(&sourcePath, "source", "", "Path to source code")
	runCmd.Flags().StringVar(&engineName, "engine", "", "Engine name")
	runCmd.Flags().StringVar(&outputDir, "output", "", "Output directory")
	runCmd.Flags().StringVar(&benchmarkID, "benchmark", "", "Benchmark ID (used when --annotation is omitted)")
	runCmd.Flags().StringVar(&projectFlag, "project", "", "Project ID (reads from cases/{id}/)")

	// scan flags
	scanCmd.Flags().StringVar(&sourcePath, "source", "", "Path to source code")
	scanCmd.Flags().StringVar(&engineName, "engine", "", "Engine name")
	scanCmd.Flags().StringVar(&outputDir, "output", "", "Output file path")
	scanCmd.Flags().StringVar(&languageFlag, "language", "", "Target language")
	scanCmd.Flags().StringVar(&configPathFlag, "config", "", "Engine config path")
	scanCmd.Flags().StringVar(&projectFlag, "project", "", "Project ID (reads from cases/{id}/)")

	// match flags
	matchCmd.Flags().StringVar(&annotationPath, "annotation", "", "Path to annotation JSON")
	matchCmd.Flags().StringVar(&findingsPath, "findings", "", "Path to findings JSON")
	matchCmd.Flags().StringVar(&outputDir, "output", "", "Output file path")
	matchCmd.Flags().StringVar(&projectFlag, "project", "", "Project ID (reads from cases/{id}/)")
	matchCmd.Flags().StringVar(&engineName, "engine", "", "Engine name")
	matchCmd.Flags().StringVar(&engineVersion, "version", "", "Engine version")

	// server flags
	serverCmd.Flags().IntVar(&port, "port", 8080, "Server port")
	serverCmd.Flags().StringVar(&staticDir, "static", "", "Static files directory")

	// case add flags (legacy)
	caseAddCmd.Flags().StringVar(&benchmarkID, "benchmark", "", "Benchmark ID")
	caseAddCmd.Flags().StringVar(&projectFlag, "project", "", "Project ID (v2)")
	caseAddCmd.Flags().StringVar(&caseFile, "file", "", "Path to case JSON file")
	caseAddCmd.Flags().BoolVar(&useStdin, "stdin", false, "Read case from stdin")

	// case create flags
	caseCreateCmd.Flags().StringVar(&caseProjectFlag, "project", "", "Project ID")
	caseCreateCmd.Flags().StringVar(&caseFile, "file", "", "Path to case JSON file")
	caseCreateCmd.Flags().BoolVar(&useStdin, "stdin", false, "Read case from stdin")
	caseCreateCmd.Flags().StringVar(&caseIDFlag, "id", "", "Case ID")
	caseCreateCmd.Flags().StringVar(&caseNameFlag, "name", "", "Case name")
	caseCreateCmd.Flags().StringVar(&caseDescFlag, "description", "", "Case description")
	caseCreateCmd.Flags().StringVar(&caseVulnDescFlag, "vuln-desc", "", "Vulnerability description")
	caseCreateCmd.Flags().StringVar(&caseLangFlag, "language", "", "Case language")
	caseCreateCmd.Flags().StringVar(&caseSourceCodeFlag, "source-code", "", "Source code file path (relative to src/)")
	caseCreateCmd.Flags().StringVar(&caseSourceFileFlag, "source-file", "", "Source location file (relative to src/)")
	caseCreateCmd.Flags().IntVar(&caseSourceLineFlag, "source-line", 0, "Source location line number")
	caseCreateCmd.Flags().StringVar(&caseSourceSymbolFlag, "source-symbol", "", "Source location symbol")
	caseCreateCmd.Flags().StringVar(&caseSinkFileFlag, "sink-file", "", "Sink location file (relative to src/)")
	caseCreateCmd.Flags().IntVar(&caseSinkLineFlag, "sink-line", 0, "Sink location line number")
	caseCreateCmd.Flags().StringVar(&caseSinkSymbolFlag, "sink-symbol", "", "Sink location symbol")
	caseCreateCmd.Flags().StringVar(&caseCWEFlag, "cwe", "", "CWE identifier")
	caseCreateCmd.Flags().StringSliceVar(&caseTagsFlag, "tags", nil, "Tags (comma-separated or multiple --tags)")

	// case list flags
	caseListCmd.Flags().StringVar(&caseProjectFlag, "project", "", "Project ID")

	// case show flags
	caseShowCmd.Flags().StringVar(&caseProjectFlag, "project", "", "Project ID")
	caseShowCmd.Flags().StringVar(&caseIDFlag, "case", "", "Case ID")

	// case delete flags
	caseDeleteCmd.Flags().StringVar(&caseProjectFlag, "project", "", "Project ID")
	caseDeleteCmd.Flags().StringVar(&caseIDFlag, "case", "", "Case ID")

	// case validate flags
	caseValidateCmd.Flags().StringVar(&caseProjectFlag, "project", "", "Project ID")

	// project create flags
	projectCreateCmd.Flags().StringVar(&projectIDFlag, "id", "", "Project ID")
	projectCreateCmd.Flags().StringVar(&projectNameFlag, "name", "", "Project name")
	projectCreateCmd.Flags().StringVar(&projectLangFlag, "language", "", "Project language")
	projectCreateCmd.Flags().StringVar(&projectDescFlag, "description", "", "Project description")
	projectCreateCmd.Flags().StringVar(&projectSourceFlag, "source-root", "", "Source root directory")

	// project import flags
	projectImportCmd.Flags().StringVar(&projectIDFlag, "id", "", "Project ID")
	projectImportCmd.Flags().StringVar(&projectNameFlag, "name", "", "Project name")
	projectImportCmd.Flags().StringVar(&projectLangFlag, "language", "", "Project language")
	projectImportCmd.Flags().StringVar(&projectFromDirFlag, "from", "", "Source directory to import")

	// project describe flags
	projectDescribeCmd.Flags().StringVar(&projectIDFlag, "id", "", "Project ID")
	projectDescribeCmd.Flags().StringVar(&projectDescFlag, "description", "", "New description")

	// project delete flags
	projectDeleteCmd.Flags().StringVar(&projectIDFlag, "id", "", "Project ID")

	// project add-file flags
	projectAddFileCmd.Flags().StringVar(&projectFlag, "project", "", "Project ID")
	projectAddFileCmd.Flags().StringVar(&projectFilePathFlag, "file", "", "File path within project source")
	projectAddFileCmd.Flags().StringVar(&caseFile, "from", "", "Source file path on disk")
	projectAddFileCmd.Flags().BoolVar(&useStdin, "stdin", false, "Read content from stdin")

	// project mkdir flags
	projectMkdirCmd.Flags().StringVar(&projectFlag, "project", "", "Project ID")
	projectMkdirCmd.Flags().StringVar(&projectDirPathFlag, "dir", "", "Directory path to create")

	// project cp-dir flags
	projectCpDirCmd.Flags().StringVar(&projectFlag, "project", "", "Project ID")
	projectCpDirCmd.Flags().StringVar(&projectFromDirFlag, "from", "", "Source directory on disk")
	projectCpDirCmd.Flags().StringVar(&projectToDirFlag, "to", "", "Target directory in project")

	// project files flags
	projectFilesCmd.Flags().StringVar(&projectFlag, "project", "", "Project ID")

	// review list flags
	reviewListCmd.Flags().StringVar(&projectFlag, "project", "", "Project ID")
	reviewListCmd.Flags().StringVar(&benchmarkID, "benchmark", "", "Project ID (legacy alias)")

	// review approve flags
	reviewApproveCmd.Flags().StringVar(&projectFlag, "project", "", "Project ID")
	reviewApproveCmd.Flags().StringVar(&benchmarkID, "benchmark", "", "Project ID (legacy alias)")
	reviewApproveCmd.Flags().StringVar(&itemID, "item", "", "Pending item ID")
	reviewApproveCmd.Flags().StringVar(&reviewerName, "reviewer", "user", "Reviewer name")
	reviewApproveCmd.Flags().StringVar(&notes, "notes", "", "Review notes")

	// review reject flags
	reviewRejectCmd.Flags().StringVar(&projectFlag, "project", "", "Project ID")
	reviewRejectCmd.Flags().StringVar(&benchmarkID, "benchmark", "", "Project ID (legacy alias)")
	reviewRejectCmd.Flags().StringVar(&itemID, "item", "", "Pending item ID")
	reviewRejectCmd.Flags().StringVar(&reviewerName, "reviewer", "user", "Reviewer name")
	reviewRejectCmd.Flags().StringVar(&reason, "reason", "", "Rejection reason")

	// results flags
	resultsListCmd.Flags().StringVar(&projectFlag, "project", "", "Project ID")
	resultsListCmd.Flags().StringVar(&benchmarkID, "benchmark", "", "Project ID (legacy alias)")
	resultsShowCmd.Flags().StringVar(&projectFlag, "project", "", "Project ID")
	resultsShowCmd.Flags().StringVar(&benchmarkID, "benchmark", "", "Project ID (legacy alias)")
	resultsShowCmd.Flags().StringVar(&engineName, "engine", "", "Engine name")
	resultsShowCmd.Flags().StringVar(&engineVersion, "version", "", "Engine version")
	resultsShowCmd.Flags().StringVar(&resultFileFlag, "file", "", "Path to result JSON file")
}

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Run full benchmark pipeline",
	RunE: func(cmd *cobra.Command, args []string) error {
		if engineName == "" {
			return fmt.Errorf("--engine is required")
		}

		baseDir := outputDir
		if baseDir == "" {
			baseDir = "data"
		}
		st := store.NewFSStore(baseDir)

		eng := resolveEngine(engineName)

		var annotation *schema.Annotation
		var bID string
		var hs *store.HybridStore
		if annotationPath != "" {
			if sourcePath == "" {
				return fmt.Errorf("--source is required when using --annotation")
			}
			data, err := os.ReadFile(annotationPath)
			if err != nil {
				return fmt.Errorf("read annotation file: %w", err)
			}
			annotation = &schema.Annotation{}
			if err := json.Unmarshal(data, annotation); err != nil {
				return fmt.Errorf("unmarshal annotation: %w", err)
			}
			bID = annotation.BenchmarkID
			if err := st.WriteAnnotation(annotation); err != nil {
				return fmt.Errorf("write annotation to store: %w", err)
			}
		} else if projectFlag != "" {
			var err error
			hs, err = store.NewHybridStore(".", "data/benchmark.db")
			if err != nil {
				return fmt.Errorf("init hybrid store: %w", err)
			}
			defer hs.Close()
			proj, err := hs.ReadProject(projectFlag)
			if err != nil {
				return fmt.Errorf("read project: %w", err)
			}
			caseSet, err := hs.ReadCases(projectFlag)
			if err != nil {
				return fmt.Errorf("read cases: %w", err)
			}
			annotation = &schema.Annotation{
				BenchmarkID: caseSet.ProjectID,
				Version:     caseSet.Version,
				Cases:       caseSet.Cases,
			}
			bID = projectFlag
			sourcePath = filepath.Join("cases", projectFlag, proj.SourceRoot)
			if err := st.WriteAnnotation(annotation); err != nil {
				return fmt.Errorf("write annotation to store: %w", err)
			}
		} else {
			if sourcePath == "" {
				return fmt.Errorf("--source is required when --annotation and --project are omitted")
			}
			bID = benchmarkID
			if bID == "" {
				return fmt.Errorf("--annotation, --project, or --benchmark is required")
			}
			var err error
			annotation, err = st.ReadAnnotation(bID)
			if err != nil {
				return fmt.Errorf("read annotation: %w", err)
			}
		}

		// Use FlowMatcher for real matching in Phase 2.
		m := &matcher.FlowMatcher{}
		pipe := pipeline.NewPipeline(st, eng, m)
		result, err := pipe.Run(context.Background(), bID, sourcePath)
		if err != nil {
			return fmt.Errorf("pipeline run: %w", err)
		}

		// For project mode, also save findings and results to HybridStore.
		if hs != nil {
			version := result.EngineVersion
			if version == "" {
				if v, err := eng.Version(context.Background()); err == nil {
					version = v
				}
			}
			findingSet, err := st.ReadFindingSet(bID, result.Engine, version)
			if err == nil && findingSet != nil {
				findingSet.BenchmarkID = bID
				_ = hs.SaveFindings(bID, findingSet)
			}
			_ = hs.SaveResult(bID, result)
			// Copy raw report to HybridStore for frontend download.
			rawData, format, err := st.ReadRawReport(bID, result.Engine, version)
			if err == nil {
				_ = hs.SaveRawReport(bID, result.Engine, version, format, rawData)
			}
		}

		if outputDir != "" {
			resultData, err := json.MarshalIndent(result, "", "  ")
			if err != nil {
				return fmt.Errorf("marshal result: %w", err)
			}
			resultFile := filepath.Join(outputDir, fmt.Sprintf("result-%s.json", bID))
			if err := os.WriteFile(resultFile, resultData, 0644); err != nil {
				return fmt.Errorf("write result: %w", err)
			}
			fmt.Printf("Result written to %s\n", resultFile)
		}

		fmt.Printf("Pipeline completed for benchmark %s (%d cases)\n", bID, result.Summary.TotalCases)
		return nil
	},
}

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Run engine scan",
	RunE: func(cmd *cobra.Command, args []string) error {
		if engineName == "" {
			return fmt.Errorf("--engine is required")
		}

		resolvedSource := sourcePath
		var hs *store.HybridStore
		if projectFlag != "" {
			var err error
			hs, err = store.NewHybridStore(".", "data/benchmark.db")
			if err != nil {
				return fmt.Errorf("init hybrid store: %w", err)
			}
			defer hs.Close()
			proj, err := hs.ReadProject(projectFlag)
			if err != nil {
				return fmt.Errorf("read project: %w", err)
			}
			resolvedSource = filepath.Join("cases", projectFlag, proj.SourceRoot)
		}
		if resolvedSource == "" {
			return fmt.Errorf("--source or --project is required")
		}
		if outputDir == "" && projectFlag == "" {
			return fmt.Errorf("--output is required")
		}

		eng := resolveEngine(engineName)

		req := engine.ScanRequest{
			SourcePath: resolvedSource,
			OutputPath: outputDir,
		}
		if languageFlag != "" {
			req.Language = languageFlag
		}
		if configPathFlag != "" {
			req.ConfigPath = configPathFlag
		}

		ctx := context.Background()
		findingSet, err := eng.Scan(ctx, req)
		if err != nil {
			return fmt.Errorf("scan failed: %w", err)
		}

		// Save to JSON if output is specified.
		if outputDir != "" {
			data, err := json.MarshalIndent(findingSet, "", "  ")
			if err != nil {
				return fmt.Errorf("marshal findings: %w", err)
			}
			if err := os.WriteFile(outputDir, data, 0644); err != nil {
				return fmt.Errorf("write findings: %w", err)
			}
			fmt.Printf("Findings written to %s (%d findings)\n", outputDir, len(findingSet.Findings))
		}

		// For project mode, also save findings to HybridStore and keep raw scan.
		if hs != nil {
			findingSet.BenchmarkID = projectFlag
			if err := hs.SaveFindings(projectFlag, findingSet); err != nil {
				return fmt.Errorf("save findings to hybrid store: %w", err)
			}
			fmt.Printf("Findings saved to SQLite for project %s\n", projectFlag)

			// Preserve raw irify JSON for downstream debugging.
			if len(findingSet.RawReport) > 0 {
				_ = hs.SaveRawReport(projectFlag, findingSet.Engine, findingSet.EngineVersion, "json", findingSet.RawReport)
				rawDir := filepath.Join("data", "raw-reports", projectFlag)
				if err := os.MkdirAll(rawDir, 0755); err == nil {
					rawPath := filepath.Join(rawDir, fmt.Sprintf("%s-%s.json", findingSet.Engine, findingSet.EngineVersion))
					_ = os.WriteFile(rawPath, findingSet.RawReport, 0644)
					fmt.Printf("Raw scan preserved at %s\n", rawPath)
				}
			}
		}

		return nil
	},
}

var matchCmd = &cobra.Command{
	Use:   "match",
	Short: "Match annotations against findings",
	RunE: func(cmd *cobra.Command, args []string) error {
		if projectFlag != "" {
			if engineName == "" {
				return fmt.Errorf("--engine is required when using --project")
			}
			if engineVersion == "" {
				return fmt.Errorf("--version is required when using --project")
			}
			if outputDir == "" {
				return fmt.Errorf("--output is required")
			}

			hs, err := store.NewHybridStore(".", "data/benchmark.db")
			if err != nil {
				return fmt.Errorf("init hybrid store: %w", err)
			}
			defer hs.Close()

			caseSet, err := hs.ReadCases(projectFlag)
			if err != nil {
				return fmt.Errorf("read cases: %w", err)
			}
			annotation := &schema.Annotation{
				BenchmarkID: caseSet.ProjectID,
				Version:     caseSet.Version,
				Cases:       caseSet.Cases,
			}

			findings, err := hs.GetFindings(projectFlag, engineName, engineVersion)
			if err != nil {
				return fmt.Errorf("read findings: %w", err)
			}

			m := &matcher.FlowMatcher{}
			result, err := m.Match(annotation, findings)
			if err != nil {
				return fmt.Errorf("match: %w", err)
			}

			if err := hs.SaveResult(projectFlag, result); err != nil {
				return fmt.Errorf("save result: %w", err)
			}

			f, err := os.Create(outputDir)
			if err != nil {
				return fmt.Errorf("create output file: %w", err)
			}
			defer f.Close()

			rep := &reporter.JSONReporter{}
			if err := rep.Render(result, f); err != nil {
				return fmt.Errorf("render report: %w", err)
			}

			fmt.Printf("Result written to %s\n", outputDir)
			return nil
		}

		// Legacy mode
		if annotationPath == "" {
			return fmt.Errorf("--annotation is required")
		}
		if findingsPath == "" {
			return fmt.Errorf("--findings is required")
		}
		if outputDir == "" {
			return fmt.Errorf("--output is required")
		}

		data, err := os.ReadFile(annotationPath)
		if err != nil {
			return fmt.Errorf("read annotation: %w", err)
		}
		var annotation schema.Annotation
		if err := json.Unmarshal(data, &annotation); err != nil {
			return fmt.Errorf("unmarshal annotation: %w", err)
		}

		data, err = os.ReadFile(findingsPath)
		if err != nil {
			return fmt.Errorf("read findings: %w", err)
		}
		var findings schema.FindingSet
		if err := json.Unmarshal(data, &findings); err != nil {
			return fmt.Errorf("unmarshal findings: %w", err)
		}

		m := &matcher.FlowMatcher{}
		result, err := m.Match(&annotation, &findings)
		if err != nil {
			return fmt.Errorf("match: %w", err)
		}

		f, err := os.Create(outputDir)
		if err != nil {
			return fmt.Errorf("create output file: %w", err)
		}
		defer f.Close()

		rep := &reporter.JSONReporter{}
		if err := rep.Render(result, f); err != nil {
			return fmt.Errorf("render report: %w", err)
		}

		fmt.Printf("Result written to %s\n", outputDir)
		return nil
	},
}

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Start HTTP server with REST API and optional static file serving",
	RunE: func(cmd *cobra.Command, args []string) error {
		return startServer(port, staticDir)
	},
}

// ---------------------------------------------------------------------------
// Project commands
// ---------------------------------------------------------------------------

var projectCmd = &cobra.Command{
	Use:   "project",
	Short: "Project management",
}

var projectCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new project",
	RunE: func(cmd *cobra.Command, args []string) error {
		if projectIDFlag == "" {
			return fmt.Errorf("--id is required")
		}
		if projectNameFlag == "" {
			return fmt.Errorf("--name is required")
		}
		if projectLangFlag == "" {
			return fmt.Errorf("--language is required")
		}
		hs, err := store.NewHybridStore(".", "data/benchmark.db")
		if err != nil {
			return fmt.Errorf("init hybrid store: %w", err)
		}
		defer hs.Close()
		pm := project.NewManager(hs)
		p, err := pm.Create(projectIDFlag, projectNameFlag, projectLangFlag, projectDescFlag, projectSourceFlag)
		if err != nil {
			return fmt.Errorf("create project: %w", err)
		}
		fmt.Printf("Created project %s (%s)\n", p.ProjectID, p.Name)
		return nil
	},
}

var projectImportCmd = &cobra.Command{
	Use:   "import",
	Short: "Import an existing directory as a project",
	RunE: func(cmd *cobra.Command, args []string) error {
		if projectIDFlag == "" {
			return fmt.Errorf("--id is required")
		}
		if projectNameFlag == "" {
			return fmt.Errorf("--name is required")
		}
		if projectLangFlag == "" {
			return fmt.Errorf("--language is required")
		}
		if projectFromDirFlag == "" {
			return fmt.Errorf("--from is required")
		}
		hs, err := store.NewHybridStore(".", "data/benchmark.db")
		if err != nil {
			return fmt.Errorf("init hybrid store: %w", err)
		}
		defer hs.Close()
		pm := project.NewManager(hs)
		p, err := pm.Import(projectIDFlag, projectNameFlag, projectLangFlag, projectFromDirFlag)
		if err != nil {
			return fmt.Errorf("import project: %w", err)
		}
		fmt.Printf("Imported project %s (%s) from %s\n", p.ProjectID, p.Name, projectFromDirFlag)
		return nil
	},
}

var projectDescribeCmd = &cobra.Command{
	Use:   "describe",
	Short: "Update project description",
	RunE: func(cmd *cobra.Command, args []string) error {
		if projectIDFlag == "" {
			return fmt.Errorf("--id is required")
		}
		hs, err := store.NewHybridStore(".", "data/benchmark.db")
		if err != nil {
			return fmt.Errorf("init hybrid store: %w", err)
		}
		defer hs.Close()
		pm := project.NewManager(hs)
		if err := pm.Describe(projectIDFlag, projectDescFlag); err != nil {
			return fmt.Errorf("describe project: %w", err)
		}
		fmt.Printf("Updated description for project %s\n", projectIDFlag)
		return nil
	},
}

var projectListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all projects",
	RunE: func(cmd *cobra.Command, args []string) error {
		hs, err := store.NewHybridStore(".", "data/benchmark.db")
		if err != nil {
			return fmt.Errorf("init hybrid store: %w", err)
		}
		defer hs.Close()
		pm := project.NewManager(hs)
		projects, err := pm.List()
		if err != nil {
			return fmt.Errorf("list projects: %w", err)
		}
		if len(projects) == 0 {
			fmt.Println("No projects found.")
			return nil
		}
		fmt.Printf("%-14s %-14s %-10s %s\n", "PROJECT ID", "NAME", "LANGUAGE", "DESCRIPTION")
		for _, p := range projects {
			desc := p.Description
			if len(desc) > 40 {
				desc = desc[:37] + "..."
			}
			fmt.Printf("%-14s %-14s %-10s %s\n", p.ProjectID, p.Name, p.Language, desc)
		}
		return nil
	},
}

var projectDeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete a project",
	RunE: func(cmd *cobra.Command, args []string) error {
		if projectIDFlag == "" {
			return fmt.Errorf("--id is required")
		}
		hs, err := store.NewHybridStore(".", "data/benchmark.db")
		if err != nil {
			return fmt.Errorf("init hybrid store: %w", err)
		}
		defer hs.Close()
		pm := project.NewManager(hs)
		if err := pm.Delete(projectIDFlag); err != nil {
			return fmt.Errorf("delete project: %w", err)
		}
		fmt.Printf("Deleted project %s\n", projectIDFlag)
		return nil
	},
}

var projectAddFileCmd = &cobra.Command{
	Use:   "add-file",
	Short: "Add or overwrite a file in the project source tree",
	RunE: func(cmd *cobra.Command, args []string) error {
		if projectFlag == "" {
			return fmt.Errorf("--project is required")
		}
		if projectFilePathFlag == "" {
			return fmt.Errorf("--file is required")
		}

		var content []byte
		var err error
		if useStdin {
			content, err = io.ReadAll(os.Stdin)
			if err != nil {
				return fmt.Errorf("read stdin: %w", err)
			}
		} else if caseFile != "" {
			content, err = os.ReadFile(caseFile)
			if err != nil {
				return fmt.Errorf("read file: %w", err)
			}
		} else {
			return fmt.Errorf("--stdin or --from is required")
		}

		hs, err := store.NewHybridStore(".", "data/benchmark.db")
		if err != nil {
			return fmt.Errorf("init hybrid store: %w", err)
		}
		defer hs.Close()
		pm := project.NewManager(hs)
		if err := pm.AddFile(projectFlag, projectFilePathFlag, content); err != nil {
			return fmt.Errorf("add file: %w", err)
		}
		fmt.Printf("Added file %s to project %s\n", projectFilePathFlag, projectFlag)
		return nil
	},
}

var projectMkdirCmd = &cobra.Command{
	Use:   "mkdir",
	Short: "Create a directory in the project source tree",
	RunE: func(cmd *cobra.Command, args []string) error {
		if projectFlag == "" {
			return fmt.Errorf("--project is required")
		}
		if projectDirPathFlag == "" {
			return fmt.Errorf("--dir is required")
		}
		hs, err := store.NewHybridStore(".", "data/benchmark.db")
		if err != nil {
			return fmt.Errorf("init hybrid store: %w", err)
		}
		defer hs.Close()
		pm := project.NewManager(hs)
		if err := pm.Mkdir(projectFlag, projectDirPathFlag); err != nil {
			return fmt.Errorf("mkdir: %w", err)
		}
		fmt.Printf("Created directory %s in project %s\n", projectDirPathFlag, projectFlag)
		return nil
	},
}

var projectCpDirCmd = &cobra.Command{
	Use:   "cp-dir",
	Short: "Copy a directory into the project source tree",
	RunE: func(cmd *cobra.Command, args []string) error {
		if projectFlag == "" {
			return fmt.Errorf("--project is required")
		}
		if projectFromDirFlag == "" {
			return fmt.Errorf("--from is required")
		}
		if projectToDirFlag == "" {
			return fmt.Errorf("--to is required")
		}
		hs, err := store.NewHybridStore(".", "data/benchmark.db")
		if err != nil {
			return fmt.Errorf("init hybrid store: %w", err)
		}
		defer hs.Close()
		pm := project.NewManager(hs)
		if err := pm.CopyDir(projectFlag, projectFromDirFlag, projectToDirFlag); err != nil {
			return fmt.Errorf("cp-dir: %w", err)
		}
		fmt.Printf("Copied %s to %s in project %s\n", projectFromDirFlag, projectToDirFlag, projectFlag)
		return nil
	},
}

var projectFilesCmd = &cobra.Command{
	Use:   "files",
	Short: "List project source files",
	RunE: func(cmd *cobra.Command, args []string) error {
		if projectFlag == "" {
			return fmt.Errorf("--project is required")
		}
		hs, err := store.NewHybridStore(".", "data/benchmark.db")
		if err != nil {
			return fmt.Errorf("init hybrid store: %w", err)
		}
		defer hs.Close()
		pm := project.NewManager(hs)
		entries, err := pm.Files(projectFlag)
		if err != nil {
			return fmt.Errorf("list files: %w", err)
		}
		if len(entries) == 0 {
			fmt.Println("(empty)")
			return nil
		}
		fmt.Println("src/")
		project.PrintFilesTree(entries, "")
		return nil
	},
}

// ---------------------------------------------------------------------------
// Case commands
// ---------------------------------------------------------------------------

var caseCmd = &cobra.Command{
	Use:   "case",
	Short: "Case management commands",
}

var caseAddCmd = &cobra.Command{
	Use:   "add",
	Short: "Add a case to a benchmark annotation",
	RunE: func(cmd *cobra.Command, args []string) error {
		if benchmarkID == "" && projectFlag == "" {
			return fmt.Errorf("--benchmark or --project is required")
		}

		var data []byte
		var err error
		if useStdin {
			data, err = io.ReadAll(os.Stdin)
			if err != nil {
				return fmt.Errorf("read stdin: %w", err)
			}
		} else if caseFile != "" {
			data, err = os.ReadFile(caseFile)
			if err != nil {
				return fmt.Errorf("read case file: %w", err)
			}
		} else {
			return fmt.Errorf("--file or --stdin is required")
		}

		var c schema.Case
		if err := json.Unmarshal(data, &c); err != nil {
			return fmt.Errorf("unmarshal case: %w", err)
		}

		if projectFlag != "" {
			hs, err := store.NewHybridStore(".", "data/benchmark.db")
			if err != nil {
				return fmt.Errorf("init hybrid store: %w", err)
			}
			defer hs.Close()
			cm := casepkg.NewManager(hs)
			if err := cm.Create(projectFlag, c); err != nil {
				return fmt.Errorf("create case: %w", err)
			}
			fmt.Printf("Added case %s to project %s\n", c.CaseID, projectFlag)
			return nil
		}

		st := store.NewFSStore("data")
		annotation, err := st.ReadAnnotation(benchmarkID)
		if err != nil {
			return fmt.Errorf("read annotation: %w", err)
		}

		annotation.Cases = append(annotation.Cases, c)
		if annotation.BenchmarkID == "" {
			annotation.BenchmarkID = benchmarkID
		}

		if err := st.WriteAnnotation(annotation); err != nil {
			return fmt.Errorf("write annotation: %w", err)
		}

		fmt.Printf("Added case %s to benchmark %s (%d total cases)\n", c.CaseID, benchmarkID, len(annotation.Cases))
		return nil
	},
}

var caseCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a case in a project",
	RunE: func(cmd *cobra.Command, args []string) error {
		if caseProjectFlag == "" {
			return fmt.Errorf("--project is required")
		}

		var c schema.Case
		hasFlags := caseIDFlag != ""

		if hasFlags {
			c.CaseID = caseIDFlag
			c.Name = caseNameFlag
			c.Description = caseDescFlag
			c.VulnDesc = caseVulnDescFlag
			c.Language = caseLangFlag
			c.SourceCode = caseSourceCodeFlag

			// Build expectation from flow flags.
			if caseSourceFileFlag != "" || caseSinkFileFlag != "" {
				c.Expectation = &schema.Expectation{
					Type: "must_alert",
					Flow: &schema.Flow{},
				}
				if caseSourceFileFlag != "" || caseSourceLineFlag > 0 || caseSourceSymbolFlag != "" {
					c.Expectation.Flow.Source = &schema.Location{
						File:   caseSourceFileFlag,
						Line:   caseSourceLineFlag,
						Symbol: caseSourceSymbolFlag,
					}
				}
				if caseSinkFileFlag != "" || caseSinkLineFlag > 0 || caseSinkSymbolFlag != "" {
					c.Expectation.Flow.Sink = &schema.Location{
						File:   caseSinkFileFlag,
						Line:   caseSinkLineFlag,
						Symbol: caseSinkSymbolFlag,
					}
				}
			}

			// Build metadata from flags.
			if caseCWEFlag != "" || len(caseTagsFlag) > 0 {
				c.Metadata = &schema.Metadata{
					CWE:  caseCWEFlag,
					Tags: caseTagsFlag,
				}
			}
		}

		if useStdin || caseFile != "" {
			var data []byte
			var err error
			if useStdin {
				data, err = io.ReadAll(os.Stdin)
				if err != nil {
					return fmt.Errorf("read stdin: %w", err)
				}
			} else {
				data, err = os.ReadFile(caseFile)
				if err != nil {
					return fmt.Errorf("read case file: %w", err)
				}
			}

			var fromJSON schema.Case
			if err := json.Unmarshal(data, &fromJSON); err != nil {
				return fmt.Errorf("unmarshal case: %w", err)
			}

			if !hasFlags {
				c = fromJSON
			} else {
				// Merge: JSON fills gaps for fields not set by CLI flags.
				if c.Name == "" {
					c.Name = fromJSON.Name
				}
				if c.Description == "" {
					c.Description = fromJSON.Description
				}
				if c.VulnDesc == "" {
					c.VulnDesc = fromJSON.VulnDesc
				}
				if c.Language == "" {
					c.Language = fromJSON.Language
				}
				if c.SourceCode == "" {
					c.SourceCode = fromJSON.SourceCode
				}
				if c.Expectation == nil {
					c.Expectation = fromJSON.Expectation
				}
				if c.Metadata == nil {
					c.Metadata = fromJSON.Metadata
				}
				if c.Notes == "" {
					c.Notes = fromJSON.Notes
				}
			}
		}

		if c.CaseID == "" {
			return fmt.Errorf("--id or --file/--stdin is required")
		}

		// Validate before creation.
		result := casepkg.ValidateCase(caseProjectFlag, c)
		if result.HasErrors() || result.HasWarnings() {
			fmt.Println("Validation result:")
			result.Print()
			if result.HasErrors() {
				return fmt.Errorf("case validation failed")
			}
		}

		hs, err := store.NewHybridStore(".", "data/benchmark.db")
		if err != nil {
			return fmt.Errorf("init hybrid store: %w", err)
		}
		defer hs.Close()
		cm := casepkg.NewManager(hs)
		if err := cm.Create(caseProjectFlag, c); err != nil {
			return fmt.Errorf("create case: %w", err)
		}
		fmt.Printf("Created case %s in project %s\n", c.CaseID, caseProjectFlag)
		fmt.Println()
		_ = project.PrintCaseWithPreview(caseProjectFlag, &c)
		return nil
	},
}

var caseListCmd = &cobra.Command{
	Use:   "list",
	Short: "List cases for a project",
	RunE: func(cmd *cobra.Command, args []string) error {
		if caseProjectFlag == "" {
			return fmt.Errorf("--project is required")
		}
		hs, err := store.NewHybridStore(".", "data/benchmark.db")
		if err != nil {
			return fmt.Errorf("init hybrid store: %w", err)
		}
		defer hs.Close()
		cm := casepkg.NewManager(hs)
		cases, err := cm.List(caseProjectFlag)
		if err != nil {
			return fmt.Errorf("list cases: %w", err)
		}
		if len(cases) == 0 {
			fmt.Println("No cases found.")
			return nil
		}
		fmt.Printf("%-20s %-20s %-10s %s\n", "CASE ID", "NAME", "LANGUAGE", "DESCRIPTION")
		for _, c := range cases {
			desc := c.Description
			if len(desc) > 40 {
				desc = desc[:37] + "..."
			}
			name := c.Name
			if len(name) > 20 {
				name = name[:17] + "..."
			}
			fmt.Printf("%-20s %-20s %-10s %s\n", c.CaseID, name, c.Language, desc)
		}
		return nil
	},
}

var caseShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show a single case with source code preview",
	RunE: func(cmd *cobra.Command, args []string) error {
		if caseProjectFlag == "" {
			return fmt.Errorf("--project is required")
		}
		if caseIDFlag == "" {
			return fmt.Errorf("--case is required")
		}
		hs, err := store.NewHybridStore(".", "data/benchmark.db")
		if err != nil {
			return fmt.Errorf("init hybrid store: %w", err)
		}
		defer hs.Close()
		cm := casepkg.NewManager(hs)
		c, err := cm.Get(caseProjectFlag, caseIDFlag)
		if err != nil {
			return fmt.Errorf("get case: %w", err)
		}
		return project.PrintCaseWithPreview(caseProjectFlag, c)
	},
}

var caseDeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete a case from a project",
	RunE: func(cmd *cobra.Command, args []string) error {
		if caseProjectFlag == "" {
			return fmt.Errorf("--project is required")
		}
		if caseIDFlag == "" {
			return fmt.Errorf("--case is required")
		}
		hs, err := store.NewHybridStore(".", "data/benchmark.db")
		if err != nil {
			return fmt.Errorf("init hybrid store: %w", err)
		}
		defer hs.Close()
		cm := casepkg.NewManager(hs)
		if err := cm.Delete(caseProjectFlag, caseIDFlag); err != nil {
			return fmt.Errorf("delete case: %w", err)
		}
		fmt.Printf("Deleted case %s from project %s\n", caseIDFlag, caseProjectFlag)
		return nil
	},
}

var caseValidateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate all cases in a project",
	RunE: func(cmd *cobra.Command, args []string) error {
		if caseProjectFlag == "" {
			return fmt.Errorf("--project is required")
		}
		hs, err := store.NewHybridStore(".", "data/benchmark.db")
		if err != nil {
			return fmt.Errorf("init hybrid store: %w", err)
		}
		defer hs.Close()
		cm := casepkg.NewManager(hs)
		cases, err := cm.List(caseProjectFlag)
		if err != nil {
			return fmt.Errorf("list cases: %w", err)
		}
		if len(cases) == 0 {
			fmt.Println("No cases found.")
			return nil
		}

		var totalErrors, totalWarnings int
		for _, c := range cases {
			result := casepkg.ValidateCase(caseProjectFlag, c)
			if !result.HasErrors() && !result.HasWarnings() {
				continue
			}
			fmt.Printf("\nCase: %s\n", c.CaseID)
			result.Print()
			totalErrors += len(result.Errors)
			totalWarnings += len(result.Warnings)
		}

		fmt.Printf("\nValidation complete: %d case(s) checked, %d error(s), %d warning(s)\n",
			len(cases), totalErrors, totalWarnings)
		if totalErrors > 0 {
			return fmt.Errorf("validation failed")
		}
		return nil
	},
}

// ---------------------------------------------------------------------------
// Review commands
// ---------------------------------------------------------------------------

var reviewCmd = &cobra.Command{
	Use:   "review",
	Short: "Review pending cases",
}

func resolveProjectID() string {
	if projectFlag != "" {
		return projectFlag
	}
	return benchmarkID
}

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0644)
}

var reviewListCmd = &cobra.Command{
	Use:   "list",
	Short: "List pending review items",
	RunE: func(cmd *cobra.Command, args []string) error {
		pid := resolveProjectID()
		if pid == "" {
			return fmt.Errorf("--project is required")
		}
		hs, err := store.NewHybridStore(".", "data/benchmark.db")
		if err != nil {
			return fmt.Errorf("init hybrid store: %w", err)
		}
		defer hs.Close()
		q, err := hs.GetPendingQueue(pid)
		if err != nil {
			return fmt.Errorf("load pending queue: %w", err)
		}
		pending := reviewer.ListPending(q)
		if len(pending) == 0 {
			fmt.Println("No pending items.")
			return nil
		}
		fmt.Printf("%-18s %-8s %-18s %-20s %-10s\n", "ITEM ID", "SOURCE", "CASE ID", "RULE NAME", "STATUS")
		for _, item := range pending {
			ruleName := ""
			if item.OriginalFinding != nil {
				ruleName = item.OriginalFinding.RuleName
			}
			caseID := ""
			if item.ProposedCase != nil {
				caseID = item.ProposedCase.CaseID
			}
			fmt.Printf("%-18s %-8s %-18s %-20s %-10s\n", item.ItemID, item.Source, caseID, ruleName, item.Status)
		}
		return nil
	},
}

var reviewApproveCmd = &cobra.Command{
	Use:   "approve",
	Short: "Approve a pending case",
	RunE: func(cmd *cobra.Command, args []string) error {
		pid := resolveProjectID()
		if pid == "" {
			return fmt.Errorf("--project is required")
		}
		if itemID == "" {
			return fmt.Errorf("--item is required")
		}
		hs, err := store.NewHybridStore(".", "data/benchmark.db")
		if err != nil {
			return fmt.Errorf("init hybrid store: %w", err)
		}
		defer hs.Close()

		q, err := hs.GetPendingQueue(pid)
		if err != nil {
			return fmt.Errorf("load pending queue: %w", err)
		}
		item, err := reviewer.GetItem(q, itemID)
		if err != nil {
			return fmt.Errorf("get item: %w", err)
		}
		if item.Status != "pending" {
			return fmt.Errorf("item %q is not pending (status=%s)", itemID, item.Status)
		}

		// For legacy FSStore compatibility, also update the annotation if it exists.
		st := store.NewFSStore("data")
		annotation, err := st.ReadAnnotation(pid)
		if err == nil && annotation != nil && item.ProposedCase != nil {
			annotation.Cases = append(annotation.Cases, *item.ProposedCase)
			_ = st.WriteAnnotation(annotation)
		}

		now := time.Now().UTC()
		if err := hs.UpdatePendingItem(pid, itemID, "approved", reviewerName, notes); err != nil {
			return fmt.Errorf("approve: %w", err)
		}
		item.Status = "approved"
		item.ReviewedAt = &now
		if reviewerName != "" {
			item.Reviewer = &reviewerName
		}
		if notes != "" {
			item.ReviewNotes = &notes
		}

		fmt.Printf("Approved item %s in project %s\n", itemID, pid)
		return nil
	},
}

var reviewRejectCmd = &cobra.Command{
	Use:   "reject",
	Short: "Reject a pending case",
	RunE: func(cmd *cobra.Command, args []string) error {
		pid := resolveProjectID()
		if pid == "" {
			return fmt.Errorf("--project is required")
		}
		if itemID == "" {
			return fmt.Errorf("--item is required")
		}
		hs, err := store.NewHybridStore(".", "data/benchmark.db")
		if err != nil {
			return fmt.Errorf("init hybrid store: %w", err)
		}
		defer hs.Close()

		q, err := hs.GetPendingQueue(pid)
		if err != nil {
			return fmt.Errorf("load pending queue: %w", err)
		}
		item, err := reviewer.GetItem(q, itemID)
		if err != nil {
			return fmt.Errorf("get item: %w", err)
		}
		if item.Status != "pending" {
			return fmt.Errorf("item %q is not pending (status=%s)", itemID, item.Status)
		}

		if err := hs.UpdatePendingItem(pid, itemID, "rejected", reviewerName, reason); err != nil {
			return fmt.Errorf("reject: %w", err)
		}

		fmt.Printf("Rejected item %s in project %s\n", itemID, pid)
		return nil
	},
}

// ---------------------------------------------------------------------------
// Results
// ---------------------------------------------------------------------------

var resultsCmd = &cobra.Command{
	Use:   "results",
	Short: "View benchmark results",
}

var resultsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List stored results for a project",
	RunE: func(cmd *cobra.Command, args []string) error {
		pid := resolveProjectID()
		if pid == "" {
			return fmt.Errorf("--project is required")
		}
		hs, err := store.NewHybridStore(".", "data/benchmark.db")
		if err != nil {
			return fmt.Errorf("init hybrid store: %w", err)
		}
		defer hs.Close()

		metas, err := hs.ListResults(pid)
		if err != nil {
			return fmt.Errorf("list results: %w", err)
		}
		if len(metas) == 0 {
			fmt.Printf("No results found for project %s\n", pid)
			return nil
		}

		fmt.Printf("Project: %s\n", pid)
		fmt.Println("Results:")
		fmt.Printf("  %-12s %-20s %s\n", "ENGINE", "VERSION", "SCAN TIME")
		for _, m := range metas {
			fmt.Printf("  %-12s %-20s %s\n", m.Engine, m.EngineVersion, m.ScanTime.Format("2006-01-02 15:04:05"))
		}
		return nil
	},
}

var (
	findingsCmd = &cobra.Command{
		Use:   "findings",
		Short: "Query engine findings",
	}
	findingsListCmd = &cobra.Command{
		Use:   "list <project-id>",
		Short: "List findings with match summary",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			projectID := args[0]
			engine, _ := cmd.Flags().GetString("engine")
			version, _ := cmd.Flags().GetString("version")
			hs, err := store.NewHybridStore(".", "data/benchmark.db")
			if err != nil {
				return fmt.Errorf("init hybrid store: %w", err)
			}
			defer hs.Close()
			return runFindingsList(hs, projectID, engine, version, os.Stdout)
		},
	}
	findingsShowCmd = &cobra.Command{
		Use:   "show <project-id> <finding-index>",
		Short: "Show single finding with match details",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			projectID := args[0]
			index, err := strconv.Atoi(args[1])
			if err != nil {
				return fmt.Errorf("invalid finding index: %w", err)
			}
			engine, _ := cmd.Flags().GetString("engine")
			version, _ := cmd.Flags().GetString("version")
			hs, err := store.NewHybridStore(".", "data/benchmark.db")
			if err != nil {
				return fmt.Errorf("init hybrid store: %w", err)
			}
			defer hs.Close()
			return runFindingsShow(hs, projectID, index, engine, version, os.Stdout)
		},
	}
	rawScanCmd = &cobra.Command{
		Use:   "raw-scan <project-id>",
		Short: "Output the raw scan report JSON",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			projectID := args[0]
			engine, _ := cmd.Flags().GetString("engine")
			version, _ := cmd.Flags().GetString("version")
			hs, err := store.NewHybridStore(".", "data/benchmark.db")
			if err != nil {
				return fmt.Errorf("init hybrid store: %w", err)
			}
			defer hs.Close()
			return runRawScan(hs, projectID, engine, version, os.Stdout)
		},
	}
)

var resultsShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show a detailed benchmark result",
	RunE: func(cmd *cobra.Command, args []string) error {
		var result *schema.Result
		var pid string

		if resultFileFlag != "" {
			data, err := os.ReadFile(resultFileFlag)
			if err != nil {
				return fmt.Errorf("read result file: %w", err)
			}
			result = &schema.Result{}
			if err := json.Unmarshal(data, result); err != nil {
				return fmt.Errorf("unmarshal result: %w", err)
			}
			pid = result.BenchmarkID
		} else {
			pid = resolveProjectID()
			if pid == "" {
				return fmt.Errorf("--project or --file is required")
			}
			if engineName == "" {
				return fmt.Errorf("--engine is required when reading from store")
			}
			hs, err := store.NewHybridStore(".", "data/benchmark.db")
			if err != nil {
				return fmt.Errorf("init hybrid store: %w", err)
			}
			defer hs.Close()

			results, err := hs.ListResults(pid)
			if err != nil {
				return fmt.Errorf("list results: %w", err)
			}
			if len(results) == 0 {
				return fmt.Errorf("no results found for project %s", pid)
			}

			// If version not specified, use the latest result.
			version := engineVersion
			if version == "" {
				version = results[0].EngineVersion
			}

			result, err = hs.GetResult(pid, engineName, version)
			if err != nil {
				return fmt.Errorf("read result: %w", err)
			}
		}

		printResult(result, pid)
		return nil
	},
}

func printResult(r *schema.Result, projectID string) {
	fmt.Printf("Project:    %s\n", projectID)
	fmt.Printf("Engine:     %s %s\n", r.Engine, r.EngineVersion)
	fmt.Printf("Scan Time:  %s\n", r.ScanTime.Format("2006-01-02 15:04:05"))
	fmt.Println()

	if r.Summary != nil {
		s := r.Summary
		fmt.Println("Summary:")
		fmt.Printf("  Total Cases: %d\n", s.TotalCases)
		fmt.Printf("  TP: %-4d FN: %-4d FP: %-4d TN: %d\n", s.TP, s.FN, s.FP, s.TN)
		fmt.Printf("  Recall:    %.2f\n", s.Recall)
		fmt.Printf("  Precision: %.2f\n", s.Precision)
		fmt.Printf("  F1:        %.2f\n", s.F1)
		fmt.Println()
	}

	if len(r.CaseResults) > 0 {
		fmt.Println("Case Results:")
		fmt.Printf("  %-20s %-8s %-40s %s\n", "CASE ID", "STATUS", "MATCHED RULE", "SCORE")
		for _, cr := range r.CaseResults {
			ruleName := "-"
			if cr.MatchedFinding != nil && cr.MatchedFinding.RuleName != "" {
				ruleName = truncate(cr.MatchedFinding.RuleName, 38)
			}
			scoreStr := "-"
			if cr.MatchScore > 0 {
				scoreStr = fmt.Sprintf("%.2f", cr.MatchScore)
			}
			fmt.Printf("  %-20s %-8s %-40s %s\n", cr.CaseID, cr.Status, ruleName, scoreStr)
			if cr.MatchDetails != nil {
				md := cr.MatchDetails
				fmt.Printf("    -> Details: SourceMatch=%v SinkMatch=%v LineDist=%d\n", md.SourceMatch, md.SinkMatch, md.LineDistance)
			}
		}
	}

	if len(r.PendingReview) > 0 {
		fmt.Println()
		fmt.Printf("Pending Review: %d items\n", len(r.PendingReview))
	}
}

func truncate(s string, max int) string {
	runes := []rune(s)
	if len(runes) <= max {
		return s
	}
	return string(runes[:max-3]) + "..."
}

// resolveEngine returns an engine.Engine implementation for the given name.
func resolveEngine(name string) engine.Engine {
	switch name {
	case "yaklang":
		return runner.NewYaklangEngine("")
	case "mock":
		return &runner.MockEngine{}
	default:
		// Fallback to mock for unknown engine names during early development.
		return &runner.MockEngine{}
	}
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

var hybridStore *store.HybridStore

func initStore() error {
	var err error
	hybridStore, err = store.NewHybridStore(".", "data/benchmark.db")
	if err != nil {
		return fmt.Errorf("init hybrid store: %w", err)
	}
	return nil
}

func startServer(port int, staticDir string) error {
	if err := initStore(); err != nil {
		return err
	}
	defer hybridStore.Close()

	// Sync existing project cases into SQLite index on startup and preload
	// project metadata, cases, and file trees into the in-memory cache.
	if projects, err := hybridStore.ListProjects(); err == nil {
		for _, proj := range projects {
			if caseSet, err := hybridStore.ReadCases(proj.ProjectID); err == nil {
				_ = hybridStore.SyncCasesIndex(proj.ProjectID, caseSet.Cases)
			}
			_, _ = hybridStore.ReadFileTree(proj.ProjectID)
		}
	}

	mux := http.NewServeMux()

	// API routes
	mux.HandleFunc("/api/projects", withCORS(handleListProjects))
	mux.HandleFunc("/api/projects/{id}", withCORS(handleProject))
	mux.HandleFunc("/api/projects/{id}/files", withCORS(handleProjectFiles))
	mux.HandleFunc("/api/projects/{id}/files/{path...}", withCORS(handleProjectFileContent))
	mux.HandleFunc("/api/projects/{id}/cases", withCORS(handleProjectCases))
	mux.HandleFunc("/api/projects/{id}/results", withCORS(handleProjectResults))
	mux.HandleFunc("/api/projects/{id}/findings", withCORS(handleProjectFindings))
	mux.HandleFunc("/api/projects/{id}/diagnosis", withCORS(handleProjectDiagnosis))
	mux.HandleFunc("/api/projects/{id}/raw-scan", withCORS(handleRawScanDownload))
	mux.HandleFunc("/api/diagnosis/validate-response", withCORS(handleValidateAIResponse))
	mux.HandleFunc("/api/cases", withCORS(handleCases))
	mux.HandleFunc("/api/pending", withCORS(handlePending))
	mux.HandleFunc("/api/pending/{itemId}/approve", withCORS(handleApprove))
	mux.HandleFunc("/api/pending/{itemId}/reject", withCORS(handleReject))

	// Static files fallback with SPA support
	if staticDir != "" {
		fs := http.FileServer(http.Dir(staticDir))
		mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Try to serve the file directly
			path := filepath.Join(staticDir, filepath.Clean(r.URL.Path))
			info, err := os.Stat(path)
			if (os.IsNotExist(err) || info.IsDir()) && !strings.HasPrefix(r.URL.Path, "/api/") {
				// File/directory not found and not an API route → serve index.html for SPA routing
				r.URL.Path = "/"
			}
			fs.ServeHTTP(w, r)
		}))
	}

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	fmt.Printf("Server listening on http://localhost:%d\n", port)
	return http.ListenAndServe(addr, mux)
}

func withCORS(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next(w, r)
	}
}

func handleListProjects(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	projects, err := hybridStore.ListProjects()
	if err != nil {
		http.Error(w, fmt.Sprintf("List projects: %v", err), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=5")
	_ = json.NewEncoder(w).Encode(projects)
}

func handleProject(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	projectID := r.PathValue("id")
	proj, err := hybridStore.ReadProject(projectID)
	if err != nil {
		if os.IsNotExist(err) {
			http.Error(w, "Project not found", http.StatusNotFound)
			return
		}
		http.Error(w, fmt.Sprintf("Read project: %v", err), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=5")
	_ = json.NewEncoder(w).Encode(proj)
}

func handleProjectFiles(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	projectID := r.PathValue("id")
	root, err := hybridStore.ReadFileTree(projectID)
	if err != nil {
		if os.IsNotExist(err) {
			http.Error(w, "Source directory not found", http.StatusNotFound)
			return
		}
		http.Error(w, fmt.Sprintf("Build file tree: %v", err), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=5")
	_ = json.NewEncoder(w).Encode(root)
}

func handleProjectFileContent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	projectID := r.PathValue("id")
	filePath := r.PathValue("path")

	data, err := hybridStore.ReadFileContent(projectID, filePath)
	if err != nil {
		if os.IsNotExist(err) {
			http.Error(w, "File not found", http.StatusNotFound)
			return
		}
		if strings.Contains(err.Error(), "invalid path") {
			http.Error(w, "Invalid path", http.StatusForbidden)
			return
		}
		http.Error(w, fmt.Sprintf("Read file: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=60")
	_, _ = w.Write(data)
}

func handleProjectCases(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	projectID := r.PathValue("id")
	q := r.URL.Query()
	filter := schema.CaseFilter{
		ProjectID: projectID,
		Keyword:   q.Get("keyword"),
		CWE:       q.Get("cwe"),
		Language:  q.Get("language"),
		Tag:       q.Get("tag"),
	}

	// If no filters, return the full case set from FS (source of truth).
	if filter.Keyword == "" && filter.CWE == "" && filter.Language == "" && filter.Tag == "" {
		caseSet, err := hybridStore.ReadCases(projectID)
		if err != nil {
			if os.IsNotExist(err) {
				http.Error(w, "Cases not found", http.StatusNotFound)
				return
			}
			http.Error(w, fmt.Sprintf("Read cases: %v", err), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=5")
		_ = json.NewEncoder(w).Encode(caseSet)
		return
	}

	// Use SQLite index for filtered queries.
	results, err := hybridStore.SearchCases(filter)
	if err != nil {
		http.Error(w, fmt.Sprintf("Search cases: %v", err), http.StatusInternalServerError)
		return
	}
	// Enrich with project name.
	proj, _ := hybridStore.ReadProject(projectID)
	for i := range results {
		results[i].Project.ProjectID = projectID
		if proj != nil {
			results[i].Project.Name = proj.Name
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"cases": results})
}

func handleCases(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	q := r.URL.Query()
	filter := schema.CaseFilter{
		ProjectID: q.Get("project_id"),
		Keyword:   q.Get("keyword"),
		CWE:       q.Get("cwe"),
		Language:  q.Get("language"),
		Tag:       q.Get("tag"),
	}

	results, err := hybridStore.SearchCases(filter)
	if err != nil {
		http.Error(w, fmt.Sprintf("Search cases: %v", err), http.StatusInternalServerError)
		return
	}

	// Enrich results with project names.
	projects, _ := hybridStore.ListProjects()
	projMap := make(map[string]string, len(projects))
	for _, p := range projects {
		projMap[p.ProjectID] = p.Name
	}
	for i := range results {
		if name, ok := projMap[results[i].Project.ProjectID]; ok {
			results[i].Project.Name = name
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"cases": results})
}

func handleProjectResults(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	projectID := r.PathValue("id")
	metas, err := hybridStore.ListResults(projectID)
	if err != nil {
		http.Error(w, fmt.Sprintf("List results: %v", err), http.StatusInternalServerError)
		return
	}

	// Enrich with full result data (summary + case_results).
	var fullResults []schema.Result
	for _, m := range metas {
		result, err := hybridStore.GetResult(projectID, m.Engine, m.EngineVersion)
		if err != nil {
			continue
		}
		fullResults = append(fullResults, *result)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(fullResults)
}

func handleProjectFindings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	projectID := r.PathValue("id")

	engine := r.URL.Query().Get("engine")
	version := r.URL.Query().Get("version")

	// If engine/version not specified, list available finding sets.
	if engine == "" || version == "" {
		metas, err := hybridStore.ListResults(projectID)
		if err != nil {
			http.Error(w, fmt.Sprintf("List results: %v", err), http.StatusInternalServerError)
			return
		}
		// Reuse result meta as finding set meta (same engine/version keys).
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"versions": metas})
		return
	}

	findingSet, err := hybridStore.GetFindings(projectID, engine, version)
	if err != nil {
		http.Error(w, fmt.Sprintf("Get findings: %v", err), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(findingSet)
}

func handleProjectDiagnosis(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	projectID := r.PathValue("id")
	engine := r.URL.Query().Get("engine")
	version := r.URL.Query().Get("version")
	format := r.URL.Query().Get("format")
	report, err := buildDiagnosisReportForHTTP(projectID, engine, version)
	if err != nil {
		http.Error(w, fmt.Sprintf("Build diagnosis: %v", err), http.StatusInternalServerError)
		return
	}
	writeDiagnosisResponse(w, *report, format, diagnosisBundleOptionsFromQuery(r))
}

func writeDiagnosisResponse(w http.ResponseWriter, report diagnose.Report, format string, bundleOptions diagnose.DiagnosticBundleOptions) {
	switch format {
	case "prompt":
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	case "markdown", "md":
		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	default:
		w.Header().Set("Content-Type", "application/json")
	}
	if err := renderDiagnosis(report, format, bundleOptions, w); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
}

func handleValidateAIResponse(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("Read response: %v", err), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(diagnose.ValidateAIResponse(body))
}

func diagnosisBundleOptionsFromQuery(r *http.Request) diagnose.DiagnosticBundleOptions {
	return diagnose.DiagnosticBundleOptions{
		MaxPriorities:  positiveIntQuery(r, "max_priorities"),
		MaxRuleReviews: positiveIntQuery(r, "max_rule_reviews"),
	}
}

func positiveIntQuery(r *http.Request, name string) int {
	value := r.URL.Query().Get(name)
	if value == "" {
		return 0
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 0 {
		return 0
	}
	return parsed
}

func buildDiagnosisReportForHTTP(projectID, engine, version string) (*diagnose.Report, error) {
	engine, version, err := resolveScanVersion(hybridStore, projectID, engine, version)
	if err != nil {
		return nil, err
	}
	project, err := hybridStore.ReadProject(projectID)
	if err != nil {
		return nil, err
	}
	caseSet, err := hybridStore.ReadCases(projectID)
	if err != nil {
		return nil, err
	}
	findingSet, err := hybridStore.GetFindings(projectID, engine, version)
	if err != nil {
		return nil, err
	}
	result, _ := hybridStore.GetResult(projectID, engine, version)
	report := diagnose.BuildReport(diagnose.BuildReportInput{
		ProjectID:     projectID,
		ProjectName:   project.Name,
		Engine:        engine,
		EngineVersion: version,
		Cases:         caseSet.Cases,
		Findings:      findingSet.Findings,
		Result:        result,
		RuleRoot:      filepath.Join("..", "yaklang", "common", "syntaxflow", "sfbuildin", "buildin"),
	})
	return &report, nil
}

func handleRawScanDownload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	projectID := r.PathValue("id")
	engine := r.URL.Query().Get("engine")
	version := r.URL.Query().Get("version")
	if engine == "" || version == "" {
		http.Error(w, "engine and version required", http.StatusBadRequest)
		return
	}

	// Try SQLite (HybridStore) first.
	data, format, err := hybridStore.GetRawReport(projectID, engine, version)
	if err != nil {
		// Fallback to filesystem.
		rawPath := filepath.Join("data", "raw-reports", projectID, fmt.Sprintf("%s-%s.json", engine, version))
		data, err = os.ReadFile(rawPath)
		if err != nil {
			if os.IsNotExist(err) {
				http.Error(w, "Raw scan not found", http.StatusNotFound)
				return
			}
			http.Error(w, fmt.Sprintf("Read raw scan: %v", err), http.StatusInternalServerError)
			return
		}
		format = "json"
	}

	contentType := "application/json"
	if format == "yaml" || format == "yml" {
		contentType = "application/x-yaml"
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s_%s_%s_scan.json", projectID, engine, version))
	w.Write(data)
}

func handlePending(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	projects, err := hybridStore.ListProjects()
	if err != nil {
		http.Error(w, fmt.Sprintf("List projects: %v", err), http.StatusInternalServerError)
		return
	}
	allItems := []schema.PendingItem{}
	for _, proj := range projects {
		queue, err := hybridStore.GetPendingQueue(proj.ProjectID)
		if err != nil {
			continue
		}
		for i := range queue.Items {
			queue.Items[i].ProjectID = proj.ProjectID
			allItems = append(allItems, queue.Items[i])
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"items": allItems})
}

func handleApprove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	itemID := r.PathValue("itemId")
	if itemID == "" {
		http.Error(w, "itemId required", http.StatusBadRequest)
		return
	}

	var req struct {
		Reviewer string `json:"reviewer"`
		Notes    string `json:"notes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		req.Reviewer = "user"
	}

	// Find the project for this item
	projects, err := hybridStore.ListProjects()
	if err != nil {
		http.Error(w, fmt.Sprintf("List projects: %v", err), http.StatusInternalServerError)
		return
	}
	var targetProjectID string
	for _, proj := range projects {
		queue, err := hybridStore.GetPendingQueue(proj.ProjectID)
		if err != nil {
			continue
		}
		for _, item := range queue.Items {
			if item.ItemID == itemID {
				targetProjectID = proj.ProjectID
				break
			}
		}
		if targetProjectID != "" {
			break
		}
	}
	if targetProjectID == "" {
		http.Error(w, "Item not found", http.StatusNotFound)
		return
	}

	if err := hybridStore.UpdatePendingItem(targetProjectID, itemID, "approved", req.Reviewer, req.Notes); err != nil {
		http.Error(w, fmt.Sprintf("Update item: %v", err), http.StatusInternalServerError)
		return
	}

	// Also append the proposed case to the project's cases.yaml
	queue, _ := hybridStore.GetPendingQueue(targetProjectID)
	for _, item := range queue.Items {
		if item.ItemID == itemID && item.ProposedCase != nil {
			cm := casepkg.NewManager(hybridStore)
			if err := cm.Create(targetProjectID, *item.ProposedCase); err != nil {
				http.Error(w, fmt.Sprintf("Create case: %v", err), http.StatusInternalServerError)
				return
			}
			break
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"status": "approved", "item_id": itemID})
}

func handleReject(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	itemID := r.PathValue("itemId")
	if itemID == "" {
		http.Error(w, "itemId required", http.StatusBadRequest)
		return
	}

	var req struct {
		Reviewer string `json:"reviewer"`
		Reason   string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		req.Reviewer = "user"
	}

	// Find the project for this item
	projects, err := hybridStore.ListProjects()
	if err != nil {
		http.Error(w, fmt.Sprintf("List projects: %v", err), http.StatusInternalServerError)
		return
	}
	var targetProjectID string
	for _, proj := range projects {
		queue, err := hybridStore.GetPendingQueue(proj.ProjectID)
		if err != nil {
			continue
		}
		for _, item := range queue.Items {
			if item.ItemID == itemID {
				targetProjectID = proj.ProjectID
				break
			}
		}
		if targetProjectID != "" {
			break
		}
	}
	if targetProjectID == "" {
		http.Error(w, "Item not found", http.StatusNotFound)
		return
	}

	if err := hybridStore.UpdatePendingItem(targetProjectID, itemID, "rejected", req.Reviewer, req.Reason); err != nil {
		http.Error(w, fmt.Sprintf("Update item: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"status": "rejected", "item_id": itemID})
}
