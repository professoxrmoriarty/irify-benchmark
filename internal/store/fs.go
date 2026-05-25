package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/irify/irify-benchmark/pkg/schema"
)

// FSStore implements Store using the local filesystem with human-readable JSON files.
type FSStore struct {
	baseDir string
}

// NewFSStore creates a new filesystem-backed store rooted at baseDir.
func NewFSStore(baseDir string) *FSStore {
	return &FSStore{baseDir: baseDir}
}

func (s *FSStore) annotationPath(benchmarkID string) string {
	return filepath.Join(s.baseDir, "annotations", benchmarkID+".json")
}

func (s *FSStore) findingPath(benchmarkID, engine, version string) string {
	return filepath.Join(s.baseDir, "findings", benchmarkID, fmt.Sprintf("%s-%s.json", engine, version))
}

func (s *FSStore) resultPath(benchmarkID, engine, version string) string {
	return filepath.Join(s.baseDir, "results", benchmarkID, fmt.Sprintf("%s-%s.json", engine, version))
}

func (s *FSStore) pendingPath(benchmarkID string) string {
	return filepath.Join(s.baseDir, "pending", benchmarkID+".json")
}

func (s *FSStore) rawReportPath(benchmarkID, engine, version string) string {
	return filepath.Join(s.baseDir, "raw-reports", benchmarkID, fmt.Sprintf("%s-%s.json", engine, version))
}

// ReadAnnotation loads an annotation from disk. Returns an empty struct if the file does not exist.
func (s *FSStore) ReadAnnotation(benchmarkID string) (*schema.Annotation, error) {
	path := s.annotationPath(benchmarkID)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &schema.Annotation{BenchmarkID: benchmarkID}, nil
		}
		return nil, fmt.Errorf("read annotation: %w", err)
	}
	var a schema.Annotation
	if err := json.Unmarshal(data, &a); err != nil {
		return nil, fmt.Errorf("unmarshal annotation: %w", err)
	}
	return &a, nil
}

// WriteAnnotation persists an annotation to disk.
func (s *FSStore) WriteAnnotation(a *schema.Annotation) error {
	path := s.annotationPath(a.BenchmarkID)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("mkdir for annotation: %w", err)
	}
	data, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal annotation: %w", err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("write annotation: %w", err)
	}
	return nil
}

// ReadFindingSet loads a finding set from disk. Returns an empty struct if the file does not exist.
func (s *FSStore) ReadFindingSet(benchmarkID, engine, version string) (*schema.FindingSet, error) {
	path := s.findingPath(benchmarkID, engine, version)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &schema.FindingSet{BenchmarkID: benchmarkID, Engine: engine, EngineVersion: version}, nil
		}
		return nil, fmt.Errorf("read findings: %w", err)
	}
	var f schema.FindingSet
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("unmarshal findings: %w", err)
	}
	return &f, nil
}

// WriteFindingSet persists a finding set to disk.
func (s *FSStore) WriteFindingSet(f *schema.FindingSet) error {
	path := s.findingPath(f.BenchmarkID, f.Engine, f.EngineVersion)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("mkdir for findings: %w", err)
	}
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal findings: %w", err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("write findings: %w", err)
	}
	return nil
}

// ReadResult loads a result from disk. Returns an empty struct if the file does not exist.
func (s *FSStore) ReadResult(benchmarkID, engine, version string) (*schema.Result, error) {
	path := s.resultPath(benchmarkID, engine, version)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &schema.Result{BenchmarkID: benchmarkID, Engine: engine, EngineVersion: version}, nil
		}
		return nil, fmt.Errorf("read result: %w", err)
	}
	var r schema.Result
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("unmarshal result: %w", err)
	}
	return &r, nil
}

// WriteResult persists a result to disk.
func (s *FSStore) WriteResult(r *schema.Result) error {
	path := s.resultPath(r.BenchmarkID, r.Engine, r.EngineVersion)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("mkdir for result: %w", err)
	}
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal result: %w", err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("write result: %w", err)
	}
	return nil
}

// ReadPendingQueue loads a pending queue from disk. Returns an empty struct if the file does not exist.
func (s *FSStore) ReadPendingQueue(benchmarkID string) (*schema.PendingQueue, error) {
	path := s.pendingPath(benchmarkID)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &schema.PendingQueue{BenchmarkID: benchmarkID}, nil
		}
		return nil, fmt.Errorf("read pending queue: %w", err)
	}
	var q schema.PendingQueue
	if err := json.Unmarshal(data, &q); err != nil {
		return nil, fmt.Errorf("unmarshal pending queue: %w", err)
	}
	return &q, nil
}

// WritePendingQueue persists a pending queue to disk.
func (s *FSStore) WritePendingQueue(q *schema.PendingQueue) error {
	path := s.pendingPath(q.BenchmarkID)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("mkdir for pending queue: %w", err)
	}
	data, err := json.MarshalIndent(q, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal pending queue: %w", err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("write pending queue: %w", err)
	}
	return nil
}

// SaveRawReport persists the original engine output bytes to disk.
func (s *FSStore) SaveRawReport(benchmarkID, engine, version, format string, data []byte) error {
	path := s.rawReportPath(benchmarkID, engine, version)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("mkdir for raw report: %w", err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("write raw report: %w", err)
	}
	return nil
}

// ReadRawReport loads the original engine output bytes from disk.
func (s *FSStore) ReadRawReport(benchmarkID, engine, version string) ([]byte, string, error) {
	path := s.rawReportPath(benchmarkID, engine, version)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, "", fmt.Errorf("raw report not found")
		}
		return nil, "", fmt.Errorf("read raw report: %w", err)
	}
	return data, "json", nil
}
