package store

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
	"github.com/irify/irify-benchmark/pkg/schema"
)

const (
	defaultCacheTTL = 5 * time.Minute
	fileContentTTL  = 30 * time.Second
)

// HybridStore combines filesystem storage for projects/cases with SQLite for runtime data.
type HybridStore struct {
	fs      *FSStore
	sqlite  *SQLiteStore
	baseDir string
	cache   *Cache
}

// NewHybridStore creates a new HybridStore rooted at baseDir with a SQLite database at dbPath.
func NewHybridStore(baseDir, dbPath string) (*HybridStore, error) {
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		return nil, fmt.Errorf("mkdir baseDir: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(dbPath), 0755); err != nil {
		return nil, fmt.Errorf("mkdir db dir: %w", err)
	}
	fs := NewFSStore(filepath.Join(baseDir, "data"))
	sqlite, err := NewSQLiteStore(dbPath)
	if err != nil {
		return nil, fmt.Errorf("new sqlite store: %w", err)
	}
	return &HybridStore{
		fs:      fs,
		sqlite:  sqlite,
		baseDir: baseDir,
		cache:   NewCache(defaultCacheTTL),
	}, nil
}

// Close closes the underlying SQLite database.
func (h *HybridStore) Close() error {
	return h.sqlite.Close()
}

func (h *HybridStore) casesDir() string {
	return filepath.Join(h.baseDir, "cases")
}

func (h *HybridStore) projectDir(projectID string) string {
	return filepath.Join(h.casesDir(), projectID)
}

func (h *HybridStore) cacheKey(kind, projectID string) string {
	return kind + ":" + projectID
}

// InvalidateProjectCache clears all cached data for a project.
func (h *HybridStore) InvalidateProjectCache(projectID string) {
	prefix := ":" + projectID + ":"
	h.cache.Delete(h.cacheKey("project", projectID))
	h.cache.Delete(h.cacheKey("cases", projectID))
	h.cache.Delete(h.cacheKey("files", projectID))
	h.cache.DeletePrefix("file" + prefix)
}

// ReadProject reads a project's metadata from the filesystem.
func (h *HybridStore) ReadProject(projectID string) (*schema.Project, error) {
	key := h.cacheKey("project", projectID)
	if v, ok := getTyped[*schema.Project](h.cache, key); ok {
		return v, nil
	}

	path := filepath.Join(h.projectDir(projectID), "project.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read project yaml: %w", err)
	}
	var p schema.Project
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("unmarshal project: %w", err)
	}
	h.cache.Set(key, &p, 0)
	return &p, nil
}

// WriteProject writes a project's metadata to the filesystem.
func (h *HybridStore) WriteProject(p *schema.Project) error {
	dir := h.projectDir(p.ProjectID)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("mkdir project dir: %w", err)
	}
	data, err := yaml.Marshal(p)
	if err != nil {
		return fmt.Errorf("marshal project: %w", err)
	}
	path := filepath.Join(dir, "project.yaml")
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("write project yaml: %w", err)
	}
	h.InvalidateProjectCache(p.ProjectID)
	return nil
}

// ReadCases reads the ground-truth case set for a project from the filesystem.
func (h *HybridStore) ReadCases(projectID string) (*schema.CaseSet, error) {
	key := h.cacheKey("cases", projectID)
	if v, ok := getTyped[*schema.CaseSet](h.cache, key); ok {
		return v, nil
	}

	path := filepath.Join(h.projectDir(projectID), "cases.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read cases yaml: %w", err)
	}
	var c schema.CaseSet
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("unmarshal cases: %w", err)
	}
	h.cache.Set(key, &c, 0)
	return &c, nil
}

// WriteCases writes a case set for a project to the filesystem and syncs the SQLite index.
func (h *HybridStore) WriteCases(c *schema.CaseSet) error {
	dir := h.projectDir(c.ProjectID)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("mkdir cases dir: %w", err)
	}
	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("marshal cases: %w", err)
	}
	path := filepath.Join(dir, "cases.yaml")
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("write cases yaml: %w", err)
	}
	// Sync SQLite index for query/filter support.
	if err := h.sqlite.SyncCasesIndex(c.ProjectID, c.Cases); err != nil {
		// Non-fatal: FS is the source of truth.
		_ = err
	}
	h.InvalidateProjectCache(c.ProjectID)
	return nil
}

// ListProjects scans the cases directory and returns all valid projects.
func (h *HybridStore) ListProjects() ([]schema.Project, error) {
	entries, err := os.ReadDir(h.casesDir())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read cases dir: %w", err)
	}

	var projects []schema.Project
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		p, err := h.ReadProject(entry.Name())
		if err != nil {
			// Skip directories without a valid project.yaml.
			continue
		}
		projects = append(projects, *p)
	}
	return projects, nil
}

// FileNode represents a node in a project's source file tree.
type FileNode struct {
	Name     string     `json:"name"`
	Type     string     `json:"type"` // "directory" or "file"
	Path     string     `json:"path,omitempty"`
	Children []FileNode `json:"children,omitempty"`
}

// ReadFileTree returns the source file tree for a project, cached in memory.
func (h *HybridStore) ReadFileTree(projectID string) (*FileNode, error) {
	key := h.cacheKey("files", projectID)
	if v, ok := getTyped[*FileNode](h.cache, key); ok {
		return v, nil
	}

	srcDir := filepath.Join(h.projectDir(projectID), "src")
	root, err := h.buildFileTree(srcDir, "")
	if err != nil {
		return nil, err
	}
	h.cache.Set(key, root, 0)
	return root, nil
}

func (h *HybridStore) buildFileTree(dir, relPath string) (*FileNode, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	node := &FileNode{
		Name: filepath.Base(relPath),
		Type: "directory",
	}
	if relPath == "" {
		node.Name = "src"
	}

	for _, entry := range entries {
		childRelPath := filepath.Join(relPath, entry.Name())
		if entry.IsDir() {
			child, err := h.buildFileTree(filepath.Join(dir, entry.Name()), childRelPath)
			if err != nil {
				return nil, err
			}
			node.Children = append(node.Children, *child)
		} else {
			node.Children = append(node.Children, FileNode{
				Name: entry.Name(),
				Type: "file",
				Path: childRelPath,
			})
		}
	}
	return node, nil
}

// ReadFileContent returns the contents of a source file, cached in memory.
func (h *HybridStore) ReadFileContent(projectID, filePath string) ([]byte, error) {
	key := h.cacheKey("file", projectID) + ":" + filePath
	if v, ok := getTyped[[]byte](h.cache, key); ok {
		return v, nil
	}

	fullPath := filepath.Join(h.projectDir(projectID), "src", filePath)
	absPath, err := filepath.Abs(fullPath)
	if err != nil {
		return nil, fmt.Errorf("invalid path: %w", err)
	}
	absBase, err := filepath.Abs(filepath.Join(h.projectDir(projectID), "src"))
	if err != nil {
		return nil, fmt.Errorf("invalid base: %w", err)
	}
	if !strings.HasPrefix(absPath, absBase+string(filepath.Separator)) && absPath != absBase {
		return nil, fmt.Errorf("invalid path")
	}

	data, err := os.ReadFile(absPath)
	if err != nil {
		return nil, err
	}
	h.cache.Set(key, data, fileContentTTL)
	return data, nil
}

// SaveFindings delegates to the SQLite store.
func (h *HybridStore) SaveFindings(projectID string, findings *schema.FindingSet) error {
	return h.sqlite.SaveFindings(projectID, findings)
}

// GetFindings delegates to the SQLite store.
func (h *HybridStore) GetFindings(projectID, engine, version string) (*schema.FindingSet, error) {
	return h.sqlite.GetFindings(projectID, engine, version)
}

// SaveResult delegates to the SQLite store.
func (h *HybridStore) SaveResult(projectID string, result *schema.Result) error {
	return h.sqlite.SaveResult(projectID, result)
}

// GetResult delegates to the SQLite store.
func (h *HybridStore) GetResult(projectID, engine, version string) (*schema.Result, error) {
	return h.sqlite.GetResult(projectID, engine, version)
}

// GetLatestResult delegates to the SQLite store.
func (h *HybridStore) GetLatestResult(projectID, engine string) (*schema.Result, error) {
	return h.sqlite.GetLatestResult(projectID, engine)
}

// ListResults delegates to the SQLite store.
func (h *HybridStore) ListResults(projectID string) ([]schema.ResultMeta, error) {
	return h.sqlite.ListResults(projectID)
}

// SavePendingItem delegates to the SQLite store.
func (h *HybridStore) SavePendingItem(projectID string, item schema.PendingItem) error {
	return h.sqlite.SavePendingItem(projectID, item)
}

// GetPendingQueue delegates to the SQLite store.
func (h *HybridStore) GetPendingQueue(projectID string) (*schema.PendingQueue, error) {
	return h.sqlite.GetPendingQueue(projectID)
}

// UpdatePendingItem delegates to the SQLite store.
func (h *HybridStore) UpdatePendingItem(projectID, itemID, status, reviewer, notes string) error {
	return h.sqlite.UpdatePendingItem(projectID, itemID, status, reviewer, notes)
}

// SearchCases delegates to the SQLite store.
func (h *HybridStore) SearchCases(filter schema.CaseFilter) ([]schema.CaseWithProject, error) {
	return h.sqlite.SearchCases(filter)
}

// SyncCasesIndex delegates to the SQLite store.
func (h *HybridStore) SyncCasesIndex(projectID string, cases []schema.Case) error {
	return h.sqlite.SyncCasesIndex(projectID, cases)
}

// SaveRawReport delegates to the SQLite store.
func (h *HybridStore) SaveRawReport(projectID, engine, version, format string, data []byte) error {
	return h.sqlite.SaveRawReport(projectID, engine, version, format, data)
}

// GetRawReport delegates to the SQLite store.
func (h *HybridStore) GetRawReport(projectID, engine, version string) ([]byte, string, error) {
	return h.sqlite.GetRawReport(projectID, engine, version)
}
