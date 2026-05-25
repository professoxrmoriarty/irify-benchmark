// Package project provides project management operations for the benchmark framework.
package project

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"time"

	"gopkg.in/yaml.v3"
	"github.com/irify/irify-benchmark/pkg/schema"
	"github.com/irify/irify-benchmark/internal/store"
)

// FileEntry represents a single node in the project source file tree.
type FileEntry struct {
	Name     string      `json:"name"`
	Type     string      `json:"type"` // "file" | "directory"
	Path     string      `json:"path"`
	Children []FileEntry `json:"children,omitempty"`
}

// Manager handles lifecycle operations for benchmark projects.
type Manager struct {
	Store *store.HybridStore
}

// NewManager creates a new project manager backed by the given HybridStore.
func NewManager(store *store.HybridStore) *Manager {
	return &Manager{Store: store}
}

// gitAdd runs `git add` on the provided paths, silently ignoring errors.
func gitAdd(paths ...string) error {
	args := append([]string{"add"}, paths...)
	cmd := exec.Command("git", args...)
	return cmd.Run()
}

// Create initializes a new project with directory structure and metadata files.
func (m *Manager) Create(projectID, name, language, description, sourceRoot string) (*schema.Project, error) {
	if sourceRoot == "" {
		sourceRoot = "src/"
	}
	p := &schema.Project{
		ProjectID:   projectID,
		Name:        name,
		Language:    language,
		Description: description,
		SourceRoot:  sourceRoot,
		CreatedAt:   time.Now().UTC().Format(time.RFC3339),
	}

	dir := filepath.Join("cases", projectID)
	if _, err := os.Stat(dir); err == nil {
		return nil, fmt.Errorf("project %q already exists", projectID)
	}

	srcDir := filepath.Join(dir, "src")
	if err := os.MkdirAll(srcDir, 0755); err != nil {
		return nil, fmt.Errorf("mkdir src: %w", err)
	}

	if err := m.Store.WriteProject(p); err != nil {
		return nil, fmt.Errorf("write project: %w", err)
	}

	caseSet := &schema.CaseSet{
		ProjectID: projectID,
		Version:   "1.0.0",
		Cases:     []schema.Case{},
	}
	if err := m.Store.WriteCases(caseSet); err != nil {
		return nil, fmt.Errorf("write cases skeleton: %w", err)
	}

	_ = gitAdd(
		filepath.Join(dir, "project.yaml"),
		filepath.Join(dir, "cases.yaml"),
		srcDir,
	)

	return p, nil
}

// Import creates a project by copying an existing directory into the project source tree.
func (m *Manager) Import(projectID, name, language string, fromDir string) (*schema.Project, error) {
	p := &schema.Project{
		ProjectID:  projectID,
		Name:       name,
		Language:   language,
		SourceRoot: "src/",
		CreatedAt:  time.Now().UTC().Format(time.RFC3339),
	}

	dir := filepath.Join("cases", projectID)
	srcDir := filepath.Join(dir, "src")

	if err := os.MkdirAll(srcDir, 0755); err != nil {
		return nil, fmt.Errorf("mkdir src: %w", err)
	}

	if err := copyDirContents(fromDir, srcDir); err != nil {
		return nil, fmt.Errorf("copy dir contents: %w", err)
	}

	if err := m.Store.WriteProject(p); err != nil {
		return nil, fmt.Errorf("write project: %w", err)
	}

	caseSet := &schema.CaseSet{
		ProjectID: projectID,
		Version:   "1.0.0",
		Cases:     []schema.Case{},
	}
	if err := m.Store.WriteCases(caseSet); err != nil {
		return nil, fmt.Errorf("write cases skeleton: %w", err)
	}

	_ = gitAdd(
		filepath.Join(dir, "project.yaml"),
		filepath.Join(dir, "cases.yaml"),
		srcDir,
	)

	return p, nil
}

// Describe updates the description field of an existing project.
func (m *Manager) Describe(projectID, description string) error {
	p, err := m.Store.ReadProject(projectID)
	if err != nil {
		return fmt.Errorf("read project: %w", err)
	}
	p.Description = description
	if err := m.Store.WriteProject(p); err != nil {
		return fmt.Errorf("write project: %w", err)
	}
	_ = gitAdd(filepath.Join("cases", projectID, "project.yaml"))
	return nil
}

// List returns all projects in the store.
func (m *Manager) List() ([]schema.Project, error) {
	return m.Store.ListProjects()
}

// Delete removes a project and all its associated files.
func (m *Manager) Delete(projectID string) error {
	dir := filepath.Join("cases", projectID)
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("remove project dir: %w", err)
	}
	return nil
}

// AddFile writes a file into the project's source tree, creating parent directories as needed.
func (m *Manager) AddFile(projectID, filePath string, content []byte) error {
	fullPath := filepath.Join("cases", projectID, "src", filePath)
	if err := os.MkdirAll(filepath.Dir(fullPath), 0755); err != nil {
		return fmt.Errorf("mkdir parent: %w", err)
	}
	if err := os.WriteFile(fullPath, content, 0644); err != nil {
		return fmt.Errorf("write file: %w", err)
	}
	_ = gitAdd(fullPath)
	return nil
}

// Mkdir creates a directory inside the project's source tree.
func (m *Manager) Mkdir(projectID, dirPath string) error {
	fullPath := filepath.Join("cases", projectID, "src", dirPath)
	if err := os.MkdirAll(fullPath, 0755); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}
	_ = gitAdd(fullPath)
	return nil
}

// CopyDir recursively copies all files from fromDir into the project's source tree at toDir.
func (m *Manager) CopyDir(projectID, fromDir, toDir string) error {
	targetDir := filepath.Join("cases", projectID, "src", toDir)
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return fmt.Errorf("mkdir target: %w", err)
	}
	if err := copyDirContents(fromDir, targetDir); err != nil {
		return fmt.Errorf("copy dir contents: %w", err)
	}
	_ = gitAdd(targetDir)
	return nil
}

// Files returns the file tree of the project's source directory.
func (m *Manager) Files(projectID string) ([]FileEntry, error) {
	srcDir := filepath.Join("cases", projectID, "src")
	entries, err := os.ReadDir(srcDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read src dir: %w", err)
	}
	return buildEntries(srcDir, "", entries), nil
}

func buildEntries(baseDir, relPath string, entries []os.DirEntry) []FileEntry {
	var result []FileEntry
	for _, entry := range entries {
		childRelPath := filepath.Join(relPath, entry.Name())
		if entry.IsDir() {
			subEntries, err := os.ReadDir(filepath.Join(baseDir, childRelPath))
			if err != nil {
				continue
			}
			result = append(result, FileEntry{
				Name:     entry.Name(),
				Type:     "directory",
				Path:     childRelPath,
				Children: buildEntries(baseDir, childRelPath, subEntries),
			})
		} else {
			result = append(result, FileEntry{
				Name: entry.Name(),
				Type: "file",
				Path: childRelPath,
			})
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Type != result[j].Type {
			return result[i].Type == "directory"
		}
		return result[i].Name < result[j].Name
	})
	return result
}

// copyDirContents recursively copies files and directories from src to dst.
func copyDirContents(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		relPath, err := filepath.Rel(src, path)
		if err != nil {
			return fmt.Errorf("rel path: %w", err)
		}
		targetPath := filepath.Join(dst, relPath)
		if info.IsDir() {
			return os.MkdirAll(targetPath, info.Mode())
		}
		srcFile, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("open src file: %w", err)
		}
		defer srcFile.Close()

		if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
			return fmt.Errorf("mkdir parent: %w", err)
		}
		dstFile, err := os.OpenFile(targetPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, info.Mode())
		if err != nil {
			return fmt.Errorf("open dst file: %w", err)
		}
		defer dstFile.Close()

		if _, err := io.Copy(dstFile, srcFile); err != nil {
			return fmt.Errorf("copy file: %w", err)
		}
		return nil
	})
}

// PrintFilesTree prints an indented file tree to stdout.
func PrintFilesTree(entries []FileEntry, prefix string) {
	for i, entry := range entries {
		isLast := i == len(entries)-1
		connector := "├── "
		if isLast {
			connector = "└── "
		}
		fmt.Printf("%s%s%s\n", prefix, connector, entry.Name)
		if entry.Type == "directory" && len(entry.Children) > 0 {
			extension := "│   "
			if isLast {
				extension = "    "
			}
			PrintFilesTree(entry.Children, prefix+extension)
		}
	}
}

// PrintCaseYAML prints a case in a YAML-like formatted output.
func PrintCaseYAML(c *schema.Case) error {
	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("marshal case: %w", err)
	}
	fmt.Print(string(data))
	return nil
}
