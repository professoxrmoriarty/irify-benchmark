// Package cases provides case management operations for the benchmark framework.
package cases

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/irify/irify-benchmark/pkg/schema"
	"github.com/irify/irify-benchmark/internal/store"
)

// Manager handles lifecycle operations for benchmark cases within a project.
type Manager struct {
	Store *store.HybridStore
}

// NewManager creates a new case manager backed by the given HybridStore.
func NewManager(store *store.HybridStore) *Manager {
	return &Manager{Store: store}
}

// gitAdd runs `git add` on the provided paths, silently ignoring errors.
func gitAdd(paths ...string) error {
	args := append([]string{"add"}, paths...)
	cmd := exec.Command("git", args...)
	return cmd.Run()
}

// Create appends a new case to the project's case set, or updates it if the case_id already exists.
func (m *Manager) Create(projectID string, c schema.Case) error {
	projectDir := filepath.Join("cases", projectID)
	if _, err := os.Stat(projectDir); os.IsNotExist(err) {
		return fmt.Errorf("project %q does not exist", projectID)
	}
	caseSet, err := m.Store.ReadCases(projectID)
	if err != nil {
		return fmt.Errorf("read cases: %w", err)
	}

	found := false
	for i := range caseSet.Cases {
		if caseSet.Cases[i].CaseID == c.CaseID {
			caseSet.Cases[i] = c
			found = true
			break
		}
	}
	if !found {
		caseSet.Cases = append(caseSet.Cases, c)
	}

	if err := m.Store.WriteCases(caseSet); err != nil {
		return fmt.Errorf("write cases: %w", err)
	}

	_ = gitAdd(filepath.Join("cases", projectID, "cases.yaml"))
	return nil
}

// List returns all cases for a project.
func (m *Manager) List(projectID string) ([]schema.Case, error) {
	caseSet, err := m.Store.ReadCases(projectID)
	if err != nil {
		return nil, fmt.Errorf("read cases: %w", err)
	}
	return caseSet.Cases, nil
}

// Get returns a single case by ID.
func (m *Manager) Get(projectID, caseID string) (*schema.Case, error) {
	caseSet, err := m.Store.ReadCases(projectID)
	if err != nil {
		return nil, fmt.Errorf("read cases: %w", err)
	}
	for i := range caseSet.Cases {
		if caseSet.Cases[i].CaseID == caseID {
			return &caseSet.Cases[i], nil
		}
	}
	return nil, fmt.Errorf("case %q not found in project %q", caseID, projectID)
}

// Delete removes a case from the project's case set.
func (m *Manager) Delete(projectID, caseID string) error {
	caseSet, err := m.Store.ReadCases(projectID)
	if err != nil {
		return fmt.Errorf("read cases: %w", err)
	}
	found := false
	var filtered []schema.Case
	for _, c := range caseSet.Cases {
		if c.CaseID == caseID {
			found = true
			continue
		}
		filtered = append(filtered, c)
	}
	if !found {
		return fmt.Errorf("case %q not found in project %q", caseID, projectID)
	}
	caseSet.Cases = filtered
	if err := m.Store.WriteCases(caseSet); err != nil {
		return fmt.Errorf("write cases: %w", err)
	}
	_ = gitAdd(filepath.Join("cases", projectID, "cases.yaml"))
	return nil
}

// Search searches cases across all projects (or a specific project) with filtering.
func (m *Manager) Search(filter schema.CaseFilter) ([]schema.CaseWithProject, error) {
	return m.Store.SearchCases(filter)
}
