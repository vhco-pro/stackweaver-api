// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package terraform

import (
	"errors"
	"testing"

	"github.com/michielvha/stackweaver/core/models"
	"gorm.io/gorm"
)

type fakeDriftRuns struct {
	existing []models.Run
	created  []*models.Run
}

func (f *fakeDriftRuns) ListByWorkspace(string, int, int) ([]models.Run, int64, error) {
	return f.existing, int64(len(f.existing)), nil
}

func (f *fakeDriftRuns) Create(run *models.Run) error {
	f.created = append(f.created, run)
	return nil
}

type fakeDriftConfigVersions struct {
	cv  *models.ConfigurationVersion
	err error
}

func (f *fakeDriftConfigVersions) GetLatestByWorkspaceID(string) (*models.ConfigurationVersion, error) {
	return f.cv, f.err
}

// TestExecuteDriftCheck_ConfigurationVersion pins issue #819: a drift run must carry the
// workspace's latest uploaded configuration version, and no run is created when there is none.
func TestExecuteDriftCheck_ConfigurationVersion(t *testing.T) {
	tests := []struct {
		name      string
		cvs       *fakeDriftConfigVersions
		wantRun   bool
		wantCVID  string
		wantError bool
	}{
		{
			name:     "uses latest uploaded configuration version",
			cvs:      &fakeDriftConfigVersions{cv: &models.ConfigurationVersion{ID: "cv-latest", Status: models.ConfigurationVersionStatusUploaded}},
			wantRun:  true,
			wantCVID: "cv-latest",
		},
		{
			name:    "skips when workspace has no configuration version",
			cvs:     &fakeDriftConfigVersions{err: gorm.ErrRecordNotFound},
			wantRun: false,
		},
		{
			name:    "skips when latest configuration version is not uploaded",
			cvs:     &fakeDriftConfigVersions{cv: &models.ConfigurationVersion{ID: "cv-pending", Status: models.ConfigurationVersionStatusPending}},
			wantRun: false,
		},
		{
			name:      "returns lookup errors without creating a run",
			cvs:       &fakeDriftConfigVersions{err: errors.New("connection refused")},
			wantRun:   false,
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runs := &fakeDriftRuns{}
			s := &DriftDetectionService{runRepo: runs, configVersionRepo: tt.cvs}

			err := s.executeDriftCheck(t.Context(), &models.Workspace{ID: "ws-1", Name: "ws"})
			if (err != nil) != tt.wantError {
				t.Fatalf("executeDriftCheck() error = %v, wantError %v", err, tt.wantError)
			}
			if !tt.wantRun {
				if len(runs.created) != 0 {
					t.Fatalf("expected no drift run, got %d", len(runs.created))
				}
				return
			}
			if len(runs.created) != 1 {
				t.Fatalf("expected 1 drift run, got %d", len(runs.created))
			}
			run := runs.created[0]
			if run.ConfigurationVersionID == nil || *run.ConfigurationVersionID != tt.wantCVID {
				t.Fatalf("ConfigurationVersionID = %v, want %q", run.ConfigurationVersionID, tt.wantCVID)
			}
			if run.Operation != models.RunOperationPlanOnly {
				t.Fatalf("Operation = %q, want plan-only", run.Operation)
			}
		})
	}
}
