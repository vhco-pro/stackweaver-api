// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"testing"

	"github.com/michielvha/stackweaver/core/models"
)

// isWorkspaceAffectedByFiles decides whether a webhook delivery should queue a run
// for a given workspace. It serves the GitHub pull-request and Azure DevOps paths,
// while isWorkspaceAffected serves the GitHub push path - the two must agree, or the
// same repository change triggers differently depending on which event arrived.
//
// Neither had any coverage; these tests pin the contract documented in
// docs/features/terraform/vcs-path-filtering.md.
func TestIsWorkspaceAffectedByFiles(t *testing.T) {
	h := &VCSAppInstallationHandlerV2{}

	tests := []struct {
		name         string
		workingDir   string
		changedFiles []string
		want         bool
	}{
		// Root-level workspaces trigger on ANY change in the repository. The
		// regression this guards: a root workspace used to match only files with no
		// "/" in their path, so a change under modules/ was silently skipped on the
		// PR and ADO paths while the push path queued a run.
		{
			name:         "root workspace matches a nested file",
			workingDir:   "",
			changedFiles: []string{"modules/network/main.tf"},
			want:         true,
		},
		{
			name:         "root workspace matches a root file",
			workingDir:   "",
			changedFiles: []string{"main.tf"},
			want:         true,
		},
		{
			name:         "slash working directory is also root",
			workingDir:   "/",
			changedFiles: []string{"modules/network/main.tf"},
			want:         true,
		},
		{
			name:         "whitespace-only working directory is also root",
			workingDir:   "  ",
			changedFiles: []string{"deep/nested/path/main.tf"},
			want:         true,
		},
		{
			name:         "root workspace with no changed files does not match",
			workingDir:   "",
			changedFiles: []string{},
			want:         false,
		},

		// Scoped workspaces match their own directory only.
		{
			name:         "scoped workspace matches a file inside it",
			workingDir:   "infra/prod",
			changedFiles: []string{"infra/prod/main.tf"},
			want:         true,
		},
		{
			name:         "scoped workspace matches the directory path itself",
			workingDir:   "infra/prod",
			changedFiles: []string{"infra/prod"},
			want:         true,
		},
		{
			name:         "scoped workspace ignores a file outside it",
			workingDir:   "infra/prod",
			changedFiles: []string{"infra/dev/main.tf"},
			want:         false,
		},
		{
			name:         "scoped workspace is not fooled by a sibling sharing its prefix",
			workingDir:   "infra/prod",
			changedFiles: []string{"infra/production/main.tf"},
			want:         false,
		},
		{
			name:         "leading and trailing slashes are normalised on both sides",
			workingDir:   "/infra/prod/",
			changedFiles: []string{"/infra/prod/main.tf"},
			want:         true,
		},
		{
			name:         "matches when any one of several files is inside",
			workingDir:   "infra/prod",
			changedFiles: []string{"README.md", "infra/dev/main.tf", "infra/prod/vars.tf"},
			want:         true,
		},
		{
			name:         "scoped workspace with no changed files does not match",
			workingDir:   "infra/prod",
			changedFiles: []string{},
			want:         false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ws := models.Workspace{WorkingDirectory: tt.workingDir}
			if got := h.isWorkspaceAffectedByFiles(ws, tt.changedFiles); got != tt.want {
				t.Errorf("isWorkspaceAffectedByFiles(%q, %v) = %v, want %v",
					tt.workingDir, tt.changedFiles, got, tt.want)
			}
		})
	}
}

// A root-level workspace must reach the same verdict on both code paths, otherwise
// the trigger depends on whether the change arrived as a push or as a pull request.
func TestRootWorkspaceAgreesAcrossBothPathFilters(t *testing.T) {
	h := &VCSAppInstallationHandlerV2{}
	ws := models.Workspace{WorkingDirectory: ""}

	nested := []string{"modules/network/main.tf"}

	byFiles := h.isWorkspaceAffectedByFiles(ws, nested)
	byCommits := h.isWorkspaceAffected(ws, []struct {
		Added    []string `json:"added"`
		Removed  []string `json:"removed"`
		Modified []string `json:"modified"`
	}{
		{Modified: nested},
	})

	if byFiles != byCommits {
		t.Errorf("root workspace verdict differs by code path: isWorkspaceAffectedByFiles=%v, isWorkspaceAffected=%v", byFiles, byCommits)
	}
}
