// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"testing"

	"github.com/michielvha/stackweaver/core/models"
)

// fakeFileLister records the extensions it was asked for and returns a fixed
// repository listing (or error).
type fakeFileLister struct {
	files  []string
	err    error
	gotExt []string
}

func (f *fakeFileLister) ListFiles(_ context.Context, _ *models.VCSConnection, _, _, _ string, extensions []string) ([]string, error) {
	f.gotExt = extensions
	return f.files, f.err
}

func TestListInventoryCandidates(t *testing.T) {
	repo := []string{
		"site.yml",
		"hosts.ini",
		"playbooks/web.yml",
		"roles/common/tasks/main.yml",
		"group_vars/all.yml",
		"inventories/prod/hosts.yml",
		"inventories/prod/host_vars/web1.yml",
		".github/workflows/ci.yml",
		"package.json",
	}
	tests := []struct {
		name  string
		files []string
		scope string
		want  []string
	}{
		{
			name:  "whole repository",
			files: repo,
			want:  []string{"hosts.ini", "inventories/prod/hosts.yml"},
		},
		{
			name:  "scoped to inventories",
			files: repo,
			scope: "inventories",
			want:  []string{"inventories/prod/hosts.yml"},
		},
		{
			name:  "no candidates encodes as an empty list",
			files: []string{"site.yml"},
			want:  []string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lister := &fakeFileLister{files: tt.files}
			got, err := listInventoryCandidates(t.Context(), lister, &models.VCSConnection{}, "acme", "infra", "main", tt.scope)
			if err != nil {
				t.Fatalf("listInventoryCandidates() error = %v", err)
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("listInventoryCandidates() = %v, want %v", got, tt.want)
			}
			if !slices.Equal(lister.gotExt, inventoryExtensions) {
				t.Errorf("ListFiles extensions = %v, want %v", lister.gotExt, inventoryExtensions)
			}
			encoded, err := json.Marshal(got)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if string(encoded) == "null" {
				t.Errorf("empty listing must encode as [], got null")
			}
		})
	}
}

// TestListInventoryCandidates_ProviderError pins that the provider error
// passes through unwrapped: the handler's isNotImplemented check maps it to 501.
func TestListInventoryCandidates_ProviderError(t *testing.T) {
	want := errors.New("not implemented")
	_, err := listInventoryCandidates(t.Context(), &fakeFileLister{err: want}, &models.VCSConnection{}, "acme", "infra", "main", "")
	if !errors.Is(err, want) || !isNotImplemented(err) {
		t.Fatalf("error = %v, want %v", err, want)
	}
}
