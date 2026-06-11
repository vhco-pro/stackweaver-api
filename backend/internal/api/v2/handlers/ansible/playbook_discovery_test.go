// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package ansible

import (
	"errors"
	"reflect"
	"testing"

	"gorm.io/gorm"
)

func TestFilterPlaybookFiles(t *testing.T) {
	repoTree := []string{
		"site.yml",
		"deploy.yaml",
		"playbooks/web.yml",
		"playbooks/db.yml",
		"roles/common/tasks/main.yml",
		"roles/common/defaults/main.yml",
		"group_vars/all.yml",
		"host_vars/web1.yml",
		"inventories/prod/hosts.yml",
		"molecule/default/converge.yml",
		"collections/requirements.yml",
		"requirements.yml",
		"galaxy.yml",
		".github/workflows/ci.yml",
		".gitlab-ci.yml",
		"docker-compose.yml",
		"docker-compose.override.yml",
		".yamllint.yml",
		"README.md",
		"scripts/run.sh",
		"nested/deep/playbook.yaml",
	}

	cases := []struct {
		name  string
		scope string
		want  []string
	}{
		{
			name:  "no scope filters conventional non-playbooks",
			scope: "",
			want:  []string{"deploy.yaml", "nested/deep/playbook.yaml", "playbooks/db.yml", "playbooks/web.yml", "site.yml"},
		},
		{
			name:  "scoped to a directory",
			scope: "playbooks",
			want:  []string{"playbooks/db.yml", "playbooks/web.yml"},
		},
		{
			name:  "scope with surrounding slashes is normalized",
			scope: "/playbooks/",
			want:  []string{"playbooks/db.yml", "playbooks/web.yml"},
		},
		{
			name:  "scope matching nothing",
			scope: "does-not-exist",
			want:  nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := filterPlaybookFiles(repoTree, tc.scope)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("filterPlaybookFiles(scope=%q) = %v, want %v", tc.scope, got, tc.want)
			}
		})
	}
}

func TestFilterPlaybookFiles_ScopeIsSegmentNotPrefix(t *testing.T) {
	// "play" must not match "playbooks/web.yml"
	got := filterPlaybookFiles([]string{"playbooks/web.yml"}, "play")
	if len(got) != 0 {
		t.Errorf("scope must match a full path segment, got %v", got)
	}
}

func TestPlaybookNameCandidates_Derived(t *testing.T) {
	got := playbookNameCandidates("playbooks/deploy.yml", "acme/infra", "")
	want := []string{
		"deploy",
		"deploy (playbooks)",
		"deploy (infra)",
		"deploy-2", "deploy-3", "deploy-4", "deploy-5", "deploy-6", "deploy-7", "deploy-8", "deploy-9",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("candidates = %v, want %v", got, want)
	}
}

func TestPlaybookNameCandidates_RootFileSkipsDirCandidate(t *testing.T) {
	got := playbookNameCandidates("site.yml", "acme/infra", "")
	if got[0] != "site" || got[1] != "site (infra)" {
		t.Errorf("root file candidates = %v, want stem then repo disambiguation", got[:2])
	}
}

func TestPlaybookNameCandidates_RequestedNameShortCircuits(t *testing.T) {
	got := playbookNameCandidates("playbooks/deploy.yml", "acme/infra", "My Deploy")
	if got[0] != "My Deploy" || got[1] != "My Deploy-2" {
		t.Errorf("requested-name candidates = %v", got[:2])
	}
	for _, c := range got {
		if c == "deploy (playbooks)" {
			t.Error("requested name must not fall back to derived candidates")
		}
	}
}

func TestIsDuplicateKeyErr(t *testing.T) {
	cases := []struct {
		err  error
		want bool
	}{
		{nil, false},
		{gorm.ErrDuplicatedKey, true},
		{errors.New(`ERROR: duplicate key value violates unique constraint "idx_project_playbook" (SQLSTATE 23505)`), true},
		{errors.New("connection refused"), false},
	}
	for _, tc := range cases {
		if got := isDuplicateKeyErr(tc.err); got != tc.want {
			t.Errorf("isDuplicateKeyErr(%v) = %v, want %v", tc.err, got, tc.want)
		}
	}
}
