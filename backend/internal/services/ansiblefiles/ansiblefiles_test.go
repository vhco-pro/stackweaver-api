// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package ansiblefiles

import (
	"slices"
	"testing"
)

// repoTree is a repository that follows the Ansible sample layout plus the
// usual tooling noise, as a provider's ListFiles returns it for the union of
// the playbook and inventory extensions.
var repoTree = []string{
	"site.yml",
	"deploy.yaml",
	"playbook.yml",
	"hosts.yml",
	"inventory.ini",
	"prod.azure_rm.yml",
	"aws_ec2.yaml",
	"playbooks/web.yml",
	"playbooks/db.yml",
	"playbooks/hosts.ini",
	"roles/common/tasks/main.yml",
	"roles/common/defaults/main.yml",
	"roles/common/files/data.json",
	"group_vars/all.yml",
	"host_vars/web1.yml",
	"inventories/prod/hosts.yml",
	"inventories/prod/group_vars/all.yml",
	"inventories/staging/hosts.ini",
	"inventories/staging/dynamic.json",
	"inventory/dev.yaml",
	"molecule/default/converge.yml",
	"molecule/default/inventory.yml",
	"collections/requirements.yml",
	"requirements.yml",
	"galaxy.yml",
	"mkdocs.yml",
	".github/workflows/ci.yml",
	".devcontainer/devcontainer.json",
	".vscode/settings.json",
	".gitlab-ci.yml",
	"docker-compose.yml",
	"docker-compose.override.yml",
	".yamllint.yml",
	"package.json",
	"package-lock.json",
	"renovate.json",
	"README.md",
	"scripts/run.sh",
	"nested/deep/playbook.yaml",
	"/leading/slash.yml",
}

func TestPlaybooks(t *testing.T) {
	tests := []struct {
		name  string
		scope string
		want  []string
	}{
		{
			name:  "no scope drops non-playbooks and inventories",
			scope: "",
			want: []string{
				"deploy.yaml", "leading/slash.yml", "nested/deep/playbook.yaml",
				"playbook.yml", "playbooks/db.yml", "playbooks/web.yml", "site.yml",
			},
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
			name:  "scope matches a full segment, not a prefix",
			scope: "play",
			want:  nil,
		},
		{
			name:  "scope into an inventory directory still excludes it",
			scope: "inventories",
			want:  nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Playbooks(repoTree, tt.scope)
			if !slices.Equal(got, tt.want) {
				t.Errorf("Playbooks(scope=%q) = %v, want %v", tt.scope, got, tt.want)
			}
		})
	}
}

func TestInventories(t *testing.T) {
	tests := []struct {
		name  string
		scope string
		want  []string
	}{
		{
			name:  "no scope drops playbooks, vars, roles and tooling",
			scope: "",
			want: []string{
				"aws_ec2.yaml", "deploy.yaml", "hosts.yml",
				"inventories/prod/hosts.yml", "inventories/staging/dynamic.json",
				"inventories/staging/hosts.ini", "inventory.ini", "inventory/dev.yaml",
				"leading/slash.yml", "prod.azure_rm.yml",
			},
		},
		{
			name:  "scoped to the inventories directory",
			scope: "inventories",
			want: []string{
				"inventories/prod/hosts.yml", "inventories/staging/dynamic.json",
				"inventories/staging/hosts.ini",
			},
		},
		{
			name:  "scoped to one environment with slashes",
			scope: "/inventories/staging/",
			want:  []string{"inventories/staging/dynamic.json", "inventories/staging/hosts.ini"},
		},
		{
			name:  "scope matches a full segment, not a prefix",
			scope: "inv",
			want:  nil,
		},
		{
			name:  "scope into a playbook directory still excludes it",
			scope: "playbooks",
			want:  nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Inventories(repoTree, tt.scope)
			if !slices.Equal(got, tt.want) {
				t.Errorf("Inventories(scope=%q) = %v, want %v", tt.scope, got, tt.want)
			}
		})
	}
}

// TestPlaybooksAndInventoriesDisjointOnConventionalLayout pins the point of
// the two filters: on a repository that follows the conventions, no file is
// offered as both a playbook and an inventory. (A root-level YAML file with no
// conventional name, such as webservers.yml, is ambiguous by path alone and is
// deliberately offered in both pickers.)
func TestPlaybooksAndInventoriesDisjointOnConventionalLayout(t *testing.T) {
	conventional := []string{
		"site.yml", "playbook.yml", "hosts.yml", "prod.azure_rm.yml",
		"playbooks/db.yml", "inventories/prod/hosts.yml", "inventory/dev.ini",
	}
	playbooks := Playbooks(conventional, "")
	inventories := Inventories(conventional, "")
	if len(playbooks) != 3 || len(inventories) != 4 {
		t.Fatalf("Playbooks() = %v, Inventories() = %v: every file should land in exactly one", playbooks, inventories)
	}
	for _, inv := range inventories {
		if slices.Contains(playbooks, inv) {
			t.Errorf("%s is offered as both a playbook and an inventory", inv)
		}
	}
}

func TestInventoriesExtensions(t *testing.T) {
	got := Inventories([]string{"a.ini", "b.INI", "c.json", "d.yml", "e.yaml", "f.cfg", "g", "h.txt"}, "")
	want := []string{"a.ini", "b.INI", "c.json", "d.yml", "e.yaml"}
	if !slices.Equal(got, want) {
		t.Errorf("Inventories() = %v, want %v", got, want)
	}
}
