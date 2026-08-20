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
		workspace    models.Workspace
		changedFiles []string
		want         bool
	}{
		// Root-level workspaces trigger on ANY change in the repository. The
		// regression this guards: a root workspace used to match only files with no
		// "/" in their path, so a change under modules/ was silently skipped on the
		// PR and ADO paths while the push path queued a run.
		{
			name:         "root workspace matches a nested file",
			workspace:    models.Workspace{FileTriggersEnabled: true},
			changedFiles: []string{"modules/network/main.tf"},
			want:         true,
		},
		{
			name:         "root workspace matches a root file",
			workspace:    models.Workspace{FileTriggersEnabled: true},
			changedFiles: []string{"main.tf"},
			want:         true,
		},
		{
			name:         "slash working directory is also root",
			workspace:    models.Workspace{FileTriggersEnabled: true, WorkingDirectory: "/"},
			changedFiles: []string{"modules/network/main.tf"},
			want:         true,
		},
		{
			name:         "whitespace-only working directory is also root",
			workspace:    models.Workspace{FileTriggersEnabled: true, WorkingDirectory: "  "},
			changedFiles: []string{"deep/nested/path/main.tf"},
			want:         true,
		},
		{
			name:         "root workspace with no changed files does not match",
			workspace:    models.Workspace{FileTriggersEnabled: true},
			changedFiles: []string{},
			want:         false,
		},

		// Scoped workspaces match their own directory only.
		{
			name:         "scoped workspace matches a file inside it",
			workspace:    models.Workspace{FileTriggersEnabled: true, WorkingDirectory: "infra/prod"},
			changedFiles: []string{"infra/prod/main.tf"},
			want:         true,
		},
		{
			name:         "scoped workspace matches the directory path itself",
			workspace:    models.Workspace{FileTriggersEnabled: true, WorkingDirectory: "infra/prod"},
			changedFiles: []string{"infra/prod"},
			want:         true,
		},
		{
			name:         "scoped workspace ignores a file outside it",
			workspace:    models.Workspace{FileTriggersEnabled: true, WorkingDirectory: "infra/prod"},
			changedFiles: []string{"infra/dev/main.tf"},
			want:         false,
		},
		{
			name:         "scoped workspace is not fooled by a sibling sharing its prefix",
			workspace:    models.Workspace{FileTriggersEnabled: true, WorkingDirectory: "infra/prod"},
			changedFiles: []string{"infra/production/main.tf"},
			want:         false,
		},
		{
			name:         "leading and trailing slashes are normalised on both sides",
			workspace:    models.Workspace{FileTriggersEnabled: true, WorkingDirectory: "/infra/prod/"},
			changedFiles: []string{"/infra/prod/main.tf"},
			want:         true,
		},
		{
			name:         "matches when any one of several files is inside",
			workspace:    models.Workspace{FileTriggersEnabled: true, WorkingDirectory: "infra/prod"},
			changedFiles: []string{"README.md", "infra/dev/main.tf", "infra/prod/vars.tf"},
			want:         true,
		},
		{
			name:         "scoped workspace with no changed files does not match",
			workspace:    models.Workspace{FileTriggersEnabled: true, WorkingDirectory: "infra/prod"},
			changedFiles: []string{},
			want:         false,
		},

		// file_triggers_enabled=false means "always trigger": every path setting is
		// ignored. Before #678 the flag was stored and echoed back but read nowhere,
		// so a workspace configured this way stayed silently path-filtered.
		{
			name:         "file triggers disabled ignores the working directory",
			workspace:    models.Workspace{WorkingDirectory: "infra/prod"},
			changedFiles: []string{"unrelated/main.tf"},
			want:         true,
		},
		{
			name:         "file triggers disabled ignores trigger prefixes",
			workspace:    models.Workspace{WorkingDirectory: "infra/prod", TriggerPrefixes: `["modules"]`},
			changedFiles: []string{"docs/readme.md"},
			want:         true,
		},

		// trigger_prefixes are monitored alongside the working directory.
		{
			name:         "trigger prefix matches outside the working directory",
			workspace:    models.Workspace{FileTriggersEnabled: true, WorkingDirectory: "infra/prod", TriggerPrefixes: `["modules/network"]`},
			changedFiles: []string{"modules/network/main.tf"},
			want:         true,
		},
		{
			name:         "working directory still matches when prefixes are set",
			workspace:    models.Workspace{FileTriggersEnabled: true, WorkingDirectory: "infra/prod", TriggerPrefixes: `["modules/network"]`},
			changedFiles: []string{"infra/prod/main.tf"},
			want:         true,
		},
		{
			name:         "file outside both the working directory and the prefixes does not match",
			workspace:    models.Workspace{FileTriggersEnabled: true, WorkingDirectory: "infra/prod", TriggerPrefixes: `["modules/network"]`},
			changedFiles: []string{"modules/storage/main.tf", "infra/dev/main.tf"},
			want:         false,
		},
		{
			name:         "a prefix narrows a root workspace",
			workspace:    models.Workspace{FileTriggersEnabled: true, TriggerPrefixes: `["modules"]`},
			changedFiles: []string{"README.md"},
			want:         false,
		},
		{
			name:         "a root prefix on a root workspace matches everything",
			workspace:    models.Workspace{FileTriggersEnabled: true, TriggerPrefixes: `["/"]`},
			changedFiles: []string{"anything/at/all.tf"},
			want:         true,
		},
		{
			name:         "prefixes are compared on directory boundaries",
			workspace:    models.Workspace{FileTriggersEnabled: true, TriggerPrefixes: `["modules/net"]`},
			changedFiles: []string{"modules/network/main.tf"},
			want:         false,
		},
		{
			name:         "blank prefix entries are ignored",
			workspace:    models.Workspace{FileTriggersEnabled: true, WorkingDirectory: "infra/prod", TriggerPrefixes: `["", "  "]`},
			changedFiles: []string{"infra/prod/main.tf"},
			want:         true,
		},
		{
			name:         "a malformed prefix column falls back to the working directory",
			workspace:    models.Workspace{FileTriggersEnabled: true, WorkingDirectory: "infra/prod", TriggerPrefixes: `not json`},
			changedFiles: []string{"infra/prod/main.tf"},
			want:         true,
		},

		// trigger_patterns replace the working directory entirely (TFE semantics).
		{
			name:         "glob pattern matches a nested file",
			workspace:    models.Workspace{FileTriggersEnabled: true, TriggerPatterns: `["/modules/**/*.tf"]`},
			changedFiles: []string{"modules/network/vpc/main.tf"},
			want:         true,
		},
		{
			name:         "glob pattern matches directly under the prefix as well",
			workspace:    models.Workspace{FileTriggersEnabled: true, TriggerPatterns: `["modules/**/*.tf"]`},
			changedFiles: []string{"modules/main.tf"},
			want:         true,
		},
		{
			name:         "glob pattern rejects a non-matching extension",
			workspace:    models.Workspace{FileTriggersEnabled: true, TriggerPatterns: `["modules/**/*.tf"]`},
			changedFiles: []string{"modules/network/README.md"},
			want:         false,
		},
		{
			name:         "single star does not cross a directory separator",
			workspace:    models.Workspace{FileTriggersEnabled: true, TriggerPatterns: `["modules/*.tf"]`},
			changedFiles: []string{"modules/network/main.tf"},
			want:         false,
		},
		{
			name:         "patterns override the working directory",
			workspace:    models.Workspace{FileTriggersEnabled: true, WorkingDirectory: "infra/prod", TriggerPatterns: `["modules/**"]`},
			changedFiles: []string{"infra/prod/main.tf"},
			want:         false,
		},
		{
			name:         "a directory pattern matches everything underneath",
			workspace:    models.Workspace{FileTriggersEnabled: true, TriggerPatterns: `["modules/"]`},
			changedFiles: []string{"modules/network/main.tf"},
			want:         true,
		},
		{
			name:         "an invalid pattern is skipped rather than matching everything",
			workspace:    models.Workspace{FileTriggersEnabled: true, TriggerPatterns: `["[", "modules/**"]`},
			changedFiles: []string{"docs/readme.md"},
			want:         false,
		},
		{
			name:         "a valid pattern still matches alongside an invalid one",
			workspace:    models.Workspace{FileTriggersEnabled: true, TriggerPatterns: `["[", "modules/**"]`},
			changedFiles: []string{"modules/network/main.tf"},
			want:         true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := h.isWorkspaceAffectedByFiles(tt.workspace, tt.changedFiles); got != tt.want {
				t.Errorf("isWorkspaceAffectedByFiles(workdir=%q prefixes=%q patterns=%q fileTriggers=%v, %v) = %v, want %v",
					tt.workspace.WorkingDirectory, tt.workspace.TriggerPrefixes, tt.workspace.TriggerPatterns,
					tt.workspace.FileTriggersEnabled, tt.changedFiles, got, tt.want)
			}
		})
	}
}

// Every workspace configuration must reach the same verdict on both code paths,
// otherwise the trigger depends on whether the change arrived as a push or as a pull
// request - the exact split #678 reported.
func TestPathFiltersAgreeAcrossBothEntryPoints(t *testing.T) {
	h := &VCSAppInstallationHandlerV2{}

	changed := []string{"modules/network/main.tf"}

	workspaces := map[string]models.Workspace{
		"root":              {FileTriggersEnabled: true},
		"scoped":            {FileTriggersEnabled: true, WorkingDirectory: "infra/prod"},
		"triggers disabled": {WorkingDirectory: "infra/prod"},
		"prefixes":          {FileTriggersEnabled: true, WorkingDirectory: "infra/prod", TriggerPrefixes: `["modules/network"]`},
		"patterns":          {FileTriggersEnabled: true, TriggerPatterns: `["modules/**/*.tf"]`},
	}

	for name, ws := range workspaces {
		t.Run(name, func(t *testing.T) {
			byFiles := h.isWorkspaceAffectedByFiles(ws, changed)
			byCommits := h.isWorkspaceAffected(ws, []struct {
				Added    []string `json:"added"`
				Removed  []string `json:"removed"`
				Modified []string `json:"modified"`
			}{
				{Modified: changed},
			})

			if byFiles != byCommits {
				t.Errorf("verdict differs by code path: isWorkspaceAffectedByFiles=%v, isWorkspaceAffected=%v", byFiles, byCommits)
			}
		})
	}
}

// compileTriggerPattern implements the glob subset TFE documents for trigger patterns.
func TestCompileTriggerPattern(t *testing.T) {
	tests := []struct {
		pattern string
		path    string
		want    bool
	}{
		{pattern: "*.tf", path: "main.tf", want: true},
		{pattern: "*.tf", path: "modules/main.tf", want: false},
		{pattern: "**/*.tf", path: "modules/network/main.tf", want: true},
		{pattern: "**/*.tf", path: "main.tf", want: true},
		{pattern: "**", path: "any/depth/at/all", want: true},
		{pattern: "/modules/**", path: "modules/network/main.tf", want: true},
		{pattern: "/modules/**", path: "other/main.tf", want: false},
		{pattern: "modules/?/main.tf", path: "modules/a/main.tf", want: true},
		{pattern: "modules/?/main.tf", path: "modules/ab/main.tf", want: false},
		{pattern: "env/prod.tfvars", path: "env/prod.tfvars", want: true},
		// A literal dot must not behave as the regex any-character metacharacter.
		{pattern: "env/prod.tfvars", path: "env/prodXtfvars", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.pattern+" vs "+tt.path, func(t *testing.T) {
			re, err := compileTriggerPattern(tt.pattern)
			if err != nil {
				t.Fatalf("compileTriggerPattern(%q): %v", tt.pattern, err)
			}
			if got := re.MatchString(tt.path); got != tt.want {
				t.Errorf("compileTriggerPattern(%q).MatchString(%q) = %v, want %v (regexp %s)",
					tt.pattern, tt.path, got, tt.want, re)
			}
		})
	}
}
