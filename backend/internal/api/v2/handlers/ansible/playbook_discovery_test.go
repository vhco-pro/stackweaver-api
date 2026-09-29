// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package ansible

import (
	"reflect"
	"testing"
)

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
