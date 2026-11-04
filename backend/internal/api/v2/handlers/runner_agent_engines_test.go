// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Integration tests for the engines a runner registers with (#933, D3, AC78): `engines` at
// registration decides which kinds of work it is offered, whatever tool versions it reports, so a
// launcher whose job images carry both engines can serve both and one that declares only Ansible is
// never offered a run.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/ -run TestEngines

//go:build integration

package handlers

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
)

func TestEngines_OfferOnlyTheDeclaredEngines(t *testing.T) {
	f := setupAgentPrepFixture(t)
	sfx := uuid.NewString()[:8]
	owner := &models.User{ID: uuid.New(), ZitadelSubject: "engines-" + sfx, Email: "engines-" + sfx + "@test.local"}
	if err := f.db.Create(owner).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.db.Where("id = ?", owner.ID).Delete(&models.User{}) })
	key := &models.APIKey{Name: "engines-" + sfx, Kind: models.APIKeyKindOrg, KeyHash: "x", KeyPrefix: "tfe-" + sfx[:4], Scopes: models.StringArray{"org:" + f.orgA.String() + ":runner:register"}, OrganizationID: &f.orgA, UserID: &owner.ID}
	if err := f.db.Create(key).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.db.Where("id = ?", key.ID).Delete(&models.APIKey{}) })
	f.keys["reg"] = key
	r := f.registerRouter(owner.ID)

	register := func(engines []string) *models.Runner {
		t.Helper()
		name := "engines-" + uuid.NewString()[:8]
		// Both tool versions are reported: the engines decide, not the versions.
		rec := runnerDo(t, r, "reg", http.MethodPost, "/api/v2/runner/register", map[string]any{
			"agent_pool_id": f.poolA.String(), "name": name, "tofu_version": "1.9.0", "ansible_version": "2.16.0", "engines": engines,
		})
		if rec.Code != http.StatusCreated && rec.Code != http.StatusOK {
			t.Fatalf("register %v: %d (%s)", engines, rec.Code, rec.Body.String())
		}
		var resp struct {
			RunnerID string `json:"runner_id"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
		var runner models.Runner
		if err := f.db.First(&runner, "id = ?", resp.RunnerID).Error; err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			f.db.Where("scopes::text LIKE ?", "%runner:"+runner.ID.String()+":%").Delete(&models.APIKey{})
			f.db.Where("id = ?", runner.ID).Delete(&models.Runner{})
		})
		// Free capacity for a run and a job at once.
		f.db.Model(&models.Runner{}).Where("id = ?", runner.ID).Update("max_concurrent_jobs", 4)
		runner.MaxConcurrentJobs = 4
		return &runner
	}
	ansibleOnly := register([]string{"ansible"})
	tofuOnly := register([]string{"tofu"})
	both := register([]string{"tofu", "ansible"})

	h := &RunnerAgentHandler{db: f.db, runnerRepo: repository.NewRunnerRepository(f.db), ansibleJobRepo: repository.NewAnsibleJobRepository(f.db)}
	kinds := func(runner *models.Runner) map[string]int {
		t.Helper()
		// Each check starts from fresh, unreserved work.
		now := time.Now()
		f.seedJobRow(t, &models.AnsibleJob{Status: models.AnsibleJobStatusPending, AgentPoolID: &f.poolA, QueuedAt: &now})
		run := f.seedRun(t, f.runnerA1)
		if err := f.db.Model(&models.Run{}).Where("id = ?", run.ID).Updates(map[string]any{"status": models.RunStatusPending, "runner_id": nil}).Error; err != nil {
			t.Fatal(err)
		}
		offers, err := h.findPendingJobsForRunner(runner)
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]int{}
		for _, o := range offers {
			out[o.JobType]++
		}
		// Release what this check reserved, so the next runner sees it as new.
		f.db.Model(&models.AnsibleJob{}).Where("agent_pool_id = ? AND status = ?", f.poolA, models.AnsibleJobStatusPending).Update("status", models.AnsibleJobStatusCanceled)
		f.db.Model(&models.Run{}).Where("id = ?", run.ID).Update("status", models.RunStatusCancelled)
		return out
	}

	if got := kinds(ansibleOnly); got["tofu_run"] != 0 || got["ansible_job"] == 0 {
		t.Errorf("an ansible-only runner was offered %v, want Ansible work and never a run", got)
	}
	if got := kinds(tofuOnly); got["ansible_job"] != 0 || got["tofu_run"] == 0 {
		t.Errorf("a tofu-only runner was offered %v, want runs and never an Ansible job", got)
	}
	if got := kinds(both); got["ansible_job"] == 0 || got["tofu_run"] == 0 {
		t.Errorf("a runner of both engines was offered %v, want both kinds", got)
	}
	for runner, want := range map[*models.Runner]models.RunnerType{ansibleOnly: models.RunnerTypeAnsible, tofuOnly: models.RunnerTypeTofu, both: models.RunnerTypeCombined} {
		if runner.RunnerType != want {
			t.Errorf("runner %s stored type %q, want %q", runner.Name, runner.RunnerType, want)
		}
	}
}

// runnerTypeFor maps engines to the stored runner type, and falls back to the reported versions
// for a runner that predates engines.
func TestRunnerTypeFor(t *testing.T) {
	cases := []struct {
		engines       []string
		tofu, ansible string
		want          models.RunnerType
	}{
		{[]string{"ansible"}, "1.9.0", "2.16.0", models.RunnerTypeAnsible},
		{[]string{"tofu"}, "", "2.16.0", models.RunnerTypeTofu},
		{[]string{"tofu", "ansible"}, "", "", models.RunnerTypeCombined},
		{nil, "1.9.0", "", models.RunnerTypeTofu},
		{nil, "", "2.16.0", models.RunnerTypeAnsible},
	}
	for _, c := range cases {
		if got := runnerTypeFor(c.engines, c.tofu, c.ansible); got != c.want {
			t.Errorf("runnerTypeFor(%v, %q, %q) = %q, want %q", c.engines, c.tofu, c.ansible, got, c.want)
		}
	}
}
