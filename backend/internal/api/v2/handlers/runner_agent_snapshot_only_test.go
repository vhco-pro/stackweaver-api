// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Snapshot only (#933, decision 18, AC68, AC58): no artifacts response to an executor that holds
// a job token carries a clone URL or a VCS credential, on either engine, whatever the playbook's
// source mode; the job starts from a snapshot a sync work item captured. An old agent, which
// authenticates with its runner token and announces no snapshot capability, is still served the
// clone URL for the deprecation window.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set.

//go:build integration

package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/michielvha/stackweaver/backend/internal/api/middleware"
	"github.com/michielvha/stackweaver/backend/internal/services/apikey"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/runnercontract"
	"github.com/michielvha/stackweaver/core/services/ansible"
	"github.com/michielvha/stackweaver/core/services/vcs"
)

// snapshotOnlyRouter is jobTokenRouter over store, with the job-data guard on the artifacts.
func (f *agentPrepFixture) snapshotOnlyRouter(store *snapshotStore) (*gin.Engine, *apikey.Service) {
	svc := apikey.NewService(repository.NewAPIKeyRepository(f.db), nil, nil, nil)
	playbookRepo := repository.NewAnsiblePlaybookRepository(f.db)
	h := &RunnerAgentHandler{
		db: f.db, apiKeyService: svc, jobExecRepo: repository.NewRunnerJobExecutionRepository(f.db),
		ansibleJobRepo: repository.NewAnsibleJobRepository(f.db), playbookRepo: playbookRepo,
		vcsRegistry: vcs.NewProviderRegistry(nil, nil, nil, nil), storageClient: store,
		syncRequester: ansible.NewPlaybookSnapshotRequester(ansible.NewWorkItemService(f.db, nil), playbookRepo),
	}
	return f.router(func(authed *gin.RouterGroup) {
		authed.POST("/jobs/:id/token", middleware.RequireRunnerToken(), h.JobToken)
		authed.GET("/jobs/:id/artifacts", middleware.JobData(), h.GetJobArtifacts)
		authed.GET("/jobs/:id/playbook-snapshot", middleware.JobData(), h.GetPlaybookSnapshot)
	}), svc
}

// runnerDoAnnouncing GETs path as key, announcing capabilities.
func runnerDoAnnouncing(t *testing.T, r *gin.Engine, key, path, capabilities string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, nil)
	req.Header.Set("X-Test-Key", key)
	if capabilities != "" {
		req.Header.Set(runnercontract.CapabilitiesHeader, capabilities)
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

func TestSnapshotOnly_NoCloneURLForAJobToken(t *testing.T) {
	f := setupAgentPrepFixture(t)
	store := newSnapshotStore()
	r, svc := f.snapshotOnlyRouter(store)

	// Ansible: a fresh-mode playbook and a cached one with its snapshot.
	captured := time.Now().UTC()
	fresh := f.seedPlaybook(t, playbookSpec{mode: models.PlaybookSourceModeFresh, cachedAt: &captured, commit: "abc1234", size: 8})
	cached := f.seedPlaybook(t, playbookSpec{mode: models.PlaybookSourceModeCached, cachedAt: &captured, commit: "abc1234", size: 8})
	for _, pb := range []*models.AnsiblePlaybook{fresh, cached} {
		if err := store.Put(t.Context(), ansible.PlaybookSnapshotKey(pb.ID), []byte("snapshot")); err != nil {
			t.Fatal(err)
		}
	}
	for name, pb := range map[string]*models.AnsiblePlaybook{"fresh": fresh, "cached": cached} {
		t.Run("ansible "+name, func(t *testing.T) {
			job := f.seedJob(t, &pb.ID, f.runnerA1)
			if code, _ := f.mintJobToken(t, r, svc, "a1", job.ID.String(), "job-"+name); code != http.StatusOK {
				t.Fatalf("minting the job token: %d", code)
			}
			rec := runnerDoAnnouncing(t, r, "job-"+name, "/api/v2/runner/jobs/"+job.ID.String()+"/artifacts", runnercontract.CapabilityPlaybookSnapshot)
			if rec.Code != http.StatusOK {
				t.Fatalf("artifacts: %d %s", rec.Code, rec.Body.String())
			}
			body := rec.Body.String()
			if strings.Contains(body, `"vcs"`) || strings.Contains(body, "glpat-") || strings.Contains(body, "gitlab.com") {
				t.Errorf("a job token was served a clone URL or VCS credential: %s", body)
			}
			if !strings.Contains(body, `"playbook_source"`) || !strings.Contains(body, "abc1234") {
				t.Errorf("the job is not pointed at its snapshot: %s", body)
			}
			if !strings.Contains(body, `"mode":"`+name+`"`) {
				t.Errorf("the snapshot does not carry its source mode %s: %s", name, body)
			}
			// The job then downloads that snapshot, whatever the source mode: a fresh-mode
			// playbook is captured for each launch and served the same way (decision 18).
			snap := runnerDoAnnouncing(t, r, "job-"+name, "/api/v2/runner/jobs/"+job.ID.String()+"/playbook-snapshot", runnercontract.CapabilityPlaybookSnapshot)
			if snap.Code != http.StatusOK || snap.Body.String() != "snapshot" {
				t.Errorf("snapshot download: %d %s", snap.Code, snap.Body.String())
			}
		})
	}

	// OpenTofu: a VCS-backed run without a configuration version.
	t.Run("opentofu", func(t *testing.T) {
		_, run := f.storedWorkspaceNaming(t, f.vcsConn)
		if err := f.db.Model(&models.Run{}).Where("id = ?", run.ID).Updates(map[string]any{"runner_id": f.runnerA1.ID, "status": models.RunStatusPlanning}).Error; err != nil {
			t.Fatal(err)
		}
		if code, _ := f.mintJobToken(t, r, svc, "a1", run.ID, "job-run"); code != http.StatusOK {
			t.Fatalf("minting the run's job token: %d", code)
		}
		rec := runnerDoAnnouncing(t, r, "job-run", "/api/v2/runner/jobs/"+run.ID+"/artifacts", "")
		if strings.Contains(rec.Body.String(), "glpat-") || strings.Contains(rec.Body.String(), `"vcs"`) {
			t.Errorf("a run's job token was served a clone URL: %d %s", rec.Code, rec.Body.String())
		}
	})
}

// An old agent authenticates with its runner token and announces no snapshot capability: it is
// still handed the clone URL it needs.
func TestSnapshotOnly_OldAgentStillServedACloneURL(t *testing.T) {
	f := setupAgentPrepFixture(t)
	r, _ := f.snapshotOnlyRouter(newSnapshotStore())
	pb := f.seedPlaybook(t, playbookSpec{mode: models.PlaybookSourceModeFresh})
	job := f.seedJob(t, &pb.ID, f.runnerA1)
	rec := runnerDoAnnouncing(t, r, "a1", "/api/v2/runner/jobs/"+job.ID.String()+"/artifacts", "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "@gitlab.com/acme/playbooks.git") {
		t.Errorf("an old agent was not served its clone URL: %d %s", rec.Code, rec.Body.String())
	}
}

// The OpenTofu side of the deprecation window: an old agent, with its runner token and no
// job-token capability, is still served a minted clone URL for a VCS-backed run that has no
// configuration version, while the executor of a launcher that holds a job token for the same run
// is served none.
func TestSnapshotOnly_OldAgentOpenTofuStillServedACloneURL(t *testing.T) {
	f := setupAgentPrepFixture(t)
	r, svc := f.snapshotOnlyRouter(newSnapshotStore())
	_, run := f.storedWorkspaceNaming(t, f.vcsConn)
	if err := f.db.Model(&models.Run{}).Where("id = ?", run.ID).Updates(map[string]any{"runner_id": f.runnerA1.ID, "status": models.RunStatusPlanning}).Error; err != nil {
		t.Fatal(err)
	}
	path := "/api/v2/runner/jobs/" + run.ID + "/artifacts"

	// a1 declares nothing: an agent built before the job token and the snapshot.
	rec := runnerDoAnnouncing(t, r, "a1", path, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("artifacts for an old agent: %d %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"vcs"`) || !strings.Contains(body, "@gitlab.com/acme/infra.git") || !strings.Contains(body, "glpat-") {
		t.Errorf("an old agent was not served the minted clone URL of the run's repository: %s", body)
	}

	// The executor of a launcher, with the run's job token, is served no clone URL and no token.
	if code, _ := f.mintJobToken(t, r, svc, "a1", run.ID, "job-run"); code != http.StatusOK {
		t.Fatalf("minting the run's job token: %d", code)
	}
	rec = runnerDoAnnouncing(t, r, "job-run", path, runnercontract.CapabilityPlaybookSnapshot)
	if strings.Contains(rec.Body.String(), "glpat-") || strings.Contains(rec.Body.String(), `"vcs"`) || strings.Contains(rec.Body.String(), "gitlab.com") {
		t.Errorf("the run's job token was served a clone URL: %d %s", rec.Code, rec.Body.String())
	}

	// Once the runner declares the job-token capability, its runner token reaches no artifacts.
	f.declareCapabilities(t, f.runnerA1, runnercontract.CapabilityJobToken)
	if rec := runnerDoAnnouncing(t, r, "a1", path, ""); rec.Code != http.StatusForbidden || strings.Contains(rec.Body.String(), "glpat-") {
		t.Errorf("a launcher's runner token on the artifacts: %d %s, want 403 and no clone URL", rec.Code, rec.Body.String())
	}
}
