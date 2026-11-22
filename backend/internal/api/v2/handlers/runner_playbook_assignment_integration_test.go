// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

//go:build integration

package handlers

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/runnercontract"
	"github.com/michielvha/stackweaver/core/services/ansible"
)

func TestPlaybookAssignment_ReplacementNeedsNewAnsibleRun(t *testing.T) {
	f := setupWorkItemRunner(t)
	pb := f.seedPlaybook(t, playbookSpec{mode: models.PlaybookSourceModeCached})
	publish := func(token, revision string) {
		t.Helper()
		item, err := f.items.RequestPlaybookSnapshot(t.Context(), pb, "manual")
		if err != nil {
			t.Fatal(err)
		}
		f.onPool(t, item)
		f.offered(t, "a1")
		f.claim(t, "a1", item.ID, token)
		path := "/api/v2/runner/jobs/" + item.ID
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, path+"/snapshot", strings.NewReader(revision))
		req.Header.Set("X-Test-Key", token)
		req.Header.Set(runnercontract.HeaderSnapshotCommit, revision)
		rec := httptest.NewRecorder()
		f.r.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("upload returned %d %s", rec.Code, rec.Body.String())
		}
		done := JobCompleteRequest{RunnerID: f.keyRunner("a1"), Status: "completed", WorkResult: &runnercontract.WorkResult{Commit: revision}}
		if rec := runnerDo(t, f.r, token, http.MethodPost, path+"/complete", done); rec.Code != http.StatusOK {
			t.Fatalf("complete returned %d %s", rec.Code, rec.Body.String())
		}
	}
	publish("first", "original")
	jobs := ansible.NewJobService(repository.NewAnsibleJobRepository(f.db), repository.NewAnsiblePlaybookRepository(f.db),
		repository.NewAnsibleInventoryRepository(f.db), repository.NewAnsibleJobTemplateRepository(f.db),
		repository.NewProjectRepository(f.db), nil)
	jobs.SetWorkItems(f.items)
	job, err := jobs.LaunchJob(t.Context(), ansible.LaunchJobInput{
		ProjectID: f.projectA, PlaybookID: pb.ID, InventoryID: f.inventory, AgentPoolID: &f.poolA,
	})
	if err != nil {
		t.Fatal(err)
	}
	if job.QueuedAt == nil {
		t.Fatal("cached job was held despite a published capture")
	}
	t.Cleanup(func() { f.db.Delete(&models.AnsibleJob{}, "id = ?", job.ID) })
	f.offered(t, "a1")
	f.claim(t, "a1", job.ID.String(), "ansible")
	base := "/api/v2/runner/jobs/" + job.ID.String()
	capabilities := runnercontract.CapabilityPlaybookSnapshot + "," + runnercontract.CapabilityVerifiedPlaybookSnapshot
	rec := runnerDoAnnouncing(t, f.r, "ansible", base+"/artifacts", capabilities)
	var artifacts struct {
		PlaybookSource runnercontract.PlaybookSource `json:"playbook_source"`
	}
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &artifacts) != nil {
		t.Fatalf("artifacts returned %d %s", rec.Code, rec.Body.String())
	}
	source := artifacts.PlaybookSource
	if source.Commit != "original" || source.SHA256 != sha256Hex([]byte("original")) || source.Validator == "" {
		t.Fatalf("the job did not receive the first capture's identity: %+v", source)
	}
	path := base + "/playbook-snapshot"
	download := func(validator string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, nil)
		req.Header.Set("X-Test-Key", "ansible")
		req.Header.Set(runnercontract.CapabilitiesHeader, capabilities)
		if validator != "" {
			req.Header.Set("If-Match", validator)
		}
		rec := httptest.NewRecorder()
		f.r.ServeHTTP(rec, req)
		return rec
	}
	for _, validator := range []string{"", `"different-capture"`} {
		if rec := download(validator); rec.Code != http.StatusPreconditionFailed {
			t.Fatalf("wrong or absent validator returned %d %q", rec.Code, rec.Body.String())
		}
	}
	if rec := download(source.Validator); rec.Code != http.StatusOK || rec.Body.String() != "original" {
		t.Fatalf("the initial verified download returned %d %q", rec.Code, rec.Body.String())
	}
	if rec := runnerGet(t, f.r, "ansible", path); rec.Code != http.StatusOK || rec.Body.String() != "original" {
		t.Fatalf("the initial legacy download returned %d %q", rec.Code, rec.Body.String())
	}
	publish("second", "replaced")
	for _, rec := range []*httptest.ResponseRecorder{download(source.Validator), runnerGet(t, f.r, "ansible", path)} {
		if rec.Code != http.StatusPreconditionFailed || !strings.Contains(rec.Body.String(), "Start a new run") {
			t.Fatalf("retry after replacement returned %d %q, want HTTP 412 with a new-run reason", rec.Code, rec.Body.String())
		}
	}
}

type snapshotDeliveryWriter struct {
	gin.ResponseWriter
	beforeBody func()
}

func (w snapshotDeliveryWriter) Write(data []byte) (int, error) {
	if w.Status() == http.StatusOK {
		w.beforeBody()
	}
	return w.ResponseWriter.Write(data)
}

func TestPlaybookAssignment_PublicationDuringDownload(t *testing.T) {
	for _, afterAdmission := range []bool{false, true} {
		name, want := "replacement wins", http.StatusPreconditionFailed
		if afterAdmission {
			name, want = "admission wins", http.StatusOK
		}
		t.Run(name, func(t *testing.T) {
			f := setupAgentPrepFixture(t)
			store := newSnapshotStore()
			now := time.Now().UTC()
			pb := f.seedPlaybook(t, playbookSpec{cachedAt: &now, commit: "original"})
			oldKey := f.publishFixtureSnapshot(t, pb, store, []byte("original"))
			job := f.seedSnapshotJob(t, pb, f.runnerA1)

			paused, resume := make(chan struct{}), make(chan struct{})
			pause := sync.OnceFunc(func() {
				close(paused)
				<-resume
			})
			var router *gin.Engine
			if afterAdmission {
				router = f.artifactsRouter(store, func(c *gin.Context) {
					c.Writer = snapshotDeliveryWriter{ResponseWriter: c.Writer, beforeBody: pause}
				})
			} else {
				stalled := runnerDeliveryStorage{Client: store, open: func(ctx context.Context, key string) (io.ReadCloser, error) {
					reader, err := store.GetStream(ctx, key)
					pause()
					return reader, err
				}}
				router = f.artifactsRouter(stalled)
			}
			request := httptest.NewRequestWithContext(t.Context(), http.MethodGet,
				"/api/v2/runner/jobs/"+job.ID.String()+"/playbook-snapshot", nil)
			request.Header.Set("X-Test-Key", "a1")
			rec := httptest.NewRecorder()
			done := make(chan struct{})
			go func() {
				defer close(done)
				router.ServeHTTP(rec, request)
			}()
			release := sync.OnceFunc(func() { close(resume) })
			defer func() {
				release()
				<-done
			}()
			select {
			case <-paused:
			case <-done:
				t.Fatalf("download ended before pause: %d %s", rec.Code, rec.Body.String())
			case <-time.After(10 * time.Second):
				t.Fatal("download did not reach the pause")
			}
			// Simulate another API publishing and cleaning up the old storage object.
			f.publishFixtureSnapshot(t, pb, store, []byte("replaced"))
			if err := store.Delete(t.Context(), oldKey); err != nil {
				t.Fatal(err)
			}
			release()
			<-done
			if rec.Code != want {
				t.Fatalf("download returned %d %s, want %d", rec.Code, rec.Body.String(), want)
			}
			if afterAdmission && rec.Body.String() != "original" {
				t.Errorf("admitted delivery changed archive: %q", rec.Body.String())
			}
			if !afterAdmission && !strings.Contains(rec.Body.String(), "Start a new run") {
				t.Errorf("superseded read returned %q", rec.Body.String())
			}
		})
	}
}
