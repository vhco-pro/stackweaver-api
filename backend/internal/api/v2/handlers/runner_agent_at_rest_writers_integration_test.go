// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Encryption at rest through the real writers (#933, D2, AC73). Each artifact an executor sends
// the API is written by its own route, the way production wires them, over the sealed storage
// client: a saved plan (POST /plan), a playbook snapshot and a configuration snapshot (POST
// /snapshot of their work items), a state above the inline threshold (POST /state as the raw state
// file), and the plan JSON a completion stores in the database (POST /complete). Each is read back
// raw, from under the sealing layer, and holds no plaintext; each still reads back as the
// plaintext through its reader.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Rows are created under unique
// names and removed by primary key. Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/ -run 'TestAtRestWriters'

//go:build integration

package handlers

import (
	"bytes"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/michielvha/stackweaver/backend/internal/api/middleware"
	terraformHandlers "github.com/michielvha/stackweaver/backend/internal/api/v2/handlers/terraform"
	"github.com/michielvha/stackweaver/backend/internal/services/apikey"
	"github.com/michielvha/stackweaver/core/crypto"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/runnercontract"
	"github.com/michielvha/stackweaver/core/services/ansible"
	"github.com/michielvha/stackweaver/core/services/state"
	"github.com/michielvha/stackweaver/core/services/vcs"
	"github.com/michielvha/stackweaver/core/storage"
)

const atRestSecret = "hunter2-written-by-a-real-writer"

type atRestWritersFixture struct {
	*agentPrepFixture
	r     *gin.Engine
	svc   *apikey.Service
	raw   *snapshotStore // under the sealing layer: what the bucket holds
	cs    *crypto.CryptoService
	items *ansible.WorkItemService
}

func setupAtRestWriters(t *testing.T) *atRestWritersFixture {
	t.Helper()
	f := setupAgentPrepFixture(t)
	cs, err := crypto.NewCryptoService([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	// The API's wiring: one sealed client over the bucket, the state service on it with the
	// at-rest key, and the plan JSON sealed with the same key.
	raw := newSnapshotStore()
	sealed := storage.NewSealed(raw, cs, storage.ArtifactSealRules()...)
	models.SetPlanOutputSealer(cs)
	t.Cleanup(func() { models.SetPlanOutputSealer(nil) })

	svc := apikey.NewService(repository.NewAPIKeyRepository(f.db), nil, nil, nil)
	inventoryRepo := repository.NewAnsibleInventoryRepository(f.db)
	export := ansible.NewInventoryService(inventoryRepo, repository.NewOrganizationRepository(f.db))
	h := &RunnerAgentHandler{
		db: f.db, apiKeyService: svc, runnerRepo: repository.NewRunnerRepository(f.db),
		jobExecRepo:    repository.NewRunnerJobExecutionRepository(f.db),
		ansibleJobRepo: repository.NewAnsibleJobRepository(f.db),
		playbookRepo:   repository.NewAnsiblePlaybookRepository(f.db),
		inventoryRepo:  inventoryRepo,
		vcsRegistry:    vcs.NewProviderRegistry(nil, nil, nil, nil),
		storageClient:  sealed,
		cryptoService:  cs,
		stateService:   state.NewService(repository.NewStateVersionRepository(f.db), repository.NewStateLockRepository(f.db), repository.NewWorkspaceRepository(f.db), sealed, nil, cs),
	}
	h.SetWorkItems(ansible.NewWorkItemRuntime(f.db, export, nil))
	f.declareCapabilities(t, f.runnerA1, runnercontract.CapabilityJobToken, runnercontract.CapabilityWorkItems)

	// The TFE plan JSON route, reached as a run task's access token reaches it.
	runs := terraformHandlers.NewRunHandlerV2(repository.NewRunRepository(f.db), nil, nil, nil, sealed, nil, nil, nil, nil, nil, nil, nil, nil, cs, nil, nil, nil)
	r := f.router(func(authed *gin.RouterGroup) {
		authed.POST("/jobs/:id/start", middleware.RequireRunnerToken(), h.JobStart)
		authed.POST("/jobs/:id/token", middleware.RequireRunnerToken(), h.JobToken)
		authed.POST("/jobs/:id/snapshot", middleware.JobData(), h.UploadSnapshot)
		authed.POST("/jobs/:id/plan", middleware.JobData(), h.UploadPlan)
		authed.GET("/jobs/:id/plan", middleware.JobData(), h.DownloadPlan)
		authed.POST("/jobs/:id/state", middleware.JobData(), h.UploadState)
		authed.POST("/jobs/:id/complete", middleware.JobData(), h.JobComplete)
	})
	r.GET("/api/v2/plans/:id/json-output", func(c *gin.Context) { c.Set("task_token_result_id", "taskresult-test") }, runs.GetPlanJSONOutput)
	return &atRestWritersFixture{agentPrepFixture: f, r: r, svc: svc, raw: raw, cs: cs, items: ansible.NewWorkItemService(f.db, nil)}
}

func (f *atRestWritersFixture) post(t *testing.T, key, path, contentType string, body []byte, header map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("X-Test-Key", key)
	for k, v := range header {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	f.r.ServeHTTP(rec, req)
	return rec
}

// assertSealedObject fails the test when the object at key reads as plaintext in the bucket or
// does not open to plaintext.
func (f *atRestWritersFixture) assertSealedObject(t *testing.T, key string, plaintext []byte) {
	t.Helper()
	data, err := f.raw.Get(t.Context(), key)
	if err != nil {
		t.Fatalf("no object at %s: %v", key, err)
	}
	if bytes.Contains(data, []byte(atRestSecret)) || bytes.Equal(data, plaintext) {
		t.Errorf("%s is readable as plaintext in the bucket", key)
	}
	if opened, err := f.cs.DecryptAtRest(data, nil); err != nil || !bytes.Equal(opened, plaintext) {
		t.Errorf("%s does not open with the at-rest helper to what was written: %v", key, err)
	}
}

// claimWorkItem moves item onto pool A, claims it as a1 and mints its job token under name.
func (f *atRestWritersFixture) claimWorkItem(t *testing.T, item *models.WorkItem, name string) {
	t.Helper()
	if err := f.db.Model(&models.WorkItem{}).Where("id = ?", item.ID).Update("agent_pool_id", f.poolA).Error; err != nil {
		t.Fatal(err)
	}
	if rec := runnerDo(t, f.r, "a1", http.MethodPost, "/api/v2/runner/jobs/"+item.ID+"/start", runnercontract.JobStartRequest{RunnerID: f.runnerA1.ID.String()}); rec.Code != http.StatusOK {
		t.Fatalf("claiming %s: %d %s", item.ID, rec.Code, rec.Body.String())
	}
	if code, _ := f.mintJobToken(t, f.r, f.svc, "a1", item.ID, name); code != http.StatusOK {
		t.Fatalf("minting the job token of %s: %d", item.ID, code)
	}
}

func TestAtRestWriters_SavedPlan(t *testing.T) {
	f := setupAtRestWriters(t)
	run := f.seedRun(t, f.runnerA1)
	if code, _ := f.mintJobToken(t, f.r, f.svc, "a1", run.ID, "job"); code != http.StatusOK {
		t.Fatalf("mint: %d", code)
	}
	plan := []byte("PK\x03\x04 saved plan " + atRestSecret)
	if rec := f.post(t, "job", "/api/v2/runner/jobs/"+run.ID+"/plan", "application/octet-stream", plan, nil); rec.Code != http.StatusOK {
		t.Fatalf("POST plan: %d %s", rec.Code, rec.Body.String())
	}
	f.assertSealedObject(t, planFileKey(run.ID), plan)
	if got := runnerDo(t, f.r, "job", http.MethodGet, "/api/v2/runner/jobs/"+run.ID+"/plan", nil); got.Code != http.StatusOK || !bytes.Equal(got.Body.Bytes(), plan) {
		t.Errorf("GET plan: %d, want the plaintext plan back", got.Code)
	}
}

func TestAtRestWriters_PlaybookSnapshot(t *testing.T) {
	f := setupAtRestWriters(t)
	pb := f.seedPlaybook(t, playbookSpec{mode: models.PlaybookSourceModeCached})
	item, err := f.items.RequestPlaybookSnapshot(t.Context(), pb, "manual")
	if err != nil {
		t.Fatal(err)
	}
	f.claimWorkItem(t, item, "wi")
	snapshot := append([]byte("\x1f\x8b\x08 playbook "), atRestSecret...)
	if rec := f.post(t, "wi", "/api/v2/runner/jobs/"+item.ID+"/snapshot", "application/octet-stream", snapshot, nil); rec.Code != http.StatusOK {
		t.Fatalf("POST snapshot: %d %s", rec.Code, rec.Body.String())
	}
	f.assertSealedObject(t, ansible.PlaybookSnapshotKey(pb.ID), snapshot)
}

func TestAtRestWriters_ConfigurationSnapshot(t *testing.T) {
	f := setupAtRestWriters(t)
	_, run := f.storedWorkspaceNaming(t, f.vcsConn)
	item, err := f.items.RequestConfigurationSnapshot(t.Context(), run)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.db.Where("workspace_id = ?", run.WorkspaceID).Delete(&models.ConfigurationVersion{}) })
	f.claimWorkItem(t, item, "wi")
	tarball := append([]byte("\x1f\x8b\x08 configuration "), atRestSecret...)
	if rec := f.post(t, "wi", "/api/v2/runner/jobs/"+item.ID+"/snapshot", "application/octet-stream", tarball, map[string]string{runnercontract.HeaderSnapshotCommit: "feedface"}); rec.Code != http.StatusOK {
		t.Fatalf("POST snapshot: %d %s", rec.Code, rec.Body.String())
	}
	var cv models.ConfigurationVersion
	if err := f.db.Where("workspace_id = ?", run.WorkspaceID).Order("created_at DESC").First(&cv).Error; err != nil {
		t.Fatalf("no configuration version from the snapshot: %v", err)
	}
	f.assertSealedObject(t, "configuration-versions/"+cv.ID+"/config.tar.gz", tarball)
}

func TestAtRestWriters_LargeState(t *testing.T) {
	f := setupAtRestWriters(t)
	run := f.seedRun(t, f.runnerA1)
	t.Cleanup(func() { f.db.Where("workspace_id = ?", run.WorkspaceID).Delete(&models.StateVersion{}) })
	if code, _ := f.mintJobToken(t, f.r, f.svc, "a1", run.ID, "job"); code != http.StatusOK {
		t.Fatalf("mint: %d", code)
	}
	// Above the inline threshold, so it travels as the raw state file, as a large state does.
	padding := strings.Repeat("p", DefaultInlineArtifactLimit+1024)
	stateFile := []byte(`{"version":4,"serial":1,"lineage":"at-rest-large","outputs":{"s":{"value":"` + atRestSecret + `","type":"string"}},"resources":[],"padding":"` + padding + `"}`)
	rec := f.post(t, "job", "/api/v2/runner/jobs/"+run.ID+"/state", "application/octet-stream", stateFile, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST state: %d %s", rec.Code, rec.Body.String())
	}
	var saved StateVersionSavedResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &saved); err != nil {
		t.Fatal(err)
	}
	key := "workspaces/" + run.WorkspaceID + "/state/" + strconv.Itoa(saved.Version) + ".json"
	data, err := f.raw.Get(t.Context(), key)
	if err != nil {
		t.Fatalf("no state object at %s: %v", key, err)
	}
	if bytes.Contains(data, []byte(atRestSecret)) || bytes.Contains(data, []byte("at-rest-large")) {
		t.Errorf("%s is readable as plaintext in the bucket", key)
	}
}

func TestAtRestWriters_PlanJSON(t *testing.T) {
	f := setupAtRestWriters(t)
	run := f.seedRun(t, f.runnerA1)
	if code, _ := f.mintJobToken(t, f.r, f.svc, "a1", run.ID, "job"); code != http.StatusOK {
		t.Fatalf("mint: %d", code)
	}
	planJSON := `{"format_version":"1.2","variables":{"db_password":{"value":"` + atRestSecret + `"}},"resource_changes":[{"address":"null_resource.a","change":{"actions":["create"]}}]}`
	done := JobCompleteRequest{RunnerID: f.runnerA1.ID.String(), Status: "completed", PlanJSON: planJSON, HasChanges: true, ResourceAdditions: 1}
	if rec := runnerDo(t, f.r, "job", http.MethodPost, "/api/v2/runner/jobs/"+run.ID+"/complete", done); rec.Code != http.StatusOK {
		t.Fatalf("POST complete: %d %s", rec.Code, rec.Body.String())
	}

	var stored *string
	if err := f.db.Raw("SELECT plan_output::text FROM runs WHERE id = ?", run.ID).Scan(&stored).Error; err != nil || stored == nil {
		t.Fatalf("reading the column: %v", err)
	}
	if strings.Contains(*stored, atRestSecret) || strings.Contains(*stored, "null_resource") || !strings.Contains(*stored, models.PlanOutputSealedKey) {
		t.Errorf("runs.plan_output is readable as plaintext: %.200s", *stored)
	}

	// Every reader gets the plan: the repository, and the TFE plan JSON route.
	read, err := repository.NewRunRepository(f.db).GetByID(run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if vars, _ := read.PlanOutput["variables"].(map[string]any); vars == nil || read.PlanOutput["AddCount"] != float64(1) {
		t.Errorf("the run reads back plan output %v", read.PlanOutput)
	}
	rec := runnerDo(t, f.r, "", http.MethodGet, "/api/v2/plans/"+run.ID+"/json-output", nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), atRestSecret) || strings.Contains(rec.Body.String(), models.PlanOutputSealedKey) {
		t.Errorf("GET plans/:id/json-output: %d %.200s, want the plaintext plan JSON", rec.Code, rec.Body.String())
	}
	// The workspace list reads has-changes in the database, from the sealed plan's flag.
	latest, err := repository.NewRunRepository(f.db).GetLatestByWorkspaceIDs([]string{run.WorkspaceID})
	if err != nil {
		t.Fatal(err)
	}
	if l := latest[run.WorkspaceID]; l == nil || !l.PlanIndicatesChanges {
		t.Errorf("the workspace list reads %+v, want changes for a sealed plan that creates a resource", l)
	}
}

// TestAtRestWriters_EveryDatabaseProcessSealsPlanOutput is the static half for the plan JSON: every
// binary that opens the database sets the plan output sealer, so none writes a plan in plaintext or
// fails to read a sealed one.
func TestAtRestWriters_EveryDatabaseProcessSealsPlanOutput(t *testing.T) {
	root := filepath.Join("..", "..", "..", "..", "cmd")
	mains, err := filepath.Glob(filepath.Join(root, "*", "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	opens := map[string]bool{}
	seals := map[string]bool{}
	for _, path := range mains {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		src, err := os.ReadFile(path) //nolint:gosec // G304: a source file of this module
		if err != nil {
			t.Fatal(err)
		}
		file, err := parser.ParseFile(fset, path, src, 0)
		if err != nil {
			t.Fatal(err)
		}
		dir := filepath.Base(filepath.Dir(path))
		ast.Inspect(file, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if id, ok := sel.X.(*ast.Ident); ok {
				if id.Name == "repository" && sel.Sel.Name == "NewDatabase" {
					opens[dir] = true
				}
				if id.Name == "models" && sel.Sel.Name == "SetPlanOutputSealer" {
					seals[dir] = true
				}
			}
			return true
		})
	}
	if len(opens) == 0 {
		t.Fatal("no binary opens the database: the walk is broken")
	}
	for dir := range opens {
		if !seals[dir] {
			t.Errorf("cmd/%s opens the database without models.SetPlanOutputSealer", dir)
		}
	}
}
