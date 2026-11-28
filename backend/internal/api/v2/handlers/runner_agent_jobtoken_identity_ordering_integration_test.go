// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Orderings of the first job token that a free-running test cannot force (#1113, D2, D3; AC-04,
// AC-21, AC-22, AC-23). A GORM callback the test registers on its own database handle holds the
// token transaction at a chosen statement while another transaction commits, so the proof needs no
// hook in production code.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Cleanup is row-scoped.

//go:build integration

package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/runnercontract"
	"gorm.io/gorm"
)

// statementHold stops the first statement matching its predicate, after it ran and inside its
// transaction, until the test releases it. It is armed when created and fires once.
type statementHold struct {
	held, release chan struct{}
	fired         atomic.Bool
	releaseOnce   sync.Once
}

// holdAfter registers a callback named name after GORM's update or query step ("update" or
// "query") on db, removed when the test ends.
func holdAfter(t *testing.T, db *gorm.DB, step, name string, match func(*gorm.Statement) bool) *statementHold {
	t.Helper()
	h := &statementHold{held: make(chan struct{}), release: make(chan struct{})}
	fn := func(tx *gorm.DB) {
		if tx.Error != nil || !match(tx.Statement) || !h.fired.CompareAndSwap(false, true) {
			return
		}
		close(h.held)
		<-h.release
	}
	var err error
	switch step {
	case "update":
		err = db.Callback().Update().After("gorm:update").Register(name, fn)
	case "query":
		err = db.Callback().Query().After("gorm:query").Register(name, fn)
	default:
		t.Fatalf("unknown step %q", step)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		h.Release()
		switch step {
		case "update":
			_ = db.Callback().Update().Remove(name)
		case "query":
			_ = db.Callback().Query().Remove(name)
		}
	})
	return h
}

// Wait blocks until the statement is held.
func (h *statementHold) Wait(t *testing.T) {
	t.Helper()
	select {
	case <-h.held:
	case <-time.After(20 * time.Second):
		t.Fatal("the statement was never held")
	}
}

// Release lets the held statement's transaction continue.
func (h *statementHold) Release() { h.releaseOnce.Do(func() { close(h.release) }) }

// waitForLockWait blocks until a backend of this database waits on a lock while running a
// statement that contains fragment.
func waitForLockWait(t *testing.T, db *gorm.DB, fragment string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		var n int64
		if err := db.Raw(`SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock' AND query LIKE ?`, "%"+fragment+"%").Scan(&n).Error; err != nil {
			t.Fatal(err)
		}
		if n > 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("no statement containing %q waited on a lock", fragment)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// isDecisionWrite matches the statement that records an attempt's identity decision.
func isDecisionWrite(s *gorm.Statement) bool {
	if s.Table != "work_items" {
		return false
	}
	m, ok := s.Dest.(map[string]any)
	if !ok {
		return false
	}
	_, ok = m["placement_identity"]
	return ok
}

// Of two first token requests for one attempt, the second, issued after the binding changed while
// the first held the claim, returns the first's decision (AC-22).
func TestJobTokenIdentity_ConcurrentFirstRequests(t *testing.T) {
	f := setupWorkItemRunner(t)
	f.kubernetesRunners(t)
	b := f.binding(t, f.poolA, "files")
	f.selectOnProject(t, b.ID)
	_, item := f.fileSyncClaimed(t)

	hold := holdAfter(t, f.db, "update", "test:hold-decision-write", isDecisionWrite)
	path := "/api/v2/runner/jobs/" + item.ID + "/token"
	first := make(chan *httptest.ResponseRecorder, 1)
	go func() { first <- runnerDo(t, f.r, "a1", http.MethodPost, path, nil) }()
	hold.Wait(t)

	// The binding changes in another transaction while the first request holds the claim.
	want := b.ServiceAccount
	if err := f.db.Model(&models.IdentityBinding{}).Where("id = ?", b.ID).Update("service_account", "sw-changed").Error; err != nil {
		t.Fatal(err)
	}
	second := make(chan *httptest.ResponseRecorder, 1)
	go func() { second <- runnerDo(t, f.r, "a1", http.MethodPost, path, nil) }()
	waitForLockWait(t, f.db, "work_items")
	hold.Release()

	for name, ch := range map[string]chan *httptest.ResponseRecorder{"first": first, "second": second} {
		rec := <-ch
		if rec.Code != http.StatusOK {
			t.Fatalf("%s token = %d %s", name, rec.Code, rec.Body.String())
		}
		var tok runnercontract.JobToken
		if err := json.Unmarshal(rec.Body.Bytes(), &tok); err != nil {
			t.Fatal(err)
		}
		if tok.Identity == nil || tok.Identity.ServiceAccount != want {
			t.Errorf("%s token identity = %+v, want the first request's ServiceAccount %s", name, tok.Identity, want)
		}
	}
	if got := f.reload(t, item.ID).Placement.Identity; got == nil || got.ServiceAccount != want {
		t.Errorf("stored decision = %+v, want ServiceAccount %s", got, want)
	}
}

// An inventory move that commits after the token transaction read the inventory row never yields a
// decision whose binding and recorded scope come from different projects (AC-23).
func TestJobTokenIdentity_MoveAfterTheInventoryRead(t *testing.T) {
	f := setupWorkItemRunner(t)
	f.kubernetesRunners(t)
	b := f.binding(t, f.poolA, "files")
	f.selectOnProject(t, b.ID)
	inv, item := f.fileSyncClaimed(t)

	// The destination selects another binding of pool A, and pool A does not let it use it.
	elsewhere := f.binding(t, f.poolA, "destination")
	other := &models.Project{ID: uuid.New(), OrganizationID: f.orgA, Name: "move-race-" + uuid.NewString()[:8], IdentityBindingID: &elsewhere.ID}
	if err := f.db.Create(other).Error; err != nil {
		t.Fatal(err)
	}
	// Update by ID: the inventory's ProjectID points at the fixture's project ID.
	origin := f.projectA
	move := func(to uuid.UUID) error {
		return f.db.Model(&models.AnsibleInventory{}).Where("id = ?", inv.ID).Update("project_id", to).Error
	}
	t.Cleanup(func() {
		_ = move(origin)
		f.db.Where("id = ?", other.ID).Delete(&models.Project{})
	})

	hold := holdAfter(t, f.db, "query", "test:hold-inventory-read", func(s *gorm.Statement) bool {
		return s.Table == "ansible_inventories" && slices.Contains(s.Selects, "identity_binding_id") && slices.Contains(s.Selects, "project_id")
	})
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- runnerDo(t, f.r, "a1", http.MethodPost, "/api/v2/runner/jobs/"+item.ID+"/token", nil) }()
	hold.Wait(t)
	if err := move(other.ID); err != nil {
		t.Fatal(err)
	}
	hold.Release()

	rec := <-done
	if rec.Code != http.StatusOK {
		t.Fatalf("token = %d %s, want 200 for the row the transaction read", rec.Code, rec.Body.String())
	}
	got := f.reload(t, item.ID).Placement.Identity
	if got == nil || got.BindingID == nil || got.Scope == nil || got.Scope.ProjectID == nil {
		t.Fatalf("decision = %+v, want a binding and a scope", got)
	}
	if *got.BindingID != b.ID || *got.Scope.ProjectID != origin {
		t.Errorf("decision binding %s with scope project %s; want both from the row read: binding %s, project %s",
			*got.BindingID, *got.Scope.ProjectID, b.ID, origin)
	}
}

// Configuration snapshots and module tag captures run with the platform identity whatever their
// project or organization selects (AC-04).
func TestJobTokenIdentity_CaptureKindsGetNoIdentity(t *testing.T) {
	f := setupWorkItemRunner(t)
	hosted := configureHosted(t, "capture-identity")
	hostedPool, _, err := repository.HostedPoolOf(f.db, f.orgA)
	if err != nil {
		t.Fatal(err)
	}
	// Both the organization and the project select the hosted binding, which hosted work is offered.
	if err := f.db.Model(&models.Organization{}).Where("id = ?", f.orgA).Update("identity_binding_id", hosted).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		f.db.Model(&models.Organization{}).Where("id = ?", f.orgA).Update("identity_binding_id", nil)
	})
	f.selectOnProject(t, hosted)
	runner := f.hostedKubernetesRunner(t, hostedPool)
	now := time.Now()
	for _, kind := range []string{models.WorkItemConfigurationSnapshot, models.WorkItemModuleTagSnapshot} {
		t.Run(kind, func(t *testing.T) {
			item := &models.WorkItem{
				OrganizationID: f.orgA, Kind: kind, TriggeredBy: "test", AgentPoolID: &hostedPool, QueuedAt: &now,
				ImageLevel: "platform",
			}
			if kind == models.WorkItemConfigurationSnapshot {
				item.ProjectID = &f.projectA
			}
			if err := f.db.Create(item).Error; err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { f.db.Where("id = ?", item.ID).Delete(&models.WorkItem{}) })
			f.startAs(t, runner, item.ID)
			tok, err := f.tokenAs(t, runner, item.ID)
			if err != nil {
				t.Fatal(err)
			}
			if tok.Identity != nil {
				t.Errorf("token identity = %+v, want none: a %s runs with the platform identity", tok.Identity, kind)
			}
			if got := f.reload(t, item.ID).Placement; got.IdentityBindingID != nil || (got.Identity != nil && got.Identity.BindingID != nil) {
				t.Errorf("placement = %+v, want no identity binding", got)
			}
		})
	}
}

// A launcher that registered with the previous release's body on the container driver is refused a
// job that resolves a binding, with 409 naming the binding and the driver (AC-21).
func TestJobTokenIdentity_PreviousReleaseRegistrationRefused(t *testing.T) {
	f := setupWorkItemRunner(t)
	b := f.binding(t, f.poolA, "files")
	f.selectOnProject(t, b.ID)
	inv := f.fileSyncInventory(t, models.InventoryTypeVCS)
	item, err := f.items.RequestInventorySync(t.Context(), inv, "manual")
	if err != nil {
		t.Fatal(err)
	}
	srv, _ := f.launcherAPI(t)
	call := func(token, path string, body any) (int, []byte) {
		t.Helper()
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+path, bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(resp.Body)
		return resp.StatusCode, buf.Bytes()
	}

	// The body the previous release's launcher sends, field for field (core/v0.628.4 RegisterRequest).
	code, body := call(f.registration, "/api/v2/runner/register", map[string]any{
		"agent_pool_id": f.poolA.String(), "name": "claim-refusal-prev-" + uuid.NewString()[:6], "hostname": "launcher-0",
		"os_type": "linux", "os_version": "6.1", "agent_version": "0.628.4", "tofu_version": "", "ansible_version": "2.18",
		"available_collections": []string{}, "max_concurrent_jobs": 1, "labels": []string{},
		"capabilities": []string{runnercontract.CapabilityJobToken, runnercontract.CapabilityWorkItems},
		"engines":      []string{"ansible"}, "driver": "container", "network_mode": "bridge",
	})
	if code != http.StatusOK && code != http.StatusCreated {
		t.Fatalf("register = %d %s", code, body)
	}
	var reg runnercontract.RegisterResponse
	if err := json.Unmarshal(body, &reg); err != nil {
		t.Fatal(err)
	}
	if code, body := call(reg.RunnerAPIKey, "/api/v2/runner/jobs/"+item.ID+"/start", runnercontract.JobStartRequest{RunnerID: reg.RunnerID}); code != http.StatusOK {
		t.Fatalf("start = %d %s", code, body)
	}
	code, body = call(reg.RunnerAPIKey, "/api/v2/runner/jobs/"+item.ID+"/token", map[string]any{})
	if code != http.StatusConflict {
		t.Fatalf("token = %d %s, want 409", code, body)
	}
	for _, want := range []string{fmt.Sprintf(`identity binding \"%s\" (%s) needs the kubernetes driver; this pool's launcher uses the container driver; run the job on a Kubernetes pool or select no binding`, b.Name, b.Mechanism)} {
		if !strings.Contains(string(body), want) {
			t.Errorf("refusal %s does not say %q", body, want)
		}
	}
	if got := f.reload(t, item.ID).Placement; got.Identity != nil || got.IdentityBindingID != nil {
		t.Errorf("a refused launcher recorded %+v", got)
	}
}

// An OpenTofu run's plan and apply are separate claims, each its own attempt, so the apply resolves
// its identity again: after the plan's first token records a decision and the workspace's
// selection changes, the apply's first token records the current selection (#1113, D3; AC-22).
func TestJobTokenIdentity_RunApplyResolvesAgain(t *testing.T) {
	f := setupWorkItemRunner(t)
	f.kubernetesRunners(t)
	planBinding := f.binding(t, f.poolA, "plan")
	applyBinding := f.binding(t, f.poolA, "apply")
	ws := &models.Workspace{ProjectID: f.projectA, Name: "id-apply-" + uuid.NewString()[:8], ExecutionMode: "agent", AgentPoolID: &f.poolA, IdentityBindingID: &planBinding.ID}
	if err := f.db.Create(ws).Error; err != nil {
		t.Fatal(err)
	}
	run := &models.Run{WorkspaceID: ws.ID, Status: models.RunStatusPending, Operation: models.RunOperationPlanAndApply, AgentPoolID: &f.poolA}
	if err := f.db.Create(run).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		f.db.Where("id = ?", run.ID).Delete(&models.Run{})
		f.db.Where("id = ?", ws.ID).Delete(&models.Workspace{})
	})
	claim := func(phase string) runnercontract.JobToken {
		t.Helper()
		if rec := runnerDo(t, f.r, "a1", http.MethodPost, "/api/v2/runner/jobs/"+run.ID+"/start", runnercontract.JobStartRequest{RunnerID: f.keyRunner("a1")}); rec.Code != http.StatusOK {
			t.Fatalf("claiming the %s: %d %s", phase, rec.Code, rec.Body.String())
		}
		code, tok := f.token(t, run.ID)
		if code != http.StatusOK {
			t.Fatalf("%s token = %d", phase, code)
		}
		return tok
	}

	plan := claim("plan")
	if plan.Identity == nil || plan.Identity.BindingID != planBinding.ID.String() {
		t.Fatalf("plan identity = %+v, want %s", plan.Identity, planBinding.ID)
	}
	// The plan finishes and the run waits for its apply; the workspace now selects another binding.
	if err := f.db.Model(&models.Run{}).Where("id = ?", run.ID).Updates(map[string]any{"status": models.RunStatusApplying, "dispatched_at": nil}).Error; err != nil {
		t.Fatal(err)
	}
	if err := f.db.Model(&models.Workspace{}).Where("id = ?", ws.ID).Update("identity_binding_id", applyBinding.ID).Error; err != nil {
		t.Fatal(err)
	}
	apply := claim("apply")
	if apply.Attempt <= plan.Attempt {
		t.Errorf("apply attempt %d, want a new attempt after the plan's %d", apply.Attempt, plan.Attempt)
	}
	if apply.Identity == nil || apply.Identity.BindingID != applyBinding.ID.String() {
		t.Errorf("apply identity = %+v, want the current selection %s", apply.Identity, applyBinding.ID)
	}
	var stored models.Run
	if err := f.db.First(&stored, "id = ?", run.ID).Error; err != nil {
		t.Fatal(err)
	}
	if got := stored.Placement; got.IdentityAttempt != apply.Attempt || got.Identity == nil || got.Identity.BindingID == nil || *got.Identity.BindingID != applyBinding.ID {
		t.Errorf("stored decision = attempt %d, %+v; want the apply's attempt %d with %s", got.IdentityAttempt, got.Identity, apply.Attempt, applyBinding.ID)
	}
}
