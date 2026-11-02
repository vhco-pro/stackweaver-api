// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// What blocks deleting an Ansible credential, inventory or playbook, and what the 409 says about
// it. A job keeps the credentials it ran with, and that link's foreign key to the credential does
// not cascade, so a credential a job ran with cannot be deleted. Every other reference to a
// credential cascades or is nulled by the reconciled delete rules (models.FKDeleteRules): a job
// template's credential set loses the credential, and inventory sources and workflow nodes drop
// their pointer to it.
//
// An inventory or playbook delete first counts its dependents and refuses with a 409 naming them
// (InventoryService.DeleteInventory, PlaybookHandler.DeletePlaybook); a reference the count does
// not cover, one nulled by the delete rules, lets the delete through. A playbook's count covers
// job templates only: the jobs that ran it keep their history with the link cleared. The 409 for
// a foreign key violation behind the count is held to the constraints that really refuse the
// delete by TestDeleteConflictDetail.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Cleanup is strictly
// row-scoped (the database may be live). Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/ansible/ -run 'TestCredentialDelete|TestInventoryDelete|TestPlaybookDelete|TestPlaybookForceDelete'

//go:build integration

package ansible

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/dbtest"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	ansiblesvc "github.com/michielvha/stackweaver/core/services/ansible"
	"github.com/michielvha/stackweaver/core/storage/storagetest"
	"gorm.io/gorm"
)

type credentialDeleteFixture struct {
	db       *gorm.DB
	router   *gin.Engine
	owner    uuid.UUID
	org      uuid.UUID
	project  uuid.UUID
	playbook uuid.UUID
	inv      uuid.UUID
	sfx      string
	// store is the object storage the playbook repository prunes a deleted playbook from.
	store *storagetest.Memory
}

func setupCredentialDelete(t *testing.T) *credentialDeleteFixture {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping integration test")
	}
	db, err := dbtest.Open(t, dsn, &gorm.Config{})
	if err != nil {
		t.Fatalf("connecting to the test database: %v", err)
	}
	// The template's credential link cascades only once the delete rules are reconciled, as the
	// API does on startup. A no-op on a database that is already reconciled.
	if _, err := models.ReconcileFKDeleteRules(db); err != nil {
		t.Fatalf("reconciling the foreign key delete rules: %v", err)
	}

	sfx := uuid.NewString()[:8]
	f := &credentialDeleteFixture{db: db, sfx: sfx}
	create := func(row any, cleanup func()) {
		t.Helper()
		if err := db.Create(row).Error; err != nil {
			t.Fatalf("seeding %T: %v", row, err)
		}
		t.Cleanup(cleanup)
	}

	org := &models.Organization{ID: uuid.New(), Name: "creddel-org-" + sfx}
	create(org, func() { db.Delete(&models.Organization{}, "id = ?", org.ID) })
	owner := &models.User{ID: uuid.New(), ZitadelSubject: "creddel-own-" + sfx, Email: "creddel-own-" + sfx + "@test.local"}
	create(owner, func() { db.Delete(&models.User{}, "id = ?", owner.ID) })
	member := &models.OrganizationMember{ID: uuid.New(), OrganizationID: org.ID, UserID: owner.ID}
	create(member, func() { db.Delete(&models.OrganizationMember{}, "id = ?", member.ID) })
	team := &models.Team{ID: uuid.New(), OrganizationID: org.ID, Name: "owners"}
	create(team, func() { db.Delete(&models.Team{}, "id = ?", team.ID) })
	teamMember := &models.TeamMember{ID: uuid.New(), TeamID: team.ID, UserID: owner.ID}
	create(teamMember, func() { db.Delete(&models.TeamMember{}, "id = ?", teamMember.ID) })
	project := &models.Project{ID: uuid.New(), OrganizationID: org.ID, Name: "creddel-proj-" + sfx}
	create(project, func() { db.Delete(&models.Project{}, "id = ?", project.ID) })
	inv := &models.AnsibleInventory{ID: uuid.New(), OrganizationID: org.ID, Name: "creddel-inv-" + sfx, Type: models.InventoryTypeStatic}
	create(inv, func() { db.Delete(&models.AnsibleInventory{}, "id = ?", inv.ID) })
	playbook := &models.AnsiblePlaybook{ID: uuid.New(), ProjectID: project.ID, Name: "creddel-pb-" + sfx}
	create(playbook, func() { db.Delete(&models.AnsiblePlaybook{}, "id = ?", playbook.ID) })
	f.owner, f.org, f.project, f.playbook, f.inv = owner.ID, org.ID, project.ID, playbook.ID, inv.ID

	orgRepo := repository.NewOrganizationRepository(db)
	projectRepo := repository.NewProjectRepository(db)
	credentialService := ansiblesvc.NewCredentialService(
		repository.NewAnsibleCredentialRepository(db), []byte("0123456789abcdef0123456789abcdef"),
	)
	authService := auth.NewService(repository.NewUserRepository(db))
	rbacService := rbac.NewServiceWithTeams(orgRepo, repository.NewTeamRepository(db), projectRepo)
	credentials := NewCredentialHandler(credentialService, orgRepo, projectRepo, authService, rbacService)
	inventoryRepo := repository.NewAnsibleInventoryRepository(db)
	inventories := NewInventoryHandler(
		ansiblesvc.NewInventoryService(inventoryRepo, orgRepo), inventoryRepo, orgRepo, projectRepo,
		authService, rbacService, nil, nil, repository.NewVCSConnectionRepository(db),
	)
	playbookRepo := repository.NewAnsiblePlaybookRepository(db)
	f.store = storagetest.NewMemory()
	playbookRepo.SetStorage(f.store)
	playbooks := NewPlaybookHandler(
		playbookRepo, repository.NewAnsibleJobTemplateRepository(db), repository.NewAnsibleJobRepository(db),
		repository.NewAnsibleScheduleRepository(db), projectRepo, orgRepo, authService, rbacService,
		nil, nil, repository.NewVCSConnectionRepository(db), nil,
	)

	gin.SetMode(gin.TestMode)
	f.router = gin.New()
	f.router.Use(func(c *gin.Context) {
		c.Set("user_id", owner.ID)
		c.Next()
	})
	// The paths and parameter names of ansible_routes.go.
	f.router.DELETE("/ansible/credentials/:id", credentials.Delete)
	f.router.DELETE("/ansible/inventories/:id", inventories.Delete)
	f.router.DELETE("/ansible/playbooks/:id", playbooks.DeletePlaybook)
	templateRepo := repository.NewAnsibleJobTemplateRepository(db)
	jobs := NewJobHandler(
		ansiblesvc.NewJobService(
			repository.NewAnsibleJobRepository(db), repository.NewAnsiblePlaybookRepository(db), inventoryRepo,
			templateRepo, projectRepo, nil,
		),
		projectRepo, orgRepo, templateRepo, authService, rbacService,
	)
	f.router.GET("/ansible/jobs/:id", jobs.Get)
	f.router.POST("/ansible/jobs/:id/actions/relaunch", jobs.Relaunch)
	return f
}

// credential creates an organization-scoped SSH credential, removed at the end of the test if
// the case under test did not delete it.
func (f *credentialDeleteFixture) credential(t *testing.T, name string) uuid.UUID {
	t.Helper()
	cred := &models.AnsibleCredential{ID: uuid.New(), OrganizationID: f.org, Name: "creddel-" + name + "-" + f.sfx, Type: models.CredentialTypeSSH}
	if err := f.db.Create(cred).Error; err != nil {
		t.Fatalf("seeding the credential: %v", err)
	}
	t.Cleanup(func() { f.db.Delete(&models.AnsibleCredential{}, "id = ?", cred.ID) })
	return cred.ID
}

func (f *credentialDeleteFixture) template(t *testing.T) uuid.UUID {
	t.Helper()
	tmpl := &models.AnsibleJobTemplate{ID: uuid.New(), ProjectID: f.project, PlaybookID: f.playbook, InventoryID: f.inv, Name: "creddel-tmpl-" + uuid.NewString()[:8]}
	if err := f.db.Create(tmpl).Error; err != nil {
		t.Fatalf("seeding the job template: %v", err)
	}
	t.Cleanup(func() { f.db.Delete(&models.AnsibleJobTemplate{}, "id = ?", tmpl.ID) })
	return tmpl.ID
}

func (f *credentialDeleteFixture) exec(t *testing.T, query string, args ...any) {
	t.Helper()
	if err := f.db.Exec(query, args...).Error; err != nil {
		t.Fatalf("writing a row directly (%q): %v", query, err)
	}
}

func (f *credentialDeleteFixture) count(t *testing.T, query string, args ...any) int64 {
	t.Helper()
	var n int64
	if err := f.db.Raw(query, args...).Scan(&n).Error; err != nil {
		t.Fatalf("counting (%q): %v", query, err)
	}
	return n
}

func (f *credentialDeleteFixture) deleteCredential(t *testing.T, id uuid.UUID) (int, []byte) {
	t.Helper()
	return f.delete(t, "/ansible/credentials/"+id.String())
}

func (f *credentialDeleteFixture) delete(t *testing.T, path string) (int, []byte) {
	t.Helper()
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, path, nil))
	return rec.Code, rec.Body.Bytes()
}

// deleteWhileInserting races a delete against a reference inserted while it runs. It inserts a
// row that references the resource in a transaction it holds open, so a dependency count cannot
// see the row while the insert's key lock makes the delete wait: the DELETE of an inventory, or
// the row lock a playbook delete takes before it counts. waitingQuery is a LIKE pattern for
// the statement that waits. Once it waits, the transaction commits, and the delete then meets the
// committed reference.
func (f *credentialDeleteFixture) deleteWhileInserting(t *testing.T, path, waitingQuery string, insert func(tx *gorm.DB) error) (int, []byte) {
	t.Helper()
	tx := f.db.Begin()
	if err := insert(tx); err != nil {
		tx.Rollback()
		t.Fatalf("inserting the late reference: %v", err)
	}
	type result struct {
		code int
		body []byte
	}
	done := make(chan result, 1)
	go func() {
		rec := httptest.NewRecorder()
		f.router.ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, path, nil))
		done <- result{rec.Code, rec.Body.Bytes()}
	}()
	deadline := time.Now().Add(15 * time.Second)
	for {
		var waiting int64
		if err := f.db.Raw(
			`SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock' AND query LIKE ?`,
			waitingQuery,
		).Scan(&waiting).Error; err != nil {
			tx.Rollback()
			t.Fatalf("watching for the waiting delete: %v", err)
		}
		if waiting > 0 {
			break
		}
		select {
		case r := <-done:
			tx.Rollback()
			t.Fatalf("the delete finished (%d %s) before it met the late reference", r.code, r.body)
		default:
		}
		if time.Now().After(deadline) {
			tx.Rollback()
			t.Fatal("the delete never waited on the late reference")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := tx.Commit().Error; err != nil {
		t.Fatalf("committing the late reference: %v", err)
	}
	r := <-done
	return r.code, r.body
}

// assertConflict checks that the delete answered one JSON:API 409 with exactly detail.
func assertConflict(t *testing.T, code int, body []byte, detail string) {
	t.Helper()
	if code != http.StatusConflict {
		t.Fatalf("status = %d, want 409 (%s)", code, body)
	}
	var doc struct {
		Errors []struct{ Status, Title, Detail string } `json:"errors"`
	}
	if err := json.Unmarshal(body, &doc); err != nil || len(doc.Errors) != 1 {
		t.Fatalf("decoding the error document %s: %v", body, err)
	}
	if got := doc.Errors[0]; got.Status != "409" || got.Title != "Conflict" || got.Detail != detail {
		t.Errorf("error = %+v, want status 409, title Conflict, detail %q", got, detail)
	}
}

func TestCredentialDelete_UsedByAJobConflicts(t *testing.T) {
	f := setupCredentialDelete(t)
	credID := f.credential(t, "used")
	tmplID := f.template(t)
	job := &models.AnsibleJob{ID: uuid.New(), ProjectID: f.project, PlaybookID: &f.playbook, InventoryID: f.inv, TemplateID: &tmplID, Status: models.AnsibleJobStatusSuccessful}
	if err := f.db.Create(job).Error; err != nil {
		t.Fatalf("seeding the job: %v", err)
	}
	t.Cleanup(func() { f.db.Delete(&models.AnsibleJob{}, "id = ?", job.ID) })
	f.exec(t, "INSERT INTO ansible_job_credentials (ansible_job_id, ansible_credential_id) VALUES (?, ?)", job.ID, credID)
	t.Cleanup(func() { f.db.Exec("DELETE FROM ansible_job_credentials WHERE ansible_job_id = ?", job.ID) })

	code, body := f.deleteCredential(t, credID)
	assertConflict(t, code, body, credentialInUseByJobsDetail)
	if n := f.count(t, "SELECT count(*) FROM ansible_credentials WHERE id = ?", credID); n != 1 {
		t.Errorf("the credential was deleted despite the conflict")
	}
}

func TestCredentialDelete_ReferencedOnlyByATemplateDeletes(t *testing.T) {
	f := setupCredentialDelete(t)
	credID := f.credential(t, "tmpl")
	tmplID := f.template(t)
	f.exec(t, "INSERT INTO ansible_job_template_credentials (ansible_job_template_id, ansible_credential_id) VALUES (?, ?)", tmplID, credID)
	t.Cleanup(func() {
		f.db.Exec("DELETE FROM ansible_job_template_credentials WHERE ansible_job_template_id = ?", tmplID)
	})

	if code, body := f.deleteCredential(t, credID); code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204 (%s)", code, body)
	}
	if n := f.count(t, "SELECT count(*) FROM ansible_credentials WHERE id = ?", credID); n != 0 {
		t.Errorf("the credential survived its delete")
	}
	if n := f.count(t, "SELECT count(*) FROM ansible_job_template_credentials WHERE ansible_job_template_id = ?", tmplID); n != 0 {
		t.Errorf("the template still holds %d link(s) to the deleted credential", n)
	}
	if n := f.count(t, "SELECT count(*) FROM ansible_job_templates WHERE id = ?", tmplID); n != 1 {
		t.Errorf("the template was removed with the credential")
	}
}

// A job template built on an inventory blocks the delete, and the 409 names it.
func TestInventoryDelete_UsedByATemplateConflicts(t *testing.T) {
	f := setupCredentialDelete(t)
	f.template(t)

	code, body := f.delete(t, "/ansible/inventories/"+f.inv.String())
	assertConflict(t, code, body,
		"cannot delete inventory: it is referenced by 1 job template(s). Remove the inventory from those resources first")
	if n := f.count(t, "SELECT count(*) FROM ansible_inventories WHERE id = ?", f.inv); n != 1 {
		t.Errorf("the inventory was deleted despite the conflict")
	}
}

// A job template built on the inventory after the dependency count is refused by its foreign key,
// and the 409 names job templates only.
func TestInventoryDelete_LateTemplateConflicts(t *testing.T) {
	f := setupCredentialDelete(t)
	tmpl := &models.AnsibleJobTemplate{ID: uuid.New(), ProjectID: f.project, PlaybookID: f.playbook, InventoryID: f.inv, Name: "creddel-late-" + f.sfx}
	t.Cleanup(func() { f.db.Delete(&models.AnsibleJobTemplate{}, "id = ?", tmpl.ID) })

	code, body := f.deleteWhileInserting(t, "/ansible/inventories/"+f.inv.String(), `%DELETE FROM "ansible_inventories"%`,
		func(tx *gorm.DB) error { return tx.Create(tmpl).Error })
	assertConflict(t, code, body, inventoryUsedByTemplatesDetail)
	if n := f.count(t, "SELECT count(*) FROM ansible_inventories WHERE id = ?", f.inv); n != 1 {
		t.Errorf("the inventory was deleted despite the conflict")
	}
}

// A job run against the inventory after the dependency count is refused by its foreign key, and
// the 409 names jobs only.
func TestInventoryDelete_LateJobConflicts(t *testing.T) {
	f := setupCredentialDelete(t)
	job := &models.AnsibleJob{ID: uuid.New(), ProjectID: f.project, InventoryID: f.inv, Status: models.AnsibleJobStatusSuccessful}
	t.Cleanup(func() { f.db.Delete(&models.AnsibleJob{}, "id = ?", job.ID) })

	code, body := f.deleteWhileInserting(t, "/ansible/inventories/"+f.inv.String(), `%DELETE FROM "ansible_inventories"%`,
		func(tx *gorm.DB) error { return tx.Create(job).Error })
	assertConflict(t, code, body, inventoryUsedByJobsDetail)
}

// playbookRowLock is the statement a playbook delete waits on while a reference to the playbook is
// being inserted: the row lock it takes before it counts what blocks it.
const playbookRowLock = `%FROM "ansible_playbooks"%FOR UPDATE%`

// A job template built on the playbook while the delete runs is counted: the delete locks the
// playbook row first, which waits for the template's insert, and then counts it, so the 409 is the
// count's. Before the row lock the count missed such a template and its foreign key refused the
// DELETE (playbookUsedByTemplatesDetail); that mapping stays for a reference the lock does not
// cover.
func TestPlaybookDelete_LateTemplateConflicts(t *testing.T) {
	f := setupCredentialDelete(t)
	tmpl := &models.AnsibleJobTemplate{ID: uuid.New(), ProjectID: f.project, PlaybookID: f.playbook, InventoryID: f.inv, Name: "creddel-late-" + f.sfx}
	t.Cleanup(func() { f.db.Delete(&models.AnsibleJobTemplate{}, "id = ?", tmpl.ID) })

	code, body := f.deleteWhileInserting(t, "/ansible/playbooks/"+f.playbook.String(), playbookRowLock,
		func(tx *gorm.DB) error { return tx.Create(tmpl).Error })
	assertConflict(t, code, body,
		"Cannot delete playbook: it is referenced by 1 job template(s). Remove the playbook from those resources first")
	if n := f.count(t, "SELECT count(*) FROM ansible_playbooks WHERE id = ?", f.playbook); n != 1 {
		t.Errorf("the playbook was deleted despite the conflict")
	}
}

// Hosts cascade with the inventory and a workflow's inventory override is nulled, so an inventory
// held only by those deletes.
func TestInventoryDelete_ReferencedOnlyByCascadingAndNulledRowsDeletes(t *testing.T) {
	f := setupCredentialDelete(t)
	host := &models.AnsibleInventoryHost{ID: uuid.New(), InventoryID: f.inv, Name: "creddel-host"}
	if err := f.db.Create(host).Error; err != nil {
		t.Fatalf("seeding the host: %v", err)
	}
	t.Cleanup(func() { f.db.Delete(&models.AnsibleInventoryHost{}, "id = ?", host.ID) })
	workflow := &models.AnsibleWorkflow{ID: uuid.New(), OrganizationID: f.org, ProjectID: f.project, Name: "creddel-wf-" + f.sfx, InventoryID: &f.inv}
	if err := f.db.Create(workflow).Error; err != nil {
		t.Fatalf("seeding the workflow: %v", err)
	}
	t.Cleanup(func() { f.db.Delete(&models.AnsibleWorkflow{}, "id = ?", workflow.ID) })

	if code, body := f.delete(t, "/ansible/inventories/"+f.inv.String()); code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204 (%s)", code, body)
	}
	if n := f.count(t, "SELECT count(*) FROM ansible_inventories WHERE id = ?", f.inv); n != 0 {
		t.Errorf("the inventory survived its delete")
	}
	if n := f.count(t, "SELECT count(*) FROM ansible_inventory_hosts WHERE id = ?", host.ID); n != 0 {
		t.Errorf("the inventory's host survived it")
	}
	if n := f.count(t, "SELECT count(*) FROM ansible_workflows WHERE id = ? AND inventory_id IS NULL", workflow.ID); n != 1 {
		t.Errorf("the workflow was removed, or still names the deleted inventory")
	}
}

// A job template built on a playbook blocks the delete, and the 409 names it. The template's past
// job does not count toward the refusal: the detail names job templates only.
func TestPlaybookDelete_UsedByATemplateConflicts(t *testing.T) {
	f := setupCredentialDelete(t)
	tmplID := f.template(t)
	f.job(t, &tmplID)

	code, body := f.delete(t, "/ansible/playbooks/"+f.playbook.String())
	assertConflict(t, code, body,
		"Cannot delete playbook: it is referenced by 1 job template(s). Remove the playbook from those resources first")
	if n := f.count(t, "SELECT count(*) FROM ansible_playbooks WHERE id = ?", f.playbook); n != 1 {
		t.Errorf("the playbook was deleted despite the conflict")
	}
}

// job creates a finished job that ran the fixture's playbook, launched from tmplID when it is
// not nil, with one output event, the way a launch records the playbook's name. Both rows are
// removed at the end of the test.
func (f *credentialDeleteFixture) job(t *testing.T, tmplID *uuid.UUID) *models.AnsibleJob {
	t.Helper()
	return f.jobIn(t, tmplID, models.AnsibleJobStatusSuccessful)
}

// jobIn is job with the given status.
func (f *credentialDeleteFixture) jobIn(t *testing.T, tmplID *uuid.UUID, status models.AnsibleJobStatus) *models.AnsibleJob {
	t.Helper()
	job := &models.AnsibleJob{
		ID: uuid.New(), ProjectID: f.project, PlaybookID: &f.playbook, PlaybookName: "creddel-pb-" + f.sfx,
		InventoryID: f.inv, TemplateID: tmplID, Name: "creddel-job-" + f.sfx,
		Status: status, HostsTotal: 2, HostsOk: 2,
	}
	if err := f.db.Create(job).Error; err != nil {
		t.Fatalf("seeding the job: %v", err)
	}
	t.Cleanup(func() { f.db.Delete(&models.AnsibleJob{}, "id = ?", job.ID) })
	event := &models.AnsibleJobEvent{ID: uuid.New(), JobID: job.ID, Counter: 1, Event: "runner_on_ok", Host: "web-01", Stdout: "ok: [web-01]"}
	if err := f.db.Create(event).Error; err != nil {
		t.Fatalf("seeding the job event: %v", err)
	}
	t.Cleanup(func() { f.db.Delete(&models.AnsibleJobEvent{}, "id = ?", event.ID) })
	return job
}

// A playbook that only past jobs ran deletes. The jobs keep their row, results, events and the
// playbook name they recorded, with the playbook link cleared, and stay readable through the API.
// A relaunch of such a job is refused with a 409, since there is no playbook left to run.
func TestPlaybookDelete_RanOnlyByPastJobsDeletes(t *testing.T) {
	f := setupCredentialDelete(t)
	job := f.job(t, nil)

	if code, body := f.delete(t, "/ansible/playbooks/"+f.playbook.String()); code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204 (%s)", code, body)
	}
	if n := f.count(t, "SELECT count(*) FROM ansible_playbooks WHERE id = ?", f.playbook); n != 0 {
		t.Errorf("the playbook survived its delete")
	}
	if n := f.count(t,
		"SELECT count(*) FROM ansible_jobs WHERE id = ? AND playbook_id IS NULL AND playbook_name = ? AND status = ? AND hosts_ok = 2",
		job.ID, job.PlaybookName, models.AnsibleJobStatusSuccessful); n != 1 {
		t.Errorf("the job was removed, still names the deleted playbook, or lost its recorded name or results")
	}
	if n := f.count(t, "SELECT count(*) FROM ansible_job_events WHERE job_id = ?", job.ID); n != 1 {
		t.Errorf("the job has %d event(s) after the playbook delete, want 1", n)
	}

	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ansible/jobs/"+job.ID.String(), nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("reading the job: status = %d, want 200 (%s)", rec.Code, rec.Body.Bytes())
	}
	var doc struct {
		Data struct {
			Attributes    map[string]any            `json:"attributes"`
			Relationships map[string]map[string]any `json:"relationships"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("decoding the job %s: %v", rec.Body.Bytes(), err)
	}
	if got := doc.Data.Attributes["playbook-name"]; got != job.PlaybookName {
		t.Errorf("playbook-name = %v, want %q", got, job.PlaybookName)
	}
	if got := doc.Data.Attributes["status"]; got != string(models.AnsibleJobStatusSuccessful) {
		t.Errorf("status = %v, want successful", got)
	}
	if _, ok := doc.Data.Relationships["playbook"]; ok {
		t.Errorf("the job still has a playbook relationship: %v", doc.Data.Relationships["playbook"])
	}

	rec = httptest.NewRecorder()
	f.router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/ansible/jobs/"+job.ID.String()+"/actions/relaunch", nil))
	assertConflict(t, rec.Code, rec.Body.Bytes(), jobPlaybookDeletedDetail)
}

// A force delete removes the playbook's templates with the jobs they launched, as a template
// delete does, and keeps the jobs that ran the playbook directly with the link cleared.
func TestPlaybookForceDelete_KeepsJobsThatRanThePlaybookDirectly(t *testing.T) {
	f := setupCredentialDelete(t)
	tmplID := f.template(t)
	fromTemplate := f.job(t, &tmplID)
	direct := f.job(t, nil)

	if code, body := f.delete(t, "/ansible/playbooks/"+f.playbook.String()+"?force=true"); code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204 (%s)", code, body)
	}
	if n := f.count(t, "SELECT count(*) FROM ansible_jobs WHERE id = ?", fromTemplate.ID); n != 0 {
		t.Errorf("the template's job survived the force delete")
	}
	if n := f.count(t, "SELECT count(*) FROM ansible_jobs WHERE id = ? AND playbook_id IS NULL AND playbook_name = ?", direct.ID, direct.PlaybookName); n != 1 {
		t.Errorf("the job that ran the playbook directly was removed, or still names the playbook")
	}
	if n := f.count(t, "SELECT count(*) FROM ansible_job_events WHERE job_id = ?", direct.ID); n != 1 {
		t.Errorf("the kept job has %d event(s), want 1", n)
	}
}

// A schedule that syncs a playbook keeps its row with the playbook link cleared, so a playbook held
// only by such a schedule deletes.
func TestPlaybookDelete_ReferencedOnlyByANulledScheduleDeletes(t *testing.T) {
	f := setupCredentialDelete(t)
	schedule := &models.AnsibleSchedule{
		ID: uuid.New(), OrganizationID: f.org, Name: "creddel-sched-" + f.sfx, Type: models.ScheduleTypePlaybookSync,
		PlaybookID: &f.playbook, CronExpression: "0 2 * * *", Timezone: "UTC",
	}
	if err := f.db.Create(schedule).Error; err != nil {
		t.Fatalf("seeding the schedule: %v", err)
	}
	t.Cleanup(func() { f.db.Delete(&models.AnsibleSchedule{}, "id = ?", schedule.ID) })

	if code, body := f.delete(t, "/ansible/playbooks/"+f.playbook.String()); code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204 (%s)", code, body)
	}
	if n := f.count(t, "SELECT count(*) FROM ansible_playbooks WHERE id = ?", f.playbook); n != 0 {
		t.Errorf("the playbook survived its delete")
	}
	if n := f.count(t, "SELECT count(*) FROM ansible_schedules WHERE id = ? AND playbook_id IS NULL", schedule.ID); n != 1 {
		t.Errorf("the schedule was removed, or still names the deleted playbook")
	}
}
