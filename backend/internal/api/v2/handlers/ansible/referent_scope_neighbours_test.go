// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// What a job launch may name (#915): credentials of the job's own organization. Anything else is
// a 400 in the JSON:API errors document, and a credential that exists in another organization
// gets the very same bytes as an identifier that names nothing, so the answer never confirms
// that the row is there. It is the rule schedules (#884) and workflows (#905) already follow;
// this file also holds the fixture and the assertions its neighbours share
// (job_template_referent_scope_test.go, inventory_source_referent_scope_test.go).
//
// The defect this test was written against: a job launch attached whatever credentials the body
// named to the job. The permission check it makes is about the project, and nothing asked which
// organization a credential belongs to. A runner decrypts a job's credentials by identifier, so
// a member of one organization could run a playbook of their own with another organization's
// keys. A template launch and a relaunch copied a stored set onto the new job the same way.
//
// Every request is sent by a member of the first organization who has no part in the second.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Cleanup is strictly
// row-scoped (the database may be live). Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/ansible/ -run 'TestJobLaunchReferents|TestJobTemplateReferents|TestInventorySourceReferents'

//go:build integration

package ansible

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/dbtest"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	ansiblesvc "github.com/michielvha/stackweaver/core/services/ansible"
	"gorm.io/gorm"
)

// neighbourScopeFixture is two organizations that each own one of everything a job launch, a job
// template and an inventory source can name, and one caller: an owner of the first organization
// with no part in the second.
type neighbourScopeFixture struct {
	router *gin.Engine
	db     *gorm.DB
	member uuid.UUID

	orgName   string
	projectID uuid.UUID
	inventory uuid.UUID
	template  uuid.UUID // of the first organization, naming its playbook and inventory
	source    uuid.UUID // an AWS inventory source of the first organization's inventory

	// What the first organization owns.
	project, playbook, playbook2, inventoryID, inventory2, sshCred, awsCred, vaultCred string

	// What the second organization owns. Every one is a real row.
	otherOrgID                                                                 uuid.UUID
	otherProject, otherPlaybook, otherInventory, otherSSH, otherAWS, otherPool string
	otherCredentialIDs                                                         []uuid.UUID
}

func setupNeighbourScope(t *testing.T) *neighbourScopeFixture {
	t.Helper()
	dbURL := os.Getenv("TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping integration test")
	}
	db, err := dbtest.Open(t, dbURL, &gorm.Config{})
	if err != nil {
		t.Fatalf("connecting to the test database: %v", err)
	}
	if err := db.AutoMigrate(
		&models.User{}, &models.Organization{}, &models.OrganizationMember{},
		&models.Team{}, &models.TeamMember{}, &models.TeamOrganizationAccess{}, &models.TeamProjectAccess{},
		&models.Project{}, &models.AgentPool{}, &models.AnsibleInventory{}, &models.AnsibleInventorySource{},
		&models.AnsibleCredential{}, &models.AnsiblePlaybook{}, &models.AnsibleJobTemplate{}, &models.AnsibleJob{},
	); err != nil {
		t.Fatalf("migrating the tables: %v", err)
	}
	sfx := uuid.NewString()[:8]

	orgA := &models.Organization{ID: uuid.New(), Name: "nbref-a-" + sfx}
	orgB := &models.Organization{ID: uuid.New(), Name: "nbref-b-" + sfx}
	member := &models.User{ID: uuid.New(), ZitadelSubject: "nbref-mem-" + sfx, Email: "nbref-mem-" + sfx + "@test.local"}
	teamA := &models.Team{ID: uuid.New(), OrganizationID: orgA.ID, Name: "owners"}
	projA := &models.Project{ID: uuid.New(), OrganizationID: orgA.ID, Name: "nbref-proj-" + sfx}
	projB := &models.Project{ID: uuid.New(), OrganizationID: orgB.ID, Name: "nbref-proj-" + sfx}
	poolB := &models.AgentPool{ID: uuid.New(), OrganizationID: orgB.ID, Name: "nbref-pool-" + sfx, OrganizationScoped: true}

	inventory := func(org uuid.UUID, name string) *models.AnsibleInventory {
		return &models.AnsibleInventory{ID: uuid.New(), OrganizationID: org, Name: name + sfx, Type: models.InventoryTypeStatic}
	}
	credential := func(org uuid.UUID, name string, credType models.CredentialType) *models.AnsibleCredential {
		return &models.AnsibleCredential{ID: uuid.New(), OrganizationID: org, Name: name + sfx, Type: credType}
	}
	playbook := func(project uuid.UUID, name string) *models.AnsiblePlaybook {
		return &models.AnsiblePlaybook{ID: uuid.New(), ProjectID: project, Name: name + sfx, PlaybookPath: "site.yml", SourceMode: "cached"}
	}
	invA, invA2, invB := inventory(orgA.ID, "nbref-inv-"), inventory(orgA.ID, "nbref-inv2-"), inventory(orgB.ID, "nbref-inv-")
	pbA, pbA2, pbB := playbook(projA.ID, "nbref-pb-"), playbook(projA.ID, "nbref-pb2-"), playbook(projB.ID, "nbref-pb-")
	sshA, awsA := credential(orgA.ID, "nbref-ssh-", models.CredentialTypeSSH), credential(orgA.ID, "nbref-aws-", models.CredentialTypeAWSAccessKey)
	vaultA := credential(orgA.ID, "nbref-vault-", models.CredentialTypeVault)
	sshB, awsB := credential(orgB.ID, "nbref-ssh-", models.CredentialTypeSSH), credential(orgB.ID, "nbref-aws-", models.CredentialTypeAWSAccessKey)
	// Simultaneous runs are allowed so that one launch's pending job does not hold the next.
	tmplA := &models.AnsibleJobTemplate{
		ID: uuid.New(), ProjectID: projA.ID, PlaybookID: pbA.ID, InventoryID: invA.ID,
		Name: "nbref-tmpl-" + sfx, AllowSimultaneous: true,
	}
	sourceA := &models.AnsibleInventorySource{ID: uuid.New(), InventoryID: invA.ID, Name: "nbref-src-" + sfx, Type: models.InventorySourceTypeAWS}

	adminAccess := "admin"
	for _, row := range []any{
		orgA, orgB, member, teamA, projA, projB, poolB,
		&models.OrganizationMember{ID: uuid.New(), OrganizationID: orgA.ID, UserID: member.ID},
		&models.TeamMember{ID: uuid.New(), TeamID: teamA.ID, UserID: member.ID},
		&models.TeamProjectAccess{ID: uuid.New(), TeamID: teamA.ID, ProjectID: projA.ID, Access: &adminAccess},
		invA, invA2, invB, pbA, pbA2, pbB, sshA, awsA, vaultA, sshB, awsB, tmplA, sourceA,
	} {
		if err := db.Create(row).Error; err != nil {
			t.Fatalf("seeding %T: %v", row, err)
		}
	}

	orgIDs := []uuid.UUID{orgA.ID, orgB.ID}
	projectIDs := []uuid.UUID{projA.ID, projB.ID}
	inventoryIDs := []uuid.UUID{invA.ID, invA2.ID, invB.ID}
	t.Cleanup(func() {
		// Children before parents (foreign-key order), every statement scoped to this run's rows.
		// The two join tables go with their parents: jobs and templates of the two projects.
		jobIDs := db.Model(&models.AnsibleJob{}).Select("id").Where("project_id IN ?", projectIDs)
		templateIDs := db.Model(&models.AnsibleJobTemplate{}).Select("id").Where("project_id IN ?", projectIDs)
		db.Exec("DELETE FROM ansible_job_credentials WHERE ansible_job_id IN (?)", jobIDs)
		db.Where("project_id IN ?", projectIDs).Delete(&models.AnsibleJob{})
		db.Exec("DELETE FROM ansible_job_template_credentials WHERE ansible_job_template_id IN (?)", templateIDs)
		db.Where("project_id IN ?", projectIDs).Delete(&models.AnsibleJobTemplate{})
		db.Where("inventory_id IN ?", inventoryIDs).Delete(&models.AnsibleInventorySource{})
		db.Where("project_id IN ?", projectIDs).Delete(&models.AnsiblePlaybook{})
		db.Where("organization_id IN ?", orgIDs).Delete(&models.AnsibleCredential{})
		db.Where("id IN ?", inventoryIDs).Delete(&models.AnsibleInventory{})
		db.Where("id = ?", poolB.ID).Delete(&models.AgentPool{})
		db.Where("team_id = ?", teamA.ID).Delete(&models.TeamProjectAccess{})
		db.Where("team_id = ?", teamA.ID).Delete(&models.TeamMember{})
		db.Where("id = ?", teamA.ID).Delete(&models.Team{})
		db.Where("id IN ?", projectIDs).Delete(&models.Project{})
		db.Where("organization_id IN ?", orgIDs).Delete(&models.OrganizationMember{})
		db.Where("id IN ?", orgIDs).Delete(&models.Organization{})
		db.Where("id = ?", member.ID).Delete(&models.User{})
	})

	orgRepo := repository.NewOrganizationRepository(db)
	projectRepo := repository.NewProjectRepository(db)
	playbookRepo := repository.NewAnsiblePlaybookRepository(db)
	inventoryRepo := repository.NewAnsibleInventoryRepository(db)
	templateRepo := repository.NewAnsibleJobTemplateRepository(db)
	credentialRepo := repository.NewAnsibleCredentialRepository(db)
	jobRepo := repository.NewAnsibleJobRepository(db)
	authService := auth.NewService(repository.NewUserRepository(db))
	rbacService := rbac.NewServiceWithTeams(orgRepo, repository.NewTeamRepository(db), projectRepo)
	// No queue: a launch stores the job and dispatches nothing.
	jobService := ansiblesvc.NewJobService(jobRepo, playbookRepo, inventoryRepo, templateRepo, projectRepo, nil)

	jobs := NewJobHandler(jobService, projectRepo, orgRepo, templateRepo, authService, rbacService)
	templates := NewPlaybookHandler(
		playbookRepo, templateRepo, jobRepo, repository.NewAnsibleScheduleRepository(db), projectRepo, orgRepo,
		authService, rbacService, nil, nil, repository.NewVCSConnectionRepository(db), jobService,
	)
	templates.SetCredentialRepo(credentialRepo)
	templates.SetAgentPoolRepo(repository.NewAgentPoolRepository(db))
	sources := NewInventorySourceHandler(
		ansiblesvc.NewInventorySourceService(repository.NewAnsibleInventorySourceRepository(db), inventoryRepo, credentialRepo, nil),
		ansiblesvc.NewInventoryService(inventoryRepo, orgRepo), authService, rbacService, nil,
	)

	adHoc := NewAdHocHandler(
		inventoryRepo, orgRepo, credentialRepo, projectRepo, repository.NewAgentPoolRepository(db),
		jobService, authService, rbacService,
	)

	router := storedAsSentRouter()
	router.POST("/api/v2/ansible/inventories/:id/actions/run-command", adHoc.RunCommand)
	router.POST("/api/v2/organizations/:name/ansible/jobs", jobs.LaunchByOrganization)
	router.POST("/api/v2/ansible/job-templates/:id/launch", jobs.LaunchFromTemplate)
	router.POST("/api/v2/ansible/jobs/:id/actions/relaunch", jobs.Relaunch)
	router.POST("/api/v2/organizations/:name/ansible/job-templates", templates.CreateTemplateByOrganization)
	router.PATCH("/api/v2/ansible/job-templates/:id", templates.UpdateTemplate)
	router.POST("/api/v2/ansible/job-templates/:id/credentials", templates.AttachTemplateCredential)
	router.POST("/api/v2/ansible/inventories/:id/sources", sources.Create)
	router.PATCH("/api/v2/ansible/inventory-sources/:source_id", sources.Update)

	return &neighbourScopeFixture{
		router: router, db: db, member: member.ID,
		orgName: orgA.Name, projectID: projA.ID, inventory: invA.ID, template: tmplA.ID, source: sourceA.ID,
		project: projA.ID.String(), playbook: pbA.ID.String(), playbook2: pbA2.ID.String(),
		inventoryID: invA.ID.String(), inventory2: invA2.ID.String(),
		sshCred: sshA.ID.String(), awsCred: awsA.ID.String(), vaultCred: vaultA.ID.String(),
		otherOrgID:   orgB.ID,
		otherProject: projB.ID.String(), otherPlaybook: pbB.ID.String(), otherInventory: invB.ID.String(),
		otherSSH: sshB.ID.String(), otherAWS: awsB.ID.String(), otherPool: poolB.ID.String(),
		otherCredentialIDs: []uuid.UUID{sshB.ID, awsB.ID},
	}
}

func (f *neighbourScopeFixture) call(t *testing.T, method, path, body string) (int, []byte) {
	t.Helper()
	return storedAsSentCall(t, f.router, method, path, f.member, body)
}

func (f *neighbourScopeFixture) exec(t *testing.T, query string, args ...any) {
	t.Helper()
	if err := f.db.Exec(query, args...).Error; err != nil {
		t.Fatalf("writing a row directly (%q): %v", query, err)
	}
}

// rows counts through a raw statement, which is how the two credential join tables are read.
func (f *neighbourScopeFixture) rows(t *testing.T, query string, args ...any) int64 {
	t.Helper()
	var n int64
	if err := f.db.Raw(query, args...).Scan(&n).Error; err != nil {
		t.Fatalf("counting with %q: %v", query, err)
	}
	return n
}

// storedRows is everything a refused write could have left behind in the first organization, and
// every place a credential of the second could have been attached.
type storedRows struct {
	jobs, templates, sources, foreignOnJobs, foreignOnTemplates, foreignOnSources int64
}

func (f *neighbourScopeFixture) stored(t *testing.T) storedRows {
	t.Helper()
	return storedRows{
		jobs:               f.rows(t, "SELECT count(*) FROM ansible_jobs WHERE project_id = ?", f.projectID),
		templates:          f.rows(t, "SELECT count(*) FROM ansible_job_templates WHERE project_id = ?", f.projectID),
		sources:            f.rows(t, "SELECT count(*) FROM ansible_inventory_sources WHERE inventory_id = ?", f.inventory),
		foreignOnJobs:      f.rows(t, "SELECT count(*) FROM ansible_job_credentials WHERE ansible_credential_id IN ?", f.otherCredentialIDs),
		foreignOnTemplates: f.rows(t, "SELECT count(*) FROM ansible_job_template_credentials WHERE ansible_credential_id IN ?", f.otherCredentialIDs),
		foreignOnSources:   f.rows(t, "SELECT count(*) FROM ansible_inventory_sources WHERE credential_id IN ?", f.otherCredentialIDs),
	}
}

// credentialsOf reads one of the two credential join tables for one parent row.
func (f *neighbourScopeFixture) credentialsOf(t *testing.T, table, column, id string) []string {
	t.Helper()
	var ids []string
	if err := f.db.Raw("SELECT ansible_credential_id FROM "+table+" WHERE "+column+" = ? ORDER BY ansible_credential_id", id).Scan(&ids).Error; err != nil {
		t.Fatalf("reading %s: %v", table, err)
	}
	return ids
}

// own is the relationships of a launch or a template document that name the first
// organization's rows, with one of them replaced when relationship is not empty.
func (f *neighbourScopeFixture) own(relationship, id string) map[string]string {
	relationships := map[string]string{"project": f.project, "playbook": f.playbook, "inventory": f.inventoryID}
	if relationship != "" {
		relationships[relationship] = id
	}
	return relationships
}

func neighbourName() map[string]any {
	return map[string]any{"name": "nbref-" + uuid.NewString()[:8]}
}

// neighbourDocument is a JSON:API request document. A to-one relationship is given as its
// identifier; credentials, when not nil, is the to-many `credentials` relationship.
func neighbourDocument(t *testing.T, resourceType string, attrs map[string]any, toOne map[string]string, credentials []string) string {
	t.Helper()
	relationships := map[string]any{}
	for name, id := range toOne {
		relationships[name] = map[string]any{"data": map[string]any{"id": id}}
	}
	if credentials != nil {
		refs := make([]map[string]any, 0, len(credentials))
		for _, id := range credentials {
			refs = append(refs, map[string]any{"id": id, "type": "ansible-credentials"})
		}
		relationships["credentials"] = map[string]any{"data": refs}
	}
	raw, err := json.Marshal(map[string]any{"data": map[string]any{
		"type": resourceType, "attributes": attrs, "relationships": relationships,
	}})
	if err != nil {
		t.Fatalf("marshalling the request document: %v", err)
	}
	return string(raw)
}

// neighbourWrite is one write that names a row: how to send it naming the given identifier, a
// real row of the second organization, and the sentence the refusal carries.
type neighbourWrite struct {
	name    string
	send    func(t *testing.T, id string) (int, []byte)
	foreign string
	detail  string
}

// assertReadAsNotFound sends each write twice, once naming a real row of the second organization
// and once naming nothing, and requires the same 400 for both and nothing stored by either.
func (f *neighbourScopeFixture) assertReadAsNotFound(t *testing.T, writes []neighbourWrite) {
	t.Helper()
	for _, w := range writes {
		t.Run(w.name+" of another organization", func(t *testing.T) {
			stored := f.stored(t)

			code, body := w.send(t, w.foreign)
			assertBadRequest(t, code, body, w.detail)

			// The same request naming nothing at all: the two answers must not differ by a byte,
			// or the difference tells the caller that the first identifier is a real row.
			missingCode, missingBody := w.send(t, uuid.NewString())
			assertBadRequest(t, missingCode, missingBody, w.detail)
			if code != missingCode || !bytes.Equal(body, missingBody) {
				t.Errorf("a row of another organization and a row that does not exist are answered differently:\n  other organization: %d %s\n  does not exist:     %d %s",
					code, body, missingCode, missingBody)
			}

			if after := f.stored(t); after != stored {
				t.Errorf("the refused requests changed what is stored:\n  before %+v\n  after  %+v", stored, after)
			}
		})
	}
}

// assertOneAnswer is assertReadAsNotFound for a write that was never exposed: it requires a
// refusal, the same bytes for the two identifiers and nothing stored, whatever the status and
// the sentence are. It turns a neighbour the survey read as safe into one a test holds safe.
func (f *neighbourScopeFixture) assertOneAnswer(t *testing.T, writes []neighbourWrite) {
	t.Helper()
	for _, w := range writes {
		t.Run(w.name+" of another organization", func(t *testing.T) {
			stored := f.stored(t)
			code, body := w.send(t, w.foreign)
			missingCode, missingBody := w.send(t, uuid.NewString())
			if code < 400 {
				t.Errorf("status = %d, want a refusal (%s)", code, body)
			}
			if code != missingCode || !bytes.Equal(body, missingBody) {
				t.Errorf("a row of another organization and a row that does not exist are answered differently:\n  other organization: %d %s\n  does not exist:     %d %s",
					code, body, missingCode, missingBody)
			}
			if after := f.stored(t); after != stored {
				t.Errorf("the refused requests changed what is stored:\n  before %+v\n  after  %+v", stored, after)
			}
		})
	}
}

// assertNotLaunched posts to a launch path with no body and requires that nothing was started:
// a refusal, no new job, no credential of the second organization on any job, and no row of the
// second organization named in the answer.
func (f *neighbourScopeFixture) assertNotLaunched(t *testing.T, path string) {
	t.Helper()
	stored := f.stored(t)
	code, body := f.call(t, http.MethodPost, path, "")
	if code < 400 {
		t.Errorf("status = %d, want a refusal (%s)", code, body)
	}
	for _, id := range []string{f.otherSSH, f.otherAWS, f.otherInventory, f.otherPlaybook} {
		if bytes.Contains(body, []byte(id)) {
			t.Errorf("the refusal names a row of the other organization: %s", body)
		}
	}
	if after := f.stored(t); after != stored {
		t.Errorf("the refused launch changed what is stored:\n  before %+v\n  after  %+v", stored, after)
	}
}

func (f *neighbourScopeFixture) launchWrites() (orgJobs string, credentials []neighbourWrite) {
	orgJobs = "/api/v2/organizations/" + f.orgName + "/ansible/jobs"
	launchWith := func(path string) func(t *testing.T, id string) (int, []byte) {
		return func(t *testing.T, id string) (int, []byte) {
			t.Helper()
			return f.call(t, http.MethodPost, path, neighbourDocument(t, "ansible-jobs", neighbourName(), f.own("", ""), []string{id}))
		}
	}
	return orgJobs, []neighbourWrite{
		{"a job launch naming a credential", launchWith(orgJobs), f.otherSSH, "credential not found"},
	}
}

func TestJobLaunchReferents_AnotherOrganizationReadsAsNotFound(t *testing.T) {
	f := setupNeighbourScope(t)
	_, credentials := f.launchWrites()
	f.assertReadAsNotFound(t, credentials)
}

func TestJobLaunchReferents_OwnOrganizationIsAccepted(t *testing.T) {
	f := setupNeighbourScope(t)
	orgJobs, _ := f.launchWrites()
	for name, path := range map[string]string{"a job launch": orgJobs} {
		t.Run(name+" with its organization's credentials", func(t *testing.T) {
			code, body := f.call(t, http.MethodPost, path,
				neighbourDocument(t, "ansible-jobs", neighbourName(), f.own("", ""), []string{f.sshCred, f.vaultCred}))
			created := createdResource(t, code, body)
			if got := f.credentialsOf(t, "ansible_job_credentials", "ansible_job_id", created.ID); len(got) != 2 {
				t.Errorf("the job runs with credentials %v, want the ssh and the vault credential", got)
			}
		})
	}
}

// TestJobLaunchReferents_StoredCredentialsAreNotTrusted is the point of use over HTTP. Each
// credential set is written directly, the way one stored before the launch checked would be, and
// then used through the API: a template launch and a relaunch copy a stored set onto a new job,
// and neither may copy a credential of another organization.
func TestJobLaunchReferents_StoredCredentialsAreNotTrusted(t *testing.T) {
	f := setupNeighbourScope(t)
	launch := "/api/v2/ansible/job-templates/" + f.template.String() + "/launch"

	t.Run("a template holding a credential of another organization is not launched", func(t *testing.T) {
		f.exec(t, "INSERT INTO ansible_job_template_credentials (ansible_job_template_id, ansible_credential_id) VALUES (?, ?)", f.template, f.otherSSH)
		// Put back whatever the case finds, so the next one starts from a clean template.
		defer f.exec(t, "DELETE FROM ansible_job_template_credentials WHERE ansible_job_template_id = ?", f.template)
		f.assertNotLaunched(t, launch)
	})
	t.Run("a template holding its organization's credential is launched with it", func(t *testing.T) {
		f.exec(t, "INSERT INTO ansible_job_template_credentials (ansible_job_template_id, ansible_credential_id) VALUES (?, ?)", f.template, f.sshCred)
		defer f.exec(t, "DELETE FROM ansible_job_template_credentials WHERE ansible_job_template_id = ?", f.template)
		code, body := f.call(t, http.MethodPost, launch, "")
		created := createdResource(t, code, body)
		if got := f.credentialsOf(t, "ansible_job_credentials", "ansible_job_id", created.ID); len(got) != 1 || got[0] != f.sshCred {
			t.Errorf("the job runs with credentials %v, want [%s]", got, f.sshCred)
		}
	})
	t.Run("a job holding a credential of another organization is not relaunched", func(t *testing.T) {
		playbook := uuid.MustParse(f.playbook)
		job := &models.AnsibleJob{
			ID: uuid.New(), ProjectID: f.projectID, PlaybookID: &playbook, InventoryID: f.inventory,
			Name: "nbref-stored-" + uuid.NewString()[:8], JobType: models.AnsibleJobTypeRun, Status: models.AnsibleJobStatusSuccessful,
		}
		if err := f.db.Create(job).Error; err != nil {
			t.Fatalf("inserting the job row: %v", err)
		}
		f.exec(t, "INSERT INTO ansible_job_credentials (ansible_job_id, ansible_credential_id) VALUES (?, ?)", job.ID, f.otherSSH)
		f.assertNotLaunched(t, "/api/v2/ansible/jobs/"+job.ID.String()+"/actions/relaunch")
	})
}

// runCommandNaming sends a Run Command against the first organization's inventory with one
// attribute of its body set to the given identifier.
func (f *neighbourScopeFixture) runCommandNaming(attribute string) func(t *testing.T, id string) (int, []byte) {
	return func(t *testing.T, id string) (int, []byte) {
		t.Helper()
		attrs := map[string]any{"module": "ping", "project-id": f.project}
		attrs[attribute] = id
		return f.call(t, http.MethodPost, "/api/v2/ansible/inventories/"+f.inventoryID+"/actions/run-command",
			neighbourDocument(t, "ansible-jobs", attrs, nil, nil))
	}
}

// TestAdHocReferents_ProjectReadsAsNotFound pins the project Run Command names in its body
// (#916). Nothing was ever stored for another organization's project, but the permission check
// answered it 403 and failed with a 500 on an identifier that names nothing, so the two told a
// caller which project identifiers are real. The project is now held to the inventory's
// organization before the permission check, with one answer.
func TestAdHocReferents_ProjectReadsAsNotFound(t *testing.T) {
	f := setupNeighbourScope(t)
	f.assertReadAsNotFound(t, []neighbourWrite{
		{name: "a command naming a project", send: f.runCommandNaming("project-id"), foreign: f.otherProject, detail: "Project not found in this organization"},
	})

	// The same command under a project of the inventory's own organization is launched.
	code, body := f.runCommandNaming("project-id")(t, f.project)
	if code != http.StatusCreated {
		t.Errorf("a command naming a project of its own organization: %d %s, want 201", code, body)
	}
}

// TestAdHocReferents_AlreadyOneAnswer pins the credential and the agent pool Run Command names
// in its body. The handler already held both to the inventory's organization with one answer.
func TestAdHocReferents_AlreadyOneAnswer(t *testing.T) {
	f := setupNeighbourScope(t)
	f.assertOneAnswer(t, []neighbourWrite{
		{name: "a command naming a credential", send: f.runCommandNaming("credential-id"), foreign: f.otherSSH},
		{name: "a command naming an agent pool", send: f.runCommandNaming("agent-pool-id"), foreign: f.otherPool},
	})
}

// TestJobLaunchReferents_AlreadyOneAnswer pins what a launch names beside its credentials. Each
// already answered another organization's row and an unknown identifier with the same bytes and
// stored nothing.
func TestJobLaunchReferents_AlreadyOneAnswer(t *testing.T) {
	f := setupNeighbourScope(t)
	orgJobs, _ := f.launchWrites()
	launchNaming := func(relationship string) func(t *testing.T, id string) (int, []byte) {
		return func(t *testing.T, id string) (int, []byte) {
			t.Helper()
			return f.call(t, http.MethodPost, orgJobs, neighbourDocument(t, "ansible-jobs", neighbourName(), f.own(relationship, id), nil))
		}
	}
	f.assertOneAnswer(t, []neighbourWrite{
		{name: "a job launch naming a project", send: launchNaming("project"), foreign: f.otherProject},
		{name: "a job launch naming a playbook", send: launchNaming("playbook"), foreign: f.otherPlaybook},
		{name: "a job launch naming an inventory", send: launchNaming("inventory"), foreign: f.otherInventory},
	})
}
