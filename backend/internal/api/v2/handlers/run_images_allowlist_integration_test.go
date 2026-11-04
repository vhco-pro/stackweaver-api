// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Integration tests for run images (#933, D6, AC29, AC27): a run image is saved and a job starts
// with it only from a registry images.allowed_registries lists, any registry when it is empty; a
// run's job token names the image its level rule resolves, with the level it came from.
//
//	go test -tags integration ./internal/api/v2/handlers/ -run TestRunImages

//go:build integration

package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
)

func TestRunImages_SaveRefusesARegistryOutsideTheAllowlist(t *testing.T) {
	f := setupPlatformAdminFixture(t)
	t.Cleanup(func() { f.db.Where("organization_id = ?", f.orgA.ID).Delete(&models.RunImage{}) })
	orgs := repository.NewOrganizationRepository(f.db)
	h := NewRunImageHandler(f.db, orgs, f.authSvc, rbac.NewServiceWithTeams(orgs, repository.NewTeamRepository(f.db), repository.NewProjectRepository(f.db)))
	r := platformAdminRouter()
	r.POST("/api/v2/organizations/:name/run-images", h.Create)
	r.PATCH("/api/v2/run-images/:id", h.Update)
	r.GET("/api/v2/organizations/:name/run-images", h.List)
	create := func(attrs string) (int, string) {
		rec := platformAdminCall(t, r, http.MethodPost, "/api/v2/organizations/"+f.orgA.Name+"/run-images", browserAs(f.owner), `{"data":{"type":"run-images","attributes":`+attrs+`}}`)
		return rec.Code, rec.Body.String()
	}

	// Empty: any registry.
	if code, body := create(`{"name":"anywhere","kind":"tofu","image":"quay.io/acme/tofu-aws:1.10"}`); code != http.StatusCreated {
		t.Fatalf("an empty allowlist refused a run image: %d %s", code, body)
	}

	h.allowed = []string{"ghcr.io/acme"}
	code, body := create(`{"name":"outside","kind":"tofu","image":"docker.io/library/alpine:3"}`)
	if code != http.StatusUnprocessableEntity || !strings.Contains(body, "images.allowed_registries") {
		t.Fatalf("a registry outside the allowlist = %d %s, want 422 naming the setting", code, body)
	}
	code, body = create(`{"name":"inside","kind":"ansible","image":"ghcr.io/acme/ee:24","digest":"sha256:` + strings.Repeat("ab", 32) + `"}`)
	if code != http.StatusCreated {
		t.Fatalf("a listed registry = %d %s", code, body)
	}
	var doc struct {
		Data struct {
			ID         string         `json:"id"`
			Attributes map[string]any `json:"attributes"`
		} `json:"data"`
	}
	_ = json.Unmarshal([]byte(body), &doc)
	if doc.Data.Attributes["image"] != "ghcr.io/acme/ee:24" || doc.Data.Attributes["kind"] != "ansible" {
		t.Errorf("created = %v", doc.Data.Attributes)
	}
	// Moving an image outside the list is refused the same way.
	rec := platformAdminCall(t, r, http.MethodPatch, "/api/v2/run-images/"+doc.Data.ID, browserAs(f.owner), `{"data":{"type":"run-images","attributes":{"image":"docker.io/library/alpine:3"}}}`)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("an update outside the allowlist = %d %s", rec.Code, rec.Body.String())
	}
	for _, bad := range []string{
		`{"name":"x","kind":"terraform","image":"ghcr.io/acme/x"}`,
		`{"name":"x","kind":"tofu","image":"--privileged"}`,
		`{"name":"x","kind":"tofu","image":"ghcr.io/acme/x","digest":"md5:abc"}`,
	} {
		if code, body := create(bad); code != http.StatusUnprocessableEntity {
			t.Errorf("%s = %d %s, want 422", bad, code, body)
		}
	}
	// A member reads, but does not write.
	if rec := platformAdminCall(t, r, http.MethodGet, "/api/v2/organizations/"+f.orgA.Name+"/run-images", browserAs(f.member), ""); rec.Code != http.StatusOK {
		t.Errorf("a member listing run images = %d", rec.Code)
	}
	if rec := platformAdminCall(t, r, http.MethodPost, "/api/v2/organizations/"+f.orgA.Name+"/run-images", browserAs(f.member), `{"data":{"type":"run-images","attributes":{"name":"m","kind":"tofu","image":"ghcr.io/acme/x"}}}`); rec.Code != http.StatusForbidden {
		t.Errorf("a member creating a run image = %d, want 403", rec.Code)
	}
}

func TestRunImages_JobStartRefusesAnImageOutsideTheAllowlist(t *testing.T) {
	f := setupAgentPrepFixture(t)
	store := newSnapshotStore()
	r, svc, h := f.cacheRouterWithHandler(store)
	img := &models.RunImage{ID: uuid.New(), OrganizationID: f.orgA, Name: "aws-" + uuid.NewString()[:6], Kind: models.RunImageKindTofu, Image: "quay.io/acme/tofu-aws:1.10", Digest: "sha256:" + strings.Repeat("cd", 32)}
	if err := f.db.Create(img).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.db.Where("id = ?", img.ID).Delete(&models.RunImage{}) })
	run := f.seedRun(t, f.runnerA1)
	if err := f.db.Model(&models.Workspace{}).Where("id = ?", run.WorkspaceID).Update("run_image_id", img.ID).Error; err != nil {
		t.Fatal(err)
	}

	code, tok := f.mintJobToken(t, r, svc, "a1", run.ID, "job")
	if code != http.StatusOK || tok.Image == nil {
		t.Fatalf("mint = %d %+v, want the run image", code, tok.Image)
	}
	if tok.Image.Ref != "quay.io/acme/tofu-aws:1.10@sha256:"+strings.Repeat("cd", 32) || tok.Image.Level != "workspace" || tok.Image.ID != img.ID.String() {
		t.Errorf("the job token's image = %+v", tok.Image)
	}

	h.allowedRegistries = []string{"ghcr.io"}
	rec := runnerDo(t, r, "a1", http.MethodPost, "/api/v2/runner/jobs/"+run.ID+"/token", nil)
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "images.allowed_registries") {
		t.Errorf("a job whose image left the allowlist = %d %s, want 409 naming the setting", rec.Code, rec.Body.String())
	}
}
