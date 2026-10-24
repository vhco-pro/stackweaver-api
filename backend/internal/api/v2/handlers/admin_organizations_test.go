// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// GET /api/v2/admin/organizations and /:name (#132, AC20): every organization on the installation
// to a platform administrator who belongs to none of them, read-only, in TFE's shape with TFE
// pagination; 404 for an unknown name and for a caller who is not a platform administrator.
//
//	go test -tags integration ./internal/api/v2/handlers/ -run TestAdminOrganizations

//go:build integration

package handlers

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/services/platformadmin"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
)

func (f *platformAdminFixture) adminOrganizationRoutes(router *gin.Engine, admins *platformadmin.Service) {
	h := NewAdminOrganizationsHandlerV2(repository.NewOrganizationRepository(f.db), admins)
	router.GET("/api/v2/admin/organizations", h.List)
	router.GET("/api/v2/admin/organizations/:name", h.Show)
}

type adminOrgsDoc struct {
	Data []struct {
		ID         string         `json:"id"`
		Type       string         `json:"type"`
		Attributes map[string]any `json:"attributes"`
	} `json:"data"`
	Meta struct {
		Pagination map[string]any `json:"pagination"`
	} `json:"meta"`
}

func TestAdminOrganizations(t *testing.T) {
	f := setupPlatformAdminFixture(t)
	router := platformAdminRouter()
	f.adminOrganizationRoutes(router, f.admins)
	// A workspace in orgA, so its workspace-count is 1.
	project := &models.Project{ID: uuid.New(), OrganizationID: f.orgA.ID, Name: "platadm-p-" + f.sfx}
	if err := f.db.Create(project).Error; err != nil {
		t.Fatalf("create project: %v", err)
	}
	ws := &models.Workspace{ID: "ws-platadm" + f.sfx, Name: "platadm-ws-" + f.sfx, ProjectID: project.ID}
	if err := f.db.Create(ws).Error; err != nil {
		t.Fatalf("create workspace: %v", err)
	}
	t.Cleanup(func() {
		f.db.Where("id = ?", ws.ID).Delete(&models.Workspace{})
		f.db.Where("id = ?", project.ID).Delete(&models.Project{})
	})

	list := func(as identity, query string) (int, adminOrgsDoc) {
		rec := platformAdminCall(t, router, http.MethodGet, "/api/v2/admin/organizations"+query, as, "")
		var doc adminOrgsDoc
		_ = json.Unmarshal(rec.Body.Bytes(), &doc)
		return rec.Code, doc
	}

	t.Run("lists every organization to an administrator who is a member of none", func(t *testing.T) {
		code, doc := list(jwtAs(f.admin), "?q="+url.QueryEscape("platadm-")+"&page%5Bsize%5D=100")
		if code != http.StatusOK {
			t.Fatalf("status %d", code)
		}
		got := map[string]map[string]any{}
		for _, d := range doc.Data {
			if d.Type != "organizations" {
				t.Errorf("type %q", d.Type)
			}
			got[d.ID] = d.Attributes
		}
		a, ok := got[f.orgA.Name]
		if !ok || got[f.orgB.Name] == nil {
			t.Fatalf("listing misses the test organizations: %v", got)
		}
		for _, k := range []string{"name", "external-id", "notification-email", "is-disabled", "created-at", "member-count", "workspace-count"} {
			if _, ok := a[k]; !ok {
				t.Errorf("attribute %s missing", k)
			}
		}
		if a["external-id"] != f.orgA.ID.String() || a["notification-email"] != f.orgA.Email || a["is-disabled"] != false {
			t.Errorf("orgA attributes %v", a)
		}
		// orgA: the owner and the member.
		if a["member-count"] != float64(2) || a["workspace-count"] != float64(1) {
			t.Errorf("orgA counts members %v workspaces %v, want 2 and 1", a["member-count"], a["workspace-count"])
		}
		for _, k := range []string{"current-page", "page-size", "total-count", "total-pages"} {
			if _, ok := doc.Meta.Pagination[k]; !ok {
				t.Errorf("pagination meta lacks %s: %v", k, doc.Meta.Pagination)
			}
		}
	})

	t.Run("q[name] and q[email] narrow", func(t *testing.T) {
		_, doc := list(jwtAs(f.admin), "?q%5Bname%5D="+url.QueryEscape(f.orgB.Name))
		if len(doc.Data) != 1 || doc.Data[0].ID != f.orgB.Name {
			t.Errorf("q[name] = %+v, want orgB only", doc.Data)
		}
		_, doc = list(jwtAs(f.admin), "?q%5Bemail%5D="+url.QueryEscape(f.orgA.Email))
		if len(doc.Data) != 1 || doc.Data[0].ID != f.orgA.Name {
			t.Errorf("q[email] = %+v, want orgA only", doc.Data)
		}
	})

	t.Run("pagination walks the listing", func(t *testing.T) {
		_, doc := list(jwtAs(f.admin), "?q="+url.QueryEscape("platadm-a-"+f.sfx)+"&page%5Bsize%5D=1&page%5Bnumber%5D=1")
		if len(doc.Data) != 1 || doc.Meta.Pagination["total-count"] != float64(1) {
			t.Errorf("one-row page = %+v %v", doc.Data, doc.Meta.Pagination)
		}
	})

	t.Run("show", func(t *testing.T) {
		rec := platformAdminCall(t, router, http.MethodGet, "/api/v2/admin/organizations/"+f.orgA.Name, jwtAs(f.admin), "")
		if rec.Code != http.StatusOK {
			t.Fatalf("show = %d", rec.Code)
		}
		rec = platformAdminCall(t, router, http.MethodGet, "/api/v2/admin/organizations/no-such-"+uuid.NewString()[:8], jwtAs(f.admin), "")
		if rec.Code != http.StatusNotFound {
			t.Errorf("unknown name = %d, want 404", rec.Code)
		}
	})

	t.Run("a non-administrator gets 404", func(t *testing.T) {
		for _, who := range []identity{jwtAs(f.owner), jwtAs(f.member), jwtAs(f.plain)} {
			for _, path := range []string{"/api/v2/admin/organizations", "/api/v2/admin/organizations/" + f.orgA.Name} {
				if rec := platformAdminCall(t, router, http.MethodGet, path, who, ""); rec.Code != http.StatusNotFound {
					t.Errorf("%s GET %s = %d, want 404", who.user, path, rec.Code)
				}
			}
		}
	})
}
