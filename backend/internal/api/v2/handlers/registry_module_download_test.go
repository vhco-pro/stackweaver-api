// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

//go:build integration

package handlers

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/api/middleware"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/registry"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/storage/storagetest"
)

// A module download answers the registry protocol the way OpenTofu and Terraform read it: 204 with
// the package location in X-Terraform-Get. The location is the platform's own archive endpoint, a
// path on the host the client used, carrying a short-lived capability token, so a job installs a private
// module through the registry host alone and never needs to reach object storage (#933, AC14).
// A 302 to a presigned storage URL is followed by the client's HTTP stack, which then reads the
// tarball as the metadata response, and the storage endpoint is often unreachable from a job.
func TestModuleDownloadNamesTheArchiveOnTheRegistryHost(t *testing.T) {
	db := setupTestDBForProvider(t)
	if err := db.AutoMigrate(&models.Module{}, &models.ModuleVersion{}, &models.ModuleDownload{}); err != nil {
		t.Fatalf("migrate module models: %v", err)
	}
	var org, other *models.Organization
	var member, outsider *models.User
	t.Cleanup(func() {
		for _, o := range []*models.Organization{org, other} {
			if o == nil {
				continue
			}
			db.Exec(`DELETE FROM module_downloads WHERE module_version_id IN (
				SELECT mv.id FROM module_versions mv JOIN modules m ON m.id = mv.module_id
				WHERE m.organization_id = ?)`, o.ID)
			db.Exec("DELETE FROM module_versions WHERE module_id IN (SELECT id FROM modules WHERE organization_id = ?)", o.ID)
			db.Exec("DELETE FROM modules WHERE organization_id = ?", o.ID)
			db.Exec("DELETE FROM team_members WHERE team_id IN (SELECT id FROM teams WHERE organization_id = ?)", o.ID)
			db.Exec("DELETE FROM team_organization_accesses WHERE team_id IN (SELECT id FROM teams WHERE organization_id = ?)", o.ID)
			db.Exec("DELETE FROM teams WHERE organization_id = ?", o.ID)
			db.Exec("DELETE FROM organization_members WHERE organization_id = ?", o.ID)
			db.Exec("DELETE FROM organizations WHERE id = ?", o.ID)
		}
		for _, u := range []*models.User{member, outsider} {
			if u != nil {
				db.Exec("DELETE FROM users WHERE id = ?", u.ID)
			}
		}
	})

	org = setupTestOrgForProvider(t, db)
	other = setupTestOrgForProvider(t, db)
	mkUser := func() *models.User {
		u := &models.User{ID: uuid.New(), Email: fmt.Sprintf("u-%s@example.com", uuid.New().String()[:8]), ZitadelSubject: uuid.New().String()}
		if err := db.Create(u).Error; err != nil {
			t.Fatalf("create user: %v", err)
		}
		return u
	}
	member = mkUser()
	outsider = mkUser()
	makeUserOrgOwner(t, db, org, member)
	makeUserOrgOwner(t, db, other, outsider)

	mod := &models.Module{ID: uuid.New(), OrganizationID: org.ID, Name: "greeting", Provider: "null"}
	if err := db.Create(mod).Error; err != nil {
		t.Fatalf("create module: %v", err)
	}
	storageClient := storagetest.NewMemory()
	tarball := []byte("\x1f\x8b module tarball bytes")
	for _, v := range []string{"1.0.0", "2.0.0"} {
		key := fmt.Sprintf("modules/%s/greeting/null/%s.tar.gz", org.ID, v)
		if err := storageClient.Put(context.Background(), key, tarball); err != nil {
			t.Fatalf("store tarball: %v", err)
		}
		if err := db.Create(&models.ModuleVersion{ModuleID: mod.ID, Version: v, TarballPath: key, PublishedAt: time.Now()}).Error; err != nil {
			t.Fatalf("create module version: %v", err)
		}
	}

	SetArtifactTokenSecret([]byte("test-secret-key-32-bytes-long!!!"))
	t.Cleanup(func() { SetArtifactTokenSecret(nil) })

	orgRepo := repository.NewOrganizationRepository(db)
	moduleService := registry.NewModuleService(
		repository.NewModuleRepository(db), repository.NewModuleVersionRepository(db),
		repository.NewModuleDownloadRepository(db), orgRepo, storageClient)
	h := NewRegistryModuleHandler(moduleService, auth.NewService(repository.NewUserRepository(db)), orgRepo, middleware.NewDBOrgResolver(db))

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		if id, err := uuid.Parse(c.GetHeader("X-Test-User")); err == nil {
			c.Set("user_id", id)
		}
		c.Next()
	})
	router.GET("/v1/modules/:namespace/:name/:provider/:version/download", h.DownloadModule)
	router.GET("/v1/modules/:namespace/:name/:provider/download", h.DownloadModule)
	router.GET("/v1/modules/:namespace/:name/:provider/:version/archive.tar.gz", h.DownloadModuleArchive)

	do := func(target, user string) *httptest.ResponseRecorder {
		req := httptest.NewRequestWithContext(context.Background(), "GET", target, nil)
		if user != "" {
			req.Header.Set("X-Test-User", user)
		}
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}

	base := fmt.Sprintf("/v1/modules/%s/greeting/null", org.Name)
	w := do(base+"/1.0.0/download", member.ID.String())
	if w.Code != http.StatusNoContent {
		t.Fatalf("download: status %d, want 204. Location %q, body %s", w.Code, w.Header().Get("Location"), w.Body.String())
	}
	location := w.Header().Get("X-Terraform-Get")
	// A path on the registry host: the client resolves it against the URL it used.
	wantPrefix := base + "/1.0.0/archive.tar.gz?token="
	if !strings.HasPrefix(location, wantPrefix) {
		t.Fatalf("X-Terraform-Get = %q, want a %q URL", location, wantPrefix)
	}

	u, err := url.Parse(location)
	if err != nil {
		t.Fatalf("parse location: %v", err)
	}
	// The client fetches the location without registry credentials: the token alone opens it.
	got := do(u.RequestURI(), "")
	if got.Code != http.StatusOK || got.Body.String() != string(tarball) {
		t.Fatalf("archive with token: status %d, body %q", got.Code, got.Body.String())
	}

	// The latest-version form names the newest version's archive.
	latest := do(base+"/download", member.ID.String())
	if latest.Code != http.StatusNoContent || !strings.Contains(latest.Header().Get("X-Terraform-Get"), "/2.0.0/archive.tar.gz?token=") {
		t.Fatalf("latest download: status %d, X-Terraform-Get %q", latest.Code, latest.Header().Get("X-Terraform-Get"))
	}

	token := u.Query().Get("token")
	for _, tc := range []struct {
		name, target, user string
	}{
		{"no token, no credentials", base + "/1.0.0/archive.tar.gz", ""},
		{"a token for another version", base + "/2.0.0/archive.tar.gz?token=" + url.QueryEscape(token), ""},
		{"a forged token", base + "/1.0.0/archive.tar.gz?token=" + url.QueryEscape(token+"x"), ""},
		{"an outsider without a token", base + "/1.0.0/archive.tar.gz", outsider.ID.String()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if w := do(tc.target, tc.user); w.Code < 400 {
				t.Fatalf("status %d, want a refusal", w.Code)
			}
		})
	}
	// A member opens the archive with their own credentials.
	if w := do(base+"/1.0.0/archive.tar.gz", member.ID.String()); w.Code != http.StatusOK {
		t.Fatalf("member archive: status %d", w.Code)
	}
	// An outsider is not handed a location at all.
	if w := do(base+"/1.0.0/download", outsider.ID.String()); w.Code != http.StatusNotFound {
		t.Fatalf("outsider download: status %d, want 404", w.Code)
	}
}
