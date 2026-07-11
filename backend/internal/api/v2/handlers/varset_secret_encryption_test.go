// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// AUD-104 / AUD-105 variable-set secret handling. Sensitive variable-set values were
// stored in cleartext at rest (no encryption-on-write, unlike workspace variables), and
// the Update path naively overwrote the value with whatever the client sent — so a client
// that round-tripped a masked read (the SPA and the TFE provider both resubmit the whole
// resource when editing an unrelated field) silently replaced the real secret with the
// "••••••••" placeholder, breaking every consuming run. These tests drive the real handler
// + real Postgres and assert: (AUD-104) a sensitive value is ciphertext at rest and
// decrypts back; (AUD-105) PATCHing the masked placeholder leaves the stored secret intact,
// while a genuine new value is re-encrypted.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Cleanup is strictly
// row-scoped (the DB may be live). Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/ -run TestVarsetSecretEncryption

//go:build integration
// +build integration

package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/services/variable"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func TestVarsetSecretEncryption(t *testing.T) {
	dbURL := os.Getenv("TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping integration test")
	}
	db, err := gorm.Open(postgres.Open(dbURL), &gorm.Config{})
	if err != nil {
		t.Fatalf("connect test db: %v", err)
	}
	if err := db.AutoMigrate(
		&models.User{}, &models.Organization{}, &models.OrganizationMember{},
		&models.Team{}, &models.TeamMember{}, &models.TeamOrganizationAccess{}, &models.TeamProjectAccess{},
		&models.Project{}, &models.VariableSet{}, &models.VariableSetVariable{}, &models.Variable{},
	); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	sfx := uuid.NewString()[:8]

	org := &models.Organization{ID: uuid.New(), Name: "vsenc-" + sfx}
	owner := &models.User{ID: uuid.New(), ZitadelSubject: "vsenc-own-" + sfx, Email: "vsenc-own-" + sfx + "@test.local"}
	ownersTeam := &models.Team{ID: uuid.New(), OrganizationID: org.ID, Name: "owners"}
	varset := &models.VariableSet{ID: "varset-enc" + sfx + "0000", OrganizationID: org.ID, Name: "vs-" + sfx, Scope: "organization", CreatedBy: owner.ID}

	seed := []interface{}{
		org, owner, ownersTeam, varset,
		&models.OrganizationMember{ID: uuid.New(), OrganizationID: org.ID, UserID: owner.ID},
		&models.TeamMember{ID: uuid.New(), TeamID: ownersTeam.ID, UserID: owner.ID},
	}
	t.Cleanup(func() {
		db.Where("variable_set_id = ?", varset.ID).Delete(&models.VariableSetVariable{})
		db.Where("id = ?", varset.ID).Delete(&models.VariableSet{})
		db.Where("team_id = ?", ownersTeam.ID).Delete(&models.TeamMember{})
		db.Where("id = ?", ownersTeam.ID).Delete(&models.Team{})
		db.Where("organization_id = ?", org.ID).Delete(&models.OrganizationMember{})
		db.Where("id = ?", org.ID).Delete(&models.Organization{})
		db.Where("id = ?", owner.ID).Delete(&models.User{})
	})
	for _, obj := range seed {
		if err := db.Create(obj).Error; err != nil {
			t.Fatalf("seed %T: %v", obj, err)
		}
	}

	orgRepo := repository.NewOrganizationRepository(db)
	varRepo := repository.NewVariableRepository(db)
	vsvRepo := repository.NewVariableSetVariableRepository(db)
	authService := auth.NewService(repository.NewUserRepository(db))
	rbacService := rbac.NewServiceWithTeams(orgRepo, repository.NewTeamRepository(db), repository.NewProjectRepository(db))
	// Real AES-256 key so Encrypt/Decrypt actually run (32 bytes).
	varSvc := variable.NewService(varRepo, []byte("0123456789abcdef0123456789abcdef"))

	h := NewVariableSetHandlerV2(
		repository.NewVariableSetRepository(db), vsvRepo, orgRepo,
		repository.NewProjectRepository(db), nil, nil, authService, rbacService, varSvc,
	)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		if v := c.GetHeader("X-Test-User"); v != "" {
			if id, err := uuid.Parse(v); err == nil {
				c.Set("user_id", id)
			}
		}
		c.Next()
	})
	router.POST("/varsets/:id/relationships/vars", h.CreateVariableSetVariable)
	router.GET("/varsets/:id/relationships/vars/:variable_id", h.GetVariableSetVariable)
	router.PATCH("/varsets/:id/relationships/vars/:variable_id", h.UpdateVariableSetVariable)

	do := func(method, path, body string) (int, map[string]any) {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/vnd.api+json")
		req.Header.Set("X-Test-User", owner.ID.String())
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}

	const secret = "super-secret-cloud-credential"
	base := "/varsets/" + varset.ID + "/relationships/vars"

	// --- AUD-104: create a sensitive variable and assert ciphertext at rest. ---
	code, resp := do(http.MethodPost, base,
		`{"data":{"type":"vars","attributes":{"key":"AWS_SECRET","value":"`+secret+`","category":"env","sensitive":true}}}`)
	if code != http.StatusCreated && code != http.StatusOK {
		t.Fatalf("create sensitive var: status %d body %v", code, resp)
	}
	varID, _ := resp["data"].(map[string]any)["id"].(string)
	if varID == "" {
		t.Fatalf("no variable id in create response: %v", resp)
	}

	stored, err := vsvRepo.GetByID(varID)
	if err != nil {
		t.Fatalf("reload stored var: %v", err)
	}
	if !stored.Encrypted {
		t.Fatal("sensitive value not marked Encrypted — AUD-104 regression")
	}
	if stored.Value == secret {
		t.Fatal("sensitive value stored in cleartext at rest — AUD-104 regression")
	}
	if plain, err := varSvc.GetDecryptedVariableSetValue(stored); err != nil || plain != secret {
		t.Fatalf("stored ciphertext did not decrypt to the secret: plain=%q err=%v", plain, err)
	}

	// The read path must never return the real value — it masks sensitive values.
	_, getResp := do(http.MethodGet, base+"/"+varID, "")
	if v := getResp["data"].(map[string]any)["attributes"].(map[string]any)["value"]; v != maskedValue {
		t.Fatalf("read path leaked sensitive value: %v", v)
	}

	// --- AUD-105: PATCH resubmitting the MASKED value must NOT overwrite the secret. ---
	code, _ = do(http.MethodPatch, base+"/"+varID,
		`{"data":{"type":"vars","attributes":{"value":"`+maskedValue+`","description":"edited elsewhere"}}}`)
	if code != http.StatusOK {
		t.Fatalf("patch masked value: status %d", code)
	}
	afterMask, err := vsvRepo.GetByID(varID)
	if err != nil {
		t.Fatalf("reload after masked patch: %v", err)
	}
	if afterMask.Description != "edited elsewhere" {
		t.Fatalf("unrelated field not updated: %q", afterMask.Description)
	}
	if plain, err := varSvc.GetDecryptedVariableSetValue(afterMask); err != nil || plain != secret {
		t.Fatalf("masked round-trip destroyed the secret (AUD-105): plain=%q err=%v", plain, err)
	}

	// --- A genuine new value must replace and re-encrypt the secret. ---
	const rotated = "rotated-credential-value"
	code, _ = do(http.MethodPatch, base+"/"+varID,
		`{"data":{"type":"vars","attributes":{"value":"`+rotated+`"}}}`)
	if code != http.StatusOK {
		t.Fatalf("patch new value: status %d", code)
	}
	afterRotate, err := vsvRepo.GetByID(varID)
	if err != nil {
		t.Fatalf("reload after rotate: %v", err)
	}
	if afterRotate.Value == rotated {
		t.Fatal("rotated sensitive value stored in cleartext — AUD-104 regression")
	}
	if plain, err := varSvc.GetDecryptedVariableSetValue(afterRotate); err != nil || plain != rotated {
		t.Fatalf("rotated value did not roundtrip: plain=%q err=%v", plain, err)
	}
}
