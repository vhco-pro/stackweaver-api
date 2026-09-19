// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// #674: an empty variable value is legitimate. `KEY=` is ordinary .env content - a flag that is
// deliberately blank, or a placeholder filled in per environment - and Terraform Cloud accepts it,
// so requiring a value was also a small TFE-compatibility gap. Both create paths used to reject it
// with a 400 from the `binding:"required"` tag, which the .env import surfaced as "Needs a value".
//
// The one combination that stays rejected is an empty value on an HCL-typed variable. The tfvars
// writers emit an HCL variable as a raw unquoted expression, so an empty value produces `key = `
// with nothing after the equals sign - an HCL syntax error that fails the run while OpenTofu parses
// a file the user never wrote. A non-HCL value is quoted, so `key = ""` is well-formed.
//
// These tests drive the real variable-set handler against real Postgres and assert both halves:
// empty values round-trip through create and read, and the HCL combination is refused with 422 -
// including when it is reached by flipping hcl onto a variable that is already empty, which the
// create-side check alone would not catch.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Cleanup is strictly
// row-scoped (the DB may be live). Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/ -run TestEmptyVariableValue

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

func TestEmptyVariableValue(t *testing.T) {
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

	org := &models.Organization{ID: uuid.New(), Name: "emptyval-" + sfx}
	owner := &models.User{ID: uuid.New(), ZitadelSubject: "emptyval-own-" + sfx, Email: "emptyval-own-" + sfx + "@test.local"}
	ownersTeam := &models.Team{ID: uuid.New(), OrganizationID: org.ID, Name: "owners"}
	varset := &models.VariableSet{ID: "varset-emp" + sfx + "0000", OrganizationID: org.ID, Name: "vs-" + sfx, Scope: "organization", CreatedBy: owner.ID}

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

	base := "/varsets/" + varset.ID + "/relationships/vars"

	resourceID := func(resp map[string]any) string {
		data, ok := resp["data"].(map[string]any)
		if !ok {
			return ""
		}
		id, _ := data["id"].(string)
		return id
	}
	attrString := func(resp map[string]any, name string) (string, bool) {
		data, ok := resp["data"].(map[string]any)
		if !ok {
			return "", false
		}
		attrs, ok := data["attributes"].(map[string]any)
		if !ok {
			return "", false
		}
		v, ok := attrs[name].(string)
		return v, ok
	}

	// --- an empty value is accepted and reads back empty, in both categories. ---
	for _, category := range []string{"terraform", "env"} {
		key := strings.ToUpper(category) + "_BLANK_" + strings.ToUpper(sfx)
		code, resp := do(http.MethodPost, base,
			`{"data":{"type":"vars","attributes":{"key":"`+key+`","value":"","category":"`+category+`"}}}`)
		if code != http.StatusCreated && code != http.StatusOK {
			t.Fatalf("create empty %s variable: status %d body %v", category, code, resp)
		}
		id := resourceID(resp)
		if id == "" {
			t.Fatalf("create empty %s variable: no id in %v", category, resp)
		}

		// Read it back through the API rather than the repository: the point is that the empty
		// value survives the round trip a client actually makes.
		code, resp = do(http.MethodGet, base+"/"+id, "")
		if code != http.StatusOK {
			t.Fatalf("read back empty %s variable: status %d body %v", category, code, resp)
		}
		got, ok := attrString(resp, "value")
		if !ok {
			t.Fatalf("read back empty %s variable: no value attribute in %v", category, resp)
		}
		if got != "" {
			t.Errorf("empty %s variable read back as %q, want empty string", category, got)
		}

		// And at rest, so a run resolving variables sees the same thing.
		var stored models.VariableSetVariable
		if err := db.Where("id = ?", id).First(&stored).Error; err != nil {
			t.Fatalf("load stored %s variable: %v", category, err)
		}
		if stored.Value != "" {
			t.Errorf("stored %s value is %q, want empty string", category, stored.Value)
		}
	}

	// --- the HCL combination is refused, on create. ---
	for name, value := range map[string]string{
		"empty":           "",
		"whitespace only": "   ",
	} {
		code, resp := do(http.MethodPost, base,
			`{"data":{"type":"vars","attributes":{"key":"HCL_`+strings.ToUpper(strings.ReplaceAll(name, " ", "_"))+`_`+strings.ToUpper(sfx)+`","value":"`+value+`","category":"terraform","hcl":true}}}`)
		if code != http.StatusUnprocessableEntity {
			t.Errorf("create %s HCL variable: status %d, want 422 (body %v)", name, code, resp)
		}
	}

	// --- and on update, which is the path the create-side check cannot see. ---
	//
	// Flipping hcl onto a variable that is already empty reaches exactly the state the create
	// check refuses, so the guard has to be evaluated against the resulting variable.
	key := "FLIP_TO_HCL_" + strings.ToUpper(sfx)
	code, resp := do(http.MethodPost, base,
		`{"data":{"type":"vars","attributes":{"key":"`+key+`","value":"","category":"terraform"}}}`)
	if code != http.StatusCreated && code != http.StatusOK {
		t.Fatalf("create variable to flip: status %d body %v", code, resp)
	}
	flipID := resourceID(resp)

	code, resp = do(http.MethodPatch, base+"/"+flipID,
		`{"data":{"type":"vars","attributes":{"hcl":true}}}`)
	if code != http.StatusUnprocessableEntity {
		t.Errorf("flip empty variable to hcl: status %d, want 422 (body %v)", code, resp)
	}
	// The refusal must not have written anything.
	var afterFlip models.VariableSetVariable
	if err := db.Where("id = ?", flipID).First(&afterFlip).Error; err != nil {
		t.Fatalf("load flipped variable: %v", err)
	}
	if afterFlip.HCL {
		t.Error("variable was marked hcl despite the request being refused")
	}

	// Clearing the value of a variable that is already HCL is the mirror image.
	hclKey := "REAL_HCL_" + strings.ToUpper(sfx)
	code, resp = do(http.MethodPost, base,
		`{"data":{"type":"vars","attributes":{"key":"`+hclKey+`","value":"[1, 2, 3]","category":"terraform","hcl":true}}}`)
	if code != http.StatusCreated && code != http.StatusOK {
		t.Fatalf("create real HCL variable: status %d body %v", code, resp)
	}
	hclID := resourceID(resp)

	code, resp = do(http.MethodPatch, base+"/"+hclID,
		`{"data":{"type":"vars","attributes":{"value":""}}}`)
	if code != http.StatusUnprocessableEntity {
		t.Errorf("clear an HCL variable's value: status %d, want 422 (body %v)", code, resp)
	}
	var afterClear models.VariableSetVariable
	if err := db.Where("id = ?", hclID).First(&afterClear).Error; err != nil {
		t.Fatalf("load HCL variable: %v", err)
	}
	if afterClear.Value != "[1, 2, 3]" {
		t.Errorf("HCL variable value is %q after a refused clear, want it untouched", afterClear.Value)
	}

	// --- a sensitive empty value still round-trips, which the ciphertext check could hide. ---
	//
	// An empty string encrypts to non-empty ciphertext, so a guard that inspected the stored bytes
	// rather than the plaintext would both mis-read this as non-empty and, on a later hcl flip,
	// wave through the very case it exists to catch.
	secretKey := "BLANK_SECRET_" + strings.ToUpper(sfx)
	code, resp = do(http.MethodPost, base,
		`{"data":{"type":"vars","attributes":{"key":"`+secretKey+`","value":"","category":"env","sensitive":true}}}`)
	if code != http.StatusCreated && code != http.StatusOK {
		t.Fatalf("create empty sensitive variable: status %d body %v", code, resp)
	}
	secretID := resourceID(resp)

	var storedSecret models.VariableSetVariable
	if err := db.Where("id = ?", secretID).First(&storedSecret).Error; err != nil {
		t.Fatalf("load stored sensitive variable: %v", err)
	}
	plaintext, err := varSvc.Decrypt(storedSecret.Value)
	if storedSecret.Encrypted && err != nil {
		t.Fatalf("decrypt stored sensitive variable: %v", err)
	}
	if storedSecret.Encrypted && plaintext != "" {
		t.Errorf("empty sensitive value decrypts to %q, want empty string", plaintext)
	}

	code, resp = do(http.MethodPatch, base+"/"+secretID,
		`{"data":{"type":"vars","attributes":{"hcl":true}}}`)
	if code != http.StatusUnprocessableEntity {
		t.Errorf("flip empty sensitive variable to hcl: status %d, want 422 (body %v)", code, resp)
	}
}
