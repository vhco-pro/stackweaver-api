// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package auth

import (
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/models"
)

// noUserLookup fails the test if a user is looked up: an ownerless key has no user to load.
type noUserLookup struct{ t *testing.T }

func (n noUserLookup) GetByID(uuid.UUID) (*models.User, error) {
	n.t.Error("an ownerless key must not look up a user")
	return nil, errors.New("no user")
}

func (n noUserLookup) GetOrCreateByZitadelSubject(string, string, string) (*models.User, error) {
	return nil, errors.New("unused")
}

type stubVerifier struct{ key *models.APIKey }

func (s stubVerifier) VerifyAPIKey(string) (*models.APIKey, error)     { return s.key, nil }
func (s stubVerifier) UpdateLastUsed(uuid.UUID) error                  { return nil }
func (s stubVerifier) IsTeamMember(uuid.UUID, uuid.UUID) (bool, error) { return false, nil }
func (s stubVerifier) ActiveAPIKey(uuid.UUID) (*models.APIKey, error)  { return s.key, nil }

// TestEstablishOwnerlessAPIKey covers the platform-minted keys of the runner architecture (#933, D1):
// the hosted registration secret, a hosted runner token and every job token belong to no user. Such a
// key authenticates as itself, with its kind and organization, and establishes no user.
func TestEstablishOwnerlessAPIKey(t *testing.T) {
	gin.SetMode(gin.TestMode)
	org := uuid.New()
	key := &models.APIKey{ID: uuid.New(), Kind: models.APIKeyKindOrg, OrganizationID: &org, Scopes: models.StringArray{"job:tofu_run:run-x:*"}}
	s := &Service{userRepo: noUserLookup{t}, apiKeyService: stubVerifier{key}}

	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequestWithContext(t.Context(), "GET", "/", nil)
	if err := s.establishAPIKey(c, key); err != nil {
		t.Fatalf("establishAPIKey: %v", err)
	}
	if m, _ := c.Get("auth_method"); m != "api_key" {
		t.Errorf("auth_method = %v", m)
	}
	if got, _ := c.Get("api_key"); got != key {
		t.Errorf("api_key not established")
	}
	if _, ok := c.Get("user_id"); ok {
		t.Error("an ownerless key must establish no user_id")
	}
	if got, _ := c.Get("token_org_id"); got != org {
		t.Errorf("token_org_id = %v, want %s", got, org)
	}
}
