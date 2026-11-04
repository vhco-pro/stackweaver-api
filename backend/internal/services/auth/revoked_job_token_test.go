// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package auth

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/runnercontract"
)

// revokedVerifier verifies nothing and reports revoked whether a token is a revoked job token.
type revokedVerifier struct{ revoked bool }

func (v revokedVerifier) VerifyAPIKey(string) (*models.APIKey, error) {
	return nil, errors.New("API key has expired")
}
func (revokedVerifier) UpdateLastUsed(uuid.UUID) error                  { return nil }
func (revokedVerifier) IsTeamMember(uuid.UUID, uuid.UUID) (bool, error) { return false, nil }
func (revokedVerifier) ActiveAPIKey(uuid.UUID) (*models.APIKey, error) {
	return nil, errors.New("none")
}
func (v revokedVerifier) IsRevokedJobToken(string) bool { return v.revoked }

// An executor presenting its revoked job token is told so with 403 job-token-revoked, the one
// answer that stops it (#933, D2, AC67, AC72); any other token that does not verify stays 401.
func TestAuthenticate_RevokedJobTokenAnswersJobTokenRevoked(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, tc := range []struct {
		name     string
		revoked  bool
		status   int
		wantCode string
	}{
		{"revoked job token", true, http.StatusForbidden, runnercontract.ErrorCodeJobTokenRevoked},
		{"unknown token", false, http.StatusUnauthorized, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &Service{apiKeyService: revokedVerifier{revoked: tc.revoked}}
			r := gin.New()
			r.GET("/x", s.AuthenticateMiddleware(), func(c *gin.Context) { c.Status(http.StatusOK) })
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/x", nil)
			req.Header.Set("Authorization", "Bearer tfe-revokedtoken")
			rec := httptest.NewRecorder()
			r.ServeHTTP(rec, req)
			if rec.Code != tc.status {
				t.Fatalf("status = %d, want %d (%s)", rec.Code, tc.status, rec.Body.String())
			}
			var doc struct {
				Errors []struct {
					Code string `json:"code"`
				} `json:"errors"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil || len(doc.Errors) != 1 {
				t.Fatalf("error document %s: %v", rec.Body.String(), err)
			}
			if doc.Errors[0].Code != tc.wantCode {
				t.Errorf("code = %q, want %q", doc.Errors[0].Code, tc.wantCode)
			}
		})
	}
}
