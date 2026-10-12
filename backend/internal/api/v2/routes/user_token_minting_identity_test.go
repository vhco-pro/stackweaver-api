// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Two routes outside /api/v2/settings hand out user-bound tokens, and a user-bound token acts as
// its owner in every organization they belong to:
//
//   - /api/v2/tokens mints, lists and revokes them. It is inside the walled group, where the
//     registry classifies it agnostic() because it has no target organization, so the wall
//     passes it without looking at the caller.
//   - POST /api/v2/oauth/authorize is the browser half of `terraform login`. It stores a one-time
//     code for whoever is signed in, and the public /api/v2/oauth/token turns that code into a
//     user-bound token.
//
// Both acted on the OWNER of whatever credential called them. A key bound read-only to one
// organization could therefore walk away with a token for all of its owner's organizations,
// which is the same escalation the settings surface allowed and has the same answer: these are
// things a person does while signed in, so a token is refused (middleware.InteractiveOnly).
//
// Like the settings test beside it, this drives the router production mounts with real keys.

//go:build integration

package routes_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/michielvha/stackweaver/core/models"
)

// assertRefused checks for the guard's answer: a 403 carrying a JSON:API error document.
func assertRefused(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	if w.Code != http.StatusForbidden {
		t.Fatalf("got %d, want 403.\nbody: %s", w.Code, tokenRe.ReplaceAllString(w.Body.String(), "<token>"))
	}
	var doc struct {
		Errors []struct {
			Status string `json:"status"`
			Title  string `json:"title"`
			Detail string `json:"detail"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
		t.Fatalf("the 403 body is not JSON: %v\nbody: %s", err, w.Body.String())
	}
	if len(doc.Errors) != 1 || doc.Errors[0].Status != "403" || doc.Errors[0].Title == "" || doc.Errors[0].Detail == "" {
		t.Fatalf("the 403 is not a JSON:API error envelope.\nbody: %s", w.Body.String())
	}
}

func TestUserTokens_TokenIdentitiesAreRefused(t *testing.T) {
	f := setupSettingsGuard(t)

	for identity, token := range f.tokens {
		requests := []struct {
			route, method, path string
			body                any
		}{
			{"GET /api/v2/tokens", http.MethodGet, "/api/v2/tokens", nil},
			{"POST /api/v2/tokens", http.MethodPost, "/api/v2/tokens", map[string]any{"description": f.mintPrefix + " " + identity}},
			// The victim is an organization key, not a user token. Revocation checks who owns
			// the key and not what kind it is, so this route could revoke it all the same.
			{"DELETE /api/v2/tokens/:id", http.MethodDelete, "/api/v2/tokens/" + f.victimKeyID.String(), nil},
		}
		for _, rq := range requests {
			t.Run(identity+"/"+rq.route, func(t *testing.T) {
				var body []byte
				if rq.body != nil {
					var err error
					if body, err = json.Marshal(rq.body); err != nil {
						t.Fatalf("marshal body: %v", err)
					}
				}
				assertRefused(t, f.do(rq.method, rq.path, token, body))
			})
		}
	}

	// A 403 that still did the work would be no fix at all.
	var minted []models.APIKey
	if err := f.db.Where("user_id = ? AND name LIKE ?", f.owner.ID, f.mintPrefix+"%").Find(&minted).Error; err != nil {
		t.Fatalf("look for minted tokens: %v", err)
	}
	for _, k := range minted {
		t.Errorf("a token minted %q, kind %q, bound to organization %v", k.Name, k.Kind, k.OrganizationID)
	}

	var victims int64
	if err := f.db.Model(&models.APIKey{}).Where("id = ?", f.victimKeyID).Count(&victims).Error; err != nil {
		t.Fatalf("look for the victim key: %v", err)
	}
	if victims != 1 {
		t.Errorf("a token revoked another of its owner's keys through the user-token route")
	}
}

func TestOAuthAuthorize_TokenIdentitiesAreRefused(t *testing.T) {
	f := setupSettingsGuard(t)

	const route = "/api/v2/oauth/authorize"
	registered := false
	for _, rt := range f.router.Routes() {
		if rt.Method == http.MethodPost && rt.Path == route {
			registered = true
		}
	}
	if !registered {
		// setupOAuthLoginRoutes registers the pair only when Redis answers, and without the
		// route there is nothing to guard.
		t.Skip("POST /api/v2/oauth/authorize is not registered (Redis unreachable) - skipping")
	}

	// A request the handler would accept in full: the advertised client, a loopback redirect on
	// an advertised port and an S256 challenge whose verifier the caller knows. Anything less
	// would be turned away by validation and look refused.
	sum := sha256.Sum256([]byte("settingsguard-verifier-0123456789-0123456789-0123456789"))
	body, err := json.Marshal(map[string]string{
		"client_id":             "terraform-cli",
		"redirect_uri":          "http://127.0.0.1:10000/login",
		"code_challenge":        base64.RawURLEncoding.EncodeToString(sum[:]),
		"code_challenge_method": "S256",
		"state":                 "settingsguard",
	})
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}

	for identity, token := range f.tokens {
		t.Run(identity, func(t *testing.T) {
			w := f.do(http.MethodPost, route, token, body)

			assertRefused(t, w)
			var resp struct {
				Code string `json:"code"`
			}
			_ = json.Unmarshal(w.Body.Bytes(), &resp)
			if resp.Code != "" {
				t.Fatalf("a refused request still returned an authorization code")
			}
		})
	}
}
