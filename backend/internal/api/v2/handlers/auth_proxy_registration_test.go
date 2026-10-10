// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// AUD-120 self-registration policy. CreateUser is on the unauthenticated /auth surface and
// forwards to Zitadel POST /v2/users/human with the admin PAT, so it must honor the login
// policy's allowRegister - otherwise an operator who disabled self-registration is bypassed.

package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func TestCreateUser_RespectsAllowRegister(t *testing.T) {
	gin.SetMode(gin.TestMode)

	newProxy := func(allowRegister bool) (*AuthProxy, *bool) {
		created := false
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			switch {
			case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v2/settings/login"):
				w.WriteHeader(http.StatusOK)
				if allowRegister {
					_, _ = w.Write([]byte(`{"settings":{"allowRegister":true}}`))
				} else {
					_, _ = w.Write([]byte(`{"settings":{"allowRegister":false}}`))
				}
			case r.Method == http.MethodPost && r.URL.Path == "/v2/users/human":
				created = true
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write([]byte(`{"userId":"123"}`))
			case r.Method == http.MethodGet && r.URL.Path == "/v2/users/123":
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"user":{"userId":"123","state":"USER_STATE_ACTIVE"}}`))
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		t.Cleanup(srv.Close)
		return NewAuthProxy(AuthProxyConfig{ZitadelInternalURL: srv.URL, PAT: "test-pat"}), &created
	}

	body := `{"username":"bob","email":{"email":"bob@example.com"}}`

	t.Run("registration disabled -> 403, Zitadel create NOT called", func(t *testing.T) {
		proxy, created := newProxy(false)
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = newTestRequestWithBody(http.MethodPost, "/auth/users/human", body)
		proxy.CreateUser(c)
		if w.Code != http.StatusForbidden {
			t.Fatalf("expected 403 when registration disabled, got %d: %s", w.Code, w.Body.String())
		}
		if *created {
			t.Fatal("Zitadel user-create must NOT be called when registration is disabled (AUD-120)")
		}
	})

	t.Run("registration enabled -> forwards to Zitadel", func(t *testing.T) {
		proxy, created := newProxy(true)
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = newTestRequestWithBody(http.MethodPost, "/auth/users/human", body)
		proxy.CreateUser(c)
		if w.Code != http.StatusCreated {
			t.Fatalf("expected 201 when registration enabled, got %d: %s", w.Code, w.Body.String())
		}
		if !*created {
			t.Fatal("Zitadel user-create must be called when registration is enabled")
		}
	})
}

// CreateUser must not answer until Zitadel's read side reports the new user as
// active. Zitadel projects writes asynchronously, and a client that signs the
// user in straight after creating it otherwise races the projection (a 404 on
// the session check, or Errors.User.NotActive at the token endpoint).
func TestCreateUser_WaitsForUserActive(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name      string
		states    []string // successive read-side answers; "" means 404
		timeout   time.Duration
		wantReads int32
	}{
		{"not found, then initial, then active", []string{"", "USER_STATE_INITIAL", "USER_STATE_ACTIVE"}, 5 * time.Second, 3},
		{"active on first read", []string{"USER_STATE_ACTIVE"}, 5 * time.Second, 1},
		{"never active: gives up and still answers", []string{""}, 200 * time.Millisecond, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var reads atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch {
				case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v2/settings/login"):
					_, _ = w.Write([]byte(`{"settings":{"allowRegister":true}}`))
				case r.Method == http.MethodPost && r.URL.Path == "/v2/users/human":
					w.WriteHeader(http.StatusCreated)
					_, _ = w.Write([]byte(`{"userId":"42"}`))
				case r.Method == http.MethodGet && r.URL.Path == "/v2/users/42":
					n := int(reads.Add(1)) - 1
					state := tt.states[min(n, len(tt.states)-1)]
					if state == "" {
						w.WriteHeader(http.StatusNotFound)
						_, _ = w.Write([]byte(`{"code":5,"message":"User could not be found"}`))
						return
					}
					_, _ = fmt.Fprintf(w, `{"user":{"userId":"42","state":%q}}`, state)
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			t.Cleanup(srv.Close)
			proxy := NewAuthProxy(AuthProxyConfig{ZitadelInternalURL: srv.URL, PAT: "test-pat"})
			proxy.userReadyTimeout = tt.timeout

			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = newTestRequestWithBody(http.MethodPost, "/auth/users/human", `{"username":"bob"}`)
			proxy.CreateUser(c)

			if w.Code != http.StatusCreated {
				t.Fatalf("status = %d, want 201: %s", w.Code, w.Body.String())
			}
			if tt.wantReads > 0 && reads.Load() != tt.wantReads {
				t.Fatalf("read-side lookups = %d, want %d (CreateUser answered before the user was active)", reads.Load(), tt.wantReads)
			}
		})
	}
}

// orgGateZitadel fakes the login settings of two orgs plus the login-service user's own org (the
// unscoped answer), and an org search by domain. "open" allows registration, "closed" does not.
func orgGateZitadel(t *testing.T, unscopedAllows bool) (*httptest.Server, *map[string]any) {
	t.Helper()
	allow := map[string]bool{"open-org": true, "closed-org": false}
	var created map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v2/settings/login":
			org := r.URL.Query().Get("ctx.orgId")
			allowed, known := allow[org]
			if org == "" {
				allowed, known = unscopedAllows, true
			}
			if !known {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_, _ = fmt.Fprintf(w, `{"settings":{"allowRegister":%t}}`, allowed)
		case r.Method == http.MethodPost && r.URL.Path == "/v2/organizations/_search":
			raw, _ := io.ReadAll(r.Body)
			body := string(raw)
			switch {
			case strings.Contains(body, `"closed.example.com"`):
				_, _ = w.Write([]byte(`{"result":[{"id":"closed-org","state":"ORGANIZATION_STATE_ACTIVE","primaryDomain":"closed.example.com"}]}`))
			case strings.Contains(body, `"open.example.com"`):
				_, _ = w.Write([]byte(`{"result":[{"id":"open-org","state":"ORGANIZATION_STATE_ACTIVE","primaryDomain":"open.example.com"}]}`))
			case strings.Contains(body, `"shared.example.com"`): // added, unverified, to two orgs
				_, _ = w.Write([]byte(`{"result":[{"id":"open-org","state":"ORGANIZATION_STATE_ACTIVE","primaryDomain":"open.example.com"},{"id":"closed-org","state":"ORGANIZATION_STATE_ACTIVE","primaryDomain":"closed.example.com"}]}`))
			case strings.Contains(body, `"unverified.example.com"`): // matches only a non-primary domain
				_, _ = w.Write([]byte(`{"result":[{"id":"open-org","state":"ORGANIZATION_STATE_ACTIVE","primaryDomain":"open.example.com"}]}`))
			default:
				_, _ = w.Write([]byte(`{"result":[]}`))
			}
		case r.Method == http.MethodPost && r.URL.Path == "/v2/users/human":
			raw, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(raw, &created)
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"userId":"123"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/v2/users/123":
			_, _ = w.Write([]byte(`{"user":{"userId":"123","state":"USER_STATE_ACTIVE"}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &created
}

// intentZitadel fakes intent retrieval, the IdPs allowed to create users, a user search by email
// and user creation. Registration is closed (Q9: SSO creation bypasses that gate).
type intentFixture struct {
	intentBody       string // JSON Zitadel returns for the intent
	creationIdPs     string // ids in the creationAllowed IdP list, comma separated
	existingEmail    string // an address that already has an account
	created          map[string]any
	intentRetrievals int
}

func intentZitadel(t *testing.T, f *intentFixture) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v2/settings/login":
			_, _ = w.Write([]byte(`{"settings":{"allowRegister":false}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/v2/idp_intents/intent-1":
			raw, _ := io.ReadAll(r.Body)
			if !strings.Contains(string(raw), `"intent-token"`) {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			f.intentRetrievals++
			_, _ = w.Write([]byte(f.intentBody))
		case r.Method == http.MethodGet && r.URL.Path == "/v2/settings/login/idps":
			if r.URL.Query().Get("creationAllowed") != "true" {
				t.Errorf("the IdP list must be filtered to creationAllowed, got %q", r.URL.RawQuery)
			}
			var items []string
			for _, id := range strings.Split(f.creationIdPs, ",") {
				if id != "" {
					items = append(items, fmt.Sprintf(`{"id":%q}`, id))
				}
			}
			_, _ = fmt.Fprintf(w, `{"identityProviders":[%s]}`, strings.Join(items, ","))
		case r.Method == http.MethodPost && r.URL.Path == "/v2/users":
			raw, _ := io.ReadAll(r.Body)
			if f.existingEmail != "" && strings.Contains(strings.ToLower(string(raw)), strings.ToLower(f.existingEmail)) {
				_, _ = w.Write([]byte(`{"details":{"totalResult":"1"},"result":[{"userId":"existing"}]}`))
				return
			}
			_, _ = w.Write([]byte(`{"details":{"totalResult":"0"},"result":[]}`))
		case r.Method == http.MethodPost && r.URL.Path == "/v2/users/human":
			raw, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(raw, &f.created)
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"userId":"123"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/v2/users/123":
			_, _ = w.Write([]byte(`{"user":{"userId":"123","state":"USER_STATE_ACTIVE"}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

const unlinkedIntent = `{
	"idpInformation": {"idpId": "idp-azure", "userId": "azure-sub-1", "userName": "ada@corp.example"},
	"addHumanUser": {
		"username": "ada@corp.example",
		"profile": {"givenName": "Ada", "familyName": "Lovelace"},
		"email": {"email": "ada@corp.example"},
		"idpLinks": [{"idpId": "idp-azure", "userId": "azure-sub-1", "userName": "ada@corp.example"}]
	}
}`

// Zitadel requires IDPLink.userName (1-200 characters) but leaves it out of the addHumanUser
// suggestion for some IdP types; the proxy fills it from the IdP's user name, else the email.
func TestCreateUser_IntentLinkUserNameIsFilled(t *testing.T) {
	gin.SetMode(gin.TestMode)
	f := intentFixture{
		intentBody: `{
			"idpInformation": {"idpId": "idp-azure", "userId": "azure-sub-1", "userName": "ada.idp"},
			"addHumanUser": {
				"profile": {"givenName": "Ada", "familyName": "Lovelace"},
				"email": {"email": "ada@corp.example"},
				"idpLinks": [{"idpId": "idp-azure", "userId": "azure-sub-1"}]
			}
		}`,
		creationIdPs: "idp-azure",
	}
	srv := intentZitadel(t, &f)
	proxy := NewAuthProxy(AuthProxyConfig{ZitadelInternalURL: srv.URL, PAT: "pat", NotificationMode: NotificationModeEmail})
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = newTestRequestWithBody(http.MethodPost, "/auth/users/human", `{"idpIntentId":"intent-1","idpIntentToken":"intent-token"}`)
	proxy.CreateUser(c)

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d: %s", w.Code, w.Body.String())
	}
	links, _ := f.created["idpLinks"].([]any)
	if len(links) != 1 || links[0].(map[string]any)["userName"] != "ada.idp" {
		t.Fatalf("the link userName must be filled from the IdP user name, got %v", f.created["idpLinks"])
	}
}

// #829 AC22/AC23 (Q8, Q9, Q13): an SSO account is created only from an intent the proxy redeems
// with Zitadel, entirely from Zitadel's own suggestion, marked verified, and even with public
// signup closed; every other attempt to attach IdP links creates nothing.
func TestCreateUser_IntentBoundSSOCreation(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tests := []struct {
		name        string
		fixture     intentFixture
		body        string
		wantStatus  int
		wantCreated bool
	}{
		{
			name:        "valid intent creates exactly the intent's user, verified, with signup closed",
			fixture:     intentFixture{intentBody: unlinkedIntent, creationIdPs: "idp-azure"},
			body:        `{"idpIntentId":"intent-1","idpIntentToken":"intent-token","email":{"email":"victim@corp.example","isVerified":true},"organization":{"orgId":"other-org"},"idpLinks":[{"idpId":"idp-azure","userId":"victim-sub"}]}`,
			wantStatus:  http.StatusCreated,
			wantCreated: true,
		},
		{
			name:       "idpLinks without an intent",
			fixture:    intentFixture{intentBody: unlinkedIntent, creationIdPs: "idp-azure"},
			body:       `{"profile":{"givenName":"Eve"},"email":{"email":"eve@corp.example"},"idpLinks":[{"idpId":"idp-azure","userId":"azure-sub-1"}]}`,
			wantStatus: http.StatusForbidden, // falls to the normal gate, which is closed
		},
		{
			name:       "wrong intent token",
			fixture:    intentFixture{intentBody: unlinkedIntent, creationIdPs: "idp-azure"},
			body:       `{"idpIntentId":"intent-1","idpIntentToken":"forged"}`,
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "IdP not allowed to create users",
			fixture:    intentFixture{intentBody: unlinkedIntent, creationIdPs: "idp-okta"},
			body:       `{"idpIntentId":"intent-1","idpIntentToken":"intent-token"}`,
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "intent already linked to a user",
			fixture:    intentFixture{intentBody: `{"userId":"367","idpInformation":{"idpId":"idp-azure"}}`, creationIdPs: "idp-azure"},
			body:       `{"idpIntentId":"intent-1","idpIntentToken":"intent-token"}`,
			wantStatus: http.StatusConflict,
		},
		{
			name:       "email that already has an account",
			fixture:    intentFixture{intentBody: unlinkedIntent, creationIdPs: "idp-azure", existingEmail: "ada@corp.example"},
			body:       `{"idpIntentId":"intent-1","idpIntentToken":"intent-token"}`,
			wantStatus: http.StatusConflict,
		},
		{
			name:       "intent without an email",
			fixture:    intentFixture{intentBody: `{"idpInformation":{"idpId":"idp-azure"},"addHumanUser":{"profile":{"givenName":"Ada"},"idpLinks":[{"idpId":"idp-azure","userId":"s"}]}}`, creationIdPs: "idp-azure"},
			body:       `{"idpIntentId":"intent-1","idpIntentToken":"intent-token"}`,
			wantStatus: http.StatusUnprocessableEntity,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := tt.fixture
			srv := intentZitadel(t, &f)
			proxy := NewAuthProxy(AuthProxyConfig{ZitadelInternalURL: srv.URL, PAT: "pat", NotificationMode: NotificationModeEmail})
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = newTestRequestWithBody(http.MethodPost, "/auth/users/human", tt.body)
			proxy.CreateUser(c)

			if w.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d: %s", w.Code, tt.wantStatus, w.Body.String())
			}
			if !tt.wantCreated {
				if f.created != nil {
					t.Fatalf("no user may be created, got %v", f.created)
				}
				return
			}
			email, _ := f.created["email"].(map[string]any)
			if email["email"] != "ada@corp.example" || email["isVerified"] != true {
				t.Errorf("email must be the intent's and verified, got %v", email)
			}
			links, _ := f.created["idpLinks"].([]any)
			if len(links) != 1 || links[0].(map[string]any)["userId"] != "azure-sub-1" {
				t.Errorf("links must be the intent's, got %v", f.created["idpLinks"])
			}
			if _, present := f.created["organization"]; present {
				t.Errorf("an intent-bound create must ignore the body's organization, got %v", f.created["organization"])
			}
		})
	}
}

// #829 AC9/AC12: registration is checked against the policy of the org the user would be created
// in, however the body names it, and a body naming an org that cannot be resolved is refused.
func TestCreateUser_GateFollowsTheTargetOrg(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tests := []struct {
		name           string
		unscopedAllows bool
		organization   string // JSON for the body's organization field, "" for none
		wantStatus     int
		wantOrgID      string // org the forwarded body must name, when created
	}{
		{name: "no org: login-service org open", unscopedAllows: true, wantStatus: http.StatusCreated},
		{name: "no org: login-service org closed", unscopedAllows: false, wantStatus: http.StatusForbidden},
		{name: "closed org by id, instance open", unscopedAllows: true, organization: `{"orgId":"closed-org"}`, wantStatus: http.StatusForbidden},
		{name: "open org by id, instance closed", unscopedAllows: false, organization: `{"orgId":"open-org"}`, wantStatus: http.StatusCreated, wantOrgID: "open-org"},
		{name: "closed org by domain", unscopedAllows: true, organization: `{"orgDomain":"closed.example.com"}`, wantStatus: http.StatusForbidden},
		{name: "open org by domain is rewritten to its id", unscopedAllows: false, organization: `{"orgDomain":"Open.Example.com"}`, wantStatus: http.StatusCreated, wantOrgID: "open-org"},
		{name: "unknown domain", unscopedAllows: true, organization: `{"orgDomain":"nowhere.example.com"}`, wantStatus: http.StatusForbidden},
		{name: "domain on two orgs", unscopedAllows: true, organization: `{"orgDomain":"shared.example.com"}`, wantStatus: http.StatusForbidden},
		{name: "domain that is not an org's primary (verified) domain", unscopedAllows: true, organization: `{"orgDomain":"unverified.example.com"}`, wantStatus: http.StatusForbidden},
		{name: "unknown org id", unscopedAllows: true, organization: `{"orgId":"no-such-org"}`, wantStatus: http.StatusForbidden},
		{name: "both id and domain", unscopedAllows: true, organization: `{"orgId":"open-org","orgDomain":"open.example.com"}`, wantStatus: http.StatusForbidden},
		{name: "malformed organization", unscopedAllows: true, organization: `"open-org"`, wantStatus: http.StatusForbidden},
		{name: "empty organization object", unscopedAllows: true, organization: `{}`, wantStatus: http.StatusForbidden},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, created := orgGateZitadel(t, tt.unscopedAllows)
			proxy := NewAuthProxy(AuthProxyConfig{ZitadelInternalURL: srv.URL, PAT: "pat", NotificationMode: NotificationModeEmail})
			body := `{"username":"bob","email":{"email":"bob@example.com"}`
			if tt.organization != "" {
				body += `,"organization":` + tt.organization
			}
			body += `}`
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = newTestRequestWithBody(http.MethodPost, "/auth/users/human", body)
			proxy.CreateUser(c)

			if w.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d: %s", w.Code, tt.wantStatus, w.Body.String())
			}
			if tt.wantStatus != http.StatusCreated {
				if *created != nil {
					t.Fatal("Zitadel user-create must not be called when the gate refuses")
				}
				return
			}
			org, _ := (*created)["organization"].(map[string]any)
			if tt.wantOrgID == "" {
				if org != nil {
					t.Fatalf("a body without organization must be forwarded without one, got %v", org)
				}
				return
			}
			if org["orgId"] != tt.wantOrgID || org["orgDomain"] != nil {
				t.Fatalf("forwarded organization = %v, want exactly {orgId: %s}", org, tt.wantOrgID)
			}
		})
	}
}
