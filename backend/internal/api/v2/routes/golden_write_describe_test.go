// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

//go:build integration
// +build integration

package routes_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
)

// These pin the rules the write recorder applies to what it commits (#869). They need no
// service: the functions are fed a request and a response directly.

// TestDeclaredSecrets pins AC6: a secret is replaced where a case declares it, and a declaration
// that matches nothing fails the case.
//
// The failure is the point. A secret is declared by where it is, so when a response changes
// shape the declaration stops matching, and the choice is between failing and committing the
// secret wherever it moved to.
func TestDeclaredSecrets(t *testing.T) {
	const token = "sw-plaintext-credential-0123456789"
	response := []byte(`{"data":{"id":"at-1","attributes":{"token":"` + token + `","description":"ci"}}}`)

	got, err := describeResponse(response, []string{"data.attributes.token"}, nil, nil)
	if err != nil {
		t.Fatalf("a declared secret that is present: %v", err)
	}
	attrs := got.(map[string]any)["data"].(map[string]any)["attributes"].(map[string]any)
	if attrs["token"] != secretPlaceholder {
		t.Errorf("token = %v, want the placeholder %q", attrs["token"], secretPlaceholder)
	}
	if attrs["description"] != "ci" {
		t.Errorf("a member that was not declared changed: %v", attrs["description"])
	}

	// The same response with the secret declared where it is not.
	if _, err := describeResponse(response, []string{"data.attributes.secret"}, nil, nil); err == nil {
		t.Error("a declared secret that is not in the response was accepted; the plaintext would have been committed")
	}
	// A response with no body cannot carry the secret a case says it returns.
	if _, err := describeResponse(nil, []string{"data.attributes.token"}, nil, nil); err == nil {
		t.Error("a declared secret was accepted for a response with no body")
	}

	// A member that varies and is no secret is declared the same way and held to the same rule.
	nonce := []byte(`{"publicKey":{"challenge":"dGhpcy1pcy1yYW5kb20","rp":{"id":"localhost"}}}`)
	withNonce, err := describeResponse(nonce, nil, []string{"publicKey.challenge"}, nil)
	if err != nil {
		t.Fatalf("a declared varying member that is present: %v", err)
	}
	if got := withNonce.(map[string]any)["publicKey"].(map[string]any)["challenge"]; got != variesPlaceholder {
		t.Errorf("challenge = %v, want %q", got, variesPlaceholder)
	}
	if _, err := describeResponse(nonce, nil, []string{"publicKey.nonce"}, nil); err == nil {
		t.Error("a declared varying member that is not in the response was accepted")
	}

	// Requests: a credential the case sends, in a JSON body and in a form.
	jsonBody := []byte(`{"data":{"attributes":{"name":"deploy","inputs":{"password":"` + token + `"}}}}`)
	req := httptest.NewRequest(http.MethodPost, "/x", bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/vnd.api+json")
	fx, err := describeRequest(req, jsonBody, nil, []string{"data.attributes.inputs.password"}, nil)
	if err != nil {
		t.Fatalf("a declared request secret that is present: %v", err)
	}
	if raw := mustJSON(t, fx); strings.Contains(raw, token) {
		t.Errorf("the request fixture still carries the credential: %s", raw)
	}
	if _, err := describeRequest(req, jsonBody, nil, []string{"data.attributes.password"}, nil); err == nil {
		t.Error("a declared request secret that is not in the body was accepted")
	}

	form := []byte("grant_type=authorization_code&client_secret=" + token)
	freq := httptest.NewRequest(http.MethodPost, "/x", bytes.NewReader(form))
	freq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ffx, err := describeRequest(freq, form, nil, []string{"client_secret"}, nil)
	if err != nil {
		t.Fatalf("a declared form secret that is present: %v", err)
	}
	if ffx.Form["client_secret"] != secretPlaceholder || ffx.Form["grant_type"] != "authorization_code" {
		t.Errorf("form = %v, want the secret replaced and the rest as sent", ffx.Form)
	}
	if _, err := describeRequest(freq, form, nil, []string{"code_verifier"}, nil); err == nil {
		t.Error("a declared form secret that is not a field was accepted")
	}

	// A body recorded as binary has nowhere to redact, so declaring a secret for one is an error
	// rather than a silent pass.
	breq := httptest.NewRequest(http.MethodPut, "/x", bytes.NewReader([]byte{0x1f, 0x8b}))
	breq.Header.Set("Content-Type", "application/octet-stream")
	if _, err := describeRequest(breq, []byte{0x1f, 0x8b}, nil, []string{"anything"}, nil); err == nil {
		t.Error("a secret declared for a binary body was accepted")
	}
}

// TestBindObserver pins how the recorder learns the type a handler decodes into (AC1): it sees
// the value gin validates after binding, sees nothing for a handler that decodes by hand, leaves
// validation working, and puts the real validator back.
func TestBindObserver(t *testing.T) {
	type attributes struct {
		Name string `json:"name" binding:"required"`
		Note string `json:"note"`
	}
	type createRequest struct {
		Data struct {
			Attributes attributes `json:"attributes" binding:"required"`
		} `json:"data" binding:"required"`
	}

	original := binding.Validator
	var obs *bindObserver
	t.Run("observing", func(t *testing.T) {
		obs = observeBinds(t)

		gin.SetMode(gin.TestMode)
		router := gin.New()
		router.POST("/bound", func(c *gin.Context) {
			var req createRequest
			if err := c.ShouldBindJSON(&req); err != nil {
				c.Status(http.StatusBadRequest)
				return
			}
			c.Status(http.StatusCreated)
		})
		router.POST("/by-hand", func(c *gin.Context) {
			if _, err := c.GetRawData(); err != nil {
				c.Status(http.StatusBadRequest)
				return
			}
			c.Status(http.StatusCreated)
		})
		send := func(path, body string) int {
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, strings.NewReader(body)))
			return rec.Code
		}

		obs.reset()
		if code := send("/bound", `{"data":{"attributes":{"name":"n"}}}`); code != http.StatusCreated {
			t.Fatalf("a valid body answered %d", code)
		}
		bound := obs.bound()
		if bound == nil || bound.Elem() != reflect.TypeFor[createRequest]() {
			t.Fatalf("bound = %v, want a pointer to the request type the handler bound", bound)
		}
		// Described from that type, the body lists the member the example did not send and the
		// one the type requires.
		req := httptest.NewRequest(http.MethodPost, "/bound", nil)
		req.Header.Set("Content-Type", "application/json")
		fx, err := describeRequest(req, []byte(`{"data":{"attributes":{"name":"n"}}}`), bound, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if fx.SchemaSource != schemaFromType {
			t.Fatalf("schema source = %q, want %q", fx.SchemaSource, schemaFromType)
		}
		attrs := fx.Schema.Properties["data"].Properties["attributes"]
		if attrs.Properties["note"] == nil || !reflect.DeepEqual(attrs.Required, []string{"name"}) {
			t.Errorf("attributes = %s, want the unsent member note and required [name]", mustJSON(t, attrs))
		}

		// The wrapper delegates: a body the real validator rejects is still rejected.
		obs.reset()
		if code := send("/bound", `{"data":{"attributes":{}}}`); code != http.StatusBadRequest {
			t.Errorf("a body missing a required member answered %d; the observer must not weaken validation", code)
		}

		// A handler that reads the body itself binds nothing, and the fixture then says its
		// schema is known from the example only.
		obs.reset()
		if code := send("/by-hand", `{"anything":1}`); code != http.StatusCreated {
			t.Fatalf("the hand-decoding handler answered %d", code)
		}
		if got := obs.bound(); got != nil {
			t.Fatalf("bound = %v for a handler that bound nothing", got)
		}
		fx, err = describeRequest(req, []byte(`{"anything":1}`), nil, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if fx.SchemaSource != schemaFromExample || fx.BoundType != "" {
			t.Errorf("a hand-decoded body was recorded as %q / %q, want an example-only schema and no type", fx.SchemaSource, fx.BoundType)
		}
	})

	if binding.Validator != original {
		t.Fatal("the real validator was not put back when the observing test ended")
	}
}

// TestWriteCoverageRule pins AC3: nothing is silently skipped, and nothing is named loosely.
func TestWriteCoverageRule(t *testing.T) {
	mutating := map[string]bool{"POST /a": true, "PATCH /a/:id": true, "DELETE /a/:id": true}
	good := map[string]namedWrite{"DELETE /a/:id": {reason: needsOutsideSystem, detail: "a VCS provider to answer"}}

	if got := writeCoverageProblems(mutating, []string{"POST /a", "PATCH /a/:id"}, good); len(got) != 0 {
		t.Fatalf("every route recorded or named, and the rule reported: %v", got)
	}

	cases := []struct {
		name   string
		routes []string
		named  map[string]namedWrite
		want   string
	}{
		{"a route with neither", []string{"POST /a"}, good, "1 of 3 mutating routes are neither recorded nor named:\n  PATCH /a/:id"},
		{"a case for a route that is gone", []string{"POST /a", "PATCH /a/:id", "POST /gone"}, good, "case POST /gone matches no mutating route"},
		{"two cases for one route", []string{"POST /a", "POST /a", "PATCH /a/:id"}, good, "POST /a has more than one case"},
		{
			"a name for a route that is gone",
			[]string{"POST /a", "PATCH /a/:id"},
			map[string]namedWrite{"DELETE /a/:id": good["DELETE /a/:id"], "POST /gone": {reason: needsAuthenticator, detail: "a passkey"}},
			"named route POST /gone matches no mutating route",
		},
		{
			"a route both recorded and named",
			[]string{"POST /a", "PATCH /a/:id", "DELETE /a/:id"},
			good,
			"DELETE /a/:id is both recorded and named",
		},
		{
			"a reason that is not one of the four",
			[]string{"POST /a", "PATCH /a/:id"},
			map[string]namedWrite{"DELETE /a/:id": {reason: "was hard to set up", detail: "time"}},
			"is not one of the four reasons",
		},
		{
			"a name that does not say what the route needs",
			[]string{"POST /a", "PATCH /a/:id"},
			map[string]namedWrite{"DELETE /a/:id": {reason: needsRunnerArtefact}},
			"is named without saying what it would need",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := strings.Join(writeCoverageProblems(mutating, c.routes, c.named), "\n")
			if !strings.Contains(got, c.want) {
				t.Errorf("problems = %q, want one containing %q", got, c.want)
			}
		})
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}
