// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// An email verification for a user id gets one answer whenever the code is not accepted, whether
// the id exists or not, so the answer does not say which ids exist. The two answers below are
// what Zitadel v4 returns from POST /v2/users/{id}/email/verify, recorded from a live instance.
const (
	answerVerifyUnknownUser = `{"code":5,"message":"Email not found (COMMAND-ieJ2e)","details":[{"@type":"type.googleapis.com/zitadel.v1.ErrorDetail","id":"COMMAND-ieJ2e","message":"Email not found"}]}`
	answerVerifyWrongCode   = `{"code":3,"message":"Code is invalid (COMMAND-eis9R)","details":[{"@type":"type.googleapis.com/zitadel.v1.ErrorDetail","id":"COMMAND-eis9R","message":"Code is invalid"}]}`
)

func TestVerifyEmail_RejectionIsIdenticalForUnknownAndRealUsers(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasPrefix(r.URL.Path, "/v2/users/"+cpRealUser+"/") {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(answerVerifyWrongCode))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(answerVerifyUnknownUser))
	}))
	t.Cleanup(upstream.Close)
	proxy := NewAuthProxy(AuthProxyConfig{ZitadelInternalURL: upstream.URL, PAT: "pat"})

	answers := map[string]*httptest.ResponseRecorder{
		"unknown id": spVerify(proxy, cpUnknown, "ABCDEF", nil),
		"real user":  spVerify(proxy, cpRealUser, "ABCDEF", nil),
	}
	assertSameAnswer(t, "email verification rejected", answers)
	if w := answers["real user"]; w.Code != http.StatusBadRequest || w.Body.String() != string(canonicalCodeInvalidResponse()) {
		t.Errorf("a rejected code must get the canonical code-invalid answer, got %d %s", w.Code, w.Body.String())
	}
}

// Zitadel refusing the proxy's own credential says nothing about the user or the code, and an
// operator needs to see it, so it is not dressed up as a wrong code.
func TestVerifyEmail_IdentityProviderRefusingTheProxyIsNotAWrongCode(t *testing.T) {
	const refused = `{"code":16,"message":"invalid auth header (AUTH-toLo1)","details":[{"@type":"type.googleapis.com/zitadel.v1.ErrorDetail","id":"AUTH-toLo1","message":"invalid auth header"}]}`
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(refused))
	}))
	t.Cleanup(upstream.Close)
	proxy := NewAuthProxy(AuthProxyConfig{ZitadelInternalURL: upstream.URL, PAT: "pat"})

	w := spVerify(proxy, cpRealUser, "ABCDEF", nil)
	if w.Code != http.StatusUnauthorized || w.Body.String() != refused {
		t.Errorf("the identity provider's refusal of the proxy = %d %s, want it unchanged", w.Code, w.Body.String())
	}
}
