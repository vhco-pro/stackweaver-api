// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The answers below are what Zitadel v4 returns from POST /v2/users/{id}/password, recorded
// verbatim from a live instance on throwaway users. The stand-in replays them so the tests pin
// the proxy against Zitadel's real error identifiers rather than against invented shapes.
const (
	answerWrongCurrent  = `{"code":3,"message":"Password is invalid (COMMAND-3M0fs)","details":[{"@type":"type.googleapis.com/zitadel.v1.CredentialsCheckError","id":"COMMAND-3M0fs","message":"Password is invalid","failedAttempts":1}]}`
	answerNoSuchUser    = `{"code":9,"message":"Password not found (COMMAND-G8dh3)","details":[{"@type":"type.googleapis.com/zitadel.v1.ErrorDetail","id":"COMMAND-G8dh3","message":"Password not found"}]}`
	answerNoneSet       = `{"code":9,"message":"User has not set a password (COMMAND-3nJ4t)","details":[{"@type":"type.googleapis.com/zitadel.v1.ErrorDetail","id":"COMMAND-3nJ4t","message":"User has not set a password"}]}`
	answerWrongCode     = `{"code":3,"message":"Code is invalid (CODE-woT0xc)","details":[{"@type":"type.googleapis.com/zitadel.v1.ErrorDetail","id":"CODE-woT0xc","message":"Code is invalid"}]}`
	answerNoPendingCode = `{"code":9,"message":"Code not found (COMMAND-2M9fs)","details":[{"@type":"type.googleapis.com/zitadel.v1.ErrorDetail","id":"COMMAND-2M9fs","message":"Code not found"}]}`
	answerComplexity    = `{"code":3,"message":"Password must contain upper case (DOMAIN-VoaRj)","details":[{"@type":"type.googleapis.com/zitadel.v1.ErrorDetail","id":"DOMAIN-VoaRj","message":"Password must contain upper case"}]}`
	answerChanged       = `{"details":{"sequence":"9","changeDate":"2026-10-16T00:00:00Z","resourceOwner":"1"}}`
)

const (
	cpRealUser   = "395290138306936843" // has the password "Password1!" and a pending reset code "RIGHTCODE"
	cpNoPassword = "395290139665891339" // exists, never set a password, no pending code
	cpUnknown    = "999999999999999999" // no user has this id
)

// passwordChangeZitadel stands in for Zitadel's SetPassword, answering each user id the way
// the live instance does.
func passwordChangeZitadel(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var body struct {
			CurrentPassword  string `json:"currentPassword"`
			VerificationCode string `json:"verificationCode"`
			NewPassword      struct {
				Password string `json:"password"`
			} `json:"newPassword"`
		}
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &body)
		answer := func(status int, b string) {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(b))
		}
		userID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v2/users/"), "/password")
		switch {
		case userID != cpRealUser && userID != cpNoPassword:
			answer(http.StatusBadRequest, answerNoSuchUser)
		case body.CurrentPassword != "" && userID == cpNoPassword:
			answer(http.StatusBadRequest, answerNoneSet)
		case body.CurrentPassword != "" && body.CurrentPassword != "Password1!":
			answer(http.StatusBadRequest, answerWrongCurrent)
		case body.VerificationCode != "" && userID == cpNoPassword:
			answer(http.StatusBadRequest, answerNoPendingCode)
		case body.VerificationCode != "" && body.VerificationCode != "RIGHTCODE":
			answer(http.StatusBadRequest, answerWrongCode)
		case strings.ToLower(body.NewPassword.Password) == body.NewPassword.Password:
			answer(http.StatusBadRequest, answerComplexity)
		default:
			answer(http.StatusOK, answerChanged)
		}
	}))
}

func newPasswordChangeProxy(t *testing.T) *AuthProxy {
	t.Helper()
	upstream := passwordChangeZitadel(t)
	t.Cleanup(upstream.Close)
	return NewAuthProxy(AuthProxyConfig{ZitadelInternalURL: upstream.URL, PAT: "pat"})
}

func assertSameAnswer(t *testing.T, label string, answers map[string]*httptest.ResponseRecorder) {
	t.Helper()
	var firstName string
	var first *httptest.ResponseRecorder
	for name, w := range answers {
		if first == nil {
			firstName, first = name, w
			continue
		}
		if w.Code != first.Code || w.Body.String() != first.Body.String() {
			t.Errorf("%s: %q and %q must be byte-identical:\n %s: %d %s\n %s: %d %s",
				label, firstName, name, firstName, first.Code, first.Body.String(), name, w.Code, w.Body.String())
		}
	}
}

// With a current password, an unknown id, a user who never set a password and a real user
// who typed the wrong password must all get the same status and the same bytes.
func TestChangePassword_CurrentPasswordRejectionIsIdenticalForUnknownAndRealUsers(t *testing.T) {
	proxy := newPasswordChangeProxy(t)
	body := `{"currentPassword":"WrongPassword1!","newPassword":{"password":"NewPassword1!x","changeRequired":false}}`

	answers := map[string]*httptest.ResponseRecorder{
		"unknown id":            changePassword(proxy, cpUnknown, body),
		"non-numeric id":        changePassword(proxy, "nosuchuser", body),
		"user without password": changePassword(proxy, cpNoPassword, body),
		"wrong password":        changePassword(proxy, cpRealUser, body),
	}
	assertSameAnswer(t, "current password rejected", answers)

	wrong := answers["wrong password"]
	if wrong.Code != http.StatusBadRequest {
		t.Errorf("a wrong current password must be refused with 400, got %d", wrong.Code)
	}
	// The password-change page tells the user their current password is wrong when the
	// message says the password is invalid, so the canonical answer must keep saying that,
	// and must not carry an internal identifier the page's error filter would hide.
	var parsed struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal(wrong.Body.Bytes(), &parsed); err != nil {
		t.Fatalf("answer must be JSON: %v: %s", err, wrong.Body.String())
	}
	if !strings.Contains(parsed.Message, "Password is invalid") {
		t.Errorf("answer must still say the password is invalid, got %q", parsed.Message)
	}
	if strings.Contains(parsed.Message, "COMMAND-") || strings.Contains(wrong.Body.String(), "failedAttempts") {
		t.Errorf("answer must not carry Zitadel's internal detail, got %s", wrong.Body.String())
	}
}

// With a verification code, an unknown id, a real user with no pending code and a real user
// with a wrong code must all get the same status and the same bytes, and that answer is the
// one the proxy already gives an unknown user and a body without proof.
func TestChangePassword_VerificationCodeRejectionIsIdenticalForUnknownAndRealUsers(t *testing.T) {
	proxy := newPasswordChangeProxy(t)
	body := `{"verificationCode":"WRONGCODE","newPassword":{"password":"NewPassword1!x","changeRequired":false}}`

	answers := map[string]*httptest.ResponseRecorder{
		"unknown id":      changePassword(proxy, cpUnknown, body),
		"no pending code": changePassword(proxy, cpNoPassword, body),
		"wrong code":      changePassword(proxy, cpRealUser, body),
		"no proof":        changePassword(proxy, cpRealUser, `{"newPassword":{"password":"NewPassword1!x"}}`),
	}
	assertSameAnswer(t, "verification code rejected", answers)
	if w := answers["wrong code"]; w.Code != http.StatusBadRequest || w.Body.String() != string(canonicalCodeInvalidResponse()) {
		t.Errorf("a rejected code must get the canonical code-invalid answer, got %d %s", w.Code, w.Body.String())
	}
}

// The canonicalisation applies only to a rejected proof: a right proof still changes the
// password, and an answer about the new password (given only once the proof was accepted)
// reaches the caller unchanged.
func TestChangePassword_RightProofStillSucceeds(t *testing.T) {
	proxy := newPasswordChangeProxy(t)

	for _, tc := range []struct{ name, body string }{
		{"currentPassword", `{"currentPassword":"Password1!","newPassword":{"password":"NewPassword1!x","changeRequired":false}}`},
		{"verificationCode", `{"verificationCode":"RIGHTCODE","newPassword":{"password":"NewPassword1!x","changeRequired":false}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := changePassword(proxy, cpRealUser, tc.body)
			if w.Code != http.StatusOK || w.Body.String() != answerChanged {
				t.Errorf("a right %s must change the password, got %d %s", tc.name, w.Code, w.Body.String())
			}
		})
	}

	w := changePassword(proxy, cpRealUser, `{"currentPassword":"Password1!","newPassword":{"password":"weakpassword1!","changeRequired":false}}`)
	if w.Code != http.StatusBadRequest || w.Body.String() != answerComplexity {
		t.Errorf("a complexity failure after a right password must pass through unchanged, got %d %s", w.Code, w.Body.String())
	}
}
