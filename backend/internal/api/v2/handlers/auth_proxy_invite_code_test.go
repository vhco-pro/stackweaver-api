// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// spRightInvite is the invite code the stand-in accepts. Zitadel checks an invite code only at
// its invite-code endpoint: the email-verify endpoint does not accept it (checked live against
// Zitadel v4, which answers 400 "Code is invalid" there).
const spRightInvite = "RIGHTINVITE"

func spVerifyInvite(proxy *AuthProxy, userID, code string, cookies []*http.Cookie) *httptest.ResponseRecorder {
	return spCall(proxy.VerifyInviteCode, "/auth/users/"+userID+"/invite-code/verify", userID, `{"verificationCode":"`+code+`"}`, cookies)
}

// An invite code is checked by Zitadel's invite-code endpoint, and a user it verifies who has no
// authentication method goes on to set one up, on the same recorded check as an email
// verification.
func TestInviteCode_VerifiedThroughTheInviteEndpoint(t *testing.T) {
	zitadel := newSetPasswordZitadel()
	proxy := NewAuthProxy(AuthProxyConfig{ZitadelInternalURL: zitadel.server(t).URL, PAT: "pat"})

	wrong := spVerifyInvite(proxy, spNoMethods, "WRONG", nil)
	if wrong.Code != http.StatusBadRequest || len(liveCookies(wrong)) != 0 {
		t.Fatalf("a wrong invite code = %d with %v, want 400 and nothing recorded", wrong.Code, wrong.Result().Cookies())
	}
	unknown := spVerifyInvite(proxy, "999999999999999999", spRightInvite, nil)
	if unknown.Code != http.StatusBadRequest || unknown.Body.String() != wrong.Body.String() {
		t.Errorf("an unknown user must get the wrong-code answer: %d %s", unknown.Code, unknown.Body.String())
	}

	ok := spVerifyInvite(proxy, spNoMethods, spRightInvite, nil)
	if ok.Code != http.StatusOK {
		t.Fatalf("a right invite code = %d, want 200 (%s)", ok.Code, ok.Body.String())
	}
	var answer struct {
		AuthenticatorSetupRequired bool `json:"authenticatorSetupRequired"`
	}
	_ = json.Unmarshal(ok.Body.Bytes(), &answer)
	if !answer.AuthenticatorSetupRequired {
		t.Errorf("the answer must send the user on to set up an authenticator: %s", ok.Body.String())
	}
	if set := spSet(proxy, spNoMethods, spNewPassword, liveCookies(ok)); set.Code != http.StatusOK {
		t.Errorf("the invite's verification check must let the user set a first password: %d %s", set.Code, set.Body.String())
	}
}
