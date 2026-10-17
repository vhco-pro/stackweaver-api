// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

//go:build integration
// +build integration

package routes_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // G505: RFC 6238 fixes the algorithm an authenticator app uses
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// Write cases for the identity routes: the sign-in the login page performs through the auth
// proxy, the sessions it keeps, what a person does to their own account there and under
// /api/v2/settings, and the tokens a signed-in person mints for themselves.
//
// Every case acts on a user it creates with w.newUser, which the recorder deletes when the case
// ends. The identity provider is the dev stack's own and every session on the machine shares it,
// so no case names a user, a session or a login name it did not make. See
// golden_write_identity_test.go.

// identityCookied puts the proxy's session cookie on a request, as the login page's browser
// does. The proxy keeps the session identifiers and tokens in that cookie and answers the
// session and user routes only to the browser that holds it.
func identityCookied(req *http.Request, cookies []*http.Cookie) *http.Request {
	for _, c := range cookies {
		req.AddCookie(c)
	}
	return req
}

// The sign-in, one request per route, in the order the login page sends them.
func init() {
	registerWriteCases(
		writeCase{
			route: "POST /auth/sessions",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return publicJSON(t, http.MethodPost, "/auth/sessions", sessionBody(w.newUser(true)))
			},
			requestSecrets:  []string{"checks.password.password"},
			responseSecrets: []string{"sessionToken"},
		},
		writeCase{
			// Joins a session whose checks passed to the authorization request the application
			// started. The answer is the application's callback URL, which carries the
			// authorization code, so the whole member is a secret.
			route: "POST /auth/oidc/finalize",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				s := w.beginSignIn(w.newUser(true))
				s.authorize()
				s.session()
				// The provider numbers every authorization request it is asked to start.
				w.publishAs(s.authRequest, "<auth-request-id>")
				return s.finalizeRequest()
			},
			requestSecrets:  []string{"sessionToken"},
			responseSecrets: []string{"callbackUrl"},
		},
		writeCase{
			route: "POST /auth/oidc/token",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				s := w.beginSignIn(w.newUser(true))
				s.authorize()
				s.session()
				s.finalize()
				return s.tokenRequest()
			},
			requestSecrets:  []string{"code", "code_verifier"},
			responseSecrets: []string{"access_token", "id_token"},
		},
		writeCase{
			// RP-initiated logout: the ID token says whose session ends. The provider answers
			// with a redirect to the application, which the proxy follows only to a host it was
			// configured to trust; the recorder's proxy has none, so it answers that the logout
			// happened and leaves the navigation to the page.
			route: "POST /auth/oidc/end-session",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				s := w.beginSignIn(w.newUser(true))
				s.authorize()
				s.session()
				s.finalize()
				tokens, _ := w.sendJSON(s.tokenRequest())
				idToken, _ := tokens["id_token"].(string)
				if idToken == "" {
					t.Fatalf("the token exchange returned no ID token: %v", keysOf(tokens))
				}
				form := url.Values{
					"id_token_hint":            {idToken},
					"client_id":                {w.rec.identity.FrontendClientID},
					"post_logout_redirect_uri": {"http://localhost:5173"},
					"state":                    {"golden-write"},
				}
				return publicRequest(http.MethodPost, "/auth/oidc/end-session", "application/x-www-form-urlencoded", []byte(form.Encode()))
			},
			requestSecrets: []string{"id_token_hint"},
		},
	)
}

// The sessions a browser holds. Each is answered only to the browser whose cookie lists it.
func init() {
	registerWriteCases(
		writeCase{
			// The login page asks for the name on one page and the password on the next: the
			// session exists after the first, and this adds the second check to it.
			route: "PATCH /auth/sessions/:id",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				u := w.newUser(true)
				created, cookies := w.sendJSON(publicJSON(t, http.MethodPost, "/auth/sessions",
					map[string]any{"checks": map[string]any{"user": map[string]any{"loginName": u.LoginName}}}))
				id, _ := created["sessionId"].(string)
				if id == "" {
					t.Fatalf("creating a session returned no session: %v", keysOf(created))
				}
				w.guard.ownSession(id)
				return identityCookied(publicJSON(t, http.MethodPatch, "/auth/sessions/"+id,
					map[string]any{"checks": map[string]any{"password": map[string]any{"password": u.Password}}}), cookies)
			},
			requestSecrets:  []string{"checks.password.password"},
			responseSecrets: []string{"sessionToken"},
		},
		writeCase{
			route: "DELETE /auth/sessions/:id",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				s := w.beginSignIn(w.newUser(true))
				s.session()
				return identityCookied(publicRequest(http.MethodDelete, "/auth/sessions/"+s.sessionID, "", nil), s.cookies)
			},
		},
		writeCase{
			// The account picker. Whatever filter the body carries is replaced by the sessions in
			// the caller's cookie, so paging and sorting are all a caller can ask for.
			route: "POST /auth/sessions/search",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				s := w.beginSignIn(w.newUser(true))
				s.session()
				return identityCookied(publicJSON(t, http.MethodPost, "/auth/sessions/search", map[string]any{
					"query":         map[string]any{"limit": 20, "asc": true},
					"sortingColumn": "SESSION_FIELD_NAME_CREATION_DATE",
				}), s.cookies)
			},
		},
	)
}

// identityTOTP is the code an authenticator app shows for a secret at a moment (RFC 6238):
// HMAC-SHA1 over the 30 second step, six digits.
func identityTOTP(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.TrimRight(secret, "=")))
	if err != nil {
		t.Fatalf("the TOTP secret is not base32: %v", err)
	}
	var step [8]byte
	binary.BigEndian.PutUint64(step[:], uint64(at.Unix()/30)) //nolint:gosec // G115: a time after 1970
	mac := hmac.New(sha1.New, key)
	mac.Write(step[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	code := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", code%1_000_000)
}

// identityStartTOTP starts enrolling an authenticator app through the login page's route and
// returns the secret the app would be given.
func identityStartTOTP(t *testing.T, w *writeRun, s *signInSteps) string {
	t.Helper()
	started, _ := w.sendJSON(identityCookied(publicRequest(http.MethodPost, "/auth/users/"+s.user.ID+"/totp", "", nil), s.cookies))
	secret, _ := started["secret"].(string)
	if secret == "" {
		t.Fatalf("starting TOTP enrolment returned no secret: %v", keysOf(started))
	}
	return secret
}

// identityPublishUserHandle names the WebAuthn user handle in a fixture. The options the provider
// returns for a new credential identify the user by its identifier in base64url, a form of this
// run's user ID that the recorder's own rules do not recognise.
func identityPublishUserHandle(w *writeRun, u identityUser) {
	w.publishAs(base64.RawURLEncoding.EncodeToString([]byte(u.ID)), "<user-id-base64url>")
}

// What the login page lets a person do to their own account. The password routes are open to a
// caller who can prove the change (the current password, or a mailed code); the rest answer only
// to a browser whose cookie holds a session of that user.
func init() {
	registerWriteCases(
		writeCase{
			route: "POST /auth/users/:id/password",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				u := w.newUser(true)
				return publicJSON(t, http.MethodPost, "/auth/users/"+u.ID+"/password", map[string]any{
					"currentPassword": u.Password,
					"newPassword":     map[string]any{"password": "Golden-write-2!", "changeRequired": false},
				})
			},
			requestSecrets: []string{"currentPassword", "newPassword.password"},
		},
		writeCase{
			// The proxy builds what it forwards itself, so the request has no body. In the
			// notification mode a server runs in, the provider mails the link and returns nothing.
			route: "POST /auth/users/:id/password-reset",
			prepare: func(_ *testing.T, w *writeRun) *http.Request {
				return publicRequest(http.MethodPost, "/auth/users/"+w.newUser(true).ID+"/password-reset", "", nil)
			},
		},
		writeCase{
			// The code is the one the provider mails to a new address. Nobody is signed in yet
			// when a new account verifies its address, so this is sent without a session cookie.
			route: "POST /auth/users/:id/email",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				u := w.newUser(false)
				code, err := w.rec.owner.emailCode(context.Background(), u.ID, "verified."+u.Email)
				if err != nil {
					t.Fatalf("issue an email verification code: %v", err)
				}
				return publicJSON(t, http.MethodPost, "/auth/users/"+u.ID+"/email", map[string]any{"verificationCode": code})
			},
			requestSecrets: []string{"verificationCode"},
		},
		writeCase{
			// An invite code is what the provider mails a user invited without a password. Nobody
			// is signed in yet, so this too is sent without a session cookie. The user has no way
			// to sign in yet, so the answer says to set one up and records the verification.
			route: "POST /auth/users/:id/invite-code/verify",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				u, code := w.newInvitedUser()
				return publicJSON(t, http.MethodPost, "/auth/users/"+u.ID+"/invite-code/verify", map[string]any{"verificationCode": code})
			},
			requestSecrets: []string{"verificationCode"},
		},
		writeCase{
			route: "POST /auth/users/:id/totp",
			prepare: func(_ *testing.T, w *writeRun) *http.Request {
				s := w.beginSignIn(w.newUser(true))
				s.session()
				return identityCookied(publicRequest(http.MethodPost, "/auth/users/"+s.user.ID+"/totp", "", nil), s.cookies)
			},
			responseSecrets: []string{"secret", "uri"},
		},
		writeCase{
			route: "POST /auth/users/:id/totp/verify",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				s := w.beginSignIn(w.newUser(true))
				s.session()
				code := identityTOTP(t, identityStartTOTP(t, w, s), time.Now())
				return identityCookied(publicJSON(t, http.MethodPost, "/auth/users/"+s.user.ID+"/totp/verify",
					map[string]any{"code": code}), s.cookies)
			},
			requestSecrets: []string{"code"},
		},
		writeCase{
			// Codes by mail as a second factor. The provider enables it only for an address
			// that is verified, and needs nothing else from the caller.
			route: "POST /auth/users/:id/otp-email",
			prepare: func(_ *testing.T, w *writeRun) *http.Request {
				s := w.beginSignIn(w.newUser(true))
				s.session()
				return identityCookied(publicRequest(http.MethodPost, "/auth/users/"+s.user.ID+"/otp-email", "", nil), s.cookies)
			},
		},
		writeCase{
			// Starting a passkey needs no authenticator: the answer is the challenge the
			// browser hands to one. `domain` is the host the login page is served from, which
			// the passkey is bound to.
			route: "POST /auth/users/:id/passkeys",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				s := w.beginSignIn(w.newUser(true))
				s.session()
				identityPublishUserHandle(w, s.user)
				return identityCookied(publicJSON(t, http.MethodPost, "/auth/users/"+s.user.ID+"/passkeys",
					map[string]any{"domain": "localhost", "authenticator": "PASSKEY_AUTHENTICATOR_UNSPECIFIED"}), s.cookies)
			},
			// A fresh random value on every call, for the authenticator to sign. Not a secret.
			responseVaries: []string{"publicKeyCredentialCreationOptions.publicKey.challenge"},
		},
		writeCase{
			// The same first step for a security key used as a second factor.
			route: "POST /auth/users/:id/u2f",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				s := w.beginSignIn(w.newUser(true))
				s.session()
				identityPublishUserHandle(w, s.user)
				return identityCookied(publicJSON(t, http.MethodPost, "/auth/users/"+s.user.ID+"/u2f",
					map[string]any{"domain": "localhost"}), s.cookies)
			},
			responseVaries: []string{"publicKeyCredentialCreationOptions.publicKey.challenge"},
		},
		writeCase{
			// Codes by text message as a second factor. The provider enables it only for a user
			// with a verified phone number, which no route of the proxy can set: the throwaway
			// user is created with one. Enabling sends nothing.
			route: "POST /auth/users/:id/otp-sms",
			prepare: func(_ *testing.T, w *writeRun) *http.Request {
				s := w.beginSignIn(w.newUserWithPhone())
				s.session()
				return identityCookied(publicRequest(http.MethodPost, "/auth/users/"+s.user.ID+"/otp-sms", "", nil), s.cookies)
			},
		},
	)
}

// The identity routes that are named instead of recorded.
func init() {
	nameWrites(map[string]namedWrite{
		"POST /auth/users": {
			reason: needsInstanceSetting,
			detail: "Self sign-up is accepted only while the login policy of the identity provider allows registration, a setting shared by everyone who signs in to the instance. Success needs that setting to allow it, and creates an account that only an administrator of the identity provider can remove.",
		},
		// The certain requirement is a provider that has been set up. One the recorder may act on
		// would be one it set up itself, and that is configuration of the whole instance.
		"POST /auth/idp/start": {
			reason: needsInstanceSetting,
			detail: "The body names an external identity provider (`idpId`), and the answer is the address at that provider the browser is sent to. Success needs an administrator to have set such a provider up at the identity provider, where it is offered to everyone who signs in to the instance.",
		},
		"POST /auth/idp/complete/:intentId": {
			reason: needsOutsideSystem,
			detail: "The intent in the path and the `idpIntentToken` in the body are handed to the browser by the external identity provider's callback, after a person has signed in there. Success needs that sign-in to have happened.",
		},
		"POST /auth/users/:id/passkeys/:pkId": {
			reason: needsAuthenticator,
			detail: "The body is the credential an authenticator creates for the challenge that `POST /auth/users/{id}/passkeys` returned, signed by the authenticator. Success needs a passkey to produce it.",
		},
		"POST /auth/users/:id/u2f/:u2fId": {
			reason: needsAuthenticator,
			detail: "The body is the credential a security key creates for the challenge that `POST /auth/users/{id}/u2f` returned, signed by the key. Success needs a security key to produce it.",
		},
	})
}

// identityJSON builds a JSON request the signed-in user sends. These routes refuse every API
// token, the recorder's own included, so the cases below go as a person who signed in.
func identityJSON(t *testing.T, sess identitySession, method, target string, body any) *http.Request {
	t.Helper()
	if body == nil {
		return sess.as(publicRequest(method, target, "", nil))
	}
	return sess.as(publicJSON(t, method, target, body))
}

// identityEnrolTOTP starts enrolling an authenticator app from the settings page and returns the
// code the app would show.
func identityEnrolTOTP(t *testing.T, w *writeRun, sess identitySession) string {
	t.Helper()
	started, _ := w.sendJSON(identityJSON(t, sess, http.MethodPost, "/api/v2/settings/2fa/start", nil))
	meta, _ := started["meta"].(map[string]any)
	secret, _ := meta["secret"].(string)
	if secret == "" {
		t.Fatalf("starting TOTP enrolment returned no secret: %v", keysOf(started))
	}
	return identityTOTP(t, secret, time.Now())
}

// identityJoinOrganization makes the signed-in user a member of the seeded organization and
// returns the organization's UUID. An API key is bound to one organization its owner belongs to,
// and a user who has only just signed in belongs to none.
func identityJoinOrganization(t *testing.T, w *writeRun, sess identitySession) string {
	t.Helper()
	// The first authenticated request is what gives the user a row here.
	account, _ := w.sendJSON(identityJSON(t, sess, http.MethodGet, "/api/v2/account/details", nil))
	userID := dataID(t, account)
	var orgID string
	if err := w.db.Raw(`SELECT id::text FROM organizations WHERE name = ?`, w.org()).Scan(&orgID).Error; err != nil || orgID == "" || userID == "" {
		t.Fatalf("resolve the seeded organization (%q) and the signed-in user (%q): %v", orgID, userID, err)
	}
	err := w.db.Exec(`INSERT INTO organization_members (id, organization_id, user_id, created_at) VALUES (uuid_generate_v4(), ?, ?, now())`,
		orgID, userID).Error
	if err != nil {
		t.Fatalf("add the signed-in user to the seeded organization: %v", err)
	}
	return orgID
}

// identityAPIKey is the document the settings page sends for a key that may read and write one
// organization.
func identityAPIKey(orgID string) map[string]any {
	return document("api-keys", map[string]any{
		"name":       "ci-pipeline",
		"scopes":     []string{"org:" + orgID + ":read", "org:" + orgID + ":write"},
		"expires-at": "2030-01-01T00:00:00Z",
	})
}

// A person's own account, from the settings pages.
func init() {
	registerWriteCases(
		writeCase{
			// The profile is part of the account's users resource (#858, D8).
			route: "PATCH /api/v2/account/update",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				sess := w.signIn(w.newUser(true))
				return identityJSON(t, sess, http.MethodPatch, "/api/v2/account/update", document("users", map[string]any{
					"name":     "Golden Recorder",
					"email":    "golden.recorder@stackweaver.local",
					"username": sess.User.Username,
					"bio":      "Recorded by the golden write harness",
					"company":  "VH & Co",
					"location": "Antwerp, Belgium",
				}))
			},
		},
		writeCase{
			route: "POST /api/v2/settings/password",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				sess := w.signIn(w.newUser(true))
				return identityJSON(t, sess, http.MethodPost, "/api/v2/settings/password", document("users", map[string]any{
					"current-password": sess.User.Password,
					"new-password":     "Golden-write-2!",
				}))
			},
			requestSecrets: []string{"data.attributes.current-password", "data.attributes.new-password"},
		},
		writeCase{
			route: "POST /api/v2/settings/2fa/start",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return identityJSON(t, w.signIn(w.newUser(true)), http.MethodPost, "/api/v2/settings/2fa/start", nil)
			},
			responseSecrets: []string{"meta.secret", "meta.url"},
		},
		writeCase{
			route: "POST /api/v2/settings/2fa/verify",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				sess := w.signIn(w.newUser(true))
				return identityJSON(t, sess, http.MethodPost, "/api/v2/settings/2fa/verify",
					document("two-factor", map[string]any{"code": identityEnrolTOTP(t, w, sess)}))
			},
			requestSecrets: []string{"data.attributes.code"},
		},
		writeCase{
			route: "DELETE /api/v2/settings/2fa",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				sess := w.signIn(w.newUser(true))
				w.sendJSON(identityJSON(t, sess, http.MethodPost, "/api/v2/settings/2fa/verify",
					document("two-factor", map[string]any{"code": identityEnrolTOTP(t, w, sess)})))
				return identityJSON(t, sess, http.MethodDelete, "/api/v2/settings/2fa", nil)
			},
		},
		writeCase{
			// Signing out another device: a second session of the same user, revoked from the
			// first.
			route: "DELETE /api/v2/settings/sessions/:sessionId",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				sess := w.signIn(w.newUser(true))
				other := w.beginSignIn(sess.User)
				other.session()
				// The handler refuses a session it cannot find in the user's list, and the
				// provider's list is a projection that trails the write by a moment.
				deadline := time.Now().Add(10 * time.Second)
				for {
					rec := w.send(identityJSON(t, sess, http.MethodGet, "/api/v2/settings/sessions", nil))
					if rec.Code == http.StatusOK && strings.Contains(rec.Body.String(), other.sessionID) {
						break
					}
					if time.Now().After(deadline) {
						t.Fatalf("the second session is not in the user's session list after 10s (last answer %d: %s)", rec.Code, rec.Body.String())
					}
					time.Sleep(150 * time.Millisecond)
				}
				return identityJSON(t, sess, http.MethodDelete, "/api/v2/settings/sessions/"+other.sessionID, nil)
			},
		},
		writeCase{
			route: "POST /api/v2/settings/api-keys",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				sess := w.signIn(w.newUser(true))
				return identityJSON(t, sess, http.MethodPost, "/api/v2/settings/api-keys",
					identityAPIKey(identityJoinOrganization(t, w, sess)))
			},
			// The prefix is the first characters of the key itself.
			responseSecrets: []string{"data.attributes.key", "data.attributes.key-prefix"},
		},
		writeCase{
			route: "DELETE /api/v2/settings/api-keys/:id",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				sess := w.signIn(w.newUser(true))
				created, _ := w.sendJSON(identityJSON(t, sess, http.MethodPost, "/api/v2/settings/api-keys",
					identityAPIKey(identityJoinOrganization(t, w, sess))))
				id := dataID(t, created)
				return identityJSON(t, sess, http.MethodDelete, "/api/v2/settings/api-keys/"+id, nil)
			},
		},
	)
}

// The tokens a signed-in person mints for themselves: the browser half of `terraform login`,
// and the user tokens of the token page.
func init() {
	registerWriteCases(
		writeCase{
			// What the consent page sends after `terraform login` opened it: the CLI's PKCE
			// challenge and the loopback address it listens on. The code in the answer is what
			// the CLI exchanges for a token.
			route: "POST /api/v2/oauth/authorize",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return identityJSON(t, w.signIn(w.newUser(true)), http.MethodPost, "/api/v2/oauth/authorize", map[string]any{
					"client_id":             "terraform-cli",
					"redirect_uri":          "http://localhost:10000/login",
					"code_challenge":        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
					"code_challenge_method": "S256",
					"state":                 "9c1f6a52-terraform-login",
				})
			},
			responseSecrets: []string{"code"},
		},
		writeCase{
			route: "POST /api/v2/tokens",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return identityJSON(t, w.signIn(w.newUser(true)), http.MethodPost, "/api/v2/tokens", document("tokens", map[string]any{
					"description": "Laptop CLI",
					"expires_at":  "2030-01-01T00:00:00Z",
				}))
			},
			responseSecrets: []string{"data.attributes.token"},
		},
		writeCase{
			route: "DELETE /api/v2/tokens/:id",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				sess := w.signIn(w.newUser(true))
				created, _ := w.sendJSON(identityJSON(t, sess, http.MethodPost, "/api/v2/tokens",
					document("tokens", map[string]any{"description": "Laptop CLI"})))
				return identityJSON(t, sess, http.MethodDelete, "/api/v2/tokens/"+dataID(t, created), nil)
			},
		},
	)
}
