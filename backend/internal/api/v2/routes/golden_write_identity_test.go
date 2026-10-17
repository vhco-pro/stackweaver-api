// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// The golden write recorder and the identity provider (#869).
//
// 27 mutating routes go through Zitadel, and five more admit only a caller who signed in
// interactively. Zitadel's state cannot be copied per case the way the database is, and it has
// no slots: every session on the machine shares the one the dev stack runs. So the recorder
// works under one rule. A write that goes through the identity provider acts only on an identity
// the recorder created in the same run, which it removes afterwards. The owner's admin user is
// the case that matters: a password change or a session revocation on it would lock them out.
//
// Two things enforce the rule rather than trusting every case to keep it. identityGuard looks at
// each request before it reaches the router and refuses one that names an identity the run did
// not create. ownerClient, the only holder of a token that could change an instance-wide
// setting, can reach five operations and nothing else.

//go:build integration
// +build integration

package routes_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	v2handlers "github.com/michielvha/stackweaver/backend/internal/api/v2/handlers"
)

const (
	envWriteIdentityEnv    = "GOLDEN_WRITE_IDENTITY_ENV"     // path of the dev stack's deploy/.env
	envWriteIdentityAddr   = "GOLDEN_WRITE_IDENTITY_ADDR"    // where a host process reaches the provider
	envWriteOwnerTokenFile = "GOLDEN_WRITE_OWNER_TOKEN_FILE" //nolint:gosec // G101: a path, not a credential

	// identityUserRoot starts the user name of every identity any recorder run creates. A run
	// adds a part of its own, and deletes only what carries both.
	identityUserRoot = "sw-golden-write-"
	// identityRedirectURI is registered for the frontend client by zitadel-init on every stack.
	identityRedirectURI = "http://localhost:5173/auth/callback"
	// identityLeftoverAge is older than any run can be. A user under the root prefix that is
	// older than this belongs to a run that died, and is swept; a younger one may belong to
	// another session's run and is left alone.
	identityLeftoverAge = 2 * time.Hour

	identityAdvice = "run it through `make test-integration` or `make record-golden-writes` in a worktree slot with the dev stack up"
)

// writeIdentity is where the identity provider is and what the recorder may present to it.
type writeIdentity struct {
	Issuer           string // what the provider calls itself in the tokens it issues
	Addr             string // host:port a host process reaches it at
	InstanceHost     string // the host name the provider routes an instance on
	LoginToken       string // the login-client token the API's own proxy uses
	OwnerToken       string // the IAM_OWNER token, for ownerClient only
	APIClientID      string
	APIClientSecret  string
	FrontendClientID string
}

// writeIdentityFromEnv reads the identity settings from the dev stack's own files, by the paths
// `make` passes. The values never travel on a command line.
func writeIdentityFromEnv() (writeIdentity, error) {
	var id writeIdentity
	envFile, tokenFile := os.Getenv(envWriteIdentityEnv), os.Getenv(envWriteOwnerTokenFile)
	if envFile == "" || tokenFile == "" {
		return id, fmt.Errorf("%s and %s are not both set; %s", envWriteIdentityEnv, envWriteOwnerTokenFile, identityAdvice)
	}
	vars, err := readEnvFile(envFile)
	if err != nil {
		return id, fmt.Errorf("reading the dev stack's identity settings: %w", err)
	}
	token, err := os.ReadFile(tokenFile) //nolint:gosec // a path the Makefile supplies
	if err != nil {
		return id, fmt.Errorf("reading the owner token: %w", err)
	}
	id = writeIdentity{
		Issuer:           vars["ZITADEL_ISSUER"],
		Addr:             os.Getenv(envWriteIdentityAddr),
		InstanceHost:     vars["ZITADEL_EXTERNAL_HOST"],
		LoginToken:       vars["ZITADEL_LOGIN_SERVICE_USER_TOKEN"],
		OwnerToken:       strings.TrimSpace(string(token)),
		APIClientID:      vars["ZITADEL_API_CLIENT_ID"],
		APIClientSecret:  vars["ZITADEL_API_CLIENT_SECRET"],
		FrontendClientID: vars["ZITADEL_FRONTEND_CLIENT_ID"],
	}
	for name, value := range map[string]string{
		"ZITADEL_ISSUER": id.Issuer, envWriteIdentityAddr: id.Addr, "ZITADEL_LOGIN_SERVICE_USER_TOKEN": id.LoginToken,
		"the owner token": id.OwnerToken, "ZITADEL_API_CLIENT_ID": id.APIClientID, "ZITADEL_FRONTEND_CLIENT_ID": id.FrontendClientID,
	} {
		if value == "" {
			return id, fmt.Errorf("%s is empty; %s", name, identityAdvice)
		}
	}
	return id, nil
}

// readEnvFile reads NAME=value lines, the format zitadel-init writes deploy/.env in.
func readEnvFile(path string) (map[string]string, error) {
	f, err := os.Open(path) //nolint:gosec // a path the Makefile supplies
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	out := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		name, value, ok := strings.Cut(line, "=")
		if !ok || strings.HasPrefix(line, "#") {
			continue
		}
		out[strings.TrimSpace(name)] = strings.Trim(strings.TrimSpace(value), `"'`)
	}
	return out, sc.Err()
}

// harness is the identity configuration a write case's router is built with: what
// scripts/worktree-dev.sh gives a slot's API, and the notification mode a server falls back to.
func (id writeIdentity) harness() harnessIdentity {
	h := harnessIdentity{
		Issuer:           id.Issuer,
		InternalAddr:     id.Addr,
		PAT:              id.LoginToken,
		NotificationMode: v2handlers.NotificationModeEmail,
	}
	if id.InstanceHost != "" {
		h.CustomRequestHeaders = "x-zitadel-instance-host:" + id.InstanceHost
	}
	return h
}

// --- the owner client ------------------------------------------------------------------------

var (
	ownerUserPath   = regexp.MustCompile(`^/v2/users/[0-9]+$`)
	ownerEmailPath  = regexp.MustCompile(`^/v2/users/[0-9]+/email$`)
	ownerInvitePath = regexp.MustCompile(`^/v2/users/[0-9]+/invite_code$`)
)

// ownerOperation names the one of the five things the owner token may do that a request is, or
// "" for anything else.
func ownerOperation(method, path string) string {
	switch {
	case method == http.MethodPost && path == "/v2/users/human":
		return "create a user"
	case method == http.MethodDelete && ownerUserPath.MatchString(path):
		return "delete a user"
	case method == http.MethodPost && ownerEmailPath.MatchString(path):
		return "issue an email code"
	case method == http.MethodPost && ownerInvitePath.MatchString(path):
		return "issue an invite code"
	case method == http.MethodPost && path == "/v2/users":
		return "search users"
	}
	return ""
}

// ownerClient talks to the identity provider with the IAM_OWNER token.
//
// That token can change anything on the instance, which every session on the machine shares, so
// this is deliberately not a general client. Every request goes through do, and do refuses
// whatever is not one of five operations.
type ownerClient struct {
	base  string
	host  string
	token string
	http  *http.Client
	// created is the users this run made, by ID. Deleting is refused for any other.
	created map[string]bool
}

func newOwnerClient(id writeIdentity) *ownerClient {
	return &ownerClient{
		base: "http://" + id.Addr, host: id.InstanceHost, token: id.OwnerToken,
		http: &http.Client{Timeout: 15 * time.Second}, created: map[string]bool{},
	}
}

func (o *ownerClient) do(ctx context.Context, method, path string, body any) (int, map[string]any, error) {
	if ownerOperation(method, path) == "" {
		return 0, nil, fmt.Errorf("the owner token is not used for %s %s: it may only create a user, delete a user, issue an email code and search users", method, path)
	}
	var raw []byte
	if body != nil {
		var err error
		if raw, err = json.Marshal(body); err != nil {
			return 0, nil, err
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, o.base+path, bytes.NewReader(raw))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+o.token)
	req.Header.Set("Content-Type", "application/json")
	if o.host != "" {
		req.Header.Set("x-zitadel-instance-host", o.host)
	}
	resp, err := o.http.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, nil, err
	}
	var out map[string]any
	if len(data) > 0 {
		if err := json.Unmarshal(data, &out); err != nil {
			return resp.StatusCode, nil, fmt.Errorf("%s %s answered %d with a body that is not JSON: %s", method, path, resp.StatusCode, data)
		}
	}
	return resp.StatusCode, out, nil
}

// identityUser is a user the recorder made for one case.
type identityUser struct {
	ID        string
	Username  string
	LoginName string
	Email     string
	Password  string
}

// identityPassword is the password every throwaway user is created with. It is a credential a
// case sends, so a case that sends it declares it and the fixture carries the placeholder.
const identityPassword = "Golden-write-1!" //nolint:gosec // G101: a throwaway user on a dev stack

// createUser makes a user and does not return until it can be found the way a sign-in finds it.
//
// Zitadel is event-sourced: the create returns once the event is stored, and the projections a
// sign-in reads catch up a moment later. A sign-in in that window answers "user not found", and
// the auth proxy turns that into a decoy session that fails later and far from here.
//
// phone, when not empty, is given to the user as an already verified number: what a second
// factor by text message requires, and something no route of the proxy can set.
func (o *ownerClient) createUser(ctx context.Context, username string, emailVerified bool, phone string) (identityUser, error) {
	return o.createUserWith(ctx, username, emailVerified, phone, identityPassword)
}

// createUserWith is createUser with the password to give the user; "" creates a user with no
// password, which is the user an invitation is for.
func (o *ownerClient) createUserWith(ctx context.Context, username string, emailVerified bool, phone, password string) (identityUser, error) {
	u := identityUser{Username: username, Email: username + "@stackweaver.local", Password: password}
	body := map[string]any{
		"username": username,
		"profile":  map[string]any{"givenName": "Golden", "familyName": "Write"},
		"email":    map[string]any{"email": u.Email, "isVerified": emailVerified},
	}
	if password != "" {
		body["password"] = map[string]any{"password": password, "changeRequired": false}
	}
	if phone != "" {
		body["phone"] = map[string]any{"phone": phone, "isVerified": true}
	}
	status, data, err := o.do(ctx, http.MethodPost, "/v2/users/human", body)
	if err != nil {
		return u, fmt.Errorf("creating user %s: %w", username, err)
	}
	if status != http.StatusOK && status != http.StatusCreated {
		return u, fmt.Errorf("creating user %s answered %d: %v", username, status, data)
	}
	u.ID, _ = data["userId"].(string)
	if u.ID == "" {
		return u, fmt.Errorf("creating user %s returned no userId: %v", username, data)
	}
	o.created[u.ID] = true

	// The provider is shared, and under load its projections have been seen to take longer than
	// twenty seconds to show a new user.
	const wait = 45 * time.Second
	deadline := time.Now().Add(wait)
	for {
		found, err := o.search(ctx, map[string]any{"userNameQuery": map[string]any{"userName": username, "method": "TEXT_QUERY_METHOD_EQUALS"}})
		if err == nil && len(found) == 1 && found[0].LoginName != "" {
			// And by login name, which is how a session resolves it: a different projection.
			byLogin, err := o.search(ctx, map[string]any{"loginNameQuery": map[string]any{"loginName": found[0].LoginName}})
			if err == nil && len(byLogin) == 1 && byLogin[0].ID == u.ID {
				u.LoginName = found[0].LoginName
				return u, nil
			}
		}
		if time.Now().After(deadline) {
			return u, fmt.Errorf("user %s (%s) was created and could not be found by its login name after %s (last error: %v)", username, u.ID, wait, err)
		}
		time.Sleep(150 * time.Millisecond)
	}
}

type foundUser struct {
	ID        string
	Username  string
	LoginName string
	Created   time.Time
}

func (o *ownerClient) search(ctx context.Context, query map[string]any) ([]foundUser, error) {
	status, data, err := o.do(ctx, http.MethodPost, "/v2/users", map[string]any{"queries": []any{query}})
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("searching users answered %d: %v", status, data)
	}
	results, _ := data["result"].([]any)
	out := make([]foundUser, 0, len(results))
	for _, r := range results {
		m, _ := r.(map[string]any)
		f := foundUser{}
		f.ID, _ = m["userId"].(string)
		f.Username, _ = m["username"].(string)
		f.LoginName, _ = m["preferredLoginName"].(string)
		if details, _ := m["details"].(map[string]any); details != nil {
			if created, _ := details["creationDate"].(string); created != "" {
				f.Created, _ = time.Parse(time.RFC3339Nano, created)
			}
		}
		out = append(out, f)
	}
	return out, nil
}

// searchPrefix lists the users whose name starts with prefix.
func (o *ownerClient) searchPrefix(ctx context.Context, prefix string) ([]foundUser, error) {
	if !strings.HasPrefix(prefix, identityUserRoot) {
		return nil, fmt.Errorf("the recorder searches only under %q, not %q", identityUserRoot, prefix)
	}
	return o.search(ctx, map[string]any{"userNameQuery": map[string]any{"userName": prefix, "method": "TEXT_QUERY_METHOD_STARTS_WITH"}})
}

// deleteUser removes a user this run created.
func (o *ownerClient) deleteUser(ctx context.Context, id string) error {
	if !o.created[id] {
		return fmt.Errorf("user %s was not created by this run and is not deleted by it", id)
	}
	return o.remove(ctx, id)
}

func (o *ownerClient) remove(ctx context.Context, id string) error {
	status, data, err := o.do(ctx, http.MethodDelete, "/v2/users/"+id, nil)
	if err != nil {
		return fmt.Errorf("deleting user %s: %w", id, err)
	}
	if status != http.StatusOK && status != http.StatusNotFound {
		return fmt.Errorf("deleting user %s answered %d: %v", id, status, data)
	}
	delete(o.created, id)
	return nil
}

// sweepLeftovers deletes users under the recorder's root prefix that are older than any run can
// be: what a run that was killed left behind. A younger one may be in use by another session's
// run right now and is not touched.
func (o *ownerClient) sweepLeftovers(ctx context.Context) (int, error) {
	found, err := o.searchPrefix(ctx, identityUserRoot)
	if err != nil {
		return 0, err
	}
	swept := 0
	for _, u := range found {
		if u.Created.IsZero() || time.Since(u.Created) < identityLeftoverAge || !strings.HasPrefix(u.Username, identityUserRoot) {
			continue
		}
		if err := o.remove(ctx, u.ID); err != nil {
			return swept, err
		}
		swept++
	}
	return swept, nil
}

// emailCode makes the provider issue a verification code for a user this run created and
// returns it, the way the provider's own API hands it to an administrator. The address has to be
// a new one: setting the address a user already has is a no-op that issues nothing.
func (o *ownerClient) emailCode(ctx context.Context, id, newEmail string) (string, error) {
	if !o.created[id] {
		return "", fmt.Errorf("user %s was not created by this run", id)
	}
	status, data, err := o.do(ctx, http.MethodPost, "/v2/users/"+id+"/email", map[string]any{"email": newEmail, "returnCode": map[string]any{}})
	if err != nil {
		return "", err
	}
	code, _ := data["verificationCode"].(string)
	if status != http.StatusOK || code == "" {
		return "", fmt.Errorf("issuing an email code for %s answered %d with no code: %v", id, status, data)
	}
	return code, nil
}

// inviteCode issues an invite code for a user the run created, returned rather than mailed.
func (o *ownerClient) inviteCode(ctx context.Context, id string) (string, error) {
	if !o.created[id] {
		return "", fmt.Errorf("user %s was not created by this run", id)
	}
	status, data, err := o.do(ctx, http.MethodPost, "/v2/users/"+id+"/invite_code", map[string]any{"returnCode": map[string]any{}})
	if err != nil {
		return "", err
	}
	code, _ := data["inviteCode"].(string)
	if status != http.StatusOK || code == "" {
		return "", fmt.Errorf("issuing an invite code for %s answered %d with no code: %v", id, status, data)
	}
	return code, nil
}

// --- the guard -------------------------------------------------------------------------------

// identityGuard knows which identities this run created and refuses a request that names any
// other. It sees every request a case sends, the preparation included.
type identityGuard struct {
	users      map[string]bool // provider user IDs
	loginNames map[string]bool
	sessions   map[string]bool
}

func newIdentityGuard() *identityGuard {
	return &identityGuard{users: map[string]bool{}, loginNames: map[string]bool{}, sessions: map[string]bool{}}
}

func (g *identityGuard) ownUser(u identityUser) {
	g.users[u.ID] = true
	g.loginNames[u.LoginName] = true
	g.loginNames[u.Username] = true
	g.loginNames[u.Email] = true
}

func (g *identityGuard) ownSession(id string) { g.sessions[id] = true }

var (
	guardUserPath     = regexp.MustCompile(`^/auth/users/([^/]+)`)
	guardSessionPath  = regexp.MustCompile(`^/auth/sessions/([^/]+)$`)
	guardSettingsPath = regexp.MustCompile(`^/api/v2/settings/sessions/([^/]+)$`)
)

// check returns an error for a request that names a user, a login name, a session or a token
// subject this run did not create.
func (g *identityGuard) check(req *http.Request, body []byte) error {
	path := req.URL.Path
	if m := guardUserPath.FindStringSubmatch(path); m != nil && !g.users[m[1]] {
		return fmt.Errorf("%s %s names user %s, which this run did not create", req.Method, path, m[1])
	}
	for _, re := range []*regexp.Regexp{guardSessionPath, guardSettingsPath} {
		// "search" is the one non-identifier under /auth/sessions.
		if m := re.FindStringSubmatch(path); m != nil && m[1] != "search" && !g.sessions[m[1]] {
			return fmt.Errorf("%s %s names session %s, which this run did not create", req.Method, path, m[1])
		}
	}

	// A bearer that is a JWT was issued by the provider to somebody. An API token is not one.
	if bearer, ok := strings.CutPrefix(req.Header.Get("Authorization"), "Bearer "); ok {
		if sub, isJWT := jwtSubject(bearer); isJWT && !g.users[sub] {
			return fmt.Errorf("%s %s is sent with a token whose subject %q this run did not create", req.Method, path, sub)
		}
	}

	// A body is read for identities only on the routes that take one to the identity provider.
	// Elsewhere the same member names mean other things: an SMTP `username` in a notification
	// template is not a login name, and refusing it stopped a case that had nothing to do with
	// the provider.
	// The settings routes need no such reading: they act on whoever the token belongs to, which
	// the check above already holds to this run.
	if !strings.HasPrefix(path, "/auth/") {
		return nil
	}
	if len(body) == 0 || !strings.Contains(req.Header.Get("Content-Type"), "json") {
		return nil
	}
	var parsed any
	if json.Unmarshal(body, &parsed) != nil {
		return nil
	}
	return g.checkValue(req, parsed)
}

// checkValue walks a JSON body for the members the identity routes name an identity with.
func (g *identityGuard) checkValue(req *http.Request, v any) error {
	switch t := v.(type) {
	case map[string]any:
		for name, val := range t {
			if s, ok := val.(string); ok && s != "" {
				var owned map[string]bool
				var kind string
				switch name {
				case "loginName", "login_name", "username", "userName":
					owned, kind = g.loginNames, "login name"
				case "userId", "user_id", "userID":
					owned, kind = g.users, "user"
				case "sessionId", "session_id", "sessionID":
					owned, kind = g.sessions, "session"
				}
				if owned != nil && !owned[s] {
					return fmt.Errorf("%s %s names %s %q in its body, which this run did not create", req.Method, req.URL.Path, kind, s)
				}
			}
			if err := g.checkValue(req, val); err != nil {
				return err
			}
		}
	case []any:
		for _, val := range t {
			if err := g.checkValue(req, val); err != nil {
				return err
			}
		}
	}
	return nil
}

// jwtSubject returns the `sub` of a token that has the shape of a JWT.
func jwtSubject(token string) (sub string, isJWT bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", false
	}
	var claims struct {
		Sub string `json:"sub"`
	}
	if json.Unmarshal(payload, &claims) != nil {
		return "", false
	}
	return claims.Sub, true
}

// --- what differs between runs ---------------------------------------------------------------------

// identityNormaliser replaces, in a write fixture, the values that are this run's own at the
// identity provider, so that two recordings of one case are the same file.
//
// The read fixtures' normalise does not do this and is left as it is: the provider's
// identifiers are plain decimal numbers, which it has no rule for, and existing fixtures pin
// values a new rule there would change.
//
// It works from what the recorder knows. Every user and session a case created is a value in
// hand, so each is replaced exactly, wherever it appears and inside whatever string. Two rules
// cover what the provider generates and a case never sees: its identifiers, which are decimal
// strings of a length nothing else in these bodies has, and its sequence numbers.
type identityNormaliser struct {
	known [][2]string // value, placeholder: longest value first
	// provider is set when the case touched the identity provider, which is when the two rules
	// for what the provider generates apply. A case that only published a stand-in's address
	// gets its known values replaced and nothing else.
	provider bool
	// from and to bound the run in Unix seconds. A ten-digit number inside a string that falls
	// between them is the server's clock, read while the case ran: the workflow engine names a
	// run "<workflow> #<unix time>". It is a time like any RFC 3339 one the other rules replace,
	// in a form they do not know. Zero means no window, and nothing is replaced.
	from, to int64
}

var tenDigits = regexp.MustCompile(`\b[0-9]{10}\b`)

var providerID = regexp.MustCompile(`^[0-9]{15,20}$`)

// identityNormaliser is nil for a case that created nothing at the identity provider, and a nil
// one changes nothing.
func (w *writeRun) identityNormaliser() *identityNormaliser {
	n := &identityNormaliser{provider: len(w.users) > 0 || len(w.guard.sessions) > 0}
	if w.rec != nil {
		// A minute either side: the database's clock and this process's are not the same clock.
		n.from, n.to = w.rec.started.Unix()-60, time.Now().Unix()+60
	}
	if !n.provider && len(w.published) == 0 && n.from == 0 {
		return nil
	}
	n.known = append(n.known, w.published...)
	add := func(value, placeholder string) {
		if value != "" {
			n.known = append(n.known, [2]string{value, placeholder})
		}
	}
	for _, u := range w.users {
		add(u.LoginName, "<login-name>")
		add(u.Email, "<email>")
		add(u.Username, "<username>")
		add(u.ID, "<user-id>")
	}
	for id := range w.guard.sessions {
		add(id, "<session-id>")
	}
	// Longest first: a login name contains the user name, and must not be left half replaced.
	sort.Slice(n.known, func(i, j int) bool {
		if len(n.known[i][0]) != len(n.known[j][0]) {
			return len(n.known[i][0]) > len(n.known[j][0])
		}
		return n.known[i][0] < n.known[j][0]
	})
	return n
}

func (n *identityNormaliser) text(s string) string {
	if n == nil {
		return s
	}
	for _, kv := range n.known {
		s = strings.ReplaceAll(s, kv[0], kv[1])
	}
	if n.provider && providerID.MatchString(s) {
		return "<id>"
	}
	if n.from != 0 {
		s = tenDigits.ReplaceAllStringFunc(s, func(digits string) string {
			if at, err := strconv.ParseInt(digits, 10, 64); err == nil && at >= n.from && at <= n.to {
				return "<unix-time>"
			}
			return digits
		})
	}
	return s
}

// apply rewrites a decoded JSON value in place and returns it. Array order is kept.
func (n *identityNormaliser) apply(v any) any {
	if n == nil {
		return v
	}
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			if k == "sequence" && n.provider {
				// The provider's event counter: a string on the wire, different on every call.
				if _, isString := val.(string); isString {
					t[k] = "<sequence>"
					continue
				}
			}
			t[k] = n.apply(val)
		}
		return t
	case []any:
		for i, val := range t {
			t[i] = n.apply(val)
		}
		return t
	case string:
		return n.text(t)
	default:
		return v
	}
}

// --- signing in --------------------------------------------------------------------------------

// identitySession is a signed-in throwaway user: what a browser holds after the login page.
type identitySession struct {
	User         identityUser
	SessionID    string
	SessionToken string
	AccessToken  string // a JWT the interactive-only routes accept
	Cookies      []*http.Cookie
}

// pkcePair is a PKCE verifier and its S256 challenge.
func pkcePair() (verifier, challenge string) {
	raw := make([]byte, 32)
	_, _ = rand.Read(raw)
	verifier = base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

// authorizeTarget is the authorize request the login page starts from.
func authorizeTarget(clientID, challenge string) string {
	q := url.Values{
		"client_id":             {clientID},
		"redirect_uri":          {identityRedirectURI},
		"response_type":         {"code"},
		"scope":                 {"openid profile email"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"state":                 {"golden-write"},
	}
	return "/auth/oidc/authorize?" + q.Encode()
}

// sessionBody is what the login page posts to check a login name and a password.
func sessionBody(u identityUser) map[string]any {
	return map[string]any{"checks": map[string]any{
		"user":     map[string]any{"loginName": u.LoginName},
		"password": map[string]any{"password": u.Password},
	}}
}

// tokenForm is the code exchange the callback page posts.
func tokenForm(clientID, code, verifier string) url.Values {
	return url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {clientID},
		"redirect_uri":  {identityRedirectURI},
		"code":          {code},
		"code_verifier": {verifier},
	}
}

// randomHex is n random bytes as hex, for the part of a user name that is unique to a run.
func randomHex(n int) string {
	raw := make([]byte, n)
	_, _ = rand.Read(raw)
	return hex.EncodeToString(raw)
}

// newUser creates a throwaway user for this case and makes it this run's own: the guard lets
// requests naming it through, and the case's cleanup deletes it.
//
// A user per case, and not one for the run: cases change the user (a password, a second factor,
// its sessions) and run in a shuffled order, so a shared user would make a fixture depend on
// what ran before it.
func (w *writeRun) newUser(emailVerified bool) identityUser {
	w.t.Helper()
	return w.makeUser(emailVerified, "")
}

// identityPhone is a number from the range reserved for fiction, so nothing can be sent to it.
const identityPhone = "+15555550100"

// newUserWithPhone is newUser with a verified email and a verified phone number.
func (w *writeRun) newUserWithPhone() identityUser {
	w.t.Helper()
	return w.makeUser(true, identityPhone)
}

// newInvitedUser is a user with no password and an unverified email, the user an invitation is
// for, together with the invite code the provider issued for it.
func (w *writeRun) newInvitedUser() (identityUser, string) {
	w.t.Helper()
	u := w.makeUserWith(false, "", "")
	code, err := w.rec.owner.inviteCode(context.Background(), u.ID)
	if err != nil {
		w.t.Fatalf("issue an invite code: %v", err)
	}
	return u, code
}

func (w *writeRun) makeUser(emailVerified bool, phone string) identityUser {
	w.t.Helper()
	return w.makeUserWith(emailVerified, phone, identityPassword)
}

func (w *writeRun) makeUserWith(emailVerified bool, phone, password string) identityUser {
	w.t.Helper()
	if w.rec.owner == nil {
		w.t.Fatalf("this case needs the identity provider, and the recorder has no settings for it; %s", identityAdvice)
	}
	username := fmt.Sprintf("%s%s-%03d-%d", identityUserRoot, w.rec.runID, w.n, len(w.users))
	u, err := w.rec.owner.createUserWith(context.Background(), username, emailVerified, phone, password)
	if u.ID != "" {
		// Registered even when the wait for it failed, so that it is still deleted.
		w.users = append(w.users, u)
		w.guard.ownUser(u)
	}
	if err != nil {
		w.t.Fatalf("create a throwaway user: %v", err)
	}
	return u
}

// sendJSON sends a request that has to succeed and returns its parsed body and the cookies it set.
func (w *writeRun) sendJSON(req *http.Request) (map[string]any, []*http.Cookie) {
	w.t.Helper()
	rec := w.send(req)
	if rec.Code < 200 || rec.Code > 299 {
		w.t.Fatalf("%s %s answered %d: %s", req.Method, req.URL.Path, rec.Code, rec.Body.String())
	}
	var out map[string]any
	if rec.Body.Len() > 0 {
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			w.t.Fatalf("%s %s returned a body that is not JSON: %s", req.Method, req.URL.Path, rec.Body.String())
		}
	}
	resp := rec.Result()
	defer func() { _ = resp.Body.Close() }()
	return out, resp.Cookies()
}

// publicRequest builds a request with no credential: the login routes are called before there is one.
func publicRequest(method, target, contentType string, body []byte) *http.Request {
	req, _ := http.NewRequestWithContext(context.Background(), method, target, bytes.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	return req
}

func publicJSON(t *testing.T, method, target string, body any) *http.Request {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal request body: %v", err)
	}
	return publicRequest(method, target, "application/json", raw)
}

// signInSteps is the login page's work, one request at a time, so that a case can stop before
// the step it records and send that one itself.
type signInSteps struct {
	w         *writeRun
	user      identityUser
	verifier  string
	challenge string

	authRequest  string
	sessionID    string
	sessionToken string
	cookies      []*http.Cookie
	code         string
}

func (w *writeRun) beginSignIn(u identityUser) *signInSteps {
	verifier, challenge := pkcePair()
	return &signInSteps{w: w, user: u, verifier: verifier, challenge: challenge}
}

// authorize starts the authorization request and keeps its identifier.
func (s *signInSteps) authorize() {
	s.w.t.Helper()
	out, _ := s.w.sendJSON(publicRequest(http.MethodGet, authorizeTarget(s.w.rec.identity.FrontendClientID, s.challenge), "", nil))
	if s.authRequest, _ = out["authRequest"].(string); s.authRequest == "" {
		s.w.t.Fatalf("the authorize request returned no authRequest: %v", out)
	}
}

// session checks the login name and password. The session it creates is this run's own.
func (s *signInSteps) session() {
	s.w.t.Helper()
	// The provider is shared with every session on the machine, and under load it has answered
	// this step with its own timeout. That is a preparation step failing for a reason that has
	// nothing to do with the case, so it is tried again; a refusal (a 4xx) is not.
	var rec *httptest.ResponseRecorder
	for attempt := 1; ; attempt++ {
		rec = s.w.send(publicJSON(s.w.t, http.MethodPost, "/auth/sessions", sessionBody(s.user)))
		if rec.Code < 500 || attempt == 3 {
			break
		}
		time.Sleep(time.Second)
	}
	if rec.Code < 200 || rec.Code > 299 {
		s.w.t.Fatalf("POST /auth/sessions answered %d: %s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		s.w.t.Fatalf("POST /auth/sessions returned a body that is not JSON: %s", rec.Body.String())
	}
	s.sessionID, _ = out["sessionId"].(string)
	s.sessionToken, _ = out["sessionToken"].(string)
	if s.sessionID == "" || s.sessionToken == "" {
		s.w.t.Fatalf("creating a session returned no session: %v", keysOf(out))
	}
	resp := rec.Result()
	defer func() { _ = resp.Body.Close() }()
	s.cookies = resp.Cookies()
	s.w.guard.ownSession(s.sessionID)
}

func (s *signInSteps) finalizeRequest() *http.Request {
	return publicJSON(s.w.t, http.MethodPost, "/auth/oidc/finalize", map[string]any{
		"authRequestId": s.authRequest, "sessionId": s.sessionID, "sessionToken": s.sessionToken,
	})
}

// finalize joins the session to the authorization request and keeps the code from the callback.
func (s *signInSteps) finalize() {
	s.w.t.Helper()
	out, _ := s.w.sendJSON(s.finalizeRequest())
	callback, _ := out["callbackUrl"].(string)
	u, err := url.Parse(callback)
	if err != nil || u.Query().Get("code") == "" {
		s.w.t.Fatalf("finalizing returned no callback URL with a code: %v", out)
	}
	s.code = u.Query().Get("code")
}

func (s *signInSteps) tokenRequest() *http.Request {
	form := tokenForm(s.w.rec.identity.FrontendClientID, s.code, s.verifier)
	return publicRequest(http.MethodPost, "/auth/oidc/token", "application/x-www-form-urlencoded", []byte(form.Encode()))
}

// signIn does all of it and returns what a browser holds afterwards.
func (w *writeRun) signIn(u identityUser) identitySession {
	w.t.Helper()
	s := w.beginSignIn(u)
	s.authorize()
	s.session()
	s.finalize()
	out, _ := w.sendJSON(s.tokenRequest())
	access, _ := out["access_token"].(string)
	if access == "" {
		w.t.Fatalf("the token exchange returned no access token: %v", keysOf(out))
	}
	if sub, isJWT := jwtSubject(access); !isJWT || sub != u.ID {
		w.t.Fatalf("the access token is not a JWT for the user that signed in (JWT: %v, subject %q, user %s)", isJWT, sub, u.ID)
	}
	return identitySession{User: u, SessionID: s.sessionID, SessionToken: s.sessionToken, AccessToken: access, Cookies: s.cookies}
}

// as builds a request the signed-in user sends: its token, and the session cookie the proxy set.
func (sess identitySession) as(req *http.Request) *http.Request {
	req.Header.Set("Authorization", "Bearer "+sess.AccessToken)
	for _, c := range sess.Cookies {
		req.AddCookie(c)
	}
	return req
}

// attachIdentity gives the recorder its identity settings and sweeps what a killed run left.
func (r *writeRecorder) attachIdentity(t *testing.T) {
	t.Helper()
	id, err := writeIdentityFromEnv()
	if err != nil {
		t.Fatalf("golden write recorder: %v", err)
	}
	r.identity, r.owner, r.runID = &id, newOwnerClient(id), randomHex(4)
	swept, err := r.owner.sweepLeftovers(context.Background())
	if err != nil {
		t.Fatalf("golden write recorder: the identity provider at %s is not usable (%v); %s", id.Addr, err, identityAdvice)
	}
	if swept > 0 {
		t.Logf("golden write recorder: removed %d user(s) a killed run left at the identity provider", swept)
	}
}

// identityLeftovers is the users of this run still at the identity provider. After the last case
// there must be none.
func (r *writeRecorder) identityLeftovers(t *testing.T) []string {
	t.Helper()
	found, err := r.owner.searchPrefix(context.Background(), identityUserRoot+r.runID+"-")
	if err != nil {
		t.Fatalf("search the identity provider for this run's users: %v", err)
	}
	names := make([]string, 0, len(found))
	for _, u := range found {
		names = append(names, u.Username)
	}
	return names
}

// TestGoldenWriteSignIn is the identity feasibility check (#869): a user the recorder creates
// signs in through the proxy's own routes, without a browser, and the token that comes out is
// one an interactive-only route accepts. Eleven routes depend on that and fit no reason for
// being named, so if this cannot be made to pass the plan goes back to its owner.
func TestGoldenWriteSignIn(t *testing.T) {
	if os.Getenv(envWritePhase) == "" {
		t.Skip(writePhaseSkipHelp)
	}
	settings := writeSettingsFromEnv()
	if err := settings.check(); err != nil {
		t.Fatalf("golden write recorder: %v", err)
	}
	settings.applyToEnv(t)

	r := newWriteRecorder(t)
	r.attachIdentity(t)
	w, done := r.open(t, 0, "the sign-in check")

	user := w.newUser(true)
	session := w.signIn(user)

	// The guard's refusal for an API token on this route is a 403. A signed-in user gets the list.
	rec := w.send(session.as(publicRequest(http.MethodGet, "/api/v2/settings/api-keys", "", nil)))
	if rec.Code != http.StatusOK {
		t.Errorf("GET /api/v2/settings/api-keys as the signed-in user answered %d, want 200: %s", rec.Code, rec.Body.String())
	}
	// And the harness's own API token is still refused there, so the 200 is the sign-in's doing.
	if rec := w.send(w.rawRequest(http.MethodGet, "/api/v2/settings/api-keys", "", nil)); rec.Code != http.StatusForbidden {
		t.Errorf("the same route with an API token answered %d, want the interactive-only 403", rec.Code)
	}

	done()
	r.waitForDrops(t)
	if left := r.identityLeftovers(t); len(left) > 0 {
		t.Errorf("users of this run are still at the identity provider: %v", left)
	}
}

// --- tests of the two rules, which need no service -----------------------------------------------

// TestIdentityGuard pins AC15's first half: a request naming an identity the run did not create
// does not reach the router.
func TestIdentityGuard(t *testing.T) {
	g := newIdentityGuard()
	mine := identityUser{ID: "345678901234567890", Username: "sw-golden-write-ab12-003", LoginName: "sw-golden-write-ab12-003@stackweaver.localhost", Email: "sw-golden-write-ab12-003@stackweaver.local"}
	g.ownUser(mine)
	g.ownSession("345678901234567999")

	jwt := func(sub string) string {
		enc := func(v any) string {
			raw, _ := json.Marshal(v)
			return base64.RawURLEncoding.EncodeToString(raw)
		}
		return enc(map[string]any{"alg": "RS256"}) + "." + enc(map[string]any{"sub": sub}) + ".c2lnbmF0dXJl"
	}
	request := func(method, target, bearer string, body any) (*http.Request, []byte) {
		var raw []byte
		if body != nil {
			raw, _ = json.Marshal(body)
		}
		req, _ := http.NewRequestWithContext(context.Background(), method, target, bytes.NewReader(raw))
		req.Header.Set("Content-Type", "application/json")
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		return req, raw
	}

	const adminID, adminLogin = "100000000000000001", "admin@zitadel.localhost"
	cases := []struct {
		name    string
		method  string
		target  string
		bearer  string
		body    any
		refused bool
	}{
		{"a user the run created, by path", http.MethodPost, "/auth/users/" + mine.ID + "/password", "", nil, false},
		{"another user, by path", http.MethodPost, "/auth/users/" + adminID + "/password", "", nil, true},
		{"another user, deeper in the path", http.MethodPost, "/auth/users/" + adminID + "/totp/verify", "", nil, true},
		{"a session the run created", http.MethodDelete, "/auth/sessions/345678901234567999", "", nil, false},
		{"another session", http.MethodDelete, "/auth/sessions/999", "", nil, true},
		{"another session, on the settings route", http.MethodDelete, "/api/v2/settings/sessions/999", "", nil, true},
		{"a new name for the signed-in user, on the account route", http.MethodPatch, "/api/v2/account/update", jwt(mine.ID), map[string]any{"data": map[string]any{"type": "users", "attributes": map[string]any{"username": "renamed"}}}, false},
		{"the session search is not a session", http.MethodPost, "/auth/sessions/search", "", nil, false},
		{"a login name the run created", http.MethodPost, "/auth/sessions", "", sessionBody(mine), false},
		{"another login name", http.MethodPost, "/auth/sessions", "", sessionBody(identityUser{LoginName: adminLogin}), true},
		{"another user ID in the body", http.MethodPost, "/auth/users/" + mine.ID + "/email", "", map[string]any{"userId": adminID}, true},
		{"another session ID, nested in the body", http.MethodPost, "/auth/oidc/finalize", "", map[string]any{"session": map[string]any{"sessionId": "999"}}, true},
		{"a token whose subject the run created", http.MethodPost, "/api/v2/settings/password", jwt(mine.ID), nil, false},
		{"a token for another subject", http.MethodPost, "/api/v2/settings/password", jwt(adminID), nil, true},
		{"an API token is not an identity", http.MethodPost, "/api/v2/organizations", "sw-user-0123456789abcdef", nil, false},
		{"a member called username on a route that is not the provider's", http.MethodPost, "/api/v2/organizations/acme/ansible/notification-templates", "", map[string]any{"username": "smtp-relay", "userId": adminID}, false},
		{"a write that names no identity", http.MethodPatch, "/api/v2/workspaces/ws-abc", "", map[string]any{"data": map[string]any{"attributes": map[string]any{"name": "prod"}}}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req, raw := request(c.method, c.target, c.bearer, c.body)
			err := g.check(req, raw)
			if c.refused && err == nil {
				t.Error("the request was let through")
			}
			if !c.refused && err != nil {
				t.Errorf("the request was refused: %v", err)
			}
		})
	}
}

// TestOwnerClientReach pins AC15's second half: the owner token reaches five operations and
// nothing else, and a refused request is never sent.
func TestOwnerClientReach(t *testing.T) {
	allowed := []struct{ method, path string }{
		{http.MethodPost, "/v2/users/human"},
		{http.MethodDelete, "/v2/users/345678901234567890"},
		{http.MethodPost, "/v2/users/345678901234567890/email"},
		{http.MethodPost, "/v2/users/345678901234567890/invite_code"},
		{http.MethodPost, "/v2/users"},
	}
	for _, a := range allowed {
		if ownerOperation(a.method, a.path) == "" {
			t.Errorf("%s %s is one of the five operations and was refused", a.method, a.path)
		}
	}

	// Everything else on the instance, of which these are the ones that would hurt.
	refused := []struct{ method, path string }{
		{http.MethodPut, "/admin/v1/policies/login"},
		{http.MethodPost, "/admin/v1/email/smtp"},
		{http.MethodPut, "/v2/settings/login"},
		{http.MethodGet, "/v2/users/345678901234567890"},
		{http.MethodPost, "/v2/users/345678901234567890/password"},
		{http.MethodPost, "/v2/users/345678901234567890/lock"},
		{http.MethodDelete, "/v2/users"},
		{http.MethodDelete, "/v2/users/345678901234567890/email"},
		{http.MethodDelete, "/v2/users/../../admin/v1/idps/1"},
		{http.MethodPost, "/v2/users/human/../../../admin/v1/policies/login"},
		{http.MethodPost, "/v2/users/abc/email"},
		{http.MethodPost, "/v2/users/abc/invite_code"},
		{http.MethodPost, "/v2/users/345678901234567890/invite_code/verify"},
		{http.MethodPost, "/management/v1/orgs"},
	}
	// A client pointed at an address nothing listens on: a request that got as far as being
	// sent would fail with a connection error, and not with the refusal.
	o := newOwnerClient(writeIdentity{Addr: "127.0.0.1:1", OwnerToken: "unused"})
	for _, r := range refused {
		if op := ownerOperation(r.method, r.path); op != "" {
			t.Errorf("%s %s was taken for %q", r.method, r.path, op)
		}
		_, _, err := o.do(context.Background(), r.method, r.path, nil)
		if err == nil || !strings.Contains(err.Error(), "the owner token is not used for") {
			t.Errorf("%s %s: got %v, want the refusal before anything is sent", r.method, r.path, err)
		}
	}

	// Deleting and issuing a code are for the run's own users only.
	if err := o.deleteUser(context.Background(), "100000000000000001"); err == nil || !strings.Contains(err.Error(), "not created by this run") {
		t.Errorf("deleting a user the run did not create: got %v", err)
	}
	if _, err := o.emailCode(context.Background(), "100000000000000001", "x@example.com"); err == nil || !strings.Contains(err.Error(), "not created by this run") {
		t.Errorf("an email code for a user the run did not create: got %v", err)
	}
	if _, err := o.inviteCode(context.Background(), "100000000000000001"); err == nil || !strings.Contains(err.Error(), "not created by this run") {
		t.Errorf("an invite code for a user the run did not create: got %v", err)
	}
	if _, err := o.searchPrefix(context.Background(), "admin"); err == nil {
		t.Error("a search outside the recorder's prefix was allowed")
	}
}

// TestIdentityNormaliser pins what makes two recordings of an identity case the same file (AC8).
func TestIdentityNormaliser(t *testing.T) {
	w := &writeRun{guard: newIdentityGuard()}
	if w.identityNormaliser() != nil {
		t.Fatal("a case that created nothing at the identity provider got a normaliser; its fixture must not change")
	}
	var none *identityNormaliser
	if got := none.apply(map[string]any{"id": "345678901234567890"}); !reflect.DeepEqual(got, map[string]any{"id": "345678901234567890"}) {
		t.Fatalf("a nil normaliser changed a value: %v", got)
	}

	u := identityUser{
		ID: "345678901234567890", Username: "sw-golden-write-ab12cd34-003-0",
		LoginName: "sw-golden-write-ab12cd34-003-0@stackweaver.localhost", Email: "sw-golden-write-ab12cd34-003-0@stackweaver.local",
	}
	w.users = []identityUser{u}
	w.guard.ownUser(u)
	w.guard.ownSession("345678901234567999")
	n := w.identityNormaliser()

	var body any
	raw := `{
		"sessionId": "345678901234567999",
		"details": {"sequence": "8841", "resourceOwner": "311111111111111111", "changeDate": "2026-10-12T10:00:00Z"},
		"factors": {"user": {"id": "345678901234567890", "loginName": "sw-golden-write-ab12cd34-003-0@stackweaver.localhost", "displayName": "Golden Write"}},
		"callbackUrl": "http://localhost:5173/auth/callback?user=345678901234567890&state=golden-write",
		"emails": ["sw-golden-write-ab12cd34-003-0@stackweaver.local", "second@example.com", "first@example.com"],
		"count": 3,
		"sequence": 12,
		"short": "12345"
	}`
	if err := json.Unmarshal([]byte(raw), &body); err != nil {
		t.Fatal(err)
	}
	got := n.apply(body).(map[string]any)

	want := map[string]any{
		"sessionId": "<session-id>",
		"details":   map[string]any{"sequence": "<sequence>", "resourceOwner": "<id>", "changeDate": "2026-10-12T10:00:00Z"},
		"factors": map[string]any{"user": map[string]any{
			"id": "<user-id>", "loginName": "<login-name>", "displayName": "Golden Write",
		}},
		// A value inside a longer string is replaced where it stands.
		"callbackUrl": "http://localhost:5173/auth/callback?user=<user-id>&state=golden-write",
		// A request's arrays are ordered input: the order is kept.
		"emails": []any{"<email>", "second@example.com", "first@example.com"},
		"count":  float64(3),
		// A number called sequence is somebody else's counter, and a short decimal string is
		// not one of the provider's identifiers.
		"sequence": float64(12),
		"short":    "12345",
	}
	if !reflect.DeepEqual(got, want) {
		gotJSON, _ := json.MarshalIndent(got, "", "  ")
		t.Errorf("normalised to\n%s", gotJSON)
	}
	if n.text("code=abc&user="+u.Username) != "code=abc&user=<username>" {
		t.Errorf("a form value was not normalised: %q", n.text("code=abc&user="+u.Username))
	}

	// The server's clock in a string, in a run that started a few seconds ago: replaced. A
	// ten-digit number from any other time is somebody's data and is left alone.
	now := time.Now().Unix()
	clocked := &writeRun{guard: newIdentityGuard(), rec: &writeRecorder{started: time.Now().Add(-5 * time.Second)}}
	cn := clocked.identityNormaliser()
	if got := cn.text(fmt.Sprintf("patch-and-verify #%d", now)); got != "patch-and-verify #<unix-time>" {
		t.Errorf("the clock in a run name normalised to %q", got)
	}
	if got := cn.text("ticket 1500000000, port 2222, id 345678901234567890"); got != "ticket 1500000000, port 2222, id 345678901234567890" {
		t.Errorf("numbers that are not the run's clock were changed: %q", got)
	}

	// A case that touched no identity and published a stand-in's address: that value is
	// replaced, and the rules for what the provider generates do not apply.
	standIn := &writeRun{guard: newIdentityGuard()}
	standIn.publishAs("http://127.0.0.1:41873", "https://tasks.example.com")
	sn := standIn.identityNormaliser()
	gotStandIn := sn.apply(map[string]any{
		"url": "http://127.0.0.1:41873/run-tasks/cost-estimate", "installation": "345678901234567890", "sequence": "7",
	})
	wantStandIn := map[string]any{
		"url": "https://tasks.example.com/run-tasks/cost-estimate", "installation": "345678901234567890", "sequence": "7",
	}
	if !reflect.DeepEqual(gotStandIn, wantStandIn) {
		t.Errorf("a published stand-in normalised to %v, want %v", gotStandIn, wantStandIn)
	}
}
