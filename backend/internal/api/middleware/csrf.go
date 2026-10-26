// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package middleware

import (
	"errors"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/jsonapi"
)

// CSRFHeader is the custom header the SPA sends on every request that rides on the session
// cookie. A browser sends a custom header cross-origin only after a CORS preflight, which the API
// answers only for allowlisted origins, so its presence proves the SPA made the request (RFC
// 10017 section 6.1.3.3).
const CSRFHeader = "X-Stackweaver-CSRF"

// OriginPolicy is the set of browser origins the API trusts with credentials. CORS, the /auth
// group's check and the session cookie's check all read the same one, so a same-origin install
// needs no extra configuration.
type OriginPolicy struct {
	origins   map[string]struct{}
	localhost bool
}

// NewOriginPolicy trusts the given origins, and any http localhost origin when localhost is set.
func NewOriginPolicy(localhost bool, origins ...string) OriginPolicy {
	p := OriginPolicy{origins: make(map[string]struct{}, len(origins)), localhost: localhost}
	for _, o := range origins {
		if o = strings.TrimRight(strings.TrimSpace(o), "/"); o != "" {
			p.origins[o] = struct{}{}
		}
	}
	return p
}

// OriginPolicyFromEnv trusts the origin of STACKWEAVER_APP_URL, every origin in
// CORS_EXTRA_ORIGINS (comma-separated), and, outside release mode, any http localhost origin.
//
// AUD-070: release mode trusts no localhost origin, since a page a victim was tricked into
// loading from their own localhost could otherwise reach the API with credentials.
func OriginPolicyFromEnv() OriginPolicy {
	var origins []string
	if app := originOf(os.Getenv("STACKWEAVER_APP_URL")); app != "" {
		origins = append(origins, app)
	}
	origins = append(origins, strings.Split(os.Getenv("CORS_EXTRA_ORIGINS"), ",")...)
	return NewOriginPolicy(os.Getenv("GIN_MODE") != "release", origins...)
}

// originOf is the scheme://host of a URL, or "" when it has neither.
func originOf(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// Allows reports whether origin is trusted.
func (p OriginPolicy) Allows(origin string) bool {
	if origin == "" {
		return false
	}
	if _, ok := p.origins[strings.TrimRight(origin, "/")]; ok {
		return true
	}
	return p.localhost && isLocalhostOrigin(origin)
}

// requestOrigin is the Origin header, or the origin of the Referer when there is no Origin.
// present is false when the request carries neither.
func requestOrigin(r *http.Request) (origin string, present bool) {
	if o := r.Header.Get("Origin"); o != "" {
		return o, true
	}
	if ref := r.Header.Get("Referer"); ref != "" {
		return originOf(ref), true
	}
	return "", false
}

func isSafeMethod(method string) bool {
	return method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions
}

var (
	errMissingCSRFHeader = errors.New("missing " + CSRFHeader + " header")
	errCrossOrigin       = errors.New("cross-origin request blocked")
	errNoOrigin          = errors.New("request carries neither Origin nor Referer")
	errNotPost           = errors.New("this action takes a POST")
)

// CheckBrowserRequest is the CSRF defence for a request that rides on the session cookie: it
// must carry X-Stackweaver-CSRF: 1 whatever its method, and a state-changing one must come from a
// trusted origin. Unlike CSRFProtection, a state-changing request carrying neither Origin nor
// Referer is refused, since Chromium and Firefox send Origin on every POST fetch.
func (p OriginPolicy) CheckBrowserRequest(r *http.Request) error {
	if r.Header.Get(CSRFHeader) != "1" {
		return errMissingCSRFHeader
	}
	if isSafeMethod(r.Method) {
		return nil
	}
	origin, present := requestOrigin(r)
	if !present {
		return errNoOrigin
	}
	if !p.Allows(origin) {
		return errCrossOrigin
	}
	return nil
}

// RequireBrowserRequest applies CheckBrowserRequest to a route the browser calls before it has a
// session or about the session itself, answering 403 when it fails.
func RequireBrowserRequest(p OriginPolicy) gin.HandlerFunc {
	return func(c *gin.Context) {
		if err := p.CheckBrowserRequest(c.Request); err != nil {
			jsonapi.AbortError(c, http.StatusForbidden, jsonapi.TitleForbidden, err.Error())
			return
		}
		c.Next()
	}
}

// CheckBrowserNavigation is the CSRF defence for a state-changing top-level navigation that rides
// on the session cookie: a form POST, which cannot carry X-Stackweaver-CSRF. It must be a POST from
// a trusted origin. Browsers send Origin on every form POST, so one carrying neither Origin nor
// Referer is refused, and so is one from another site or from a sibling host of the same site,
// which SameSite alone would let through.
func (p OriginPolicy) CheckBrowserNavigation(r *http.Request) error {
	if r.Method != http.MethodPost {
		return errNotPost
	}
	origin, present := requestOrigin(r)
	if !present {
		return errNoOrigin
	}
	if !p.Allows(origin) {
		return errCrossOrigin
	}
	return nil
}

// RequireBrowserNavigation applies CheckBrowserNavigation, answering 403 when it fails.
func RequireBrowserNavigation(p OriginPolicy) gin.HandlerFunc {
	return func(c *gin.Context) {
		if err := p.CheckBrowserNavigation(c.Request); err != nil {
			jsonapi.AbortError(c, http.StatusForbidden, jsonapi.TitleForbidden, err.Error())
			return
		}
		c.Next()
	}
}

// CSRFProtection validates Origin and Referer headers on mutating requests
// to /auth/* endpoints. Required because SameSite=Lax alone is not sufficient
// for SPA-to-API CSRF protection (see plan D6).
//
// For non-mutating methods (GET, HEAD, OPTIONS) this is a no-op. A request carrying neither header
// passes: the login UI's own steps carry no session yet, and Zitadel's back-channel logout POST
// comes server to server with neither. The routes that act on a session use
// RequireBrowserRequest instead.
func CSRFProtection(p OriginPolicy) gin.HandlerFunc {
	return func(c *gin.Context) {
		if isSafeMethod(c.Request.Method) {
			c.Next()
			return
		}
		origin, present := requestOrigin(c.Request)
		if present && !p.Allows(origin) {
			jsonapi.WriteError(c, http.StatusForbidden, jsonapi.TitleForbidden, "cross-origin request blocked")
			c.Abort()
			return
		}
		c.Next()
	}
}
