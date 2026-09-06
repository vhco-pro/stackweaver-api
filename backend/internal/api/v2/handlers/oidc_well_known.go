// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/michielvha/stackweaver/core/services/oidc"
)

// OIDCWellKnownHandler serves the OIDC discovery endpoints.
// These are unauthenticated - Azure AD calls them to validate workload identity tokens.
type OIDCWellKnownHandler struct {
	signingKey *oidc.SigningKey
	issuerURL  string
}

// NewOIDCWellKnownHandler creates an OIDCWellKnownHandler.
func NewOIDCWellKnownHandler(signingKey *oidc.SigningKey) *OIDCWellKnownHandler {
	issuerURL := os.Getenv("OIDC_ISSUER_URL")
	if issuerURL == "" {
		// Default to the API URL if not explicitly set
		issuerURL = os.Getenv("API_URL")
	}
	if issuerURL == "" {
		issuerURL = "http://localhost:8022"
	}
	return &OIDCWellKnownHandler{
		signingKey: signingKey,
		issuerURL:  issuerURL,
	}
}

// OpenIDConfiguration serves the OIDC discovery document.
// GET /.well-known/openid-configuration
// Reference: https://openid.net/specs/openid-connect-discovery-1_0.html
func (h *OIDCWellKnownHandler) OpenIDConfiguration(c *gin.Context) {
	c.JSON(http.StatusOK, OpenIDConfigurationResponse{
		Issuer:                           h.issuerURL,
		JWKSURI:                          h.issuerURL + "/.well-known/jwks",
		IDTokenSigningAlgValuesSupported: []string{"RS256"},
		ResponseTypesSupported:           []string{"id_token"},
		SubjectTypesSupported:            []string{"public"},
		ClaimsSupported: []string{
			"sub", "aud", "iss", "iat", "exp", "nbf",
			"terraform_organization_name",
			"terraform_workspace_name",
			"terraform_project_name",
			"terraform_run_id",
			"terraform_run_phase",
		},
	})
}

// JWKS serves the JSON Web Key Set containing the platform's public signing key.
// GET /.well-known/jwks
// Azure AD fetches this to verify the signature of workload identity tokens.
func (h *OIDCWellKnownHandler) JWKS(c *gin.Context) {
	c.JSON(http.StatusOK, h.signingKey.JWKS())
}
