// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

// The installation flow: the four steps of connecting a VCS provider's app that a signed-in
// person drives from the organization's VCS settings, all mounted on the authenticated
// orgVCSConnections group. They answer JSON:API like every other handler (#858, D12): the three
// URL-issuing steps answer the URL as meta alone, and the GitHub completion takes a
// vcs-connections document. The webhook receivers and the Azure DevOps OAuth callback, which a
// provider calls on an unauthenticated root group, stay in vcs_app_installation.go, the protocol
// file the writer guard exempts.

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/logger"
	"github.com/michielvha/stackweaver/backend/internal/api/middleware"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/jsonapi"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/services/vcs"
	"gorm.io/gorm"
)

// gitHubInstallStateRefusal is the answer to a GitHub App installation authorized or completed
// without the state the step before issued to this caller for this organization, whichever part
// of the state is wrong. It is shaped like the permission refusal and does not say which check
// failed.
var gitHubInstallStateRefusal = fmt.Sprintf("This GitHub installation cannot be completed here. Connect GitHub again from the organization's VCS settings and finish the installation within %d minutes, signed in as the person who started it.", int(oauthStateTTL.Minutes()))

// gitHubAuthorizationRefusal answers a completion GitHub did not authorize: no code, or one
// GitHub would not exchange.
const gitHubAuthorizationRefusal = "GitHub did not confirm your authorization of the GitHub App. Connect GitHub again from the organization's VCS settings and authorize the app when GitHub asks."

// gitHubInstallationAccessRefusal answers a completion for an installation the person who
// authorized the App cannot access at GitHub.
const gitHubInstallationAccessRefusal = "The GitHub account you authorized cannot access this installation of the GitHub App. Install the app on an account or organization you can access, then connect again."

// gitHubAuthorizedPath is the SPA page GitHub returns to after a person authorizes the App. It
// must be registered as a callback URL of the App.
const gitHubAuthorizedPath = "/vcs/github/authorized"

// mintGitHubInstallState issues the state a GitHub App installation for orgName, started by
// userID, is completed with. The payload is "orgName|returnPath|userID|nonce". The organization
// and return path come first and stay readable, because the page GitHub sends the browser back
// to reads them to know where to complete and where to go next. Returns "" when state signing
// is not configured.
func mintGitHubInstallState(orgName, returnPath string, userID uuid.UUID) string {
	payload := strings.Join([]string{orgName, url.QueryEscape(returnPath), userID.String(), uuid.NewString()}, "|")
	return mintOAuthState(stateGitHubAppInstall, payload)
}

// readGitHubInstallState returns the escaped return path of a state mintGitHubInstallState
// issued, not yet expired, for orgName and to userID; ok is false for any other state.
func readGitHubInstallState(state, orgName string, userID uuid.UUID) (escapedReturn string, ok bool) {
	payload, ok := verifyOAuthState(stateGitHubAppInstall, state)
	if !ok {
		return "", false
	}
	parts := strings.Split(payload, "|")
	if len(parts) != 4 || parts[0] != orgName || parts[2] != userID.String() {
		return "", false
	}
	return parts[1], true
}

// mintGitHubAuthorizeState issues the state the person's authorization of the App comes back
// with, for installationID of orgName. The payload is
// "orgName|returnPath|userID|installationID|nonce", the organization and return path first and
// readable for the page GitHub returns to, as in the install state.
func mintGitHubAuthorizeState(orgName, escapedReturn string, userID uuid.UUID, installationID string) string {
	payload := strings.Join([]string{orgName, escapedReturn, userID.String(), installationID, uuid.NewString()}, "|")
	return mintOAuthState(stateGitHubAppAuthorize, payload)
}

// verifyGitHubAuthorizeState reports whether state is one mintGitHubAuthorizeState issued, not
// yet expired, for installationID of orgName and to userID.
func verifyGitHubAuthorizeState(state, orgName string, userID uuid.UUID, installationID string) bool {
	payload, ok := verifyOAuthState(stateGitHubAppAuthorize, state)
	if !ok {
		return false
	}
	parts := strings.Split(payload, "|")
	return len(parts) == 5 && parts[0] == orgName && parts[2] == userID.String() && parts[3] == installationID
}

// validGitHubInstallationID reports whether id has the shape of a GitHub installation id, a
// positive integer, so that it is safe in a URL path and a state.
func validGitHubInstallationID(id string) bool {
	n, err := strconv.ParseInt(id, 10, 64)
	return err == nil && n > 0 && strconv.FormatInt(n, 10) == id
}

// SetAppURL sets the SPA's public origin (STACKWEAVER_APP_URL). The App's user authorization
// returns to its /vcs/github/authorized page; without an origin GitHub picks the App's first
// registered callback URL.
func (h *VCSAppInstallationHandlerV2) SetAppURL(appURL string) {
	h.appURL = strings.TrimRight(appURL, "/")
}

// gitHubAuthorizeRedirectURI is where GitHub returns a person who authorized the App, or "" to
// leave it to GitHub. The authorization and the code exchange must name the same one.
func (h *VCSAppInstallationHandlerV2) gitHubAuthorizeRedirectURI() string {
	if h.appURL == "" {
		return ""
	}
	return h.appURL + gitHubAuthorizedPath
}

// AuthorizeInstallation is the second step of connecting a GitHub App installation. GitHub's
// Setup URL redirect brings the browser back with the installation id and the state the start
// issued; this takes that state back and answers with GitHub's page for authorizing the App,
// carrying a new state bound to the organization, the caller and the installation. A person who
// has already authorized the App is sent straight back by GitHub without seeing that page.
//
// The authorization is what lets the completion confirm that the person can access the
// installation at GitHub: the installation id alone says nothing about who installed it.
// GET /api/v2/organizations/:name/vcs-connections/github/installations/:installation_id/authorize
func (h *VCSAppInstallationHandlerV2) AuthorizeInstallation(c *gin.Context) {
	org, err := h.orgRepo.GetByName(c.Param("name"))
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "Organization not found")
		return
	}
	// The state issued below is what the completion accepts, so this read issues the means to a
	// write, as the start does.
	if !middleware.AuthorizeTokenOrgWrite(c, org.ID) {
		return
	}
	if !authorizeManageVCSSettings(c, h.authService, h.rbacService, org.ID) {
		return
	}
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		jsonapi.WriteError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return
	}
	escapedReturn, ok := readGitHubInstallState(c.Query("state"), org.Name, user.ID)
	if !ok {
		jsonapi.WriteError(c, http.StatusForbidden, "Forbidden", gitHubInstallStateRefusal)
		return
	}
	installationID := c.Param("installation_id")
	if !validGitHubInstallationID(installationID) {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Invalid GitHub installation id")
		return
	}
	if h.githubAppManager == nil || !h.githubAppManager.UserAuthorizationConfigured() {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Configuration Error", gitHubUserAuthorizationNotConfigured)
		return
	}

	state := mintGitHubAuthorizeState(org.Name, escapedReturn, user.ID, installationID)
	if state == "" {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Configuration Error", "OAuth state signing is not configured (ENCRYPTION_KEY unset)")
		return
	}
	authURL := h.githubAppManager.UserAuthorizationURL(state, h.gitHubAuthorizeRedirectURI())
	jsonapi.WriteMeta(c, http.StatusOK, VCSAuthURLMeta{AuthURL: authURL})
}

// gitHubUserAuthorizationNotConfigured answers a GitHub App connection on a deployment without
// the App's OAuth client credentials, which confirming the installation takes.
const gitHubUserAuthorizationNotConfigured = "GitHub App user authorization is not configured. Set GITHUB_APP_CLIENT_ID and GITHUB_APP_CLIENT_SECRET from the GitHub App's settings, and register <app URL>/vcs/github/authorized as a callback URL of the app."

// InitiateInstallation initiates the GitHub App installation flow
// Returns the installation URL for the frontend to redirect to
// GET /api/v2/organizations/:name/vcs-connections/github/install
func (h *VCSAppInstallationHandlerV2) InitiateInstallation(c *gin.Context) {
	orgName := c.Param("name")
	redirect := c.Query("redirect")
	returnPath := c.Query("return")

	// Verify organization exists
	org, err := h.orgRepo.GetByName(orgName)
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "Organization not found")
		return
	}

	// Starting an installation is the first half of connecting the organization, so it takes
	// what connecting takes. The state issued below is what CreateConnectionFromInstallation
	// accepts, so this read issues the means to a write: a token needs write scope here, not
	// only the read scope the wall asks of a GET.
	if !middleware.AuthorizeTokenOrgWrite(c, org.ID) {
		return
	}
	if !authorizeManageVCSSettings(c, h.authService, h.rbacService, org.ID) {
		return
	}
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		jsonapi.WriteError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return
	}

	if h.githubAppManager == nil || !h.githubAppManager.IsEnabled() {
		jsonapi.WriteError(c, http.StatusInternalServerError, "GitHub App Not Configured", "The GitHub App integration is not available. Check the API pod logs for initialization errors (search for 'GitHub App Manager'). Common causes: missing GITHUB_APP_ID/GITHUB_APP_NAME env vars, or the PEM private key lost its newlines during secret provisioning.")
		return
	}

	// GitHub returns the state unchanged on the redirect to the app's Setup URL, together with
	// the installation id. The installation id says nothing about who started the installation,
	// so the state is what ties the completion to this start: signed, expiring, and naming both
	// the organization and the caller, who must be the one to complete it.
	state := mintGitHubInstallState(org.Name, returnPath, user.ID)
	if state == "" {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Configuration Error", "OAuth state signing is not configured (ENCRYPTION_KEY unset)")
		return
	}

	// GitHub App installation URL
	// Users will be redirected here to install the app on their organization
	query := url.Values{"state": {state}}
	// If a redirect URL is provided, include it so GitHub sends users back to our app
	if redirect != "" {
		query.Set("redirect_url", redirect)
	}
	installURL := fmt.Sprintf("https://github.com/apps/%s/installations/new?%s", h.githubAppManager.GetAppName(), query.Encode())

	// Return the installation URL as JSON (frontend will handle redirect)
	jsonapi.WriteMeta(c, http.StatusOK, VCSInstallURLMeta{InstallURL: installURL})
}

// InitiateAzureDevOpsInstallation initiates the Azure DevOps OAuth2 installation flow
// Returns the authorization URL for the frontend to redirect to
// GET /api/v2/organizations/:name/vcs-connections/azure-devops/install
func (h *VCSAppInstallationHandlerV2) InitiateAzureDevOpsInstallation(c *gin.Context) {
	orgName := c.Param("name")
	adoOrg := c.Query("ado_org")    // Azure DevOps organization name
	returnPath := c.Query("return") // Where to send user after auth

	org, err := h.orgRepo.GetByName(orgName)
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "Organization not found")
		return
	}

	// The state issued below is what CompleteAzureDevOpsInstallation accepts in place of a
	// caller, so it is issued only to someone who may connect this organization. This is the
	// authorization for the whole flow: the callback has no identity to check. That makes this
	// read a write, so a token needs write scope here, not only the read scope the wall asks of
	// a GET.
	if !middleware.AuthorizeTokenOrgWrite(c, org.ID) {
		return
	}
	if !authorizeManageVCSSettings(c, h.authService, h.rbacService, org.ID) {
		return
	}

	if h.azureDevOpsManager == nil || !h.azureDevOpsManager.IsEnabled() {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Configuration Error", "Azure DevOps OAuth is not configured. Please set AZURE_DEVOPS_CLIENT_ID, AZURE_DEVOPS_CLIENT_SECRET, and AZURE_DEVOPS_REDIRECT_URI.")
		return
	}

	// State payload: "stackweaverOrg|adoOrg|returnPath|uuid", wrapped in an HMAC-signed,
	// expiring envelope so the callback can prove it minted this state (AUD-155).
	escapedReturn := url.QueryEscape(returnPath)
	payload := fmt.Sprintf("%s|%s|%s|%s", orgName, adoOrg, escapedReturn, uuid.New().String())
	state := mintOAuthState(stateAzureDevOpsInstall, payload)
	if state == "" {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Configuration Error", "OAuth state signing is not configured (ENCRYPTION_KEY unset)")
		return
	}

	authURL := h.azureDevOpsManager.GetAuthorizationURL(state)
	jsonapi.WriteMeta(c, http.StatusOK, VCSAuthURLMeta{AuthURL: authURL})
}

// CreateConnectionFromInstallation is the last step of connecting a GitHub App installation. It
// takes the state AuthorizeInstallation issued (query `state`) and the code GitHub returned with
// it (a vcs-connections document carrying the code attribute), confirms that the person who authorized the App can access the installation, and creates the
// organization's GitHub connection or points the existing one at the installation.
// POST /api/v2/organizations/:name/vcs-connections/github/installations/:installation_id
func (h *VCSAppInstallationHandlerV2) CreateConnectionFromInstallation(c *gin.Context) {
	orgName := c.Param("name")
	installationID := c.Param("installation_id")

	// Get organization
	org, err := h.orgRepo.GetByName(orgName)
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "Organization not found")
		return
	}

	// This creates the organization's GitHub connection or points the existing one at another
	// installation, so it takes the permission that creating and deleting a connection take.
	// Checked before the installation is looked up at GitHub and before anything is written.
	if !authorizeManageVCSSettings(c, h.authService, h.rbacService, org.ID) {
		return
	}

	// The installation id arrives through the browser and says nothing about who installed it,
	// so it is accepted only together with the state AuthorizeInstallation issued (for this
	// organization, this caller and this installation, not yet expired) and the code GitHub
	// returned with it. Checked before anything is asked of GitHub or written.
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		jsonapi.WriteError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return
	}
	if !verifyGitHubAuthorizeState(c.Query("state"), org.Name, user.ID, installationID) {
		jsonapi.WriteError(c, http.StatusForbidden, "Forbidden", gitHubInstallStateRefusal)
		return
	}

	if h.githubAppManager == nil || !h.githubAppManager.IsEnabled() {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Configuration Error", "GitHub App is not configured.")
		return
	}

	// The code GitHub returned with the state travels in the body, which access logs do not
	// record, as a vcs-connections document. An empty code is refused below by GitHub's answer.
	var req InstallationCompletionRequest
	if !jsonapi.BindDocument(c, &req, vcsConnectionsType) {
		return
	}
	body := req.Data.Attributes

	// The person who authorized the App must be able to access the installation at GitHub. The
	// user access token this takes is used for that one check inside the call and then revoked.
	ctx := c.Request.Context()
	switch err := h.githubAppManager.VerifyUserCanAccessInstallation(ctx, body.Code, h.gitHubAuthorizeRedirectURI(), installationID); {
	case err == nil:
	case errors.Is(err, vcs.ErrUserAuthorizationNotConfigured):
		jsonapi.WriteError(c, http.StatusInternalServerError, "Configuration Error", gitHubUserAuthorizationNotConfigured)
		return
	case errors.Is(err, vcs.ErrUserAuthorizationNotGranted):
		jsonapi.WriteError(c, http.StatusForbidden, "Forbidden", gitHubAuthorizationRefusal)
		return
	case errors.Is(err, vcs.ErrInstallationNotAccessible):
		jsonapi.WriteError(c, http.StatusForbidden, "Forbidden", gitHubInstallationAccessRefusal)
		return
	default:
		logger.Warnf("Confirming access to GitHub installation %s for organization %s: %v", installationID, org.Name, err)
		jsonapi.WriteError(c, http.StatusBadGateway, "Bad Gateway", "GitHub could not be asked whether you can access this installation. Try again.")
		return
	}

	// Get installation info from GitHub
	githubService := h.githubAppManager.GetService()
	installation, err := githubService.GetInstallation(ctx, installationID)
	if err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", fmt.Sprintf("Failed to get installation info: %v", err))
		return
	}

	// Check if connection already exists
	existing, getErr := h.vcsConnectionRepo.GetByOrganizationAndProvider(org.ID, models.VCSProviderGitHub)
	// Only "not found" means there is none. Any other error leaves the question unanswered, and
	// creating on it could give the organization a second connection for the provider.
	if getErr != nil && !errors.Is(getErr, gorm.ErrRecordNotFound) {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to check for an existing VCS connection")
		return
	}
	if getErr == nil && existing != nil && existing.ID != uuid.Nil {
		// Update existing connection
		existing.InstallationID = installationID
		existing.AccountName = installation.AccountName
		existing.AccountType = installation.AccountType
		if err := h.vcsConnectionRepo.Update(existing); err != nil {
			jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to update VCS connection")
			return
		}

		jsonapi.WriteDocument(c, http.StatusOK, jsonapi.Resource[VCSConnectionAckWithTypeAttributes]{
			ID:   existing.ID.String(),
			Type: "vcs-connections",
			Attributes: VCSConnectionAckWithTypeAttributes{
				Provider:    existing.Provider,
				AccountName: existing.AccountName,
				AccountType: existing.AccountType,
			},
		})
		return
	}

	// Create new connection
	connection := &models.VCSConnection{
		OrganizationID: org.ID,
		Provider:       models.VCSProviderGitHub,
		InstallationID: installationID,
		AccountName:    installation.AccountName,
		AccountType:    installation.AccountType,
	}

	if err := h.vcsConnectionRepo.Create(connection); err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to create VCS connection")
		return
	}

	jsonapi.WriteDocument(c, http.StatusCreated, jsonapi.Resource[VCSConnectionAckWithTypeAttributes]{
		ID:   connection.ID.String(),
		Type: "vcs-connections",
		Attributes: VCSConnectionAckWithTypeAttributes{
			Provider:    connection.Provider,
			AccountName: connection.AccountName,
			AccountType: connection.AccountType,
		},
	})
}

// InstallationCompletionRequest is the document that completes a GitHub App installation: the
// code GitHub returned when the person authorized the App, as an attribute of the
// vcs-connections resource the step creates or points at the installation (#858, D6). It
// travels in the body, which access logs do not record; the state stays in the query.
type InstallationCompletionRequest struct {
	Data *struct {
		Type       string `json:"type"`
		Attributes struct {
			Code string `json:"code"`
		} `json:"attributes"`
	} `json:"data" binding:"required"`
}

// PrimaryType reports data.type and whether data was sent (jsonapi.TypedDocument).
func (r *InstallationCompletionRequest) PrimaryType() (string, bool) {
	if r.Data == nil {
		return "", false
	}
	return r.Data.Type, true
}
