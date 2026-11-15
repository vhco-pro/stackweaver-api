// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/api/middleware"
	"github.com/michielvha/stackweaver/backend/internal/api/pagination"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/apierror"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/jsonapi"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"gorm.io/gorm"
)

// GitHubAppInstallationsHandler serves the TFE GitHub App installation routes that
// terraform-provider-tfe's tfe_github_app_installation data source reads (#938):
// GET /api/v2/github-app/installations and GET /api/v2/github-app/installation/:id.
//
// Installations are organization-bound (owner decision, 2026-10-16): a caller sees the
// installations connected in the organizations they belong to, and an organization token only
// those of its own organization. No GitHub call is made. Neither route names an organization, so
// the org wall classifies them agnostic and this handler applies the scope itself; it never falls
// back to the token owner's memberships for an organization token.
type GitHubAppInstallationsHandler struct {
	db          *gorm.DB
	authService *auth.Service
	orgRepo     *repository.OrganizationRepository
	orgResolver middleware.OrgResolver
}

// NewGitHubAppInstallationsHandler returns the handler.
func NewGitHubAppInstallationsHandler(db *gorm.DB, authService *auth.Service) *GitHubAppInstallationsHandler {
	return &GitHubAppInstallationsHandler{db: db, authService: authService, orgRepo: repository.NewOrganizationRepository(db), orgResolver: middleware.NewDBOrgResolver(db)}
}

// GitHubAppInstallationAttributes are the attributes of a github-app-installations resource. The
// resource id is the GitHub installation id as a string, which is what
// vcs_repo.github_app_installation_id takes, so the data source's id round-trips.
type GitHubAppInstallationAttributes struct {
	InstallationID   int64  `json:"installation-id"`
	Name             string `json:"name"`
	InstallationType string `json:"installation-type"`
	InstallationURL  string `json:"installation-url"`
	IconURL          string `json:"icon-url,omitempty"`
}

type installationRow struct {
	InstallationID string
	AccountName    string
	AccountType    string
	UpdatedAt      time.Time
}

// visibleOrganizations is the organizations whose installations the caller may see: an
// organization token's own organization, otherwise every organization the user belongs to that
// the org wall lets the caller's token reach. A user token is thereby held to each organization's
// user_tokens_enabled policy, with the wall's owner exemption, exactly as on that organization's
// own routes.
func (h *GitHubAppInstallationsHandler) visibleOrganizations(c *gin.Context) ([]uuid.UUID, bool) {
	if kindVal, isToken := c.Get("token_kind"); isToken {
		if kind, _ := kindVal.(string); kind == models.APIKeyKindOrg {
			bound, ok := c.Get("token_org_id")
			org, isUUID := bound.(uuid.UUID)
			if !ok || !isUUID {
				jsonapi.WriteError(c, http.StatusForbidden, "Forbidden", "token is not bound to an organization")
				return nil, false
			}
			if !middleware.TokenMayReachOrg(c, h.orgResolver, org) {
				return nil, true
			}
			return []uuid.UUID{org}, true
		}
	}
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		jsonapi.WriteError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return nil, false
	}
	orgs, err := h.orgRepo.WithContext(c.Request.Context()).ListByUser(user.ID)
	if err != nil {
		apierror.Internal(c, "Failed to list organizations", err)
		return nil, false
	}
	ids := make([]uuid.UUID, 0, len(orgs))
	for _, o := range orgs {
		if middleware.TokenMayReachOrg(c, h.orgResolver, o.ID) {
			ids = append(ids, o.ID)
		}
	}
	return ids, true
}

// installations returns one row per distinct installation connected in orgs, the most recently
// updated connection's account for each, narrowed by the optional filters.
func (h *GitHubAppInstallationsHandler) installations(c *gin.Context, orgs []uuid.UUID, name, installationID string) ([]installationRow, error) {
	if len(orgs) == 0 {
		return nil, nil
	}
	q := h.db.WithContext(c.Request.Context()).Table("vcs_connections").
		Select("DISTINCT ON (installation_id) installation_id, account_name, account_type, updated_at").
		Where("provider = ? AND COALESCE(installation_id, '') <> '' AND organization_id IN ?", models.VCSProviderGitHub, orgs)
	if installationID != "" {
		q = q.Where("installation_id = ?", installationID)
	}
	q = q.Order("installation_id, updated_at DESC")
	var rows []installationRow
	if err := q.Scan(&rows).Error; err != nil {
		return nil, fmt.Errorf("listing App installations: %w", err)
	}
	if name == "" {
		return rows, nil
	}
	kept := rows[:0]
	for _, r := range rows {
		if strings.EqualFold(r.AccountName, name) {
			kept = append(kept, r)
		}
	}
	return kept, nil
}

func installationResource(r installationRow) jsonapi.Resource[GitHubAppInstallationAttributes] {
	id, _ := strconv.ParseInt(r.InstallationID, 10, 64)
	kind := r.AccountType
	if kind == "" {
		kind = "Organization"
	}
	url := "https://github.com/settings/installations/" + r.InstallationID
	if strings.EqualFold(kind, "organization") {
		url = "https://github.com/organizations/" + r.AccountName + "/settings/installations/" + r.InstallationID
	}
	return jsonapi.Resource[GitHubAppInstallationAttributes]{
		ID:   r.InstallationID,
		Type: "github-app-installations",
		Attributes: GitHubAppInstallationAttributes{
			InstallationID:   id,
			Name:             r.AccountName,
			InstallationType: kind,
			InstallationURL:  url,
		},
	}
}

// List handles GET /api/v2/github-app/installations.
func (h *GitHubAppInstallationsHandler) List(c *gin.Context) {
	orgs, ok := h.visibleOrganizations(c)
	if !ok {
		return
	}
	rows, err := h.installations(c, orgs, c.Query("filter[name]"), c.Query("filter[installation_id]"))
	if err != nil {
		apierror.Internal(c, "Failed to list App installations", err)
		return
	}
	page, perPage := pagination.Parse(c, 20)
	if perPage > 100 {
		perPage = 100
	}
	start := min((page-1)*perPage, len(rows))
	end := min(start+perPage, len(rows))
	data := make([]jsonapi.Resource[GitHubAppInstallationAttributes], 0, end-start)
	for _, r := range rows[start:end] {
		data = append(data, installationResource(r))
	}
	jsonapi.WriteDocumentMeta(c, http.StatusOK, data, jsonapi.NewPaginationMeta(page, perPage, int64(len(rows))))
}

// Get handles GET /api/v2/github-app/installation/:id. An installation not connected in a
// visible organization is 404, whether or not another organization connected it.
func (h *GitHubAppInstallationsHandler) Get(c *gin.Context) {
	orgs, ok := h.visibleOrganizations(c)
	if !ok {
		return
	}
	id := c.Param("id")
	rows, err := h.installations(c, orgs, "", id)
	if err != nil {
		apierror.Internal(c, "Failed to read the App installation", err)
		return
	}
	if id == "" || len(rows) == 0 {
		jsonapi.WriteErrorNoDetail(c, http.StatusNotFound, "Not Found")
		return
	}
	jsonapi.WriteDocument(c, http.StatusOK, installationResource(rows[0]))
}
