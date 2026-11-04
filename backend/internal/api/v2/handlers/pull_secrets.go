// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/jsonapi"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"gorm.io/gorm"
)

// PullSecretAttributes is a pool's registry pull Secret on the wire (#933, D8, D15): the Secret a
// customer pool's job pods pull images of one registry with. declared-externally,
// external-manager, object-present and reported-at are what the pool's launcher last reported,
// read-only.
type PullSecretAttributes struct {
	Name                 string     `json:"name"`
	SecretName           string     `json:"secret-name"`
	Registry             string     `json:"registry"`
	RegistryCredentialID *string    `json:"registry-credential-id"`
	Reference            bool       `json:"reference"`
	DeclaredExternally   bool       `json:"declared-externally"`
	ExternalManager      string     `json:"external-manager"`
	ObjectPresent        *bool      `json:"object-present"`
	ReportedAt           *time.Time `json:"reported-at"`
	CreatedAt            time.Time  `json:"created-at"`
}

// PullSecretRelationships names the pull Secret's pool.
type PullSecretRelationships struct {
	AgentPool jsonapi.Relationship `json:"agent-pool"`
}

type pullSecretRequest struct {
	Data struct {
		Type       string `json:"type"`
		Attributes struct {
			Name                 *string `json:"name"`
			SecretName           *string `json:"secret-name"`
			Registry             *string `json:"registry"`
			RegistryCredentialID *string `json:"registry-credential-id"`
			Reference            *bool   `json:"reference"`
		} `json:"attributes"`
	} `json:"data"`
}

// PullSecretHandler serves the registry pull Secrets of customer pools.
type PullSecretHandler struct {
	poolRepo    *repository.AgentPoolRepository
	pulls       *repository.PullSecretRepository
	inventory   *repository.IdentityBindingRepository
	db          *gorm.DB
	authService *auth.Service
	rbacService *rbac.Service
}

// NewPullSecretHandler builds the handler.
func NewPullSecretHandler(poolRepo *repository.AgentPoolRepository, pulls *repository.PullSecretRepository, db *gorm.DB, authService *auth.Service, rbacService *rbac.Service) *PullSecretHandler {
	return &PullSecretHandler{poolRepo: poolRepo, pulls: pulls, inventory: repository.NewIdentityBindingRepository(db), db: db, authService: authService, rbacService: rbacService}
}

func pullSecretResource(p *models.PullSecret) jsonapi.Resource[PullSecretAttributes] {
	var cred *string
	if p.RegistryCredentialID != nil {
		s := p.RegistryCredentialID.String()
		cred = &s
	}
	return jsonapi.Resource[PullSecretAttributes]{
		ID:   p.ID.String(),
		Type: "pull-secrets",
		Attributes: PullSecretAttributes{
			Name: p.Name, SecretName: p.SecretName, Registry: p.Registry, RegistryCredentialID: cred, Reference: p.Reference,
			DeclaredExternally: p.DeclaredExternally, ExternalManager: p.ExternalManager, ObjectPresent: p.ObjectPresent,
			ReportedAt: p.ReportedAt, CreatedAt: p.CreatedAt,
		},
		Relationships: PullSecretRelationships{AgentPool: jsonapi.ToOne(p.AgentPoolID.String(), "agent-pools")},
	}
}

// access checks the caller's right on the organization: manage for writes, membership for reads.
func (h *PullSecretHandler) access(c *gin.Context, orgID uuid.UUID, write bool) bool {
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		jsonapi.WriteError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return false
	}
	var ok bool
	if write {
		ok, err = h.rbacService.CheckOrgManageAgentPools(c.Request.Context(), user.ID, orgID)
	} else {
		ok, err = h.rbacService.UserInOrg(c.Request.Context(), user.ID, orgID)
	}
	if err != nil {
		jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		return false
	}
	if !ok {
		jsonapi.WriteError(c, http.StatusForbidden, "Forbidden", "You do not have permission to manage this pool's pull Secrets")
		return false
	}
	return true
}

func (h *PullSecretHandler) pool(c *gin.Context) (*models.AgentPool, bool) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "Agent pool not found")
		return nil, false
	}
	// A hosted pool's launchers are the platform's: its jobs pull with per-job credentials.
	pool, err := h.poolRepo.GetCustomerByID(id, false)
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "Agent pool not found")
		return nil, false
	}
	return pool, true
}

func (h *PullSecretHandler) pullSecret(c *gin.Context) (*models.PullSecret, bool) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "Pull Secret not found")
		return nil, false
	}
	p, err := h.pulls.GetByID(id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "Pull Secret not found")
		} else {
			jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		}
		return nil, false
	}
	return p, true
}

// validate checks a pull Secret's fields: a create-mode one is built from a registry credential
// of its own organization, which a reference-mode one does not need.
func (h *PullSecretHandler) validate(p *models.PullSecret) string {
	switch {
	case strings.TrimSpace(p.Name) == "" || len(p.Name) > 100:
		return "name must be 1 to 100 characters"
	case len(p.SecretName) > 253 || !serviceAccountName.MatchString(p.SecretName):
		return "secret-name must be a Kubernetes Secret name (lowercase letters, digits, '-' and '.')"
	case strings.TrimSpace(p.Registry) == "" || strings.ContainsAny(p.Registry, "/ ") || len(p.Registry) > 253:
		return "registry must be a registry host, such as ghcr.io or registry.example:5000"
	case !p.Reference && p.RegistryCredentialID == nil:
		return "a pull Secret Stackweaver creates needs registry-credential-id, a registry credential; set reference to use a Secret declared elsewhere"
	}
	if p.RegistryCredentialID != nil {
		var n int64
		if err := h.db.Model(&models.AnsibleCredential{}).Where("id = ? AND organization_id = ? AND type = ?", *p.RegistryCredentialID, p.OrganizationID, models.CredentialTypeRegistry).Count(&n).Error; err != nil || n == 0 {
			return "registry-credential-id must name a registry credential of the pool's organization"
		}
	}
	return ""
}

// clash refuses a create-mode pull Secret whose name another manager holds, from the pool
// launcher's last report (Order 1 of D8, AC49a). It writes the 409 and returns true on a clash.
func (h *PullSecretHandler) clash(c *gin.Context, p *models.PullSecret) bool {
	if p.Reference {
		return false
	}
	obj, err := h.inventory.ExternalObject(p.AgentPoolID, "Secret", p.SecretName)
	if err != nil {
		jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		return true
	}
	if obj != nil {
		jsonapi.WriteError(c, http.StatusConflict, "Conflict", fmt.Sprintf(
			"%s exists in namespace %s and is managed by %s; reference it by name instead of creating it", obj.Name, obj.Namespace, obj.ExternalManager))
		return true
	}
	return false
}

// apply copies the request's attributes onto p; an unparsable credential id is reported.
func applyPullSecretAttributes(p *models.PullSecret, req *pullSecretRequest) string {
	a := req.Data.Attributes
	if a.Name != nil {
		p.Name = strings.TrimSpace(*a.Name)
	}
	if a.SecretName != nil {
		p.SecretName = strings.TrimSpace(*a.SecretName)
	}
	if a.Registry != nil {
		p.Registry = strings.TrimSpace(*a.Registry)
	}
	if a.RegistryCredentialID != nil {
		if *a.RegistryCredentialID == "" {
			p.RegistryCredentialID = nil
		} else {
			id, err := uuid.Parse(*a.RegistryCredentialID)
			if err != nil {
				return "registry-credential-id must be a credential id"
			}
			p.RegistryCredentialID = &id
		}
	}
	if a.Reference != nil {
		p.Reference = *a.Reference
	}
	return ""
}

// Create adds a registry pull Secret to a customer pool.
//
// POST /api/v2/agent-pools/:id/pull-secrets
func (h *PullSecretHandler) Create(c *gin.Context) {
	pool, ok := h.pool(c)
	if !ok || !h.access(c, pool.OrganizationID, true) {
		return
	}
	var req pullSecretRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", err.Error())
		return
	}
	p := &models.PullSecret{ID: uuid.New(), OrganizationID: pool.OrganizationID, AgentPoolID: pool.ID}
	if detail := applyPullSecretAttributes(p, &req); detail != "" {
		jsonapi.WriteError(c, http.StatusUnprocessableEntity, "Unprocessable Entity", detail)
		return
	}
	if detail := h.validate(p); detail != "" {
		jsonapi.WriteError(c, http.StatusUnprocessableEntity, "Unprocessable Entity", detail)
		return
	}
	if h.clash(c, p) {
		return
	}
	if err := h.pulls.Create(p); err != nil {
		if strings.Contains(err.Error(), "duplicate") || strings.Contains(err.Error(), "unique") {
			jsonapi.WriteError(c, http.StatusConflict, "Conflict", "the pool already has a pull Secret of that name")
			return
		}
		jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	jsonapi.WriteDocument(c, http.StatusCreated, pullSecretResource(p))
}

// List returns a pool's pull Secrets, readable by the organization's members.
//
// GET /api/v2/agent-pools/:id/pull-secrets
func (h *PullSecretHandler) List(c *gin.Context) {
	pool, ok := h.pool(c)
	if !ok || !h.access(c, pool.OrganizationID, false) {
		return
	}
	list, err := h.pulls.ListByPool(pool.ID)
	if err != nil {
		jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	data := make([]jsonapi.Resource[PullSecretAttributes], 0, len(list))
	for i := range list {
		data = append(data, pullSecretResource(&list[i]))
	}
	jsonapi.WriteDocumentMeta(c, http.StatusOK, data, jsonapi.NewPaginationMeta(1, len(list), int64(len(list))))
}

// Get reads one pull Secret.
//
// GET /api/v2/pull-secrets/:id
func (h *PullSecretHandler) Get(c *gin.Context) {
	p, ok := h.pullSecret(c)
	if !ok || !h.access(c, p.OrganizationID, false) {
		return
	}
	jsonapi.WriteDocument(c, http.StatusOK, pullSecretResource(p))
}

// Update changes a pull Secret. Once its pool's launcher reported its Secret as managed outside
// Stackweaver, its Kubernetes fields are read-only (AC49b); its name stays Stackweaver's.
//
// PATCH /api/v2/pull-secrets/:id
func (h *PullSecretHandler) Update(c *gin.Context) {
	p, ok := h.pullSecret(c)
	if !ok || !h.access(c, p.OrganizationID, true) {
		return
	}
	var req pullSecretRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", err.Error())
		return
	}
	a := req.Data.Attributes
	if p.DeclaredExternally && (a.SecretName != nil || a.Registry != nil || a.RegistryCredentialID != nil || a.Reference != nil) {
		jsonapi.WriteError(c, http.StatusConflict, "Conflict", fmt.Sprintf("the pull Secret is declared outside Stackweaver (%s); change it where it is declared", p.ExternalManager))
		return
	}
	nameBefore, refBefore := p.SecretName, p.Reference
	if detail := applyPullSecretAttributes(p, &req); detail != "" {
		jsonapi.WriteError(c, http.StatusUnprocessableEntity, "Unprocessable Entity", detail)
		return
	}
	if detail := h.validate(p); detail != "" {
		jsonapi.WriteError(c, http.StatusUnprocessableEntity, "Unprocessable Entity", detail)
		return
	}
	if (p.SecretName != nameBefore || p.Reference != refBefore) && h.clash(c, p) {
		return
	}
	if err := h.pulls.Update(p); err != nil {
		jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	jsonapi.WriteDocument(c, http.StatusOK, pullSecretResource(p))
}

// Delete removes a pull Secret. One declared outside Stackweaver is refused (AC49b): its Secret
// belongs to its manager.
//
// DELETE /api/v2/pull-secrets/:id
func (h *PullSecretHandler) Delete(c *gin.Context) {
	p, ok := h.pullSecret(c)
	if !ok || !h.access(c, p.OrganizationID, true) {
		return
	}
	if p.DeclaredExternally && !p.Reference {
		jsonapi.WriteError(c, http.StatusConflict, "Conflict", fmt.Sprintf("the pull Secret is declared outside Stackweaver (%s); remove it there, or reference it instead", p.ExternalManager))
		return
	}
	if err := h.pulls.Delete(p.ID); err != nil {
		jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	c.Status(http.StatusNoContent)
}
