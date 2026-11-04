// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"errors"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/jsonapi"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/settings"
	"gorm.io/gorm"
)

// RunImageAttributes is a run image on the wire (#933, D6, D15).
type RunImageAttributes struct {
	Name                 string    `json:"name"`
	Kind                 string    `json:"kind"`
	Image                string    `json:"image"`
	Digest               string    `json:"digest"`
	RegistryCredentialID *string   `json:"registry-credential-id"`
	Description          string    `json:"description"`
	CreatedAt            time.Time `json:"created-at"`
	UpdatedAt            time.Time `json:"updated-at"`
}

// RunImageRelationships names the image's organization.
type RunImageRelationships struct {
	Organization jsonapi.Relationship `json:"organization"`
}

type runImageRequest struct {
	Data struct {
		Type       string `json:"type"`
		Attributes struct {
			Name                 *string `json:"name"`
			Kind                 *string `json:"kind"`
			Image                *string `json:"image"`
			Digest               *string `json:"digest"`
			RegistryCredentialID *string `json:"registry-credential-id"`
			Description          *string `json:"description"`
		} `json:"attributes"`
	} `json:"data"`
}

// RunImageHandler serves an organization's run images.
type RunImageHandler struct {
	db          *gorm.DB
	orgRepo     *repository.OrganizationRepository
	authService *auth.Service
	rbacService *rbac.Service
	// allowed is images.allowed_registries; empty accepts any registry.
	allowed []string
}

// NewRunImageHandler builds the handler with the deployment's allowlist.
func NewRunImageHandler(db *gorm.DB, orgRepo *repository.OrganizationRepository, authService *auth.Service, rbacService *rbac.Service) *RunImageHandler {
	return &RunImageHandler{db: db, orgRepo: orgRepo, authService: authService, rbacService: rbacService, allowed: settings.AllowedRegistries(os.Getenv)}
}

func runImageResource(r *models.RunImage) jsonapi.Resource[RunImageAttributes] {
	var cred *string
	if r.RegistryCredentialID != nil {
		s := r.RegistryCredentialID.String()
		cred = &s
	}
	return jsonapi.Resource[RunImageAttributes]{
		ID:   r.ID.String(),
		Type: "run-images",
		Attributes: RunImageAttributes{
			Name: r.Name, Kind: r.Kind, Image: r.Image, Digest: r.Digest, RegistryCredentialID: cred,
			Description: r.Description, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
		},
		Relationships: RunImageRelationships{Organization: jsonapi.ToOne(r.OrganizationID.String(), "organizations")},
	}
}

// access checks the caller's right on the organization: managing agent pools for writes, which is
// who configures where jobs run, and membership for reads.
func (h *RunImageHandler) access(c *gin.Context, orgID uuid.UUID, write bool) bool {
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
		jsonapi.WriteError(c, http.StatusForbidden, "Forbidden", "You do not have permission to manage this organization's run images")
		return false
	}
	return true
}

func (h *RunImageHandler) image(c *gin.Context) (*models.RunImage, bool) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "Run image not found")
		return nil, false
	}
	var r models.RunImage
	if err := h.db.First(&r, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "Run image not found")
		} else {
			jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		}
		return nil, false
	}
	return &r, true
}

var imageDigest = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

// validate checks a run image and answers the request when it is not valid.
func (h *RunImageHandler) validate(c *gin.Context, r *models.RunImage) bool {
	detail := ""
	switch {
	case strings.TrimSpace(r.Name) == "" || len(r.Name) > 100:
		detail = "name must be 1 to 100 characters"
	case r.Kind != models.RunImageKindTofu && r.Kind != models.RunImageKindAnsible:
		detail = "kind must be tofu or ansible"
	case len(r.Image) > 500 || strings.Contains(r.Image, "@") || !settings.ValidImageReference(r.Image):
		detail = "image must be an image reference with an optional tag; pin it with digest"
	case r.Digest != "" && !imageDigest.MatchString(r.Digest):
		detail = "digest must be sha256:<64 lowercase hex characters>"
	case !settings.RegistryAllowed(r.Image, h.allowed):
		detail = "the image's registry is not in images.allowed_registries (" + strings.Join(h.allowed, ", ") + ")"
	}
	if detail == "" && r.RegistryCredentialID != nil {
		var cred models.AnsibleCredential
		err := h.db.Select("id", "organization_id", "type").First(&cred, "id = ?", *r.RegistryCredentialID).Error
		if err != nil || cred.OrganizationID != r.OrganizationID || cred.Type != models.CredentialTypeRegistry {
			detail = "registry-credential-id must name a registry credential of the organization"
		}
	}
	if detail != "" {
		jsonapi.WriteError(c, http.StatusUnprocessableEntity, "Unprocessable Entity", detail)
		return false
	}
	return true
}

func applyRunImageAttributes(r *models.RunImage, req *runImageRequest) {
	a := req.Data.Attributes
	if a.Name != nil {
		r.Name = strings.TrimSpace(*a.Name)
	}
	if a.Kind != nil {
		r.Kind = *a.Kind
	}
	if a.Image != nil {
		r.Image = strings.TrimSpace(*a.Image)
	}
	if a.Digest != nil {
		r.Digest = strings.TrimSpace(*a.Digest)
	}
	if a.Description != nil {
		r.Description = *a.Description
	}
	if a.RegistryCredentialID != nil {
		if *a.RegistryCredentialID == "" {
			r.RegistryCredentialID = nil
		} else if id, err := uuid.Parse(*a.RegistryCredentialID); err == nil {
			r.RegistryCredentialID = &id
		} else {
			bad := uuid.Nil
			r.RegistryCredentialID = &bad
		}
	}
}

// Create adds a run image to an organization.
//
// POST /api/v2/organizations/:name/run-images
func (h *RunImageHandler) Create(c *gin.Context) {
	org, err := h.orgRepo.GetByName(c.Param("name"))
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "Organization not found")
		return
	}
	if !h.access(c, org.ID, true) {
		return
	}
	var req runImageRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", err.Error())
		return
	}
	r := &models.RunImage{ID: uuid.New(), OrganizationID: org.ID}
	applyRunImageAttributes(r, &req)
	if !h.validate(c, r) {
		return
	}
	if err := h.db.Create(r).Error; err != nil {
		if repository.IsUniqueViolation(err) {
			jsonapi.WriteError(c, http.StatusConflict, "Conflict", "the organization already has a run image of that name")
			return
		}
		jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	jsonapi.WriteDocument(c, http.StatusCreated, runImageResource(r))
}

// List returns an organization's run images, readable by its members.
//
// GET /api/v2/organizations/:name/run-images
func (h *RunImageHandler) List(c *gin.Context) {
	org, err := h.orgRepo.GetByName(c.Param("name"))
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "Organization not found")
		return
	}
	if !h.access(c, org.ID, false) {
		return
	}
	var list []models.RunImage
	q := h.db.Where("organization_id = ?", org.ID)
	if kind := c.Query("filter[kind]"); kind != "" {
		q = q.Where("kind = ?", kind)
	}
	if err := q.Order("name").Find(&list).Error; err != nil {
		jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	data := make([]jsonapi.Resource[RunImageAttributes], 0, len(list))
	for i := range list {
		data = append(data, runImageResource(&list[i]))
	}
	jsonapi.WriteDocumentMeta(c, http.StatusOK, data, jsonapi.NewPaginationMeta(1, len(list), int64(len(list))))
}

// Get reads one run image.
//
// GET /api/v2/run-images/:id
func (h *RunImageHandler) Get(c *gin.Context) {
	r, ok := h.image(c)
	if !ok || !h.access(c, r.OrganizationID, false) {
		return
	}
	jsonapi.WriteDocument(c, http.StatusOK, runImageResource(r))
}

// Update changes a run image; its kind is fixed once levels may select it.
//
// PATCH /api/v2/run-images/:id
func (h *RunImageHandler) Update(c *gin.Context) {
	r, ok := h.image(c)
	if !ok || !h.access(c, r.OrganizationID, true) {
		return
	}
	var req runImageRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", err.Error())
		return
	}
	if req.Data.Attributes.Kind != nil && *req.Data.Attributes.Kind != r.Kind {
		jsonapi.WriteError(c, http.StatusUnprocessableEntity, "Unprocessable Entity", "a run image's kind cannot change; create another")
		return
	}
	applyRunImageAttributes(r, &req)
	if !h.validate(c, r) {
		return
	}
	if err := h.db.Save(r).Error; err != nil {
		if repository.IsUniqueViolation(err) {
			jsonapi.WriteError(c, http.StatusConflict, "Conflict", "the organization already has a run image of that name")
			return
		}
		jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	jsonapi.WriteDocument(c, http.StatusOK, runImageResource(r))
}

// Delete removes a run image and clears it from every level that selected it, which then defers
// to the next level.
//
// DELETE /api/v2/run-images/:id
func (h *RunImageHandler) Delete(c *gin.Context) {
	r, ok := h.image(c)
	if !ok || !h.access(c, r.OrganizationID, true) {
		return
	}
	err := h.db.Transaction(func(tx *gorm.DB) error {
		for _, clear := range []struct {
			model  any
			column string
		}{
			{&models.Workspace{}, "run_image_id"},
			{&models.AnsibleJobTemplate{}, "run_image_id"},
			{&models.AnsibleInventorySource{}, "run_image_id"},
			{&models.Project{}, "tofu_run_image_id"},
			{&models.Project{}, "ansible_run_image_id"},
			{&models.Organization{}, "tofu_run_image_id"},
			{&models.Organization{}, "ansible_run_image_id"},
		} {
			if err := tx.Model(clear.model).Where(clear.column+" = ?", r.ID).Update(clear.column, nil).Error; err != nil {
				return err
			}
		}
		return tx.Delete(&models.RunImage{}, "id = ?", r.ID).Error
	})
	if err != nil {
		jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	c.Status(http.StatusNoContent)
}
