// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package terraform

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/jsonapi"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	varsvc "github.com/michielvha/stackweaver/core/services/variable" // aliased: handlers here use a local `variable` for the model, which would shadow the package name
)

// maskedVariableValue is the placeholder every read path returns for a sensitive value - the
// real value is never sent to clients (TFE-compatible). Update compares against it so a client
// that round-trips a masked read does not overwrite the real secret with bullets (AUD-105). It
// mirrors maskedValue in the variable-set handler, which lives in a different package.
const maskedVariableValue = "••••••••"

type VariableHandlerV2 struct {
	variableRepo    *repository.VariableRepository
	workspaceRepo   *repository.WorkspaceRepository
	orgRepo         *repository.OrganizationRepository
	projectRepo     *repository.ProjectRepository
	authService     *auth.Service
	rbacService     *rbac.Service
	variableService *varsvc.Service
}

func NewVariableHandlerV2(
	variableRepo *repository.VariableRepository,
	workspaceRepo *repository.WorkspaceRepository,
	authService *auth.Service,
	rbacService *rbac.Service,
	variableService *varsvc.Service,
) *VariableHandlerV2 {
	return &VariableHandlerV2{
		variableRepo:    variableRepo,
		workspaceRepo:   workspaceRepo,
		authService:     authService,
		rbacService:     rbacService,
		variableService: variableService,
	}
}

// SetRepositories allows setting org and project repos for building TFE-compatible links
func (h *VariableHandlerV2) SetRepositories(orgRepo *repository.OrganizationRepository, projectRepo *repository.ProjectRepository) {
	h.orgRepo = orgRepo
	h.projectRepo = projectRepo
}

// formatVariableResponse formats a variable in TFE-compatible JSON:API format
// Reference: https://developer.hashicorp.com/terraform/enterprise/api-docs/workspace-variables
func (h *VariableHandlerV2) formatVariableResponse(variable *models.Variable, workspaceID string) jsonapi.Resource[WorkspaceVariableAttributes] {
	// Get workspace to build proper links
	workspace, err := h.workspaceRepo.GetByID(workspaceID)
	var orgName, workspaceName string
	if err == nil {
		// Try to get organization and workspace names for links
		if h.projectRepo != nil && h.orgRepo != nil {
			project, _ := h.projectRepo.GetByID(workspace.ProjectID)
			if project != nil {
				org, _ := h.orgRepo.GetByID(project.OrganizationID)
				if org != nil {
					orgName = org.Name
					workspaceName = workspace.Name
				}
			}
		}
	}

	// Build configurable relationship link
	var configurableLink string
	if orgName != "" && workspaceName != "" {
		configurableLink = fmt.Sprintf("/api/v2/organizations/%s/workspaces/%s", orgName, workspaceName)
	} else {
		configurableLink = fmt.Sprintf("/api/v2/workspaces/%s", workspaceID)
	}

	// TFE-compatible response format
	// Note: TFE uses "configurable" relationship, not "workspace"
	// Also uses type "vars" not "variables"
	// TFE spec: Sensitive variable values must be masked in API responses
	value := variable.Value
	if variable.Sensitive {
		value = maskedVariableValue
	}

	configurable := jsonapi.ToOne(workspaceID, "workspaces")
	configurable.Links = jsonapi.RelatedLink{Related: configurableLink}
	return jsonapi.Resource[WorkspaceVariableAttributes]{
		ID:   variable.ID,
		Type: "vars", // TFE uses "vars" not "variables"
		Attributes: WorkspaceVariableAttributes{
			Key:         variable.Key,
			Value:       value, // Masked if sensitive
			Description: variable.Description,
			Sensitive:   variable.Sensitive,
			Category:    variable.Category,
			HCL:         variable.HCL,
		},
		// TFE uses "configurable", not "workspace".
		Relationships: WorkspaceVariableRelationships{Configurable: configurable},
		Links:         jsonapi.SelfLink{Self: fmt.Sprintf("/api/v2/workspaces/%s/vars/%s", workspaceID, variable.ID)},
	}
}

// WorkspaceVariableAttributes is the workspace vars attribute block. VersionID is always the
// empty string (TFE includes the member; there is no versioning subsystem behind it).
type WorkspaceVariableAttributes struct {
	Key         string `json:"key"`
	Value       string `json:"value"`
	Description string `json:"description"`
	Sensitive   bool   `json:"sensitive"`
	Category    string `json:"category"`
	HCL         bool   `json:"hcl"`
	VersionID   string `json:"version-id"`
}

// WorkspaceVariableRelationships carries TFE's "configurable" relation.
type WorkspaceVariableRelationships struct {
	Configurable jsonapi.Relationship `json:"configurable"`
}

// CreateVariableRequestV2 uses JSON:API format (TFE-compatible)
// Reference: https://developer.hashicorp.com/terraform/enterprise/api-docs/workspace-variables#create-a-variable
type CreateVariableRequestV2 struct {
	Data struct {
		Type       string `json:"type"` // Must be "vars"
		Attributes struct {
			Key string `json:"key" binding:"required"`
			// Value carries no `required` binding (#674): an empty value is legitimate - `KEY=`
			// is ordinary .env content and TFE accepts it. The HCL combination is rejected in
			// the handler instead, where a specific reason can be given.
			Value       string `json:"value"`
			Description string `json:"description,omitempty"`
			Category    string `json:"category,omitempty"`  // "terraform" or "env", defaults to "terraform"
			HCL         bool   `json:"hcl,omitempty"`       // Defaults to false
			Sensitive   bool   `json:"sensitive,omitempty"` // Defaults to false
		} `json:"attributes"`
	} `json:"data"`
}

// storedPlaintext returns the variable's value as the tfvars writers will eventually see it,
// decrypting when it is held encrypted at rest. A sensitive variable stores ciphertext, and the
// ciphertext of an empty string is not itself empty, so an emptiness check that skipped this
// would wave through exactly the sensitive-and-HCL case it is meant to catch.
//
// An undecryptable value is returned as-is on purpose: it is certainly not the empty string, so
// the caller treats it as non-empty and a decryption hiccup cannot block an otherwise valid edit.
func (h *VariableHandlerV2) storedPlaintext(v *models.Variable) string {
	if !v.Encrypted || h.variableService == nil {
		return v.Value
	}
	plaintext, err := h.variableService.Decrypt(v.Value)
	if err != nil {
		return v.Value
	}
	return plaintext
}

// UpdateVariableRequestV2 uses JSON:API format (TFE-compatible)
// Reference: https://developer.hashicorp.com/terraform/enterprise/api-docs/workspace-variables#update-variables
//
// Every attribute is a pointer so an omitted field (nil, left unchanged) is distinguishable from
// an explicit empty one (#815): a description or value can be cleared by sending "". TFE draws the
// same distinction, and go-tfe's VariableUpdateOptions sends pointers for all of these.
type UpdateVariableRequestV2 struct {
	Data struct {
		ID         string `json:"id"`   // Variable ID
		Type       string `json:"type"` // Must be "vars"
		Attributes struct {
			Key         *string `json:"key,omitempty"`
			Value       *string `json:"value,omitempty"`
			Description *string `json:"description,omitempty"`
			Category    *string `json:"category,omitempty"`
			HCL         *bool   `json:"hcl,omitempty"`
			Sensitive   *bool   `json:"sensitive,omitempty"`
		} `json:"attributes"`
	} `json:"data"`
}

// ListByWorkspace lists variables for a workspace (TFE-compatible)
// GET /api/v2/workspaces/:id/variables
func (h *VariableHandlerV2) ListByWorkspace(c *gin.Context) {
	workspaceID := c.Param("id")
	if workspaceID == "" {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Invalid workspace ID")
		return
	}

	// Verify workspace exists and get project ID
	workspace, err := h.workspaceRepo.GetByID(workspaceID)
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "Workspace not found")
		return
	}

	// Check permission: variables read
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		jsonapi.WriteError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return
	}

	hasPermission, err := h.rbacService.CheckVariablePermission(c.Request.Context(), user.ID, workspaceID, workspace.ProjectID, "read")
	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to check permissions")
		return
	}
	if !hasPermission {
		jsonapi.WriteError(c, http.StatusForbidden, "Forbidden", "Insufficient permissions to view variables")
		return
	}

	variables, err := h.variableRepo.ListByWorkspace(workspaceID)
	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to list variables")
		return
	}

	// Format variables in TFE-compatible JSON:API format
	variablesData := make([]jsonapi.Resource[WorkspaceVariableAttributes], len(variables))
	for i := range variables {
		variablesData[i] = h.formatVariableResponse(&variables[i], workspaceID)
	}

	// TFE-compatible response format
	jsonapi.WriteDocumentMeta(c, http.StatusOK, variablesData, jsonapi.NewFullPageMeta(len(variablesData)))
}

// Get returns a single workspace variable by ID (TFE-compatible).
// GET /api/v2/workspaces/:id/vars/:variable_id
// Provider uses this for Read/refresh; missing endpoint caused 404 → "resource gone" → drift.
func (h *VariableHandlerV2) Get(c *gin.Context) {
	workspaceID := c.Param("id")
	if workspaceID == "" {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Invalid workspace ID")
		return
	}
	variableID := c.Param("variable_id")
	if variableID == "" {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Invalid variable ID")
		return
	}

	workspace, err := h.workspaceRepo.GetByID(workspaceID)
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "Workspace not found")
		return
	}

	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		jsonapi.WriteError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return
	}
	hasPermission, err := h.rbacService.CheckVariablePermission(c.Request.Context(), user.ID, workspaceID, workspace.ProjectID, "read")
	if err != nil || !hasPermission {
		jsonapi.WriteError(c, http.StatusForbidden, "Forbidden", "Insufficient permissions to view variables")
		return
	}

	variable, err := h.variableRepo.GetByID(variableID)
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "Variable not found")
		return
	}
	if variable.WorkspaceID != workspaceID {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "Variable not found")
		return
	}

	jsonapi.WriteDocument(c, http.StatusOK, h.formatVariableResponse(variable, workspaceID))
}

// Create creates a new variable for a workspace (TFE-compatible)
// POST /api/v2/workspaces/:id/variables
func (h *VariableHandlerV2) Create(c *gin.Context) {
	workspaceID := c.Param("id")
	if workspaceID == "" {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Invalid workspace ID")
		return
	}

	// Verify workspace exists and get project ID
	workspace, err := h.workspaceRepo.GetByID(workspaceID)
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "Workspace not found")
		return
	}

	// Check permission: variables write
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		jsonapi.WriteError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return
	}

	hasPermission, err := h.rbacService.CheckVariablePermission(c.Request.Context(), user.ID, workspaceID, workspace.ProjectID, "write")
	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to check permissions")
		return
	}
	if !hasPermission {
		jsonapi.WriteError(c, http.StatusForbidden, "Forbidden", "Insufficient permissions to create variables")
		return
	}

	var req CreateVariableRequestV2
	if err := c.ShouldBindJSON(&req); err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", err.Error())
		return
	}

	// Validate JSON:API format
	if req.Data.Type != "vars" {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "data.type must be 'vars'")
		return
	}

	attrs := req.Data.Attributes

	// Set defaults
	category := attrs.Category
	if category == "" {
		category = "terraform" // TFE default
	}
	if category != "terraform" && category != "env" {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "category must be 'terraform' or 'env'")
		return
	}

	// #674: an empty value is allowed - `KEY=` is ordinary .env content and TFE accepts it - but
	// not in combination with the HCL flag, which would write an unfinished `key = ` into the
	// generated tfvars. 422 rather than the 400 its neighbours use: the payload is well-formed
	// and only its meaning is rejected, which is the split the duplicate-and-conflict guideline
	// draws. (The surrounding 400s predate that guideline.)
	if varsvc.IncompleteHCLValue(attrs.HCL, attrs.Value) {
		jsonapi.WriteError(c, http.StatusUnprocessableEntity, "Unprocessable Entity",
			"An HCL variable cannot have an empty value - it would render as an incomplete assignment in the generated tfvars. Unset hcl, or supply a value.")
		return
	}

	// Check if variable with same key already exists
	existing, _ := h.variableRepo.GetByWorkspaceAndKey(workspaceID, attrs.Key)
	if existing != nil {
		jsonapi.WriteError(c, http.StatusConflict, "Conflict", "Variable with this key already exists in this workspace")
		return
	}

	// Encrypt sensitive values
	var finalValue string
	var encrypted bool
	if attrs.Sensitive && h.variableService != nil {
		encryptedValue, err := h.variableService.Encrypt(attrs.Value)
		if err != nil {
			jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", fmt.Sprintf("Failed to encrypt variable: %v", err))
			return
		}
		finalValue = encryptedValue
		encrypted = true
	} else {
		finalValue = attrs.Value
		encrypted = false
	}

	variable := &models.Variable{
		WorkspaceID: workspaceID,
		Key:         attrs.Key,
		Value:       finalValue,
		Description: attrs.Description,
		Category:    category,
		HCL:         attrs.HCL,
		Encrypted:   encrypted,
		Sensitive:   attrs.Sensitive,
	}

	if err := h.variableRepo.Create(variable); err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to create variable")
		return
	}

	// TFE-compatible response format
	jsonapi.WriteDocument(c, http.StatusCreated, h.formatVariableResponse(variable, workspaceID))
}

// Update updates a variable by ID (TFE-compatible)
// PATCH /api/v2/workspaces/:id/variables/:variable_id
func (h *VariableHandlerV2) Update(c *gin.Context) {
	workspaceID := c.Param("id")
	if workspaceID == "" {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Invalid workspace ID")
		return
	}

	variableID := c.Param("variable_id")
	if variableID == "" {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Invalid variable ID")
		return
	}

	// Get workspace for permission check
	workspace, err := h.workspaceRepo.GetByID(workspaceID)
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "Workspace not found")
		return
	}

	// Check permission: variables write
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		jsonapi.WriteError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return
	}

	hasPermission, err := h.rbacService.CheckVariablePermission(c.Request.Context(), user.ID, workspaceID, workspace.ProjectID, "write")
	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to check permissions")
		return
	}
	if !hasPermission {
		jsonapi.WriteError(c, http.StatusForbidden, "Forbidden", "Insufficient permissions to update variables")
		return
	}

	variable, err := h.variableRepo.GetByID(variableID)
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "Variable not found")
		return
	}

	// Verify variable belongs to workspace
	if variable.WorkspaceID != workspaceID {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Variable does not belong to this workspace")
		return
	}

	var req UpdateVariableRequestV2
	if err := c.ShouldBindJSON(&req); err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", err.Error())
		return
	}

	// Validate JSON:API format
	if req.Data.Type != "vars" {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "data.type must be 'vars'")
		return
	}

	// Validate ID matches
	if req.Data.ID != "" && req.Data.ID != variableID {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "data.id must match the variable ID in the URL")
		return
	}

	attrs := req.Data.Attributes

	// #815: nil means "not supplied, leave it alone"; an explicit "" is a real request to clear
	// the field. AUD-105: a value equal to the mask means the client round-tripped a masked read
	// (the SPA and the TFE provider resubmit whole resources when editing an unrelated field), so
	// it is treated as not supplied rather than written over the real secret.
	newValue := attrs.Value
	if newValue != nil && *newValue == maskedVariableValue {
		newValue = nil
	}

	// Determine if variable should be sensitive after update
	willBeSensitive := variable.Sensitive
	if attrs.Sensitive != nil {
		willBeSensitive = *attrs.Sensitive
	}

	if attrs.Key != nil {
		if *attrs.Key == "" {
			jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "key cannot be empty")
			return
		}
		// Check if new key conflicts with existing variable
		if *attrs.Key != variable.Key {
			existing, _ := h.variableRepo.GetByWorkspaceAndKey(workspaceID, *attrs.Key)
			if existing != nil {
				jsonapi.WriteError(c, http.StatusConflict, "Conflict", "Variable with this key already exists in this workspace")
				return
			}
		}
		variable.Key = *attrs.Key
	}
	if newValue != nil {
		// Encrypt value if sensitive
		if willBeSensitive && h.variableService != nil {
			encryptedValue, err := h.variableService.Encrypt(*newValue)
			if err != nil {
				jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", fmt.Sprintf("Failed to encrypt variable: %v", err))
				return
			}
			variable.Value = encryptedValue
			variable.Encrypted = true
		} else {
			variable.Value = *newValue
			// If changing from sensitive to non-sensitive, clear encryption
			if !willBeSensitive {
				variable.Encrypted = false
			}
		}
	}
	if attrs.Description != nil {
		variable.Description = *attrs.Description
	}
	if attrs.Category != nil {
		if *attrs.Category != "terraform" && *attrs.Category != "env" {
			jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "category must be 'terraform' or 'env'")
			return
		}
		variable.Category = *attrs.Category
	}
	if attrs.HCL != nil {
		variable.HCL = *attrs.HCL
	}
	// #674: the create path refuses an empty value on an HCL variable, and the same state is
	// reachable here two ways - clearing the value of an HCL variable, or flipping hcl on a
	// variable that is already empty - so the check runs against the resulting variable: the
	// incoming value when one was supplied, the decrypted stored one otherwise.
	resultingValue := h.storedPlaintext(variable)
	if newValue != nil {
		resultingValue = *newValue
	}
	if varsvc.IncompleteHCLValue(variable.HCL, resultingValue) {
		jsonapi.WriteError(c, http.StatusUnprocessableEntity, "Unprocessable Entity",
			"An HCL variable cannot have an empty value - it would render as an incomplete assignment in the generated tfvars. Supply a value in the same request, or leave hcl unset.")
		return
	}
	// AUD-044: when the sensitivity flag flips but no new value was supplied, reconcile the
	// stored value's encryption state so the Encrypted flag always tracks how the value is
	// actually stored. Previously a sensitive→non-sensitive toggle left the value as ciphertext
	// with Encrypted=true while unmasking it, desyncing the flags (and a non-sensitive→sensitive
	// toggle left a "sensitive" value in cleartext). A new-value update already sets encryption
	// correctly above, so this only handles the value-unchanged case, which includes a
	// round-tripped mask.
	if attrs.Sensitive != nil && *attrs.Sensitive != variable.Sensitive && newValue == nil && h.variableService != nil {
		switch {
		case *attrs.Sensitive && !variable.Encrypted:
			// non-sensitive → sensitive: encrypt the existing plaintext at rest.
			encryptedValue, err := h.variableService.Encrypt(variable.Value)
			if err != nil {
				jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", fmt.Sprintf("Failed to encrypt variable on sensitivity change: %v", err))
				return
			}
			variable.Value = encryptedValue
			variable.Encrypted = true
		case !*attrs.Sensitive && variable.Encrypted:
			// sensitive → non-sensitive: decrypt so we don't keep serving/storing stale ciphertext.
			plaintext, err := h.variableService.Decrypt(variable.Value)
			if err != nil {
				jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", fmt.Sprintf("Failed to decrypt variable on sensitivity change: %v", err))
				return
			}
			variable.Value = plaintext
			variable.Encrypted = false
		}
	}
	if attrs.Sensitive != nil {
		variable.Sensitive = *attrs.Sensitive
	}

	if err := h.variableRepo.Update(variable); err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to update variable")
		return
	}

	// TFE-compatible response format
	jsonapi.WriteDocument(c, http.StatusOK, h.formatVariableResponse(variable, workspaceID))
}

// Delete deletes a variable by ID (TFE-compatible)
// DELETE /api/v2/workspaces/:id/variables/:variable_id
func (h *VariableHandlerV2) Delete(c *gin.Context) {
	workspaceID := c.Param("id")
	if workspaceID == "" {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Invalid workspace ID")
		return
	}

	variableID := c.Param("variable_id")
	if variableID == "" {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Invalid variable ID")
		return
	}

	// Get workspace for permission check
	workspace, err := h.workspaceRepo.GetByID(workspaceID)
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "Workspace not found")
		return
	}

	// Check permission: variables write
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		jsonapi.WriteError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return
	}

	hasPermission, err := h.rbacService.CheckVariablePermission(c.Request.Context(), user.ID, workspaceID, workspace.ProjectID, "write")
	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to check permissions")
		return
	}
	if !hasPermission {
		jsonapi.WriteError(c, http.StatusForbidden, "Forbidden", "Insufficient permissions to delete variables")
		return
	}

	variable, err := h.variableRepo.GetByID(variableID)
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "Variable not found")
		return
	}

	// Verify variable belongs to workspace
	if variable.WorkspaceID != workspaceID {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Variable does not belong to this workspace")
		return
	}

	if err := h.variableRepo.Delete(variableID); err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to delete variable")
		return
	}

	c.Status(http.StatusNoContent)
}

// GetPlatformVariableKeys returns the list of platform variable keys for a workspace.
// GET /api/v2/workspaces/:id/platform-variables
// Used by frontend to show warnings when users create variables that would override platform variables.
func (h *VariableHandlerV2) GetPlatformVariableKeys(c *gin.Context) {
	workspaceID := c.Param("id")
	if workspaceID == "" {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Invalid workspace ID")
		return
	}

	// Verify workspace exists
	workspace, err := h.workspaceRepo.GetByID(workspaceID)
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "Workspace not found")
		return
	}

	// Check permission: variables read (same permission as listing variables)
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		jsonapi.WriteError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return
	}

	hasPermission, err := h.rbacService.CheckVariablePermission(c.Request.Context(), user.ID, workspaceID, workspace.ProjectID, "read")
	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to check permissions")
		return
	}
	if !hasPermission {
		jsonapi.WriteError(c, http.StatusForbidden, "Forbidden", "Insufficient permissions to view platform variables")
		return
	}

	// Get platform variable keys
	keys, err := h.variableService.GetPlatformVariableKeys(c.Request.Context(), workspaceID)
	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to get platform variable keys")
		return
	}

	// Return simple JSON array of keys
	jsonapi.WriteDocumentMeta(c, http.StatusOK, keys, jsonapi.NewFullPageMeta(len(keys)))
}
