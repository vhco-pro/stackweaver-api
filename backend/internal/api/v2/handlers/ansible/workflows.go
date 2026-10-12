// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package ansible

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/apierror"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/jsonapi"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/services/ansible"
	"gorm.io/datatypes"
)

// WorkflowHandler handles Ansible workflow template endpoints
type WorkflowHandler struct {
	workflowRepo *repository.AnsibleWorkflowRepository
	orgRepo      *repository.OrganizationRepository
	projectRepo  *repository.ProjectRepository
	authService  *auth.Service
	rbacService  *rbac.Service
	// engine executes workflow runs, and owns the rule for what a workflow, a node and an edge
	// may name. Every write asks it, so it is required.
	engine *ansible.WorkflowEngineService
}

// NewWorkflowHandler creates a new WorkflowHandler
func NewWorkflowHandler(
	workflowRepo *repository.AnsibleWorkflowRepository,
	orgRepo *repository.OrganizationRepository,
	projectRepo *repository.ProjectRepository,
	authService *auth.Service,
	rbacService *rbac.Service,
	engine *ansible.WorkflowEngineService,
) *WorkflowHandler {
	return &WorkflowHandler{
		workflowRepo: workflowRepo,
		orgRepo:      orgRepo,
		projectRepo:  projectRepo,
		authService:  authService,
		rbacService:  rbacService,
		engine:       engine,
	}
}

// ============================================================================
// Request/Response types
// ============================================================================

type CreateWorkflowRequest struct {
	Data struct {
		Type       string `json:"type"`
		Attributes struct {
			Name                 string `json:"name"`
			Description          string `json:"description"`
			AllowSimultaneous    bool   `json:"allow-simultaneous"`
			AskVariablesOnLaunch bool   `json:"ask-variables-on-launch"`
			AskInventoryOnLaunch bool   `json:"ask-inventory-on-launch"`
			AskLimitOnLaunch     bool   `json:"ask-limit-on-launch"`
			ExtraVars            string `json:"extra-vars"`
			Limit                string `json:"limit"`
			SurveyEnabled        bool   `json:"survey-enabled"`
		} `json:"attributes"`
		Relationships struct {
			Project struct {
				Data *struct {
					ID string `json:"id"`
				} `json:"data"`
			} `json:"project"`
			Inventory struct {
				Data *struct {
					ID string `json:"id"`
				} `json:"data"`
			} `json:"inventory"`
		} `json:"relationships"`
	} `json:"data"`
}

// UpdateWorkflowRequest is the PATCH document of a workflow. Every attribute is a pointer because
// absent and zero mean different things here: an attribute the document leaves out is not
// touched, one it carries is stored, the empty string and false included.
type UpdateWorkflowRequest struct {
	Data struct {
		Type       string `json:"type"`
		Attributes struct {
			Name                 *string `json:"name"`
			Description          *string `json:"description"`
			AllowSimultaneous    *bool   `json:"allow-simultaneous"`
			AskVariablesOnLaunch *bool   `json:"ask-variables-on-launch"`
			AskInventoryOnLaunch *bool   `json:"ask-inventory-on-launch"`
			AskLimitOnLaunch     *bool   `json:"ask-limit-on-launch"`
			ExtraVars            *string `json:"extra-vars"`
			Limit                *string `json:"limit"`
			SurveyEnabled        *bool   `json:"survey-enabled"`
		} `json:"attributes"`
	} `json:"data"`
}

type CreateNodeRequest struct {
	Data struct {
		Type       string `json:"type"`
		Attributes struct {
			NodeType               string  `json:"node-type"`
			Identifier             string  `json:"identifier"`
			PositionX              float64 `json:"position-x"`
			PositionY              float64 `json:"position-y"`
			ExtraVars              string  `json:"extra-vars"`
			Limit                  string  `json:"limit"`
			Tags                   string  `json:"tags"`
			SkipTags               string  `json:"skip-tags"`
			Verbosity              int     `json:"verbosity"`
			AllParentsMustConverge bool    `json:"all-parents-must-converge"`
			ApprovalTimeout        int     `json:"approval-timeout"`
			ApprovalMessage        string  `json:"approval-message"`
		} `json:"attributes"`
		Relationships struct {
			JobTemplate struct {
				Data *struct {
					ID string `json:"id"`
				} `json:"data"`
			} `json:"job-template"`
			Inventory struct {
				Data *struct {
					ID string `json:"id"`
				} `json:"data"`
			} `json:"inventory"`
			Credential struct {
				Data *struct {
					ID string `json:"id"`
				} `json:"data"`
			} `json:"credential"`
		} `json:"relationships"`
	} `json:"data"`
}

// UpdateNodeRequest is the PATCH document of a workflow node, with the same pointer rule as
// UpdateWorkflowRequest. It carries the attributes a node can change after it is created; its
// type, identifier, approval settings and relationships are set by CreateNodeRequest only.
type UpdateNodeRequest struct {
	Data struct {
		Type       string `json:"type"`
		Attributes struct {
			PositionX              *float64 `json:"position-x"`
			PositionY              *float64 `json:"position-y"`
			ExtraVars              *string  `json:"extra-vars"`
			Limit                  *string  `json:"limit"`
			Tags                   *string  `json:"tags"`
			SkipTags               *string  `json:"skip-tags"`
			Verbosity              *int     `json:"verbosity"`
			AllParentsMustConverge *bool    `json:"all-parents-must-converge"`
		} `json:"attributes"`
	} `json:"data"`
}

// errExtraVarsNotObject is the answer to an `extra-vars` attribute that is not a JSON object. Its
// text is the detail of the 400 the caller reads.
var errExtraVarsNotObject = errors.New("extra-vars must be a JSON object")

// extraVarsColumn turns the `extra-vars` attribute, a JSON object travelling as a string, into
// the value its jsonb column stores. The empty string clears the variables: it becomes the empty
// object, which is what a row created without any holds.
//
// Anything else must decode to a JSON object, and errExtraVarsNotObject is returned when it does
// not. Text that is not JSON would be refused by the column, which the caller would read as a
// 500; a list, a string, a number or null would be stored and then dropped without a word when
// the workflow runs, because the engine decodes the column into a map and discards the error.
func extraVarsColumn(attr string) (datatypes.JSON, error) {
	if attr == "" {
		return datatypes.JSON("{}"), nil
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal([]byte(attr), &object); err != nil || object == nil {
		// A nil map after a clean decode is the JSON null.
		return nil, errExtraVarsNotObject
	}
	return datatypes.JSON(attr), nil
}

// referentsAccepted answers the request when err, the result of checking what a workflow, a node
// or an edge names, is not nil, and reports whether the handler may go on to store the row.
//
// The checks are the engine's (CheckWorkflowReferents, CheckNodeReferents, CheckEdgeNodes): the
// engine is what later acts on a stored reference with no caller to authorize, so it owns the
// rule and applies the same one again at launch. A row the caller may not name is their input
// and answers 400 with the engine's sentence, which is the same for a row of another
// organization and for one that does not exist. Anything else is the database's and answers 500
// without its text.
func referentsAccepted(c *gin.Context, err error, failure string) bool {
	switch {
	case err == nil:
		return true
	case errors.Is(err, ansible.ErrInvalidInput):
		jsonapi.WriteError(c, http.StatusBadRequest, jsonapi.TitleBadRequest, err.Error())
	default:
		apierror.Internal(c, failure, err)
	}
	return false
}

type CreateEdgeRequest struct {
	Data struct {
		Type       string `json:"type"`
		Attributes struct {
			Condition string `json:"condition"` // on_success, on_failure, always
		} `json:"attributes"`
		Relationships struct {
			SourceNode struct {
				Data struct {
					ID string `json:"id"`
				} `json:"data"`
			} `json:"source-node"`
			TargetNode struct {
				Data struct {
					ID string `json:"id"`
				} `json:"data"`
			} `json:"target-node"`
		} `json:"relationships"`
	} `json:"data"`
}

// ============================================================================
// Workflow CRUD
// ============================================================================

// List lists workflows for an organization
// GET /api/v2/organizations/:name/ansible/workflows
func (h *WorkflowHandler) List(c *gin.Context) {
	orgName := c.Param("name")
	org, err := h.orgRepo.GetByName(orgName)
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, jsonapi.TitleNotFound, "Organization not found")
		return
	}

	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		jsonapi.WriteError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return
	}

	hasPermission, err := h.rbacService.CheckOrgReadAnsible(c.Request.Context(), user.ID, org.ID)
	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to check permissions")
		return
	}
	if !hasPermission {
		jsonapi.WriteError(c, http.StatusForbidden, "Forbidden", "You do not have permission to list workflows in this organization")
		return
	}

	// This read page[number] into a variable named `offset` and converted in place, which
	// arrived at the right answer but had no upper bound on page[size] - so page[size]=100000
	// pulled the whole table in one request.
	page, limit := jsonapi.PageParams(c, 20, 100)
	offset := jsonapi.Offset(page, limit)

	workflows, total, err := h.workflowRepo.ListByOrganization(org.ID, limit, offset)
	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, jsonapi.TitleInternal, "Failed to list workflows")
		return
	}

	data := make([]*WorkflowResource, len(workflows))
	for i, w := range workflows {
		data[i] = formatWorkflowResponse(&w)
	}

	jsonapi.WriteDocumentMeta(c, http.StatusOK, data, jsonapi.NewPaginationMeta(page, limit, total))
}

// Create creates a new workflow
// POST /api/v2/organizations/:name/ansible/workflows
func (h *WorkflowHandler) Create(c *gin.Context) {
	orgName := c.Param("name")
	org, err := h.orgRepo.GetByName(orgName)
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, jsonapi.TitleNotFound, "Organization not found")
		return
	}

	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		jsonapi.WriteError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return
	}

	hasPermission, err := h.rbacService.CheckOrgManageAnsible(c.Request.Context(), user.ID, org.ID)
	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to check permissions")
		return
	}
	if !hasPermission {
		jsonapi.WriteError(c, http.StatusForbidden, "Forbidden", "You do not have permission to create workflows in this organization")
		return
	}

	var req CreateWorkflowRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, jsonapi.TitleBadRequest, err.Error())
		return
	}

	// The model's `not null` is satisfied by the empty string, so the name is checked here.
	if strings.TrimSpace(req.Data.Attributes.Name) == "" {
		jsonapi.WriteError(c, http.StatusBadRequest, jsonapi.TitleBadRequest, "name is required")
		return
	}
	extraVars, err := extraVarsColumn(req.Data.Attributes.ExtraVars)
	if err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, jsonapi.TitleBadRequest, err.Error())
		return
	}

	workflow := &models.AnsibleWorkflow{
		OrganizationID:       org.ID,
		Name:                 req.Data.Attributes.Name,
		Description:          req.Data.Attributes.Description,
		AllowSimultaneous:    req.Data.Attributes.AllowSimultaneous,
		AskVariablesOnLaunch: req.Data.Attributes.AskVariablesOnLaunch,
		AskInventoryOnLaunch: req.Data.Attributes.AskInventoryOnLaunch,
		AskLimitOnLaunch:     req.Data.Attributes.AskLimitOnLaunch,
		ExtraVars:            extraVars,
		Limit:                req.Data.Attributes.Limit,
		SurveyEnabled:        req.Data.Attributes.SurveyEnabled,
	}

	if req.Data.Relationships.Project.Data != nil {
		projectID, err := uuid.Parse(req.Data.Relationships.Project.Data.ID)
		if err != nil {
			jsonapi.WriteError(c, http.StatusBadRequest, jsonapi.TitleBadRequest, "Invalid project ID")
			return
		}
		workflow.ProjectID = projectID
	} else {
		// No project relationship: fall back to the org's default project
		// (mirrors inventory creation). Without this the insert violates the
		// project foreign key.
		defaultProject, err := h.projectRepo.GetByOrganizationAndName(org.ID, "default")
		if err != nil {
			jsonapi.WriteError(c, http.StatusBadRequest, jsonapi.TitleBadRequest, "A project relationship is required (no default project exists)")
			return
		}
		workflow.ProjectID = defaultProject.ID
	}

	if req.Data.Relationships.Inventory.Data != nil {
		inventoryID, err := uuid.Parse(req.Data.Relationships.Inventory.Data.ID)
		if err != nil {
			jsonapi.WriteError(c, http.StatusBadRequest, jsonapi.TitleBadRequest, "Invalid inventory ID")
			return
		}
		workflow.InventoryID = &inventoryID
	}

	// The permission check above is about the organization in the URL. It says nothing about
	// the project and the inventory the document names, which must be that organization's too:
	// the workflow's own permissions are derived from its project.
	if !referentsAccepted(c, h.engine.CheckWorkflowReferents(c.Request.Context(), workflow), "Failed to create workflow") {
		return
	}

	workflow.CreatedBy = &user.ID

	if err := h.workflowRepo.Create(workflow); err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, jsonapi.TitleInternal, "Failed to create workflow")
		return
	}

	jsonapi.WriteDocument(c, http.StatusCreated, formatWorkflowResponse(workflow))
}

// Get retrieves a workflow by ID
// GET /api/v2/ansible/workflows/:id
func (h *WorkflowHandler) Get(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, jsonapi.TitleBadRequest, "Invalid workflow ID")
		return
	}

	workflow, edges, err := h.workflowRepo.GetByIDWithEdges(id)
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, jsonapi.TitleNotFound, "Workflow not found")
		return
	}

	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		jsonapi.WriteError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return
	}

	hasPermission, err := h.rbacService.CheckAnsibleResourcePermission(
		c.Request.Context(),
		user.ID,
		rbac.ResourceTypeAnsibleJobTemplate,
		workflow.ID.String(),
		rbac.PermissionAnsibleJobTemplateRead,
		&workflow.ProjectID,
	)
	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to check permissions")
		return
	}
	if !hasPermission {
		jsonapi.WriteError(c, http.StatusForbidden, "Forbidden", "You do not have permission to view this workflow")
		return
	}

	response := formatWorkflowResponse(workflow)

	// Add nodes and edges
	nodesData := make([]jsonapi.Resource[WorkflowNodeAttributes], len(workflow.Nodes))
	for i, node := range workflow.Nodes {
		nodesData[i] = formatNodeResponse(&node)
	}
	response.Relationships.Nodes = &WorkflowNodesRelationship{Data: nodesData}

	edgesData := make([]jsonapi.Resource[WorkflowEdgeAttributes], len(edges))
	for i, edge := range edges {
		edgesData[i] = formatEdgeResponse(&edge)
	}
	response.Relationships.Edges = &WorkflowEdgesRelationship{Data: edgesData}

	jsonapi.WriteDocument(c, http.StatusOK, response)
}

// Update updates a workflow
// PATCH /api/v2/ansible/workflows/:id
func (h *WorkflowHandler) Update(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, jsonapi.TitleBadRequest, "Invalid workflow ID")
		return
	}

	workflow, err := h.workflowRepo.GetByID(id)
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, jsonapi.TitleNotFound, "Workflow not found")
		return
	}

	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		jsonapi.WriteError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return
	}

	hasPermission, err := h.rbacService.CheckAnsibleResourcePermission(
		c.Request.Context(),
		user.ID,
		rbac.ResourceTypeAnsibleJobTemplate,
		workflow.ID.String(),
		rbac.PermissionAnsibleJobTemplateWrite,
		&workflow.ProjectID,
	)
	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to check permissions")
		return
	}
	if !hasPermission {
		jsonapi.WriteError(c, http.StatusForbidden, "Forbidden", "You do not have permission to update this workflow")
		return
	}

	var req UpdateWorkflowRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, jsonapi.TitleBadRequest, err.Error())
		return
	}

	// The two attributes that can be refused are checked before anything is assigned, so a
	// refused document leaves the row exactly as it was.
	attrs := req.Data.Attributes
	if attrs.Name != nil && strings.TrimSpace(*attrs.Name) == "" {
		jsonapi.WriteError(c, http.StatusBadRequest, jsonapi.TitleBadRequest, "name must not be empty")
		return
	}
	if attrs.ExtraVars != nil {
		extraVars, err := extraVarsColumn(*attrs.ExtraVars)
		if err != nil {
			jsonapi.WriteError(c, http.StatusBadRequest, jsonapi.TitleBadRequest, err.Error())
			return
		}
		workflow.ExtraVars = extraVars
	}
	if attrs.Name != nil {
		workflow.Name = *attrs.Name
	}
	if attrs.Description != nil {
		workflow.Description = *attrs.Description
	}
	if attrs.AllowSimultaneous != nil {
		workflow.AllowSimultaneous = *attrs.AllowSimultaneous
	}
	if attrs.AskVariablesOnLaunch != nil {
		workflow.AskVariablesOnLaunch = *attrs.AskVariablesOnLaunch
	}
	if attrs.AskInventoryOnLaunch != nil {
		workflow.AskInventoryOnLaunch = *attrs.AskInventoryOnLaunch
	}
	if attrs.AskLimitOnLaunch != nil {
		workflow.AskLimitOnLaunch = *attrs.AskLimitOnLaunch
	}
	if attrs.Limit != nil {
		workflow.Limit = *attrs.Limit
	}
	if attrs.SurveyEnabled != nil {
		workflow.SurveyEnabled = *attrs.SurveyEnabled
	}

	if err := h.workflowRepo.Update(workflow); err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, jsonapi.TitleInternal, "Failed to update workflow")
		return
	}

	jsonapi.WriteDocument(c, http.StatusOK, formatWorkflowResponse(workflow))
}

// Delete deletes a workflow
// DELETE /api/v2/ansible/workflows/:id
func (h *WorkflowHandler) Delete(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, jsonapi.TitleBadRequest, "Invalid workflow ID")
		return
	}

	workflow, err := h.workflowRepo.GetByID(id)
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, jsonapi.TitleNotFound, "Workflow not found")
		return
	}

	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		jsonapi.WriteError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return
	}

	hasPermission, err := h.rbacService.CheckAnsibleResourcePermission(
		c.Request.Context(),
		user.ID,
		rbac.ResourceTypeAnsibleJobTemplate,
		workflow.ID.String(),
		rbac.PermissionAnsibleJobTemplateWrite,
		&workflow.ProjectID,
	)
	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to check permissions")
		return
	}
	if !hasPermission {
		jsonapi.WriteError(c, http.StatusForbidden, "Forbidden", "You do not have permission to delete this workflow")
		return
	}

	if err := h.workflowRepo.Delete(id); err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, jsonapi.TitleInternal, "Failed to delete workflow")
		return
	}

	c.Status(http.StatusNoContent)
}

// ============================================================================
// Node operations
// ============================================================================

// CreateNode creates a new node in a workflow
// POST /api/v2/ansible/workflows/:id/nodes
func (h *WorkflowHandler) CreateNode(c *gin.Context) {
	workflowIDStr := c.Param("id")
	workflowID, err := uuid.Parse(workflowIDStr)
	if err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, jsonapi.TitleBadRequest, "Invalid workflow ID")
		return
	}

	workflow, err := h.workflowRepo.GetByID(workflowID)
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, jsonapi.TitleNotFound, "Workflow not found")
		return
	}

	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		jsonapi.WriteError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return
	}

	hasPermission, err := h.rbacService.CheckAnsibleResourcePermission(
		c.Request.Context(),
		user.ID,
		rbac.ResourceTypeAnsibleJobTemplate,
		workflow.ID.String(),
		rbac.PermissionAnsibleJobTemplateWrite,
		&workflow.ProjectID,
	)
	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to check permissions")
		return
	}
	if !hasPermission {
		jsonapi.WriteError(c, http.StatusForbidden, "Forbidden", "You do not have permission to modify this workflow")
		return
	}

	var req CreateNodeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, jsonapi.TitleBadRequest, err.Error())
		return
	}

	extraVars, err := extraVarsColumn(req.Data.Attributes.ExtraVars)
	if err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, jsonapi.TitleBadRequest, err.Error())
		return
	}
	// A node of a type the engine does not know is never started and never finished, so the
	// run it is part of never ends.
	nodeType := models.WorkflowNodeType(req.Data.Attributes.NodeType)
	if !nodeType.IsValid() {
		jsonapi.WriteError(c, http.StatusBadRequest, jsonapi.TitleBadRequest, fmt.Sprintf(
			"node-type must be one of %s, %s, %s, %s",
			models.WorkflowNodeTypeJobTemplate, models.WorkflowNodeTypeWorkflow,
			models.WorkflowNodeTypeInventorySync, models.WorkflowNodeTypeApproval,
		))
		return
	}

	node := &models.AnsibleWorkflowNode{
		WorkflowID:             workflowID,
		NodeType:               nodeType,
		Identifier:             req.Data.Attributes.Identifier,
		PositionX:              req.Data.Attributes.PositionX,
		PositionY:              req.Data.Attributes.PositionY,
		ExtraVars:              extraVars,
		Limit:                  req.Data.Attributes.Limit,
		Tags:                   req.Data.Attributes.Tags,
		SkipTags:               req.Data.Attributes.SkipTags,
		Verbosity:              req.Data.Attributes.Verbosity,
		AllParentsMustConverge: req.Data.Attributes.AllParentsMustConverge,
		ApprovalTimeout:        req.Data.Attributes.ApprovalTimeout,
		ApprovalMessage:        req.Data.Attributes.ApprovalMessage,
	}

	// A relationship identifier that does not parse is the caller's mistake. Left unchecked it
	// became the zero UUID and failed at the foreign key, which the caller read as a 500.
	if req.Data.Relationships.JobTemplate.Data != nil {
		templateID, err := uuid.Parse(req.Data.Relationships.JobTemplate.Data.ID)
		if err != nil {
			jsonapi.WriteError(c, http.StatusBadRequest, jsonapi.TitleBadRequest, "Invalid job template ID")
			return
		}
		node.JobTemplateID = &templateID
	}

	if req.Data.Relationships.Inventory.Data != nil {
		inventoryID, err := uuid.Parse(req.Data.Relationships.Inventory.Data.ID)
		if err != nil {
			jsonapi.WriteError(c, http.StatusBadRequest, jsonapi.TitleBadRequest, "Invalid inventory ID")
			return
		}
		node.InventoryID = &inventoryID
	}

	if req.Data.Relationships.Credential.Data != nil {
		credentialID, err := uuid.Parse(req.Data.Relationships.Credential.Data.ID)
		if err != nil {
			jsonapi.WriteError(c, http.StatusBadRequest, jsonapi.TitleBadRequest, "Invalid credential ID")
			return
		}
		node.CredentialID = &credentialID
	}

	// The permission check above is about the workflow. What the node names must belong to the
	// workflow's organization as well, or a launch would run another organization's job
	// template on that organization's hosts.
	if !referentsAccepted(c, h.engine.CheckNodeReferents(c.Request.Context(), workflow.OrganizationID, node), "Failed to create node") {
		return
	}

	if err := h.workflowRepo.CreateNode(node); err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, jsonapi.TitleInternal, "Failed to create node")
		return
	}

	jsonapi.WriteDocument(c, http.StatusCreated, formatNodeResponse(node))
}

// ListNodes lists nodes in a workflow
// GET /api/v2/ansible/workflows/:id/nodes
func (h *WorkflowHandler) ListNodes(c *gin.Context) {
	workflowIDStr := c.Param("id")
	workflowID, err := uuid.Parse(workflowIDStr)
	if err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, jsonapi.TitleBadRequest, "Invalid workflow ID")
		return
	}

	workflow, err := h.workflowRepo.GetByID(workflowID)
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, jsonapi.TitleNotFound, "Workflow not found")
		return
	}

	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		jsonapi.WriteError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return
	}

	hasPermission, err := h.rbacService.CheckAnsibleResourcePermission(
		c.Request.Context(),
		user.ID,
		rbac.ResourceTypeAnsibleJobTemplate,
		workflow.ID.String(),
		rbac.PermissionAnsibleJobTemplateRead,
		&workflow.ProjectID,
	)
	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to check permissions")
		return
	}
	if !hasPermission {
		jsonapi.WriteError(c, http.StatusForbidden, "Forbidden", "You do not have permission to view this workflow")
		return
	}

	nodes, err := h.workflowRepo.ListNodesByWorkflow(workflowID)
	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, jsonapi.TitleInternal, "Failed to list nodes")
		return
	}

	data := make([]jsonapi.Resource[WorkflowNodeAttributes], len(nodes))
	for i, node := range nodes {
		data[i] = formatNodeResponse(&node)
	}

	jsonapi.WriteDocumentMeta(c, http.StatusOK, data, jsonapi.NewFullPageMeta(len(data)))
}

// UpdateNode updates a node
// PATCH /api/v2/ansible/workflow-nodes/:id
func (h *WorkflowHandler) UpdateNode(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, jsonapi.TitleBadRequest, "Invalid node ID")
		return
	}

	node, err := h.workflowRepo.GetNodeByID(id)
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, jsonapi.TitleNotFound, "Node not found")
		return
	}

	workflow, err := h.workflowRepo.GetByID(node.WorkflowID)
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, jsonapi.TitleNotFound, "Workflow not found")
		return
	}

	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		jsonapi.WriteError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return
	}

	hasPermission, err := h.rbacService.CheckAnsibleResourcePermission(
		c.Request.Context(),
		user.ID,
		rbac.ResourceTypeAnsibleJobTemplate,
		workflow.ID.String(),
		rbac.PermissionAnsibleJobTemplateWrite,
		&workflow.ProjectID,
	)
	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to check permissions")
		return
	}
	if !hasPermission {
		jsonapi.WriteError(c, http.StatusForbidden, "Forbidden", "You do not have permission to modify this workflow")
		return
	}

	var req UpdateNodeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, jsonapi.TitleBadRequest, err.Error())
		return
	}

	// The one attribute that can be refused is checked before anything is assigned, so a refused
	// document leaves the row exactly as it was.
	attrs := req.Data.Attributes
	if attrs.ExtraVars != nil {
		extraVars, err := extraVarsColumn(*attrs.ExtraVars)
		if err != nil {
			jsonapi.WriteError(c, http.StatusBadRequest, jsonapi.TitleBadRequest, err.Error())
			return
		}
		node.ExtraVars = extraVars
	}
	if attrs.PositionX != nil {
		node.PositionX = *attrs.PositionX
	}
	if attrs.PositionY != nil {
		node.PositionY = *attrs.PositionY
	}
	if attrs.Limit != nil {
		node.Limit = *attrs.Limit
	}
	if attrs.Tags != nil {
		node.Tags = *attrs.Tags
	}
	if attrs.SkipTags != nil {
		node.SkipTags = *attrs.SkipTags
	}
	if attrs.Verbosity != nil {
		node.Verbosity = *attrs.Verbosity
	}
	if attrs.AllParentsMustConverge != nil {
		node.AllParentsMustConverge = *attrs.AllParentsMustConverge
	}

	if err := h.workflowRepo.UpdateNode(node); err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, jsonapi.TitleInternal, "Failed to update node")
		return
	}

	jsonapi.WriteDocument(c, http.StatusOK, formatNodeResponse(node))
}

// DeleteNode deletes a node
// DELETE /api/v2/ansible/workflow-nodes/:id
func (h *WorkflowHandler) DeleteNode(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, jsonapi.TitleBadRequest, "Invalid node ID")
		return
	}

	node, err := h.workflowRepo.GetNodeByID(id)
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, jsonapi.TitleNotFound, "Node not found")
		return
	}

	workflow, err := h.workflowRepo.GetByID(node.WorkflowID)
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, jsonapi.TitleNotFound, "Workflow not found")
		return
	}

	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		jsonapi.WriteError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return
	}

	hasPermission, err := h.rbacService.CheckAnsibleResourcePermission(
		c.Request.Context(),
		user.ID,
		rbac.ResourceTypeAnsibleJobTemplate,
		workflow.ID.String(),
		rbac.PermissionAnsibleJobTemplateWrite,
		&workflow.ProjectID,
	)
	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to check permissions")
		return
	}
	if !hasPermission {
		jsonapi.WriteError(c, http.StatusForbidden, "Forbidden", "You do not have permission to modify this workflow")
		return
	}

	if err := h.workflowRepo.DeleteNode(id); err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, jsonapi.TitleInternal, "Failed to delete node")
		return
	}

	c.Status(http.StatusNoContent)
}

// ============================================================================
// Edge operations
// ============================================================================

// CreateEdge creates a new edge between nodes
// POST /api/v2/ansible/workflows/:id/edges
func (h *WorkflowHandler) CreateEdge(c *gin.Context) {
	workflowIDStr := c.Param("id")
	workflowID, err := uuid.Parse(workflowIDStr)
	if err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, jsonapi.TitleBadRequest, "Invalid workflow ID")
		return
	}

	workflow, err := h.workflowRepo.GetByID(workflowID)
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, jsonapi.TitleNotFound, "Workflow not found")
		return
	}

	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		jsonapi.WriteError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return
	}

	hasPermission, err := h.rbacService.CheckAnsibleResourcePermission(
		c.Request.Context(),
		user.ID,
		rbac.ResourceTypeAnsibleJobTemplate,
		workflow.ID.String(),
		rbac.PermissionAnsibleJobTemplateWrite,
		&workflow.ProjectID,
	)
	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to check permissions")
		return
	}
	if !hasPermission {
		jsonapi.WriteError(c, http.StatusForbidden, "Forbidden", "You do not have permission to modify this workflow")
		return
	}

	var req CreateEdgeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, jsonapi.TitleBadRequest, err.Error())
		return
	}

	// Both ends are required. An identifier that is absent or does not parse is the caller's
	// mistake; left unchecked it became the zero UUID and failed at the foreign key.
	sourceNodeID, err := uuid.Parse(req.Data.Relationships.SourceNode.Data.ID)
	if err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, jsonapi.TitleBadRequest, "Invalid source node ID")
		return
	}
	targetNodeID, err := uuid.Parse(req.Data.Relationships.TargetNode.Data.ID)
	if err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, jsonapi.TitleBadRequest, "Invalid target node ID")
		return
	}
	// The engine follows an edge only when its condition is one it knows.
	condition := models.WorkflowEdgeCondition(req.Data.Attributes.Condition)
	if !condition.IsValid() {
		jsonapi.WriteError(c, http.StatusBadRequest, jsonapi.TitleBadRequest, fmt.Sprintf(
			"condition must be one of %s, %s, %s",
			models.WorkflowEdgeOnSuccess, models.WorkflowEdgeOnFailure, models.WorkflowEdgeAlways,
		))
		return
	}

	edge := &models.AnsibleWorkflowEdge{
		WorkflowID:   workflowID,
		SourceNodeID: sourceNodeID,
		TargetNodeID: targetNodeID,
		Condition:    condition,
	}

	// An edge joins two nodes of the workflow in the URL. The foreign keys only ask that the two
	// rows exist, so an edge could be hung on a node of any other workflow.
	if !referentsAccepted(c, h.engine.CheckEdgeNodes(c.Request.Context(), edge), "Failed to create edge") {
		return
	}

	if err := h.workflowRepo.CreateEdge(edge); err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, jsonapi.TitleInternal, "Failed to create edge")
		return
	}

	jsonapi.WriteDocument(c, http.StatusCreated, formatEdgeResponse(edge))
}

// ListEdges lists edges in a workflow
// GET /api/v2/ansible/workflows/:id/edges
func (h *WorkflowHandler) ListEdges(c *gin.Context) {
	workflowIDStr := c.Param("id")
	workflowID, err := uuid.Parse(workflowIDStr)
	if err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, jsonapi.TitleBadRequest, "Invalid workflow ID")
		return
	}

	workflow, err := h.workflowRepo.GetByID(workflowID)
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, jsonapi.TitleNotFound, "Workflow not found")
		return
	}

	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		jsonapi.WriteError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return
	}

	hasPermission, err := h.rbacService.CheckAnsibleResourcePermission(
		c.Request.Context(),
		user.ID,
		rbac.ResourceTypeAnsibleJobTemplate,
		workflow.ID.String(),
		rbac.PermissionAnsibleJobTemplateRead,
		&workflow.ProjectID,
	)
	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to check permissions")
		return
	}
	if !hasPermission {
		jsonapi.WriteError(c, http.StatusForbidden, "Forbidden", "You do not have permission to view this workflow")
		return
	}

	edges, err := h.workflowRepo.ListEdgesByWorkflow(workflowID)
	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, jsonapi.TitleInternal, "Failed to list edges")
		return
	}

	data := make([]jsonapi.Resource[WorkflowEdgeAttributes], len(edges))
	for i, edge := range edges {
		data[i] = formatEdgeResponse(&edge)
	}

	jsonapi.WriteDocumentMeta(c, http.StatusOK, data, jsonapi.NewFullPageMeta(len(data)))
}

// DeleteEdge deletes an edge
// DELETE /api/v2/ansible/workflow-edges/:id
func (h *WorkflowHandler) DeleteEdge(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, jsonapi.TitleBadRequest, "Invalid edge ID")
		return
	}

	edge, err := h.workflowRepo.GetEdgeByID(id)
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, jsonapi.TitleNotFound, "Edge not found")
		return
	}

	workflow, err := h.workflowRepo.GetByID(edge.WorkflowID)
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, jsonapi.TitleNotFound, "Workflow not found")
		return
	}

	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		jsonapi.WriteError(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return
	}

	hasPermission, err := h.rbacService.CheckAnsibleResourcePermission(
		c.Request.Context(),
		user.ID,
		rbac.ResourceTypeAnsibleJobTemplate,
		workflow.ID.String(),
		rbac.PermissionAnsibleJobTemplateWrite,
		&workflow.ProjectID,
	)
	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to check permissions")
		return
	}
	if !hasPermission {
		jsonapi.WriteError(c, http.StatusForbidden, "Forbidden", "You do not have permission to modify this workflow")
		return
	}

	if err := h.workflowRepo.DeleteEdge(id); err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, jsonapi.TitleInternal, "Failed to delete edge")
		return
	}

	c.Status(http.StatusNoContent)
}

// ============================================================================
// Response formatters
// ============================================================================

func formatWorkflowResponse(w *models.AnsibleWorkflow) *WorkflowResource {
	rels := &WorkflowRelationships{
		Organization: jsonapi.ToOne(w.OrganizationID.String(), "organizations"),
	}
	if w.ProjectID != uuid.Nil {
		r := jsonapi.ToOne(w.ProjectID.String(), "projects")
		rels.Project = &r
	}
	if w.InventoryID != nil {
		r := jsonapi.ToOne(w.InventoryID.String(), "ansible-inventories")
		rels.Inventory = &r
	}
	return &WorkflowResource{
		ID:   w.ID.String(),
		Type: "ansible-workflows",
		Attributes: WorkflowAttributes{
			Name:                 w.Name,
			Description:          w.Description,
			AllowSimultaneous:    w.AllowSimultaneous,
			AskVariablesOnLaunch: w.AskVariablesOnLaunch,
			AskInventoryOnLaunch: w.AskInventoryOnLaunch,
			AskLimitOnLaunch:     w.AskLimitOnLaunch,
			ExtraVars:            string(w.ExtraVars),
			Limit:                w.Limit,
			SurveyEnabled:        w.SurveyEnabled,
			CreatedAt:            w.CreatedAt,
			UpdatedAt:            w.UpdatedAt,
		},
		Relationships: rels,
	}
}

func formatNodeResponse(n *models.AnsibleWorkflowNode) jsonapi.Resource[WorkflowNodeAttributes] {
	attrs := WorkflowNodeAttributes{
		NodeType:               string(n.NodeType),
		Identifier:             n.Identifier,
		PositionX:              n.PositionX,
		PositionY:              n.PositionY,
		ExtraVars:              string(n.ExtraVars),
		Limit:                  n.Limit,
		Tags:                   n.Tags,
		SkipTags:               n.SkipTags,
		Verbosity:              n.Verbosity,
		AllParentsMustConverge: n.AllParentsMustConverge,
		ApprovalTimeout:        n.ApprovalTimeout,
		ApprovalMessage:        n.ApprovalMessage,
		CreatedAt:              n.CreatedAt,
	}
	rels := WorkflowNodeRelationships{
		Workflow: jsonapi.ToOne(n.WorkflowID.String(), "ansible-workflows"),
	}
	if n.JobTemplateID != nil {
		r := jsonapi.ToOne(n.JobTemplateID.String(), "ansible-job-templates")
		rels.JobTemplate = &r
		if n.JobTemplate != nil {
			attrs.JobTemplateName = n.JobTemplate.Name
		}
	}
	if n.InventoryID != nil {
		r := jsonapi.ToOne(n.InventoryID.String(), "ansible-inventories")
		rels.Inventory = &r
	}
	if n.CredentialID != nil {
		r := jsonapi.ToOne(n.CredentialID.String(), "ansible-credentials")
		rels.Credential = &r
	}
	return jsonapi.Resource[WorkflowNodeAttributes]{
		ID:            n.ID.String(),
		Type:          "ansible-workflow-nodes",
		Attributes:    attrs,
		Relationships: rels,
	}
}

func formatEdgeResponse(e *models.AnsibleWorkflowEdge) jsonapi.Resource[WorkflowEdgeAttributes] {
	return jsonapi.Resource[WorkflowEdgeAttributes]{
		ID:   e.ID.String(),
		Type: "ansible-workflow-edges",
		Attributes: WorkflowEdgeAttributes{
			Condition: string(e.Condition),
			CreatedAt: e.CreatedAt,
		},
		Relationships: WorkflowEdgeRelationships{
			Workflow:   jsonapi.ToOne(e.WorkflowID.String(), "ansible-workflows"),
			SourceNode: jsonapi.ToOne(e.SourceNodeID.String(), "ansible-workflow-nodes"),
			TargetNode: jsonapi.ToOne(e.TargetNodeID.String(), "ansible-workflow-nodes"),
		},
	}
}
