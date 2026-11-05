// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
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

// IdentityBindingAttributes is an identity binding on the wire (#933, D8, D15): the mechanism and
// the ServiceAccount a customer pool's job pods run as. declared-externally, external-manager,
// object-present and reported-at are what the pool's launcher last reported, read-only.
type IdentityBindingAttributes struct {
	Name               string            `json:"name"`
	Mechanism          string            `json:"mechanism"`
	ServiceAccount     string            `json:"service-account"`
	Annotations        map[string]string `json:"annotations"`
	PerJobSA           bool              `json:"per-job-sa"`
	Reference          bool              `json:"reference"`
	DeclaredExternally bool              `json:"declared-externally"`
	ExternalManager    string            `json:"external-manager"`
	ObjectPresent      *bool             `json:"object-present"`
	ReportedAt         *time.Time        `json:"reported-at"`
	CreatedAt          time.Time         `json:"created-at"`
}

// IdentityBindingRelationships names the binding's pool.
type IdentityBindingRelationships struct {
	AgentPool jsonapi.Relationship `json:"agent-pool"`
}

type identityBindingRequest struct {
	Data struct {
		Type       string `json:"type"`
		Attributes struct {
			Name           *string            `json:"name"`
			Mechanism      *string            `json:"mechanism"`
			ServiceAccount *string            `json:"service-account"`
			Annotations    *map[string]string `json:"annotations"`
			PerJobSA       *bool              `json:"per-job-sa"`
			Reference      *bool              `json:"reference"`
		} `json:"attributes"`
	} `json:"data"`
}

// IdentityBindingHandler serves the identity bindings of customer pools.
type IdentityBindingHandler struct {
	poolRepo    *repository.AgentPoolRepository
	bindings    *repository.IdentityBindingRepository
	authService *auth.Service
	rbacService *rbac.Service
}

// NewIdentityBindingHandler builds the handler.
func NewIdentityBindingHandler(poolRepo *repository.AgentPoolRepository, bindings *repository.IdentityBindingRepository, authService *auth.Service, rbacService *rbac.Service) *IdentityBindingHandler {
	return &IdentityBindingHandler{poolRepo: poolRepo, bindings: bindings, authService: authService, rbacService: rbacService}
}

func identityBindingResource(b *models.IdentityBinding) jsonapi.Resource[IdentityBindingAttributes] {
	ann := map[string]string{}
	for k, v := range b.Annotations {
		if s, ok := v.(string); ok {
			ann[k] = s
		}
	}
	return jsonapi.Resource[IdentityBindingAttributes]{
		ID:   b.ID.String(),
		Type: "identity-bindings",
		Attributes: IdentityBindingAttributes{
			Name: b.Name, Mechanism: b.Mechanism, ServiceAccount: b.ServiceAccount, Annotations: ann,
			PerJobSA: b.PerJobSA, Reference: b.Reference, DeclaredExternally: b.DeclaredExternally,
			ExternalManager: b.ExternalManager, ObjectPresent: b.ObjectPresent, ReportedAt: b.ReportedAt, CreatedAt: b.CreatedAt,
		},
		Relationships: IdentityBindingRelationships{AgentPool: jsonapi.ToOne(b.AgentPoolID.String(), "agent-pools")},
	}
}

// access checks the caller's right on the organization: manage for writes, membership for reads.
func (h *IdentityBindingHandler) access(c *gin.Context, orgID uuid.UUID, write bool) bool {
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
		jsonapi.WriteError(c, http.StatusForbidden, "Forbidden", "You do not have permission to manage this pool's identity bindings")
		return false
	}
	return true
}

func (h *IdentityBindingHandler) pool(c *gin.Context) (*models.AgentPool, bool) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "Agent pool not found")
		return nil, false
	}
	// Hosted pools offer no binding: their jobs use the platform identity (D8, D9).
	pool, err := h.poolRepo.GetCustomerByID(id, false)
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "Agent pool not found")
		return nil, false
	}
	return pool, true
}

func (h *IdentityBindingHandler) binding(c *gin.Context) (*models.IdentityBinding, bool) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "Identity binding not found")
		return nil, false
	}
	b, err := h.bindings.GetByID(id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "Identity binding not found")
		} else {
			jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		}
		return nil, false
	}
	return b, true
}

// serviceAccountName is a DNS-1123 subdomain, the form a ServiceAccount name takes.
var serviceAccountName = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`)

// bindingName is a binding's own name: letters, digits, '.', '_' and '-', starting with a letter or
// digit, like the other names of the platform.
var bindingName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// annotationKeyName is the name part of a Kubernetes annotation key: at most 63 characters,
// alphanumeric at both ends, with '-', '_' and '.' between.
var annotationKeyName = regexp.MustCompile(`^[A-Za-z0-9]([-A-Za-z0-9_.]*[A-Za-z0-9])?$`)

// Annotation values the launcher puts on a created ServiceAccount, each checked for its form:
// IRSA's IAM role ARN in any partition, and Entra Workload ID's application client id.
var (
	iamRoleARN = regexp.MustCompile(`^arn:aws[a-z-]*:iam::[0-9]+:role/\S+$`)
	clientUUID = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
)

// requiredAnnotations is the ServiceAccount annotation each mechanism cannot work without (#933,
// D5): the role IRSA assumes and the application Entra Workload ID federates with. EKS Pod
// Identity binds the role outside the ServiceAccount, and GKE Workload Identity Federation can
// grant the Kubernetes ServiceAccount directly, so neither requires one.
var requiredAnnotations = map[string]struct {
	key, form string
	valid     *regexp.Regexp
}{
	models.IdentityMechanismAWSIRSA:               {"eks.amazonaws.com/role-arn", "an IAM role ARN (arn:aws:iam::<account>:role/<name>)", iamRoleARN},
	models.IdentityMechanismAzureWorkloadIdentity: {"azure.workload.identity/client-id", "the application's client id (a UUID)", clientUUID},
}

// validAnnotationKey reports whether k is a Kubernetes annotation key: an optional DNS subdomain
// prefix and '/', then a name.
func validAnnotationKey(k string) bool {
	name := k
	if prefix, rest, hasPrefix := strings.Cut(k, "/"); hasPrefix {
		if prefix == "" || len(prefix) > 253 || !serviceAccountName.MatchString(prefix) {
			return false
		}
		name = rest
	}
	return len(name) <= 63 && annotationKeyName.MatchString(name)
}

func validateBinding(b *models.IdentityBinding) string {
	switch {
	case b.Name == "" || len(b.Name) > 100 || !bindingName.MatchString(b.Name):
		return "name must be 1 to 100 letters, digits, '.', '_' or '-', starting with a letter or digit"
	case !slices.Contains(models.IdentityMechanisms, b.Mechanism):
		return "mechanism must be one of " + strings.Join(models.IdentityMechanisms, ", ")
	case len(b.ServiceAccount) > 253 || !serviceAccountName.MatchString(b.ServiceAccount):
		return "service-account must be a Kubernetes ServiceAccount name (lowercase letters, digits, '-' and '.')"
	}
	keys := make([]string, 0, len(b.Annotations))
	for k := range b.Annotations {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		if !validAnnotationKey(k) {
			return fmt.Sprintf("annotation key %q is not a Kubernetes annotation key (an optional DNS prefix and '/', then up to 63 letters, digits, '-', '_' or '.')", k)
		}
	}
	// The launcher writes the annotations on an account it creates, a per-job clone included; a
	// referenced account carries its own where it is declared.
	if req, ok := requiredAnnotations[b.Mechanism]; ok && (!b.Reference || b.PerJobSA) {
		v, _ := b.Annotations[req.key].(string)
		if !req.valid.MatchString(strings.TrimSpace(v)) {
			return fmt.Sprintf("a %s binding whose ServiceAccount Stackweaver creates needs the annotation %s, set to %s", b.Mechanism, req.key, req.form)
		}
	}
	return ""
}

// clash refuses a create-mode binding whose ServiceAccount another manager holds, from the pool
// launcher's last report (Order 1 of D8, AC49a). It writes the 409 and returns true on a clash.
func (h *IdentityBindingHandler) clash(c *gin.Context, b *models.IdentityBinding) bool {
	if b.Reference {
		return false
	}
	obj, err := h.bindings.ExternalObject(b.AgentPoolID, "ServiceAccount", b.ServiceAccount)
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

// Create adds an identity binding to a customer pool.
//
// POST /api/v2/agent-pools/:id/identity-bindings
func (h *IdentityBindingHandler) Create(c *gin.Context) {
	pool, ok := h.pool(c)
	if !ok || !h.access(c, pool.OrganizationID, true) {
		return
	}
	var req identityBindingRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", err.Error())
		return
	}
	a := req.Data.Attributes
	b := &models.IdentityBinding{ID: uuid.New(), OrganizationID: pool.OrganizationID, AgentPoolID: pool.ID, Annotations: models.JSONB{}}
	applyBindingAttributes(b, a.Name, a.Mechanism, a.ServiceAccount, a.Annotations, a.PerJobSA, a.Reference)
	if detail := validateBinding(b); detail != "" {
		jsonapi.WriteError(c, http.StatusUnprocessableEntity, "Unprocessable Entity", detail)
		return
	}
	if h.clash(c, b) {
		return
	}
	if err := h.bindings.Create(b); err != nil {
		if strings.Contains(err.Error(), "duplicate") || strings.Contains(err.Error(), "unique") {
			jsonapi.WriteError(c, http.StatusConflict, "Conflict", "the pool already has an identity binding of that name")
			return
		}
		jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	jsonapi.WriteDocument(c, http.StatusCreated, identityBindingResource(b))
}

func applyBindingAttributes(b *models.IdentityBinding, name, mechanism, sa *string, ann *map[string]string, perJob, reference *bool) {
	if name != nil {
		b.Name = strings.TrimSpace(*name)
	}
	if mechanism != nil {
		b.Mechanism = *mechanism
	}
	if sa != nil {
		b.ServiceAccount = strings.TrimSpace(*sa)
	}
	if ann != nil {
		b.Annotations = models.JSONB{}
		for k, v := range *ann {
			b.Annotations[k] = v
		}
	}
	if perJob != nil {
		b.PerJobSA = *perJob
	}
	if reference != nil {
		b.Reference = *reference
	}
}

// List returns a pool's identity bindings, readable by the organization's members.
//
// GET /api/v2/agent-pools/:id/identity-bindings
func (h *IdentityBindingHandler) List(c *gin.Context) {
	pool, ok := h.pool(c)
	if !ok || !h.access(c, pool.OrganizationID, false) {
		return
	}
	list, err := h.bindings.ListByPool(pool.ID)
	if err != nil {
		jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	data := make([]jsonapi.Resource[IdentityBindingAttributes], 0, len(list))
	for i := range list {
		data = append(data, identityBindingResource(&list[i]))
	}
	jsonapi.WriteDocumentMeta(c, http.StatusOK, data, jsonapi.NewPaginationMeta(1, len(list), int64(len(list))))
}

// Get reads one identity binding.
//
// GET /api/v2/identity-bindings/:id
func (h *IdentityBindingHandler) Get(c *gin.Context) {
	b, ok := h.binding(c)
	if !ok || !h.access(c, b.OrganizationID, false) {
		return
	}
	jsonapi.WriteDocument(c, http.StatusOK, identityBindingResource(b))
}

// Update changes a binding. Once its pool's launcher reported its ServiceAccount as managed outside
// Stackweaver, its Kubernetes fields are read-only (AC49b); its name stays Stackweaver's.
//
// PATCH /api/v2/identity-bindings/:id
func (h *IdentityBindingHandler) Update(c *gin.Context) {
	b, ok := h.binding(c)
	if !ok || !h.access(c, b.OrganizationID, true) {
		return
	}
	var req identityBindingRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", err.Error())
		return
	}
	a := req.Data.Attributes
	if b.DeclaredExternally && (a.Mechanism != nil || a.ServiceAccount != nil || a.Annotations != nil || a.PerJobSA != nil || a.Reference != nil) {
		jsonapi.WriteError(c, http.StatusConflict, "Conflict", fmt.Sprintf("the binding's ServiceAccount is declared outside Stackweaver (%s); change it where it is declared", b.ExternalManager))
		return
	}
	saBefore, refBefore := b.ServiceAccount, b.Reference
	applyBindingAttributes(b, a.Name, a.Mechanism, a.ServiceAccount, a.Annotations, a.PerJobSA, a.Reference)
	if detail := validateBinding(b); detail != "" {
		jsonapi.WriteError(c, http.StatusUnprocessableEntity, "Unprocessable Entity", detail)
		return
	}
	if (b.ServiceAccount != saBefore || b.Reference != refBefore) && h.clash(c, b) {
		return
	}
	if err := h.bindings.Update(b); err != nil {
		jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	jsonapi.WriteDocument(c, http.StatusOK, identityBindingResource(b))
}

// Delete removes a binding, and clears it from every level that selected it. A binding declared
// outside Stackweaver is refused (AC49b): its object belongs to its manager.
//
// DELETE /api/v2/identity-bindings/:id
func (h *IdentityBindingHandler) Delete(c *gin.Context) {
	b, ok := h.binding(c)
	if !ok || !h.access(c, b.OrganizationID, true) {
		return
	}
	if b.DeclaredExternally && !b.Reference {
		jsonapi.WriteError(c, http.StatusConflict, "Conflict", fmt.Sprintf("the binding's ServiceAccount is declared outside Stackweaver (%s); remove it there, or reference it instead", b.ExternalManager))
		return
	}
	if err := h.bindings.Delete(b.ID); err != nil {
		jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	c.Status(http.StatusNoContent)
}
