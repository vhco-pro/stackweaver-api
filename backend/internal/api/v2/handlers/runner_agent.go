// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/logger"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/jsonapi"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/response"
	"github.com/michielvha/stackweaver/backend/internal/services/apikey"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/backend/internal/services/registry"
	"github.com/michielvha/stackweaver/core/crypto"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/runnercontract"
	"github.com/michielvha/stackweaver/core/services/ansible"
	"github.com/michielvha/stackweaver/core/services/logbuffer"
	"github.com/michielvha/stackweaver/core/services/oidc"
	"github.com/michielvha/stackweaver/core/services/state"
	"github.com/michielvha/stackweaver/core/services/variable"
	"github.com/michielvha/stackweaver/core/services/vcs"
	"github.com/michielvha/stackweaver/core/services/wakeup"
	"github.com/michielvha/stackweaver/core/settings"
	"github.com/michielvha/stackweaver/core/storage"
	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// RunnerAgentHandler handles runner agent API endpoints
// These endpoints are used by the runner agents to register, heartbeat, and report job status.
type RunnerAgentHandler struct {
	// snapshotAuthorized and beforeWorkItemFinish are test seams, nil in production: each is called
	// with the work item's id between a request's authorization check and its effect, so a test can
	// cancel the capture in that window (#938).
	snapshotAuthorized   func(workItemID string)
	beforeWorkItemFinish func(workItemID string)

	runnerRepo        *repository.RunnerRepository
	jobExecRepo       *repository.RunnerJobExecutionRepository
	poolRepo          *repository.AgentPoolRepository
	apiKeyService     *apikey.Service
	rbacService       *rbac.Service
	ansibleJobRepo    *repository.AnsibleJobRepository
	playbookRepo      *repository.AnsiblePlaybookRepository
	inventoryRepo     *repository.AnsibleInventoryRepository
	credentialRepo    *repository.AnsibleCredentialRepository
	ansibleConfigRepo *repository.AnsibleConfigRepository
	inventoryService  *ansible.InventoryService
	vcsRegistry       *vcs.ProviderRegistry
	cryptoService     *crypto.CryptoService
	// Terraform run support
	variableService *variable.Service
	storageClient   storage.Client
	// OIDC workload identity support for self-hosted runners
	azureOIDCRepo    *repository.AzureOIDCConfigurationRepository
	awsOIDCRepo      *repository.AWSOIDCConfigurationRepository
	gcpOIDCRepo      *repository.GCPOIDCConfigurationRepository
	vaultOIDCRepo    *repository.VaultOIDCConfigurationRepository
	oidcTokenService *oidc.TokenService
	db               *gorm.DB
	// State materialization (outputs/resources) - optional, injected after creation
	stateMaterializer *state.Materializer
	// State object access (encryption at rest) - optional, injected after creation.
	// Routes self-hosted-runner state reads/writes through the encrypt/decrypt chokepoint.
	stateService *state.Service
	// Redis log buffer - optional, injected after creation. When set, agent job output streams
	// through Redis (O(1) APPEND) instead of the O(n²) read-modify-write on object storage
	// (AUD-028), and is copied to MinIO once at completion.
	logBuffer *logbuffer.RedisLogBuffer
	// inlineArtifactLimit overrides DefaultInlineArtifactLimit; zero keeps the default.
	inlineArtifactLimit int
	// registryHost is the host OpenTofu addresses the platform's private module registry by; when
	// set, a job's artifacts carry a registry token for it (SetRegistryHost).
	registryHost string
	// mirror is the deployment's mirror, proxy and CA block served to every job (SetMirror).
	mirror *runnercontract.Mirror
	// allowedRegistries is images.allowed_registries, checked again at job start (SetAllowedRegistries).
	allowedRegistries []string
	// logLimits caps one job's stored output; the zero value reads the deployment's cap.
	logLimits logbuffer.Limits
	// outputBodyCap bounds one output request; zero means DefaultOutputBodyCap.
	outputBodyCap int64
	// wakeHub holds this replica's long-poll heartbeats, wakeRedis publishes wakeups to every
	// replica, and longPollMax caps a heartbeat's wait (SetWakeup). Without a hub a heartbeat is
	// answered at once.
	wakeHub     *wakeup.Hub
	wakeRedis   *redis.Client
	longPollMax time.Duration
	// workItems runs the sync work items (#933, D2; SetWorkItems). Without it none is offered.
	workItems *ansible.WorkItemRuntime
	// modulePublisher publishes the version a module_tag_snapshot uploads (#938;
	// SetModulePublisher).
	modulePublisher *registry.ModulePublisher
	// pauseRegistration holds new launcher registration and work admission during staged upgrades.
	pauseRegistration bool
}

// SetModulePublisher sets the publisher of module versions captured from a tag.
func (h *RunnerAgentHandler) SetModulePublisher(p *registry.ModulePublisher) { h.modulePublisher = p }

// DefaultLongPollMax caps a heartbeat's wait below the idle timeouts of the proxies between a
// launcher and the API (ingress-nginx's proxy-read-timeout defaults to 60 seconds; #933, D3).
const DefaultLongPollMax = 25 * time.Second

// SetWakeup enables the long-poll heartbeat: hub holds this replica's waiting heartbeats, rdb
// publishes wakeups, and maxWait caps a requested wait (zero means DefaultLongPollMax).
func (h *RunnerAgentHandler) SetWakeup(hub *wakeup.Hub, rdb *redis.Client, maxWait time.Duration) {
	if maxWait <= 0 {
		maxWait = DefaultLongPollMax
	}
	h.wakeHub, h.wakeRedis, h.longPollMax = hub, rdb, maxWait
}

// DefaultOutputBodyCap bounds one POST /runner/jobs/:id/output body (#933, D2, AC73).
const DefaultOutputBodyCap = 4 << 20

// jobLogLimits is the cap applied to a job's stored output.
func (h *RunnerAgentHandler) jobLogLimits() logbuffer.Limits {
	if h.logLimits.MaxBytes > 0 {
		return h.logLimits
	}
	return logbuffer.Limits{MaxBytes: settings.JobLogMaxBytes(os.Getenv), TailBytes: logbuffer.DefaultTailBytes}
}

// SetMirror sets the deployment's mirror, proxy and CA block, served in every job's artifacts so a
// job never depends on its launcher host's environment (#933, D2).
func (h *RunnerAgentHandler) SetMirror(m *runnercontract.Mirror) {
	h.mirror = m
}

// SetRegistryHost sets the host of the platform's private module registry, taken from its public
// URL, for which a job token's artifacts carry a per-job registry token (#933, D2, AC14).
func (h *RunnerAgentHandler) SetRegistryHost(host string) {
	h.registryHost = host
}

// NewRunnerAgentHandlerWithRepos creates a new runner agent handler with all repositories
func NewRunnerAgentHandlerWithRepos(
	runnerRepo *repository.RunnerRepository,
	jobExecRepo *repository.RunnerJobExecutionRepository,
	poolRepo *repository.AgentPoolRepository,
	apiKeyService *apikey.Service,
	ansibleJobRepo *repository.AnsibleJobRepository,
	playbookRepo *repository.AnsiblePlaybookRepository,
	inventoryRepo *repository.AnsibleInventoryRepository,
	credentialRepo *repository.AnsibleCredentialRepository,
	ansibleConfigRepo *repository.AnsibleConfigRepository,
	inventoryService *ansible.InventoryService,
	vcsRegistry *vcs.ProviderRegistry,
	cryptoService *crypto.CryptoService,
	variableService *variable.Service,
	storageClient storage.Client,
	db *gorm.DB,
) *RunnerAgentHandler {
	return &RunnerAgentHandler{
		runnerRepo:        runnerRepo,
		jobExecRepo:       jobExecRepo,
		poolRepo:          poolRepo,
		apiKeyService:     apiKeyService,
		ansibleJobRepo:    ansibleJobRepo,
		playbookRepo:      playbookRepo,
		inventoryRepo:     inventoryRepo,
		credentialRepo:    credentialRepo,
		ansibleConfigRepo: ansibleConfigRepo,
		inventoryService:  inventoryService,
		vcsRegistry:       vcsRegistry,
		cryptoService:     cryptoService,
		variableService:   variableService,
		storageClient:     storageClient,
		db:                db,
		pauseRegistration: os.Getenv("RUNNER_UPGRADE_PAUSE_REGISTRATION") == "true",
	}
}

// SetOIDCServices injects OIDC workload identity services for self-hosted runner OIDC injection.
// Called after handler creation because OIDC is optional (may not be configured).
func (h *RunnerAgentHandler) SetOIDCServices(
	azureOIDCRepo *repository.AzureOIDCConfigurationRepository,
	awsOIDCRepo *repository.AWSOIDCConfigurationRepository,
	gcpOIDCRepo *repository.GCPOIDCConfigurationRepository,
	vaultOIDCRepo *repository.VaultOIDCConfigurationRepository,
	oidcTokenService *oidc.TokenService,
) {
	h.azureOIDCRepo = azureOIDCRepo
	h.awsOIDCRepo = awsOIDCRepo
	h.gcpOIDCRepo = gcpOIDCRepo
	h.vaultOIDCRepo = vaultOIDCRepo
	h.oidcTokenService = oidcTokenService
}

// SetStateMaterializer injects the state outputs/resources materializer (State Storage
// Rework). Optional: when unset, state uploads simply skip materialization.
func (h *RunnerAgentHandler) SetStateMaterializer(m *state.Materializer) {
	h.stateMaterializer = m
}

// SetStateService injects the state service so self-hosted-runner state reads/writes
// route through the encryption-at-rest chokepoint (#95). Optional: when unset, state
// objects are read/written directly via the storage client (legacy/dev behaviour).
func (h *RunnerAgentHandler) SetStateService(s *state.Service) {
	h.stateService = s
}

// SetLogBuffer injects the Redis log buffer so agent job output streams through Redis instead of
// the O(n²) object-storage read-modify-write (AUD-028). Optional: when unset, output falls back to
// the direct object-storage append.
func (h *RunnerAgentHandler) SetLogBuffer(lb *logbuffer.RedisLogBuffer) {
	h.logBuffer = lb
}

// SetRBACService injects the permission check that holds an organization registration key to its
// owner's current permission (registrationKeyVerdict). Without it such keys register nothing; agent
// and just-in-time tokens are unaffected.
func (h *RunnerAgentHandler) SetRBACService(s *rbac.Service) {
	h.rbacService = s
}

// registrationKeyVerdict holds an organization key carrying runner:register to its owner's current
// permission. A key created on request stands for its owner, who must hold
// org:manage-agent-pools in orgID now, so a key created before that was required, or whose owner
// has since lost the permission, registers nothing. A just-in-time token is held to its owner, the
// user whose credential minted it, the same way. An agent token is a pool credential issued under
// that permission and passes. It answers 0 when the key may act, or the status and detail to
// refuse with.
func registrationKeyVerdict(c *gin.Context, rbacService *rbac.Service, orgID uuid.UUID) (int, string) {
	raw, _ := c.Get("api_key")
	key, ok := raw.(*models.APIKey)
	if !ok || key == nil {
		return http.StatusUnauthorized, "API key required for launcher registration"
	}
	if key.IsAgentToken && !key.IsJITToken {
		return 0, ""
	}
	const refused = "the owner of this key may not manage the organization's agent pools, so it cannot register launchers; use an agent token of the pool"
	if key.UserID == nil || rbacService == nil {
		return http.StatusForbidden, refused
	}
	may, err := rbacService.CheckOrgManageAgentPools(c.Request.Context(), *key.UserID, orgID)
	if err != nil {
		return http.StatusInternalServerError, "the key owner's agent pool permission could not be read"
	}
	if !may {
		return http.StatusForbidden, refused
	}
	return 0, ""
}

// RegisterRequest is runnercontract.RegisterRequest, the shared runner wire contract.
type RegisterRequest = runnercontract.RegisterRequest

// RegisterResponse is runnercontract.RegisterResponse, the shared runner wire contract.
type RegisterResponse = runnercontract.RegisterResponse

// poolBindingVerdict is the pool-binding check shared by registration and the queue-depth read:
// it answers 0 when a key may act on poolID, or the status and detail to refuse with. A binding
// that could not be read refuses, because reading it as "no binding" would let an agent token
// reach every pool of its organization.
func poolBindingVerdict(bound *uuid.UUID, err error, poolID uuid.UUID) (int, string) {
	switch {
	case err != nil:
		return http.StatusInternalServerError, "the token's agent pool binding could not be read"
	case bound != nil && *bound != poolID:
		return http.StatusForbidden, "this agent token is bound to a different agent pool"
	default:
		return 0, ""
	}
}

// grantsRunnerRegister reports whether a key's scopes name runner:register on orgID. An
// unrestricted key (no scopes, or the wildcard) is a general-purpose user token, not a runner
// credential, so it never qualifies; HasOrgPermission alone treats an empty scope list as full
// access.
func grantsRunnerRegister(checker *apikey.ScopeChecker, orgID uuid.UUID) bool {
	return !checker.IsUnrestricted() && checker.HasOrgPermission(orgID, "runner:register")
}

// Register registers a new runner
// POST /api/v2/runner/register
// Requires an API key with runner:register scope
// deriveRunnerType maps reported tool capabilities to a runner type. A runner that reports both
// (or neither) is treated as combined.
// runnerTypeFor is the stored runner type for the engines a runner declared (#933, D3, AC78), or,
// for a runner that declared none, for the tool versions it reported.
func runnerTypeFor(engines []string, tofuVersion, ansibleVersion string) models.RunnerType {
	if len(engines) > 0 {
		tofu, ansible := slices.Contains(engines, runnercontract.EngineTofu), slices.Contains(engines, runnercontract.EngineAnsible)
		switch {
		case tofu && !ansible:
			return models.RunnerTypeTofu
		case ansible && !tofu:
			return models.RunnerTypeAnsible
		}
		return models.RunnerTypeCombined
	}
	return deriveRunnerType(tofuVersion, ansibleVersion)
}

func deriveRunnerType(tofuVersion, ansibleVersion string) models.RunnerType {
	switch {
	case tofuVersion != "" && ansibleVersion == "":
		return models.RunnerTypeTofu
	case ansibleVersion != "" && tofuVersion == "":
		return models.RunnerTypeAnsible
	default:
		return models.RunnerTypeCombined
	}
}

func (h *RunnerAgentHandler) rejectPausedRegistration(c *gin.Context) bool {
	if !h.pauseRegistration {
		return false
	}
	jsonapi.WriteCodedError(c, http.StatusServiceUnavailable, "runner-upgrade-registration-paused",
		"Service Unavailable", "Launcher registration is paused during this upgrade. Retry after cutover.")
	return true
}

func (h *RunnerAgentHandler) Register(c *gin.Context) {
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", err.Error())
		return
	}

	// The hosted registration secret registers the one platform-level hosted runner identity (#933,
	// D9); every other key registers into a customer pool.
	if kind, _ := c.Get("token_kind"); kind == models.APIKeyKindHosted {
		h.registerHosted(c, req)
		return
	}
	if req.Hosted {
		jsonapi.WriteError(c, http.StatusForbidden, "Forbidden", "only the deployment's hosted registration secret registers a hosted launcher")
		return
	}

	// Parse agent pool ID
	poolID, err := uuid.Parse(req.AgentPoolID)
	if err != nil {
		jsonapi.WriteErrorNoDetail(c, http.StatusBadRequest, "Invalid agent_pool_id")
		return
	}

	// Get the pool to verify it exists and get org ID
	pool, err := h.poolRepo.GetByID(poolID, false)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			jsonapi.WriteErrorNoDetail(c, http.StatusNotFound, "Agent pool not found")
		} else {
			jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		}
		return
	}

	// A hosted pool is served by the hosted launchers alone (#933, D9): no organization key
	// registers a runner into it.
	if pool.IsHosted() {
		jsonapi.WriteError(c, http.StatusForbidden, "Forbidden", "hosted capacity is served by the platform's hosted launchers; register into one of the organization's agent pools")
		return
	}

	// Get the API key from context (set by auth middleware)
	apiKeyID, exists := c.Get("api_key_id")
	if !exists {
		jsonapi.WriteError(c, http.StatusUnauthorized, "Unauthorized", "API key required for launcher registration")
		return
	}

	// Only an organization key registers a runner into a customer pool: an agent token or an org
	// key carrying runner:register (#933, AC65). A user token, a job token or any other kind is
	// refused before its scopes are read, whatever they name.
	if kind, _ := c.Get("token_kind"); kind != models.APIKeyKindOrg {
		jsonapi.WriteError(c, http.StatusForbidden, "Forbidden", "only an agent token or an organization key carrying runner:register may register a launcher")
		return
	}

	// Check if API key has runner:register scope for this organization
	scopes, _ := c.Get("api_key_scopes")
	scopeStrs, ok := scopes.([]string)
	if !ok {
		jsonapi.WriteErrorNoDetail(c, http.StatusUnauthorized, "Unauthorized")
		return
	}

	scopeChecker, err := apikey.NewScopeChecker(scopeStrs)
	if err != nil {
		jsonapi.WriteErrorNoDetail(c, http.StatusUnauthorized, "Unauthorized")
		return
	}

	// Check for runner:register permission on the organization
	if !grantsRunnerRegister(scopeChecker, pool.OrganizationID) {
		jsonapi.WriteError(c, http.StatusForbidden, "Forbidden", "API key does not have the launcher registration scope (runner:register) for this organization")
		return
	}
	if status, detail := registrationKeyVerdict(c, h.rbacService, pool.OrganizationID); status != 0 {
		jsonapi.WriteError(c, status, http.StatusText(status), detail)
		return
	}

	// Pool-binding enforcement: an agent token (tfe_agent_token) is bound to a single pool, so a runner
	// presenting one may only join THAT pool. An ordinary org-level runner:register key has no binding
	// (nil) and keeps the historical behavior of joining any pool named in the body.
	if apiKeyUUID, perr := uuid.Parse(fmt.Sprintf("%v", apiKeyID)); perr == nil {
		boundPool, berr := h.apiKeyService.AgentPoolBindingForKey(apiKeyUUID)
		if status, detail := poolBindingVerdict(boundPool, berr, poolID); status != 0 {
			jsonapi.WriteError(c, status, http.StatusText(status), detail)
			return
		}
	}

	if h.rejectPausedRegistration(c) {
		return
	}
	rawKey, _ := c.Get("api_key")
	registrationKey, _ := rawKey.(*models.APIKey)
	registeringUserID, _ := c.Get("user_id")
	registeringUserUUID, _ := registeringUserID.(uuid.UUID)
	apiKeyUUID, _ := uuid.Parse(fmt.Sprintf("%v", apiKeyID))
	runner, raw, created, err := h.registerCustomerRunner(c.Request.Context(), req, pool, registrationKey, apiKeyUUID, registeringUserUUID, c.ClientIP())
	if errors.Is(err, errJITRegistrationConsumed) {
		jsonapi.WriteError(c, http.StatusUnauthorized, "Unauthorized", "this just-in-time token has been used or has expired")
		return
	}
	if err != nil {
		logger.Warnf("Launcher registration failed for pool %s: %v", poolID, err)
		jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Failed to register launcher")
		return
	}
	logger.Infof("Launcher registered: %s (ID: %s, pool: %s)", runner.Name, runner.ID, poolID)

	// Fetch post-registration state after commit. No response may disclose an
	// identity or key that failed to commit alongside the one-time token.
	active := h.activeClaims(c.Request.Context(), runner.ID)
	if !created {
		pendingJobs := []PendingJob{}
		if jobs, err := h.findPendingJobsForRunner(c.Request.Context(), runner); err == nil {
			pendingJobs = jobs
		}
		c.JSON(http.StatusOK, RunnerReRegisterResponse{
			RunnerID: runner.ID.String(), RunnerAPIKey: raw, Status: "re-registered",
			PendingJobs: pendingJobs, Capabilities: runnercontract.APICapabilities, ActiveClaims: active,
		})
		return
	}
	c.JSON(http.StatusCreated, RunnerRegisterResponse{
		RunnerID: runner.ID.String(), RunnerAPIKey: raw, PollIntervalSeconds: 10,
		ActiveClaims: active, Capabilities: runnercontract.APICapabilities,
	})
}

// registerHosted registers a hosted launcher (#933, D9, AC69): one runner row of kind hosted with
// no organization and no pool, named uniquely among hosted runners, serving every hosted pool of
// its placement group, with a hosted runner token. Only the hosted registration secret gets here;
// a hosted runner token, which is of the same kind, is refused.
func (h *RunnerAgentHandler) registerHosted(c *gin.Context, req RegisterRequest) {
	raw, _ := c.Get("api_key")
	key, _ := raw.(*models.APIKey)
	if !apikey.IsHostedRegistrationKey(key) {
		jsonapi.WriteError(c, http.StatusForbidden, "Forbidden", "only the hosted registration secret may register a hosted launcher")
		return
	}
	if h.rejectPausedRegistration(c) {
		return
	}
	if h.apiKeyService == nil {
		jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	group := strings.TrimSpace(req.HostedGroup)
	if group == "" {
		group = "default"
	}
	now := time.Now()
	maxJobs := max(req.MaxConcurrentJobs, 1)
	runner, err := h.runnerRepo.GetHostedByName(req.Name)
	status := http.StatusOK
	if err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
			return
		}
		runner = &models.Runner{Kind: models.RunnerKindHosted, Name: req.Name, RegisteredAt: now}
		status = http.StatusCreated
	}
	runner.Status = models.RunnerStatusOnline
	runner.HostedGroup = group
	runner.RunnerType = runnerTypeFor(req.Engines, req.TofuVersion, req.AnsibleVersion)
	runner.Hostname, runner.IPAddress, runner.OSType, runner.OSVersion = req.Hostname, c.ClientIP(), req.OSType, req.OSVersion
	runner.AgentVersion, runner.TofuVersion, runner.AnsibleVersion = req.AgentVersion, req.TofuVersion, req.AnsibleVersion
	runner.MaxConcurrentJobs = maxJobs
	runner.Labels = models.RunnerLabels(req.Labels)
	runner.Capabilities = models.RunnerLabels(req.Capabilities)
	runner.Driver, runner.NetworkMode = req.Driver, req.NetworkMode
	applyLauncherSettings(runner, req)
	runner.DrainRequestedAt = nil
	runner.LastHeartbeatAt = &now
	runner.RegisteredWithAPIKeyID = &key.ID
	if status == http.StatusCreated {
		err = h.runnerRepo.Create(runner)
	} else {
		err = h.runnerRepo.Update(runner)
	}
	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "failed to register the hosted launcher")
		return
	}
	_ = h.apiKeyService.DeleteAPIKeysForRunner(runner.ID)
	_, token, err := h.apiKeyService.CreateHostedRunnerToken(runner.ID, "runner-"+runner.Name)
	if err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "failed to mint the hosted launcher token")
		return
	}
	logger.Infof("Hosted launcher registered: %s (ID: %s, group: %s)", runner.Name, runner.ID, group)
	c.JSON(status, RunnerRegisterResponse{RunnerID: runner.ID.String(), RunnerAPIKey: token, PollIntervalSeconds: 10, Capabilities: runnercontract.APICapabilities, ActiveClaims: h.activeClaims(c.Request.Context(), runner.ID)})
}

// HeartbeatRequest is runnercontract.HeartbeatRequest, the shared runner wire contract.
type HeartbeatRequest = runnercontract.HeartbeatRequest

// HeartbeatResponse is runnercontract.HeartbeatResponse, the shared runner wire contract.
type HeartbeatResponse = runnercontract.HeartbeatResponse

// PendingJob is runnercontract.PendingJob, the shared runner wire contract.
type PendingJob = runnercontract.PendingJob

// Heartbeat processes a runner heartbeat and returns pending jobs
// POST /api/v2/runner/heartbeat
func (h *RunnerAgentHandler) Heartbeat(c *gin.Context) {
	var req HeartbeatRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", err.Error())
		return
	}

	// AUD-001: the authenticated runner (from its runner-scoped token) is the only
	// identity we trust. A runner may only heartbeat as itself, so the body
	// runner_id must match - otherwise a runner could drive another runner's job
	// offers/reservations.
	runner, ok := callingRunner(c)
	if !ok {
		writeRunnerForbidden(c, "launcher identity required")
		return
	}
	runnerID := runner.ID
	if req.RunnerID != "" && req.RunnerID != runner.ID.String() {
		writeRunnerForbidden(c, "runner_id does not match the authenticated launcher")
		return
	}

	// Update runner status
	status := models.RunnerStatusOnline
	if req.Status == "busy" {
		status = models.RunnerStatusBusy
	}
	if err := h.runnerRepo.UpdateHeartbeat(runnerID, status, req.CurrentJobs); err != nil {
		jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	// The runner token lives as long as its runner keeps calling (#933, D1).
	if raw, ok := c.Get("api_key"); ok && h.apiKeyService != nil {
		if key, isKey := raw.(*models.APIKey); isKey {
			if err := h.apiKeyService.RenewRunnerToken(key); err != nil {
				logger.Warnf("heartbeat of runner %s: %v", runnerID, err)
			}
		}
	}

	if h.pauseRegistration {
		if err := h.runnerRepo.ReleaseUpgradeReservations(c.Request.Context(), runnerID); err != nil {
			logger.Warnf("releasing unstarted upgrade reservations for runner %s: %v", runnerID, err)
		}
	}

	// Find pending jobs for this runner's pool
	pendingJobs := []PendingJob{}

	// Determine available capacity: use explicit field if sent, otherwise derive from runner settings
	availableCapacity := req.AvailableCapacity
	if availableCapacity == 0 && req.CurrentJobs == 0 {
		// Runner didn't send available_capacity but has no current jobs - it has capacity
		maxJobs := runner.MaxConcurrentJobs
		if maxJobs <= 0 {
			maxJobs = 1
		}
		availableCapacity = maxJobs - req.CurrentJobs
	}

	// A runner asked to drain is offered nothing and told so (D11).
	draining := runner.DrainRequestedAt != nil
	if draining || h.pauseRegistration {
		availableCapacity = 0
	}

	// Only query for jobs if runner has capacity
	if availableCapacity > 0 {
		pendingJobs = h.offers(c.Request.Context(), runner)
		// The long poll (#933, D3): with nothing to offer, hold the request until a wakeup for the
		// runner's pool or the wait ends, then query again. The waiter is registered before the
		// second query, so work that became offerable between the two is not missed; while it waits
		// the request holds a goroutine, no database connection.
		if len(pendingJobs) == 0 && req.WaitSeconds > 0 && h.wakeHub != nil {
			wait := min(time.Duration(req.WaitSeconds)*time.Second, h.longPollMax)
			woken, forget := h.wakeHub.Wait(wakeKey(runner))
			if pendingJobs = h.offers(c.Request.Context(), runner); len(pendingJobs) == 0 {
				timer := time.NewTimer(wait)
				select {
				case <-woken:
				case <-timer.C:
				case <-c.Request.Context().Done():
				}
				timer.Stop()
				forget()
				if c.Request.Context().Err() != nil {
					return
				}
				// The runner was here for the whole wait: stamp it again, so the monitor measures
				// only the time the launcher spends between requests, claiming what it is offered
				// (AC17). A failed stamp leaves the one taken when the request arrived.
				if err := h.runnerRepo.UpdateHeartbeat(runnerID, status, req.CurrentJobs); err != nil {
					logger.Warnf("heartbeat of runner %s after its wait: %v", runnerID, err)
				}
				pendingJobs = h.offers(c.Request.Context(), runner)
			} else {
				forget()
			}
		}
	}

	resp := HeartbeatResponse{
		PendingJobs: pendingJobs, Capabilities: runnercontract.APICapabilities,
		Drain: draining, ActiveClaims: h.activeClaims(c.Request.Context(), runner.ID),
	}
	if !h.pauseRegistration {
		resp.Ensure = h.ingestInventory(runner, req.Inventory)
		resp.HostedDepth = h.hostedDepth(runner)
		resp.ReapRunners = h.lostPeers(runner)
		if resp.CachePromotions = h.pendingPromotions(runner); len(resp.CachePromotions) > 0 {
			resp.Mirror = h.mirror
		}
	}
	c.JSON(http.StatusOK, resp)
}

// lostPeerWindow bounds how long after a runner was last heard from its leftovers are reaped: a
// placement outlives its job's timeout by at most its keep window, so a week covers every one.
const lostPeerWindow = 7 * 24 * time.Hour

// lostPeers names the offline runners of the caller's pool or hosted group, whose leftover
// placements the launcher stops and removes (#933, D3, AC67); a failed lookup names none.
func (h *RunnerAgentHandler) lostPeers(runner *models.Runner) []string {
	if h.runnerRepo == nil {
		return nil
	}
	peers, err := h.runnerRepo.LostPeers(runner, lostPeerWindow)
	if err != nil {
		logger.Warnf("listing the lost peers of runner %s: %v", runner.ID, err)
		return nil
	}
	return peers
}

// Drain asks a runner to drain (#933, D11): its next heartbeat answers drain and offers nothing,
// and the launcher finishes its in-flight jobs, claims nothing more and deregisters, as on
// SIGTERM. The caller is the runner's own token, so whatever holds it (the launcher, or the
// operator that started it with a just-in-time token) drains it; another runner is refused.
//
// POST /api/v2/runner/drain
func (h *RunnerAgentHandler) Drain(c *gin.Context) {
	var req DrainRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", err.Error())
		return
	}
	runner, ok := callingRunner(c)
	if !ok {
		writeRunnerForbidden(c, "launcher identity required")
		return
	}
	if req.RunnerID != runner.ID.String() {
		writeRunnerForbidden(c, "a launcher drains itself only")
		return
	}
	if err := h.runnerRepo.RequestDrain(runner.ID); err != nil {
		jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	c.Status(http.StatusAccepted)
}

// DrainRequest is runnercontract.DrainRequest, the shared runner wire contract.
type DrainRequest = runnercontract.DrainRequest

// offers is the work offered to runner now; a failed query offers nothing and the next heartbeat
// asks again.
func (h *RunnerAgentHandler) offers(ctx context.Context, runner *models.Runner) []PendingJob {
	jobs, err := h.findPendingJobsForRunner(ctx, runner)
	if err != nil || jobs == nil {
		return []PendingJob{}
	}
	return jobs
}

// JobStartRequest is runnercontract.JobStartRequest, the shared runner wire contract.
type JobStartRequest = runnercontract.JobStartRequest

// JobStart marks a job as started
// POST /api/v2/runner/jobs/:id/start
func (h *RunnerAgentHandler) JobStart(c *gin.Context) {
	var req JobStartRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", err.Error())
		return
	}
	runner, ok := callingRunner(c)
	if !ok {
		writeRunnerForbidden(c, "launcher identity required")
		return
	}
	if isWorkItem(c.Param("id")) && h.workItems == nil {
		jsonapi.WriteErrorNoDetail(c, http.StatusNotFound, "Work item not found")
		return
	}
	result, err := h.startExpectedClaim(c.Request.Context(), c.Param("id"), runner.ID, req)
	if err != nil {
		writeRunnerClaimError(c, err)
		return
	}
	jsonapi.WriteMeta(c, http.StatusOK, result)
}

// upsertJobExecution ensures a running RunnerJobExecution record exists for the
// (claimed) Ansible job, bound to the winning runner. Created at claim time so a
// runner is only counted as busy with jobs it actually owns.
func (h *RunnerAgentHandler) upsertJobExecution(job *models.AnsibleJob, runnerID uuid.UUID) error {
	exec, err := h.jobExecRepo.GetByJobID(job.ID)
	if err == nil {
		return h.db.Model(&models.RunnerJobExecution{}).Where("id = ?", exec.ID).Updates(map[string]any{
			"runner_id": runnerID, "status": models.JobExecutionStatusRunning,
			"started_at": job.StartedAt, "finished_at": nil, "error_message": "",
			"workspace_name": job.Project.Name,
		}).Error
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return fmt.Errorf("loading the job execution: %w", err)
	}

	return h.jobExecRepo.Create(&models.RunnerJobExecution{
		RunnerID:      runnerID,
		JobType:       models.JobTypeAnsibleJob,
		JobID:         job.ID,
		WorkspaceName: job.Project.Name,
		Status:        models.JobExecutionStatusRunning,
		StartedAt:     job.StartedAt,
	})
}

// JobOutputRequest is runnercontract.JobOutputRequest, the shared runner wire contract.
type JobOutputRequest = runnercontract.JobOutputRequest

// JobOutput receives streaming output from a job and stores it as structured events
// POST /api/v2/runner/jobs/:id/output
func (h *RunnerAgentHandler) JobOutput(c *gin.Context) {
	jobIDStr := c.Param("id")

	bodyCap := h.outputBodyCap
	if bodyCap <= 0 {
		bodyCap = DefaultOutputBodyCap
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, bodyCap)
	var req JobOutputRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			jsonapi.WriteError(c, http.StatusRequestEntityTooLarge, "Request Entity Too Large", "the output body exceeds the size limit")
			return
		}
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", err.Error())
		return
	}
	// A placement alone is a launcher reporting what it learnt after the claim: the image digest a
	// kubelet pulled (the Kubernetes driver).
	if req.Output == "" && req.PhaseState == nil && req.Placement == nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "output, phase_state or placement is required")
		return
	}
	if isWorkItem(jobIDStr) {
		h.jobOutputWorkItem(c, jobIDStr, req)
		return
	}

	// Terraform run output - store in MinIO logs for the run
	if strings.HasPrefix(jobIDStr, "run-") {
		// AUD-001: only the assigned runner may append to a run's logs - otherwise
		// any runner could poison another tenant's plan/apply output.
		var run models.Run
		if err := h.db.First(&run, "id = ?", jobIDStr).Error; err != nil {
			writeRunnerJobReadError(c, err)
			return
		}
		if !h.authorizeRunnerForRunReport(c, &run) {
			return
		}
		h.recordPlacement(models.JobTypeTofuRun, run.ID, req.Placement)
		if h.storageClient != nil && req.Output != "" {
			ctx := context.Background()
			// Append output to the run's log in storage
			// Phase must match the log retrieval handler's expectations:
			// plan → runs/{id}/logs/plan.log, apply → runs/{id}/logs/apply.log
			// TFE-compatible: destroy runs use plan + apply phases (no separate "destroy" phase)
			phase := "plan"
			if req.Stream == "apply" {
				phase = "apply"
			}
			// AUD-028: stream through Redis (O(1) APPEND) when available - the same buffer the
			// remote-runner path uses - instead of the O(n²) read-modify-write on object storage.
			// It is copied to MinIO once at JobComplete. Fall back to the object-storage append
			// when no Redis buffer is configured.
			// The stored output of a job is capped (#933, D2, AC73): past the cap the head and the
			// end are kept and the log says how much was dropped; the job carries on.
			var firstDrop bool
			var appendErr error
			if h.logBuffer != nil {
				firstDrop, appendErr = h.logBuffer.AppendCapped(ctx, jobIDStr, phase, req.Output, h.jobLogLimits())
			} else {
				firstDrop, appendErr = logbuffer.AppendStorageLogCapped(ctx, h.storageClient, jobIDStr, phase, req.Output, h.jobLogLimits())
			}
			if appendErr != nil {
				logger.Warnf("Failed to append agent output for %s phase %s: %v", jobIDStr, phase, appendErr)
			}
			if firstDrop {
				logger.Infof("Run %s phase %s output passed the job log cap; the middle is dropped", jobIDStr, phase)
			}
		}
		if req.PhaseState != nil {
			if !h.storePhaseState(c, run.ID, req.PhaseState) {
				return
			}
		}
		response.Status(c, http.StatusOK, "received")
		return
	}
	if req.Output == "" && req.Placement == nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "output is required")
		return
	}

	jobID, err := uuid.Parse(jobIDStr)
	if err != nil {
		jsonapi.WriteErrorNoDetail(c, http.StatusBadRequest, "Invalid job ID")
		return
	}

	if h.ansibleJobRepo == nil {
		response.Status(c, http.StatusOK, "received")
		return
	}

	// AUD-001: only the runner that owns the job may write its output/events.
	outputJob, err := h.ansibleJobRepo.GetByID(jobID)
	if err != nil {
		writeRunnerJobReadError(c, err)
		return
	}
	if !h.authorizeRunnerForAnsibleJobReport(c, outputJob) {
		return
	}
	h.recordPlacement(models.JobTypeAnsibleJob, jobIDStr, req.Placement)

	line := strings.TrimSpace(req.Output)
	if line == "" {
		response.Status(c, http.StatusOK, "received")
		return
	}
	// The stored output of a job is capped (#933, D2, AC73); trimming runs after this line is stored.
	defer h.capAnsibleOutput(jobID, int64(len(line)))

	// Handle stderr output - store as stderr events
	if req.Stream == "stderr" {
		// AUD-063: CreateEventNextCounter allocates the counter atomically; concurrent runner POSTs
		// used to read the same MAX(counter) and collide.
		event := &models.AnsibleJobEvent{
			JobID:     jobID,
			Event:     "runner_stderr",
			EventData: map[string]interface{}{"stderr": line},
			Stderr:    line,
		}
		_ = h.ansibleJobRepo.CreateEventNextCounter(event)
		response.Status(c, http.StatusOK, "received")
		return
	}

	// Handle stdout - parse as JSONL from ansible.posix.jsonl callback
	var eventData map[string]interface{}
	if err := json.Unmarshal([]byte(line), &eventData); err != nil {
		// Not JSON - store as raw output event
		event := &models.AnsibleJobEvent{
			JobID:  jobID,
			Event:  "runner_output",
			Stdout: line,
		}
		_ = h.ansibleJobRepo.CreateEventNextCounter(event)
		response.Status(c, http.StatusOK, "received")
		return
	}

	// Parse JSONL event and store as structured event
	h.parseAndStoreAgentEvent(jobID, eventData, line)

	response.Status(c, http.StatusOK, "received")
}

// capAnsibleOutput accounts n bytes of a job's output against the job log cap. Once the output
// passes the cap's head it records one log_truncated event, and from then on keeps only the last
// TailBytes of output after that event, counting what it drops on the event and the job.
func (h *RunnerAgentHandler) capAnsibleOutput(jobID uuid.UUID, n int64) {
	limits := h.jobLogLimits()
	total, truncatedAt, err := h.ansibleJobRepo.AddOutputBytes(jobID, n)
	if err != nil {
		logger.Warnf("accounting the output of job %s: %v", jobID, err)
		return
	}
	if total <= limits.MaxBytes-limits.TailBytes {
		return
	}
	if truncatedAt == 0 {
		marker := &models.AnsibleJobEvent{
			JobID:     jobID,
			Event:     "log_truncated",
			EventData: map[string]interface{}{"dropped_bytes": 0, "max_bytes": limits.MaxBytes},
			Stdout:    "",
		}
		if err := h.ansibleJobRepo.CreateEventNextCounter(marker); err != nil {
			logger.Warnf("recording the truncation of job %s: %v", jobID, err)
			return
		}
		if truncatedAt, err = h.ansibleJobRepo.MarkOutputTruncated(jobID, marker.Counter); err != nil {
			logger.Warnf("recording the truncation of job %s: %v", jobID, err)
			return
		}
	}
	if _, err := h.ansibleJobRepo.TrimOutputTail(jobID, truncatedAt, limits.TailBytes); err != nil {
		logger.Warnf("trimming the output of job %s: %v", jobID, err)
	}
}

// storePhaseState upserts a run's per-resource state for one phase from a phase_state event
// (#933, D2, AC8). It writes the error response and returns false when the event is invalid.
func (h *RunnerAgentHandler) storePhaseState(c *gin.Context, runID string, ps *runnercontract.PhaseState) bool {
	if ps.Phase != "plan" && ps.Phase != "apply" {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "phase_state.phase must be plan or apply")
		return false
	}
	resources := ps.Resources
	if resources == nil {
		resources = models.ResourceStates{}
	}
	row := &models.RunPhaseState{RunID: runID, Phase: ps.Phase, Resources: resources, Summary: ps.Summary, ParsedAt: time.Now()}
	if err := repository.NewRunPhaseStateRepository(h.db).Upsert(row); err != nil {
		jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		return false
	}
	return true
}

// JobEventRequest is runnercontract.JobEventRequest, the shared runner wire contract.
type JobEventRequest = runnercontract.JobEventRequest

// runnerJobEvents is the closed set of events a runner may record through JobEvents:
// the playbook-preparation rows the platform runner writes straight to the database.
// Everything else, in particular the runner_on_* and v2_playbook_on_stats rows that
// drive host counters and the task tree, is derived server-side from the streamed
// output and must not be forgeable through this endpoint.
var runnerJobEvents = []string{
	"galaxy_cache_seeded",
	"galaxy_install",
	"galaxy_install_failed",
	"galaxy_install_complete",
	"playbook_source",
}

// maxJobEventTaskLen is the width of AnsibleJobEvent.Task.
const maxJobEventTaskLen = 500

// JobEvents records a playbook-preparation event for an Ansible job on behalf of the
// self-hosted runner executing it. The row takes the job's next counter, so it stays
// in sequence with the output streamed through JobOutput.
// POST /api/v2/runner/jobs/:id/events
func (h *RunnerAgentHandler) JobEvents(c *gin.Context) {
	jobID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		jsonapi.WriteErrorNoDetail(c, http.StatusBadRequest, "Invalid job ID")
		return
	}

	var req JobEventRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", err.Error())
		return
	}

	if h.ansibleJobRepo == nil {
		jsonapi.WriteErrorNoDetail(c, http.StatusNotImplemented, "Job events not configured")
		return
	}

	job, err := h.ansibleJobRepo.GetByID(jobID)
	if err != nil {
		writeRunnerJobReadError(c, err)
		return
	}
	// AUD-001: only the runner that owns the job may write its events.
	if !h.authorizeRunnerForAnsibleJobReport(c, job) {
		return
	}

	// The task column holds maxJobEventTaskLen characters; a longer one would fail the
	// insert and read as a server error when it is the caller's.
	if utf8.RuneCountInString(req.Task) > maxJobEventTaskLen {
		jsonapi.WriteError(c, http.StatusUnprocessableEntity, "Unprocessable Entity",
			fmt.Sprintf("task is longer than %d characters", maxJobEventTaskLen))
		return
	}

	if !slices.Contains(runnerJobEvents, req.Event) {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request",
			fmt.Sprintf("event %q cannot be recorded by a launcher; allowed: %s", req.Event, strings.Join(runnerJobEvents, ", ")))
		return
	}

	event := &models.AnsibleJobEvent{
		JobID:     jobID,
		Event:     req.Event,
		Task:      req.Task,
		Stdout:    req.Stdout,
		Stderr:    req.Stderr,
		Failed:    req.Failed,
		Timestamp: time.Now().UTC(),
	}
	if err := h.ansibleJobRepo.CreateEventNextCounter(event); err != nil {
		logger.Errorf("Failed to store %s event for job %s: %v", req.Event, jobID, err)
		jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		return
	}

	response.Status(c, http.StatusOK, "received")
}

// parseAndStoreAgentEvent parses a JSONL event from a self-hosted runner and stores it
func (h *RunnerAgentHandler) parseAndStoreAgentEvent(jobID uuid.UUID, eventData map[string]interface{}, rawLine string) {
	// AUD-063: the counter is assigned atomically at insert time by CreateEventNextCounter, not
	// read-then-incremented here where concurrent runner POSTs would collide.
	event, stats, ok := ansible.ParseJSONLEvent(jobID, eventData, rawLine, time.Now())
	if !ok {
		return
	}
	if stats != nil {
		// The recap's totals are the job's stats; its host count is the authoritative one.
		if job, err := h.ansibleJobRepo.GetByID(jobID); err == nil {
			job.HostsTotal = stats.Hosts
			job.HostsOk = stats.OK
			job.HostsChanged = stats.Changed
			job.HostsFailed = stats.Failed
			job.HostsSkipped = stats.Skipped
			job.HostsUnreachable = stats.Unreachable
			job.HostsRescued = stats.Rescued
			job.HostsIgnored = stats.Ignored
			_ = h.ansibleJobRepo.UpdateColumns(job, "hosts_total", "hosts_ok", "hosts_changed", "hosts_failed",
				"hosts_skipped", "hosts_unreachable", "hosts_rescued", "hosts_ignored")
		}
	}
	_ = h.ansibleJobRepo.CreateEventNextCounter(event)
}

// JobCompleteRequest is runnercontract.JobCompleteRequest, the shared runner wire contract.
type JobCompleteRequest = runnercontract.JobCompleteRequest

// JobComplete marks a job as completed
// POST /api/v2/runner/jobs/:id/complete
func (h *RunnerAgentHandler) JobComplete(c *gin.Context) {
	jobID := c.Param("id")
	var req JobCompleteRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", err.Error())
		return
	}
	if _, jobToken := callingJob(c); !jobToken {
		h.completeStartupFailure(c, jobID, req)
		return
	}
	validStatus := req.Status == "completed" || req.Status == "failed" || req.Status == "canceled" || (isWorkItem(jobID) && req.Status == "successful")
	if !validStatus || req.Attempt < 0 {
		jsonapi.WriteErrorNoDetail(c, http.StatusBadRequest, "Invalid completion")
		return
	}
	effect, err := h.completeReportedClaim(c, jobID, req)
	if errors.Is(err, errCompletionAnswered) {
		return
	}
	if errors.Is(err, errCompletionMissing) {
		jsonapi.WriteErrorNoDetail(c, http.StatusNotFound, "Job not found")
		return
	}
	if errors.Is(err, repository.ErrInvalidClaim) || errors.Is(err, errInvalidRunnerJobID) {
		jsonapi.WriteErrorNoDetail(c, http.StatusBadRequest, "Invalid completion identity")
		return
	}
	if err != nil {
		jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	h.finalizeCompletedClaim(c.Request.Context(), effect)
	h.wakeCallersPool(c)
	response.Status(c, http.StatusOK, "completed")
}

// completeStartupFailure is the completion-only launcher-key exception. It consumes the
// original candidate under the start lock before committing its failed outcome and cleanup.
func (h *RunnerAgentHandler) completeStartupFailure(c *gin.Context, id string, req JobCompleteRequest) {
	runner, ok := callingRunner(c)
	if !ok || req.RunnerID != runner.ID.String() {
		writeRunnerForbidden(c, "runner_id does not match the authenticated launcher")
		return
	}
	tofu := strings.HasPrefix(id, "run-")
	validPhase := req.Phase == ""
	if tofu {
		validPhase = req.Phase == "plan" || req.Phase == "apply"
	}
	if req.Attempt <= 0 || !validPhase || req.Status != "failed" || req.Output != "" || req.PlanJSON != "" ||
		req.ResourceAdditions != 0 || req.ResourceChanges != 0 || req.ResourceDestructions != 0 ||
		req.OutputChanges != 0 || req.HasChanges || req.WorkResult != nil || req.CacheManifest != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "launcher completion requires a bound failed startup without result data")
		return
	}
	if h.db == nil || (isWorkItem(id) && h.workItems == nil) {
		jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	err := h.db.WithContext(c.Request.Context()).Transaction(func(tx *gorm.DB) error {
		expected := runnercontract.JobStartRequest{RunnerID: req.RunnerID, Attempt: req.Attempt, Phase: req.Phase}
		if tofu {
			var run models.Run
			if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&run, "id = ?", id).Error; err != nil {
				return err
			}
			expected.RunType = runnercontract.ExecutableRunType(run.Operation, req.Phase)
			if expected.RunType == "" {
				return repository.ErrInvalidClaim
			}
		}
		scoped := *h
		scoped.db = tx
		if _, err := scoped.startExpectedClaim(c.Request.Context(), id, runner.ID, expected); err != nil {
			return err
		}
		kind, err := failStartedClaim(tx, id, req)
		if err != nil {
			return err
		}
		keys := apikey.NewService(repository.NewAPIKeyRepository(tx), nil, nil, nil)
		if err := keys.RevokeJobTokens(kind, id); err != nil {
			return err
		}
		return updateRunnerAfterClaim(tx, runner.ID)
	})
	if errors.Is(err, repository.ErrClaimConflict) {
		jsonapi.WriteCodedError(c, http.StatusConflict, runnercontract.ErrorCodeJobTerminal, "Conflict", "the expected claim has settled or been superseded")
		return
	}
	if err != nil {
		writeRunnerClaimError(c, err)
		return
	}
	h.wakeCallersPool(c)
	response.Status(c, http.StatusOK, "completed")
}

// wakeCallersPool wakes the launchers of the calling runner's pool once a job of theirs ended:
// its capacity is free, and for a run its workspace lock and for a hosted pool a slot of its cap.
func (h *RunnerAgentHandler) wakeCallersPool(c *gin.Context) {
	if runner, ok := callingRunner(c); ok {
		wakeup.Publish(c.Request.Context(), h.wakeRedis, wakeKey(runner))
	}
}

// wakeKey is the wakeup a runner's long poll waits on: its pool, or for a hosted runner every
// hosted pool (wakeup.KeyHosted), which is what publishers for a hosted pool publish.
func wakeKey(runner *models.Runner) string {
	if runner.IsHosted() {
		return wakeup.KeyHosted
	}
	return runner.PoolID().String()
}

// lockWorkspaceForRun takes the workspace state lock for a run's phase when the run writes state
// (plan-and-apply and destroy, as the queue runner does), with the run as holder and its resolved
// timeout as TTL. It reports false when another run holds the lock.
func (h *RunnerAgentHandler) lockWorkspaceForRun(run *models.Run) (bool, error) {
	if run.Operation != models.RunOperationPlanAndApply && run.Operation != models.RunOperationDestroy {
		return true, nil
	}
	ws, err := repository.NewWorkspaceRepository(h.db).GetByID(run.WorkspaceID)
	if err != nil {
		return false, fmt.Errorf("loading workspace %s: %w", run.WorkspaceID, err)
	}
	timeout := settings.EffectiveWorkspaceRunTimeout(ws, settings.DeploymentRunTimeout(os.Getenv)).Value
	holder := run.ID
	err = repository.NewStateLockRepository(h.db).AcquireLock(&models.StateLock{
		WorkspaceID: run.WorkspaceID,
		LockID:      repository.RunStateLockID(run.ID),
		Operation:   string(run.Operation),
		LockedBy:    &holder,
		ExpiresAt:   time.Now().Add(time.Duration(timeout) * time.Second),
	})
	if errors.Is(err, repository.ErrStateAlreadyLocked) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("locking workspace %s: %w", run.WorkspaceID, err)
	}
	return true, nil
}

// MaxStateUploadBytes bounds one uploaded state.
const MaxStateUploadBytes = 512 << 20

// readStateUpload reads an uploaded state: the raw state file when the body is
// application/octet-stream, otherwise the base64 state member of the JSON form. It writes the error
// response and returns false when the body is unusable.
func readStateUpload(c *gin.Context) ([]byte, bool) {
	if strings.HasPrefix(c.ContentType(), "application/octet-stream") {
		data, err := io.ReadAll(io.LimitReader(c.Request.Body, MaxStateUploadBytes+1))
		if err != nil {
			jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "reading the state")
			return nil, false
		}
		if len(data) > MaxStateUploadBytes {
			jsonapi.WriteError(c, http.StatusRequestEntityTooLarge, "Request Entity Too Large", "the state exceeds the size limit")
			return nil, false
		}
		if len(data) == 0 {
			jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "the state is empty")
			return nil, false
		}
		return data, true
	}
	var req struct {
		RunnerID string `json:"runner_id"`
		State    string `json:"state"` // base64-encoded terraform.tfstate
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", err.Error())
		return nil, false
	}
	if req.State == "" {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "state field required")
		return nil, false
	}
	data, err := base64.StdEncoding.DecodeString(req.State)
	if err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "invalid base64 state data")
		return nil, false
	}
	return data, true
}

// jobRegistryBlock replaces a job's private-registry credential under its current
// claim lock. Only a committed replacement is returned to the executor.
func (h *RunnerAgentHandler) jobRegistryBlock(c *gin.Context, run *models.Run) (*runnercontract.RegistryBlock, bool) {
	principal, isJob := callingJob(c)
	if !isJob {
		return nil, true
	}
	values, supplied := c.Request.Header[http.CanonicalHeaderKey(runnercontract.ArtifactSequenceHeader)]
	var sequence int64
	if supplied {
		var err error
		if len(values) == 1 {
			sequence, err = strconv.ParseInt(values[0], 10, 64)
		}
		if len(values) != 1 || err != nil || sequence <= 0 {
			jsonapi.WriteErrorNoDetail(c, http.StatusBadRequest, "Invalid artifact sequence")
			return nil, false
		}
	}
	fixedClient := runnerCan(c, runnercontract.CapabilityClaimRecovery)
	if (run.ClaimRecovery || run.ArtifactSequence > 0 || fixedClient) && !supplied {
		jsonapi.WriteErrorNoDetail(c, http.StatusBadRequest, "Artifact sequence required")
		return nil, false
	}
	if h.registryHost == "" {
		return nil, true
	}
	if h.apiKeyService == nil {
		jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		return nil, false
	}
	var token string
	err := h.db.WithContext(c.Request.Context()).Transaction(func(tx *gorm.DB) error {
		var current models.Run
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Preload("Workspace.Project.Organization").First(&current, "id = ?", run.ID).Error; err != nil {
			writeRunnerJobReadError(c, err)
			return err
		}
		scoped := *h
		scoped.db = tx
		if !authorizeJobPrincipal(c, principal, models.JobTypeTofuRun, current.ID, current.RunnerID, current.Attempt, false) || !scoped.authorizeRunnerForRun(c, &current, true) {
			return errors.New("artifact claim authorization refused")
		}
		phase := current.ClaimedPhase
		if phase != "plan" && phase != "apply" {
			return errors.New("original artifact phase unavailable")
		}
		resolved := runnercontract.ExecutableRunType(current.Operation, phase)
		if resolved == "" || (current.ClaimedRunType != "" && current.ClaimedRunType != resolved) {
			return errors.New("original artifact operation unavailable")
		}
		active := current.DispatchedAt != nil && ((phase == "plan" && current.Status == models.RunStatusPlanning) || (phase == "apply" && current.Status == models.RunStatusApplying))
		if !active {
			jsonapi.WriteCodedError(c, http.StatusForbidden, runnercontract.ErrorCodeJobTerminal, "Forbidden", "the original artifact claim has finished")
			return errors.New("artifact claim has finished")
		}
		ordered := current.ClaimRecovery || current.ArtifactSequence > 0 || fixedClient || supplied
		if ordered && !supplied {
			jsonapi.WriteErrorNoDetail(c, http.StatusBadRequest, "Artifact sequence required")
			return errors.New("artifact sequence required")
		}
		if ordered && sequence <= current.ArtifactSequence {
			c.Header(runnercontract.ArtifactSequenceHeader, strconv.FormatInt(current.ArtifactSequence, 10))
			jsonapi.WriteCodedError(c, http.StatusConflict, runnercontract.ErrorCodeArtifactReadSuperseded, "Conflict", "a later artifact request has been accepted")
			return errors.New("artifact read superseded")
		}
		if ordered {
			if err := tx.Model(&models.Run{}).Where("id = ?", current.ID).UpdateColumn("artifact_sequence", sequence).Error; err != nil {
				return err
			}
		}
		keys := apikey.NewService(repository.NewAPIKeyRepository(tx), nil, nil, nil)
		if err := keys.RevokeJobRegistryTokens(models.JobTypeTofuRun, current.ID); err != nil {
			return err
		}
		timeout := settings.EffectiveWorkspaceRunTimeout(&current.Workspace, settings.DeploymentRunTimeout(os.Getenv)).Value
		expiresAt := time.Now().Add(time.Duration(timeout)*time.Second + apikey.JobTokenGrace)
		var err error
		pool := current.AgentPoolID
		if pool == nil {
			pool = current.Workspace.AgentPoolID
		}
		if pool == nil {
			return errors.New("original artifact pool unavailable")
		}
		token, err = keys.CreateJobRegistryToken(current.Workspace.Project.OrganizationID, *pool, models.JobTypeTofuRun, current.ID, expiresAt)
		return err
	})
	if err != nil {
		if !c.Writer.Written() {
			jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		}
		return nil, false
	}
	return &runnercontract.RegistryBlock{Hosts: []runnercontract.RegistryHostToken{{Host: h.registryHost, Token: token}}}, true
}

// recordPlacement merges a launcher's or executor's placement report into the job's placement
// record (#933, D4, AC77). A failure is logged: the record is informational and reconciliation
// also lists the driver's own labelled placements.
func (h *RunnerAgentHandler) recordPlacement(kind models.JobType, jobID string, report *runnercontract.Placement) {
	if report == nil {
		return
	}
	var table any
	switch kind {
	case models.JobTypeTofuRun:
		table = &models.Run{}
	case models.JobTypeWorkItem:
		table = &models.WorkItem{}
	case models.JobTypeAnsibleJob:
		table = &models.AnsibleJob{}
	}
	// Only the placement columns are read, into a row of the job's own table.
	columns := []string{"id", "placement_driver", "placement_placement_id", "placement_image", "placement_image_digest", "placement_image_level", "placement_node"}
	var current models.JobPlacement
	switch kind {
	case models.JobTypeWorkItem:
		var item models.WorkItem
		if err := h.db.Select(columns).First(&item, "id = ?", jobID).Error; err != nil {
			return
		}
		current = item.Placement
	case models.JobTypeTofuRun:
		var run models.Run
		if err := h.db.Select(columns).First(&run, "id = ?", jobID).Error; err != nil {
			return
		}
		current = run.Placement
	case models.JobTypeAnsibleJob:
		var job models.AnsibleJob
		if err := h.db.Select(columns).First(&job, "id = ?", jobID).Error; err != nil {
			return
		}
		current = job.Placement
	}
	err := h.db.Model(table).Where("id = ?", jobID).Updates(placementColumns(current, report)).Error
	if err != nil {
		logger.Warnf("recording the placement of %s %s: %v", kind, jobID, err)
	}
}

// planFinishedStatus is the status a run takes when its plan job completes (TFE run states):
//
//   - a post_plan task stage runs first, whatever the plan holds; its continuation decides next;
//   - a plan-only run, and a plan-and-apply or destroy run whose plan has no changes, end at
//     planned_and_finished: there is nothing to apply, and the run is final;
//   - a plan with changes applies at once under auto-apply, or rests at planned for confirmation.
//
// runtask.ContinueAfterStagePassed makes the same decision for a run resuming after its post_plan
// stage, so the two cannot disagree on what a finished plan leads to.
func planFinishedStatus(op models.RunOperation, hasChanges, hasPostPlanStage, autoApply bool) models.RunStatus {
	switch {
	case hasPostPlanStage:
		return models.RunStatusPostPlanRunning
	case op == models.RunOperationPlanOnly || !hasChanges:
		return models.RunStatusPlannedAndFinished
	case autoApply:
		return models.RunStatusApplying
	default:
		return models.RunStatusPlanned
	}
}

// Deregister removes a runner
// POST /api/v2/runner/deregister
func (h *RunnerAgentHandler) Deregister(c *gin.Context) {
	var req struct {
		RunnerID string `json:"runner_id"`
	}
	_ = c.ShouldBindJSON(&req)

	// AUD-001: a runner may only deregister itself. Ignore the body runner_id as an
	// authority and act on the authenticated runner; also revoke its tokens so the
	// credential cannot outlive the runner.
	runner, ok := callingRunner(c)
	if !ok {
		writeRunnerForbidden(c, "launcher identity required")
		return
	}
	if req.RunnerID != "" && req.RunnerID != runner.ID.String() {
		writeRunnerForbidden(c, "runner_id does not match the authenticated launcher")
		return
	}
	runnerID := runner.ID
	_ = h.apiKeyService.DeleteAPIKeysForRunner(runnerID)

	// Simply mark the runner as offline rather than deleting
	// Admins can delete through the management API
	if err := h.runnerRepo.UpdateStatus(runnerID, models.RunnerStatusOffline); err != nil {
		if err == gorm.ErrRecordNotFound {
			jsonapi.WriteErrorNoDetail(c, http.StatusNotFound, "Launcher not found")
		} else {
			jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		}
		return
	}

	response.Status(c, http.StatusOK, "deregistered")
}

// JobArtifactsResponse is runnercontract.AnsibleArtifacts, the shared runner wire contract.
type JobArtifactsResponse = runnercontract.AnsibleArtifacts

// PlaybookSourceArtifact is runnercontract.PlaybookSource, the shared runner wire contract.
type PlaybookSourceArtifact = runnercontract.PlaybookSource

// VaultArtifact is runnercontract.Vault, the shared runner wire contract.
type VaultArtifact = runnercontract.Vault

// VCSArtifact is runnercontract.VCS, the shared runner wire contract.
type VCSArtifact = runnercontract.VCS

// CredentialArtifact is runnercontract.Credential, the shared runner wire contract.
type CredentialArtifact = runnercontract.Credential

// AnsibleJobConfig is runnercontract.AnsibleJobConfig, the shared runner wire contract.
type AnsibleJobConfig = runnercontract.AnsibleJobConfig

// runnerCapabilitiesHeader is how a runner announces, on the artifacts request, what it
// can do: a comma-separated list of capability tokens. It is sent per request rather
// than stored at registration, so it is true for the exact binary making the call.
const runnerCapabilitiesHeader = runnercontract.CapabilitiesHeader

// runnerCapabilityPlaybookSnapshot is announced by a runner that honours playbook_source:
// it downloads a cached playbook's snapshot instead of cloning. A runner that does not
// announce it can only clone, so it is sent the clone URL and nothing else changes for it.
const runnerCapabilityPlaybookSnapshot = runnercontract.CapabilityPlaybookSnapshot

// runnerCapabilities returns the set of capabilities the calling runner announced.
func runnerCapabilities(c *gin.Context) map[string]bool {
	announced := map[string]bool{}
	for token := range strings.SplitSeq(c.GetHeader(runnerCapabilitiesHeader), ",") {
		if token = strings.ToLower(strings.TrimSpace(token)); token != "" {
			announced[token] = true
		}
	}
	return announced
}

// isVCSBacked reports whether a playbook's files come from a repository. Only such
// playbooks have a source mode.
func isVCSBacked(playbook *models.AnsiblePlaybook) bool {
	return playbook.VCSConnectionID != nil && playbook.VCSRepository != ""
}

// playbookSourceMode resolves a VCS-backed playbook's source mode exactly as the
// platform runner does: an empty mode counts as cached.
func playbookSourceMode(playbook *models.AnsiblePlaybook) string {
	if playbook.SourceMode == models.PlaybookSourceModeFresh {
		return models.PlaybookSourceModeFresh
	}
	return models.PlaybookSourceModeCached
}

// playbookVCSArtifact builds the clone instructions for a VCS-backed playbook: a fresh
// token from the provider registry embedded in the clone URL. It returns nil when the
// connection or a clone URL cannot be resolved.
//
// The connection is loaded within the playbook's organization. A playbook row that names another
// organization's connection resolves to nothing, so a self-hosted runner is handed no clone URL
// and no token for it.
func (h *RunnerAgentHandler) playbookVCSArtifact(ctx context.Context, playbook *models.AnsiblePlaybook) (*VCSArtifact, error) {
	if playbook.VCSConnectionID == nil {
		return nil, nil //nolint:nilnil // no usable legacy clone source
	}
	scope := repository.NewOrganizationScope(h.db).WithContext(ctx)
	vcsConn, err := ansible.PlaybookVCSConnection(scope, playbook.ProjectID, *playbook.VCSConnectionID)
	if err != nil {
		if !errors.Is(err, ansible.ErrInvalidInput) {
			return nil, fmt.Errorf("loading the playbook VCS connection: %w", err)
		}
		return nil, nil //nolint:nilnil // no usable legacy clone source
	}
	if h.vcsRegistry == nil {
		return nil, nil //nolint:nilnil // no usable legacy clone source
	}
	provider, err := h.vcsRegistry.GetProvider(vcsConn)
	if err != nil {
		return nil, nil //nolint:nilnil // no usable legacy clone source
	}
	accessToken, err := provider.GetFreshToken(ctx, vcsConn)
	if err != nil {
		return nil, fmt.Errorf("refreshing the playbook VCS token: %w", err)
	}
	repoURL := provider.BuildCloneURL(vcsConn, accessToken, playbook.VCSRepository)
	if repoURL == "" {
		return nil, nil //nolint:nilnil // no usable legacy clone source
	}
	branch := playbook.VCSBranch
	if branch == "" {
		branch = "main"
	}
	return &VCSArtifact{RepoURL: repoURL, Branch: branch, Repository: playbook.VCSRepository}, nil
}

// GetPlaybookSnapshot streams the cached snapshot of a job's playbook to the self-hosted
// runner executing it. A runner reaches nothing but this API, so the object is proxied
// from storage rather than handed out as a presigned storage URL.
// GET /api/v2/runner/jobs/:id/playbook-snapshot
func (h *RunnerAgentHandler) GetPlaybookSnapshot(c *gin.Context) {
	jobID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		jsonapi.WriteErrorNoDetail(c, http.StatusBadRequest, "Invalid job ID")
		return
	}
	if h.ansibleJobRepo == nil || h.playbookRepo == nil || h.storageClient == nil {
		jsonapi.WriteErrorNoDetail(c, http.StatusNotImplemented, "Playbook snapshots not configured")
		return
	}
	scoped := *h
	scoped.db = h.db.WithContext(c.Request.Context())
	h = &scoped

	job, err := h.ansibleJobRepo.WithContext(c.Request.Context()).GetByID(jobID)
	if err != nil {
		writeRunnerJobReadError(c, err)
		return
	}
	// Same binding as the artifacts endpoint (AUD-001): a runner in the job's
	// organization and pool, and once the job is claimed only the assignee.
	if !h.authorizeRunnerForAnsibleJob(c, job, false) {
		return
	}
	if refuseFinishedAnsibleJob(c, job) {
		return
	}

	if job.PlaybookID == nil {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "this job has no playbook")
		return
	}
	playbook, err := h.playbookRepo.WithContext(c.Request.Context()).GetByID(*job.PlaybookID)
	if err != nil {
		switch {
		case errors.Is(err, gorm.ErrRecordNotFound) && job.PlaybookSnapshotUploadID != nil:
			writeAssignedSnapshotError(c, errAssignedSnapshotUnavailable)
		case errors.Is(err, gorm.ErrRecordNotFound):
			jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "playbook not found")
		default:
			jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		}
		return
	}
	if !isVCSBacked(playbook) && job.PlaybookSnapshotUploadID == nil {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "the playbook has no VCS repository, so it has no snapshot")
		return
	}
	ctx := c.Request.Context()
	upload, err := h.assignedPlaybookSnapshot(ctx, job, playbook)
	if err != nil {
		writeAssignedSnapshotError(c, err)
		return
	}
	match := c.Request.Header.Values("If-Match")
	if runnerCapabilities(c)[runnercontract.CapabilityVerifiedPlaybookSnapshot] || len(match) != 0 {
		if len(match) != 1 || match[0] != assignedSnapshotValidator(upload.ID) {
			writeAssignedSnapshotError(c, errAssignedSnapshotUnavailable)
			return
		}
	}
	if !tryPlaybookSnapshotSlot() {
		writePlaybookSnapshotBusy(c)
		return
	}
	defer releasePlaybookSnapshotSlot()
	data, err := h.readAssignedPlaybookSnapshot(ctx, job, upload)
	if err != nil {
		writeAssignedSnapshotError(c, err)
		return
	}
	c.Header("Content-Length", strconv.Itoa(len(data)))
	c.Data(http.StatusOK, "application/gzip", data)
}

// GetJobStatus returns the current run/job status so the agent can poll for cancellation.
// GET /api/v2/runner/jobs/:id/status
func (h *RunnerAgentHandler) GetJobStatus(c *gin.Context) {
	jobIDStr := c.Param("id")
	if jobIDStr == "" {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "job id required")
		return
	}
	if isWorkItem(jobIDStr) {
		h.workItemStatus(c, jobIDStr)
		return
	}
	// Terraform jobs use run ID (run-xxx)
	if strings.HasPrefix(jobIDStr, "run-") {
		// Select the fields the authorization check needs (AUD-001) in addition to status.
		var run models.Run
		if err := h.db.Select("id", "status", "workspace_id", "agent_pool_id", "runner_id", "attempt").First(&run, "id = ?", jobIDStr).Error; err != nil {
			writeRunnerJobReadError(c, err)
			return
		}
		if !h.authorizeRunnerForRun(c, &run, false) {
			return
		}
		response.Status(c, http.StatusOK, string(run.Status))
		return
	}
	// Ansible jobs use UUID
	if h.ansibleJobRepo == nil {
		jsonapi.WriteErrorNoDetail(c, http.StatusNotFound, "Not Found")
		return
	}
	jobID, parseErr := uuid.Parse(jobIDStr)
	if parseErr != nil {
		jsonapi.WriteErrorNoDetail(c, http.StatusBadRequest, "Invalid job ID")
		return
	}
	job, getErr := h.ansibleJobRepo.GetByID(jobID)
	if getErr != nil {
		writeRunnerJobReadError(c, getErr)
		return
	}
	if !h.authorizeRunnerForAnsibleJob(c, job, false) {
		return
	}
	response.Status(c, http.StatusOK, string(job.Status))
}

// ansibleJobCredentialIDs returns the credentials a job's artifacts are built from. When it
// cannot, it answers the request and reports false.
//
// It reads the set through ansible.JobCredentialIDs, the point-of-use check the platform runner
// makes too: a job whose stored set names a credential outside the job's organization gets none
// of them. Such a job is failed here and the runner is told 409 with the same sentence a missing
// credential gets, so that it neither receives another organization's secret nor runs the job
// without a credential the job names. A lookup that fails for any other reason answers 500 and
// leaves the job as it is.
func (h *RunnerAgentHandler) ansibleJobCredentialIDs(c *gin.Context, job *models.AnsibleJob) ([]uuid.UUID, bool) {
	if h.credentialRepo == nil {
		// No credential is ever decrypted without the repository, so there is no set to read.
		return nil, true
	}
	credIDs, err := ansible.JobCredentialIDs(c.Request.Context(), h.ansibleJobRepo, job.ID)
	if err == nil {
		return credIDs, true
	}
	if !errors.Is(err, ansible.ErrInvalidInput) {
		logger.Errorf("Reading the credentials of job %s: %v", job.ID, err)
		jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		return nil, false
	}
	message := "reading the job's credentials: " + err.Error()
	logger.Warnf("Job %s is not handed to runner: %s", job.ID, message)
	job.Status = models.AnsibleJobStatusFailed
	job.ErrorMessage = message
	if updateErr := h.ansibleJobRepo.UpdateColumns(job, "status", "error_message"); updateErr != nil {
		logger.Warnf("Failed to mark job %s failed: %v", job.ID, updateErr)
	}
	jsonapi.WriteError(c, http.StatusConflict, "Conflict", message)
	return nil, false
}

// GetJobArtifacts returns all artifacts needed to execute a job
// GET /api/v2/runner/jobs/:id/artifacts
func (h *RunnerAgentHandler) GetJobArtifacts(c *gin.Context) {
	h = h.artifactReadContext(c.Request.Context())
	jobIDStr := c.Param("id")

	if isWorkItem(jobIDStr) {
		h.getWorkItemArtifacts(c, jobIDStr)
		return
	}

	// Determine if this is a Terraform run or Ansible job
	if strings.HasPrefix(jobIDStr, "run-") {
		h.getTerraformRunArtifacts(c, jobIDStr)
		return
	}

	jobID, err := uuid.Parse(jobIDStr)
	if err != nil {
		jsonapi.WriteErrorNoDetail(c, http.StatusBadRequest, "Invalid job ID")
		return
	}

	// Check if repos are available
	if h.ansibleJobRepo == nil {
		jsonapi.WriteErrorNoDetail(c, http.StatusNotImplemented, "Job artifacts not configured")
		return
	}

	// Get the ansible job
	job, err := h.ansibleJobRepo.GetByID(jobID)
	if err != nil {
		writeRunnerJobReadError(c, err)
		return
	}

	// AUD-001: artifacts contain decrypted credentials, vault passwords, and minted
	// OIDC tokens. Only a runner in the job's org+pool (and, once claimed, the
	// assignee) may fetch them. This is the crown-jewel disclosure the finding names.
	if !h.authorizeRunnerForAnsibleJob(c, job, false) {
		return
	}
	if refuseFinishedAnsibleJob(c, job) {
		return
	}

	// A runner that announces playbook-snapshot gets the playbook-source contract:
	// project_id, playbook_source, and a clone URL only when this run clones. One that
	// does not (a runner built before the capability existed) can only clone, so it gets
	// the response it has always got, with no new fields and no side effects.
	capabilities := runnerCapabilities(c)
	verifiedSnapshot := capabilities[runnercontract.CapabilityVerifiedPlaybookSnapshot]
	snapshotCapable := verifiedSnapshot || capabilities[runnerCapabilityPlaybookSnapshot]

	response := JobArtifactsResponse{
		JobID:           job.ID.String(),
		JobType:         "ansible_job",
		ContractVersion: runnercontract.Version,
		Mirror:          h.mirror,
		JobConfig: &AnsibleJobConfig{
			Limit:          job.Limit,
			Tags:           job.Tags,
			SkipTags:       job.SkipTags,
			Verbosity:      job.Verbosity,
			Forks:          job.Forks,
			BecomeEnabled:  job.BecomeEnabled,
			DiffMode:       job.DiffMode,
			TimeoutSeconds: job.TimeoutSeconds,
		},
	}
	if snapshotCapable {
		response.ProjectID = job.ProjectID.String()
	}

	// Ad hoc jobs have no playbook: ship the generated transient playbook as
	// content; the agent writes it into the job workspace and runs it.
	if job.JobType == models.AnsibleJobTypeAdHoc {
		if content, adhocErr := ansible.BuildAdHocPlaybook(job.Module, job.ModuleArgs); adhocErr != nil {
			logger.Warnf("Failed to build ad hoc playbook for job %s: %v", job.ID, adhocErr)
		} else {
			response.PlaybookContent = string(content)
			response.PlaybookPath = "adhoc.yml"
		}
	}

	// Resolve the job's assigned capture before handing out any execution artifacts.
	if h.playbookRepo != nil && job.PlaybookID != nil {
		playbook, err := h.playbookRepo.GetByID(*job.PlaybookID)
		if errors.Is(err, gorm.ErrRecordNotFound) && job.PlaybookSnapshotUploadID != nil {
			writeAssignedSnapshotError(c, errAssignedSnapshotUnavailable)
			return
		}
		if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
			return
		}
		if err == nil {
			response.PlaybookPath = playbook.PlaybookPath
			_, executorWithJobToken := callingJob(c)
			var sourceErr error
			switch {
			case !isVCSBacked(playbook) && job.PlaybookSnapshotUploadID == nil:
			case job.PlaybookSnapshotUploadID != nil || executorWithJobToken ||
				verifiedSnapshot ||
				(snapshotCapable && playbookSourceMode(playbook) == models.PlaybookSourceModeCached):
				if job.PlaybookSnapshotUploadID != nil && !snapshotCapable && !executorWithJobToken {
					writeAssignedSnapshotError(c, errAssignedSnapshotUnavailable)
					return
				}
				upload, err := h.assignedPlaybookSnapshot(c.Request.Context(), job, playbook)
				if err != nil {
					writeAssignedSnapshotError(c, err)
					return
				}
				response.PlaybookPath = job.PlaybookSnapshotPath
				response.PlaybookSource = &PlaybookSourceArtifact{
					Mode: job.PlaybookSnapshotMode, Commit: upload.Commit, CapturedAt: upload.StoredAt, SizeBytes: upload.SizeBytes,
				}
				if verifiedSnapshot {
					response.PlaybookSource.SHA256 = upload.SHA256
					response.PlaybookSource.Validator = assignedSnapshotValidator(upload.ID)
				}
			default:
				// Pre-upgrade jobs that explicitly use the runner-token clone path.
				response.VCS, sourceErr = h.playbookVCSArtifact(c.Request.Context(), playbook)
				if snapshotCapable {
					response.PlaybookSource = &PlaybookSourceArtifact{Mode: models.PlaybookSourceModeFresh}
				}
			}
			if sourceErr != nil {
				jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
				return
			}
		}
	}

	// Resolve every credential attached to the job: the template's
	// multi-credential set plus the job's own credential (legacy single
	// machine credential; skipped when already in the set).
	//
	// The job's own credential set, snapshotted at launch - not the template's live set, so an
	// edit to the template cannot change what an already-dispatched job authenticates with.
	credIDs, ok := h.ansibleJobCredentialIDs(c, job)
	if !ok {
		return
	}
	var decryptedPassword string
	if h.credentialRepo != nil && h.cryptoService != nil {
		decrypt := func(v string) string {
			if v == "" {
				return ""
			}
			if d, derr := h.cryptoService.Decrypt(v); derr == nil {
				return d
			}
			return ""
		}
		if len(credIDs) > 0 && response.EnvironmentVars == nil {
			response.EnvironmentVars = map[string]string{}
		}
		for _, id := range credIDs {
			cred, err := h.credentialRepo.GetByID(id)
			if err != nil {
				jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
				return
			}
			switch cred.Type {
			case models.CredentialTypeSSH, models.CredentialTypeMachineSSH:
				credArtifact := &CredentialArtifact{Type: string(cred.Type), Username: cred.Username}
				credArtifact.Password = decrypt(cred.Password)
				if cred.Type == models.CredentialTypeMachineSSH && credArtifact.Password != "" {
					decryptedPassword = credArtifact.Password
				}
				credArtifact.SSHKey = decrypt(cred.SSHPrivateKey)
				credArtifact.BecomePassword = decrypt(cred.BecomePassword)
				response.Credential = credArtifact
			case models.CredentialTypeVault:
				if pw := decrypt(cred.VaultPassword); pw != "" {
					response.Vaults = append(response.Vaults, VaultArtifact{Password: pw, VaultID: cred.VaultID})
				}
			case models.CredentialTypeAWSAccessKey:
				if v := decrypt(cred.AWSAccessKeyID); v != "" {
					response.EnvironmentVars["AWS_ACCESS_KEY_ID"] = v
				}
				if v := decrypt(cred.AWSSecretAccessKey); v != "" {
					response.EnvironmentVars["AWS_SECRET_ACCESS_KEY"] = v
				}
			case models.CredentialTypeAzure:
				if cred.AzureTenantID != "" {
					response.EnvironmentVars["AZURE_TENANT_ID"] = cred.AzureTenantID
					response.EnvironmentVars["AZURE_TENANT"] = cred.AzureTenantID
				}
				if cred.AzureClientID != "" {
					response.EnvironmentVars["AZURE_CLIENT_ID"] = cred.AzureClientID
				}
				if v := decrypt(cred.AzureClientSecret); v != "" {
					response.EnvironmentVars["AZURE_CLIENT_SECRET"] = v
					response.EnvironmentVars["AZURE_SECRET"] = v
				}
			case models.CredentialTypeGCP:
				if v := decrypt(cred.GCPServiceAccount); v != "" {
					response.GCPServiceAccount = v
				}
			case models.CredentialTypeVMware:
				if cred.Username != "" {
					response.EnvironmentVars["VMWARE_USER"] = cred.Username
				}
				if v := decrypt(cred.Password); v != "" {
					response.EnvironmentVars["VMWARE_PASSWORD"] = v
				}
			case models.CredentialTypeRegistry:
				// Never served to a job: only the launcher pulls a run image with it (#933, D6).
			}
		}
	}

	// Generate inventory content using the inventory service (same approach as platform-managed runner)
	if h.inventoryService != nil {
		inventoryJSON, err := h.inventoryService.GenerateInventoryJSON(job.InventoryID)
		if err != nil {
			jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
			return
		}
		// Job slicing: keep only this slice's modulo-partition of the hosts.
		if err == nil && job.SliceCount > 1 {
			inventoryJSON, err = ansible.FilterInventoryJSONForSlice(inventoryJSON, job.SliceNumber, job.SliceCount)
			if err != nil {
				// Fail the job rather than shipping no inventory (which would run
				// against zero hosts and report success) - mirrors the platform
				// runner, which hard-fails the same slice error.
				logger.Warnf("Failed to slice inventory for job %s: %v", job.ID, err)
				job.Status = models.AnsibleJobStatusFailed
				job.ErrorMessage = fmt.Sprintf("failed to slice inventory: %v", err)
				if updateErr := h.ansibleJobRepo.UpdateColumns(job, "status", "error_message"); updateErr != nil {
					logger.Warnf("Failed to mark sliced job %s failed: %v", job.ID, updateErr)
				}
				jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "failed to slice inventory: "+err.Error())
				return
			}
		}
		if err == nil {
			// If we have a Machine SSH credential with a password, inject it into the inventory
			if decryptedPassword != "" {
				if injected, err := injectPasswordIntoInventory(inventoryJSON, decryptedPassword); err == nil {
					inventoryJSON = injected
				}
			}
			// If we have a credential with a username, inject ansible_user so the runner uses it
			// (avoids falling back to the runner process user e.g. "iac" in Docker)
			if h.credentialRepo != nil {
				for _, id := range credIDs {
					cred, err := h.credentialRepo.GetByID(id)
					if err != nil {
						jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
						return
					}
					if cred.Username == "" {
						continue
					}
					if cred.Type != models.CredentialTypeSSH && cred.Type != models.CredentialTypeMachineSSH {
						continue
					}
					if injected, err := injectUserIntoInventory(inventoryJSON, cred.Username); err == nil {
						inventoryJSON = injected
					}
					break
				}
			}
			response.InventoryContent = inventoryJSON
		}
	}

	// Get ansible.cfg for the job's project
	if h.ansibleConfigRepo != nil {
		// Get project to find workspace
		var project models.Project
		if err := h.db.First(&project, "id = ?", job.ProjectID).Error; err != nil {
			jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
			return
		}
		// Try project config first, then org (no workspace for ansible jobs)
		// GetForWorkspace signature: (workspaceID string, projectID, orgID uuid.UUID)
		config, err := h.ansibleConfigRepo.GetForWorkspace("", job.ProjectID, project.OrganizationID)
		if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
			return
		}
		if err == nil && config != nil {
			response.AnsibleCfg = config.ConfigContent
		}
	}

	// Get extra vars (already in job)
	if job.ExtraVars != nil {
		response.ExtraVars = job.ExtraVars
	}

	// Workload identity: the platform-minted per-run tokens for Azure, AWS, GCP and Vault, the same
	// four an OpenTofu run's artifacts carry (#933, D2, D8, AC37).
	// A job never starts without an identity its organization configured.
	environment, err := h.ansibleWorkloadIdentityEnv(job, response.EnvironmentVars)
	if err != nil {
		refuseWithoutIdentity(c, jobIDStr, err)
		return
	}
	response.EnvironmentVars = environment
	// A runner that cannot start from a snapshot predates the cache too, and gets neither.
	if org, _, err := h.ansibleJobOrgAndPool(job); err == nil && snapshotCapable {
		response.Cache = h.ansibleCacheDescriptor(c.Request.Context(), org, job)
	}

	c.JSON(http.StatusOK, response)
}

// runConfigurationVersion loads the configuration version a run names, within the run's
// workspace (ConfigurationVersionRepository.GetByIDForWorkspace). A run row stored before the API
// checked may name one uploaded to another workspace; that one is gorm.ErrRecordNotFound here,
// exactly like one that does not exist. The run must name a configuration version.
func (h *RunnerAgentHandler) runConfigurationVersion(run *models.Run) (*models.ConfigurationVersion, error) {
	return repository.NewConfigurationVersionRepository(h.db).GetByIDForWorkspace(*run.ConfigurationVersionID, run.WorkspaceID)
}

// getTerraformRunArtifacts returns artifacts needed for a self-hosted Terraform runner
// to execute a run: configuration tarball, variables, environment variables, and workspace metadata.
func (h *RunnerAgentHandler) getTerraformRunArtifacts(c *gin.Context, runID string) {
	scoped := *h
	scoped.db = h.db.WithContext(c.Request.Context())
	h = &scoped
	var run models.Run
	if err := h.db.Preload("Workspace.Project.Organization").First(&run, "id = ?", runID).Error; err != nil {
		writeRunnerJobReadError(c, err)
		return
	}

	// AUD-001: this response embeds decrypted cloud credentials, a fresh VCS clone
	// token, minted OIDC workload-identity tokens, all variables (incl. sensitive),
	// and the config tarball. Only a runner in the run's org+pool may fetch it.
	if !h.authorizeRunnerForRun(c, &run, false) {
		return
	}
	// A finished run has nothing left to prepare, so its artifacts are served to no token
	// (#933, D1: the finished-job refusal of both engines).
	if runFinished(&run) {
		jsonapi.WriteCodedError(c, http.StatusForbidden, runnercontract.ErrorCodeJobTerminal, "Forbidden", "the run has finished; its artifacts are no longer served")
		return
	}

	// The OpenTofu version resolves by the shared level rule: workspace, project, organization,
	// then the installation default (#1069, D2). It is fixed here, when the executor fetches the
	// run's artifacts.
	tfVersion := settings.EffectiveTofuVersion(&run.Workspace, repository.InstallationTofuVersion(h.db)).Value

	plan, err := h.planDescriptor(c.Request.Context(), &run)
	if err != nil {
		jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	response := AgentJobArtifacts{
		JobID:            run.ID,
		JobType:          "tofu_run",
		ContractVersion:  runnercontract.Version,
		TofuVersion:      tfVersion,
		WorkingDirectory: run.Workspace.WorkingDirectory,
		Plan:             plan,
		Mirror:           h.mirror,
	}

	// A run whose configuration is still being captured is refused rather than handed no
	// configuration (#938). A new replica never offers such a run; an older one during a rolling
	// deploy might, and the runner then retries or the run ends with the reason.
	if run.ConfigurationVersionID != nil {
		cv, err := h.runConfigurationVersion(&run)
		if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
			return
		}
		if err == nil && cv.Status != models.ConfigurationVersionStatusUploaded {
			jsonapi.WriteError(c, http.StatusConflict, "Conflict", "the run's configuration is not uploaded yet")
			return
		}
	}

	// Get configuration tarball from storage if configuration version exists. The version is
	// looked up within the run's workspace first: a run row that names a configuration version
	// uploaded to another workspace finds none, and the runner is handed none of its code.
	var tarball []byte
	if run.ConfigurationVersionID != nil {
		if h.storageClient == nil {
			jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
			return
		}
		if configVersion, cvErr := h.runConfigurationVersion(&run); cvErr == nil {
			storageKey := configVersion.TarballKey()
			ctx := c.Request.Context()
			data, err := h.storageClient.Get(ctx, storageKey)
			if err != nil {
				jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
				return
			}
			tarball = data
			if len(data) > h.inlineLimit() && runnerCan(c, runnercontract.CapabilityBlob) {
				response.ConfigTarballBlob = blobRef(run.ID, blobConfigTarball, data)
			} else {
				response.ConfigTarball = base64.StdEncoding.EncodeToString(data)
			}
		} else if !errors.Is(cvErr, gorm.ErrRecordNotFound) {
			jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
			return
		}
	}
	response.Cache = h.runCacheDescriptor(run.Workspace.Project.OrganizationID, &run, tfVersion, tarball)

	// Get VCS info from workspace for cloning (fallback when no config version). The connection
	// is loaded within the workspace's organization: a workspace row that names another
	// organization's connection finds none, and the runner is handed no clone URL for it.
	//
	// An executor holding a job token is never handed a clone URL (#933, decision 18, AC68): its run
	// starts from the configuration version a configuration_snapshot work item captured. Only an
	// old agent, authenticating with its runner token, is served one, for the deprecation window.
	_, executorWithJobToken := callingJob(c)
	if !executorWithJobToken && run.ConfigurationVersionID == nil && run.Workspace.VCSConnectionID != nil && run.Workspace.VCSRepository != "" {
		scope := repository.NewOrganizationScope(h.db).WithContext(c.Request.Context())
		if vcsConn, err := scope.VCSConnectionForProject(*run.Workspace.VCSConnectionID, run.Workspace.ProjectID); err == nil {
			ctx := c.Request.Context()
			var repoURL string

			// Use provider registry for token refresh and clone URL building
			if h.vcsRegistry != nil {
				provider, provErr := h.vcsRegistry.GetProvider(vcsConn)
				if provErr == nil {
					freshToken, tokenErr := provider.GetFreshToken(ctx, vcsConn)
					if tokenErr != nil {
						logger.Warnf("Failed to get fresh token for VCS connection %s: %v", vcsConn.ID, tokenErr)
					}
					repoURL = provider.BuildCloneURL(vcsConn, freshToken, run.Workspace.VCSRepository)
				} else {
					logger.Warnf("Failed to get VCS provider for connection %s: %v", vcsConn.ID, provErr)
				}
			} else {
				logger.Warnf("VCS registry not available for run %s", runID)
			}

			if repoURL != "" {
				// Log whether token auth is being used (without leaking the token)
				hasAuth := strings.Contains(repoURL, "@")
				logger.Infof("VCS clone URL for run %s: hasAuth=%v, repo=%s, branch=%s, provider=%s",
					runID, hasAuth, run.Workspace.VCSRepository, run.Workspace.VCSBranch, vcsConn.Provider)
				response.VCS = &AgentJobVCS{
					RepoURL:    repoURL,
					Branch:     run.Workspace.VCSBranch,
					Repository: run.Workspace.VCSRepository,
				}
			} else {
				logger.Warnf("VCS clone URL is empty for run %s: provider=%s",
					runID, vcsConn.Provider)
			}
		} else if !errors.Is(err, gorm.ErrRecordNotFound) {
			jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
			return
		}
	}

	// Get Terraform variables (category == "terraform")
	if h.variableService != nil {
		ctx := c.Request.Context()
		varsMeta, err := h.variableService.GetVariablesWithMetaForRun(ctx, run.WorkspaceID)
		if err != nil {
			jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
			return
		}
		if len(varsMeta) > 0 {
			vars := make(map[string]string, len(varsMeta))
			var hclKeys []string
			for k, v := range varsMeta {
				vars[k] = v.Value
				if v.HCL {
					hclKeys = append(hclKeys, k)
				}
			}
			response.Variables = vars
			// AUD-022: tell the self-hosted agent which variables are HCL-typed so it writes them
			// unquoted in tfvars. Sent as a separate optional field so older agents (which ignore
			// unknown fields) keep working with the plain string map.
			if len(hclKeys) > 0 {
				response.VariablesHCL = hclKeys
			}
		}
		// Get environment variables (category == "env")
		envVars, err := h.variableService.GetEnvironmentVariablesForRun(ctx, run.WorkspaceID)
		if err != nil {
			jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
			return
		}
		response.EnvironmentVars = envVars
	}

	// Workload identity: the platform-minted per-run tokens for Azure, AWS, GCP and Vault (#933, D8).
	// A run never starts without an identity its organization configured.
	environment, err := h.tofuWorkloadIdentityEnv(&run, response.EnvironmentVars)
	if err != nil {
		refuseWithoutIdentity(c, runID, err)
		return
	}
	response.EnvironmentVars = environment

	// TFE-compatible: Include latest state so the self-hosted runner can restore it.
	// Self-hosted runners use fresh temp dirs per job, so they need the current state
	// to know about existing resources and avoid re-creating them.
	if h.stateService != nil {
		// Find the latest state version for this workspace
		var latestState models.StateVersion
		if err := h.db.Where("workspace_id = ?", run.WorkspaceID).
			Order("version DESC").First(&latestState).Error; err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
			return
		} else if err == nil {
			// Read state from object storage (the authoritative copy), decrypting at rest
			// state to plaintext before base64-encoding it into the job payload.
			ctx := c.Request.Context()
			stateData, err := h.stateService.GetStateObject(ctx, run.WorkspaceID, latestState.Version)
			if err != nil || len(stateData) == 0 {
				jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
				return
			}
			if len(stateData) > h.inlineLimit() && runnerCan(c, runnercontract.CapabilityBlob) {
				response.StateBlob = blobRef(run.ID, blobState, stateData)
			} else {
				response.StateJSON = base64.StdEncoding.EncodeToString(stateData)
			}
			logger.Infof("Including state version %d (%d bytes) in artifacts for run %s", latestState.Version, len(stateData), runID)
		}
	}

	registry, ok := h.jobRegistryBlock(c, &run)
	if !ok {
		return
	}
	response.Registry = registry
	c.JSON(http.StatusOK, response)
}

// projectNameByID returns a project's name for display on offered jobs, or "" if
// it can't be resolved (best-effort - the agent only uses it for labelling).
func (h *RunnerAgentHandler) projectNameByID(projectID uuid.UUID) string {
	var project models.Project
	if err := h.db.Select("name").First(&project, "id = ?", projectID).Error; err != nil {
		return ""
	}
	return project.Name
}

// findPendingJobsForRunner finds pending jobs that can be executed by the given runner.
// Ansible jobs are reserved for the runner here (runner_id stamped) so concurrent
// pollers get disjoint work; the agent then claims each via JobStart.
// Supports both Ansible jobs and Terraform runs depending on runner type.
func (h *RunnerAgentHandler) findPendingJobsForRunner(ctx context.Context, runner *models.Runner) ([]PendingJob, error) {
	scoped := *h
	scoped.db = h.db.WithContext(ctx)
	if h.workItems != nil {
		scoped.workItems = ansible.NewWorkItemRuntime(scoped.db, nil, nil)
	}
	pending, err := scoped.reservePendingJobsForRunner(runner)
	if err != nil {
		return nil, err
	}
	offers := make([]PendingJob, 0, len(pending))
	repo := repository.NewRunnerRepository(scoped.db)
	for _, job := range pending {
		offer, eligible, err := repo.PrepareOffer(ctx, runner.ID, job)
		if err != nil {
			return nil, err
		}
		if eligible {
			offers = append(offers, offer)
		}
	}
	return offers, nil
}

func (h *RunnerAgentHandler) reservePendingJobsForRunner(runner *models.Runner) ([]PendingJob, error) {
	if runner.IsHosted() {
		return h.hostedOffers(runner)
	}
	pendingJobs := []PendingJob{}

	// Capacity-aware, distribution-safe offering. `maxJobs` bounds how much work a
	// runner takes; the agent runs serially so it is usually 1.
	maxJobs := runner.MaxConcurrentJobs
	if maxJobs <= 0 {
		maxJobs = 1
	}

	// Ansible jobs: each polling runner ATOMICALLY reserves its own pending jobs by
	// stamping runner_id under FOR UPDATE SKIP LOCKED. Without this, simultaneous
	// pollers all get offered the same top job and contend on the claim - which
	// funnels every sibling slice onto whichever runner wins the race (no
	// distribution). SKIP LOCKED makes concurrent pollers grab DISJOINT rows, so N
	// slices spread across N idle agents. Held jobs (queued_at NULL, waiting on the
	// template concurrency gate) are not offered. A reservation is released if the
	// runner goes offline before starting (see ReleaseStaleAnsibleReservations in
	// core/repository/runner.go, driven by services/runner/monitor.go).
	if runner.CanExecuteAnsible() && h.ansibleJobRepo != nil {
		// Re-offer anything this runner already holds a reservation on but never
		// started. The reserve query below only ever RETURNS rows it newly stamped
		// (it matches `runner_id IS NULL`), so an offer the agent dropped - the
		// response was lost, or it arrived while the agent was mid-job and was
		// discarded - is never offered again. ReleaseStaleAnsibleReservations only
		// frees reservations held by OFFLINE runners, so an online agent strands that
		// job permanently AND wedges its own capacity, since `outstanding` below still
		// counts it. Proven on the kind harness: with 2 agents and 3 slices, one slice
		// sat `pending` holding an online runner's id indefinitely while the spec timed
		// out. Re-offering makes it self-heal on the next poll; a job the agent is
		// actually executing is `running`, not `pending`, so this cannot steal live
		// work, and a duplicate offer is rejected by the atomic claim in JobStart.
		var held []models.AnsibleJob
		if err := h.db.
			Where("runner_id = ? AND status = ? AND queued_at IS NOT NULL",
				runner.ID, models.AnsibleJobStatusPending).
			Order("created_at ASC").
			Limit(maxJobs).
			Find(&held).Error; err != nil {
			return pendingJobs, err
		}
		for i := range held {
			pendingJobs = append(pendingJobs, PendingJob{
				JobID:         held[i].ID.String(),
				JobType:       "ansible_job",
				WorkspaceName: h.projectNameByID(held[i].ProjectID),
			})
		}

		// Outstanding = jobs this runner has reserved or is running but hasn't
		// finished. Caps reservations to the runner's free capacity.
		var outstanding int64
		if err := h.db.Model(&models.AnsibleJob{}).
			Where("runner_id = ? AND status IN ?", runner.ID,
				[]models.AnsibleJobStatus{models.AnsibleJobStatusPending, models.AnsibleJobStatusRunning}).
			Count(&outstanding).Error; err != nil {
			return pendingJobs, err
		}
		if capacity := maxJobs - int(outstanding); capacity > 0 {
			// The picking query MUST be a CTE, not a subquery of `WHERE id IN (…)`.
			// A locking subquery is not guaranteed to be evaluated once: Postgres
			// may re-run it while the UPDATE walks candidate rows, and each run
			// returns a fresh unlocked row, so `LIMIT n` stops bounding anything -
			// a runner with capacity 1 reserved every pending job in its pool,
			// which is the opposite of the distribution this code exists for. A
			// CTE is evaluated exactly once, so the limit holds.
			var reserved []models.AnsibleJob
			if err := h.db.Raw(`
				WITH picked AS (
					SELECT id FROM ansible_jobs
					WHERE status = ? AND agent_pool_id = ? AND queued_at IS NOT NULL AND runner_id IS NULL
					ORDER BY created_at ASC
					LIMIT ?
					FOR UPDATE SKIP LOCKED
				)
				UPDATE ansible_jobs SET runner_id = ?, updated_at = now()
				FROM picked
				WHERE ansible_jobs.id = picked.id
				RETURNING ansible_jobs.*`,
				models.AnsibleJobStatusPending, runner.PoolID(), capacity, runner.ID).
				Scan(&reserved).Error; err != nil {
				return pendingJobs, err
			}
			for i := range reserved {
				pendingJobs = append(pendingJobs, PendingJob{
					JobID:         reserved[i].ID.String(),
					JobType:       "ansible_job",
					WorkspaceName: h.projectNameByID(reserved[i].ProjectID),
				})
			}
		}
	}

	// OpenTofu runs are reserved the way Ansible jobs are (#933, D2, AC9): a runner's own
	// unstarted reservations are offered again first, then new runs are reserved up to its free
	// capacity under FOR UPDATE SKIP LOCKED, so concurrent pollers take disjoint runs and no runner
	// is handed more than it can run. The capacity is shared with the Ansible jobs above.
	if runner.CanExecuteTerraform() {
		runRepo := repository.NewRunRepository(h.db)
		held, err := runRepo.HeldForRunner(runner.ID, maxJobs)
		if err != nil {
			return pendingJobs, err
		}
		busy, err := h.outstandingFor(runner)
		if err != nil {
			return pendingJobs, err
		}
		runs := held
		if capacity := maxJobs - busy; capacity > 0 {
			reserved, err := runRepo.ReserveForRunner(runner.ID, runner.PoolID(), capacity)
			if err != nil {
				return pendingJobs, err
			}
			runs = append(runs, reserved...)
		}
		for _, run := range runs {
			pendingJobs = append(pendingJobs, h.runOffer(&run))
		}
	}

	// Work items (#933, D2) are reserved the same way, from the same capacity, for a runner that
	// declared it runs them; only an Ansible-capable one is offered the inventory kinds.
	if h.offersWorkItems(runner) {
		items, err := h.workItemOffersFor(runner, maxJobs)
		if err != nil {
			return pendingJobs, err
		}
		pendingJobs = append(pendingJobs, items...)
	}

	return pendingJobs, nil
}

// workItemOffersFor is a customer runner's work item offers: its own unstarted reservations, then
// new ones up to the capacity its runs, jobs and work items leave free.
func (h *RunnerAgentHandler) workItemOffersFor(runner *models.Runner, maxJobs int) ([]PendingJob, error) {
	items := h.workItems.Items()
	held, err := items.HeldForRunner(runner.ID, maxJobs)
	if err != nil {
		return nil, err
	}
	busy, err := h.outstandingFor(runner)
	if err != nil {
		return nil, err
	}
	if capacity := maxJobs - busy; capacity > 0 {
		reserved, err := items.ReserveForRunner(runner.ID, runner.PoolID(), capacity, runner.CanExecuteAnsible())
		if err != nil {
			return nil, err
		}
		held = append(held, reserved...)
	}
	offers := make([]PendingJob, 0, len(held))
	for i := range held {
		offers = append(offers, workItemOffer(&held[i]))
	}
	return offers, nil
}

// outstandingFor counts what a runner holds and has not finished: runs, Ansible jobs and work
// items, reserved or running.
func (h *RunnerAgentHandler) outstandingFor(runner *models.Runner) (int, error) {
	runs, err := repository.NewRunRepository(h.db).CountOutstandingForRunner(runner.ID)
	if err != nil {
		return 0, err
	}
	var jobs int64
	if err := h.db.Model(&models.AnsibleJob{}).
		Where("runner_id = ? AND status IN ?", runner.ID, []models.AnsibleJobStatus{models.AnsibleJobStatusPending, models.AnsibleJobStatusRunning}).
		Count(&jobs).Error; err != nil {
		return 0, err
	}
	var items int64
	if h.workItems != nil {
		if items, err = h.workItems.Items().CountOutstandingForRunner(runner.ID); err != nil {
			return 0, err
		}
	}
	return int(runs + jobs + items), nil
}

// hostedOffers is the work offered to a hosted runner (#933, D9): its own unstarted reservations
// first, then new reservations across every hosted pool of its placement group, fairly and under
// each pool's cap, up to its free capacity.
func (h *RunnerAgentHandler) hostedOffers(runner *models.Runner) ([]PendingJob, error) {
	offers := []PendingJob{}
	maxJobs := max(runner.MaxConcurrentJobs, 1)
	held, err := repository.HostedHeld(h.db, runner.ID, maxJobs)
	if err != nil {
		return offers, err
	}
	busy, err := h.outstandingFor(runner)
	if err != nil {
		return offers, err
	}
	all := held
	if capacity := maxJobs - busy; capacity > 0 {
		group := runner.HostedGroup
		if group == "" {
			group = "default"
		}
		reserved, err := repository.ReserveHosted(h.db, runner.ID, group, capacity, settings.HostedDefaultMaxConcurrentJobs(os.Getenv),
			repository.HostedEngines{Tofu: runner.CanExecuteTerraform(), Ansible: runner.CanExecuteAnsible(), WorkItems: h.offersWorkItems(runner)})
		if err != nil {
			return offers, err
		}
		all.Runs = append(all.Runs, reserved.Runs...)
		all.Jobs = append(all.Jobs, reserved.Jobs...)
		all.WorkItems = append(all.WorkItems, reserved.WorkItems...)
	}
	for i := range all.WorkItems {
		offers = append(offers, workItemOffer(&all.WorkItems[i]))
	}
	for i := range all.Jobs {
		offers = append(offers, PendingJob{JobID: all.Jobs[i].ID.String(), JobType: "ansible_job", WorkspaceName: h.projectNameByID(all.Jobs[i].ProjectID)})
	}
	for i := range all.Runs {
		offers = append(offers, h.runOffer(&all.Runs[i]))
	}
	return offers, nil
}

// runOffer is the offer of one OpenTofu run's next phase.
func (h *RunnerAgentHandler) runOffer(run *models.Run) PendingJob {
	runType := "plan"
	switch run.Operation {
	case models.RunOperationPlanOnly:
		runType = "plan"
	case models.RunOperationPlanAndApply:
		if run.Status == models.RunStatusApplying {
			runType = "apply"
		}
	case models.RunOperationDestroy:
		// TFE-compatible: destroy runs follow the same two-phase flow as plan-and-apply.
		runType = "plan-destroy"
		if run.Status == models.RunStatusApplying {
			runType = "apply-destroy"
		}
	}
	workspaceName := ""
	var ws models.Workspace
	if err := h.db.Select("name").First(&ws, "id = ?", run.WorkspaceID).Error; err == nil {
		workspaceName = ws.Name
	}
	return PendingJob{
		JobID:         run.ID,
		JobType:       "tofu_run",
		WorkspaceID:   run.WorkspaceID,
		WorkspaceName: workspaceName,
		RunType:       runType,
	}
}

// injectPasswordIntoInventory adds ansible_password to all hosts in the inventory JSON.
// This matches the behavior of the platform-managed runner's password injection.
func injectPasswordIntoInventory(inventoryJSON, password string) (string, error) {
	var inventory map[string]interface{}
	if err := json.Unmarshal([]byte(inventoryJSON), &inventory); err != nil {
		return "", fmt.Errorf("failed to parse inventory JSON: %w", err)
	}

	// Iterate through all groups in the inventory
	for _, groupData := range inventory {
		groupMap, ok := groupData.(map[string]interface{})
		if !ok {
			continue
		}

		// Check if this group has a "hosts" field
		if hosts, exists := groupMap["hosts"]; exists {
			hostsMap, ok := hosts.(map[string]interface{})
			if !ok {
				continue
			}

			// Add ansible_password to each host
			for hostName, hostVars := range hostsMap {
				if hostVars == nil {
					hostsMap[hostName] = map[string]interface{}{
						"ansible_password": password,
					}
				} else if hostVarsMap, ok := hostVars.(map[string]interface{}); ok {
					hostVarsMap["ansible_password"] = password
				}
			}
		}
	}

	modifiedJSON, err := json.MarshalIndent(inventory, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal inventory JSON: %w", err)
	}

	return string(modifiedJSON), nil
}

// injectUserIntoInventory adds ansible_user to all hosts in the inventory JSON so the
// self-hosted runner uses the credential username instead of the process user (e.g. iac).
func injectUserIntoInventory(inventoryJSON, username string) (string, error) {
	var inventory map[string]interface{}
	if err := json.Unmarshal([]byte(inventoryJSON), &inventory); err != nil {
		return "", fmt.Errorf("failed to parse inventory JSON: %w", err)
	}

	for _, groupData := range inventory {
		groupMap, ok := groupData.(map[string]interface{})
		if !ok {
			continue
		}
		if hosts, exists := groupMap["hosts"]; exists {
			hostsMap, ok := hosts.(map[string]interface{})
			if !ok {
				continue
			}
			for hostName, hostVars := range hostsMap {
				if hostVars == nil {
					hostsMap[hostName] = map[string]interface{}{
						"ansible_user": username,
					}
				} else if hostVarsMap, ok := hostVars.(map[string]interface{}); ok {
					hostVarsMap["ansible_user"] = username
				}
			}
		}
	}

	modifiedJSON, err := json.MarshalIndent(inventory, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal inventory JSON: %w", err)
	}
	return string(modifiedJSON), nil
}

// UploadState handles state file uploads from self-hosted runners.
// This is called after apply (both successful and cancelled) to persist Terraform state.
// POST /api/v2/runner/jobs/:id/state
func (h *RunnerAgentHandler) UploadState(c *gin.Context) {
	jobIDStr := c.Param("id")
	if jobIDStr == "" || !strings.HasPrefix(jobIDStr, "run-") {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "valid run ID required")
		return
	}

	// A large state arrives as the raw state file (#933, D2); the JSON form carries it base64.
	stateData, ok := readStateUpload(c)
	if !ok {
		return
	}

	// Parse state JSON
	var stateJSON map[string]interface{}
	if err := json.Unmarshal(stateData, &stateJSON); err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "invalid state JSON")
		return
	}

	// Look up the run to get workspace ID
	var run models.Run
	if err := h.db.First(&run, "id = ?", jobIDStr).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			jsonapi.WriteErrorNoDetail(c, http.StatusNotFound, "Run not found")
		} else {
			jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		}
		return
	}

	// AUD-001: writing state to a workspace is the highest-impact write on this
	// plane (a poisoned state hijacks the next apply). Only the assigned runner in
	// the run's org+pool may upload it. The body runner_id is not trusted. A canceled run still takes
	// the state its interrupted apply saved (authorizeRunnerForRunReport).
	if !h.authorizeRunnerForRunReport(c, &run) {
		return
	}

	// Extract serial and lineage from state JSON (serial drives regression rejection)
	var serial *int
	var lineage string
	if s, ok := stateJSON["serial"].(float64); ok {
		sInt := int(s)
		serial = &sInt
	}
	if l, ok := stateJSON["lineage"].(string); ok {
		lineage = l
	}

	// Extract commit info from configuration version if available
	commitHash := ""
	committer := ""
	if run.ConfigurationVersionID != nil {
		if configVersion, err := h.runConfigurationVersion(&run); err == nil {
			commitHash = configVersion.CommitHash
			committer = configVersion.Committer
		}
	}

	// AUD-018: atomically reserve the next version through the shared path - retries on the
	// (workspace_id, version) unique-violation instead of the old racy MAX(version)+1, and rejects
	// a serial regression (a stale push) with 409. Row-first, then object storage keyed on the
	// reserved version; roll the row back if the object write fails.
	runID := jobIDStr
	stateVersion := models.StateVersion{
		WorkspaceID: run.WorkspaceID,
		RunID:       &runID,
		Serial:      serial,
		Lineage:     lineage,
		CommitHash:  commitHash,
		Committer:   committer,
	}
	stateVersionRepo := repository.NewStateVersionRepository(h.db)
	nextVersion, err := stateVersionRepo.CreateNextVersion(&stateVersion)
	if err != nil {
		if errors.Is(err, repository.ErrStateSerialRegression) {
			jsonapi.WriteError(c, http.StatusConflict, "Stale state", "incoming state serial is older than the current state version")
			return
		}
		logger.Warnf("Failed to reserve state version for run %s: %v", jobIDStr, err)
		jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Failed to save state version")
		return
	}

	if h.stateService != nil {
		// Encrypt at rest before persisting (the state service owns the crypto + key format).
		if err := h.stateService.PutStateObject(c.Request.Context(), run.WorkspaceID, nextVersion, stateData); err != nil {
			_ = stateVersionRepo.Delete(stateVersion.ID)
			logger.Errorf("Failed to save state to object storage for run %s: %v", jobIDStr, err)
			jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Failed to persist state to object storage")
			return
		}
	}

	// Materialize outputs/resources for fast serving (State Storage Rework).
	// Best-effort: the raw state is already persisted in object storage authoritatively.
	if err := h.stateMaterializer.Materialize(stateVersion.ID, stateJSON); err != nil {
		logger.Warnf("Failed to materialize outputs/resources for state version %s: %v", stateVersion.ID, err)
	}

	logger.Infof("State version %d saved for run %s (workspace %s, serial=%v)", nextVersion, jobIDStr, run.WorkspaceID, serial)
	c.JSON(http.StatusOK, StateVersionSavedResponse{Status: "ok", Version: nextVersion})
}

// RunnerReRegisterResponse answers a runner re-registering with an existing identity.
type RunnerReRegisterResponse struct {
	RunnerID     string       `json:"runner_id"`
	RunnerAPIKey string       `json:"runner_api_key"`
	Status       string       `json:"status"`
	PendingJobs  []PendingJob `json:"pending_jobs"`
	// Capabilities are the API's (runnercontract.APICapabilities).
	Capabilities []string                     `json:"capabilities,omitempty"`
	ActiveClaims []runnercontract.ActiveClaim `json:"active_claims"`
}

// RunnerRegisterResponse answers a first-time runner registration.
type RunnerRegisterResponse struct {
	RunnerID            string `json:"runner_id"`
	RunnerAPIKey        string `json:"runner_api_key"`
	PollIntervalSeconds int    `json:"poll_interval_seconds"`
	// Capabilities are the API's (runnercontract.APICapabilities).
	Capabilities []string                     `json:"capabilities,omitempty"`
	ActiveClaims []runnercontract.ActiveClaim `json:"active_claims"`
}

// PendingJobsResponse is the runner poll response.
type PendingJobsResponse struct {
	PendingJobs []PendingJob `json:"pending_jobs"`
}

// StateVersionSavedResponse acknowledges a state version upload.
type StateVersionSavedResponse struct {
	Status  string `json:"status"`
	Version int    `json:"version"`
}

// applyLauncherSettings copies the launcher's reported deployment-level settings onto its runner
// row (#933, D0, D15).
func applyLauncherSettings(r *models.Runner, req runnercontract.RegisterRequest) {
	r.HostedStrict, r.CacheVerification = req.HostedStrict, req.CacheVerification
	r.LocalCache, r.LocalCacheSizeLimit = req.LocalCache, req.LocalCacheSizeLimit
}
