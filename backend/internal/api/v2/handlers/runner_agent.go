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
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/logger"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/jsonapi"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/response"
	"github.com/michielvha/stackweaver/backend/internal/services/apikey"
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
)

// RunnerAgentHandler handles runner agent API endpoints
// These endpoints are used by the runner agents to register, heartbeat, and report job status.
type RunnerAgentHandler struct {
	runnerRepo        *repository.RunnerRepository
	jobExecRepo       *repository.RunnerJobExecutionRepository
	poolRepo          *repository.AgentPoolRepository
	apiKeyService     *apikey.Service
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
	// syncRequester queues a playbook sync when a cached-mode job reaches an agent
	// before the playbook has a snapshot. Optional: when nil the run still clones, the
	// snapshot is just not repaired for the next run.
	syncRequester *ansible.PlaybookSyncRequester
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
}

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
	syncRequester *ansible.PlaybookSyncRequester,
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
		syncRequester:     syncRequester,
		db:                db,
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

	// A just-in-time token registers one launcher once (#933, D11): using it up is the same
	// statement that checks it is still unused, so two registrations racing with it cannot both
	// pass. A refused pool above did not use it.
	if raw, ok := c.Get("api_key"); ok {
		if k, ok := raw.(*models.APIKey); ok && k != nil && k.IsJITToken {
			used, err := h.apiKeyService.UseJITToken(k.ID)
			if err != nil {
				jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
				return
			}
			if !used {
				jsonapi.WriteError(c, http.StatusUnauthorized, "Unauthorized", "this just-in-time token has been used or has expired")
				return
			}
		}
	}

	// The runner-scoped token is owned by the same user as the registering key.
	registeringUserID, _ := c.Get("user_id")
	registeringUserUUID, _ := registeringUserID.(uuid.UUID)

	// Check if runner with this name already exists - if so, re-register (update and reuse)
	existing, _ := h.runnerRepo.GetByName(pool.OrganizationID, req.Name)
	if existing != nil {
		// Re-register: update the existing runner entry and return it
		existing.Status = models.RunnerStatusOnline
		existing.AgentPoolID = &poolID
		existing.IPAddress = c.ClientIP()
		now := time.Now()
		existing.LastHeartbeatAt = &now
		if req.TofuVersion != "" {
			existing.TofuVersion = req.TofuVersion
		}
		if req.AnsibleVersion != "" {
			existing.AnsibleVersion = req.AnsibleVersion
		}
		// Refresh the runner type from the capabilities just reported. Without this a row keeps
		// whatever type it was first created with, so a runner whose capabilities changed - or one
		// created under an older enum value - stays permanently unroutable: it heartbeats as Online
		// while FindAvailableRunner never matches it and every job sits pending, silently.
		existing.RunnerType = runnerTypeFor(req.Engines, req.TofuVersion, req.AnsibleVersion)
		// The capabilities are the binary's, so a re-registration replaces them.
		existing.Capabilities = models.RunnerLabels(req.Capabilities)
		existing.Driver, existing.NetworkMode = req.Driver, req.NetworkMode
		applyLauncherSettings(existing, req)
		// A new launcher process under the name is not draining (D11).
		existing.DrainRequestedAt = nil
		apiKeyUUID, _ := uuid.Parse(fmt.Sprintf("%v", apiKeyID))
		existing.RegisteredWithAPIKeyID = &apiKeyUUID
		if err := h.runnerRepo.Update(existing); err != nil {
			jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Failed to re-register launcher")
			return
		}
		logger.Infof("Launcher re-registered: %s (ID: %s, pool: %s)", existing.Name, existing.ID, poolID)

		// Mint a fresh runner-scoped token on every registration (AUD-001): the
		// runner authenticates the control plane with it, not the org registration
		// key. Old tokens for this runner id are revoked inside generateRunnerAPIKey.
		reRegKey, keyErr := h.generateRunnerAPIKey(existing, registeringUserUUID)
		if keyErr != nil {
			jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Failed to mint launcher token")
			return
		}

		// On re-registration, also check for pending jobs (same as heartbeat) so
		// runners that re-register on each cycle still pick up work.
		pendingJobs := []PendingJob{}
		if jobs, err := h.findPendingJobsForRunner(existing); err == nil {
			pendingJobs = jobs
		}

		c.JSON(http.StatusOK, RunnerReRegisterResponse{
			RunnerID:     existing.ID.String(),
			RunnerAPIKey: reRegKey,
			Status:       "re-registered",
			PendingJobs:  pendingJobs,
			Capabilities: runnercontract.APICapabilities,
		})
		return
	}

	// The engines the runner declared decide what it is offered; one that predates engines is typed
	// by the tool versions it reports.
	runnerType := runnerTypeFor(req.Engines, req.TofuVersion, req.AnsibleVersion)

	// Get client IP
	clientIP := c.ClientIP()

	// Create the runner. AUD-080: parse the API key ID the same safe way as the re-register branch
	// above - a bare type assertion panics if the middleware stored api_key_id as a non-uuid.UUID.
	apiKeyUUID, _ := uuid.Parse(fmt.Sprintf("%v", apiKeyID))
	now := time.Now()
	maxJobs := req.MaxConcurrentJobs
	if maxJobs <= 0 {
		maxJobs = 1
	}

	runner := &models.Runner{
		OrganizationID:         &pool.OrganizationID,
		AgentPoolID:            &poolID,
		Name:                   req.Name,
		RunnerType:             runnerType,
		Status:                 models.RunnerStatusOnline,
		Hostname:               req.Hostname,
		IPAddress:              clientIP,
		OSType:                 req.OSType,
		OSVersion:              req.OSVersion,
		AgentVersion:           req.AgentVersion,
		TofuVersion:            req.TofuVersion,
		AnsibleVersion:         req.AnsibleVersion,
		AvailableCollections:   models.RunnerCollections(req.AvailableCollections),
		MaxConcurrentJobs:      maxJobs,
		Labels:                 models.RunnerLabels(req.Labels),
		Capabilities:           models.RunnerLabels(req.Capabilities),
		Driver:                 req.Driver,
		NetworkMode:            req.NetworkMode,
		LastHeartbeatAt:        &now,
		RegisteredAt:           now,
		RegisteredWithAPIKeyID: &apiKeyUUID,
	}
	applyLauncherSettings(runner, req)

	if err := h.runnerRepo.Create(runner); err != nil {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to create launcher")
		return
	}

	// Generate a runner-specific API key
	// This key is scoped to only this runner: runner:<runner_id>:*
	runnerAPIKey, err := h.generateRunnerAPIKey(runner, registeringUserUUID)
	if err != nil {
		// The runner-scoped credential is mandatory now (AUD-001): without it the
		// runner cannot authenticate the control plane. Fail registration so the
		// agent retries rather than silently falling back to the org key.
		logger.Errorf("Launcher registration: failed to mint launcher token for %s: %v", runner.ID, err)
		_ = h.runnerRepo.Delete(runner.ID)
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "failed to mint launcher token")
		return
	}

	c.JSON(http.StatusCreated, RunnerRegisterResponse{
		RunnerID:            runner.ID.String(),
		RunnerAPIKey:        runnerAPIKey,
		PollIntervalSeconds: 10,
		Capabilities:        runnercontract.APICapabilities,
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
	c.JSON(status, RunnerRegisterResponse{RunnerID: runner.ID.String(), RunnerAPIKey: token, PollIntervalSeconds: 10, Capabilities: runnercontract.APICapabilities})
}

// generateRunnerAPIKey mints and persists a runner-scoped API key (AUD-001).
// The key binds to this runner via runner:<id>:* scopes and to the runner's org;
// the runner authenticates every subsequent /runner/* call with it, and
// middleware.RunnerAuth recovers the runner identity from the scopes. Any stale
// tokens for the same runner id (re-registration) are revoked first so a runner
// never has more than one live credential.
func (h *RunnerAgentHandler) generateRunnerAPIKey(runner *models.Runner, userID uuid.UUID) (string, error) {
	if h.apiKeyService == nil {
		return "", fmt.Errorf("api key service not configured for launcher token minting")
	}
	_ = h.apiKeyService.DeleteAPIKeysForRunner(runner.ID)
	_, rawKey, err := h.apiKeyService.CreateRunnerToken(userID, runner.ID, runner.OrgID(), "runner-"+runner.Name)
	if err != nil {
		return "", err
	}
	return rawKey, nil
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
	if draining {
		availableCapacity = 0
	}

	// Only query for jobs if runner has capacity
	if availableCapacity > 0 {
		pendingJobs = h.offers(runner)
		// The long poll (#933, D3): with nothing to offer, hold the request until a wakeup for the
		// runner's pool or the wait ends, then query again. The waiter is registered before the
		// second query, so work that became offerable between the two is not missed; while it waits
		// the request holds a goroutine, no database connection.
		if len(pendingJobs) == 0 && req.WaitSeconds > 0 && h.wakeHub != nil {
			wait := min(time.Duration(req.WaitSeconds)*time.Second, h.longPollMax)
			woken, forget := h.wakeHub.Wait(wakeKey(runner))
			if pendingJobs = h.offers(runner); len(pendingJobs) == 0 {
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
				pendingJobs = h.offers(runner)
			} else {
				forget()
			}
		}
	}

	resp := HeartbeatResponse{
		PendingJobs: pendingJobs, Capabilities: runnercontract.APICapabilities,
		Ensure:      h.ingestInventory(runner, req.Inventory),
		HostedDepth: h.hostedDepth(runner),
		Drain:       draining,
		ReapRunners: h.lostPeers(runner),
	}
	if resp.CachePromotions = h.pendingPromotions(runner); len(resp.CachePromotions) > 0 {
		resp.Mirror = h.mirror
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
func (h *RunnerAgentHandler) offers(runner *models.Runner) []PendingJob {
	jobs, err := h.findPendingJobsForRunner(runner)
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
	jobIDStr := c.Param("id")

	var req JobStartRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", err.Error())
		return
	}

	if isWorkItem(jobIDStr) {
		h.jobStartWorkItem(c, jobIDStr, req.Placement)
		return
	}

	// Determine if this is a Terraform run (ID starts with "run-") or Ansible job (UUID)
	if strings.HasPrefix(jobIDStr, "run-") {
		// Terraform run
		h.jobStartTerraformRun(c, jobIDStr)
		if c.Writer.Status() == http.StatusOK {
			h.recordPlacement(models.JobTypeTofuRun, jobIDStr, req.Placement)
		}
		return
	}

	// Ansible job (UUID)
	jobID, err := uuid.Parse(jobIDStr)
	if err != nil {
		jsonapi.WriteErrorNoDetail(c, http.StatusBadRequest, "Invalid job ID")
		return
	}

	if h.ansibleJobRepo == nil {
		jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		return
	}

	// AUD-001: the runner is the authenticated identity, never the body runner_id.
	runnerCaller, ok := callingRunner(c)
	if !ok {
		writeRunnerForbidden(c, "launcher identity required")
		return
	}
	runnerID := runnerCaller.ID

	// Authorize the runner for this job (same org + agent pool) before claiming.
	job, err := h.ansibleJobRepo.GetByID(jobID)
	if err != nil {
		jsonapi.WriteErrorNoDetail(c, http.StatusNotFound, "Job not found")
		return
	}
	if !h.authorizeRunnerForAnsibleJob(c, job, false) {
		return
	}

	// Atomically claim the job. Only the runner that flips the still-pending row
	// wins; any other runner offered the same job loses the race and is told to
	// skip it (409). This prevents two agent-pool runners from executing the same
	// job/slice.
	claimed, err := h.ansibleJobRepo.ClaimForRunner(jobID, runnerID)
	if err != nil {
		jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	if !claimed {
		// Either the job no longer exists, or another runner already claimed it.
		if _, getErr := h.ansibleJobRepo.GetByID(jobID); getErr != nil {
			jsonapi.WriteErrorNoDetail(c, http.StatusNotFound, "Job not found")
			return
		}
		jsonapi.WriteError(c, http.StatusConflict, "Conflict", "Job already claimed by another launcher")
		return
	}

	// Record the execution against the winning runner. The exec record is created
	// here (at claim time) rather than at offer time, so capacity accounting and
	// completion tracking reflect the runner that actually owns the job.
	h.upsertJobExecution(jobID, runnerID)
	h.revokeJobTokens(models.JobTypeAnsibleJob, jobIDStr)
	h.recordPlacement(models.JobTypeAnsibleJob, jobIDStr, req.Placement)

	response.Status(c, http.StatusOK, "started")
}

// upsertJobExecution ensures a running RunnerJobExecution record exists for the
// (claimed) Ansible job, bound to the winning runner. Created at claim time so a
// runner is only counted as busy with jobs it actually owns.
func (h *RunnerAgentHandler) upsertJobExecution(jobID, runnerID uuid.UUID) {
	workspaceName := ""
	if job, err := h.ansibleJobRepo.GetByID(jobID); err == nil && job.Project.Name != "" {
		workspaceName = job.Project.Name
	}

	if exec, err := h.jobExecRepo.GetByJobID(jobID); err == nil {
		_ = h.jobExecRepo.UpdateStatus(exec.ID, models.JobExecutionStatusRunning, "")
		return
	}

	_ = h.jobExecRepo.Create(&models.RunnerJobExecution{
		RunnerID:      runnerID,
		JobType:       models.JobTypeAnsibleJob,
		JobID:         jobID,
		WorkspaceName: workspaceName,
		Status:        models.JobExecutionStatusRunning,
	})
}

// jobStartTerraformRun handles job start for Terraform runs
func (h *RunnerAgentHandler) jobStartTerraformRun(c *gin.Context, runID string) {
	var run models.Run
	if err := h.db.First(&run, "id = ?", runID).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			jsonapi.WriteErrorNoDetail(c, http.StatusNotFound, "Run not found")
		} else {
			jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		}
		return
	}

	// AUD-001: authorize the authenticated runner for this run (same org + agent
	// pool; run may still be unassigned - this is the assignment point) and bind
	// the run to the authenticated runner, not the body runner_id.
	runnerCaller, ok := callingRunner(c)
	if !ok {
		writeRunnerForbidden(c, "launcher identity required")
		return
	}
	if !h.authorizeRunnerForRun(c, &run, false) {
		return
	}
	runnerID := runnerCaller.ID

	// AUD-007/112: atomically claim this run for dispatch before starting it. The heartbeat offers
	// the same pending/applying run to every agent runner in the pool; the claim (a conditional
	// UPDATE that wins for exactly one caller) ensures the run is started - and therefore applied -
	// on only one machine. A runner that loses the race gets 409 and skips the job. A run that was
	// canceled in the meantime is no longer pending/applying, so the claim also fails → 409.
	claimed, err := repository.NewRunRepository(h.db).ClaimForDispatch(runID)
	if err != nil {
		jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Failed to claim run")
		return
	}
	if !claimed {
		jsonapi.WriteErrorNoDetail(c, http.StatusConflict, "Run already claimed by another launcher or no longer dispatchable")
		return
	}

	// The API holds the workspace state lock for the phase (#933, D2, AC7), so the lock is the
	// same on every driver and an executor that vanishes wedges nothing beyond the TTL. A run whose
	// workspace another run holds is not started: the claim is undone and it stays pending, to be
	// offered again once the lock is released.
	if locked, lockErr := h.lockWorkspaceForRun(&run); lockErr != nil || !locked {
		_ = repository.NewRunRepository(h.db).ClearDispatch(runID)
		if lockErr != nil {
			jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Failed to lock the workspace state")
			return
		}
		jsonapi.WriteError(c, http.StatusConflict, "Conflict", "the workspace state is locked by another run; this run waits")
		return
	}

	now := time.Now()

	// Only the phase's own columns are written: the row was loaded before the claim, and saving it
	// whole would write the claim's dispatched_at and attempt back to their old values, leaving a
	// started run looking unstarted (#933, AC9).
	columns := map[string]any{"runner_id": runnerID}
	switch run.Status { //nolint:exhaustive // only pending/pre_plan_completed and applying need action on job start
	case models.RunStatusPending, models.RunStatusPrePlanCompleted:
		// pre_plan_completed = the run's pre_plan task stage passed; it dispatches like pending
		// (a run with an UNPASSED pre_plan stage never gets here - ClaimForDispatch refuses it).
		columns["status"], columns["started_at"] = models.RunStatusPlanning, now
	case models.RunStatusApplying:
		// Apply phase start - already in applying status
		columns["apply_started_at"] = now
	}
	_ = h.db.Model(&models.Run{}).Where("id = ?", runID).Updates(columns).Error
	h.revokeJobTokens(models.JobTypeTofuRun, runID)

	response.Status(c, http.StatusOK, "started")
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
			jsonapi.WriteErrorNoDetail(c, http.StatusNotFound, "Run not found")
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
		jsonapi.WriteErrorNoDetail(c, http.StatusNotFound, "Job not found")
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
		jsonapi.WriteErrorNoDetail(c, http.StatusNotFound, "Job not found")
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
	jobIDStr := c.Param("id")

	var req JobCompleteRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", err.Error())
		return
	}

	if isWorkItem(jobIDStr) {
		h.jobCompleteWorkItem(c, jobIDStr, req)
		return
	}

	// Determine if this is a Terraform run or Ansible job
	if strings.HasPrefix(jobIDStr, "run-") {
		h.jobCompleteTerraformRun(c, jobIDStr, req)
		if c.Writer.Status() == http.StatusOK {
			if req.Status == "completed" && req.CacheManifest != nil {
				var run models.Run
				if err := h.db.First(&run, "id = ?", jobIDStr).Error; err == nil {
					if org, pool, err := h.runOrgAndPool(&run); err == nil {
						h.recordCachePromotions(c, models.JobTypeTofuRun, jobIDStr, org, pool, req.CacheManifest)
					}
				}
			}
			h.revokeJobTokens(models.JobTypeTofuRun, jobIDStr)
			h.releaseWorkspaceLock(jobIDStr)
			h.wakeCallersPool(c)
		}
		return
	}

	jobID, err := uuid.Parse(jobIDStr)
	if err != nil {
		jsonapi.WriteErrorNoDetail(c, http.StatusBadRequest, "Invalid job ID")
		return
	}

	// Get the job execution record
	exec, err := h.jobExecRepo.GetByJobID(jobID)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			jsonapi.WriteErrorNoDetail(c, http.StatusNotFound, "Job not found")
		} else {
			jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		}
		return
	}

	// AUD-001: only the runner that owns the job may complete it - otherwise a
	// caller could force-complete/fail another tenant's job. Gate on the job's
	// org/pool/reservation before mutating any status.
	wasCanceled := false
	if completeJob, jErr := h.ansibleJobRepo.GetByID(jobID); jErr == nil {
		if !h.authorizeRunnerForAnsibleJobReport(c, completeJob) {
			return
		}
		wasCanceled = completeJob.Status == models.AnsibleJobStatusCanceled
	} else if runner, rok := callingRunner(c); !rok || exec.RunnerID != runner.ID {
		// Job row gone but the exec record must still belong to the caller.
		writeRunnerForbidden(c, "job is not owned by this launcher")
		return
	}

	// Map status string to enum
	var status models.JobExecutionStatus
	switch req.Status {
	case "completed":
		status = models.JobExecutionStatusCompleted
	case "failed":
		status = models.JobExecutionStatusFailed
	case "canceled":
		status = models.JobExecutionStatusCanceled
	default:
		jsonapi.WriteErrorNoDetail(c, http.StatusBadRequest, "Invalid status")
		return
	}

	// Update execution record status
	if err := h.jobExecRepo.UpdateStatus(exec.ID, status, req.ErrorMessage); err != nil {
		jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		return
	}

	// Update the ansible job status and finalize stats
	if h.ansibleJobRepo != nil {
		job, err := h.ansibleJobRepo.GetByID(jobID)
		if err == nil && wasCanceled {
			// Canceled while it ran: the executor's report ends its log, and the job stays canceled
			// whatever the interrupted playbook's exit says.
			_ = h.ansibleJobRepo.CreateEventNextCounter(&models.AnsibleJobEvent{JobID: jobID, Event: "runner_output", Stdout: jobCancelMarker})
			if job.FinishedAt == nil {
				now := time.Now()
				job.FinishedAt = &now
				_ = h.ansibleJobRepo.UpdateColumns(job, "finished_at")
			}
		} else if err == nil {
			now := time.Now()
			job.FinishedAt = &now

			switch req.Status {
			case "completed":
				job.Status = models.AnsibleJobStatusSuccessful
			case "failed":
				job.Status = models.AnsibleJobStatusFailed
				if req.ErrorMessage != "" {
					job.ErrorMessage = req.ErrorMessage
				}
				// If no failures or unreachable hosts were counted, set failures to 1
				if job.HostsFailed == 0 && job.HostsUnreachable == 0 {
					job.HostsFailed = 1
				}
			case "canceled":
				job.Status = models.AnsibleJobStatusCanceled
			}

			// Count warnings from stderr events
			events, _, _ := h.ansibleJobRepo.ListEventsByJob(jobID, 10000, 0)
			warningsCount := 0
			for _, evt := range events {
				if evt.Stderr != "" {
					warningsCount += strings.Count(evt.Stderr, "[WARNING]:") + strings.Count(evt.Stderr, "[DEPRECATION WARNING]:")
				}
			}
			if warningsCount > 0 {
				job.HasWarnings = true
				job.WarningsCount = warningsCount
			}

			_ = h.ansibleJobRepo.UpdateColumns(job, "finished_at", "status", "error_message", "hosts_failed",
				"has_warnings", "warnings_count")
		}
	}

	// Update runner status back to online (if it was busy). Use the authenticated
	// runner, not the body runner_id (AUD-001).
	if runner, ok := callingRunner(c); ok {
		activeJobs, _ := h.jobExecRepo.CountActiveByRunner(runner.ID)
		if activeJobs == 0 {
			_ = h.runnerRepo.UpdateStatus(runner.ID, models.RunnerStatusOnline)
		}
	}

	if req.Status == "completed" && req.CacheManifest != nil {
		if job, err := h.ansibleJobRepo.GetByID(jobID); err == nil {
			if org, pool, err := h.ansibleJobOrgAndPool(job); err == nil {
				h.recordCachePromotions(c, models.JobTypeAnsibleJob, jobIDStr, org, pool, req.CacheManifest)
			}
		}
	}
	h.revokeJobTokens(models.JobTypeAnsibleJob, jobIDStr)
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

// releaseWorkspaceLock releases the state lock a run holds once a phase completes.
func (h *RunnerAgentHandler) releaseWorkspaceLock(runID string) {
	var run models.Run
	if err := h.db.Select("id", "workspace_id").First(&run, "id = ?", runID).Error; err != nil {
		return
	}
	if err := repository.NewRunRepository(h.db).ReleaseStateLock(run.WorkspaceID, run.ID); err != nil {
		logger.Warnf("releasing the state lock of run %s: %v", runID, err)
	}
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

// jobRegistryBlock mints a job's token for the platform's private module registry when the
// artifacts are fetched with a job token, replacing any earlier one of the job. An agent fetching
// with its runner token gets none: it predates the per-job token and reads the registry through
// its host's own TF_TOKEN_ variables.
func (h *RunnerAgentHandler) jobRegistryBlock(c *gin.Context, run *models.Run) *runnercontract.RegistryBlock {
	if _, isJob := callingJob(c); !isJob || h.registryHost == "" || h.apiKeyService == nil {
		return nil
	}
	if err := h.apiKeyService.RevokeJobRegistryTokens(models.JobTypeTofuRun, run.ID); err != nil {
		logger.Warnf("replacing the registry token of run %s: %v", run.ID, err)
	}
	timeout := settings.EffectiveWorkspaceRunTimeout(&run.Workspace, settings.DeploymentRunTimeout(os.Getenv)).Value
	expiresAt := time.Now().Add(time.Duration(timeout)*time.Second + apikey.JobTokenGrace)
	token, err := h.apiKeyService.CreateJobRegistryToken(run.Workspace.Project.OrganizationID, models.JobTypeTofuRun, run.ID, expiresAt)
	if err != nil {
		logger.Warnf("minting the registry token of run %s: %v", run.ID, err)
		return nil
	}
	return &runnercontract.RegistryBlock{Hosts: []runnercontract.RegistryHostToken{{Host: h.registryHost, Token: token}}}
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
	columns := []string{"id", "placement_driver", "placement_placement_id", "placement_image", "placement_image_digest", "placement_image_level", "placement_identity_binding_id", "placement_node"}
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
	current.Merge(report.ToModel())
	err := h.db.Model(table).Where("id = ?", jobID).Updates(map[string]any{
		"placement_driver":              current.Driver,
		"placement_placement_id":        current.PlacementID,
		"placement_image":               current.Image,
		"placement_image_digest":        current.ImageDigest,
		"placement_image_level":         current.ImageLevel,
		"placement_identity_binding_id": current.IdentityBindingID,
		"placement_node":                current.Node,
	}).Error
	if err != nil {
		logger.Warnf("recording the placement of %s %s: %v", kind, jobID, err)
	}
}

// appendCancelMarker ends the log of the phase a canceled run was in with cancelMarker, after the
// interrupted engine's last output. The phase is apply once the plan completed, as the log reader
// expects (plan.log or apply.log).
func (h *RunnerAgentHandler) appendCancelMarker(ctx context.Context, run *models.Run) {
	phase := "plan"
	if run.PlanCompletedAt != nil && run.Operation != models.RunOperationPlanOnly {
		phase = "apply"
	}
	line := "\n" + cancelMarker + "\n"
	var err error
	switch {
	case h.logBuffer != nil:
		_, err = h.logBuffer.AppendCapped(ctx, run.ID, phase, line, h.jobLogLimits())
	case h.storageClient != nil:
		_, err = logbuffer.AppendStorageLogCapped(ctx, h.storageClient, run.ID, phase, line, h.jobLogLimits())
	}
	if err != nil {
		logger.Warnf("Failed to append the cancel marker to run %s phase %s: %v", run.ID, phase, err)
	}
}

// revokeJobTokens deletes every job token of a job (#933, D1): at completion, and at a claim, which
// starts a new attempt the earlier attempts' tokens must not reach. A failure is logged, not
// returned: the attempt and terminal checks refuse a token that survives.
func (h *RunnerAgentHandler) revokeJobTokens(kind models.JobType, jobID string) {
	if h.apiKeyService == nil {
		return
	}
	if err := h.apiKeyService.RevokeJobTokens(kind, jobID); err != nil {
		logger.Warnf("revoking job tokens of %s %s: %v", kind, jobID, err)
	}
}

// jobCompleteTerraformRun handles job completion for Terraform runs
func (h *RunnerAgentHandler) jobCompleteTerraformRun(c *gin.Context, runID string, req JobCompleteRequest) {
	var run models.Run
	if err := h.db.First(&run, "id = ?", runID).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			jsonapi.WriteErrorNoDetail(c, http.StatusNotFound, "Run not found")
		} else {
			jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		}
		return
	}

	// AUD-001: only the assigned runner may complete a run - this handler flips run
	// status (planned/applied/failed), can trigger auto-apply, and finalizes logs. A canceled run
	// still takes the completion of the attempt that was running (authorizeRunnerForRunReport).
	if !h.authorizeRunnerForRunReport(c, &run) {
		return
	}
	canceled := run.Status == models.RunStatusCancelled
	if canceled {
		h.appendCancelMarker(c.Request.Context(), &run)
	}

	// JobComplete is terminal for whichever phase this job ran, so no more output will
	// follow: append the ETX end-of-text marker to the phase logs. Finalizing both
	// phases is safe - it is idempotent (a missing or already-terminated object is left
	// untouched), so the plan job finalizes plan.log while apply.log is still absent,
	// and the later apply job finalizes apply.log without touching the framed plan.log.
	for _, phase := range []string{"plan", "apply"} {
		// AUD-028: when the Redis buffer is in use, finalize there and copy the completed phase log
		// to MinIO once (so it persists past Redis eviction and the read path's MinIO fallback
		// finds it). Otherwise finalize the object-storage log in place.
		if h.logBuffer != nil {
			if err := h.logBuffer.Finalize(c.Request.Context(), runID, phase); err != nil {
				logger.Warnf("Failed to finalize agent Redis log for run %s phase %s: %v", runID, phase, err)
			}
			if h.storageClient != nil {
				if err := h.logBuffer.CopyToStorage(c.Request.Context(), runID, phase, h.storageClient); err != nil {
					logger.Warnf("Failed to copy agent log to storage for run %s phase %s: %v", runID, phase, err)
				}
			}
		} else if h.storageClient != nil {
			if err := logbuffer.FinalizeStorageLog(c.Request.Context(), h.storageClient, runID, phase); err != nil {
				logger.Warnf("Failed to finalize agent log for run %s phase %s: %v", runID, phase, err)
			}
		}
	}

	now := time.Now()

	// Store plan metadata if provided (from self-hosted runner's terraform show -json)
	if req.PlanJSON != "" || req.HasChanges {
		if run.PlanOutput == nil {
			run.PlanOutput = make(models.PlanOutput)
		}
		run.PlanOutput["AddCount"] = float64(req.ResourceAdditions)
		run.PlanOutput["ChangeCount"] = float64(req.ResourceChanges)
		run.PlanOutput["DestroyCount"] = float64(req.ResourceDestructions)
		run.PlanOutput["OutputChangeCount"] = float64(req.OutputChanges)

		// Store the FULL parsed plan JSON (all top-level keys), matching the platform runner. The
		// old subset (resource_changes/output_changes only) was enough for hasChanges() detection
		// but starved the plans/:id/json-output endpoint that run-task services (plan_json_api_url)
		// and go-tfe read - agent runs must serve the same plan JSON platform runs do.
		if req.PlanJSON != "" {
			var planData map[string]interface{}
			if err := json.Unmarshal([]byte(req.PlanJSON), &planData); err == nil {
				for k, v := range planData {
					run.PlanOutput[k] = v
				}
			}
		}

		logger.Infof("Stored plan metadata for run %s: additions=%d, changes=%d, destructions=%d, hasChanges=%v",
			runID, req.ResourceAdditions, req.ResourceChanges, req.ResourceDestructions, req.HasChanges)
	}

	switch req.Status {
	case "completed":
		switch run.Status { //nolint:exhaustive // only planning has special handling
		case models.RunStatusPlanning:
			// Plan phase completed (for plan-and-apply and destroy runs)
			run.Status = models.RunStatusPlanned
			run.PlanCompletedAt = &now
			// TFE-compatible: Only auto-apply for VCS-triggered runs with workspace.AutoApply enabled
			// UI-triggered "Plan and Apply" runs must wait for user confirmation via the Apply endpoint.
			// The AutoApplyAfterPlan flag only indicates this is a "plan-and-apply" run (not "plan-only"),
			// it does NOT mean the run should auto-apply without user confirmation.
			// Computed BEFORE the run-task gate below so a run pausing at a post_plan stage persists
			// the same decision (AutoApplyResolved) for the continuation to apply.
			shouldAutoApply := false
			if (run.AutoApplyAfterPlan || run.AutoApply) && (run.Operation == models.RunOperationPlanAndApply || run.Operation == models.RunOperationDestroy) {
				// go-tfe `auto-apply: true` (e.g. tfe_workspace_run fire-and-forget) auto-applies
				// regardless of VCS/workspace settings - it is an explicit per-run intent.
				if run.AutoApply {
					shouldAutoApply = true
					logger.Infof("Auto-applying run %s: per-run auto-apply intent (go-tfe auto-apply)", runID)
				}
				if run.ConfigurationVersionID != nil {
					if configVersion, err := h.runConfigurationVersion(&run); err == nil {
						if configVersion.Source == "tfe-vcs" {
							var workspace models.Workspace
							if err := h.db.First(&workspace, "id = ?", run.WorkspaceID).Error; err == nil && workspace.AutoApply {
								shouldAutoApply = true
								logger.Infof("Auto-applying run %s: VCS-triggered with workspace auto-apply enabled", runID)
							}
						}
					}
				}
			}

			// Run-task gate: a run with a post_plan task stage pauses at post_plan_running; the
			// continuation applies the planned/completed/applying decision after the stage passes.
			// Mirrors the platform runner's gate in backend/cmd/runner/main.go - the two finalize
			// paths must gate identically.
			hasPostPlanStage, tsErr := repository.NewTaskStageRepository(h.db).HasStage(runID, models.TaskStagePostPlan)
			if tsErr != nil {
				// Fail closed: skipping the gate on a DB error would let a run bypass a mandatory task.
				jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Failed to check task stages")
				return
			}
			switch {
			case hasPostPlanStage:
				run.Status = models.RunStatusPostPlanRunning
				run.AutoApplyResolved = shouldAutoApply
				logger.Infof("Run %s paused at post_plan task stage (auto-apply resolved: %v)", runID, shouldAutoApply)
			case shouldAutoApply:
				run.Status = models.RunStatusApplying
				// Clear the dispatch claim consumed by the PLAN job start, or no agent can ever claim
				// the apply phase (ClaimForDispatch requires a NULL claim) and the run wedges at
				// `applying`. The manual-confirm path already clears it; this auto-apply path never
				// did (pre-existing bug, found while wiring run tasks - see #554). Cleared via a
				// separate UPDATE before the Save below persists the applying status.
				if clearErr := repository.NewRunRepository(h.db).ClearDispatch(runID); clearErr != nil {
					logger.Warnf("Failed to clear dispatch claim for auto-applied run %s: %v", runID, clearErr)
				}
				run.DispatchedAt = nil // keep the in-memory struct consistent with the cleared claim for the Save below
				run.RunnerID = nil     // the apply phase is offered afresh, as ClearDispatch releases the reservation
			default:
				logger.Infof("Run %s plan completed, waiting for user confirmation (not VCS-triggered or workspace auto-apply disabled)", runID)
			}
		case models.RunStatusCancelled:
			// Run was cancelled (e.g. user cancelled mid-apply); do not overwrite with applied
			break
		default:
			// Apply phase, plan-only, or destroy completed. Only set applied if run is not cancelled
			// (atomic update so we never overwrite cancelled, regardless of race with Cancel API).
			// Run-task gate: with a post_apply task stage the run pauses at post_apply_running (no
			// completed_at yet); the continuation writes applied after the stage passes. Mirrors the
			// platform runner's post-apply gate.
			hasPostApplyStage, tsErr := repository.NewTaskStageRepository(h.db).HasStage(runID, models.TaskStagePostApply)
			if tsErr != nil {
				jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Failed to check task stages")
				return
			}
			terminalUpdates := map[string]interface{}{
				"status":       models.RunStatusApplied,
				"completed_at": now,
				"updated_at":   now,
			}
			if hasPostApplyStage {
				terminalUpdates = map[string]interface{}{
					"status":     models.RunStatusPostApplyRunning,
					"updated_at": now,
				}
				logger.Infof("Run %s paused at post_apply task stage", runID)
			}
			res := h.db.Model(&models.Run{}).Where("id = ? AND status != ?", runID, models.RunStatusCancelled).Updates(terminalUpdates)
			if res.RowsAffected == 0 {
				response.Status(c, http.StatusOK, "completed")
				return
			}
			// Persist plan metadata if provided (run struct was updated above the switch)
			if req.PlanJSON != "" || req.HasChanges {
				_ = h.db.Model(&models.Run{}).Where("id = ?", runID).Update("plan_output", run.PlanOutput)
			}
			response.Status(c, http.StatusOK, "completed")
			return
		}
	case "failed":
		if canceled {
			// The engine exited non-zero because it was interrupted: the run stays canceled.
			break
		}
		run.Status = models.RunStatusFailed
		// Use ErrorMessage if provided, fall back to Output for error context
		errMsg := req.ErrorMessage
		if errMsg == "" && req.Output != "" {
			errMsg = req.Output
		}
		run.ErrorMessage = errMsg
		run.CompletedAt = &now
	case "canceled":
		run.Status = models.RunStatusCancelled
		if run.CompletedAt == nil {
			run.CompletedAt = &now
		}
	default:
		jsonapi.WriteErrorNoDetail(c, http.StatusBadRequest, "Invalid status")
		return
	}

	if err := h.db.Save(&run).Error; err != nil {
		jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		return
	}

	// Update runner status back to online (if it was busy). Use the authenticated
	// runner, not the body runner_id (AUD-001).
	if runner, ok := callingRunner(c); ok {
		activeJobs, _ := h.jobExecRepo.CountActiveByRunner(runner.ID)
		if activeJobs == 0 {
			_ = h.runnerRepo.UpdateStatus(runner.ID, models.RunnerStatusOnline)
		}
	}

	response.Status(c, http.StatusOK, "completed")
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

// resolvePlaybookSource decides how a self-hosted runner obtains a VCS-backed playbook.
//
//   - fresh: the runner clones, so it gets the clone URL.
//   - cached with a snapshot: the runner downloads the snapshot. No clone URL is sent,
//     because a runner has no reason to hold a token-embedded URL it will not use.
//   - cached without a snapshot: a self-hosted runner cannot build one (it has no object
//     storage), so this run clones and a sync is queued to repair the cache for the next.
func (h *RunnerAgentHandler) resolvePlaybookSource(ctx context.Context, playbook *models.AnsiblePlaybook) (*PlaybookSourceArtifact, *VCSArtifact) {
	mode := playbookSourceMode(playbook)
	source := &PlaybookSourceArtifact{Mode: mode}
	if mode == models.PlaybookSourceModeFresh {
		return source, h.playbookVCSArtifact(ctx, playbook)
	}

	if h.playbookSnapshotExists(ctx, playbook) {
		source.Commit = playbook.CachedCommit
		source.CapturedAt = playbook.CachedAt
		source.SizeBytes = playbook.CachedSizeBytes
		return source, nil
	}

	// Resolve the clone URL before queueing the sync: Request rewrites the sync status
	// on the playbook, and the artifact must not depend on that write succeeding.
	vcsArtifact := h.playbookVCSArtifact(ctx, playbook)
	if h.syncRequester != nil {
		if err := h.syncRequester.RequestTriggered(ctx, playbook, "launch"); err != nil {
			logger.Warnf("Playbook %s has no snapshot and a sync could not be queued (this run clones regardless): %v", playbook.ID, err)
		}
	}
	return source, vcsArtifact
}

// snapshotOnlySource is the playbook source of a job whose executor holds a job token: the
// playbook's snapshot, whatever its source mode (a fresh-mode one is taken at launch). A playbook that has none yet gets a sync, and the
// job fails with the reason rather than run without its files; it answers the request then.
func (h *RunnerAgentHandler) snapshotOnlySource(c *gin.Context, job *models.AnsibleJob, playbook *models.AnsiblePlaybook) (*PlaybookSourceArtifact, bool) {
	ctx := c.Request.Context()
	if h.playbookSnapshotExists(ctx, playbook) {
		// The mode travels with the snapshot: a fresh-mode one was captured for this launch.
		return &PlaybookSourceArtifact{Mode: playbookSourceMode(playbook), Commit: playbook.CachedCommit, CapturedAt: playbook.CachedAt, SizeBytes: playbook.CachedSizeBytes}, true
	}
	if h.syncRequester != nil {
		if err := h.syncRequester.RequestTriggered(ctx, playbook, "launch"); err != nil {
			logger.Warnf("Playbook %s has no snapshot and a sync could not be requested: %v", playbook.ID, err)
		}
	}
	const reason = "the playbook has no snapshot yet: a sync was requested; launch the job again once it completes"
	if h.ansibleJobRepo != nil {
		if err := h.db.Model(&models.AnsibleJob{}).Where("id = ? AND status IN ?", job.ID,
			[]models.AnsibleJobStatus{models.AnsibleJobStatusPending, models.AnsibleJobStatusRunning}).
			Updates(map[string]any{"status": models.AnsibleJobStatusFailed, "error_message": reason}).Error; err != nil {
			logger.Warnf("failing job %s without a playbook snapshot: %v", job.ID, err)
		}
	}
	jsonapi.WriteError(c, http.StatusConflict, "Conflict", reason)
	return nil, false
}

// playbookSnapshotExists reports whether a cached playbook has a snapshot a runner can
// download: the metadata says one was captured and the object is not missing from
// storage. The object is probed by opening it and closing it straight away.
func (h *RunnerAgentHandler) playbookSnapshotExists(ctx context.Context, playbook *models.AnsiblePlaybook) bool {
	if playbook.CachedAt == nil || h.storageClient == nil {
		return false
	}
	stream, err := h.storageClient.GetStream(ctx, ansible.PlaybookSnapshotKey(playbook.ID))
	if errors.Is(err, storage.ErrNotFound) {
		return false
	}
	if err != nil {
		// Not provably missing. Treat the snapshot as present: the download reports the
		// real failure, instead of this silently turning a cached run into a clone.
		logger.Warnf("Playbook %s: probing the cached snapshot failed: %v", playbook.ID, err)
		return true
	}
	if closeErr := stream.Close(); closeErr != nil {
		logger.Warnf("Playbook %s: closing the snapshot probe failed: %v", playbook.ID, closeErr)
	}
	return true
}

// playbookVCSArtifact builds the clone instructions for a VCS-backed playbook: a fresh
// token from the provider registry embedded in the clone URL. It returns nil when the
// connection or a clone URL cannot be resolved.
//
// The connection is loaded within the playbook's organization. A playbook row that names another
// organization's connection resolves to nothing, so a self-hosted runner is handed no clone URL
// and no token for it.
func (h *RunnerAgentHandler) playbookVCSArtifact(ctx context.Context, playbook *models.AnsiblePlaybook) *VCSArtifact {
	if playbook.VCSConnectionID == nil {
		return nil
	}
	scope := repository.NewOrganizationScope(h.db).WithContext(ctx)
	vcsConn, err := ansible.PlaybookVCSConnection(scope, playbook.ProjectID, *playbook.VCSConnectionID)
	if err != nil {
		if !errors.Is(err, ansible.ErrInvalidInput) {
			logger.Warnf("Playbook %s: loading its VCS connection failed: %v", playbook.ID, err)
		}
		return nil
	}
	if h.vcsRegistry == nil {
		return nil
	}
	provider, err := h.vcsRegistry.GetProvider(vcsConn)
	if err != nil {
		return nil
	}
	accessToken, _ := provider.GetFreshToken(ctx, vcsConn)
	repoURL := provider.BuildCloneURL(vcsConn, accessToken, playbook.VCSRepository)
	if repoURL == "" {
		return nil
	}
	branch := playbook.VCSBranch
	if branch == "" {
		branch = "main"
	}
	return &VCSArtifact{RepoURL: repoURL, Branch: branch, Repository: playbook.VCSRepository}
}

// playbookSnapshotStreamTimeout bounds one snapshot response. It matches the time the
// executor allows itself for the download (see ansibleexec.Execute), so neither side
// gives up before the other.
const playbookSnapshotStreamTimeout = 10 * time.Minute

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

	job, err := h.ansibleJobRepo.GetByID(jobID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			jsonapi.WriteErrorNoDetail(c, http.StatusNotFound, "Job not found")
		} else {
			jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		}
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
	playbook, err := h.playbookRepo.GetByID(*job.PlaybookID)
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "playbook not found")
		return
	}
	if !isVCSBacked(playbook) {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "the playbook has no VCS repository, so it has no snapshot")
		return
	}
	// An executor with a job token starts every job from a snapshot, a fresh-mode one too: that
	// playbook is captured at the branch head for each launch (decision 18). An old agent with a
	// runner token still clones a fresh-mode playbook and has no use for its snapshot.
	if _, executorWithJobToken := callingJob(c); !executorWithJobToken && playbookSourceMode(playbook) == models.PlaybookSourceModeFresh {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "the playbook's source mode is fresh: it is cloned, not served from a snapshot")
		return
	}
	if playbook.CachedAt == nil {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "the playbook has no snapshot yet")
		return
	}

	stream, err := h.storageClient.GetStream(c.Request.Context(), ansible.PlaybookSnapshotKey(playbook.ID))
	if errors.Is(err, storage.ErrNotFound) {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "the playbook has no snapshot yet")
		return
	}
	if err != nil {
		logger.Errorf("Failed to open the snapshot of playbook %s for job %s: %v", playbook.ID, job.ID, err)
		jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	defer func() { _ = stream.Close() }()

	// The server's write timeout is sized for JSON responses and would cut a large
	// snapshot on a slow link every time. Give this one response the same budget the
	// runner gives the download. A writer that cannot move its deadline (a test
	// recorder) keeps the server default, which is all it had before.
	if err := http.NewResponseController(c.Writer).SetWriteDeadline(time.Now().Add(playbookSnapshotStreamTimeout)); err != nil && !errors.Is(err, http.ErrNotSupported) {
		logger.Warnf("Could not extend the write deadline for the snapshot of playbook %s: %v", playbook.ID, err)
	}

	// No Content-Length: the size in the playbook metadata can lag a sync that replaced
	// the object after the row was read, and the stream does not expose the object's
	// size. Without it the response is sent chunked.
	c.Header("Content-Type", "application/gzip")
	c.Status(http.StatusOK)
	if _, err := io.Copy(c.Writer, stream); err != nil {
		// The status line is already out; all that is left is to say why the body is short.
		logger.Warnf("Streaming the snapshot of playbook %s to job %s was cut short: %v", playbook.ID, job.ID, err)
	}
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
			if err == gorm.ErrRecordNotFound {
				jsonapi.WriteErrorNoDetail(c, http.StatusNotFound, "Not Found")
				return
			}
			jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
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
	if getErr != nil || job == nil {
		jsonapi.WriteErrorNoDetail(c, http.StatusNotFound, "Not Found")
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
		if err == gorm.ErrRecordNotFound {
			jsonapi.WriteErrorNoDetail(c, http.StatusNotFound, "Job not found")
		} else {
			jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		}
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
	snapshotCapable := runnerCapabilities(c)[runnerCapabilityPlaybookSnapshot]

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

	// Get playbook info, and for a VCS-backed playbook decide where this job's files
	// come from: the cached snapshot or a clone.
	if h.playbookRepo != nil && job.PlaybookID != nil {
		playbook, err := h.playbookRepo.GetByID(*job.PlaybookID)
		if err == nil {
			response.PlaybookPath = playbook.PlaybookPath
			_, executorWithJobToken := callingJob(c)
			switch {
			case !isVCSBacked(playbook):
			case executorWithJobToken:
				// An executor holding a job token runs the playbook's snapshot and is never handed
				// a clone URL (#933, decision 18, AC68); the launch held the job until a
				// playbook_snapshot work item captured it.
				source, ok := h.snapshotOnlySource(c, job, playbook)
				if !ok {
					return
				}
				response.PlaybookSource = source
			case snapshotCapable:
				response.PlaybookSource, response.VCS = h.resolvePlaybookSource(c.Request.Context(), playbook)
			default:
				// Clone URL only, whatever the source mode: no snapshot probe, no sync.
				response.VCS = h.playbookVCSArtifact(c.Request.Context(), playbook)
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
				logger.Warnf("Failed to load credential %s for job %s: %v", id, job.ID, err)
				continue
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
					if err != nil || cred.Username == "" {
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
		if err := h.db.First(&project, "id = ?", job.ProjectID).Error; err == nil {
			// Try project config first, then org (no workspace for ansible jobs)
			// GetForWorkspace signature: (workspaceID string, projectID, orgID uuid.UUID)
			config, err := h.ansibleConfigRepo.GetForWorkspace("", job.ProjectID, project.OrganizationID)
			if err == nil && config != nil {
				response.AnsibleCfg = config.ConfigContent
			}
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
	var run models.Run
	if err := h.db.Preload("Workspace.Project.Organization").First(&run, "id = ?", runID).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			jsonapi.WriteErrorNoDetail(c, http.StatusNotFound, "Run not found")
		} else {
			jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
		}
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
	// else the newest release the organization caches; empty, the executor takes the newest
	// upstream release.
	tofuVersion, _ := settings.EffectiveTofuVersion(&run.Workspace)
	tfVersion := h.runTofuVersion(run.Workspace.Project.OrganizationID, tofuVersion.Value)

	response := AgentJobArtifacts{
		JobID:            run.ID,
		JobType:          "tofu_run",
		ContractVersion:  runnercontract.Version,
		TofuVersion:      tfVersion,
		WorkingDirectory: run.Workspace.WorkingDirectory,
		Plan:             h.planDescriptor(c.Request.Context(), &run),
		Registry:         h.jobRegistryBlock(c, &run),
		Mirror:           h.mirror,
	}

	// Get configuration tarball from storage if configuration version exists. The version is
	// looked up within the run's workspace first: a run row that names a configuration version
	// uploaded to another workspace finds none, and the runner is handed none of its code.
	var tarball []byte
	if run.ConfigurationVersionID != nil && h.storageClient != nil {
		if configVersion, cvErr := h.runConfigurationVersion(&run); cvErr == nil {
			storageKey := models.ConfigurationTarballKey(configVersion.ID)
			ctx := context.Background()
			if data, err := h.storageClient.Get(ctx, storageKey); err == nil {
				tarball = data
				if len(data) > h.inlineLimit() && runnerCan(c, runnercontract.CapabilityBlob) {
					response.ConfigTarballBlob = blobRef(run.ID, blobConfigTarball, data)
				} else {
					response.ConfigTarball = base64.StdEncoding.EncodeToString(data)
				}
			}
		} else {
			logger.Warnf("Configuration version lookup failed for run %s: %v", runID, cvErr)
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
		} else {
			logger.Warnf("VCS connection lookup failed for run %s, vcsConnectionID=%v", runID, run.Workspace.VCSConnectionID)
		}
	}

	// Get Terraform variables (category == "terraform")
	if h.variableService != nil {
		ctx := context.Background()
		if varsMeta, err := h.variableService.GetVariablesWithMetaForRun(ctx, run.WorkspaceID); err == nil && len(varsMeta) > 0 {
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
		if envVars, err := h.variableService.GetEnvironmentVariablesForRun(ctx, run.WorkspaceID); err == nil && len(envVars) > 0 {
			response.EnvironmentVars = envVars
		}
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
			Order("version DESC").First(&latestState).Error; err == nil {
			// Read state from object storage (the authoritative copy), decrypting at rest
			// state to plaintext before base64-encoding it into the job payload.
			ctx := context.Background()
			if stateData, err := h.stateService.GetStateObject(ctx, run.WorkspaceID, latestState.Version); err == nil && len(stateData) > 0 {
				if len(stateData) > h.inlineLimit() && runnerCan(c, runnercontract.CapabilityBlob) {
					response.StateBlob = blobRef(run.ID, blobState, stateData)
				} else {
					response.StateJSON = base64.StdEncoding.EncodeToString(stateData)
				}
				logger.Infof("Including state version %d (%d bytes) in artifacts for run %s", latestState.Version, len(stateData), runID)
			}
		}
	}

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
func (h *RunnerAgentHandler) findPendingJobsForRunner(runner *models.Runner) ([]PendingJob, error) {
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
	Capabilities []string `json:"capabilities,omitempty"`
}

// RunnerRegisterResponse answers a first-time runner registration.
type RunnerRegisterResponse struct {
	RunnerID            string `json:"runner_id"`
	RunnerAPIKey        string `json:"runner_api_key"`
	PollIntervalSeconds int    `json:"poll_interval_seconds"`
	// Capabilities are the API's (runnercontract.APICapabilities).
	Capabilities []string `json:"capabilities,omitempty"`
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
