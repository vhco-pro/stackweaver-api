// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/logger"
	terraform "github.com/michielvha/stackweaver/backend/internal/api/v2/handlers/terraform"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/jsonapi"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/response"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/security/gitargs"
	coreansible "github.com/michielvha/stackweaver/core/services/ansible"
	"github.com/michielvha/stackweaver/core/services/vcs"
	"github.com/michielvha/stackweaver/core/storage"
	"gorm.io/gorm"
)

// VCSAppInstallationHandlerV2 handles VCS App installation flow (GitHub, Azure DevOps)
type VCSAppInstallationHandlerV2 struct {
	vcsConnectionRepo  *repository.VCSConnectionRepository
	orgRepo            *repository.OrganizationRepository
	moduleRepo         *repository.ModuleRepository
	workspaceRepo      *repository.WorkspaceRepository
	runRepo            *repository.RunRepository
	configVersionRepo  *repository.ConfigurationVersionRepository
	inventoryRepo      *repository.AnsibleInventoryRepository
	playbookRepo       *repository.AnsiblePlaybookRepository
	webhookEventRepo   *repository.WebhookEventRepository // For recording webhook deliveries
	authService        *auth.Service
	rbacService        *rbac.Service // For the manage-vcs-settings check on the installation flows
	githubAppManager   *vcs.GitHubAppManager
	azureDevOpsManager *vcs.AzureDevOpsManager
	vcsRegistry        *vcs.ProviderRegistry
	statusService      *vcs.GitHubStatusService      // For GitHub status checks
	adoStatusService   *vcs.AzureDevOpsStatusService // For Azure DevOps PR status checks
	registryPublisher  *RegistryPublishingHandler    // For tag push event handling
	storageClient      storage.Client
	workItems          *coreansible.WorkItemService // inventory and playbook syncs, as work items (#933, D2)

	// verifyADOAccount proves that an Azure DevOps connection's token reaches the Azure DevOps
	// organization it names. Nil means verifyADOAccountWithToken; a test replaces it.
	verifyADOAccount func(ctx context.Context, conn *models.VCSConnection) error

	// appURL is the SPA's public origin (STACKWEAVER_APP_URL). GitHub returns a person who
	// authorized the App to its /vcs/github/authorized page (SetAppURL).
	appURL string

	// Optional webhook template launcher (SetTemplateLauncher): templates with
	// launch_on_webhook fire when their playbook's repo receives a push.
	templateRepo      *repository.AnsibleJobTemplateRepository
	webhookJobService *coreansible.JobService
}

// SetTemplateLauncher wires webhook-triggered template launches. Optional;
// without it pushes only sync playbooks/inventories (legacy behavior).
func (h *VCSAppInstallationHandlerV2) SetTemplateLauncher(templateRepo *repository.AnsibleJobTemplateRepository, jobService *coreansible.JobService) {
	h.templateRepo = templateRepo
	h.webhookJobService = jobService
}

// launchWebhookTemplates launches every enabled template of the playbook that
// opted into webhook launches. Best-effort: failures are logged and never fail
// the webhook delivery. Returns the number of launched jobs.
func (h *VCSAppInstallationHandlerV2) launchWebhookTemplates(playbookID uuid.UUID, playbookName, repo, branch string) int {
	if h.templateRepo == nil || h.webhookJobService == nil {
		return 0
	}
	templates, err := h.templateRepo.ListWebhookLaunchByPlaybook(playbookID)
	if err != nil {
		logger.Errorf("Webhook launch: failed to list templates for playbook %s: %v", playbookID, err)
		return 0
	}
	launched := 0
	for i := range templates {
		template := &templates[i]
		job, err := h.webhookJobService.LaunchFromTemplate(context.Background(), template.ID, nil, nil)
		if err != nil {
			logger.Warnf("Webhook launch: template %q failed to launch: %v", template.Name, err)
			continue
		}
		logger.Infof("Webhook launch: push to %s@%s launched template %q (playbook %q) as job %s", repo, branch, template.Name, playbookName, job.ID)
		launched++
	}
	return launched
}

func NewVCSAppInstallationHandlerV2(
	vcsConnectionRepo *repository.VCSConnectionRepository,
	orgRepo *repository.OrganizationRepository,
	moduleRepo *repository.ModuleRepository,
	workspaceRepo *repository.WorkspaceRepository,
	runRepo *repository.RunRepository,
	configVersionRepo *repository.ConfigurationVersionRepository,
	inventoryRepo *repository.AnsibleInventoryRepository,
	playbookRepo *repository.AnsiblePlaybookRepository,
	webhookEventRepo *repository.WebhookEventRepository,
	authService *auth.Service,
	rbacService *rbac.Service,
	githubAppManager *vcs.GitHubAppManager,
	azureDevOpsManager *vcs.AzureDevOpsManager,
	vcsRegistry *vcs.ProviderRegistry,
	registryPublisher *RegistryPublishingHandler,
	storageClient storage.Client,
	workItems *coreansible.WorkItemService,
) *VCSAppInstallationHandlerV2 {
	// Create status service from app manager if available
	var statusService *vcs.GitHubStatusService
	if githubAppManager != nil && githubAppManager.IsEnabled() {
		appService := githubAppManager.GetService()
		if appService != nil {
			statusService = vcs.NewGitHubStatusService(appService)
		}
	}

	// Create Azure DevOps status service if available
	var adoStatusService *vcs.AzureDevOpsStatusService
	if azureDevOpsManager != nil && azureDevOpsManager.IsEnabled() && vcsRegistry != nil {
		adoStatusService = vcs.NewAzureDevOpsStatusService(azureDevOpsManager, vcsRegistry.GetConnUpdater())
	}

	return &VCSAppInstallationHandlerV2{
		vcsConnectionRepo:  vcsConnectionRepo,
		orgRepo:            orgRepo,
		moduleRepo:         moduleRepo,
		workspaceRepo:      workspaceRepo,
		runRepo:            runRepo,
		configVersionRepo:  configVersionRepo,
		inventoryRepo:      inventoryRepo,
		playbookRepo:       playbookRepo,
		webhookEventRepo:   webhookEventRepo,
		authService:        authService,
		rbacService:        rbacService,
		githubAppManager:   githubAppManager,
		azureDevOpsManager: azureDevOpsManager,
		vcsRegistry:        vcsRegistry,
		statusService:      statusService,
		adoStatusService:   adoStatusService,
		registryPublisher:  registryPublisher,
		storageClient:      storageClient,
		workItems:          workItems,
	}
}

// requestInventorySync requests the webhook-triggered sync of an inventory as a work item. The
// credential the clone needs is resolved when a launcher runs it, never carried on the request.
func (h *VCSAppInstallationHandlerV2) requestInventorySync(inv *models.AnsibleInventory) {
	if h.workItems == nil {
		return
	}
	if _, err := h.workItems.RequestInventorySync(context.Background(), inv, "webhook"); err != nil {
		logger.Errorf("Error requesting a sync of inventory %s: %v", inv.ID, err)
	}
}

// requestPlaybookSync requests the webhook-triggered snapshot of a playbook as a work item.
func (h *VCSAppInstallationHandlerV2) requestPlaybookSync(pb *models.AnsiblePlaybook) {
	if h.workItems == nil {
		return
	}
	if _, err := h.workItems.RequestPlaybookSnapshot(context.Background(), pb, "webhook"); err != nil {
		logger.Errorf("Error requesting a sync of playbook %s: %v", pb.ID, err)
	}
}

// inventoryConnection loads the VCS connection an inventory names, within the inventory's
// organization. A push has no caller to authorize, so this is where an inventory row that names
// another organization's connection stops: the connection is not found, the inventory is not
// matched to the delivery and gets no clone URL. The inventory must name a connection.
func (h *VCSAppInstallationHandlerV2) inventoryConnection(ctx context.Context, inv *models.AnsibleInventory) (*models.VCSConnection, error) {
	scope := h.vcsConnectionRepo.OrganizationScope().WithContext(ctx)
	return coreansible.InventoryVCSConnection(scope, inv.OrganizationID, *inv.VCSConnectionID)
}

// workspaceConnection loads the VCS connection a workspace names, within the workspace's
// organization, which is that of its project. It is how every webhook path reaches a workspace's
// connection: to match the workspace to a delivery, to clone for the run a push or a pull request
// starts, and to post a commit status. None of them has a caller to authorize, so a workspace row
// that names another organization's connection stops here: the connection is not found
// (gorm.ErrRecordNotFound), exactly as if it did not exist. The workspace must name a connection.
func (h *VCSAppInstallationHandlerV2) workspaceConnection(ws *models.Workspace) (*models.VCSConnection, error) {
	return h.vcsConnectionRepo.OrganizationScope().VCSConnectionForProject(*ws.VCSConnectionID, ws.ProjectID)
}

// CompleteAzureDevOpsInstallation handles the Azure DevOps OAuth2 callback
// POST /api/v2/vcs-connections/azure-devops/callback
func (h *VCSAppInstallationHandlerV2) CompleteAzureDevOpsInstallation(c *gin.Context) {
	code := c.Query("code")
	state := c.Query("state")

	if code == "" {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Missing code parameter")
		return
	}

	if h.azureDevOpsManager == nil || !h.azureDevOpsManager.IsEnabled() {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Configuration Error", "Azure DevOps OAuth is not configured")
		return
	}

	// AUD-155: verify the HMAC-signed state before trusting any field. A missing/forged/expired
	// state (e.g. an attacker-crafted state pointing at a victim org) fails signature verification.
	//
	// The state is also this handler's authorization. The route is registered without the
	// authentication middleware, so there is no caller to check here; what stands in for one is
	// that InitiateAzureDevOpsInstallation issues a state only to someone who holds
	// manage-vcs-settings in the organization it names.
	payload, ok := verifyOAuthState(stateAzureDevOpsInstall, state)
	if !ok {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Invalid or expired state parameter")
		return
	}

	// Decode state payload: "stackweaverOrg|adoOrg|returnPath|uuid"
	stateParts := strings.SplitN(payload, "|", 4)
	if len(stateParts) < 2 {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Invalid state parameter")
		return
	}
	orgName := stateParts[0]
	adoOrgName := stateParts[1]

	if orgName == "" {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Invalid state: missing org name")
		return
	}

	org, err := h.orgRepo.GetByName(orgName)
	if err != nil {
		jsonapi.WriteError(c, http.StatusNotFound, "Not Found", "Organization not found")
		return
	}

	ctx := c.Request.Context()
	tokenResult, err := h.azureDevOpsManager.ExchangeCode(ctx, code)
	if err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", fmt.Sprintf("Failed to exchange authorization code: %v", err))
		return
	}

	// Validate the token against Azure DevOps before saving the connection.
	// This call hits the global VSSPS profile endpoint first (which can trigger identity
	// materialization), then verifies access to the specified organization.
	adoProvider := vcs.NewAzureDevOpsProvider(h.azureDevOpsManager)
	if validationErr := adoProvider.ValidateTokenAndOrg(ctx, tokenResult.AccessToken, adoOrgName); validationErr != nil {
		jsonapi.WriteError(c, http.StatusUnprocessableEntity, "Azure DevOps Access Error", fmt.Sprintf("Token validated but org access failed: %v", validationErr))
		return
	}
	verifiedAt := time.Now()

	var tokenExpiresAt *time.Time
	if tokenResult.ExpiresIn > 0 {
		t := time.Now().Add(time.Duration(tokenResult.ExpiresIn) * time.Second)
		tokenExpiresAt = &t
	}

	// The Azure DevOps organization is the connection's identity (#938): reconnecting it, in any
	// case, refreshes that connection's tokens, and another Azure DevOps organization adds one.
	existing, getErr := h.vcsConnectionRepo.GetByOrganizationProviderAndAccount(org.ID, models.VCSProviderAzureDevOps, adoOrgName)
	// Only "not found" means there is none. Any other error leaves the question unanswered, and
	// creating on it would be refused by the identity index anyway.
	if getErr != nil && !errors.Is(getErr, gorm.ErrRecordNotFound) {
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to check for an existing VCS connection")
		return
	}

	update := func(existing *models.VCSConnection) {
		existing.AccessToken = tokenResult.AccessToken
		existing.RefreshToken = tokenResult.RefreshToken
		existing.TokenExpiresAt = tokenExpiresAt
		if adoOrgName != "" {
			existing.AccountName = adoOrgName
			// ValidateTokenAndOrg above proved these tokens against adoOrgName.
			existing.AccountVerifiedAt = &verifiedAt
		}
		// Encrypt tokens at rest (#95, AUD-005) before persisting. No-op when encryption
		// is disabled. Without this the ADO OAuth callback stored tokens in cleartext,
		// unlike every other VCS connection write path.
		if h.vcsRegistry != nil {
			if err := h.vcsRegistry.EncryptTokens(existing); err != nil {
				jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to encrypt VCS tokens")
				return
			}
		}
		if err := h.vcsConnectionRepo.Update(existing); err != nil {
			jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to update VCS connection")
			return
		}
		jsonapi.WriteDocument(c, http.StatusOK, jsonapi.Resource[VCSConnectionAckAttributes]{
			ID:         existing.ID.String(),
			Type:       "vcs-connections",
			Attributes: VCSConnectionAckAttributes{Provider: existing.Provider, AccountName: existing.AccountName},
		})
	}
	if getErr == nil {
		update(existing)
		return
	}

	connection := &models.VCSConnection{
		OrganizationID: org.ID,
		Provider:       models.VCSProviderAzureDevOps,
		AccessToken:    tokenResult.AccessToken,
		RefreshToken:   tokenResult.RefreshToken,
		TokenExpiresAt: tokenExpiresAt,
		AccountName:    adoOrgName,
		AccountType:    "organization",
	}
	if adoOrgName != "" {
		connection.AccountVerifiedAt = &verifiedAt
	}
	// Encrypt tokens at rest (#95, AUD-005) before persisting - matches the create path
	// in vcs_connections.go. No-op when encryption is disabled.
	if h.vcsRegistry != nil {
		if err := h.vcsRegistry.EncryptTokens(connection); err != nil {
			jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to encrypt VCS tokens")
			return
		}
	}
	if err := h.vcsConnectionRepo.Create(connection); err != nil {
		// A concurrent completion for the same Azure DevOps organization created it first; this
		// one refreshes it.
		if repository.IsUniqueViolation(err) {
			if winner, err := h.vcsConnectionRepo.GetByOrganizationProviderAndAccount(org.ID, models.VCSProviderAzureDevOps, adoOrgName); err == nil {
				update(winner)
				return
			}
		}
		jsonapi.WriteError(c, http.StatusInternalServerError, "Internal Server Error", "Failed to create VCS connection")
		return
	}
	jsonapi.WriteDocument(c, http.StatusCreated, jsonapi.Resource[VCSConnectionAckAttributes]{
		ID:         connection.ID.String(),
		Type:       "vcs-connections",
		Attributes: VCSConnectionAckAttributes{Provider: connection.Provider, AccountName: connection.AccountName},
	})
}

// verifyAzureDevOpsWebhook authenticates an Azure DevOps service-hook delivery via the
// Basic-auth password configured on the subscription (AUD-002). Fails closed: a missing
// secret, missing Basic-auth header, or password mismatch each yield 401.
func (h *VCSAppInstallationHandlerV2) verifyAzureDevOpsWebhook(c *gin.Context) bool {
	secret := h.azureDevOpsManager.GetWebhookSecret()
	if secret == "" {
		logger.Errorf("Azure DevOps webhook rejected: AZURE_DEVOPS_WEBHOOK_SECRET is not configured")
		webhookUnauthorized(c, "webhook authentication is not configured")
		return false
	}
	_, password, ok := c.Request.BasicAuth()
	if !ok {
		webhookUnauthorized(c, "missing webhook credentials")
		return false
	}
	if !hmac.Equal([]byte(password), []byte(secret)) {
		logger.Warnf("Azure DevOps webhook rejected: credential mismatch")
		webhookUnauthorized(c, "invalid webhook credentials")
		return false
	}
	return true
}

// HandleAzureDevOpsWebhook handles Azure DevOps Service Hook events (push and pull request)
// POST /api/v2/vcs-connections/azure-devops/webhook
func (h *VCSAppInstallationHandlerV2) HandleAzureDevOpsWebhook(c *gin.Context) {
	// AUD-002: authenticate the delivery before parsing. Azure DevOps service hooks carry no
	// HMAC; they authenticate with the Basic-auth credential configured on the subscription.
	// Fail closed: reject unless AZURE_DEVOPS_WEBHOOK_SECRET is set and matches the request's
	// Basic-auth password.
	if !h.verifyAzureDevOpsWebhook(c) {
		return // verifyAzureDevOpsWebhook already wrote the 401
	}

	payload, err := c.GetRawData()
	if err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Failed to read webhook payload")
		return
	}

	adoProvider := vcs.NewAzureDevOpsProvider(h.azureDevOpsManager)
	wp, err := adoProvider.ParseWebhookPayload(payload)
	if err != nil {
		logger.Errorf("Failed to parse Azure DevOps webhook payload: %v", err)
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Failed to parse webhook payload")
		return
	}

	logger.Infof("Azure DevOps webhook - eventType=%s, repository=%s, branch=%s, commit=%s, PR=%d",
		wp.EventType, wp.Repository, wp.Branch, wp.Commit, wp.PRNumber)

	switch wp.EventType {
	case "push":
		h.handleAzureDevOpsPushEvent(c, wp, payload)
	case "pull_request":
		h.handleAzureDevOpsPullRequestEvent(c, wp, payload)
	default:
		h.recordAttributed(h.adoAttribution(wp.Organization), nil, fixedSummary("ignored", fmt.Sprintf("Event type %q not handled", wp.EventType)),
			wp.EventType, "azure_devops", wp.Repository, wp.Branch, wp.Commit, http.StatusOK, string(payload))
		response.Message(c, http.StatusOK, fmt.Sprintf("Event type %q ignored", wp.EventType))
	}
}

// handleAzureDevOpsPushEvent handles Azure DevOps git.push events - triggers plan-and-apply runs.
func (h *VCSAppInstallationHandlerV2) handleAzureDevOpsPushEvent(c *gin.Context, wp *vcs.WebhookPayload, payload []byte) {
	// Finding no workspace does not end the delivery: the repository's playbooks and inventories
	// are synced below either way, because an Ansible resource is linked to its repository, not to
	// a workspace.
	workspaces, err := h.workspaceRepo.FindByVCSRepositoryAndBranch(wp.Repository, wp.Branch)
	if err != nil {
		logger.Errorf("Error finding workspaces for %s/%s: %v", wp.Repository, wp.Branch, err)
		workspaces = nil
	}
	// AUD-102 (ADO residual): only trigger workspaces connected through THIS delivery's ADO org.
	workspaces = h.filterWorkspacesByADOOrg(workspaces, wp.Organization)

	filteredWorkspaces := make([]models.Workspace, 0, len(workspaces))
	for _, workspace := range workspaces {
		if len(wp.ChangedFiles) == 0 || h.isWorkspaceAffectedByFiles(workspace, wp.ChangedFiles) {
			filteredWorkspaces = append(filteredWorkspaces, workspace)
		} else {
			logger.Infof("Workspace %s skipped (no changed files in its path)", workspace.ID)
		}
	}

	commitHash := wp.Commit
	branchName := wp.Branch
	committer := wp.Committer

	for _, workspace := range filteredWorkspaces {
		ws := workspace
		run, created, err := h.queueCapturedRun(&ws, captureSpec{commit: commitHash, committer: committer}, func(runs *repository.RunRepository, versions *repository.ConfigurationVersionRepository) {
			terraform.AutoCancelConflictingRuns(runs, ws.ID, models.RunOperationPlanAndApply)
		})
		switch {
		case err != nil:
			logger.Errorf("Azure DevOps push: %v", err)
		case !created:
			logger.Infof("Azure DevOps push: workspace %s already has a run at %s", ws.ID, commitHash)
		default:
			logger.Infof("Created run %s for workspace %s (ADO push, commit %s)", run.ID, ws.ID, commitHash)
		}
	}

	// Sync inventories and playbooks for the repo and branch, whether or not a workspace matched.
	// When the delivery lists the changed files, the same path checks as a GitHub push apply
	// (Azure DevOps paths start with "/"); a delivery that lists none syncs every one, as it
	// triggers every workspace.
	changed := make([]string, 0, len(wp.ChangedFiles))
	for _, f := range wp.ChangedFiles {
		changed = append(changed, strings.TrimPrefix(f, "/"))
	}
	changedCommits := []pushCommitFiles{{Modified: changed}}
	syncedInventories, syncedPlaybooks := 0, 0
	attribution := h.adoAttribution(wp.Organization)
	reached := tallies{}
	attribution.addWorkspaces(reached, filteredWorkspaces)
	inventories, _ := h.inventoryRepo.FindByVCSRepositoryAndBranch(wp.Repository, branchName)
	// AUD-102 (ADO residual): only sync inventories connected through THIS delivery's ADO org.
	for _, inventory := range h.filterInventoriesByADOOrg(inventories, wp.Organization) {
		if len(changed) > 0 && !h.isInventoryAffected(inventory, changedCommits) {
			continue
		}
		inv := inventory
		syncedInventories++
		attribution.tally(reached, inv.VCSConnectionID).inventories++
		h.requestInventorySync(&inv)
	}
	if h.playbookRepo != nil {
		playbooks, _ := h.playbookRepo.ListByVCSRepositoryAndBranch(wp.Repository, branchName)
		// Only sync playbooks connected through THIS delivery's Azure DevOps organization.
		for _, playbook := range h.filterPlaybooksByADOOrg(playbooks, wp.Organization) {
			if len(changed) > 0 && !h.isPlaybookAffected(playbook, changedCommits) {
				continue
			}
			pb := playbook
			syncedPlaybooks++
			attribution.tally(reached, pb.VCSConnectionID).playbooks++
			h.requestPlaybookSync(&pb)
			h.launchWebhookTemplates(pb.ID, pb.Name, wp.Repository, branchName)
		}
	}

	_, eventMessage := pushEventSummary(filteredWorkspaces, syncedPlaybooks, syncedInventories)
	h.recordAttributed(attribution, reached, pushTallySummary,
		"push", "azure_devops", wp.Repository, branchName, commitHash, http.StatusOK, string(payload))

	response.Message(c, http.StatusOK, "Azure DevOps push event processed: "+eventMessage)
}

// handleAzureDevOpsPullRequestEvent handles Azure DevOps git.pullrequest.* events - triggers speculative plan runs.
func (h *VCSAppInstallationHandlerV2) handleAzureDevOpsPullRequestEvent(c *gin.Context, wp *vcs.WebhookPayload, payload []byte) {
	if wp.BaseBranch == "" || wp.HeadBranch == "" {
		logger.Infof("Azure DevOps PR event missing base/head branch, ignoring")
		response.Message(c, http.StatusOK, "PR event missing branch info, ignored")
		return
	}

	logger.Infof("Azure DevOps PR #%d: head=%s -> base=%s, commit=%s, repo=%s",
		wp.PRNumber, wp.HeadBranch, wp.BaseBranch, wp.Commit, wp.Repository)

	// Find workspaces that match the target (base) branch with speculative plans enabled
	workspaces, err := h.workspaceRepo.FindByVCSRepositoryAndBranch(wp.Repository, wp.BaseBranch)
	if err != nil {
		logger.Errorf("Error finding workspaces for %s/%s: %v", wp.Repository, wp.BaseBranch, err)
		response.Message(c, http.StatusOK, fmt.Sprintf("No workspaces found: %v", err))
		return
	}
	// AUD-102 (ADO residual): only trigger workspaces connected through THIS delivery's ADO org.
	workspaces = h.filterWorkspacesByADOOrg(workspaces, wp.Organization)

	// Filter to workspaces with speculative plans enabled
	filteredWorkspaces := make([]models.Workspace, 0, len(workspaces))
	for _, ws := range workspaces {
		if ws.SpeculativeEnabled {
			filteredWorkspaces = append(filteredWorkspaces, ws)
		}
	}

	if len(filteredWorkspaces) == 0 {
		h.recordAttributed(h.adoAttribution(wp.Organization), nil, fixedSummary("ignored", "No workspaces with speculative plans enabled"),
			"pull_request", "azure_devops", wp.Repository, wp.BaseBranch, wp.Commit, http.StatusOK, string(payload))
		response.Message(c, http.StatusOK, "No workspaces with speculative plans enabled")
		return
	}

	// Path-based filtering using changed files (if available)
	if len(wp.ChangedFiles) > 0 {
		pathFiltered := make([]models.Workspace, 0, len(filteredWorkspaces))
		for _, ws := range filteredWorkspaces {
			if h.isWorkspaceAffectedByFiles(ws, wp.ChangedFiles) {
				pathFiltered = append(pathFiltered, ws)
			}
		}
		// tfe_organization send_passing_statuses_for_untriggered_speculative_plans (ADO): skipped
		// workspaces still get a passing PR status when their org opts in.
		h.postUntriggeredPassingStatusesADO(context.Background(),
			splitUntriggeredWorkspaces(filteredWorkspaces, pathFiltered), wp.PRNumber)
		if len(pathFiltered) == 0 {
			h.recordAttributed(h.adoAttribution(wp.Organization), nil,
				fixedSummary("ignored", "No workspace with speculative plans enabled matches the changed files"),
				"pull_request", "azure_devops", wp.Repository, wp.BaseBranch, wp.Commit, http.StatusOK, string(payload))
			response.Message(c, http.StatusOK, "No workspaces match the changed files")
			return
		}
		filteredWorkspaces = pathFiltered
	}

	logger.Infof("Azure DevOps PR #%d: triggering speculative plans for %d workspace(s)", wp.PRNumber, len(filteredWorkspaces))

	commitHash := wp.Commit

	for _, workspace := range filteredWorkspaces {
		ws := workspace
		// The source branch's head is fetched by its ref: a pull request's commit need not be on the
		// workspace's branch.
		run, created, err := h.queueCapturedRun(&ws, captureSpec{
			commit: commitHash, fetchRef: "refs/heads/" + wp.HeadBranch, committer: wp.Committer,
			sourceBranch: wp.HeadBranch, prNumber: wp.PRNumber, speculative: true,
		}, func(runs *repository.RunRepository, versions *repository.ConfigurationVersionRepository) {
			// tfe_organization speculative_plan_management_enabled (default on): cancel superseded
			// speculative plans for this branch/PR before queueing the new one.
			if wsOrg := h.orgForWorkspace(&ws); wsOrg == nil || wsOrg.SpeculativePlanManagement() {
				terraform.AutoCancelSupersededSpeculativeRuns(runs, versions, ws.ID, wp.HeadBranch, wp.PRNumber)
			}
		})
		if err != nil {
			logger.Errorf("Azure DevOps PR #%d: %v", wp.PRNumber, err)
			continue
		}
		if !created {
			logger.Infof("Azure DevOps PR #%d: workspace %s already has a run at %s", wp.PRNumber, ws.ID, commitHash)
			continue
		}
		logger.Infof("Created speculative run %s for workspace %s (ADO PR #%d, commit %s)",
			run.ID, ws.ID, wp.PRNumber, commitHash)

		var vcsConn *models.VCSConnection
		if ws.VCSConnectionID != nil {
			if vcsConn, err = h.workspaceConnection(&ws); err != nil {
				logger.Errorf("Failed to get VCS connection for workspace %s: %v", ws.ID, err)
				continue
			}
		}
		// The pending status is posted in the background, so the delivery is answered at once.
		go func(ws models.Workspace, run *models.Run, vcsConn *models.VCSConnection) {
			defer func() {
				if r := recover(); r != nil {
					logger.Errorf("PANIC posting the ADO PR status for workspace %s: %v", ws.ID, r)
				}
			}()
			ctx := context.Background()
			var err error

			// Create Azure DevOps PR status check (pending)
			if h.adoStatusService != nil && vcsConn != nil && wp.PRNumber > 0 {
				repoPath := ws.VCSRepository
				if repoPath == "" {
					repoPath = wp.Repository
				}
				repoParts := strings.SplitN(repoPath, "/", 2)
				if len(repoParts) == 2 {
					// Generate target URL for the status check
					baseURL := os.Getenv("STACKWEAVER_BASE_URL")
					if baseURL == "" {
						baseURL = "http://localhost:5173"
					}
					workspaceForURL, urlErr := h.workspaceRepo.GetByID(ws.ID)
					var targetURL string
					if urlErr == nil && workspaceForURL.Project.Organization.Name != "" {
						targetURL = fmt.Sprintf("%s/app/%s/workspaces/%s/runs/%s", baseURL, workspaceForURL.Project.Organization.Name, workspaceForURL.Name, run.ID)
					} else {
						targetURL = fmt.Sprintf("%s/workspaces/%s/runs/%s", baseURL, ws.ID, run.ID)
					}

					statusContext := fmt.Sprintf("terraform-plan/%s", ws.Name)
					if wsOrg := h.orgForWorkspace(&ws); wsOrg != nil && wsOrg.AggregatedCommitStatusEnabled {
						// tfe_organization aggregated_commit_status_enabled: one rolled-up context.
						statusContext = "terraform-plan"
					}
					token, tokenErr := func() (string, error) {
						if h.vcsRegistry != nil {
							if provider, pErr := h.vcsRegistry.GetProvider(vcsConn); pErr == nil {
								return provider.GetFreshToken(ctx, vcsConn)
							}
						}
						return vcsConn.AccessToken, nil
					}()
					if tokenErr == nil {
						err = h.adoStatusService.CreateOrUpdatePRStatus(
							ctx,
							token,
							vcsConn.AccountName,
							repoParts[0],
							repoParts[1],
							wp.PRNumber,
							vcs.StatusStatePending,
							statusContext,
							"Terraform plan is queued",
							targetURL,
						)
						if err != nil {
							logger.Errorf("Failed to create ADO PR status for run %s: %v", run.ID, err)
						} else {
							logger.Infof("Created ADO PR status for run %s (PR #%d, commit %s)", run.ID, wp.PRNumber, commitHash)
						}
					}
				}
			}
		}(ws, run, vcsConn)
	}

	adoPRAttribution := h.adoAttribution(wp.Organization)
	adoPRReached := tallies{}
	adoPRAttribution.addWorkspaces(adoPRReached, filteredWorkspaces)
	h.recordAttributed(adoPRAttribution, adoPRReached, pullRequestTallySummary(wp.PRNumber),
		"pull_request", "azure_devops", wp.Repository, wp.BaseBranch, commitHash, http.StatusOK, string(payload))

	response.Message(c, http.StatusOK, fmt.Sprintf("Azure DevOps PR event processed: %d workspace(s) queued for speculative plans", len(filteredWorkspaces)))
}

// adoConnectionTrusted reports whether a delivery from the Azure DevOps organization adoOrg may
// reach conn. The connection must be an Azure DevOps connection for that organization, and its
// token must have proven access to it. The OAuth flow and the direct-create API prove it when the
// connection is made. A connection without the mark proves it here, once, with its stored token,
// and keeps the mark on success. Without the proof, anyone could create a connection naming
// another tenant's Azure DevOps organization and receive its deliveries. Fails closed.
func (h *VCSAppInstallationHandlerV2) adoConnectionTrusted(ctx context.Context, conn *models.VCSConnection, adoOrg string) bool {
	if conn == nil || conn.Provider != models.VCSProviderAzureDevOps || adoOrg == "" || !strings.EqualFold(conn.AccountName, adoOrg) {
		return false
	}
	if conn.AccountVerifiedAt != nil {
		return true
	}
	verify := h.verifyADOAccount
	if verify == nil {
		verify = h.verifyADOAccountWithToken
	}
	if err := verify(ctx, conn); err != nil {
		logger.Warnf("webhook: Azure DevOps connection %s has not proven access to %q; skipping: %v", conn.ID, conn.AccountName, err)
		return false
	}
	now := time.Now()
	if err := h.vcsConnectionRepo.MarkAccountVerified(conn.ID, now); err != nil {
		logger.Warnf("webhook: recording the verification of Azure DevOps connection %s: %v", conn.ID, err)
	}
	conn.AccountVerifiedAt = &now
	return true
}

// adoAccountValidator is the Azure DevOps provider's account check, declared where it is used.
type adoAccountValidator interface {
	ValidateTokenAndOrg(ctx context.Context, token, org string) error
}

// verifyADOAccountWithToken proves the connection's stored token against its Azure DevOps
// organization, refreshing the token first when needed.
func (h *VCSAppInstallationHandlerV2) verifyADOAccountWithToken(ctx context.Context, conn *models.VCSConnection) error {
	if h.vcsRegistry == nil {
		return errors.New("no VCS provider registry")
	}
	// GetProvider decrypts the tokens in place, so work on a copy and leave conn as loaded.
	c := *conn
	provider, err := h.vcsRegistry.GetProvider(&c)
	if err != nil {
		return fmt.Errorf("getting the provider: %w", err)
	}
	validator, ok := provider.(adoAccountValidator)
	if !ok {
		return errors.New("provider cannot validate an Azure DevOps account")
	}
	token, err := provider.GetFreshToken(ctx, &c)
	if err != nil {
		return fmt.Errorf("getting a fresh token: %w", err)
	}
	return validator.ValidateTokenAndOrg(ctx, token, c.AccountName)
}

// recordWebhookEvent records a webhook event for debugging and auditing, in the organization
// the delivery was proven to come from: one connected through its GitHub App installation or its
// Azure DevOps organization (recordAttributed calls it once per such organization). Without such
// an organization the event is recorded with none.
//
// It never guesses an organization from the repository name. Repository names are not unique
// across Azure DevOps organizations, and anyone can name a repository after another's, so a
// guess files one tenant's deliveries, payload included, into another tenant's event log.
func (h *VCSAppInstallationHandlerV2) recordWebhookEvent(trustedOrgID *uuid.UUID, eventType, provider, repoFullName, branch, commit, status, message string, responseCode int, payload string) {
	if h.webhookEventRepo == nil {
		return
	}

	orgID := trustedOrgID
	if orgID == nil {
		logger.Infof("Webhook delivery for repository %s comes from no connected installation or organization, recording without org", repoFullName)
	}

	event := &models.WebhookEvent{
		OrganizationID: orgID,
		EventType:      eventType,
		Provider:       provider,
		Repository:     repoFullName,
		Branch:         branch,
		Commit:         commit,
		Status:         status,
		ResponseCode:   responseCode,
		Message:        message,
		Payload:        payload,
		DeliveredAt:    time.Now(),
	}

	if err := h.webhookEventRepo.Create(event); err != nil {
		logger.Errorf("Failed to record webhook event: %v", err)
	}
}

// webhookUnauthorized writes a JSON:API 401 for a rejected webhook delivery.
func webhookUnauthorized(c *gin.Context, detail string) {
	jsonapi.WriteError(c, http.StatusUnauthorized, "Unauthorized", detail)
}

// verifyGitHubWebhook authenticates an incoming GitHub webhook via HMAC-SHA256 of the raw
// body against the configured secret (AUD-002). It fails closed: a missing secret, a missing
// X-Hub-Signature-256 header, or a signature mismatch each yield 401. Returns true only when
// the delivery is authentic.
func (h *VCSAppInstallationHandlerV2) verifyGitHubWebhook(c *gin.Context, payload []byte) bool {
	secret := ""
	if h.githubAppManager != nil {
		secret = h.githubAppManager.GetWebhookSecret()
	}
	if secret == "" {
		logger.Errorf("GitHub webhook rejected: GITHUB_WEBHOOK_SECRET is not configured")
		webhookUnauthorized(c, "webhook signature verification is not configured")
		return false
	}
	signature := c.GetHeader("X-Hub-Signature-256")
	if signature == "" {
		webhookUnauthorized(c, "missing webhook signature")
		return false
	}
	if !validGitHubSignature(payload, signature, secret) {
		logger.Warnf("GitHub webhook rejected: signature mismatch")
		webhookUnauthorized(c, "invalid webhook signature")
		return false
	}
	return true
}

// validGitHubSignature reports whether signatureHeader ("sha256=<hex>") is a valid HMAC-SHA256
// of payload under secret, compared in constant time.
func validGitHubSignature(payload []byte, signatureHeader, secret string) bool {
	const prefix = "sha256="
	if !strings.HasPrefix(signatureHeader, prefix) {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	expected := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(signatureHeader[len(prefix):]), []byte(expected))
}

// filterWorkspacesByInstallation drops workspaces whose VCS connection does not belong to the
// webhook delivery's GitHub App installation (AUD-102). Matching by repo full_name + branch
// alone lets an attacker who installs the app on a same-named repo trigger runs in a victim
// org (VCS runs auto-apply); binding to the installation the workspace was actually connected
// through closes that. A workspace with no connection, an unloadable connection, or a
// mismatched/empty installation id is skipped and logged, never run.
func (h *VCSAppInstallationHandlerV2) filterWorkspacesByInstallation(workspaces []models.Workspace, installationID string) []models.Workspace {
	kept := make([]models.Workspace, 0, len(workspaces))
	for _, ws := range workspaces {
		if ws.VCSConnectionID == nil {
			logger.Warnf("webhook: workspace %s has no VCS connection; skipping (AUD-102)", ws.ID)
			continue
		}
		conn, err := h.workspaceConnection(&ws)
		if err != nil || conn == nil {
			logger.Warnf("webhook: workspace %s VCS connection load failed; skipping", ws.ID)
			continue
		}
		if conn.InstallationID == "" || conn.InstallationID != installationID {
			logger.Warnf("webhook: workspace %s connection installation %q != delivery installation %q; skipping cross-org trigger (AUD-102)", ws.ID, conn.InstallationID, installationID)
			continue
		}
		kept = append(kept, ws)
	}
	return kept
}

// filterInventoriesByInstallation is the ansible counterpart of filterWorkspacesByInstallation
// (AUD-102): it drops VCS inventories whose connection is not the delivery's installation, so a
// forged/foreign push cannot trigger another org's inventory sync (which runs cloud inventory
// plugins with that org's credentials).
func (h *VCSAppInstallationHandlerV2) filterInventoriesByInstallation(inventories []models.AnsibleInventory, installationID string) []models.AnsibleInventory {
	kept := make([]models.AnsibleInventory, 0, len(inventories))
	for _, inv := range inventories {
		if inv.VCSConnectionID == nil {
			continue
		}
		conn, err := h.inventoryConnection(context.Background(), &inv)
		if err != nil || conn == nil || conn.InstallationID == "" || conn.InstallationID != installationID {
			logger.Warnf("webhook: inventory %s connection installation does not match delivery installation %q; skipping (AUD-102)", inv.ID, installationID)
			continue
		}
		kept = append(kept, inv)
	}
	return kept
}

// filterWorkspacesByADOOrg is the Azure DevOps analogue of filterWorkspacesByInstallation
// (AUD-102 ADO residual). ADO has no installation id, but each connection is bound to one ADO
// organization (conn.AccountName), and the org is recoverable from the delivery's repository
// remoteUrl. Keep only workspaces whose connection is an ADO connection for the delivery's org
// - a same-named project/repo in another ADO org (all of which share the one webhook secret)
// can no longer inject runs. Fails closed: an empty/unresolved org keeps nothing.
func (h *VCSAppInstallationHandlerV2) filterWorkspacesByADOOrg(workspaces []models.Workspace, adoOrg string) []models.Workspace {
	kept := make([]models.Workspace, 0, len(workspaces))
	for _, ws := range workspaces {
		if ws.VCSConnectionID == nil {
			logger.Warnf("webhook: workspace %s has no VCS connection; skipping (AUD-102 ADO)", ws.ID)
			continue
		}
		conn, err := h.workspaceConnection(&ws)
		if err != nil || conn == nil {
			logger.Warnf("webhook: workspace %s VCS connection load failed; skipping", ws.ID)
			continue
		}
		if !h.adoConnectionTrusted(context.Background(), conn, adoOrg) {
			logger.Warnf("webhook: workspace %s connection ADO org %q != delivery org %q; skipping cross-org trigger (AUD-102 ADO)", ws.ID, conn.AccountName, adoOrg)
			continue
		}
		kept = append(kept, ws)
	}
	return kept
}

// filterInventoriesByADOOrg is the ansible-inventory counterpart of filterWorkspacesByADOOrg.
func (h *VCSAppInstallationHandlerV2) filterInventoriesByADOOrg(inventories []models.AnsibleInventory, adoOrg string) []models.AnsibleInventory {
	kept := make([]models.AnsibleInventory, 0, len(inventories))
	for _, inv := range inventories {
		if inv.VCSConnectionID == nil {
			continue
		}
		conn, err := h.inventoryConnection(context.Background(), &inv)
		if err != nil || !h.adoConnectionTrusted(context.Background(), conn, adoOrg) {
			logger.Warnf("webhook: inventory %s connection ADO org does not match delivery org %q; skipping (AUD-102 ADO)", inv.ID, adoOrg)
			continue
		}
		kept = append(kept, inv)
	}
	return kept
}

// playbookConnection loads the VCS connection a playbook names, within the organization of the
// playbook's project. A playbook row that names another organization's connection gets none.
// The playbook must name a connection.
func (h *VCSAppInstallationHandlerV2) playbookConnection(ctx context.Context, pb *models.AnsiblePlaybook) (*models.VCSConnection, error) {
	return coreansible.PlaybookVCSConnection(h.vcsConnectionRepo.OrganizationScope().WithContext(ctx), pb.ProjectID, *pb.VCSConnectionID)
}

// filterPlaybooksByInstallation keeps the playbooks connected through the delivery's GitHub App
// installation, as filterWorkspacesByInstallation does for workspaces. A push syncs a matched
// playbook and launches its webhook-enabled job templates, so a playbook matched by repository
// name alone would let a delivery for one installation run another organization's jobs.
func (h *VCSAppInstallationHandlerV2) filterPlaybooksByInstallation(playbooks []models.AnsiblePlaybook, installationID string) []models.AnsiblePlaybook {
	kept := make([]models.AnsiblePlaybook, 0, len(playbooks))
	for _, pb := range playbooks {
		if pb.VCSConnectionID == nil {
			continue
		}
		conn, err := h.playbookConnection(context.Background(), &pb)
		if err != nil || conn == nil || conn.InstallationID == "" || conn.InstallationID != installationID {
			logger.Warnf("webhook: playbook %s connection installation does not match delivery installation %q; skipping", pb.ID, installationID)
			continue
		}
		kept = append(kept, pb)
	}
	return kept
}

// filterPlaybooksByADOOrg is the Azure DevOps counterpart of filterPlaybooksByInstallation. Azure
// DevOps repository names (project/repository) are only unique within one Azure DevOps
// organization, so this binding is what tells two tenants' same-named repositories apart. Fails
// closed: an empty or unresolved delivery organization keeps nothing.
func (h *VCSAppInstallationHandlerV2) filterPlaybooksByADOOrg(playbooks []models.AnsiblePlaybook, adoOrg string) []models.AnsiblePlaybook {
	kept := make([]models.AnsiblePlaybook, 0, len(playbooks))
	for _, pb := range playbooks {
		if pb.VCSConnectionID == nil {
			continue
		}
		conn, err := h.playbookConnection(context.Background(), &pb)
		if err != nil || !h.adoConnectionTrusted(context.Background(), conn, adoOrg) {
			logger.Warnf("webhook: playbook %s connection Azure DevOps organization does not match delivery organization %q; skipping", pb.ID, adoOrg)
			continue
		}
		kept = append(kept, pb)
	}
	return kept
}

// filterModulesByInstallation keeps the registry modules connected through the delivery's GitHub
// App installation. A tag push publishes a version of every matched module, so a module matched
// by repository name alone would publish into another organization's registry.
func (h *VCSAppInstallationHandlerV2) filterModulesByInstallation(modules []models.Module, installationID string) []models.Module {
	kept := make([]models.Module, 0, len(modules))
	for _, m := range modules {
		if m.VCSConnectionID == nil {
			continue
		}
		conn, err := h.vcsConnectionRepo.OrganizationScope().VCSConnection(*m.VCSConnectionID, m.OrganizationID)
		if err != nil || conn == nil || conn.InstallationID == "" || conn.InstallationID != installationID {
			logger.Warnf("webhook: module %s connection installation does not match delivery installation %q; skipping", m.ID, installationID)
			continue
		}
		kept = append(kept, m)
	}
	return kept
}

// HandleInstallationWebhook handles GitHub App installation webhook events
// POST /api/v2/vcs-connections/github/webhook
func (h *VCSAppInstallationHandlerV2) HandleInstallationWebhook(c *gin.Context) {
	logger.Infof("Received webhook request - Method: %s, Path: %s", c.Request.Method, c.Request.URL.Path)

	// Verify webhook signature
	payload, err := c.GetRawData()
	if err != nil {
		logger.Errorf("Failed to read webhook payload: %v", err)
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Failed to read webhook payload")
		return
	}

	logger.Infof("Received payload (size: %d bytes)", len(payload))

	// AUD-002: authenticate the delivery via HMAC-SHA256 of the raw body BEFORE parsing
	// anything. This webhook secret is the only authentication on the endpoint - without
	// this check an unauthenticated attacker could forge push/PR events and trigger
	// plan-and-apply runs. Fail closed: reject when the secret is unset or the signature is
	// missing/invalid (the routes sit outside the auth middleware group).
	if !h.verifyGitHubWebhook(c, payload) {
		return // verifyGitHubWebhook already wrote the 401
	}

	// Parse webhook event
	eventType := c.GetHeader("X-GitHub-Event")
	logger.Infof("Event type: %s", eventType)

	// Handle push events (both tag pushes for modules and branch pushes for workspaces)
	if eventType == "push" {
		// First check if it's a tag push (for module publishing)
		var pushEvent struct {
			Ref string `json:"ref"`
		}
		if err := json.Unmarshal(payload, &pushEvent); err == nil {
			if strings.HasPrefix(pushEvent.Ref, "refs/tags/") {
				// Tag push - handle module publishing
				h.handlePushEvent(c, payload)
				return
			} else if strings.HasPrefix(pushEvent.Ref, "refs/heads/") {
				// Branch push - handle workspace runs
				h.handleBranchPushEvent(c, payload)
				return
			}
		}
		// Fallback to old handler for tag pushes
		h.handlePushEvent(c, payload)
		return
	}

	// Handle pull request events (for speculative plans and status checks)
	if eventType == "pull_request" {
		h.handlePullRequestEvent(c, payload)
		return
	}

	if eventType != "installation" && eventType != "installation_repositories" {
		// Ignore other event types
		response.Message(c, http.StatusOK, "Event ignored")
		return
	}

	var installationEvent struct {
		Action       string `json:"action"`
		Installation struct {
			ID                  int64  `json:"id"`
			RepositorySelection string `json:"repository_selection"` // "all" or "selected"
			Repositories        []struct {
				ID   int64  `json:"id"`
				Name string `json:"name"`
			} `json:"repositories,omitempty"`
		} `json:"installation"`
		RepositoriesAdded []struct {
			ID   int64  `json:"id"`
			Name string `json:"name"`
		} `json:"repositories_added,omitempty"`
		RepositoriesRemoved []struct {
			ID   int64  `json:"id"`
			Name string `json:"name"`
		} `json:"repositories_removed,omitempty"`
		Sender struct {
			Login string `json:"login"`
		} `json:"sender"`
	}

	if err := json.Unmarshal(payload, &installationEvent); err != nil {
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Failed to parse webhook payload")
		return
	}

	installationID := strconv.FormatInt(installationEvent.Installation.ID, 10)

	// Handle different installation events
	switch installationEvent.Action {
	case "created":
		// Acknowledged, and nothing else. A connection is made through the interactive flow:
		// InitiateInstallation sends a signed-in user to GitHub, and
		// CreateConnectionFromInstallation records the installation they came back with for
		// the organization they named.
		//
		// This used to connect the organization whose name equalled the installing account's
		// login. A delivery proves only that some GitHub account installed the app, and on an
		// app installable by any account that is anyone who holds a login equal to an
		// organization's name. Do not derive an organization from the payload here.
		c.Status(http.StatusOK)

	case "deleted":
		// The installation is gone from GitHub, so it goes from every organization that connected
		// it (#938); their workspaces, modules, playbooks and inventories are detached.
		deleted, err := h.vcsConnectionRepo.DeleteByInstallationID(installationID)
		if err != nil {
			logger.Errorf("Removing the connections on uninstalled installation %s: %v", installationID, err)
			jsonapi.WriteErrorNoDetail(c, http.StatusInternalServerError, "Internal Server Error")
			return
		}
		logger.Infof("Installation %s was uninstalled; removed %d connection(s)", installationID, len(deleted))
		response.Message(c, http.StatusOK, "Installation deleted")

	case "suspend":
		// Installation suspended - mark as inactive
		connections, _ := h.vcsConnectionRepo.ListByProvider(models.VCSProviderGitHub)
		for _, conn := range connections {
			if conn.InstallationID == installationID {
				// TODO: Add status field to mark as suspended
				break
			}
		}
		response.Message(c, http.StatusOK, "Installation suspended")

	case "unsuspend":
		// Installation unsuspended - mark as active
		connections, _ := h.vcsConnectionRepo.ListByProvider(models.VCSProviderGitHub)
		for _, conn := range connections {
			if conn.InstallationID == installationID {
				// TODO: Add status field to mark as active
				break
			}
		}
		response.Message(c, http.StatusOK, "Installation unsuspended")

	default:
		response.Message(c, http.StatusOK, "Event processed")
	}
}

// handlePushEvent handles GitHub push events for tag-based module publishing
func (h *VCSAppInstallationHandlerV2) handlePushEvent(c *gin.Context, payload []byte) {
	if h.registryPublisher == nil || h.moduleRepo == nil {
		logger.Infof("Registry publishing not configured (registryPublisher=%v, moduleRepo=%v)", h.registryPublisher != nil, h.moduleRepo != nil)
		response.Message(c, http.StatusOK, "Registry publishing not configured")
		return
	}

	var pushEvent struct {
		Ref        string `json:"ref"`
		RefType    string `json:"ref_type"`
		Repository struct {
			FullName string `json:"full_name"`
			ID       int64  `json:"id"`
		} `json:"repository"`
		Installation struct {
			ID int64 `json:"id"`
		} `json:"installation"`
	}

	if err := json.Unmarshal(payload, &pushEvent); err != nil {
		logger.Errorf("Failed to parse push event: %v", err)
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Failed to parse push event")
		return
	}

	logger.Infof("Received push event - ref=%s, repository=%s", pushEvent.Ref, pushEvent.Repository.FullName)

	// Only process tag push events
	if !strings.HasPrefix(pushEvent.Ref, "refs/tags/") {
		logger.Infof("Not a tag push event (ref=%s)", pushEvent.Ref)
		response.Message(c, http.StatusOK, "Not a tag push event")
		return
	}

	// Extract tag name
	tagName := strings.TrimPrefix(pushEvent.Ref, "refs/tags/")
	repositoryFullName := pushEvent.Repository.FullName

	logger.Infof("Processing tag push - tag=%s, repository=%s", tagName, repositoryFullName)

	// Find modules connected to this repository with auto-publish enabled
	modules, err := h.moduleRepo.FindByVCSRepository(repositoryFullName)
	if err != nil {
		logger.Errorf("Error finding modules for repository %s: %v", repositoryFullName, err)
		response.Message(c, http.StatusOK, fmt.Sprintf("No modules found for repository: %v", err))
		return
	}
	// Only modules connected through this delivery's installation publish its tag.
	modules = h.filterModulesByInstallation(modules, strconv.FormatInt(pushEvent.Installation.ID, 10))

	if len(modules) == 0 {
		logger.Infof("No modules found for repository %s (auto-publish enabled)", repositoryFullName)
		response.Message(c, http.StatusOK, "No modules found for repository")
		return
	}

	logger.Infof("Found %d module(s) for repository %s", len(modules), repositoryFullName)

	// Process each module
	successCount := 0
	for _, module := range modules {
		if !module.AutoPublishTags {
			logger.Infof("Module %s/%s/%s has auto-publish disabled, skipping", module.Organization.Name, module.Name, module.Provider)
			continue
		}

		logger.Infof("Publishing module %s/%s/%s version from tag %s", module.Organization.Name, module.Name, module.Provider, tagName)

		// Publish version from Git tag
		if err := h.registryPublisher.PublishFromGitTag(
			c.Request.Context(),
			module.ID,
			tagName,
			repositoryFullName,
		); err != nil {
			// Log error but continue processing other modules
			logger.Errorf("Failed to publish module %s/%s/%s from tag %s: %v", module.Organization.Name, module.Name, module.Provider, tagName, err)
			continue
		}

		successCount++
		logger.Infof("Successfully published module %s/%s/%s version from tag %s", module.Organization.Name, module.Name, module.Provider, tagName)
	}

	response.Message(c, http.StatusOK, fmt.Sprintf("Tag push event processed: %d module(s) published", successCount))
}

// handleBranchPushEvent handles GitHub branch push events for workspace runs
// TFE-compatible: Creates plan runs (and apply runs if auto-apply enabled) when code is pushed to the default branch
func (h *VCSAppInstallationHandlerV2) handleBranchPushEvent(c *gin.Context, payload []byte) {
	var pushEvent struct {
		Ref        string `json:"ref"`
		After      string `json:"after"` // Commit SHA
		Repository struct {
			FullName string `json:"full_name"`
			ID       int64  `json:"id"`
		} `json:"repository"`
		Installation struct {
			ID int64 `json:"id"`
		} `json:"installation"`
		Commits []struct {
			ID       string   `json:"id"`
			Message  string   `json:"message"`
			Added    []string `json:"added"`
			Removed  []string `json:"removed"`
			Modified []string `json:"modified"`
			Author   struct {
				Name  string `json:"name"`
				Email string `json:"email"`
			} `json:"author"`
		} `json:"commits"`
		Pusher struct {
			Name  string `json:"name"`
			Email string `json:"email"`
		} `json:"pusher"`
	}

	if err := json.Unmarshal(payload, &pushEvent); err != nil {
		logger.Errorf("Failed to parse branch push event: %v", err)
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Failed to parse push event")
		return
	}

	// Extract branch name from ref (e.g., "refs/heads/main" -> "main")
	branchName := strings.TrimPrefix(pushEvent.Ref, "refs/heads/")
	repositoryFullName := pushEvent.Repository.FullName
	commitHash := pushEvent.After
	committer := ""
	if len(pushEvent.Commits) > 0 {
		// Use the last commit's author as committer
		lastCommit := pushEvent.Commits[len(pushEvent.Commits)-1]
		committer = fmt.Sprintf("%s <%s>", lastCommit.Author.Name, lastCommit.Author.Email)
	} else if pushEvent.Pusher.Email != "" {
		committer = fmt.Sprintf("%s <%s>", pushEvent.Pusher.Name, pushEvent.Pusher.Email)
	}

	logger.Infof("Received branch push event - ref=%s, branch=%s, repository=%s, commit=%s", pushEvent.Ref, branchName, repositoryFullName, commitHash)

	installationID := strconv.FormatInt(pushEvent.Installation.ID, 10)

	// Collect all changed files from commits for path-based filtering
	commitsForCheck := make([]pushCommitFiles, len(pushEvent.Commits))
	allChangedFilesList := make([]string, 0)
	for i, commit := range pushEvent.Commits {
		commitsForCheck[i] = pushCommitFiles{Added: commit.Added, Removed: commit.Removed, Modified: commit.Modified}
		allChangedFilesList = append(allChangedFilesList, commit.Added...)
		allChangedFilesList = append(allChangedFilesList, commit.Modified...)
		allChangedFilesList = append(allChangedFilesList, commit.Removed...)
	}
	logger.Infof("Changed files in push: %v", allChangedFilesList)

	// Find workspaces that match this repository and branch with AutoQueueRuns enabled. Finding
	// none does not end the delivery: the repository's playbooks and inventories are synced below
	// either way, because an Ansible resource is linked to its repository, not to a workspace.
	workspaces, err := h.workspaceRepo.FindByVCSRepositoryAndBranch(repositoryFullName, branchName)
	if err != nil {
		logger.Errorf("Error finding workspaces for repository %s, branch %s: %v", repositoryFullName, branchName, err)
		workspaces = nil
	}
	// AUD-102: only trigger workspaces connected through THIS delivery's installation.
	workspaces = h.filterWorkspacesByInstallation(workspaces, installationID)
	logger.Infof("Found %d workspace(s) for repository %s, branch %s", len(workspaces), repositoryFullName, branchName)

	// Filter workspaces based on changed files and their WorkingDirectory paths (GitOps-style filtering)
	filteredWorkspaces := make([]models.Workspace, 0)
	for _, workspace := range workspaces {
		if h.isWorkspaceAffected(workspace, commitsForCheck) {
			filteredWorkspaces = append(filteredWorkspaces, workspace)
			logger.Infof("Workspace %s (path: %q) will be triggered - files in its path were changed", workspace.ID, workspace.WorkingDirectory)
		} else {
			logger.Infof("Workspace %s (path: %q) skipped - no files in its path were changed", workspace.ID, workspace.WorkingDirectory)
		}
	}

	for _, workspace := range filteredWorkspaces {
		ws := workspace
		// TFE-compatible: a VCS push runs plan and apply, after cancelling the workspace's other
		// pending plan-and-apply runs (the same auto-cancel a UI-triggered run applies).
		run, created, err := h.queueCapturedRun(&ws, captureSpec{commit: commitHash, committer: committer}, func(runs *repository.RunRepository, versions *repository.ConfigurationVersionRepository) {
			terraform.AutoCancelConflictingRuns(runs, ws.ID, models.RunOperationPlanAndApply)
		})
		switch {
		case err != nil:
			logger.Errorf("GitHub push: %v", err)
		case !created:
			logger.Infof("GitHub push: workspace %s already has a run at %s", ws.ID, commitHash)
		default:
			logger.Infof("Created plan-and-apply run %s for workspace %s from commit %s", run.ID, ws.ID, commitHash)
		}
	}

	attribution := h.installationAttribution(installationID)
	reached := tallies{}
	attribution.addWorkspaces(reached, filteredWorkspaces)
	syncedInventories, syncedPlaybooks := h.syncAnsibleOnGitHubPush(repositoryFullName, branchName, installationID, commitsForCheck, attribution, reached)

	_, eventMessage := pushEventSummary(filteredWorkspaces, syncedPlaybooks, syncedInventories)
	h.recordAttributed(attribution, reached, pushTallySummary,
		"push", "github", repositoryFullName, branchName, commitHash, http.StatusOK, string(payload))

	response.Message(c, http.StatusOK, "Branch push event processed: "+eventMessage)
}

// pushCommitFiles is the files one pushed commit added, removed and modified, the shape the
// path checks (isWorkspaceAffected, isInventoryAffected, isPlaybookAffected) take.
type pushCommitFiles = struct {
	Added    []string `json:"added"`
	Removed  []string `json:"removed"`
	Modified []string `json:"modified"`
}

// syncAnsibleOnGitHubPush syncs the VCS inventories and playbooks a GitHub push reaches, and
// launches their webhook-enabled job templates. It runs whether or not the push also triggered a
// workspace: a playbook or inventory is linked to its repository and branch, not to a Terraform
// workspace. Only resources connected through the delivery's installation, and whose path the
// push changed, are synced. Returns how many inventories and playbooks were synced.
func (h *VCSAppInstallationHandlerV2) syncAnsibleOnGitHubPush(repositoryFullName, branchName, installationID string, commits []pushCommitFiles, attribution deliveryAttribution, reached tallies) (syncedInventories, syncedPlaybooks int) {
	inventories, err := h.inventoryRepo.FindByVCSRepositoryAndBranch(repositoryFullName, branchName)
	if err != nil {
		logger.Errorf("Error finding inventories for repository %s, branch %s: %v", repositoryFullName, branchName, err)
	}
	// AUD-102: only sync inventories connected through THIS delivery's installation.
	for _, inventory := range h.filterInventoriesByInstallation(inventories, installationID) {
		if !h.isInventoryAffected(inventory, commits) {
			continue
		}
		logger.Infof("Triggering sync for inventory: %s (ID: %s)", inventory.Name, inventory.ID)
		syncedInventories++
		attribution.tally(reached, inventory.VCSConnectionID).inventories++
		h.requestInventorySync(&inventory)
	}

	if h.playbookRepo == nil {
		return syncedInventories, syncedPlaybooks
	}
	playbooks, err := h.playbookRepo.ListByVCSRepositoryAndBranch(repositoryFullName, branchName)
	if err != nil {
		logger.Errorf("Error finding playbooks for repository %s, branch %s: %v", repositoryFullName, branchName, err)
	}
	// Only sync playbooks connected through THIS delivery's installation.
	for _, playbook := range h.filterPlaybooksByInstallation(playbooks, installationID) {
		if !h.isPlaybookAffected(playbook, commits) {
			continue
		}
		logger.Infof("Triggering sync for playbook: %s (ID: %s)", playbook.Name, playbook.ID)
		syncedPlaybooks++
		attribution.tally(reached, playbook.VCSConnectionID).playbooks++
		h.requestPlaybookSync(&playbook)
		h.launchWebhookTemplates(playbook.ID, playbook.Name, repositoryFullName, branchName)
	}
	return syncedInventories, syncedPlaybooks
}

// pushEventSummary is the webhook-event status and message for a push: "ignored" when it
// reached nothing, otherwise "success". Ansible counts come first, because the Webhooks page
// reads the workspace names from the end of the message ("N workspace(s) triggered: a, b").
func pushEventSummary(workspaces []models.Workspace, syncedPlaybooks, syncedInventories int) (status, message string) {
	if len(workspaces) == 0 && syncedPlaybooks == 0 && syncedInventories == 0 {
		return "ignored", "No workspace, playbook or inventory tracks the changed files"
	}
	names := make([]string, 0, len(workspaces))
	for _, ws := range workspaces {
		names = append(names, ws.Name)
	}
	message = fmt.Sprintf("%d workspace(s) triggered", len(workspaces))
	if len(names) > 0 {
		message += ": " + strings.Join(names, ", ")
	}
	if syncedPlaybooks > 0 || syncedInventories > 0 {
		message = fmt.Sprintf("%d playbook(s) and %d inventory(ies) synced; %s", syncedPlaybooks, syncedInventories, message)
	}
	return "success", message
}

// pushTallySummary is pushEventSummary over one organization's tally.
func pushTallySummary(e *orgTally) (string, string) {
	return pushEventSummary(e.workspaces, e.playbooks, e.inventories)
}

// pullRequestTallySummary is the webhook-event status and message for a pull request in one
// organization: the workspaces of that organization it triggered, or "ignored" when it
// triggered none there.
func pullRequestTallySummary(prNumber int) func(*orgTally) (string, string) {
	return func(e *orgTally) (string, string) {
		if len(e.workspaces) == 0 {
			return "ignored", fmt.Sprintf("PR #%d: no workspace triggered", prNumber)
		}
		names := make([]string, 0, len(e.workspaces))
		for _, ws := range e.workspaces {
			names = append(names, ws.Name)
		}
		return "success", fmt.Sprintf("PR #%d: %d workspace(s) triggered: %s", prNumber, len(e.workspaces), strings.Join(names, ", "))
	}
}

// handlePullRequestEvent handles GitHub pull request events for speculative plans
// TFE-compatible: Creates speculative plan-only runs when PRs are opened or updated
func (h *VCSAppInstallationHandlerV2) handlePullRequestEvent(c *gin.Context, payload []byte) {
	var prEvent struct {
		Action      string `json:"action"` // "opened", "synchronize", "reopened", etc.
		Number      int    `json:"number"` // PR number
		PullRequest struct {
			Head struct {
				Ref string `json:"ref"` // Source branch
				SHA string `json:"sha"` // Head commit SHA
			} `json:"head"`
			Base struct {
				Ref string `json:"ref"` // Target branch (typically "main")
			} `json:"base"`
			User struct {
				Login string `json:"login"` // PR author username
			} `json:"user"`
			ChangedFiles int `json:"changed_files"` // how many files the pull request changes
		} `json:"pull_request"`
		Repository struct {
			FullName string `json:"full_name"`
			ID       int64  `json:"id"`
		} `json:"repository"`
		Installation struct {
			ID int64 `json:"id"`
		} `json:"installation"`
	}

	if err := json.Unmarshal(payload, &prEvent); err != nil {
		logger.Errorf("Failed to parse pull request event: %v", err)
		jsonapi.WriteError(c, http.StatusBadRequest, "Bad Request", "Failed to parse pull request event")
		return
	}

	// Only process opened, synchronize (new commits), and reopened PRs
	if prEvent.Action != "opened" && prEvent.Action != "synchronize" && prEvent.Action != "reopened" {
		logger.Infof("Ignoring PR event action: %s", prEvent.Action)
		response.Message(c, http.StatusOK, fmt.Sprintf("PR action %s ignored", prEvent.Action))
		return
	}

	baseBranch := prEvent.PullRequest.Base.Ref
	headBranch := prEvent.PullRequest.Head.Ref
	headSHA := prEvent.PullRequest.Head.SHA
	repositoryFullName := prEvent.Repository.FullName
	prNumber := prEvent.Number
	// A delivery that triggers nothing is still recorded in each organization connected through the
	// installation, as an Azure DevOps pull request is, so the event log shows why nothing ran.
	ignored := func(message string) {
		h.recordAttributed(h.installationAttribution(strconv.FormatInt(prEvent.Installation.ID, 10)), nil, fixedSummary("ignored", message),
			"pull_request", "github", repositoryFullName, baseBranch, headSHA, http.StatusOK, string(payload))
		response.Message(c, http.StatusOK, message)
	}

	logger.Infof("Received pull request event - action=%s, PR=%d, base=%s, head=%s, headSHA=%s, repository=%s",
		prEvent.Action, prNumber, baseBranch, headBranch, headSHA, repositoryFullName)

	// Find workspaces that match this repository and base branch (target branch)
	// Only trigger speculative plans for workspaces connected to the target branch
	workspaces, err := h.workspaceRepo.FindByVCSRepositoryAndBranch(repositoryFullName, baseBranch)
	if err != nil {
		logger.Errorf("Error finding workspaces for repository %s, branch %s: %v", repositoryFullName, baseBranch, err)
		ignored(fmt.Sprintf("No workspaces found or error: %v", err))
		return
	}
	// AUD-102: only workspaces connected through THIS delivery's installation.
	workspaces = h.filterWorkspacesByInstallation(workspaces, strconv.FormatInt(prEvent.Installation.ID, 10))

	if len(workspaces) == 0 {
		logger.Infof("No workspaces found for repository %s, branch %s", repositoryFullName, baseBranch)
		ignored("No workspaces found for this repository and branch")
		return
	}

	// Filter workspaces that have speculative plans enabled
	filteredWorkspaces := make([]models.Workspace, 0)
	for _, ws := range workspaces {
		if ws.SpeculativeEnabled {
			filteredWorkspaces = append(filteredWorkspaces, ws)
		}
	}

	if len(filteredWorkspaces) == 0 {
		logger.Infof("No workspaces with speculative plans enabled for repository %s, branch %s", repositoryFullName, baseBranch)
		ignored("No workspaces with speculative plans enabled")
		return
	}

	logger.Infof("Found %d workspace(s) for PR #%d (filtered from %d total)", len(filteredWorkspaces), prNumber, len(workspaces))

	// The changed files, from GitHub's API with the delivering installation's token, decide which
	// workspaces' paths are affected (#938). Without a complete list every workspace is triggered.
	changedFiles := h.pullRequestFiles(c.Request.Context(), strconv.FormatInt(prEvent.Installation.ID, 10),
		repositoryFullName, prNumber, prEvent.PullRequest.ChangedFiles)

	// Filter workspaces based on changed files and their WorkingDirectory paths (GitOps-style filtering)
	// This prevents unnecessary plan runs for workspaces whose code wasn't changed
	finalFilteredWorkspaces := make([]models.Workspace, 0)
	if len(changedFiles) > 0 {
		logger.Infof("PR #%d changed files: %v", prNumber, changedFiles)
		for _, workspace := range filteredWorkspaces {
			if h.isWorkspaceAffectedByFiles(workspace, changedFiles) {
				finalFilteredWorkspaces = append(finalFilteredWorkspaces, workspace)
				logger.Infof("Workspace %s (path: %q) will be triggered - files in its path were changed", workspace.ID, workspace.WorkingDirectory)
			} else {
				logger.Infof("Workspace %s (path: %q) skipped - no files in its path were changed", workspace.ID, workspace.WorkingDirectory)
			}
		}
		// tfe_organization send_passing_statuses_for_untriggered_speculative_plans: workspaces the
		// path filter skipped still get a passing status when their org opts in.
		h.postUntriggeredPassingStatuses(context.Background(),
			splitUntriggeredWorkspaces(filteredWorkspaces, finalFilteredWorkspaces), headSHA)
		if len(finalFilteredWorkspaces) == 0 {
			logger.Infof("No workspaces match the changed files for PR #%d (found %d workspace(s) but none match path filters)", prNumber, len(filteredWorkspaces))
			// The count would cover every organization the installation reaches, so the recorded
			// event, which each organization reads, carries none.
			ignored("No workspace with speculative plans enabled matches the changed files")
			return
		}
		logger.Infof("Filtered to %d workspace(s) that match changed files (from %d total with speculative enabled)", len(finalFilteredWorkspaces), len(filteredWorkspaces))
		if len(finalFilteredWorkspaces) != len(filteredWorkspaces) {
			logger.Infof("Summary - %d workspace(s) filtered out due to path mismatch", len(filteredWorkspaces)-len(finalFilteredWorkspaces))
		}
		filteredWorkspaces = finalFilteredWorkspaces
	} else {
		logger.Infof("Could not determine changed files for PR #%d, triggering all %d workspaces with speculative enabled", prNumber, len(filteredWorkspaces))
	}

	for _, workspace := range filteredWorkspaces {
		ws := workspace
		// A pull request's head, a fork's included, is fetched from the base repository by its
		// pull request ref.
		run, created, err := h.queueCapturedRun(&ws, captureSpec{
			commit: headSHA, fetchRef: fmt.Sprintf("refs/pull/%d/head", prNumber), committer: prEvent.PullRequest.User.Login,
			sourceBranch: headBranch, prNumber: prNumber, speculative: true,
		}, func(runs *repository.RunRepository, versions *repository.ConfigurationVersionRepository) {
			// tfe_organization speculative_plan_management_enabled (default on): a newer commit to
			// this branch/PR supersedes still-pending speculative plans.
			if wsOrg := h.orgForWorkspace(&ws); wsOrg == nil || wsOrg.SpeculativePlanManagement() {
				terraform.AutoCancelSupersededSpeculativeRuns(runs, versions, ws.ID, headBranch, prNumber)
			}
		})
		if err != nil {
			logger.Errorf("GitHub PR #%d: %v", prNumber, err)
			continue
		}
		if !created {
			logger.Infof("GitHub PR #%d: workspace %s already has a run at %s", prNumber, ws.ID, headSHA)
			continue
		}
		logger.Infof("Created speculative plan-only run %s for workspace %s from PR #%d commit %s", run.ID, ws.ID, prNumber, headSHA)

		var vcsConn *models.VCSConnection
		if ws.VCSConnectionID != nil {
			if vcsConn, err = h.workspaceConnection(&ws); err != nil {
				logger.Errorf("Failed to get VCS connection for workspace %s: %v", ws.ID, err)
				continue
			}
		}
		// The pending status check is posted in the background, so the delivery is answered at once.
		go func(ws models.Workspace, run *models.Run, vcsConn *models.VCSConnection) {
			defer func() {
				if r := recover(); r != nil {
					logger.Errorf("PANIC posting the status check for workspace %s: %v", ws.ID, r)
				}
			}()
			ctx := context.Background()
			var err error

			// Create GitHub status check
			if h.statusService == nil {
				logger.Warnf("Status service is nil, cannot create status check for run %s", run.ID)
				return
			}
			if vcsConn == nil {
				logger.Warnf("VCS connection is nil for workspace %s, cannot create status check for run %s", ws.ID, run.ID)
				return
			}
			if vcsConn.InstallationID == "" {
				logger.Warnf("VCS connection has no installation ID for workspace %s, cannot create status check for run %s", ws.ID, run.ID)
				return
			}
			// Use workspace VCS repository if available, otherwise use PR event repository
			repoFullName := repositoryFullName
			if ws.VCSRepository != "" {
				repoFullName = ws.VCSRepository
				logger.Infof("Using workspace VCS repository %s for status check (PR event had %s)", repoFullName, repositoryFullName)
			}

			// Extract owner and repo from full name (e.g., "owner/repo")
			parts := strings.Split(repoFullName, "/")
			if len(parts) != 2 {
				logger.Warnf("Invalid repository full name format '%s' for workspace %s, cannot create status check", repoFullName, ws.ID)
			} else {
				owner := parts[0]
				repo := parts[1]

				// Generate target URL for status check
				// Format: /app/:orgName/workspaces/:workspaceName/runs/:runId
				// Use request host if available, otherwise construct from config
				host := c.GetHeader("Host")
				if host == "" {
					host = c.Request.Host
				}
				if host == "" {
					host = "localhost:5173" // Fallback to frontend default
				}
				scheme := forwardedScheme(c)
				if scheme == "" {
					scheme = "http"
					if c.Request.TLS != nil {
						scheme = "https"
					}
				}

				// Get organization name from workspace (need to fetch with project preloaded)
				workspaceForURL, urlErr := h.workspaceRepo.GetByID(ws.ID)
				var targetURL string
				if urlErr == nil && workspaceForURL.Project.ID != (uuid.UUID{}) && workspaceForURL.Project.Organization.ID != (uuid.UUID{}) && workspaceForURL.Project.Organization.Name != "" {
					// Use organization name and workspace name for proper routing
					targetURL = fmt.Sprintf("%s://%s/app/%s/workspaces/%s/runs/%s", scheme, host, workspaceForURL.Project.Organization.Name, workspaceForURL.Name, run.ID)
				} else {
					// Fallback to workspace ID if org info not available
					logger.Warnf("Could not get org info for workspace %s, using fallback URL with workspace ID", ws.ID)
					targetURL = fmt.Sprintf("%s://%s/workspaces/%s/runs/%s", scheme, host, ws.ID, run.ID)
				}

				// Status check context: terraform-plan/<workspace-name>
				statusContext := fmt.Sprintf("terraform-plan/%s", ws.Name)
				if wsOrg := h.orgForWorkspace(&ws); wsOrg != nil && wsOrg.AggregatedCommitStatusEnabled {
					// tfe_organization aggregated_commit_status_enabled: one rolled-up context per
					// commit instead of one per workspace.
					statusContext = "terraform-plan"
				}

				logger.Infof("Creating status check for run %s - installationID=%s, owner=%s, repo=%s, sha=%s, context=%s",
					run.ID, vcsConn.InstallationID, owner, repo, headSHA, statusContext)

				// Create pending status check
				err = h.statusService.CreateStatusCheck(
					ctx,
					vcsConn.InstallationID,
					owner,
					repo,
					headSHA,
					statusContext,
					vcs.StatusStatePending,
					"Terraform plan is queued",
					targetURL,
				)
				if err != nil {
					// Log error but don't fail the run creation
					logger.Errorf("Failed to create status check for run %s: %v", run.ID, err)
				} else {
					logger.Infof("Created status check for run %s (PR #%d, commit %s)", run.ID, prNumber, headSHA)
				}
			}
		}(ws, run, vcsConn)
	}

	prAttribution := h.installationAttribution(strconv.FormatInt(prEvent.Installation.ID, 10))
	prReached := tallies{}
	prAttribution.addWorkspaces(prReached, filteredWorkspaces)
	h.recordAttributed(prAttribution, prReached, pullRequestTallySummary(prNumber),
		"pull_request", "github", repositoryFullName, headBranch, headSHA, http.StatusOK, string(payload))

	response.Message(c, http.StatusOK, fmt.Sprintf("Pull request event processed: %d workspace(s) queued for speculative plans", len(filteredWorkspaces)))
}

// pullRequestFiles returns the files pull request number of repo changes, read from GitHub's List
// pull request files endpoint with an installation token of the delivering installation. It
// returns nil, which triggers every workspace, when the list cannot be read or is truncated:
// GitHub lists at most MaxPullRequestFiles files, and the delivery says how many changed.
func (h *VCSAppInstallationHandlerV2) pullRequestFiles(ctx context.Context, installationID, repo string, number, changed int) []string {
	if h.githubAppManager == nil || !h.githubAppManager.IsEnabled() {
		return nil
	}
	owner, name, ok := strings.Cut(repo, "/")
	if !ok || gitargs.RepoFullNameRe.FindString(repo) == "" {
		return nil
	}
	files, entries, complete, err := h.githubAppManager.GetService().ListPullRequestFiles(ctx, installationID, owner, name, number)
	if err != nil {
		logger.Warnf("Listing the files of pull request #%d of %s failed, triggering every workspace: %v", number, repo, err)
		return nil
	}
	if !complete || entries < changed {
		logger.Infof("Pull request #%d of %s lists %d of %d changed files, triggering every workspace", number, repo, entries, changed)
		return nil
	}
	return files
}

// Helper function to get keys from map for logging
func getKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// isInventoryAffected checks if an inventory file was affected by a push event
// Helper function to check if inventory path is in the changed files
func (h *VCSAppInstallationHandlerV2) isInventoryAffected(inventory models.AnsibleInventory, commits []struct {
	Added    []string `json:"added"`
	Removed  []string `json:"removed"`
	Modified []string `json:"modified"`
},
) bool {
	// If inventory path is empty, assume it's affected
	if inventory.InventoryPath == "" {
		return true
	}

	// Check if the inventory file was in any of the commits
	for _, commit := range commits {
		for _, file := range commit.Added {
			if file == inventory.InventoryPath || strings.HasSuffix(file, inventory.InventoryPath) {
				return true
			}
		}
		for _, file := range commit.Modified {
			if file == inventory.InventoryPath || strings.HasSuffix(file, inventory.InventoryPath) {
				return true
			}
		}
		for _, file := range commit.Removed {
			if file == inventory.InventoryPath || strings.HasSuffix(file, inventory.InventoryPath) {
				return true
			}
		}
	}

	return false
}

// isPlaybookAffected checks if a playbook's files were affected by a push event
// Helper function to check if playbook path or files in the playbook's directory were changed
func (h *VCSAppInstallationHandlerV2) isPlaybookAffected(playbook models.AnsiblePlaybook, commits []struct {
	Added    []string `json:"added"`
	Removed  []string `json:"removed"`
	Modified []string `json:"modified"`
},
) bool {
	// If no specific path is set, any change to the repo affects the playbook
	if playbook.PlaybookPath == "" {
		return true
	}

	// Get the directory containing the playbook
	playbookDir := getDirectory(playbook.PlaybookPath)

	// Check if any changed files are in the playbook's directory
	for _, commit := range commits {
		for _, file := range commit.Added {
			if strings.HasPrefix(file, playbookDir) || file == playbook.PlaybookPath {
				return true
			}
		}
		for _, file := range commit.Modified {
			if strings.HasPrefix(file, playbookDir) || file == playbook.PlaybookPath {
				return true
			}
		}
		for _, file := range commit.Removed {
			if strings.HasPrefix(file, playbookDir) || file == playbook.PlaybookPath {
				return true
			}
		}
	}

	return false
}

// getDirectory returns the directory portion of a path
func getDirectory(path string) string {
	lastSlash := strings.LastIndex(path, "/")
	if lastSlash == -1 {
		return ""
	}
	return path[:lastSlash+1]
}
