// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package routes

import (
	"os"

	"github.com/gin-gonic/gin"
	"github.com/michielvha/logger"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/handlers"
	ansibleHandlers "github.com/michielvha/stackweaver/backend/internal/api/v2/handlers/ansible"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/crypto"
	"github.com/michielvha/stackweaver/core/queue"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/services/ansible"
	"github.com/michielvha/stackweaver/core/services/oidc"
	"github.com/michielvha/stackweaver/core/services/variable"
	vcs "github.com/michielvha/stackweaver/core/services/vcs"
	"gorm.io/gorm"
)

// AnsibleRouteServices exposes the ansible services built by SetupAnsibleRoutes
// that later route groups (workflows, public callbacks) need to share.
type AnsibleRouteServices struct {
	WorkflowEngine *ansible.WorkflowEngineService
	JobService     *ansible.JobService
}

// SetupAnsibleWorkflowRoutes sets up workflow-specific routes (called after other repos are initialized)
func SetupAnsibleWorkflowRoutes(
	v2 *gin.RouterGroup,
	workflowRepo *repository.AnsibleWorkflowRepository,
	orgRepo *repository.OrganizationRepository,
	projectRepo *repository.ProjectRepository,
	authService *auth.Service,
	rbacService *rbac.Service,
	workflowEngine *ansible.WorkflowEngineService,
) {
	// Initialize Workflow Handler
	workflowHandler := ansibleHandlers.NewWorkflowHandler(workflowRepo, orgRepo, projectRepo, authService, rbacService)
	workflowHandler.SetEngine(workflowEngine)

	// ==========================================
	// Ansible Workflow Template Routes
	// ==========================================

	// Organization-scoped workflow endpoints
	// GET/POST /api/v2/organizations/:name/ansible/workflows
	orgWorkflows := v2.Group("/organizations/:name/ansible/workflows")
	{
		orgWorkflows.GET("", workflowHandler.List)
		orgWorkflows.POST("", workflowHandler.Create)
	}

	// Workflow by ID endpoints
	// GET/PATCH/DELETE /api/v2/ansible/workflows/:id
	workflows := v2.Group("/ansible/workflows")
	{
		workflows.GET("/:id", workflowHandler.Get)
		workflows.PATCH("/:id", workflowHandler.Update)
		workflows.DELETE("/:id", workflowHandler.Delete)
		// Nodes management
		workflows.GET("/:id/nodes", workflowHandler.ListNodes)
		workflows.POST("/:id/nodes", workflowHandler.CreateNode)
		// Edges management
		workflows.GET("/:id/edges", workflowHandler.ListEdges)
		workflows.POST("/:id/edges", workflowHandler.CreateEdge)

		// Execution
		workflows.POST("/:id/launch", workflowHandler.LaunchWorkflow)
		workflows.GET("/:id/jobs", workflowHandler.ListWorkflowJobs)
	}

	// Workflow Node by ID endpoints
	// Workflow runs + approval decisions
	workflowJobs := v2.Group("/ansible/workflow-jobs")
	{
		workflowJobs.GET("/:id", workflowHandler.GetWorkflowJob)
	}
	workflowNodeJobs := v2.Group("/ansible/workflow-node-jobs")
	{
		workflowNodeJobs.POST("/:id/approve", workflowHandler.ApproveWorkflowNode)
		workflowNodeJobs.POST("/:id/deny", workflowHandler.DenyWorkflowNode)
	}

	// PATCH/DELETE /api/v2/ansible/workflow-nodes/:id
	workflowNodes := v2.Group("/ansible/workflow-nodes")
	{
		workflowNodes.PATCH("/:id", workflowHandler.UpdateNode)
		workflowNodes.DELETE("/:id", workflowHandler.DeleteNode)
	}

	// Workflow Edge by ID endpoints
	// DELETE /api/v2/ansible/workflow-edges/:id
	workflowEdges := v2.Group("/ansible/workflow-edges")
	{
		workflowEdges.DELETE("/:id", workflowHandler.DeleteEdge)
	}
}

// SetupAnsibleRoutes sets up the Ansible-related API routes
func SetupAnsibleRoutes(
	v2 *gin.RouterGroup,
	db *gorm.DB,
	inventoryRepo *repository.AnsibleInventoryRepository,
	playbookRepo *repository.AnsiblePlaybookRepository,
	templateRepo *repository.AnsibleJobTemplateRepository,
	jobRepo *repository.AnsibleJobRepository,
	credentialRepo *repository.AnsibleCredentialRepository,
	projectRepo *repository.ProjectRepository,
	orgRepo *repository.OrganizationRepository,
	authService *auth.Service,
	rbacService *rbac.Service,
	redisQueue queue.Queue,
	encryptionKey []byte,
	vcsRegistry *vcs.ProviderRegistry,
	vcsConnectionRepo *repository.VCSConnectionRepository,
) *AnsibleRouteServices {
	// Initialize Ansible Services
	credentialService := ansible.NewCredentialService(credentialRepo, encryptionKey)
	inventoryService := ansible.NewInventoryService(inventoryRepo, orgRepo)

	// Initialize variable service for Ansible (with variable sets, workspace, and template variable support)
	// Create repositories needed for variable service
	workspaceRepo := repository.NewWorkspaceRepository(db)
	variableRepo := repository.NewVariableRepository(db)
	variableSetRepo := repository.NewVariableSetRepository(db)
	templateVariableRepo := repository.NewAnsibleJobTemplateVariableRepository(db)
	variableService := variable.NewServiceWithTemplateVariables(variableRepo, variableSetRepo, workspaceRepo, templateVariableRepo, encryptionKey)

	// Create job service with variable set support
	jobService := ansible.NewJobServiceWithVariables(jobRepo, playbookRepo, inventoryRepo, templateRepo, projectRepo, variableService, redisQueue)
	// Wire the VCS resolver so job launches pre-resolve a token-embedded playbook
	// clone URL server-side (runner then needs no VCS OAuth credentials).
	jobService.SetVCSResolver(vcsRegistry, vcsConnectionRepo)

	// Initialize new repositories for inventory sources and schedules
	inventorySourceRepo := repository.NewAnsibleInventorySourceRepository(db)
	scheduleRepo := repository.NewAnsibleScheduleRepository(db)
	// Honor update_on_launch on API launches: stale dynamic sources sync first
	// and the job is held until they settle.
	jobService.SetInventorySourceRepo(inventorySourceRepo)
	// Enforce the ad hoc module allowlist at the launch choke point (covers Run
	// Command and relaunch of ad hoc jobs).
	jobService.SetOrganizationRepo(orgRepo)

	// Initialize crypto service for secure credential handling
	cryptoService, err := crypto.NewCryptoService(encryptionKey)
	if err != nil {
		logger.Warnf("Failed to initialize crypto service: %v (credential decryption will fail)", err)
	}

	// Initialize Inventory Source Service
	inventorySourceService := ansible.NewInventorySourceService(inventorySourceRepo, inventoryRepo, credentialRepo, cryptoService)
	// Record sync runs in the history table (Syncs tab)
	inventorySyncRepo := repository.NewAnsibleInventorySyncRepository(db)
	inventorySourceService.SetSyncRepo(inventorySyncRepo)

	// Wire OIDC workload identity support for Azure inventory sync (dynamic sources)
	azureOIDCRepo := repository.NewAzureOIDCConfigurationRepository(db)
	oidcSigningKey, oidcErr := oidc.NewSigningKey()
	if oidcErr != nil {
		logger.Warnf("Failed to initialize OIDC signing key for inventory source sync: %v (OIDC auth will be disabled)", oidcErr)
	} else {
		issuerURL := os.Getenv("OIDC_ISSUER_URL")
		if issuerURL == "" {
			issuerURL = os.Getenv("API_URL")
		}
		if issuerURL == "" {
			issuerURL = "http://localhost:8022"
		}
		oidcTokenService := oidc.NewTokenService(oidcSigningKey, issuerURL)
		inventorySourceService.SetOIDCServices(azureOIDCRepo, oidcTokenService)
		logger.Info("OIDC workload identity enabled for inventory source sync")
	}

	// Initialize Scheduler Service
	schedulerService := ansible.NewSchedulerService(
		scheduleRepo,
		jobRepo,
		templateRepo,
		playbookRepo,
		inventorySourceService,
		jobService,
		orgRepo,
	)

	// Workflow execution engine: launches runnable nodes and follows edges.
	// Returned to the caller so the workflow routes (and the started scheduler
	// in cmd/api) share one instance.
	workflowEngine := ansible.NewWorkflowEngineService(
		repository.NewAnsibleWorkflowRepository(db),
		jobRepo,
		jobService,
		inventorySourceService,
	)
	// The HTTP scheduler instance is CRUD-only (it never ticks — the executing
	// scheduler lives in cmd/api), but CreateSchedule validates workflow
	// schedules against the engine, so it must be wired here too or workflow
	// schedules can never be created.
	schedulerService.SetWorkflowEngine(workflowEngine)

	// Notification templates + attachments (webhook / email / Teams).
	notificationRepo := repository.NewAnsibleNotificationRepository(db)
	notificationService := ansible.NewNotificationService(notificationRepo, jobRepo, cryptoService)
	notificationHandler := ansibleHandlers.NewNotificationHandler(
		notificationRepo,
		templateRepo,
		repository.NewAnsibleWorkflowRepository(db),
		orgRepo,
		authService,
		rbacService,
		cryptoService,
		notificationService,
	)

	// Org-scoped notification template endpoints
	orgNotifications := v2.Group("/organizations/:name/ansible/notification-templates")
	{
		orgNotifications.GET("", notificationHandler.List)
		orgNotifications.POST("", notificationHandler.Create)
	}
	notificationTemplates := v2.Group("/ansible/notification-templates")
	{
		notificationTemplates.PATCH("/:id", notificationHandler.Update)
		notificationTemplates.DELETE("/:id", notificationHandler.Delete)
		notificationTemplates.POST("/:id/test", notificationHandler.TestSend)
	}
	// Attachments
	v2.POST("/organizations/:name/ansible/notification-attachments", notificationHandler.Attach)
	v2.DELETE("/organizations/:name/ansible/notification-attachments/:attachment_id", notificationHandler.Detach)

	// Initialize Variable Set Handler for job template variable sets (reuse from terraform routes)
	variableSetRepoForAnsible := repository.NewVariableSetRepository(db)
	variableSetVariableRepoForAnsible := repository.NewVariableSetVariableRepository(db)
	variableSetHandlerForAnsible := handlers.NewVariableSetHandlerV2(variableSetRepoForAnsible, variableSetVariableRepoForAnsible, orgRepo, projectRepo, nil, templateRepo, authService, rbacService, variableService)

	// Initialize Ansible Handlers
	inventoryHandler := ansibleHandlers.NewInventoryHandler(inventoryService, inventoryRepo, orgRepo, projectRepo, authService, rbacService, redisQueue, vcsRegistry, vcsConnectionRepo)
	hostHandler := ansibleHandlers.NewHostHandler(inventoryService, inventoryRepo, authService, rbacService)
	groupHandler := ansibleHandlers.NewGroupHandler(inventoryService, inventoryRepo, authService, rbacService)
	credentialHandler := ansibleHandlers.NewCredentialHandler(credentialService, orgRepo, projectRepo, authService, rbacService)
	agentPoolRepo := repository.NewAgentPoolRepository(db)
	playbookHandler := ansibleHandlers.NewPlaybookHandler(playbookRepo, templateRepo, jobRepo, scheduleRepo, projectRepo, orgRepo, authService, rbacService, redisQueue, vcsRegistry, vcsConnectionRepo)
	playbookHandler.SetCredentialRepo(credentialRepo)
	playbookHandler.SetAgentPoolRepo(agentPoolRepo)
	jobHandler := ansibleHandlers.NewJobHandler(jobService, projectRepo, orgRepo, templateRepo, authService, rbacService)
	adHocHandler := ansibleHandlers.NewAdHocHandler(inventoryRepo, orgRepo, credentialRepo, projectRepo, agentPoolRepo, jobService, authService, rbacService)

	// Initialize new handlers
	inventorySourceHandler := ansibleHandlers.NewInventorySourceHandler(inventorySourceService, inventoryService, authService, rbacService, redisQueue)
	inventorySyncHandler := ansibleHandlers.NewInventorySyncHandler(inventorySyncRepo, inventoryRepo, authService, rbacService)
	scheduleHandler := ansibleHandlers.NewScheduleHandler(schedulerService, orgRepo, authService, rbacService)
	collectionsHandler := ansibleHandlers.NewCollectionsHandler(jobService, authService, rbacService)

	// Initialize job template variable handler
	// Note: Template variables use project-level permissions (similar to other Ansible resources)
	templateVariableHandler := ansibleHandlers.NewJobTemplateVariableHandlerV2(templateVariableRepo, templateRepo, authService, rbacService, variableService)
	templateVariableHandler.SetRepositories(orgRepo, projectRepo)

	// ==========================================
	// Ansible Inventory Routes
	// ==========================================

	// Organization-scoped inventory endpoints
	// GET/POST /api/v2/organizations/:name/ansible/inventories
	orgInventories := v2.Group("/organizations/:name/ansible/inventories")
	{
		orgInventories.GET("", inventoryHandler.List)
		orgInventories.POST("", inventoryHandler.Create)
	}

	// Inventory by ID endpoints
	// GET/PATCH/DELETE /api/v2/ansible/inventories/:id
	inventories := v2.Group("/ansible/inventories")
	{
		inventories.GET("/:id", inventoryHandler.Get)
		inventories.PATCH("/:id", inventoryHandler.Update)
		inventories.DELETE("/:id", inventoryHandler.Delete)

		// Sync action
		inventories.POST("/:id/actions/sync", inventoryHandler.SyncInventory)

		// Inventory format exports
		inventories.GET("/:id/ini", inventoryHandler.GetInventoryINI)
		inventories.GET("/:id/json", inventoryHandler.GetInventoryJSON)

		// Inventory Hosts
		// GET/POST /api/v2/ansible/inventories/:id/hosts
		inventories.GET("/:id/hosts", hostHandler.List)
		inventories.POST("/:id/hosts", hostHandler.Create)

		// Inventory Groups
		// GET/POST /api/v2/ansible/inventories/:id/groups
		inventories.GET("/:id/groups", groupHandler.List)
		inventories.POST("/:id/groups", groupHandler.Create)
	}

	// Host by ID endpoints
	// GET/PATCH/DELETE /api/v2/ansible/hosts/:id
	hosts := v2.Group("/ansible/hosts")
	{
		hosts.GET("/:id", hostHandler.Get)
		hosts.PATCH("/:id", hostHandler.Update)
		hosts.DELETE("/:id", hostHandler.Delete)
	}

	// Group by ID endpoints
	// GET/PATCH/DELETE /api/v2/ansible/groups/:id
	groups := v2.Group("/ansible/groups")
	{
		groups.GET("/:id", groupHandler.Get)
		groups.PATCH("/:id", groupHandler.Update)
		groups.DELETE("/:id", groupHandler.Delete)
	}

	// ==========================================
	// Ansible Credential Routes
	// ==========================================

	// Organization-scoped credential endpoints
	// GET/POST /api/v2/organizations/:name/ansible/credentials
	orgCredentials := v2.Group("/organizations/:name/ansible/credentials")
	{
		orgCredentials.GET("", credentialHandler.List)
		orgCredentials.POST("", credentialHandler.Create)
	}

	// Credential by ID endpoints
	// GET/PATCH/DELETE /api/v2/ansible/credentials/:id
	credentials := v2.Group("/ansible/credentials")
	{
		credentials.GET("/:id", credentialHandler.Get)
		credentials.PATCH("/:id", credentialHandler.Update)
		credentials.DELETE("/:id", credentialHandler.Delete)
	}

	// ==========================================
	// Ansible Playbook Routes
	// ==========================================

	// Organization-scoped playbook endpoints (TFE-compatible pattern)
	// GET/POST /api/v2/organizations/:name/ansible/playbooks
	orgPlaybooks := v2.Group("/organizations/:name/ansible/playbooks")
	{
		orgPlaybooks.GET("", playbookHandler.ListPlaybooksByOrganization)
		orgPlaybooks.POST("", playbookHandler.CreatePlaybookByOrganization)
		// Discovery actions: register many playbooks from one repository / find-or-create one
		orgPlaybooks.POST("/actions/bulk-import", playbookHandler.BulkImportPlaybooks)
		orgPlaybooks.POST("/actions/find-or-create", playbookHandler.FindOrCreatePlaybook)
	}

	// GET /api/v2/organizations/:name/ansible/vcs-playbook-files
	// Lists playbook candidate files in a connected repository (annotated with
	// already-registered playbooks) for the bulk-import wizard and the job
	// template repository browser.
	v2.GET("/organizations/:name/ansible/vcs-playbook-files", playbookHandler.ListPlaybookFiles)

	// Project-scoped playbook endpoints (for backward compatibility and querying by project)
	// GET /api/v2/projects/:id/ansible/playbooks
	projectPlaybooks := v2.Group("/projects/:id/ansible/playbooks")
	{
		projectPlaybooks.GET("", playbookHandler.ListPlaybooks)
	}

	// Playbook by ID endpoints
	// GET/PATCH/DELETE /api/v2/ansible/playbooks/:id
	playbooks := v2.Group("/ansible/playbooks")
	{
		playbooks.GET("/:id", playbookHandler.GetPlaybook)
		playbooks.PATCH("/:id", playbookHandler.UpdatePlaybook)
		playbooks.DELETE("/:id", playbookHandler.DeletePlaybook)
		// Sync action
		playbooks.POST("/:id/actions/sync", playbookHandler.SyncPlaybook)
	}

	// ==========================================
	// Ansible Job Template Routes
	// ==========================================

	// Organization-scoped job template endpoints (TFE-compatible pattern)
	// GET/POST /api/v2/organizations/:name/ansible/job-templates
	orgJobTemplates := v2.Group("/organizations/:name/ansible/job-templates")
	{
		orgJobTemplates.GET("", playbookHandler.ListTemplatesByOrganization)
		orgJobTemplates.POST("", playbookHandler.CreateTemplateByOrganization)
	}

	// Project-scoped job template endpoints (for backward compatibility and querying by project)
	// GET /api/v2/projects/:id/ansible/job-templates
	projectJobTemplates := v2.Group("/projects/:id/ansible/job-templates")
	{
		projectJobTemplates.GET("", playbookHandler.ListTemplates)
	}

	// Job Template by ID endpoints
	// GET/PATCH/DELETE /api/v2/ansible/job-templates/:id
	jobTemplates := v2.Group("/ansible/job-templates")
	{
		jobTemplates.GET("/:id", playbookHandler.GetTemplate)
		jobTemplates.PATCH("/:id", playbookHandler.UpdateTemplate)
		jobTemplates.DELETE("/:id", playbookHandler.DeleteTemplate)
		// Launch from template
		jobTemplates.POST("/:id/launch", jobHandler.LaunchFromTemplate)
		// Notification attachments
		jobTemplates.GET("/:id/notifications", notificationHandler.ListForJobTemplate)
		// Read-only team access summary
		jobTemplates.GET("/:id/access", playbookHandler.GetTemplateAccess)
		// Multi-credential attachment set (AWX-style)
		jobTemplates.GET("/:id/credentials", playbookHandler.ListTemplateCredentials)
		jobTemplates.POST("/:id/credentials", playbookHandler.AttachTemplateCredential)
		jobTemplates.DELETE("/:id/credentials/:credential_id", playbookHandler.DetachTemplateCredential)
		// Variable sets that apply to this job template (inherited from project)
		jobTemplates.GET("/:id/variable-sets", variableSetHandlerForAnsible.ListVariableSetsByJobTemplate)
		// Template variables (individual variables for this job template)
		jobTemplates.GET("/:id/vars", templateVariableHandler.ListByJobTemplate)
		jobTemplates.POST("/:id/vars", templateVariableHandler.Create)
		jobTemplates.PATCH("/:id/vars/:variable_id", templateVariableHandler.Update)
		jobTemplates.DELETE("/:id/vars/:variable_id", templateVariableHandler.Delete)
	}

	// ==========================================
	// Ansible Job Routes
	// ==========================================

	// Organization-scoped job endpoints (TFE-compatible pattern)
	// GET/POST /api/v2/organizations/:name/ansible/jobs
	orgJobs := v2.Group("/organizations/:name/ansible/jobs")
	{
		orgJobs.GET("", jobHandler.ListByOrganization)
		orgJobs.POST("", jobHandler.LaunchByOrganization)
		orgJobs.GET("/queue", jobHandler.GetQueue)
	}

	// Project-scoped job endpoints (for backward compatibility and querying by project)
	// GET /api/v2/projects/:id/ansible/jobs
	projectJobs := v2.Group("/projects/:id/ansible/jobs")
	{
		projectJobs.GET("", jobHandler.ListByProject)
	}

	// Job by ID endpoints
	// GET /api/v2/ansible/jobs/:id
	jobs := v2.Group("/ansible/jobs")
	{
		jobs.GET("/:id", jobHandler.Get)
		jobs.DELETE("/:id", jobHandler.Delete)
		// Job actions
		jobs.POST("/:id/actions/cancel", jobHandler.Cancel)
		jobs.POST("/:id/actions/relaunch", jobHandler.Relaunch)
		// Job events and output
		jobs.GET("/:id/events", jobHandler.GetEvents)
		jobs.GET("/:id/output", jobHandler.GetOutput)
	}

	// ==========================================
	// Ansible Inventory Source Routes (Dynamic Inventories)
	// ==========================================

	// Inventory-scoped inventory source endpoints
	// GET/POST /api/v2/ansible/inventories/:id/sources
	inventorySources := v2.Group("/ansible/inventories/:id/sources")
	{
		inventorySources.GET("", inventorySourceHandler.List)
		inventorySources.POST("", inventorySourceHandler.Create)
	}

	// Ad hoc commands (AWX-style "Run Command")
	// POST /api/v2/ansible/inventories/:id/actions/run-command
	v2.POST("/ansible/inventories/:id/actions/run-command", adHocHandler.RunCommand)
	// GET /api/v2/organizations/:name/ansible/adhoc-modules (effective allowlist)
	v2.GET("/organizations/:name/ansible/adhoc-modules", adHocHandler.ListModules)

	// Inventory sync history
	// GET /api/v2/ansible/inventories/:id/syncs
	v2.GET("/ansible/inventories/:id/syncs", inventorySyncHandler.List)
	// GET /api/v2/ansible/inventory-syncs/:sync_id (includes captured output)
	v2.GET("/ansible/inventory-syncs/:sync_id", inventorySyncHandler.Get)

	// Inventory Source by ID endpoints
	// GET/PATCH/DELETE /api/v2/ansible/inventory-sources/:id
	inventorySourcesByID := v2.Group("/ansible/inventory-sources")
	{
		inventorySourcesByID.GET("/:source_id", inventorySourceHandler.Get)
		inventorySourcesByID.PATCH("/:source_id", inventorySourceHandler.Update)
		inventorySourcesByID.DELETE("/:source_id", inventorySourceHandler.Delete)
		// Sync action
		inventorySourcesByID.POST("/:source_id/actions/sync", inventorySourceHandler.Sync)
	}

	// ==========================================
	// Ansible Schedule Routes
	// ==========================================

	// Organization-scoped schedule endpoints
	// GET/POST /api/v2/organizations/:name/ansible/schedules
	orgSchedules := v2.Group("/organizations/:name/ansible/schedules")
	{
		orgSchedules.GET("", scheduleHandler.ListByOrganization)
		orgSchedules.POST("", scheduleHandler.Create)
	}

	// Schedule by ID endpoints
	// GET/PATCH/DELETE /api/v2/ansible/schedules/:id
	schedules := v2.Group("/ansible/schedules")
	{
		schedules.GET("/:schedule_id", scheduleHandler.Get)
		schedules.PATCH("/:schedule_id", scheduleHandler.Update)
		schedules.DELETE("/:schedule_id", scheduleHandler.Delete)
		// Schedule actions
		schedules.POST("/:schedule_id/actions/enable", scheduleHandler.Enable)
		schedules.POST("/:schedule_id/actions/disable", scheduleHandler.Disable)
		schedules.POST("/:schedule_id/actions/run-now", scheduleHandler.RunNow)
	}

	// ==========================================
	// Ansible Galaxy Collections Routes
	// ==========================================

	// Collections endpoints
	// GET /api/v2/ansible/collections/pre-installed - List pre-installed collections
	// GET /api/v2/ansible/collections/search - Search Galaxy Hub
	collections := v2.Group("/ansible/collections")
	{
		collections.GET("/pre-installed", collectionsHandler.ListPreInstalledCollections)
		collections.GET("/search", collectionsHandler.SearchGalaxyCollections)
	}

	// Per-job collections (requirements.yml installs)
	// GET /api/v2/ansible/jobs/:id/collections
	jobs.GET("/:id/collections", collectionsHandler.ListJobCollections)

	return &AnsibleRouteServices{WorkflowEngine: workflowEngine, JobService: jobService}
}
