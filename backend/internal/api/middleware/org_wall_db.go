// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package middleware

import (
	"strings"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/repository"
	"gorm.io/gorm"
)

// dbOrgResolver is the production OrgResolver backed by GORM repositories.
// Each method loads the named resource and chains to its owning org.
type dbOrgResolver struct {
	org              *repository.OrganizationRepository
	project          *repository.ProjectRepository
	workspace        *repository.WorkspaceRepository
	run              *repository.RunRepository
	runTrigger       *repository.RunTriggerRepository
	configVersion    *repository.ConfigurationVersionRepository
	stateVersion     *repository.StateVersionRepository
	variable         *repository.VariableRepository
	variableSet      *repository.VariableSetRepository
	variableSetVar   *repository.VariableSetVariableRepository
	team             *repository.TeamRepository
	agentPool        *repository.AgentPoolRepository
	runner           *repository.RunnerRepository
	vcsConnection    *repository.VCSConnectionRepository
	oidcConfig       *repository.AzureOIDCConfigurationRepository
	awsOIDCConfig    *repository.AWSOIDCConfigurationRepository
	gcpOIDCConfig    *repository.GCPOIDCConfigurationRepository
	vaultOIDCConfig  *repository.VaultOIDCConfigurationRepository
	gpgKey           *repository.GPGKeyRepository
	provider         *repository.ProviderRepository
	ansibleInventory *repository.AnsibleInventoryRepository
	ansibleInvSource *repository.AnsibleInventorySourceRepository
	ansibleCred      *repository.AnsibleCredentialRepository
	ansiblePlaybook  *repository.AnsiblePlaybookRepository
	ansibleJobTpl    *repository.AnsibleJobTemplateRepository
	ansibleJobTplVar *repository.AnsibleJobTemplateVariableRepository
	ansibleJob       *repository.AnsibleJobRepository
	ansibleSchedule  *repository.AnsibleScheduleRepository
	ansibleWorkflow  *repository.AnsibleWorkflowRepository
	notificationCfg  *repository.NotificationConfigurationRepository
}

// NewDBOrgResolver builds the production OrgResolver from a database handle.
func NewDBOrgResolver(db *gorm.DB) OrgResolver {
	return &dbOrgResolver{
		org:              repository.NewOrganizationRepository(db),
		project:          repository.NewProjectRepository(db),
		workspace:        repository.NewWorkspaceRepository(db),
		run:              repository.NewRunRepository(db),
		runTrigger:       repository.NewRunTriggerRepository(db),
		configVersion:    repository.NewConfigurationVersionRepository(db),
		stateVersion:     repository.NewStateVersionRepository(db),
		variable:         repository.NewVariableRepository(db),
		variableSet:      repository.NewVariableSetRepository(db),
		variableSetVar:   repository.NewVariableSetVariableRepository(db),
		team:             repository.NewTeamRepository(db),
		agentPool:        repository.NewAgentPoolRepository(db),
		runner:           repository.NewRunnerRepository(db),
		vcsConnection:    repository.NewVCSConnectionRepository(db),
		oidcConfig:       repository.NewAzureOIDCConfigurationRepository(db),
		awsOIDCConfig:    repository.NewAWSOIDCConfigurationRepository(db),
		gcpOIDCConfig:    repository.NewGCPOIDCConfigurationRepository(db),
		vaultOIDCConfig:  repository.NewVaultOIDCConfigurationRepository(db),
		gpgKey:           repository.NewGPGKeyRepository(db),
		provider:         repository.NewProviderRepository(db),
		ansibleInventory: repository.NewAnsibleInventoryRepository(db),
		ansibleInvSource: repository.NewAnsibleInventorySourceRepository(db),
		ansibleCred:      repository.NewAnsibleCredentialRepository(db),
		ansiblePlaybook:  repository.NewAnsiblePlaybookRepository(db),
		ansibleJobTpl:    repository.NewAnsibleJobTemplateRepository(db),
		ansibleJobTplVar: repository.NewAnsibleJobTemplateVariableRepository(db),
		ansibleJob:       repository.NewAnsibleJobRepository(db),
		ansibleSchedule:  repository.NewAnsibleScheduleRepository(db),
		ansibleWorkflow:  repository.NewAnsibleWorkflowRepository(db),
		notificationCfg:  repository.NewNotificationConfigurationRepository(db),
	}
}

// --- internal chaining helpers ---

func (r *dbOrgResolver) orgByProjectUUID(projectID uuid.UUID) (uuid.UUID, error) {
	p, err := r.project.GetByID(projectID)
	if err != nil {
		return uuid.Nil, err
	}
	return p.OrganizationID, nil
}

func (r *dbOrgResolver) orgByWorkspaceStr(workspaceID string) (uuid.UUID, error) {
	ws, err := r.workspace.GetByID(workspaceID)
	if err != nil {
		return uuid.Nil, err
	}
	return r.orgByProjectUUID(ws.ProjectID)
}

func (r *dbOrgResolver) orgByTeamUUID(teamID uuid.UUID) (uuid.UUID, error) {
	t, err := r.team.GetByID(teamID)
	if err != nil {
		return uuid.Nil, err
	}
	return t.OrganizationID, nil
}

func (r *dbOrgResolver) orgByInventoryUUID(invID uuid.UUID) (uuid.UUID, error) {
	inv, err := r.ansibleInventory.GetByID(invID)
	if err != nil {
		return uuid.Nil, err
	}
	return inv.OrganizationID, nil
}

func (r *dbOrgResolver) orgByJobTemplateUUID(jtID uuid.UUID) (uuid.UUID, error) {
	jt, err := r.ansibleJobTpl.GetByID(jtID)
	if err != nil {
		return uuid.Nil, err
	}
	return r.orgByProjectUUID(jt.ProjectID)
}

func (r *dbOrgResolver) orgByWorkflowUUID(wfID uuid.UUID) (uuid.UUID, error) {
	wf, err := r.ansibleWorkflow.GetByID(wfID)
	if err != nil {
		return uuid.Nil, err
	}
	return wf.OrganizationID, nil
}

// --- OrgResolver implementation ---

func (r *dbOrgResolver) ByOrgName(name string) (uuid.UUID, error) {
	o, err := r.org.GetByName(name)
	if err != nil {
		return uuid.Nil, err
	}
	return o.ID, nil
}

func (r *dbOrgResolver) ByOrgMembershipID(id string) (uuid.UUID, error) {
	memberID, err := uuid.Parse(id)
	if err != nil {
		return uuid.Nil, err
	}
	m, err := r.org.GetMemberByID(memberID)
	if err != nil {
		return uuid.Nil, err
	}
	return m.OrganizationID, nil
}

func (r *dbOrgResolver) ByProjectID(id string) (uuid.UUID, error) {
	projectID, err := uuid.Parse(id)
	if err != nil {
		return uuid.Nil, err
	}
	return r.orgByProjectUUID(projectID)
}

func (r *dbOrgResolver) ByWorkspaceID(id string) (uuid.UUID, error) {
	return r.orgByWorkspaceStr(id)
}

func (r *dbOrgResolver) ByRunID(id string) (uuid.UUID, error) {
	run, err := r.run.GetByID(id)
	if err != nil {
		return uuid.Nil, err
	}
	return r.orgByWorkspaceStr(run.WorkspaceID)
}

func (r *dbOrgResolver) ByRunTriggerID(id string) (uuid.UUID, error) {
	rt, err := r.runTrigger.GetByID(id)
	if err != nil {
		return uuid.Nil, err
	}
	// Resolve via the TARGET workspace (the trigger belongs to the org that owns the workspace it runs in).
	return r.orgByWorkspaceStr(rt.WorkspaceID)
}

func (r *dbOrgResolver) ByNotificationConfigID(id string) (uuid.UUID, error) {
	nc, err := r.notificationCfg.GetByID(id)
	if err != nil {
		return uuid.Nil, err
	}
	return r.orgByWorkspaceStr(nc.WorkspaceID)
}

func (r *dbOrgResolver) ByConfigVersionID(id string) (uuid.UUID, error) {
	cv, err := r.configVersion.GetByID(id)
	if err != nil {
		return uuid.Nil, err
	}
	return r.orgByWorkspaceStr(cv.WorkspaceID)
}

func (r *dbOrgResolver) ByStateVersionID(id string) (uuid.UUID, error) {
	sv, err := r.stateVersion.GetByID(id)
	if err != nil {
		return uuid.Nil, err
	}
	return r.orgByWorkspaceStr(sv.WorkspaceID)
}

func (r *dbOrgResolver) ByVariableID(id string) (uuid.UUID, error) {
	v, err := r.variable.GetByID(id)
	if err != nil {
		return uuid.Nil, err
	}
	return r.orgByWorkspaceStr(v.WorkspaceID)
}

func (r *dbOrgResolver) ByVariableSetID(id string) (uuid.UUID, error) {
	vs, err := r.variableSet.GetByID(id)
	if err != nil {
		return uuid.Nil, err
	}
	return vs.OrganizationID, nil
}

func (r *dbOrgResolver) ByVariableSetVariableID(id string) (uuid.UUID, error) {
	vsv, err := r.variableSetVar.GetByID(id)
	if err != nil {
		return uuid.Nil, err
	}
	vs, err := r.variableSet.GetByID(vsv.VariableSetID)
	if err != nil {
		return uuid.Nil, err
	}
	return vs.OrganizationID, nil
}

func (r *dbOrgResolver) ByTeamID(id string) (uuid.UUID, error) {
	teamID, err := uuid.Parse(id)
	if err != nil {
		return uuid.Nil, err
	}
	return r.orgByTeamUUID(teamID)
}

func (r *dbOrgResolver) ByTeamWorkspaceAccessID(id string) (uuid.UUID, error) {
	accessID, err := uuid.Parse(id)
	if err != nil {
		return uuid.Nil, err
	}
	access, err := r.team.GetWorkspaceAccessByID(accessID)
	if err != nil {
		return uuid.Nil, err
	}
	return r.orgByTeamUUID(access.TeamID)
}

func (r *dbOrgResolver) ByTeamProjectAccessID(id string) (uuid.UUID, error) {
	accessID, err := uuid.Parse(id)
	if err != nil {
		return uuid.Nil, err
	}
	access, err := r.team.GetProjectAccessByID(accessID)
	if err != nil {
		return uuid.Nil, err
	}
	return r.orgByTeamUUID(access.TeamID)
}

func (r *dbOrgResolver) ByAgentPoolID(id string) (uuid.UUID, error) {
	poolID, err := uuid.Parse(id)
	if err != nil {
		return uuid.Nil, err
	}
	pool, err := r.agentPool.GetByID(poolID, false)
	if err != nil {
		return uuid.Nil, err
	}
	return pool.OrganizationID, nil
}

func (r *dbOrgResolver) ByRunnerID(id string) (uuid.UUID, error) {
	runnerID, err := uuid.Parse(id)
	if err != nil {
		return uuid.Nil, err
	}
	runner, err := r.runner.GetByID(runnerID)
	if err != nil {
		return uuid.Nil, err
	}
	return runner.OrganizationID, nil
}

func (r *dbOrgResolver) ByVCSConnectionID(id string) (uuid.UUID, error) {
	connID, err := uuid.Parse(id)
	if err != nil {
		return uuid.Nil, err
	}
	conn, err := r.vcsConnection.GetByID(connID)
	if err != nil {
		return uuid.Nil, err
	}
	return conn.OrganizationID, nil
}

func (r *dbOrgResolver) ByOIDCConfigID(id string) (uuid.UUID, error) {
	// OIDC configurations share the /oidc-configurations/:id path across providers; resolve the
	// owning org by ID prefix (azoidc- / awsoidc- / gcpoidc-; extend as Vault lands).
	if strings.HasPrefix(id, "awsoidc-") {
		cfg, err := r.awsOIDCConfig.GetByID(id)
		if err != nil {
			return uuid.Nil, err
		}
		return cfg.OrganizationID, nil
	}
	if strings.HasPrefix(id, "gcpoidc-") {
		cfg, err := r.gcpOIDCConfig.GetByID(id)
		if err != nil {
			return uuid.Nil, err
		}
		return cfg.OrganizationID, nil
	}
	if strings.HasPrefix(id, "vaultoidc-") {
		cfg, err := r.vaultOIDCConfig.GetByID(id)
		if err != nil {
			return uuid.Nil, err
		}
		return cfg.OrganizationID, nil
	}
	cfg, err := r.oidcConfig.GetByID(id)
	if err != nil {
		return uuid.Nil, err
	}
	return cfg.OrganizationID, nil
}

func (r *dbOrgResolver) ByGPGKeyID(id string) (uuid.UUID, error) {
	keyID, err := uuid.Parse(id)
	if err != nil {
		return uuid.Nil, err
	}
	key, err := r.gpgKey.GetByID(keyID)
	if err != nil {
		return uuid.Nil, err
	}
	return key.OrganizationID, nil
}

func (r *dbOrgResolver) ByRegistryProviderID(id string) (uuid.UUID, error) {
	provID, err := uuid.Parse(id)
	if err != nil {
		return uuid.Nil, err
	}
	provider, err := r.provider.GetByID(provID)
	if err != nil {
		return uuid.Nil, err
	}
	return provider.OrganizationID, nil
}

func (r *dbOrgResolver) ByAnsibleInventoryID(id string) (uuid.UUID, error) {
	invID, err := uuid.Parse(id)
	if err != nil {
		return uuid.Nil, err
	}
	return r.orgByInventoryUUID(invID)
}

func (r *dbOrgResolver) ByAnsibleHostID(id string) (uuid.UUID, error) {
	hostID, err := uuid.Parse(id)
	if err != nil {
		return uuid.Nil, err
	}
	host, err := r.ansibleInventory.GetHostByID(hostID)
	if err != nil {
		return uuid.Nil, err
	}
	return r.orgByInventoryUUID(host.InventoryID)
}

func (r *dbOrgResolver) ByAnsibleGroupID(id string) (uuid.UUID, error) {
	groupID, err := uuid.Parse(id)
	if err != nil {
		return uuid.Nil, err
	}
	group, err := r.ansibleInventory.GetGroupByID(groupID)
	if err != nil {
		return uuid.Nil, err
	}
	return r.orgByInventoryUUID(group.InventoryID)
}

func (r *dbOrgResolver) ByAnsibleInventorySourceID(id string) (uuid.UUID, error) {
	sourceID, err := uuid.Parse(id)
	if err != nil {
		return uuid.Nil, err
	}
	source, err := r.ansibleInvSource.GetByID(sourceID)
	if err != nil {
		return uuid.Nil, err
	}
	return r.orgByInventoryUUID(source.InventoryID)
}

func (r *dbOrgResolver) ByAnsibleCredentialID(id string) (uuid.UUID, error) {
	credID, err := uuid.Parse(id)
	if err != nil {
		return uuid.Nil, err
	}
	cred, err := r.ansibleCred.GetByID(credID)
	if err != nil {
		return uuid.Nil, err
	}
	return cred.OrganizationID, nil
}

func (r *dbOrgResolver) ByAnsiblePlaybookID(id string) (uuid.UUID, error) {
	pbID, err := uuid.Parse(id)
	if err != nil {
		return uuid.Nil, err
	}
	pb, err := r.ansiblePlaybook.GetByID(pbID)
	if err != nil {
		return uuid.Nil, err
	}
	return r.orgByProjectUUID(pb.ProjectID)
}

func (r *dbOrgResolver) ByAnsibleJobTemplateID(id string) (uuid.UUID, error) {
	jtID, err := uuid.Parse(id)
	if err != nil {
		return uuid.Nil, err
	}
	return r.orgByJobTemplateUUID(jtID)
}

func (r *dbOrgResolver) ByAnsibleJobTemplateVariableID(id string) (uuid.UUID, error) {
	v, err := r.ansibleJobTplVar.GetByID(id)
	if err != nil {
		return uuid.Nil, err
	}
	return r.orgByJobTemplateUUID(v.JobTemplateID)
}

func (r *dbOrgResolver) ByAnsibleJobID(id string) (uuid.UUID, error) {
	jobID, err := uuid.Parse(id)
	if err != nil {
		return uuid.Nil, err
	}
	job, err := r.ansibleJob.GetByID(jobID)
	if err != nil {
		return uuid.Nil, err
	}
	return r.orgByProjectUUID(job.ProjectID)
}

func (r *dbOrgResolver) ByAnsibleScheduleID(id string) (uuid.UUID, error) {
	schedID, err := uuid.Parse(id)
	if err != nil {
		return uuid.Nil, err
	}
	sched, err := r.ansibleSchedule.GetByID(schedID)
	if err != nil {
		return uuid.Nil, err
	}
	return sched.OrganizationID, nil
}

func (r *dbOrgResolver) ByAnsibleWorkflowID(id string) (uuid.UUID, error) {
	wfID, err := uuid.Parse(id)
	if err != nil {
		return uuid.Nil, err
	}
	return r.orgByWorkflowUUID(wfID)
}

func (r *dbOrgResolver) ByAnsibleWorkflowNodeID(id string) (uuid.UUID, error) {
	nodeID, err := uuid.Parse(id)
	if err != nil {
		return uuid.Nil, err
	}
	node, err := r.ansibleWorkflow.GetNodeByID(nodeID)
	if err != nil {
		return uuid.Nil, err
	}
	return r.orgByWorkflowUUID(node.WorkflowID)
}

func (r *dbOrgResolver) ByAnsibleWorkflowEdgeID(id string) (uuid.UUID, error) {
	edgeID, err := uuid.Parse(id)
	if err != nil {
		return uuid.Nil, err
	}
	edge, err := r.ansibleWorkflow.GetEdgeByID(edgeID)
	if err != nil {
		return uuid.Nil, err
	}
	return r.orgByWorkflowUUID(edge.WorkflowID)
}

func (r *dbOrgResolver) UserInOrg(userID, orgID uuid.UUID) (bool, error) {
	return r.org.UserInOrg(userID, orgID)
}
