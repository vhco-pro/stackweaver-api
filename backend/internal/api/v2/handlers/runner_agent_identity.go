// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/logger"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/jsonapi"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/services/ansible"
	"github.com/michielvha/stackweaver/core/services/oidc"
)

// workload is what the identity of one job needs from its engine (#933, D2, D8, AC37).
type workload struct {
	// kind names it in a refusal: run or job.
	kind string
	// sessionID is the run or job in the AWS session name.
	sessionID string
	// mint signs a token for an audience with the job's claims.
	mint func(audience string) (string, error)
	// azure writes the variables the engine's Azure tooling reads; nil leaves Azure out.
	azure func(env map[string]string, cfg *models.AzureOIDCConfiguration, token string)
}

// refuseWithoutIdentity answers an artifacts request whose job's configured identity cannot be
// provided: the executor fails the job with err's sentence. A job left to run would act as whatever
// identity its machine has.
func refuseWithoutIdentity(c *gin.Context, jobID string, err error) {
	logger.Warnf("Job %s is not handed to its runner: %v", jobID, err)
	jsonapi.WriteError(c, http.StatusConflict, "Conflict", err.Error())
}

// workloadIdentityEnv adds to env the platform-minted per-run identity of each provider the
// organization configured, under the same variables on both engines; the executor materializes
// them. It fails when a configured identity cannot be read or minted, so no job runs without one.
func (h *RunnerAgentHandler) workloadIdentityEnv(orgID uuid.UUID, w workload, env map[string]string) (map[string]string, error) {
	if h.oidcTokenService == nil {
		return env, nil
	}
	if env == nil {
		env = map[string]string{}
	}
	unreadable := func(provider string, err error) error {
		logger.Errorf("Reading the %s OIDC configuration of organization %s: %v", provider, orgID, err)
		return fmt.Errorf("the %s's %s per-run identity could not be read", w.kind, provider)
	}
	token := func(provider, audience string) (string, error) {
		t, err := w.mint(audience)
		if err != nil {
			return "", fmt.Errorf("the %s's %s per-run identity could not be minted: %w", w.kind, provider, err)
		}
		return t, nil
	}

	if h.azureOIDCRepo != nil && w.azure != nil {
		configs, err := h.azureOIDCRepo.GetByOrganization(orgID)
		if err != nil {
			return nil, unreadable("Azure", err)
		}
		if len(configs) > 0 {
			t, err := token("Azure", "api://AzureADTokenExchange")
			if err != nil {
				return nil, err
			}
			w.azure(env, &configs[0], t)
		}
	}
	if h.awsOIDCRepo != nil {
		configs, err := h.awsOIDCRepo.GetByOrganization(orgID)
		if err != nil {
			return nil, unreadable("AWS", err)
		}
		if len(configs) > 0 {
			t, err := token("AWS", "sts.amazonaws.com")
			if err != nil {
				return nil, err
			}
			env["AWS_ROLE_ARN"] = configs[0].RoleARN
			env["AWS_ROLE_SESSION_NAME"] = "stackweaver-" + w.sessionID
			// The executor writes it to a file and sets AWS_WEB_IDENTITY_TOKEN_FILE.
			env["AWS_WEB_IDENTITY_TOKEN"] = t
		}
	}
	if h.gcpOIDCRepo != nil {
		configs, err := h.gcpOIDCRepo.GetByOrganization(orgID)
		if err != nil {
			return nil, unreadable("GCP", err)
		}
		if len(configs) > 0 {
			cfg := configs[0]
			// Workload Identity Federation's audience is the provider's full resource name.
			t, err := token("GCP", "//iam.googleapis.com/"+cfg.WorkloadProviderName)
			if err != nil {
				return nil, err
			}
			// The executor writes the token and credential configuration files.
			env["GCP_OIDC_RAW_TOKEN"] = t
			env["GCP_OIDC_SERVICE_ACCOUNT_EMAIL"] = cfg.ServiceAccountEmail
			env["GCP_OIDC_WORKLOAD_PROVIDER_NAME"] = cfg.WorkloadProviderName
			env["GCP_OIDC_PROJECT_NUMBER"] = cfg.ProjectNumber
		}
	}
	if h.vaultOIDCRepo != nil {
		configs, err := h.vaultOIDCRepo.GetByOrganization(orgID)
		if err != nil {
			return nil, unreadable("Vault", err)
		}
		if len(configs) > 0 {
			cfg := configs[0]
			t, err := token("Vault", oidc.VaultWorkloadIdentityAudience)
			if err != nil {
				return nil, err
			}
			// Only the job's machine can reach the customer's Vault: the executor runs the login.
			env["VAULT_OIDC_RAW_TOKEN"] = t
			env["VAULT_OIDC_ADDRESS"] = cfg.Address
			env["VAULT_OIDC_ROLE"] = cfg.RoleName
			env["VAULT_OIDC_NAMESPACE"] = cfg.Namespace
			env["VAULT_OIDC_AUTH_PATH"] = cfg.JWTAuthPath
			env["VAULT_OIDC_ENCODED_CACERT"] = cfg.TLSCACertificate
		}
	}
	return env, nil
}

// tofuWorkloadIdentityEnv is an OpenTofu run's identity. The run's workspace, project and
// organization are loaded.
func (h *RunnerAgentHandler) tofuWorkloadIdentityEnv(run *models.Run, env map[string]string) (map[string]string, error) {
	project := &run.Workspace.Project
	phase := "plan"
	if run.Status == models.RunStatusApplying {
		phase = "apply"
	}
	return h.workloadIdentityEnv(project.OrganizationID, workload{
		kind:      "run",
		sessionID: run.ID,
		mint: func(audience string) (string, error) {
			return h.oidcTokenService.GenerateToken(oidc.TokenRequest{
				Audience:         audience,
				OrganizationName: project.Organization.Name,
				OrganizationID:   project.OrganizationID.String(),
				ProjectName:      project.Name,
				ProjectID:        project.ID.String(),
				WorkspaceName:    run.Workspace.Name,
				WorkspaceID:      run.WorkspaceID,
				RunID:            run.ID,
				RunPhase:         phase,
			})
		},
		azure: func(env map[string]string, cfg *models.AzureOIDCConfiguration, token string) {
			env["TFC_WORKLOAD_IDENTITY_TOKEN"] = token
			env["ARM_OIDC_TOKEN"] = token
			env["ARM_CLIENT_ID"] = cfg.ClientID
			env["ARM_SUBSCRIPTION_ID"] = cfg.SubscriptionID
			env["ARM_TENANT_ID"] = cfg.TenantID
			env["ARM_USE_OIDC"] = "true"
		},
	}, env)
}

// ansibleWorkloadIdentityEnv is an Ansible job's identity, the same four an OpenTofu run's artifacts
// carry. An attached Azure credential wins over the organization's Azure identity.
func (h *RunnerAgentHandler) ansibleWorkloadIdentityEnv(job *models.AnsibleJob, env map[string]string) (map[string]string, error) {
	if h.oidcTokenService == nil {
		return env, nil
	}
	var project models.Project
	if err := h.db.Preload("Organization").First(&project, "id = ?", job.ProjectID).Error; err != nil {
		logger.Errorf("Reading the project of Ansible job %s: %v", job.ID, err)
		return nil, errors.New("the job's project could not be read for its per-run identity")
	}
	w := workload{
		kind:      "job",
		sessionID: job.ID.String(),
		mint: func(audience string) (string, error) {
			name, err := h.ansibleJobIdentityName(job)
			if err != nil {
				return "", err
			}
			return h.oidcTokenService.GenerateWorkloadToken(oidc.WorkloadTokenRequest{
				Audience:         audience,
				OrganizationName: project.Organization.Name,
				OrganizationID:   project.OrganizationID.String(),
				ProjectName:      project.Name,
				ProjectID:        project.ID.String(),
				ResourceType:     oidc.ResourceTypeJob,
				ResourceName:     name,
				ActionKind:       oidc.ActionRun,
				ActionID:         job.ID.String(),
			})
		},
	}
	if env["AZURE_CLIENT_ID"] == "" {
		w.azure = func(env map[string]string, cfg *models.AzureOIDCConfiguration, token string) {
			env["AZURE_CLIENT_ID"] = cfg.ClientID
			env["AZURE_TENANT_ID"] = cfg.TenantID
			// azure.azcollection reads the legacy AZURE_TENANT name.
			env["AZURE_TENANT"] = cfg.TenantID
			env["AZURE_SUBSCRIPTION_ID"] = cfg.SubscriptionID
			env["AZURE_FEDERATED_TOKEN"] = token
			env["ARM_OIDC_TOKEN"] = token
			env["ARM_CLIENT_ID"] = cfg.ClientID
			env["ARM_SUBSCRIPTION_ID"] = cfg.SubscriptionID
			env["ARM_TENANT_ID"] = cfg.TenantID
			env["ARM_USE_OIDC"] = "true"
		}
	}
	return h.workloadIdentityEnv(project.OrganizationID, w, env)
}

// ansibleJobIdentityName is the name in the job's subject, reading its template's when it has one.
func (h *RunnerAgentHandler) ansibleJobIdentityName(job *models.AnsibleJob) (string, error) {
	if job.TemplateID == nil {
		return ansible.JobIdentityName(job, ""), nil
	}
	var template models.AnsibleJobTemplate
	if err := h.db.Select("name").First(&template, "id = ?", *job.TemplateID).Error; err != nil {
		return "", fmt.Errorf("reading the job's template: %w", err)
	}
	return ansible.JobIdentityName(job, template.Name), nil
}
