// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/core/repository"
)

type DashboardHandler struct {
	orgRepo             *repository.OrganizationRepository
	projectRepo         *repository.ProjectRepository
	workspaceRepo       *repository.WorkspaceRepository
	runRepo             *repository.RunRepository
	ansibleJobRepo      *repository.AnsibleJobRepository
	ansiblePlaybookRepo *repository.AnsiblePlaybookRepository
	authService         *auth.Service
}

func NewDashboardHandler(
	orgRepo *repository.OrganizationRepository,
	projectRepo *repository.ProjectRepository,
	workspaceRepo *repository.WorkspaceRepository,
	runRepo *repository.RunRepository,
	ansibleJobRepo *repository.AnsibleJobRepository,
	ansiblePlaybookRepo *repository.AnsiblePlaybookRepository,
	authService *auth.Service,
) *DashboardHandler {
	return &DashboardHandler{
		orgRepo:             orgRepo,
		projectRepo:         projectRepo,
		workspaceRepo:       workspaceRepo,
		runRepo:             runRepo,
		ansibleJobRepo:      ansibleJobRepo,
		ansiblePlaybookRepo: ansiblePlaybookRepo,
		authService:         authService,
	}
}

// GetStats returns aggregated dashboard statistics for the authenticated user
// GET /api/v2/dashboard/stats
func (h *DashboardHandler) GetStats(c *gin.Context) {
	// Get authenticated user from context
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"errors": []gin.H{
				{
					"status": "401",
					"title":  "Unauthorized",
					"detail": "User not authenticated",
				},
			},
		})
		return
	}

	// Get all organizations the user belongs to
	orgs, err := h.orgRepo.ListByUser(user.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"errors": []gin.H{
				{
					"status": "500",
					"title":  "Internal Server Error",
					"detail": "Failed to load organizations",
				},
			},
		})
		return
	}

	// Initialize aggregate stats
	var totalProjects int64
	var totalWorkspaces int64
	var totalAnsiblePlaybooks int64
	var activeTerraformRuns int64
	var activeAnsibleJobs int64
	var completedTerraformRunsThisMonth int64
	var completedAnsibleJobsThisMonth int64

	// Calculate first day of current month for "this month" filtering
	now := time.Now()
	firstDayOfMonth := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location())

	// Organization-level stats
	orgStats := make([]gin.H, 0, len(orgs))

	// AUD-063: each metric is a single aggregate COUNT rather than loading every row and taking
	// len() (the old code paged up to 10k runs/jobs into memory per org and ran one ListByProject
	// per project — an N+1). A repository error now fails the whole request with a 500 instead of a
	// silent `continue` that under-reported totals as if nothing were wrong.
	statErr := func(detail string, err error) bool {
		if err == nil {
			return false
		}
		c.JSON(http.StatusInternalServerError, gin.H{
			"errors": []gin.H{
				{
					"status": "500",
					"title":  "Internal Server Error",
					"detail": detail,
				},
			},
		})
		return true
	}

	for _, org := range orgs {
		projectCount, err := h.projectRepo.CountByOrganization(org.ID)
		if statErr("Failed to count projects", err) {
			return
		}
		totalProjects += projectCount

		workspaceCount, err := h.workspaceRepo.CountByOrganization(org.ID)
		if statErr("Failed to count workspaces", err) {
			return
		}
		totalWorkspaces += workspaceCount

		playbookCount, err := h.ansiblePlaybookRepo.CountByOrganization(org.ID)
		if statErr("Failed to count playbooks", err) {
			return
		}
		totalAnsiblePlaybooks += playbookCount

		orgActiveRuns, err := h.runRepo.CountActiveByOrganizationAndUser(org.ID, user.ID)
		if statErr("Failed to count active runs", err) {
			return
		}
		activeTerraformRuns += orgActiveRuns

		orgCompletedRunsThisMonth, err := h.runRepo.CountCompletedSinceByOrganizationAndUser(org.ID, user.ID, firstDayOfMonth)
		if statErr("Failed to count completed runs", err) {
			return
		}
		completedTerraformRunsThisMonth += orgCompletedRunsThisMonth

		orgActiveJobs, err := h.ansibleJobRepo.CountActiveByOrganizationAndUser(org.ID, user.ID)
		if statErr("Failed to count active jobs", err) {
			return
		}
		activeAnsibleJobs += orgActiveJobs

		orgCompletedJobsThisMonth, err := h.ansibleJobRepo.CountSuccessfulSinceByOrganizationAndUser(org.ID, user.ID, firstDayOfMonth)
		if statErr("Failed to count completed jobs", err) {
			return
		}
		completedAnsibleJobsThisMonth += orgCompletedJobsThisMonth

		// Add organization stats
		orgStats = append(orgStats, gin.H{
			"id":                                  org.ID.String(),
			"name":                                org.Name,
			"description":                         org.Description,
			"projects":                            projectCount,
			"terraform_workspaces":                workspaceCount,
			"ansible_playbooks":                   playbookCount,
			"active_terraform_runs":               orgActiveRuns,
			"active_ansible_jobs":                 orgActiveJobs,
			"completed_terraform_runs_this_month": orgCompletedRunsThisMonth,
			"completed_ansible_jobs_this_month":   orgCompletedJobsThisMonth,
		})
	}

	// Return JSON:API compatible response
	c.JSON(http.StatusOK, gin.H{
		"data": gin.H{
			"type": "dashboard-stats",
			"attributes": gin.H{
				"projects":                            totalProjects,
				"terraform_workspaces":                totalWorkspaces,
				"ansible_playbooks":                   totalAnsiblePlaybooks,
				"active_terraform_runs":               activeTerraformRuns,
				"active_ansible_jobs":                 activeAnsibleJobs,
				"completed_terraform_runs_this_month": completedTerraformRunsThisMonth,
				"completed_ansible_jobs_this_month":   completedAnsibleJobsThisMonth,
				"organizations":                       orgStats,
			},
		},
	})
}
