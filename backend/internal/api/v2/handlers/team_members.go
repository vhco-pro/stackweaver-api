// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/logger"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"gorm.io/gorm"
)

type TeamMemberHandlerV2 struct {
	teamRepo    *repository.TeamRepository
	orgRepo     *repository.OrganizationRepository
	userRepo    *repository.UserRepository
	authService *auth.Service
	rbacService *rbac.Service
}

func NewTeamMemberHandlerV2(
	teamRepo *repository.TeamRepository,
	orgRepo *repository.OrganizationRepository,
	userRepo *repository.UserRepository,
	authService *auth.Service,
	rbacService *rbac.Service,
) *TeamMemberHandlerV2 {
	return &TeamMemberHandlerV2{
		teamRepo:    teamRepo,
		orgRepo:     orgRepo,
		userRepo:    userRepo,
		authService: authService,
		rbacService: rbacService,
	}
}

// requireTeamMembershipManagement gates team-membership mutations (AUD-003). The owners
// team is only manageable by owners themselves — a ManageTeams/ManageMembership grant is
// not enough, since owners hold every permission and adding yourself would be escalation.
// Other teams accept either org-level grant (TFE semantics). Writes the JSON:API error
// response and returns false when the caller is not allowed.
func (h *TeamMemberHandlerV2) requireTeamMembershipManagement(c *gin.Context, team *models.Team) bool {
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"errors": []gin.H{
				{
					"status": "401",
					"title":  "Unauthorized",
					"detail": "Authentication required",
				},
			},
		})
		return false
	}

	ctx := c.Request.Context()
	if team.Name == "owners" {
		isOwner, err := h.rbacService.IsOrgOwner(ctx, user.ID, team.OrganizationID)
		if err == nil && isOwner {
			return true
		}
		c.JSON(http.StatusForbidden, gin.H{
			"errors": []gin.H{
				{
					"status": "403",
					"title":  "Forbidden",
					"detail": "Only organization owners can manage the owners team",
				},
			},
		})
		return false
	}

	if hasPermission, err := h.rbacService.CheckOrgManageTeams(ctx, user.ID, team.OrganizationID); err == nil && hasPermission {
		return true
	}
	if hasPermission, err := h.rbacService.CheckOrgManageMembership(ctx, user.ID, team.OrganizationID); err == nil && hasPermission {
		return true
	}
	c.JSON(http.StatusForbidden, gin.H{
		"errors": []gin.H{
			{
				"status": "403",
				"title":  "Forbidden",
				"detail": "Only organization admins can manage team membership",
			},
		},
	})
	return false
}

// ListOrganizationMemberships handles GET /api/v2/teams/:id/relationships/organization-memberships
// Returns organization memberships for a team (frontend-specific endpoint)
func (h *TeamMemberHandlerV2) ListOrganizationMemberships(c *gin.Context) {
	teamIDStr := c.Param("id")
	teamID, err := uuid.Parse(teamIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"errors": []gin.H{
				{
					"status": "400",
					"title":  "Bad Request",
					"detail": "Invalid team ID format",
				},
			},
		})
		return
	}

	// Get team
	team, err := h.teamRepo.GetByID(teamID)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{
				"errors": []gin.H{
					{
						"status": "404",
						"title":  "Not Found",
						"detail": "Team not found",
					},
				},
			})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{
			"errors": []gin.H{
				{
					"status": "500",
					"title":  "Internal Server Error",
					"detail": "Failed to retrieve team",
				},
			},
		})
		return
	}

	// AUD-003 (read side): team rosters carry usernames + emails — tenant data.
	// Require the caller to be a member of the team's organization.
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"errors": []gin.H{
				{
					"status": "401",
					"title":  "Unauthorized",
					"detail": "Authentication required",
				},
			},
		})
		return
	}
	inOrg, err := h.orgRepo.UserInOrg(user.ID, team.OrganizationID)
	if err != nil || !inOrg {
		c.JSON(http.StatusForbidden, gin.H{
			"errors": []gin.H{
				{
					"status": "403",
					"title":  "Forbidden",
					"detail": "You are not a member of this team's organization",
				},
			},
		})
		return
	}

	// Get organization name for response formatting
	org, err := h.orgRepo.GetByID(team.OrganizationID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"errors": []gin.H{
				{
					"status": "500",
					"title":  "Internal Server Error",
					"detail": "Failed to retrieve organization",
				},
			},
		})
		return
	}

	// Get organization memberships for all team members
	userIDs := make([]uuid.UUID, 0, len(team.Members))
	for _, member := range team.Members {
		userIDs = append(userIDs, member.UserID)
	}

	var orgMemberships []models.OrganizationMember
	if len(userIDs) > 0 {
		orgMemberships, err = h.orgRepo.GetMembersByUserIDs(team.OrganizationID, userIDs)
		if err != nil {
			logger.Errorf("TeamMember ListOrganizationMemberships - Failed to get organization memberships for team %s: %v", teamIDStr, err)
			c.JSON(http.StatusInternalServerError, gin.H{
				"errors": []gin.H{
					{
						"status": "500",
						"title":  "Internal Server Error",
						"detail": "Failed to retrieve organization memberships",
					},
				},
			})
			return
		}
	}

	// Always return JSON:API format (no simple format handling)
	// Use formatOrganizationMembershipResponse for consistent formatting
	data := make([]gin.H, len(orgMemberships))
	included := make([]gin.H, 0)
	seenUserIDs := make(map[uuid.UUID]bool)

	for i, membership := range orgMemberships {
		// Use the same formatting function as organization_memberships.go for consistency
		membershipData := formatOrganizationMembershipResponse(&membership, org.Name)
		data[i] = membershipData

		// Include user data in included array (JSON:API pattern)
		if membership.User.ID != uuid.Nil && !seenUserIDs[membership.User.ID] {
			seenUserIDs[membership.User.ID] = true
			included = append(included, gin.H{
				"id":   membership.User.ID.String(),
				"type": "users",
				"attributes": gin.H{
					"username": membership.User.Username,
					"email":    membership.User.Email,
					"name":     membership.User.Name,
				},
			})
		}
	}

	response := gin.H{"data": data}
	if len(included) > 0 {
		response["included"] = included
	}
	c.JSON(http.StatusOK, response)
}

// AddOrganizationMemberships handles POST /api/v2/teams/:id/relationships/organization-memberships
// TFE-compatible: Adds organization memberships to a team
// Reference: go-tfe/team_member.go - TeamMembers.Add with OrganizationMembershipIDs
func (h *TeamMemberHandlerV2) AddOrganizationMemberships(c *gin.Context) {
	teamIDStr := c.Param("id")
	teamID, err := uuid.Parse(teamIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"errors": []gin.H{
				{
					"status": "400",
					"title":  "Bad Request",
					"detail": "Invalid team ID format",
				},
			},
		})
		return
	}

	// Get team
	team, err := h.teamRepo.GetByID(teamID)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{
				"errors": []gin.H{
					{
						"status": "404",
						"title":  "Not Found",
						"detail": "Team not found",
					},
				},
			})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{
			"errors": []gin.H{
				{
					"status": "500",
					"title":  "Internal Server Error",
					"detail": "Failed to retrieve team",
				},
			},
		})
		return
	}

	// AUD-003: mutating team membership requires team-management permission —
	// without this check any org member could add themselves to the owners team.
	if !h.requireTeamMembershipManagement(c, team) {
		return
	}

	// Parse request body - TFE sends JSON:API format: {"data": [{"type": "...", "id": "..."}, ...]}
	// go-tfe uses jsonapi.MarshalPayloadWithoutIncluded which wraps arrays in {"data": [...]}
	var req struct {
		Data []struct {
			Type string `json:"type" binding:"required"`
			ID   string `json:"id" binding:"required"`
		} `json:"data" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		logger.Debugf("TeamMember AddOrganizationMemberships - JSON parse error: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{
			"errors": []gin.H{
				{
					"status": "400",
					"title":  "Bad Request",
					"detail": err.Error(),
				},
			},
		})
		return
	}

	logger.Debugf("TeamMember AddOrganizationMemberships - Team ID: %s, Memberships: %d", teamIDStr, len(req.Data))

	// Process each organization membership
	for _, membershipRef := range req.Data {
		if membershipRef.Type != "organization-memberships" {
			c.JSON(http.StatusBadRequest, gin.H{
				"errors": []gin.H{
					{
						"status": "400",
						"title":  "Bad Request",
						"detail": "Invalid type, expected 'organization-memberships'",
					},
				},
			})
			return
		}

		// Parse membership ID
		membershipID, err := uuid.Parse(membershipRef.ID)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"errors": []gin.H{
					{
						"status": "400",
						"title":  "Bad Request",
						"detail": fmt.Sprintf("Invalid organization membership ID: %s", membershipRef.ID),
					},
				},
			})
			return
		}

		// Get organization membership
		membership, err := h.orgRepo.GetMemberByID(membershipID)
		if err != nil {
			if err == gorm.ErrRecordNotFound {
				logger.Errorf("TeamMember AddOrganizationMemberships - Membership %s not found. This may indicate Terraform state is out of sync.", membershipRef.ID)
				c.JSON(http.StatusNotFound, gin.H{
					"errors": []gin.H{
						{
							"status": "404",
							"title":  "Not Found",
							"detail": fmt.Sprintf("Organization membership not found: %s. This may indicate the membership was deleted or recreated with a different ID.", membershipRef.ID),
						},
					},
				})
				return
			}
			logger.Errorf("TeamMember AddOrganizationMemberships - Error getting membership %s: %v", membershipRef.ID, err)
			c.JSON(http.StatusInternalServerError, gin.H{
				"errors": []gin.H{
					{
						"status": "500",
						"title":  "Internal Server Error",
						"detail": "Failed to retrieve organization membership",
					},
				},
			})
			return
		}

		// Verify membership belongs to same organization as team
		if membership.OrganizationID != team.OrganizationID {
			c.JSON(http.StatusBadRequest, gin.H{
				"errors": []gin.H{
					{
						"status": "400",
						"title":  "Bad Request",
						"detail": "Organization membership must belong to the same organization as the team",
					},
				},
			})
			return
		}

		// Add user to team (via team member)
		// Check if already a member
		existingMembers, _ := h.teamRepo.GetMembers(teamID)
		alreadyMember := false
		for _, member := range existingMembers {
			if member.ID == membership.UserID {
				alreadyMember = true
				break
			}
		}

		if !alreadyMember {
			if err := h.teamRepo.AddMember(teamID, membership.UserID); err != nil {
				logger.Debugf("TeamMember AddOrganizationMemberships - Failed to add member: %v", err)
				c.JSON(http.StatusInternalServerError, gin.H{
					"errors": []gin.H{
						{
							"status": "500",
							"title":  "Internal Server Error",
							"detail": fmt.Sprintf("Failed to add user to team: %v", err),
						},
					},
				})
				return
			}
			logger.Debugf("TeamMember AddOrganizationMemberships - Added user %s to team %s", membership.UserID.String(), teamIDStr)
		}
	}

	// TFE returns 204 No Content on success
	c.Status(http.StatusNoContent)
}

// RemoveOrganizationMemberships handles DELETE /api/v2/teams/:id/relationships/organization-memberships
// TFE-compatible: Removes organization memberships from a team
func (h *TeamMemberHandlerV2) RemoveOrganizationMemberships(c *gin.Context) {
	teamIDStr := c.Param("id")
	teamID, err := uuid.Parse(teamIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"errors": []gin.H{
				{
					"status": "400",
					"title":  "Bad Request",
					"detail": "Invalid team ID format",
				},
			},
		})
		return
	}

	// Get team (verify it exists)
	team, err := h.teamRepo.GetByID(teamID)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{
				"errors": []gin.H{
					{
						"status": "404",
						"title":  "Not Found",
						"detail": "Team not found",
					},
				},
			})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{
			"errors": []gin.H{
				{
					"status": "500",
					"title":  "Internal Server Error",
					"detail": "Failed to retrieve team",
				},
			},
		})
		return
	}

	// AUD-003: removing members requires the same permission as adding them —
	// without this check any org member could strip all owners from a team (lockout).
	if !h.requireTeamMembershipManagement(c, team) {
		return
	}

	// Parse request body - TFE sends JSON:API format: {"data": [{"type": "...", "id": "..."}, ...]}
	var req struct {
		Data []struct {
			Type string `json:"type" binding:"required"`
			ID   string `json:"id" binding:"required"`
		} `json:"data" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"errors": []gin.H{
				{
					"status": "400",
					"title":  "Bad Request",
					"detail": err.Error(),
				},
			},
		})
		return
	}

	// Process each organization membership
	for _, membershipRef := range req.Data {
		if membershipRef.Type != "organization-memberships" {
			continue
		}

		membershipID, err := uuid.Parse(membershipRef.ID)
		if err != nil {
			logger.Debugf("TeamMember RemoveOrganizationMemberships - Invalid membership ID: %s", membershipRef.ID)
			continue
		}

		// Get organization membership
		membership, err := h.orgRepo.GetMemberByID(membershipID)
		if err != nil {
			// If membership not found, it may have been deleted already or never existed
			// This can happen during destroy operations or when Terraform state is out of sync
			// Just log and continue - we can't remove a membership that doesn't exist
			if err == gorm.ErrRecordNotFound {
				logger.Warnf("TeamMember RemoveOrganizationMemberships - Membership %s not found (may have been deleted or state is out of sync), continuing", membershipRef.ID)
				continue
			}
			logger.Errorf("TeamMember RemoveOrganizationMemberships - Error getting membership %s: %v", membershipRef.ID, err)
			continue
		}

		// Remove user from team (ignore error if user is not in team)
		if err := h.teamRepo.RemoveMember(teamID, membership.UserID); err != nil {
			logger.Debugf("TeamMember RemoveOrganizationMemberships - Error removing user %s from team %s: %v", membership.UserID.String(), teamIDStr, err)
			// Continue processing other memberships even if one fails
		} else {
			logger.Debugf("TeamMember RemoveOrganizationMemberships - Removed user %s from team %s", membership.UserID.String(), teamIDStr)
		}
	}

	// TFE returns 204 No Content on success
	c.Status(http.StatusNoContent)
}

// resolveTeamMemberIdentifier resolves a tfe_team_members `usernames` entry to an existing user that
// belongs to the team's organization. TFE addresses team members by a unique username; Stackweaver
// provisions users from Zitadel without a populated username, so the identifier is resolved by EMAIL
// (case-insensitive) — the stable, org-portable identity (documented divergence). The user must
// already be a member of the team's organization (tenant safety: no cross-org resolution, and you add
// existing org members to teams, matching TFE). Returns the user, or writes a JSON:API error + false.
func (h *TeamMemberHandlerV2) resolveTeamMemberIdentifier(c *gin.Context, team *models.Team, identifier string) (*models.User, bool) {
	user, err := h.userRepo.GetByEmailCaseInsensitive(identifier)
	if err != nil || user == nil {
		c.JSON(http.StatusNotFound, gin.H{"errors": []gin.H{{"status": "404", "title": "Not Found", "detail": fmt.Sprintf("No user found for %q — Stackweaver identifies team members by email; ensure the user exists and is a member of the organization", identifier)}}})
		return nil, false
	}
	// Tenant safety: the user must be a member of the team's organization. This both matches TFE
	// (team members are drawn from org members) and prevents adding/probing users from other orgs.
	if _, err := h.orgRepo.GetMember(team.OrganizationID, user.ID); err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"errors": []gin.H{{"status": "422", "title": "Unprocessable Entity", "detail": fmt.Sprintf("User %q is not a member of this organization — add them to the organization before adding them to a team", identifier)}}})
		return nil, false
	}
	return user, true
}

// AddUsers handles POST /api/v2/teams/:id/relationships/users
// TFE spec: go-tfe TeamMembers.Add with Usernames. go-tfe serializes each username as the JSON:API
// resource id of a "users" resource: {"data":[{"type":"users","id":"<username>"}]}. Stackweaver
// resolves the id as an email (see resolveTeamMemberIdentifier). Reference:
// https://developer.hashicorp.com/terraform/enterprise/api-docs/team-members#add-a-user-to-team
func (h *TeamMemberHandlerV2) AddUsers(c *gin.Context) {
	teamIDStr := c.Param("id")
	teamID, err := uuid.Parse(teamIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"errors": []gin.H{{"status": "400", "title": "Bad Request", "detail": "Invalid team ID format"}}})
		return
	}

	team, err := h.teamRepo.GetByID(teamID)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"errors": []gin.H{{"status": "404", "title": "Not Found", "detail": "Team not found"}}})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"errors": []gin.H{{"status": "500", "title": "Internal Server Error", "detail": "Failed to retrieve team"}}})
		return
	}

	if !h.requireTeamMembershipManagement(c, team) {
		return
	}

	// go-tfe sends the username as the resource id: {"data":[{"type":"users","id":"<username>"}]}.
	var req struct {
		Data []struct {
			Type string `json:"type" binding:"required"`
			ID   string `json:"id" binding:"required"`
		} `json:"data" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"errors": []gin.H{{"status": "400", "title": "Bad Request", "detail": err.Error()}}})
		return
	}

	for _, userRef := range req.Data {
		if userRef.Type != "users" {
			c.JSON(http.StatusBadRequest, gin.H{"errors": []gin.H{{"status": "400", "title": "Bad Request", "detail": "Invalid type, expected 'users'"}}})
			return
		}
		user, ok := h.resolveTeamMemberIdentifier(c, team, userRef.ID)
		if !ok {
			return
		}
		// Idempotent: skip if already a member.
		if isMember, _ := h.teamRepo.IsMember(teamID, user.ID); isMember {
			continue
		}
		if err := h.teamRepo.AddMember(teamID, user.ID); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"errors": []gin.H{{"status": "500", "title": "Internal Server Error", "detail": fmt.Sprintf("Failed to add user to team: %v", err)}}})
			return
		}
		logger.Debugf("TeamMember AddUsers - Added user %s to team %s", user.ID.String(), teamIDStr)
	}

	c.Status(http.StatusNoContent)
}

// RemoveUsers handles DELETE /api/v2/teams/:id/relationships/users
// TFE spec: go-tfe TeamMembers.Remove with Usernames (same id-as-username serialization as AddUsers).
// Reference:
// https://developer.hashicorp.com/terraform/enterprise/api-docs/team-members#delete-a-user-from-team
func (h *TeamMemberHandlerV2) RemoveUsers(c *gin.Context) {
	teamIDStr := c.Param("id")
	teamID, err := uuid.Parse(teamIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"errors": []gin.H{{"status": "400", "title": "Bad Request", "detail": "Invalid team ID format"}}})
		return
	}

	team, err := h.teamRepo.GetByID(teamID)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"errors": []gin.H{{"status": "404", "title": "Not Found", "detail": "Team not found"}}})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"errors": []gin.H{{"status": "500", "title": "Internal Server Error", "detail": "Failed to retrieve team"}}})
		return
	}

	if !h.requireTeamMembershipManagement(c, team) {
		return
	}

	var req struct {
		Data []struct {
			Type string `json:"type" binding:"required"`
			ID   string `json:"id" binding:"required"`
		} `json:"data" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"errors": []gin.H{{"status": "400", "title": "Bad Request", "detail": err.Error()}}})
		return
	}

	for _, userRef := range req.Data {
		if userRef.Type != "users" {
			continue
		}
		// Resolve by email but do NOT require current org membership on removal — a user removed from
		// the org should still be strippable from the team, and destroy paths must be forgiving.
		user, err := h.userRepo.GetByEmailCaseInsensitive(userRef.ID)
		if err != nil || user == nil {
			logger.Warnf("TeamMember RemoveUsers - No user for %q (may already be gone), continuing", userRef.ID)
			continue
		}
		if err := h.teamRepo.RemoveMember(teamID, user.ID); err != nil {
			logger.Debugf("TeamMember RemoveUsers - Error removing user %s from team %s: %v", user.ID.String(), teamIDStr, err)
		} else {
			logger.Debugf("TeamMember RemoveUsers - Removed user %s from team %s", user.ID.String(), teamIDStr)
		}
	}

	c.Status(http.StatusNoContent)
}
