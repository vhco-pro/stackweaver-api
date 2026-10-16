// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package rbac

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/services/apikey"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
)

// A request authenticated by an organization token that carries no organization-level scope is
// judged as the team or project its scope names, never as the token's owner. The mapping, after
// Terraform Enterprise's token types:
//
//	user token (kind=user)                  TFE user token          the user's own access
//	org key with an org:<id>:<level> scope  TFE organization token  the owner's access, capped by
//	                                                                the scope level at the org wall
//	team token (IsTeamToken, team:<id>)     TFE team token          the team's access alone
//	key with a team:<id> scope              no twin; as the team    the team's access, while the
//	                                                                owner is a member of the team
//	key with a project:<id>:<level> scope   no twin                 the owner's access, within that
//	                                                                project and up to that level
//
// A team-scoped key can be minted by any member of the organization, so it acts as the team only
// while its owner belongs to it: membership means the owner already holds everything the team
// grants, so the key never lends access the owner lacks. A project-scoped key likewise never
// exceeds its owner. The team token is minted by an owner and acts as the team whoever minted it.
type subjectKind int

const (
	subjectTeam subjectKind = iota + 1
	subjectProject
)

// Subject is the identity a scoped organization token is judged as. See the table above.
type Subject struct {
	kind           subjectKind
	organizationID uuid.UUID
	teamID         uuid.UUID
	denied         bool // a team-scoped key whose owner is not in the team: it reaches nothing
	projectID      uuid.UUID
	level          string // the highest level the project scope names
}

type subjectKey struct{}

// WithSubject returns a context in which every permission check is judged as subj.
func WithSubject(ctx context.Context, subj Subject) context.Context {
	return context.WithValue(ctx, subjectKey{}, subj)
}

func subjectFrom(ctx context.Context) (Subject, bool) {
	subj, ok := ctx.Value(subjectKey{}).(Subject)
	return subj, ok
}

// SubjectForAPIKey reports the subject an api key is judged as, and false when the key is judged
// as its owner (a user token, or an organization key with an organization-level scope). It is
// called once per request, by the authentication that accepts the key; isTeamMember settles there
// whether a team-scoped key's owner belongs to its team, so nothing later needs to ask.
func SubjectForAPIKey(key *models.APIKey, isTeamMember func(teamID, userID uuid.UUID) (bool, error)) (Subject, bool, error) {
	if key == nil || key.Kind != models.APIKeyKindOrg || key.OrganizationID == nil {
		return Subject{}, false, nil
	}
	if key.IsTeamToken && key.TeamID != nil {
		return Subject{kind: subjectTeam, organizationID: *key.OrganizationID, teamID: *key.TeamID}, true, nil
	}
	scopes, err := apikey.ParseScopes([]string(key.Scopes))
	if err != nil {
		// Unparseable scopes authorize nothing beyond what the org wall allows, and judged as a
		// project nobody has, they reach nothing.
		return Subject{kind: subjectProject, organizationID: *key.OrganizationID}, true, nil
	}
	var subj Subject
	for _, sc := range scopes {
		switch {
		case sc.Type == "org" || sc.Type == "*":
			return Subject{}, false, nil
		case sc.Type == "team" && sc.ResourceID != nil:
			subj = Subject{kind: subjectTeam, organizationID: *key.OrganizationID, teamID: *sc.ResourceID}
		case sc.Type == "project" && sc.ResourceID != nil && subj.kind != subjectTeam:
			level := subj.level
			if subj.kind != subjectProject || levelRank[sc.Permission] > levelRank[level] {
				level = sc.Permission
			}
			subj = Subject{kind: subjectProject, organizationID: *key.OrganizationID, projectID: *sc.ResourceID, level: level}
		}
	}
	if subj.kind == subjectTeam {
		member, err := isTeamMember(subj.teamID, key.UserID)
		if err != nil {
			return Subject{}, false, fmt.Errorf("checking membership of team %s: %w", subj.teamID, err)
		}
		subj.denied = !member
	}
	return subj, subj.kind != 0, nil
}

var levelRank = map[string]int{"read": 1, "write": 2, "admin": 3}

// projectScopeAllows reports, for a project subject, whether a permission on a resource of
// projectID lies within the key's project and level.
func (subj Subject) projectScopeAllows(permission Permission, projectID *uuid.UUID) bool {
	if projectID == nil || *projectID != subj.projectID || levelRank[subj.level] == 0 {
		return false
	}
	access := subj.level
	return (&Service{}).getPermissionsFromProjectAccess(&models.TeamProjectAccess{Access: &access}, "")[permission]
}

// UserInOrg reports whether the caller belongs to the organization: the user, or for a scoped
// token, its team or project. Handlers gate member-visible reads on it, so it is the one place
// that answer is given; a direct repository lookup would answer for the token's owner.
func UserInOrg(ctx context.Context, orgRepo *repository.OrganizationRepository, userID, orgID uuid.UUID) (bool, error) {
	subj, ok := subjectFrom(ctx)
	if !ok {
		return orgRepo.UserInOrg(userID, orgID)
	}
	if subj.organizationID != orgID || subj.denied {
		return false, nil
	}
	if subj.kind == subjectProject {
		return orgRepo.UserInOrg(userID, orgID)
	}
	return true, nil
}

// TeamsInOrg returns the teams the caller acts through in the organization: the user's teams, the
// token's team, or none for a project-scoped key, whose access is its project alone.
func TeamsInOrg(ctx context.Context, orgRepo *repository.OrganizationRepository, teamRepo *repository.TeamRepository, userID, orgID uuid.UUID) ([]models.Team, error) {
	subj, ok := subjectFrom(ctx)
	if !ok {
		return teamRepo.GetTeamsByUserID(userID, orgID)
	}
	if subj.kind == subjectProject {
		return nil, nil
	}
	in, err := UserInOrg(ctx, orgRepo, userID, orgID)
	if err != nil || !in {
		return nil, err
	}
	team, err := teamRepo.GetByID(subj.teamID)
	if err != nil || team.OrganizationID != orgID {
		return nil, nil //nolint:nilerr // a team that is gone grants nothing
	}
	return []models.Team{*team}, nil
}

// withoutSubject returns ctx judged as the token's owner. Used only once a project-scoped key's
// cap has been applied, to compute the owner's share of the answer.
func withoutSubject(ctx context.Context) context.Context {
	return context.WithValue(ctx, subjectKey{}, nil)
}

// isProjectSubject reports whether ctx carries a project-scoped key, which holds no
// organization-level permission of any kind.
func isProjectSubject(ctx context.Context) bool {
	subj, ok := subjectFrom(ctx)
	return ok && subj.kind == subjectProject
}

// inOrg and teamsOf are the membership lookups every check in this package goes through.
func (s *Service) inOrg(ctx context.Context, userID, orgID uuid.UUID) (bool, error) {
	return UserInOrg(ctx, s.orgRepo, userID, orgID)
}

func (s *Service) teamsOf(ctx context.Context, userID, orgID uuid.UUID) ([]models.Team, error) {
	subj, ok := subjectFrom(ctx)
	if ok && subj.kind == subjectProject {
		// A project-scoped key is capped at each check, and within that cap holds what its owner
		// holds; the owner's teams are what that is computed from.
		return s.teamRepo.GetTeamsByUserID(userID, orgID)
	}
	return TeamsInOrg(ctx, s.orgRepo, s.teamRepo, userID, orgID)
}

// UserInOrg is the package UserInOrg on this service's repositories.
func (s *Service) UserInOrg(ctx context.Context, userID, orgID uuid.UUID) (bool, error) {
	return s.inOrg(ctx, userID, orgID)
}

// TeamsInOrg is the package TeamsInOrg on this service's repositories.
func (s *Service) TeamsInOrg(ctx context.Context, userID, orgID uuid.UUID) ([]models.Team, error) {
	return TeamsInOrg(ctx, s.orgRepo, s.teamRepo, userID, orgID)
}
