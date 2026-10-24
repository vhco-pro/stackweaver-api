// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package platformadmin

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/michielvha/stackweaver/core/models"
)

// OrganizationCreation is who may create an organization on this installation.
type OrganizationCreation string

const (
	// OrganizationCreationEveryone lets every signed-in user create organizations (the default).
	OrganizationCreationEveryone OrganizationCreation = "everyone"
	// OrganizationCreationPlatformAdmins limits organization creation to platform administrators.
	OrganizationCreationPlatformAdmins OrganizationCreation = "platform-admins"
)

// ParseOrganizationCreation reads a STACKWEAVER_ORGANIZATION_CREATION value. Empty means the
// default, everyone; any value other than everyone or platform-admins is an error.
func ParseOrganizationCreation(v string) (OrganizationCreation, error) {
	switch OrganizationCreation(strings.TrimSpace(v)) {
	case "", OrganizationCreationEveryone:
		return OrganizationCreationEveryone, nil
	case OrganizationCreationPlatformAdmins:
		return OrganizationCreationPlatformAdmins, nil
	}
	return "", fmt.Errorf("STACKWEAVER_ORGANIZATION_CREATION must be %q or %q, got %q",
		OrganizationCreationEveryone, OrganizationCreationPlatformAdmins, v)
}

// ConfigFromEnv reads the deployment's platform administration settings:
// STACKWEAVER_PLATFORM_ADMINS (see DeclaredFromEnv) and STACKWEAVER_ORGANIZATION_CREATION.
func ConfigFromEnv() (Config, error) {
	creation, err := ParseOrganizationCreation(os.Getenv("STACKWEAVER_ORGANIZATION_CREATION"))
	if err != nil {
		return Config{}, err
	}
	return Config{Declared: DeclaredFromEnv(), OrganizationCreation: creation}, nil
}

// OrganizationCreation reports the installation's organization-creation setting.
func (s *Service) OrganizationCreation() OrganizationCreation {
	if s.cfg.OrganizationCreation == "" {
		return OrganizationCreationEveryone
	}
	return s.cfg.OrganizationCreation
}

// CanCreateOrganizations reports whether the user may create an organization under the
// installation's setting.
func (s *Service) CanCreateOrganizations(_ context.Context, user *models.User) bool {
	admin, _ := Status(user)
	return s.canCreate(admin)
}

func (s *Service) canCreate(isAdmin bool) bool {
	return s.OrganizationCreation() == OrganizationCreationEveryone || isAdmin
}
