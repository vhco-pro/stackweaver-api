// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package platformadmin

import "testing"

// AC19: organization creation is everyone (the default) or platform-admins; anything else is an
// error, so the API refuses to start on a typo rather than opening or closing creation silently.
func TestParseOrganizationCreation(t *testing.T) {
	for _, tt := range []struct {
		in      string
		want    OrganizationCreation
		wantErr bool
	}{
		{"", OrganizationCreationEveryone, false},
		{"everyone", OrganizationCreationEveryone, false},
		{" platform-admins ", OrganizationCreationPlatformAdmins, false},
		{"Platform-Admins", "", true},
		{"admins", "", true},
		{"nobody", "", true},
	} {
		got, err := ParseOrganizationCreation(tt.in)
		if (err != nil) != tt.wantErr || got != tt.want {
			t.Errorf("ParseOrganizationCreation(%q) = %q, %v; want %q, error %v", tt.in, got, err, tt.want, tt.wantErr)
		}
	}
}

func TestCanCreateOrganizations(t *testing.T) {
	admin := Service{cfg: Config{OrganizationCreation: OrganizationCreationPlatformAdmins}}
	open := Service{}
	for _, tt := range []struct {
		name    string
		svc     *Service
		isAdmin bool
		want    bool
	}{
		{"everyone, non-admin", &open, false, true},
		{"everyone, admin", &open, true, true},
		{"platform-admins, non-admin", &admin, false, false},
		{"platform-admins, admin", &admin, true, true},
	} {
		if got := tt.svc.canCreate(tt.isAdmin); got != tt.want {
			t.Errorf("%s: canCreate = %v, want %v", tt.name, got, tt.want)
		}
	}
}
