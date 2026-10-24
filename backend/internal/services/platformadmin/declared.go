// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Package platformadmin is the platform administrator: the one principal above the organization
// (#132). It owns the deployment's declared list, applies it at sign-in and at startup, and holds
// the one check every install-wide route calls. The flag on the user row is interpreted here and
// nowhere else.
package platformadmin

import (
	"os"
	"slices"
	"strings"
)

// Declared is the deployment's list of platform administrators, as lower-cased email addresses.
// The zero value is the empty list.
type Declared struct {
	emails map[string]struct{}
}

// NewDeclared returns the list of the given addresses, trimmed, lower-cased and de-duplicated;
// blank entries are dropped.
func NewDeclared(emails []string) Declared {
	d := Declared{emails: map[string]struct{}{}}
	for _, e := range emails {
		if e = normalizeEmail(e); e != "" {
			d.emails[e] = struct{}{}
		}
	}
	return d
}

// DeclaredFromEnv reads STACKWEAVER_PLATFORM_ADMINS, a comma-separated list of email addresses.
// When it holds no address, the list is the bootstrap admin's email from ZITADEL_ADMIN_USERNAME,
// which both installers set to the address of the human they create, or empty when that is unset
// too.
func DeclaredFromEnv() Declared {
	d := NewDeclared(strings.Split(os.Getenv("STACKWEAVER_PLATFORM_ADMINS"), ","))
	if d.Empty() {
		d = NewDeclared([]string{os.Getenv("ZITADEL_ADMIN_USERNAME")})
	}
	return d
}

// Contains reports whether email is on the list, compared case-insensitively.
func (d Declared) Contains(email string) bool {
	e := normalizeEmail(email)
	if e == "" {
		return false
	}
	_, ok := d.emails[e]
	return ok
}

// Empty reports whether the list holds no address.
func (d Declared) Empty() bool { return len(d.emails) == 0 }

// Emails returns the addresses on the list, sorted.
func (d Declared) Emails() []string {
	if len(d.emails) == 0 {
		return nil
	}
	out := make([]string, 0, len(d.emails))
	for e := range d.emails {
		out = append(out, e)
	}
	slices.Sort(out)
	return out
}

func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}
