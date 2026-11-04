// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Package levelrefs checks the references a level of the level rule makes (#933, D0, D6, D8): the
// run image and the identity binding a workspace, job template, inventory source, project or
// organization selects. The handlers of every level share it, so each validates the same way.
package levelrefs

import (
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/models"
	"gorm.io/gorm"
)

// Checker validates level references against the database.
type Checker struct {
	db *gorm.DB
}

// New builds a checker.
func New(db *gorm.DB) *Checker { return &Checker{db: db} }

// ErrInvalid is a reference the caller must correct (a 422).
var ErrInvalid = errors.New("invalid level reference")

// parse reads an attribute: absent leaves the level as it is, empty clears it.
func parse(raw *string) (id *uuid.UUID, set bool, err error) {
	if raw == nil {
		return nil, false, nil
	}
	if *raw == "" {
		return nil, true, nil
	}
	v, err := uuid.Parse(*raw)
	if err != nil {
		return nil, true, fmt.Errorf("%w: %q is not an id", ErrInvalid, *raw)
	}
	return &v, true, nil
}

// RunImage checks that raw names a run image of org for the engine kind.
func (c *Checker) RunImage(org uuid.UUID, kind string, raw *string) (*uuid.UUID, bool, error) {
	id, set, err := parse(raw)
	if err != nil || id == nil {
		return id, set, err
	}
	var img models.RunImage
	if err := c.db.Select("id", "organization_id", "kind").First(&img, "id = ?", *id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, true, fmt.Errorf("%w: no run image %s", ErrInvalid, *id)
		}
		return nil, true, err
	}
	if img.OrganizationID != org {
		return nil, true, fmt.Errorf("%w: the run image belongs to another organization", ErrInvalid)
	}
	if img.Kind != kind {
		return nil, true, fmt.Errorf("%w: the run image is for %s jobs, not %s", ErrInvalid, img.Kind, kind)
	}
	return id, true, nil
}

// IdentityBinding checks that raw names an identity binding of org. Whether the job's pool offers
// it is checked when the job is created (#933, D8).
func (c *Checker) IdentityBinding(org uuid.UUID, raw *string) (*uuid.UUID, bool, error) {
	id, set, err := parse(raw)
	if err != nil || id == nil {
		return id, set, err
	}
	var b models.IdentityBinding
	if err := c.db.Select("id", "organization_id").First(&b, "id = ?", *id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, true, fmt.Errorf("%w: no identity binding %s", ErrInvalid, *id)
		}
		return nil, true, err
	}
	if b.OrganizationID != org {
		return nil, true, fmt.Errorf("%w: the identity binding belongs to another organization", ErrInvalid)
	}
	return id, true, nil
}

// UUIDString is a level's selection on the wire: its id, or null.
func UUIDString(id *uuid.UUID) *string {
	if id == nil {
		return nil
	}
	s := id.String()
	return &s
}
