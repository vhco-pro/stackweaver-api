// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Package placement renders the placement record of a run, an Ansible job or a work item (#933, D4,
// AC77) as the read-only JSON:API attributes every native resource carries.
package placement

import (
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/settings"
)

// Attributes is the placement record on the wire.
type Attributes struct {
	Attempt           int     `json:"attempt"`
	Driver            string  `json:"driver"`
	PlacementID       string  `json:"placement-id"`
	Image             string  `json:"image"`
	ImageDigest       string  `json:"image-digest"`
	ImageLevel        string  `json:"image-level"`
	IdentityBindingID *string `json:"identity-binding-id"`
	Node              string  `json:"node"`
	// QueueReason says why waiting work on a hosted pool has not started: hosted_capacity_cap or
	// no_hosted_capacity_in_group, empty otherwise (#933, D9, AC56). QueueCap and QueueInFlight are
	// the hosted pool's cap (0 for unlimited) and its work in flight, null off a hosted pool.
	QueueReason   string `json:"queue-reason"`
	QueueCap      *int   `json:"queue-cap"`
	QueueInFlight *int   `json:"queue-in-flight"`
	// QueuePosition is the item's place in the hosted pool's queue, 1 for the next to start; null
	// off a hosted pool or once the item is not waiting.
	QueuePosition *int `json:"queue-position"`
}

// QueueReader reads a pool's queue state with the deployment's default cap, as an item queued at
// queuedAt sees it (repository.HostedQueueAt).
type QueueReader func(pool uuid.UUID, defaultCap int, queuedAt time.Time) (repository.HostedQueueState, error)

// WithQueue adds the queue state of a hosted pool to a waiting item's attributes. Work that is
// not waiting, or waits on a customer pool, keeps them empty; a lookup that fails leaves them too.
func WithQueue(read QueueReader, a Attributes, pool *uuid.UUID, queuedAt time.Time, waiting bool) Attributes {
	if !waiting || pool == nil || read == nil {
		return a
	}
	st, err := read(*pool, settings.HostedDefaultMaxConcurrentJobs(os.Getenv), queuedAt)
	if err != nil || st.Group == "" {
		return a
	}
	a.QueueReason, a.QueueCap, a.QueueInFlight = st.Reason, &st.Cap, &st.InFlight
	if st.Position > 0 {
		a.QueuePosition = &st.Position
	}
	return a
}

// FromModel renders a stored placement with its attempt.
func FromModel(attempt int, p models.JobPlacement) Attributes {
	a := Attributes{
		Attempt: attempt, Driver: p.Driver, PlacementID: p.PlacementID, Image: p.Image,
		ImageDigest: p.ImageDigest, ImageLevel: p.ImageLevel, Node: p.Node,
	}
	if p.IdentityBindingID != nil {
		s := p.IdentityBindingID.String()
		a.IdentityBindingID = &s
	}
	return a
}
