// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"context"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/models"
)

// deliveryAttribution is who a webhook delivery belongs to (#938): the connections it reaches and
// their organizations. Several organizations can connect one GitHub App installation or one Azure
// DevOps organization, so a delivery is recorded once per organization, and each organization's
// event names only the resources it reached through its own connection.
type deliveryAttribution struct {
	// orgs are the organizations the delivery belongs to, each once, in connection order.
	orgs []uuid.UUID
	// orgOf maps a delivering connection to its organization.
	orgOf map[uuid.UUID]uuid.UUID
}

func newDeliveryAttribution(conns []models.VCSConnection) deliveryAttribution {
	a := deliveryAttribution{orgOf: map[uuid.UUID]uuid.UUID{}}
	seen := map[uuid.UUID]bool{}
	for _, c := range conns {
		if c.OrganizationID == uuid.Nil {
			continue
		}
		a.orgOf[c.ID] = c.OrganizationID
		if !seen[c.OrganizationID] {
			seen[c.OrganizationID] = true
			a.orgs = append(a.orgs, c.OrganizationID)
		}
	}
	return a
}

// installationAttribution is every organization's connection on a GitHub App installation. An
// installation nobody connected belongs to no organization. AUD-124: a delivery is attributed to
// the installation it was validated for, never to "the first workspace matching this repository
// name"; otherwise someone who installs the App on a same-named repository files their payloads
// into another organization's event log.
func (h *VCSAppInstallationHandlerV2) installationAttribution(installationID string) deliveryAttribution {
	if h.vcsConnectionRepo == nil || installationID == "" || installationID == "0" {
		return deliveryAttribution{}
	}
	conns, err := h.vcsConnectionRepo.ListByInstallationID(installationID)
	if err != nil {
		return deliveryAttribution{}
	}
	return newDeliveryAttribution(conns)
}

// adoAttribution is every Azure DevOps connection that has proven access to the delivery's Azure
// DevOps organization (adoConnectionTrusted). A connection that only names it is left out, so it
// receives none of that organization's events.
func (h *VCSAppInstallationHandlerV2) adoAttribution(adoOrg string) deliveryAttribution {
	if h.vcsConnectionRepo == nil || adoOrg == "" {
		return deliveryAttribution{}
	}
	conns, err := h.vcsConnectionRepo.ListByProviderAndAccountName(models.VCSProviderAzureDevOps, adoOrg)
	if err != nil {
		return deliveryAttribution{}
	}
	trusted := conns[:0]
	for i := range conns {
		if h.adoConnectionTrusted(context.Background(), &conns[i], adoOrg) {
			trusted = append(trusted, conns[i])
		}
	}
	return newDeliveryAttribution(trusted)
}

// orgTally is what a delivery reached in one organization.
type orgTally struct {
	workspaces             []models.Workspace
	playbooks, inventories int
}

// tallies groups what a delivery reached by organization.
type tallies map[uuid.UUID]*orgTally

func (a deliveryAttribution) tally(t tallies, conn *uuid.UUID) *orgTally {
	org := uuid.Nil
	if conn != nil {
		if o, ok := a.orgOf[*conn]; ok {
			org = o
		}
	}
	if t[org] == nil {
		t[org] = &orgTally{}
	}
	return t[org]
}

// addWorkspaces files each workspace under its connection's organization.
func (a deliveryAttribution) addWorkspaces(t tallies, workspaces []models.Workspace) {
	for _, ws := range workspaces {
		e := a.tally(t, ws.VCSConnectionID)
		e.workspaces = append(e.workspaces, ws)
	}
}

// recordAttributed records the delivery once in each organization it belongs to, with that
// organization's own tally, or once without an organization when it belongs to none (the
// combined tally, which can then only hold resources no organization owns through this delivery).
func (h *VCSAppInstallationHandlerV2) recordAttributed(a deliveryAttribution, t tallies, summarize func(*orgTally) (status, message string),
	eventType, provider, repo, branch, commit string, responseCode int, payload string,
) {
	if len(a.orgs) == 0 {
		all := &orgTally{}
		for _, e := range t {
			all.workspaces = append(all.workspaces, e.workspaces...)
			all.playbooks += e.playbooks
			all.inventories += e.inventories
		}
		status, message := summarize(all)
		h.recordWebhookEvent(nil, eventType, provider, repo, branch, commit, status, message, responseCode, payload)
		return
	}
	for _, org := range a.orgs {
		e := t[org]
		if e == nil {
			e = &orgTally{}
		}
		status, message := summarize(e)
		id := org
		h.recordWebhookEvent(&id, eventType, provider, repo, branch, commit, status, message, responseCode, payload)
	}
}

// fixedSummary records the same status and message in every organization, for a delivery that
// reached no resource at all.
func fixedSummary(status, message string) func(*orgTally) (string, string) {
	return func(*orgTally) (string, string) { return status, message }
}
