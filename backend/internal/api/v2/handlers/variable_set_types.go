// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"fmt"

	"github.com/michielvha/stackweaver/backend/internal/api/v2/jsonapi"
	"github.com/michielvha/stackweaver/core/models"
)

// Typed varset wire shapes (#760). Before this, the varsets surface re-spelled its resource
// shape at eight call sites across 87 anonymous map literals - the single densest file in the
// tree - and the small deliberate differences between those sites (which relationships appear,
// whether created-at is present) were indistinguishable from accidents. The pointer fields
// below make each difference a visible decision.

// VarsetVarAttributes is the attribute block of a "vars" resource inside the varsets API.
//
// CreatedAt is a pointer because the surface genuinely differs: the list and show endpoints
// emit it, create and update do not, and the embedded copies inside a varset's `vars`
// relationship do not either. That asymmetry predates the typing and is preserved exactly.
type VarsetVarAttributes struct {
	Key         string  `json:"key"`
	Value       string  `json:"value"`
	Description string  `json:"description"`
	Sensitive   bool    `json:"sensitive"`
	Category    string  `json:"category"`
	HCL         bool    `json:"hcl"`
	CreatedAt   *string `json:"created-at,omitempty"`
}

// VarsetVarRelationships points a standalone vars resource back at its set.
type VarsetVarRelationships struct {
	Varset jsonapi.Relationship `json:"varset"`
}

// varsetVarEmbedded builds the bare id/type/attributes form embedded in a varset's `vars`
// relationship. Sensitive values are masked before they leave the process.
func varsetVarEmbedded(v *models.VariableSetVariable) jsonapi.Resource[VarsetVarAttributes] {
	value := v.Value
	if v.Sensitive {
		value = maskedValue
	}
	return jsonapi.Resource[VarsetVarAttributes]{
		ID:   v.ID,
		Type: "vars", // TFE uses "vars" not "variable-set-variables"
		Attributes: VarsetVarAttributes{
			Key:         v.Key,
			Value:       value,
			Description: v.Description,
			Sensitive:   v.Sensitive,
			Category:    v.Category,
			HCL:         v.HCL,
		},
	}
}

// varsetVarResource builds the standalone form with relationships and links.
// withCreatedAt reproduces the list/show versus create/update asymmetry.
func varsetVarResource(v *models.VariableSetVariable, setID string, withCreatedAt bool) jsonapi.Resource[VarsetVarAttributes] {
	res := varsetVarEmbedded(v)
	if withCreatedAt {
		created := v.CreatedAt.Format("2006-01-02T15:04:05Z")
		res.Attributes.CreatedAt = &created
	}
	rel := jsonapi.ToOne(setID, "varsets")
	rel.Links = jsonapi.RelatedLink{Related: fmt.Sprintf("/api/v2/varsets/%s", setID)}
	res.Relationships = VarsetVarRelationships{Varset: rel}
	res.Links = jsonapi.SelfLink{Self: fmt.Sprintf("/api/v2/vars/%s", v.ID)}
	return res
}

// VarsetVarsRelationship carries full embedded var resources, which is how TFE ships a
// varset's variables inline rather than as bare identifiers.
type VarsetVarsRelationship struct {
	Data []jsonapi.Resource[VarsetVarAttributes] `json:"data"`
}

// VarsetAttributes is the varsets attribute block.
type VarsetAttributes struct {
	Name           string `json:"name"`
	Description    string `json:"description"`
	Global         bool   `json:"global"`
	Priority       bool   `json:"priority"`
	UpdatedAt      string `json:"updated-at"`
	VarCount       int    `json:"var-count"`
	WorkspaceCount int    `json:"workspace-count"`
	ProjectCount   int    `json:"project-count"`
}

// VarsetRelationships: every member optional, because the five emitting endpoints deliberately
// include different subsets - list and show carry vars inline, update carries none, the
// job-template listing may omit organization. A nil member is absent, matching the old maps.
type VarsetRelationships struct {
	Organization *jsonapi.Relationship     `json:"organization,omitempty"`
	Parent       *jsonapi.Relationship     `json:"parent,omitempty"`
	Vars         *VarsetVarsRelationship   `json:"vars,omitempty"`
	Projects     *jsonapi.ManyRelationship `json:"projects,omitempty"`
	Workspaces   *jsonapi.ManyRelationship `json:"workspaces,omitempty"`
}

func varsetAttributes(vs *models.VariableSet, varCount, workspaceCount, projectCount int) VarsetAttributes {
	return VarsetAttributes{
		Name:           vs.Name,
		Description:    vs.Description,
		Global:         vs.Global, // AUD-150: global is its own field, independent of ownership
		Priority:       vs.Priority,
		UpdatedAt:      vs.UpdatedAt.Format("2006-01-02T15:04:05Z"),
		VarCount:       varCount,
		WorkspaceCount: workspaceCount,
		ProjectCount:   projectCount,
	}
}

func resourceIDs(typ string, ids []string) []jsonapi.ResourceID {
	out := make([]jsonapi.ResourceID, len(ids))
	for i, id := range ids {
		out[i] = jsonapi.ResourceID{ID: id, Type: typ}
	}
	return out
}
