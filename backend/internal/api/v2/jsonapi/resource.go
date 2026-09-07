// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package jsonapi

// The recurring JSON:API building blocks (#760). Before this, every handler spelled
// {"id": ..., "type": ...} and {"data": {...}} as anonymous maps at each site - the same
// half-dozen shapes re-typed hundreds of times, which is where list-versus-get drift breeds.

// ResourceID is a JSON:API resource identifier object.
type ResourceID struct {
	ID   string `json:"id"`
	Type string `json:"type"`
}

// Relationship is a to-one relationship. Data is a pointer so an empty relationship
// serialises as {"data": null}, which JSON:API distinguishes from the member being absent.
type Relationship struct {
	Data  *ResourceID `json:"data"`
	Links any         `json:"links,omitempty"`
}

// ToOne builds a populated to-one relationship.
func ToOne(id, typ string) Relationship {
	return Relationship{Data: &ResourceID{ID: id, Type: typ}}
}

// ManyRelationship is a to-many relationship; an empty one serialises as {"data": []}.
type ManyRelationship struct {
	Data  []ResourceID `json:"data"`
	Links any          `json:"links,omitempty"`
}

// SelfLink is the common {"self": "..."} links object.
type SelfLink struct {
	Self string `json:"self"`
}

// Resource is a generic JSON:API resource object. Attributes carries the per-resource typed
// struct; Relationships is either a typed struct or nil. Meta and Links follow the same
// omitempty discipline as Document.
type Resource[A any] struct {
	ID            string `json:"id"`
	Type          string `json:"type"`
	Attributes    A      `json:"attributes"`
	Relationships any    `json:"relationships,omitempty"`
	Links         any    `json:"links,omitempty"`
	Meta          any    `json:"meta,omitempty"`
}

// RelatedLink is the common {"related": "..."} relationship links object.
type RelatedLink struct {
	Related string `json:"related"`
}
