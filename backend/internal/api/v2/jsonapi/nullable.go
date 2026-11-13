// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package jsonapi

import (
	"bytes"
	"encoding/json"
	"reflect"
)

// Nullable is a request attribute that tells an absent key, a JSON null and a value apart. A plain
// *T cannot: encoding/json leaves it nil for an absent key and for null alike. An attribute whose
// null means "clear back to inheriting" while an absent key means "leave it" binds through this
// (#1069, D2: a workspace's terraform-version and an organization's default-terraform-version).
//
// The zero value is an absent key. Present is set when the key was in the document; Null when its
// value was null, in which case Value is the zero value.
type Nullable[T any] struct {
	Present bool
	Null    bool
	Value   T
}

// UnmarshalJSON records that the key was present and whether it was null. encoding/json calls it
// for a null too, because Nullable is a struct and not a pointer.
func (n *Nullable[T]) UnmarshalJSON(data []byte) error {
	n.Present = true
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		n.Null = true
		var zero T
		n.Value = zero
		return nil
	}
	return json.Unmarshal(data, &n.Value)
}

// NullableElem reports the type a Nullable carries, so the OpenAPI document describes the member
// as that type, nullable, rather than as an opaque value.
func (Nullable[T]) NullableElem() reflect.Type { return reflect.TypeFor[T]() }
