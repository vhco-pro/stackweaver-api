// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// What the golden write recorder commits (#869): the request it sent, what the handler bound it
// into, and the response it got, with the values that differ between runs replaced by
// placeholders.

//go:build integration
// +build integration

package routes_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/gin-gonic/gin/binding"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/openapi"
)

// goldenWriteDir holds one fixture per mutating route. A directory of its own, because the
// generator and several tests read every file in the golden directory and its errors/ child as
// a response fixture, which these are not.
const goldenWriteDir = "testdata/golden/writes"

// secretPlaceholder is what every secret is committed and published as. A case declares where
// its secrets are; nothing guesses from a member's name, because existing fixtures legitimately
// hold members called "key" and "token" that are not secrets.
const secretPlaceholder = "<secret>"

// variesPlaceholder stands for a value the server makes up afresh on every call and that is not
// a secret. Declared the same way, for the same reason: nothing guesses.
const variesPlaceholder = "<varies>"

// How the recorder learned a request body's schema.
const (
	schemaFromType    = "type"    // the Go type the handler bound, observed during the request
	schemaFromExample = "example" // the shape of the body that was accepted, nothing more
)

// writeFixture is the committed record of one mutating route: the write the server accepted, or
// the reason the route is named instead of recorded. Every mutating route has exactly one, so
// the generator, which reads fixtures and nothing else, can account for all of them.
type writeFixture struct {
	Method   string              `json:"method"`
	Path     string              `json:"path"`
	Request  writeFixtureRequest `json:"request,omitzero"`
	Status   int                 `json:"status,omitempty"`
	Response any                 `json:"response,omitempty"`
	// Named is set, and nothing else is, for a route that is not recorded.
	Named *writeFixtureNamed `json:"named,omitempty"`
}

// writeFixtureNamed is why a route was not recorded: one of the four reasons, and what this
// route in particular would need. Both are published in the operation's description.
type writeFixtureNamed struct {
	Reason string `json:"reason"`
	Detail string `json:"detail"`
}

// writeFixtureRequest is what was sent, and what is known about what may be sent.
type writeFixtureRequest struct {
	// ContentType is the media type sent, without parameters. Empty when the write has no body.
	ContentType string `json:"content_type,omitempty"`
	// Body is the JSON body as accepted, with identifiers, timestamps and secrets replaced by
	// placeholders and array order kept.
	Body any `json:"body,omitempty"`
	// Form is the fields of a form-encoded or multipart body; a file part is recorded as "<file>".
	Form map[string]string `json:"form,omitempty"`
	// Binary is set for a body that is neither JSON nor a form (an archive, a signed payload).
	Binary bool `json:"binary,omitempty"`
	// TakesNone is set when the write succeeded with no body and the handler bound nothing.
	TakesNone bool `json:"takes_none,omitempty"`
	// Schema describes the JSON body, and SchemaSource says where it came from.
	Schema       *openapi.Schema `json:"schema,omitempty"`
	SchemaSource string          `json:"schema_source,omitempty"`
	// BoundType names the Go type the handler bound, for a reader of the fixture.
	BoundType string `json:"bound_type,omitempty"`
}

// bindObserver sees every value a handler binds with ShouldBindJSON.
//
// gin decodes the body and then calls binding.Validator.ValidateStruct with the value the handler
// passed, so a validator that wraps the real one learns the exact Go type a handler decoded into
// without any change to the handlers. It delegates everything, so validation behaves as it does
// in production. The validator is a package-level variable: this is safe because the integration
// suites run with -p 1 and nothing in this package calls t.Parallel.
type bindObserver struct {
	inner binding.StructValidator
	mu    sync.Mutex
	seen  []reflect.Type
}

func (o *bindObserver) ValidateStruct(obj any) error {
	if obj != nil {
		o.mu.Lock()
		o.seen = append(o.seen, reflect.TypeOf(obj))
		o.mu.Unlock()
	}
	return o.inner.ValidateStruct(obj)
}

func (o *bindObserver) Engine() any { return o.inner.Engine() }

// reset forgets what was bound so far. The recorder calls it after a case's preparation, so
// that only the recorded request's bind is seen.
func (o *bindObserver) reset() {
	o.mu.Lock()
	o.seen = nil
	o.mu.Unlock()
}

// bound returns the first type bound since reset, or nil when the handler bound nothing.
func (o *bindObserver) bound() reflect.Type {
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.seen) == 0 {
		return nil
	}
	return o.seen[0]
}

// observeBinds installs the observer for the rest of the test and restores the real validator.
func observeBinds(t *testing.T) *bindObserver {
	t.Helper()
	o := &bindObserver{inner: binding.Validator}
	binding.Validator = o
	t.Cleanup(func() { binding.Validator = o.inner })
	return o
}

// normaliseRequest replaces the values of a recorded request that differ between runs with the
// same placeholders the response fixtures use, and leaves everything else as it was sent.
//
// It is not normalise, and the difference is the arrays. normalise sorts every array, because the
// API returns collections in no defined order. A request's arrays are the opposite: they are
// input, in the order the client chose, and the published example must show the request the
// server accepted. So this recurses the same way and keeps the order it finds.
//
// What comes out is therefore not replayable byte for byte - an identifier reads `<uuid>` - and
// the document says so. That is the price of a fixture that reproduces: seeded identifiers are
// freshly random on every seed.
func normaliseRequest(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			out[k] = normaliseRequest(val)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, val := range t {
			out[i] = normaliseRequest(val)
		}
		return out
	case string:
		return normaliseString(t)
	default:
		return v
	}
}

func normaliseString(s string) string {
	s = tokenRe.ReplaceAllString(s, "<token>")
	s = logTokenRe.ReplaceAllString(s, "token=<signed>")
	s = uuidRe.ReplaceAllString(s, "<uuid>")
	s = timestampRe.ReplaceAllString(s, "<timestamp>")
	s = tfeIDRe.ReplaceAllString(s, "<id>")
	return s
}

// redact replaces the value at a dotted path ("data.attributes.token", "items.0.secret") with
// the secret placeholder and reports whether the path existed.
//
// A declared secret that is not there is an error, not a no-op: it means the response changed
// shape and the secret may now be somewhere this declaration does not cover.
func redact(v any, path string) bool { return replaceAt(v, path, secretPlaceholder) }

// replaceAt puts placeholder at a dotted path and reports whether the path existed.
func replaceAt(v any, path, placeholder string) bool {
	segs := strings.Split(path, ".")
	cur := v
	for i, seg := range segs {
		last := i == len(segs)-1
		switch node := cur.(type) {
		case map[string]any:
			next, ok := node[seg]
			if !ok {
				return false
			}
			if last {
				node[seg] = placeholder
				return true
			}
			cur = next
		case []any:
			n, err := strconv.Atoi(seg)
			if err != nil || n < 0 || n >= len(node) {
				return false
			}
			if last {
				node[n] = placeholder
				return true
			}
			cur = node[n]
		default:
			return false
		}
	}
	return false
}

// isJSONMedia reports whether a media type carries a JSON document.
func isJSONMedia(mediaType string) bool {
	return mediaType == "application/json" || strings.HasSuffix(mediaType, "+json")
}

// describeRequest turns the request that was sent, and the type the handler bound it into, into
// the fixture's request record.
//
// idn, when not nil, replaces the values that are this run's own at the identity provider. It
// goes first, on the values as they were sent, so that no later rule can take half of one.
func describeRequest(req *http.Request, body []byte, bound reflect.Type, secrets []string, idn *identityNormaliser) (writeFixtureRequest, error) {
	var out writeFixtureRequest
	mediaType, params, _ := mime.ParseMediaType(req.Header.Get("Content-Type"))

	if len(body) == 0 {
		// No body. The handler may still have bound (an empty object decodes), but with nothing
		// sent and nothing bound, the write takes none.
		out.TakesNone = bound == nil
		return out, nil
	}
	out.ContentType = mediaType

	switch {
	case isJSONMedia(mediaType):
		var parsed any
		if err := json.Unmarshal(body, &parsed); err != nil {
			return out, fmt.Errorf("request body is declared %s and is not JSON: %w", mediaType, err)
		}
		for _, p := range secrets {
			if !redact(parsed, p) {
				return out, fmt.Errorf("declared request secret %q is not in the request body", p)
			}
		}
		example := normaliseRequest(idn.apply(parsed))
		out.Body = example

		// A struct the handler bound states every member; anything else is known only from
		// this one accepted example.
		elem := bound
		for elem != nil && elem.Kind() == reflect.Pointer {
			elem = elem.Elem()
		}
		if elem != nil && elem.Kind() == reflect.Struct {
			schema := openapi.SchemaForType(bound)
			openapi.FillOpaque(schema, example)
			out.Schema, out.SchemaSource = schema, schemaFromType
			out.BoundType = elem.String()
		} else {
			out.Schema, out.SchemaSource = openapi.SchemaForValue(example), schemaFromExample
		}

	case mediaType == "application/x-www-form-urlencoded":
		values, err := url.ParseQuery(string(body))
		if err != nil {
			return out, fmt.Errorf("form body does not parse: %w", err)
		}
		out.Form = map[string]string{}
		for k, v := range values {
			out.Form[k] = normaliseString(idn.text(strings.Join(v, ",")))
		}
		for _, p := range secrets {
			if _, ok := out.Form[p]; !ok {
				return out, fmt.Errorf("declared request secret %q is not a field of the form", p)
			}
			out.Form[p] = secretPlaceholder
		}

	case mediaType == "multipart/form-data":
		form, err := readMultipart(body, params["boundary"])
		if err != nil {
			return out, err
		}
		out.Form = form
		for _, p := range secrets {
			if _, ok := out.Form[p]; !ok {
				return out, fmt.Errorf("declared request secret %q is not a part of the form", p)
			}
			out.Form[p] = secretPlaceholder
		}

	default:
		if len(secrets) > 0 {
			return out, fmt.Errorf("request secrets were declared for a %s body, which is recorded as binary", mediaType)
		}
		out.Binary = true
	}
	return out, nil
}

// describeResponse parses, redacts and normalises a response body. A body that is not JSON is
// kept as a string, as the read recorder does.
func describeResponse(raw []byte, secrets, varies []string, idn *identityNormaliser) (any, error) {
	declared := len(secrets) + len(varies)
	if len(raw) == 0 {
		if declared > 0 {
			return nil, fmt.Errorf("response members were declared and the response has no body")
		}
		return nil, nil
	}
	var parsed any
	if err := json.Unmarshal(raw, &parsed); err != nil {
		if declared > 0 {
			return nil, fmt.Errorf("response members were declared and the response is not JSON")
		}
		return normaliseString(idn.text(string(raw))), nil
	}
	for _, p := range secrets {
		if !redact(parsed, p) {
			return nil, fmt.Errorf("declared response secret %q is not in the response; the response changed shape, and the secret may now be somewhere this declaration does not cover", p)
		}
	}
	for _, p := range varies {
		if !replaceAt(parsed, p, variesPlaceholder) {
			return nil, fmt.Errorf("declared varying response member %q is not in the response", p)
		}
	}
	return normalise(idn.apply(parsed)), nil
}

// readMultipart lists the parts of a multipart body: a field's value, or "<file>" for a file.
func readMultipart(body []byte, boundary string) (map[string]string, error) {
	if boundary == "" {
		return nil, fmt.Errorf("multipart body has no boundary")
	}
	form, err := multipart.NewReader(bytes.NewReader(body), boundary).ReadForm(32 << 20)
	if err != nil {
		return nil, fmt.Errorf("multipart body does not parse: %w", err)
	}
	defer func() { _ = form.RemoveAll() }()
	out := map[string]string{}
	for k, v := range form.Value {
		out[k] = normaliseString(strings.Join(v, ","))
	}
	for k := range form.File {
		out[k] = "<file>"
	}
	return out, nil
}

// writeFixturePath is where a route's write fixture lives.
func writeFixturePath(route string) string {
	method, path, _ := strings.Cut(route, " ")
	return filepath.Join(goldenWriteDir, fixtureName(method, path))
}

// saveOrCompare writes the fixture under -update and compares against the committed one otherwise.
func saveOrCompare(t *testing.T, got writeFixture) {
	t.Helper()
	path := writeFixturePath(got.Method + " " + got.Path)

	buf, err := json.MarshalIndent(got, "", "  ")
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	if *updateGolden {
		if err := os.MkdirAll(goldenWriteDir, 0o750); err != nil {
			t.Fatalf("create %s: %v", goldenWriteDir, err)
		}
		if err := os.WriteFile(path, append(buf, '\n'), 0o644); err != nil {
			t.Fatalf("write fixture: %v", err)
		}
		return
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Errorf("%s %s has no write fixture - run `make record-golden-writes`: %v", got.Method, got.Path, err)
		return
	}
	// Compared as parsed values, like the read fixtures: key order may move, nothing else may.
	var want, have any
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatalf("parse fixture %s: %v", path, err)
	}
	if err := json.Unmarshal(buf, &have); err != nil {
		t.Fatalf("re-parse recorded fixture: %v", err)
	}
	if !reflect.DeepEqual(have, want) {
		wantJSON, _ := json.MarshalIndent(want, "", "  ")
		t.Errorf("%s %s: the recorded write differs from its fixture\n--- want ---\n%s\n--- got ---\n%s", got.Method, got.Path, wantJSON, buf)
	}
}

// sortedKeys is a map's keys in order, for messages that must not change between runs.
func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
