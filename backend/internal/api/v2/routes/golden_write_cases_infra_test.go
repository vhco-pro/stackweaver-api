// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

//go:build integration
// +build integration

package routes_test

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/michielvha/stackweaver/core/queue"
)

// infraGPGPublicKey is the public half of a key generated once for these cases; the private half
// was discarded. It is a constant, not a key generated per run, because the key id is the
// resource's identifier: it is in the response, in the publish form and in the URL, so a fresh
// key would give a fixture that never reproduces. A public key is not a secret.
const (
	infraGPGKeyID     = "9FDEA9EA70FFAA2C"
	infraGPGPublicKey = `-----BEGIN PGP PUBLIC KEY BLOCK-----

xjMEas0K1hYJKwYBBAHaRw8BAQdAh01KN8xf8Ktli4eVGbLFxniuogsxNQxnkV1/
z3D+I/zNKUV4YW1wbGUgUHVibGlzaGVyIDxwdWJsaXNoZXJAZXhhbXBsZS5jb20+
wr0EExYIAG8FgmrNCtYCCwcJEJ/eqepw/6osNRQAAAAAABwAEHNhbHRAbm90YXRp
b25zLm9wZW5wZ3Bqcy5vcmeSBhf5NmyOW5uc03S3sOYmAhUIAhYAAhkBApsDAh4B
FiEE04bZtLiGDFZM0bvln96p6nD/qiwAADwPAQC8R5butyQqGWZLIfEYoWR56NTz
pEJBrNGpdUBoJ4hV9QEAvIruX8dWCXK6DYxJchtTI44QKXVPlNV14JgdX660pgPO
OARqzQrWEgorBgEEAZdVAQUBAQdAor8PZLBVOUKLMrYzZ7Uir1rzd/QJ/l+UJV7Y
0wnU+BADAQoJwq4EGBYIAGAFgmrNCtYJEJ/eqepw/6osNRQAAAAAABwAEHNhbHRA
bm90YXRpb25zLm9wZW5wZ3Bqcy5vcmerHCZzfOX7oKC5zqSJn+CWApsMFiEE04bZ
tLiGDFZM0bvln96p6nD/qiwAANStAQDdiHiEp7Zr878xnS3l66bH2QvdTy8DYoEa
B0l9PmhDbAEAitlue+AM5KjGbnJ6GQGyMUh+rsWJbMXxX72b1pPlfg0=
=MEZv
-----END PGP PUBLIC KEY BLOCK-----
`
)

// infraToMany adds a to-many relationship to a document built by document.
func infraToMany(doc map[string]any, name, resourceType string, ids ...string) map[string]any {
	data := doc["data"].(map[string]any)
	rels, _ := data["relationships"].(map[string]any)
	if rels == nil {
		rels = map[string]any{}
		data["relationships"] = rels
	}
	refs := make([]any, 0, len(ids))
	for _, id := range ids {
		refs = append(refs, map[string]any{"type": resourceType, "id": id})
	}
	rels[name] = map[string]any{"data": refs}
	return doc
}

// infraCreateGPGKey registers the fixed public key with the seeded organization, which has none.
func infraCreateGPGKey(t *testing.T, w *writeRun) {
	t.Helper()
	w.mustSend(t, w.jsonRequest(t, http.MethodPost, w.path("/api/registry/:registry/v2/gpg-keys"),
		document("gpg-keys", map[string]any{"namespace": w.org(), "ascii-armor": infraGPGPublicKey})))
}

// infraRunner is a runner registered into a seeded agent pool the way an agent does it.
type infraRunner struct {
	id     string
	token  string // the runner-scoped token registration returns
	poolID string
}

// infraAgentToken mints a registration token for the seeded agent pool. Registration admits only
// an API key carrying runner:register, which the harness's own user token does not.
func infraAgentToken(t *testing.T, w *writeRun) string {
	t.Helper()
	minted := w.mustSend(t, w.jsonRequest(t, http.MethodPost, w.path("/api/v2/agent-pools/:id/authentication-tokens"),
		document("authentication-tokens", map[string]any{"description": "golden-write-agent"})))
	data, _ := minted["data"].(map[string]any)
	attrs, _ := data["attributes"].(map[string]any)
	token, _ := attrs["token"].(string)
	if token == "" {
		t.Fatalf("minting an agent token returned none: %v", minted)
	}
	return token
}

// infraPlainRequest builds an authenticated request whose body is plain JSON. A few routes here
// predate the JSON:API convention or speak another party's protocol, and a client sends them
// application/json, which is what the published document should say.
func infraPlainRequest(t *testing.T, w *writeRun, method, target string, body any) *http.Request {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal request body: %v", err)
	}
	return w.rawRequest(method, target, "application/json", raw)
}

// infraRunnerRequest builds a runner-protocol request. The protocol is plain JSON and is
// authenticated by the token of whoever is calling: an agent token to register, the runner's own
// token for everything after.
func infraRunnerRequest(t *testing.T, w *writeRun, token, target string, body any) *http.Request {
	t.Helper()
	req := infraPlainRequest(t, w, http.MethodPost, target, body)
	req.Header.Set("Authorization", "Bearer "+token)
	return req
}

// infraFile is one file part of a multipart form.
type infraFile struct {
	field, name string
	content     []byte
}

// infraMultipartRequest builds an authenticated multipart form, which is how the registry takes
// an upload together with what it is.
func infraMultipartRequest(t *testing.T, w *writeRun, target string, fields map[string]string, files ...infraFile) *http.Request {
	t.Helper()
	var buf bytes.Buffer
	form := multipart.NewWriter(&buf)
	for name, value := range fields {
		if err := form.WriteField(name, value); err != nil {
			t.Fatalf("write form field %s: %v", name, err)
		}
	}
	for _, f := range files {
		part, err := form.CreateFormFile(f.field, f.name)
		if err != nil {
			t.Fatalf("create form file %s: %v", f.field, err)
		}
		if _, err := part.Write(f.content); err != nil {
			t.Fatalf("write form file %s: %v", f.field, err)
		}
	}
	if err := form.Close(); err != nil {
		t.Fatalf("close form: %v", err)
	}
	return w.rawRequest(http.MethodPost, target, form.FormDataContentType(), buf.Bytes())
}

// infraWebhookSecret is the shared secret the inbound-webhook cases start their server with (the
// case's env) and sign with. It is a test value, not a credential of anything.
const infraWebhookSecret = "golden-write-webhook-secret"

// infraUnauthenticated builds a request for a route no token authenticates: an inbound webhook or
// a public protocol endpoint, where the proof is a signature or a one-time code.
func infraUnauthenticated(w *writeRun, target, contentType string, body []byte) *http.Request {
	req := w.rawRequest(http.MethodPost, target, contentType, body)
	req.Header.Del("Authorization")
	return req
}

// infraHMAC is the hex HMAC-SHA256 both GitHub and Zitadel sign a delivery with.
func infraHMAC(secret string, signed []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(signed)
	return hex.EncodeToString(mac.Sum(nil))
}

// infraZitadelAction builds a call from the identity provider to one of its action targets,
// signed the way Zitadel signs it: a timestamp and an HMAC over "<timestamp>.<body>".
func infraZitadelAction(t *testing.T, w *writeRun, target string, payload any) *http.Request {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal action payload: %v", err)
	}
	stamp := strconv.FormatInt(time.Now().Unix(), 10)
	req := infraUnauthenticated(w, target, "application/json", raw)
	req.Header.Set("zitadel-signature", "t="+stamp+",v1="+infraHMAC(infraWebhookSecret, []byte(stamp+"."+string(raw))))
	return req
}

// infraGCPOIDCConfig is a workload-identity configuration for Google Cloud. The create route takes
// one of four bodies, told apart by data.type; this is the one these cases use throughout.
func infraGCPOIDCConfig() map[string]any {
	return document("gcp-oidc-configurations", map[string]any{
		"service-account-email":  "stackweaver-deployer@acme-platform.iam.gserviceaccount.com",
		"project-number":         "123456789012",
		"workload-provider-name": "projects/123456789012/locations/global/workloadIdentityPools/stackweaver/providers/stackweaver-oidc",
	})
}

// infraVCSConnectionBody is a connection made from a token the caller already holds, the one
// kind that needs no exchange with the provider. The seed has no connection of any kind.
func infraVCSConnectionBody() map[string]any {
	return map[string]any{
		"provider":         "gitlab",
		"account_name":     "acme-platform",
		"account_type":     "organization",
		"access_token":     "golden-write-access-token",
		"refresh_token":    "golden-write-refresh-token",
		"token_expires_at": "2030-01-01T00:00:00Z",
	}
}

// infraCreateVCSConnection gives the seeded organization a connection and returns its identifier.
func infraCreateVCSConnection(t *testing.T, w *writeRun) string {
	t.Helper()
	created := w.mustSend(t, w.jsonRequest(t, http.MethodPost, w.path("/api/v2/organizations/:name/vcs-connections"), infraVCSConnectionBody()))
	id := dataID(t, created)
	return id
}

// infraRegisterBody is what an agent reports about itself when it joins a pool.
func infraRegisterBody(poolID string) map[string]any {
	return map[string]any{
		"agent_pool_id":         poolID,
		"name":                  "golden-write-runner",
		"hostname":              "runner-01.internal.example.com",
		"os_type":               "linux",
		"os_version":            "Ubuntu 24.04",
		"agent_version":         "1.4.2",
		"tofu_version":          "1.9.0",
		"ansible_version":       "2.17.4",
		"available_collections": []string{"ansible.posix", "community.general"},
		"max_concurrent_jobs":   2,
		"labels":                []string{"region:eu-west-1", "gpu"},
	}
}

// infraRegisterRunner registers a runner and returns what every later protocol call needs.
func infraRegisterRunner(t *testing.T, w *writeRun) infraRunner {
	t.Helper()
	pool := w.id("agent-pools")
	registered := w.mustSend(t, infraRunnerRequest(t, w, infraAgentToken(t, w), "/api/v2/runner/register", infraRegisterBody(pool)))
	id, _ := registered["runner_id"].(string)
	token, _ := registered["runner_api_key"].(string)
	if id == "" || token == "" {
		t.Fatalf("registering a runner returned no identity: %v", registered)
	}
	return infraRunner{id: id, token: token, poolID: pool}
}

// infraAgentRun queues a run the runner's pool is responsible for. A run reaches an agent only
// when its workspace executes in agent mode on that pool, so the seeded workspace, which is
// remote, is switched over first.
func infraAgentRun(t *testing.T, w *writeRun, r infraRunner) string {
	t.Helper()
	w.mustSend(t, w.jsonRequest(t, http.MethodPatch, w.path("/api/v2/workspaces/:id"),
		document("workspaces", map[string]any{"execution-mode": "agent", "agent-pool-id": r.poolID})))
	run := w.mustSend(t, w.jsonRequest(t, http.MethodPost, "/api/v2/runs", related(
		document("runs", map[string]any{"message": "Recorded by the golden write harness"}),
		"workspace", "workspaces", w.id("workspaces"))))
	return dataID(t, run)
}

// infraStartedRun is a run the runner has claimed, which is what output, completion and state
// upload all require: they are refused for a run assigned to nobody or to another runner.
func infraStartedRun(t *testing.T, w *writeRun, r infraRunner) string {
	t.Helper()
	runID := infraAgentRun(t, w, r)
	w.mustSend(t, infraRunnerRequest(t, w, r.token, "/api/v2/runner/jobs/"+runID+"/start", map[string]any{"runner_id": r.id}))
	return runID
}

// Write cases for the registry, agent pools and runners (the runner protocol included), the
// admin catalogue, notification configurations, workload-identity configurations, VCS
// connections, inbound webhooks and the OAuth token endpoint. They register from three init
// functions; this one holds the GPG keys, the admin catalogue, agent pools and runners.
func init() {
	registerWriteCases(
		// --- registry: GPG keys ----------------------------------------------------------------
		writeCase{
			route: "POST /api/registry/:registry/v2/gpg-keys",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodPost, w.path("/api/registry/:registry/v2/gpg-keys"),
					document("gpg-keys", map[string]any{"namespace": w.org(), "ascii-armor": infraGPGPublicKey}))
			},
		},
		writeCase{
			// The handler reads no body: neither attribute of a key can change, so the update the
			// TFE client library defines is answered with the key as it is.
			route: "PATCH /api/registry/:registry/v2/gpg-keys/:namespace/:key_id",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				infraCreateGPGKey(t, w)
				return w.jsonRequest(t, http.MethodPatch, "/api/registry/private/v2/gpg-keys/"+w.org()+"/"+infraGPGKeyID, nil)
			},
		},
		writeCase{
			route: "DELETE /api/registry/:registry/v2/gpg-keys/:namespace/:key_id",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				infraCreateGPGKey(t, w)
				return w.jsonRequest(t, http.MethodDelete, "/api/registry/private/v2/gpg-keys/"+w.org()+"/"+infraGPGKeyID, nil)
			},
		},

		// --- admin: the OpenTofu version catalogue ---------------------------------------------
		writeCase{
			route: "POST /api/v2/admin/terraform-versions",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodPost, "/api/v2/admin/terraform-versions", infraCustomTofuVersion())
			},
		},
		writeCase{
			route: "PATCH /api/v2/admin/terraform-versions/:id",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodPatch, w.path("/api/v2/admin/terraform-versions/:id"),
					document("terraform-versions", map[string]any{
						"deprecated":        true,
						"deprecated-reason": "Superseded by a patched release; move workspaces off this version.",
						"enabled":           false,
					}))
			},
		},
		writeCase{
			// A version of the case's own: the seeded ones are all official, and an official
			// version cannot be deleted.
			route: "DELETE /api/v2/admin/terraform-versions/:id",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				created := w.mustSend(t, w.jsonRequest(t, http.MethodPost, "/api/v2/admin/terraform-versions", infraCustomTofuVersion()))
				return w.jsonRequest(t, http.MethodDelete, "/api/v2/admin/terraform-versions/"+dataID(t, created), nil)
			},
		},

		// --- agent pools and their tokens ------------------------------------------------------
		writeCase{
			route: "POST /api/v2/organizations/:name/agent-pools",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodPost, w.path("/api/v2/organizations/:name/agent-pools"), infraToMany(
					document("agent-pools", map[string]any{"name": "golden-write-pool", "organization-scoped": false}),
					"allowed-workspaces", "workspaces", w.id("workspaces")))
			},
		},
		writeCase{
			route: "PATCH /api/v2/agent-pools/:id",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodPatch, w.path("/api/v2/agent-pools/:id"), infraToMany(
					document("agent-pools", map[string]any{"name": "golden-write-renamed-pool", "organization-scoped": false}),
					"allowed-projects", "projects", w.id("projects")))
			},
		},
		writeCase{
			// A pool of the case's own. The seeded pools have runners, and a pool with runners
			// cannot be deleted: runners.agent_pool_id deliberately carries no ON DELETE rule. The
			// handler answers that refusal with a 500 where a 4xx belongs, which is a defect in
			// the product; a case has to be a write the server accepts.
			route: "DELETE /api/v2/agent-pools/:id",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				created := w.mustSend(t, w.jsonRequest(t, http.MethodPost, w.path("/api/v2/organizations/:name/agent-pools"),
					document("agent-pools", map[string]any{"name": "golden-write-doomed-pool"})))
				return w.jsonRequest(t, http.MethodDelete, "/api/v2/agent-pools/"+dataID(t, created), nil)
			},
		},
		writeCase{
			// The server generates the token and returns it exactly once, here.
			route: "POST /api/v2/agent-pools/:id/authentication-tokens",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodPost, w.path("/api/v2/agent-pools/:id/authentication-tokens"),
					document("authentication-tokens", map[string]any{"description": "Runners in the eu-west-1 build cluster"}))
			},
			responseSecrets: []string{"data.attributes.token"},
		},

		// --- runners: the management API -------------------------------------------------------
		writeCase{
			route: "PATCH /api/v2/runners/:id",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodPatch, w.path("/api/v2/runners/:id"),
					document("runners", map[string]any{
						"description": "Build capacity for non-production workspaces",
						"labels":      []string{"region:eu-west-1", "tier:build"},
					}))
			},
		},
		writeCase{
			route: "DELETE /api/v2/runners/:id",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodDelete, w.path("/api/v2/runners/:id"), nil)
			},
		},

		// --- the runner protocol ---------------------------------------------------------------
		writeCase{
			// Authenticated by an agent token, not a user's. The runner's own token comes back
			// once, here, and authenticates every later call.
			route: "POST /api/v2/runner/register",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return infraRunnerRequest(t, w, infraAgentToken(t, w), "/api/v2/runner/register", infraRegisterBody(w.id("agent-pools")))
			},
			responseSecrets: []string{"runner_api_key"},
		},
		writeCase{
			// A run is queued for the pool first, so the answer shows what a heartbeat is for:
			// the work waiting for this runner.
			route: "POST /api/v2/runner/heartbeat",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				r := infraRegisterRunner(t, w)
				infraAgentRun(t, w, r)
				return infraRunnerRequest(t, w, r.token, "/api/v2/runner/heartbeat",
					map[string]any{"runner_id": r.id, "status": "online", "current_jobs": 0, "available_capacity": 2})
			},
		},
		writeCase{
			route: "POST /api/v2/runner/deregister",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				r := infraRegisterRunner(t, w)
				return infraRunnerRequest(t, w, r.token, "/api/v2/runner/deregister", map[string]any{"runner_id": r.id})
			},
		},
		writeCase{
			// :id is a run here. The same route takes an Ansible job's id, with the same body.
			route: "POST /api/v2/runner/jobs/:id/start",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				r := infraRegisterRunner(t, w)
				return infraRunnerRequest(t, w, r.token, "/api/v2/runner/jobs/"+infraAgentRun(t, w, r)+"/start",
					map[string]any{"runner_id": r.id})
			},
		},
		writeCase{
			route: "POST /api/v2/runner/jobs/:id/output",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				r := infraRegisterRunner(t, w)
				return infraRunnerRequest(t, w, r.token, "/api/v2/runner/jobs/"+infraStartedRun(t, w, r)+"/output",
					map[string]any{
						"runner_id": r.id,
						"stream":    "plan",
						"output":    "OpenTofu will perform the following actions:\n\n  # null_resource.example will be created\n\nPlan: 1 to add, 0 to change, 0 to destroy.\n",
					})
			},
		},
		writeCase{
			// :id is an Ansible job here, the only kind of job that has events: a run's :id is
			// refused. A job reaches an agent when its template runs on the agent's pool, so the
			// seeded template is put on the pool, launched, and the job claimed.
			route: "POST /api/v2/runner/jobs/:id/events",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				r := infraRegisterRunner(t, w)
				w.mustSend(t, w.jsonRequest(t, http.MethodPatch, w.path("/api/v2/ansible/job-templates/:id"),
					related(document("job-templates", nil), "agent-pool", "agent-pools", r.poolID)))
				job := w.mustSend(t, w.jsonRequest(t, http.MethodPost, w.path("/api/v2/ansible/job-templates/:id/launch"), nil))
				jobID := dataID(t, job)
				w.mustSend(t, infraRunnerRequest(t, w, r.token, "/api/v2/runner/jobs/"+jobID+"/start", map[string]any{"runner_id": r.id}))
				return infraRunnerRequest(t, w, r.token, "/api/v2/runner/jobs/"+jobID+"/events",
					map[string]any{
						"event":  "galaxy_install",
						"task":   "Install collections from requirements.yml",
						"stdout": "Starting galaxy collection install process\ncommunity.general:9.4.0 was installed successfully\n",
						"stderr": "",
						"failed": false,
					})
			},
		},
		writeCase{
			// The plan a runner reports is the JSON form of its plan file, sent as a string. The
			// server stores it as given, so a small hand-written one stands in for a real plan.
			route: "POST /api/v2/runner/jobs/:id/complete",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				r := infraRegisterRunner(t, w)
				return infraRunnerRequest(t, w, r.token, "/api/v2/runner/jobs/"+infraStartedRun(t, w, r)+"/complete",
					map[string]any{
						"runner_id":             r.id,
						"status":                "completed",
						"exit_code":             0,
						"plan_json":             `{"format_version":"1.2","resource_changes":[{"address":"null_resource.example","mode":"managed","type":"null_resource","name":"example","change":{"actions":["create"]}}]}`,
						"resource_additions":    1,
						"resource_changes":      0,
						"resource_destructions": 0,
						"output_changes":        0,
						"has_changes":           true,
					})
			},
		},
		writeCase{
			// Storage-backed. The state is the base64 of a state file; the server needs it to be
			// JSON and reads only its serial and lineage, so a minimal state stands in for the one
			// an apply writes.
			route: "POST /api/v2/runner/jobs/:id/state",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				r := infraRegisterRunner(t, w)
				state := `{"version":4,"terraform_version":"1.9.0","serial":1,"lineage":"golden-write-lineage","outputs":{"endpoint":{"value":"https://service.example.com","type":"string"}},"resources":[]}`
				return infraRunnerRequest(t, w, r.token, "/api/v2/runner/jobs/"+infraStartedRun(t, w, r)+"/state",
					map[string]any{"runner_id": r.id, "state": base64.StdEncoding.EncodeToString([]byte(state))})
			},
		},
	)
}

// What a publisher uploads for one platform of a provider version: the archive, the SHA256SUMS
// file that lists it, and that file's detached signature.
//
// The server verifies the signature against the organization's registered GPG key and the
// archive against the checksum, so the three belong together and to infraGPGPublicKey. The
// signature was made once with the key's discarded private half, which is why the archive, its
// file name and the provider it is published to are constants here and not resolved from the
// seed: change any of them and a new key and signature have to be generated together.
const (
	infraProviderName    = "internal-dns" // a seeded private provider
	infraProviderVersion = "1.0.0"
	infraProviderArchive = "terraform-provider-internal-dns_1.0.0_linux_amd64.zip"
	// The smallest valid zip: an end-of-central-directory record and nothing else.
	infraProviderZip     = "PK\x05\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	infraProviderShasums = "8739c76e681f900923b900c9df0ef75cf421d39cabb54650c4b9ad19b6a76d85  " + infraProviderArchive + "\n"
	infraProviderSig     = `-----BEGIN PGP SIGNATURE-----

wqsEABYIAF0FgmrNCtYJEJ/eqepw/6osNRQAAAAAABwAEHNhbHRAbm90YXRpb25z
Lm9wZW5wZ3Bqcy5vcmfBVjRi07tSAqpb9aWCA12bFiEE04bZtLiGDFZM0bvln96p
6nD/qiwAAJ0KAP9e7Djx8NbISpUIzNvdbJmUIfkZ6PEMNuSbUM3UigTLPwD/btLo
r5qNAMaqjBM1slXoljOXd3HSU7bdsV3hfhO/RA8=
=JtuI
-----END PGP SIGNATURE-----
`
)

// The registry, notification configurations, workload-identity configurations and VCS connections.
func init() {
	registerWriteCases(
		// --- registry: providers ---------------------------------------------------------------
		writeCase{
			route: "POST /api/v2/organizations/:name/registry-providers",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodPost, w.path("/api/v2/organizations/:name/registry-providers"),
					document("registry-providers", map[string]any{"name": "golden-write", "namespace": w.org(), "registry-name": "private"}))
			},
		},
		writeCase{
			// Storage-backed, and it needs the key the signature was made with registered first.
			// The path is spelled out: a private provider's namespace is its organization's name.
			route: "POST /api/v2/organizations/:name/registry-providers/:registry_name/:namespace/:provider_name/versions/:version/platforms",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				infraCreateGPGKey(t, w)
				target := "/api/v2/organizations/" + w.org() + "/registry-providers/private/" + w.org() + "/" + infraProviderName +
					"/versions/" + infraProviderVersion + "/platforms"
				return infraMultipartRequest(t, w, target,
					map[string]string{"os": "linux", "arch": "amd64", "key_id": infraGPGKeyID, "protocols": "5.0,6.0"},
					infraFile{"file", infraProviderArchive, []byte(infraProviderZip)},
					infraFile{"shasums", "SHA256SUMS", []byte(infraProviderShasums)},
					infraFile{"shasums_sig", "SHA256SUMS.sig", []byte(infraProviderSig)})
			},
		},
		writeCase{
			route: "DELETE /api/v2/organizations/:name/registry-providers/:registry_name/:namespace/:provider_name",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodDelete,
					"/api/v2/organizations/"+w.org()+"/registry-providers/private/"+w.org()+"/"+infraProviderName, nil)
			},
		},
		writeCase{
			route: "DELETE /api/v2/registry-providers/:id",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodDelete, w.path("/api/v2/registry-providers/:id"), nil)
			},
		},

		// --- registry: modules -----------------------------------------------------------------
		writeCase{
			// A module published by upload. The same route takes vcs_connection_id and
			// vcs_repository to publish from a repository's tags, which needs the provider.
			route: "POST /api/v2/organizations/:name/registry/modules",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return infraPlainRequest(t, w, http.MethodPost, w.path("/api/v2/organizations/:name/registry/modules"),
					map[string]any{
						"name":              "golden-write",
						"provider":          "aws",
						"description":       "Recorded by the golden write harness",
						"auto_publish_tags": false,
					})
			},
		},
		writeCase{
			// Storage-backed: the archive is unpacked, read for its inputs and outputs, and stored.
			route: "POST /api/v2/organizations/:name/registry/modules/:module_name/:provider/versions",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return infraMultipartRequest(t, w, w.path("/api/v2/organizations/:name/registry/modules/:module_name/:provider/versions"),
					map[string]string{"version": "3.0.0"},
					infraFile{"file", "module-3.0.0.tar.gz", tinyConfigArchive(t)})
			},
		},
		writeCase{
			route: "DELETE /api/v2/organizations/:name/registry/modules/:module_name/:provider/versions/:version",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodDelete,
					w.path("/api/v2/organizations/:name/registry/modules/:module_name/:provider/versions/:version"), nil)
			},
		},
		writeCase{
			route: "DELETE /api/v2/organizations/:name/registry/modules/:module_name/:provider",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodDelete, w.path("/api/v2/organizations/:name/registry/modules/:module_name/:provider"), nil)
			},
		},
		writeCase{
			// Empties the organization's module registry.
			route: "DELETE /api/v2/organizations/:name/registry/modules",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodDelete, w.path("/api/v2/organizations/:name/registry/modules"), nil)
			},
		},

		// --- notification configurations -------------------------------------------------------
		writeCase{
			// The token is the secret generic deliveries are signed with. It is write-only.
			route: "PATCH /api/v2/notification-configurations/:id",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodPatch, w.path("/api/v2/notification-configurations/:id"),
					document("notification-configurations", map[string]any{
						"name":     "run-events-signed",
						"url":      "https://hooks.example.com/stackweaver/runs",
						"token":    "golden-write-signing-token",
						"enabled":  true,
						"triggers": []string{"run:needs_attention", "run:completed", "run:errored"},
					}))
			},
			requestSecrets: []string{"data.attributes.token"},
		},
		writeCase{
			route: "DELETE /api/v2/notification-configurations/:id",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodDelete, w.path("/api/v2/notification-configurations/:id"), nil)
			},
		},
		writeCase{
			// Verifying sends a test delivery and answers 2xx only if the destination took it. An
			// email destination is the one kind that needs nothing outside the machine: the server
			// accepts email configurations and does not deliver to them yet, so verifying one
			// succeeds without sending. Every other destination has to be reached.
			route: "POST /api/v2/notification-configurations/:id/actions/verify",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				created := w.mustSend(t, w.jsonRequest(t, http.MethodPost, w.path("/api/v2/workspaces/:id/notification-configurations"),
					document("notification-configurations", map[string]any{
						"name":             "platform-on-call",
						"destination-type": "email",
						"email-addresses":  []string{"platform-on-call@example.com"},
						"enabled":          true,
						"triggers":         []string{"run:errored"},
					})))
				return w.jsonRequest(t, http.MethodPost, "/api/v2/notification-configurations/"+dataID(t, created)+"/actions/verify", nil)
			},
		},

		// --- workload-identity (OIDC) configurations -------------------------------------------
		writeCase{
			route: "POST /api/v2/organizations/:name/oidc-configurations",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodPost, w.path("/api/v2/organizations/:name/oidc-configurations"), infraGCPOIDCConfig())
			},
		},
		writeCase{
			// The seed has no configuration, and which body an update takes follows from the
			// identifier's prefix, so the case makes the Google Cloud one it then updates.
			route: "PATCH /api/v2/oidc-configurations/:id",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				created := w.mustSend(t, w.jsonRequest(t, http.MethodPost, w.path("/api/v2/organizations/:name/oidc-configurations"), infraGCPOIDCConfig()))
				return w.jsonRequest(t, http.MethodPatch, "/api/v2/oidc-configurations/"+dataID(t, created),
					document("gcp-oidc-configurations", map[string]any{
						"service-account-email": "stackweaver-readonly@acme-platform.iam.gserviceaccount.com",
					}))
			},
		},
		writeCase{
			route: "DELETE /api/v2/oidc-configurations/:id",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				created := w.mustSend(t, w.jsonRequest(t, http.MethodPost, w.path("/api/v2/organizations/:name/oidc-configurations"), infraGCPOIDCConfig()))
				return w.jsonRequest(t, http.MethodDelete, "/api/v2/oidc-configurations/"+dataID(t, created), nil)
			},
		},

		// --- VCS connections -------------------------------------------------------------------
		writeCase{
			// One connection per provider and organization: a second for the same provider is
			// answered 409.
			route: "POST /api/v2/organizations/:name/vcs-connections",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodPost, w.path("/api/v2/organizations/:name/vcs-connections"), infraVCSConnectionBody())
			},
			requestSecrets: []string{"access_token", "refresh_token"},
		},
		writeCase{
			route: "DELETE /api/v2/vcs-connections/:id",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return w.jsonRequest(t, http.MethodDelete, "/api/v2/vcs-connections/"+infraCreateVCSConnection(t, w), nil)
			},
		},
	)

	nameWrites(map[string]namedWrite{
		"POST /api/v2/organizations/:name/vcs-connections/github/installations/:installation_id": {
			reason: needsOutsideSystem,
			detail: "The server asks GitHub, as the GitHub App it is configured to be, which account the installation belongs to before it stores the connection. Success needs a real installation of that App and GitHub to answer for it.",
		},
		"POST /api/v2/vcs-connections/azure-devops/callback": {
			reason: needsOutsideSystem,
			detail: "The server exchanges the authorization code with Microsoft Entra ID and then checks the token it gets against the Azure DevOps organization. Success needs a code Entra ID issued for a browser sign-in and both services to answer.",
		},
	})
}

// Inbound webhooks, the identity provider's action targets and the OAuth token endpoint: the
// routes no user token authenticates.
func init() {
	registerWriteCases(
		writeCase{
			// Authenticated by GitHub's signature over the body, with the secret the server was
			// started with; which event it is travels in the X-GitHub-Event header. This is a
			// push. A seeded playbook is pointed at the repository first, so the push is one the
			// server has something to do with.
			route: "POST /api/v2/webhooks/github",
			env:   map[string]string{"GITHUB_WEBHOOK_SECRET": infraWebhookSecret},
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				if err := w.db.Exec("UPDATE ansible_playbooks SET vcs_repository = ?, vcs_branch = ? WHERE id = ?",
					"acme-platform/ansible-playbooks", "main", w.id("playbooks")).Error; err != nil {
					t.Fatalf("point a seeded playbook at the repository: %v", err)
				}
				const commit = "6dcb09b5b57875f334f61aebed695e2e4193db5e"
				raw, err := json.Marshal(map[string]any{
					"ref":    "refs/heads/main",
					"before": "9049f1265b7d61be4a8904a9a27120d2064dab3b",
					"after":  commit,
					"repository": map[string]any{
						"name":           "ansible-playbooks",
						"full_name":      "acme-platform/ansible-playbooks",
						"private":        true,
						"default_branch": "main",
						"owner":          map[string]any{"login": "acme-platform"},
					},
					"pusher": map[string]any{"name": "avery-diaz", "email": "avery.diaz@example.com"},
					"head_commit": map[string]any{
						"id":       commit,
						"message":  "Raise the nginx worker limit",
						"modified": []string{"site.yml", "roles/nginx/defaults/main.yml"},
					},
					"commits": []any{map[string]any{
						"id":       commit,
						"message":  "Raise the nginx worker limit",
						"modified": []string{"site.yml", "roles/nginx/defaults/main.yml"},
					}},
				})
				if err != nil {
					t.Fatalf("marshal push event: %v", err)
				}
				req := infraUnauthenticated(w, "/api/v2/webhooks/github", "application/json", raw)
				req.Header.Set("X-GitHub-Event", "push")
				req.Header.Set("X-GitHub-Delivery", "72d3162e-cc78-11e3-81ab-4c9367dc0958")
				req.Header.Set("X-Hub-Signature-256", "sha256="+infraHMAC(infraWebhookSecret, raw))
				return req
			},
		},
		writeCase{
			// An Azure DevOps service hook carries no signature: it authenticates with the
			// basic-auth password set on the subscription, which the server compares with the
			// secret it was started with. This is a git.push for a repository no workspace
			// tracks. A push that matches one makes the server clone from Azure DevOps.
			route: "POST /api/v2/vcs-connections/azure-devops/webhook",
			env:   map[string]string{"AZURE_DEVOPS_WEBHOOK_SECRET": infraWebhookSecret},
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				const commit = "33b55f7cb7e7e245323987634f960cf4a6e6bc74"
				raw, err := json.Marshal(map[string]any{
					"subscriptionId": "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d",
					"notificationId": 14,
					"eventType":      "git.push",
					"publisherId":    "tfs",
					"resource": map[string]any{
						"refUpdates": []any{map[string]any{
							"name":        "refs/heads/main",
							"oldObjectId": "aad331d8d3b131fa9ae03cf5e53965b51942618a",
							"newObjectId": commit,
						}},
						"commits": []any{map[string]any{
							"commitId": commit,
							"comment":  "Open the admin port to the bastion subnet",
							"author":   map[string]any{"name": "Avery Diaz", "email": "avery.diaz@example.com"},
						}},
						"repository": map[string]any{
							"name":      "network",
							"remoteUrl": "https://dev.azure.com/acme-platform/Infrastructure/_git/network",
							"project":   map[string]any{"name": "Infrastructure"},
						},
					},
				})
				if err != nil {
					t.Fatalf("marshal service hook event: %v", err)
				}
				req := infraUnauthenticated(w, "/api/v2/vcs-connections/azure-devops/webhook", "application/json", raw)
				req.SetBasicAuth("stackweaver", infraWebhookSecret)
				return req
			},
		},
		writeCase{
			// Called by Zitadel when it has an identity provider's answer for a sign-in, and
			// answered with that answer, complemented. The signing key is one Zitadel issues for
			// the target and the server is started with; any key both sides hold verifies.
			//
			// The sign-in is a new user's. For an existing user the server also writes the groups
			// to that user at Zitadel, and this recorder shares its Zitadel with real people: so
			// the payload names no user, and the server is started without the token it would
			// make that call with. For the same reason the payload leaves out the members that
			// name the person at the identity provider (userId, userName), which the recorder's
			// identity guard refuses in any body.
			route: "POST /api/v2/zitadel/actions/idp-sync",
			env: map[string]string{
				"ZITADEL_WEBHOOK_IDP_SYNC_KEY":     infraWebhookSecret,
				"ZITADEL_LOGIN_SERVICE_USER_TOKEN": "",
			},
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return infraZitadelAction(t, w, "/api/v2/zitadel/actions/idp-sync", map[string]any{
					"fullMethod": "/zitadel.user.v2.UserService/RetrieveIdentityProviderIntent",
					"instanceID": "312909075211976984",
					"orgID":      "312909075212042520",
					"request":    map[string]any{"idpIntentId": "312911568405479384"},
					"response": map[string]any{
						"details": map[string]any{"sequence": "599", "resourceOwner": "312909075211976984"},
						"idpInformation": map[string]any{
							"idpId": "312910411843633176",
							"rawInformation": map[string]any{
								"sub":    "00u1a2b3c4d5e6f7g8h9",
								"email":  "avery.diaz@example.com",
								"groups": []string{"platform-engineering", "security"},
							},
						},
						"addHumanUser": map[string]any{
							"profile": map[string]any{"givenName": "Avery", "familyName": "Diaz"},
							"email":   map[string]any{"email": "avery.diaz@example.com", "isVerified": true},
						},
					},
				})
			},
		},
		writeCase{
			// Called by Zitadel before it issues an access token, and answered with the claims
			// to add: the groups the sign-in stored in the user's metadata, base64 as Zitadel
			// keeps metadata values.
			route: "POST /api/v2/zitadel/actions/complement-token",
			env:   map[string]string{"ZITADEL_WEBHOOK_COMPLEMENT_TOKEN_KEY": infraWebhookSecret},
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				return infraZitadelAction(t, w, "/api/v2/zitadel/actions/complement-token", map[string]any{
					"function": "function/preaccesstoken",
					"user":     map[string]any{"id": "312912345678901234", "preferred_login_name": "avery.diaz@example.com"},
					"org":      map[string]any{"id": "312909075212042520", "name": "acme-platform"},
					"user_metadata": []any{map[string]any{
						"key":   "sso_groups",
						"value": base64.StdEncoding.EncodeToString([]byte(`["platform-engineering","security"]`)),
					}},
				})
			},
		},
		writeCase{
			// The exchange that ends `terraform login`: a one-time code and the PKCE verifier
			// for a token. The code comes from POST /api/v2/oauth/authorize, which only a
			// signed-in browser session may call, so the case stores one the way that handler
			// does, in the queue's Redis, for the user the harness runs as.
			route: "POST /api/v2/oauth/token",
			prepare: func(t *testing.T, w *writeRun) *http.Request {
				const (
					code        = "golden-write-authorization-code"
					verifier    = "golden-write-code-verifier-0123456789-abcdefghijklmnopqrstuvwxyz"
					redirectURI = "http://localhost:10000/login"
				)
				account := w.mustSend(t, w.jsonRequest(t, http.MethodGet, "/api/v2/account/details", nil))
				challenge := sha256.Sum256([]byte(verifier))
				stored, err := json.Marshal(map[string]string{
					"user_id":        dataID(t, account),
					"code_challenge": base64.RawURLEncoding.EncodeToString(challenge[:]),
					"redirect_uri":   redirectURI,
					"client_id":      "terraform-cli",
				})
				if err != nil {
					t.Fatalf("marshal authorization code: %v", err)
				}
				q, err := queue.NewRedisQueueFromEnv()
				if err != nil {
					t.Fatalf("connect to the slot's Redis: %v", err)
				}
				defer func() { _ = q.Close() }()
				if err := q.Client().Set(context.Background(), "oauth:authcode:"+code, stored, time.Minute).Err(); err != nil {
					t.Fatalf("store the authorization code: %v", err)
				}
				form := url.Values{
					"grant_type":    {"authorization_code"},
					"client_id":     {"terraform-cli"},
					"code":          {code},
					"code_verifier": {verifier},
					"redirect_uri":  {redirectURI},
				}
				return infraUnauthenticated(w, "/api/v2/oauth/token", "application/x-www-form-urlencoded", []byte(form.Encode()))
			},
			requestSecrets:  []string{"code", "code_verifier"},
			responseSecrets: []string{"access_token"},
		},
	)
}

// infraCustomTofuVersion is a catalogue entry for a build the official list does not carry.
func infraCustomTofuVersion() map[string]any {
	const (
		url = "https://mirror.example.com/opentofu/1.6.0-rc1/tofu_1.6.0-rc1_linux_amd64.zip"
		sha = "5f2b1c0a9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a"
	)
	return document("terraform-versions", map[string]any{
		"version":  "1.6.0-rc1",
		"url":      url,
		"sha":      sha,
		"official": false,
		"enabled":  true,
		"beta":     true,
		"archs":    []any{map[string]any{"os": "linux", "arch": "amd64", "url": url, "sha": sha}},
	})
}
