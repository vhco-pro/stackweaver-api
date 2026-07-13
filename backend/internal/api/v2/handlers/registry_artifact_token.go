// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// AUD-123 gated the Terraform provider-install byte-stream endpoints (binary / SHA256SUMS / .sig)
// on org membership. But the provider-install protocol fetches the download_url / shasums_url /
// shasums_signature_url WITHOUT sending registry credentials — Terraform treats them as opaque
// artifact links (exactly as HashiCorp's TFE hands back separately-signed CDN URLs). So membership
// gating those URLs broke `terraform init` for private providers: the SHASUMS fetch 401s.
//
// The fix keeps AUD-123's gate for direct access while restoring install: the AUTHENTICATED metadata
// endpoint (DownloadProvider) embeds a short-TTL capability token — scoped to a single provider
// version and HMAC-signed with the deployment's ENCRYPTION_KEY — in those URLs, and the stream
// endpoints accept a valid token as an ALTERNATIVE to membership. Only a caller who already passed
// the membership check on the metadata endpoint receives working artifact URLs, so a non-member
// still cannot download a private binary.

const artifactTokenTTL = 15 * time.Minute

// artifactTokenSecret is the HMAC key for provider-artifact capability tokens, set once at startup.
var artifactTokenSecret []byte

// SetArtifactTokenSecret installs the signing key. Wiring passes the resolved ENCRYPTION_KEY (or, in
// deployments without one, an ephemeral per-process key). When empty, capability tokens are disabled
// and artifact reads fall back to membership auth only.
func SetArtifactTokenSecret(key []byte) { artifactTokenSecret = key }

// artifactScope identifies the artifact set a capability token grants access to: one provider
// version's binary, SHA256SUMS and signature.
func artifactScope(namespace, name, version string) string {
	return fmt.Sprintf("%s/%s/%s", namespace, name, version)
}

// mintArtifactToken returns a version-scoped, expiring capability token, or "" if signing is disabled.
func mintArtifactToken(scope string) string {
	if len(artifactTokenSecret) == 0 {
		return ""
	}
	payload := fmt.Sprintf("%s:%d", scope, time.Now().Add(artifactTokenTTL).Unix())
	return base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." + signArtifactPayload(payload)
}

// verifyArtifactToken reports whether token is a valid, unexpired capability token for scope.
func verifyArtifactToken(token, scope string) bool {
	if len(artifactTokenSecret) == 0 || token == "" {
		return false
	}
	b64, sig, ok := strings.Cut(token, ".")
	if !ok {
		return false
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(b64)
	if err != nil {
		return false
	}
	payload := string(payloadBytes)
	if !hmac.Equal([]byte(sig), []byte(signArtifactPayload(payload))) {
		return false
	}
	// payload = "<scope>:<exp>"; the scope (namespace/name/version) carries no colon, so the last
	// colon separates the expiry.
	idx := strings.LastIndex(payload, ":")
	if idx < 0 || payload[:idx] != scope {
		return false
	}
	exp, err := strconv.ParseInt(payload[idx+1:], 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return false
	}
	return true
}

func signArtifactPayload(payload string) string {
	mac := hmac.New(sha256.New, artifactTokenSecret)
	mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
