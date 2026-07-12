// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// AUD-012 audience enforcement. VerifyToken previously discarded the audience-check error,
// so any token signed by the same Zitadel instance (for any client/project) authenticated
// and auto-provisioned a user. Real user access tokens are issued to the frontend PKCE
// client, so their `aud` carries the frontend client id — enforcement must accept that while
// rejecting tokens minted for other clients.

package auth

import "testing"

func TestAudienceAccepted(t *testing.T) {
	t.Run("no configured audiences preserves availability", func(t *testing.T) {
		v := &ZitadelVerifier{}
		if !v.audienceAccepted([]string{"anything"}) {
			t.Fatal("with no registered audiences, enforcement must be disabled (allow)")
		}
	})

	// Mirror production wiring: register the API client id and the frontend PKCE client id.
	v := &ZitadelVerifier{}
	v.AcceptAudience("api-client")
	v.AcceptAudience("frontend-client")
	v.AcceptAudience("") // empty is a no-op

	t.Run("real user token (frontend client in aud) is accepted", func(t *testing.T) {
		// Shape observed on a live Zitadel access token: [frontend-client, project, project].
		if !v.audienceAccepted([]string{"frontend-client", "proj-a", "proj-b"}) {
			t.Fatal("a token whose aud contains the frontend client id must be accepted")
		}
	})

	t.Run("api-client token is accepted", func(t *testing.T) {
		if !v.audienceAccepted([]string{"api-client"}) {
			t.Fatal("a token whose aud contains the API client id must be accepted")
		}
	})

	t.Run("token for another client is rejected", func(t *testing.T) {
		if v.audienceAccepted([]string{"some-other-app", "proj-x"}) {
			t.Fatal("a token whose aud names only other clients must be rejected (AUD-012)")
		}
	})
}
