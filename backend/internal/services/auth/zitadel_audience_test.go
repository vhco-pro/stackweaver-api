// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// AUD-012 audience enforcement. VerifyToken previously discarded the audience-check error,
// so any token signed by the same Zitadel instance (for any client/project) authenticated
// and auto-provisioned a user. The access token received at browser sign-in is issued to the
// BFF client, so its `aud` carries the BFF client id - enforcement must accept that while
// rejecting tokens minted for other clients. (These tokens were issued to the public frontend
// client while the browser held them; that client is retired, backend-for-frontend-session-plan.md.)

package auth

import "testing"

func TestAudienceAccepted(t *testing.T) {
	t.Run("no configured audiences preserves availability", func(t *testing.T) {
		v := &ZitadelVerifier{}
		if !v.audienceAccepted([]string{"anything"}) {
			t.Fatal("with no registered audiences, enforcement must be disabled (allow)")
		}
	})

	// Mirror production wiring: register the API client id and the BFF client id.
	v := &ZitadelVerifier{}
	v.AcceptAudience("api-client")
	v.AcceptAudience("bff-client")
	v.AcceptAudience("") // empty is a no-op

	t.Run("sign-in token (BFF client in aud) is accepted", func(t *testing.T) {
		// Shape observed on a live Zitadel access token: [client, project, project].
		if !v.audienceAccepted([]string{"bff-client", "proj-a", "proj-b"}) {
			t.Fatal("a token whose aud contains the BFF client id must be accepted")
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
