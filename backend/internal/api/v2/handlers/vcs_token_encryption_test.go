// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// AUD-005 residual — VCS token encryption at rest for the Azure DevOps OAuth callback.
// Every other VCS-connection write path runs tokens through ProviderRegistry.EncryptTokens
// before persisting, but the ADO OAuth callback (vcs_app_installation.go create/update
// branches) wrote tokenResult.AccessToken/RefreshToken to the DB verbatim — cleartext at
// rest. This test locks the invariant at the persistence seam the handler now uses: an ADO
// connection persisted through EncryptTokens + the real repository lands as ciphertext in
// Postgres and decrypts back to the originals, while a persist that skips EncryptTokens
// (the pre-fix behavior) demonstrably leaks the plaintext token. The handler wiring itself
// is a two-line mirror of the already-tested vcs_connections.go create path; the Microsoft
// OAuth token endpoint is hardcoded (no injection seam), so the callback cannot be driven
// end-to-end without a production HTTP-client seam, out of scope for this residual.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Cleanup is strictly
// row-scoped (the DB may be live). Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/ -run TestVCSTokenEncryptionAtRest

//go:build integration
// +build integration

package handlers

import (
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/crypto"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/services/vcs"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func TestVCSTokenEncryptionAtRest(t *testing.T) {
	dbURL := os.Getenv("TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping integration test")
	}
	db, err := gorm.Open(postgres.Open(dbURL), &gorm.Config{})
	if err != nil {
		t.Fatalf("connect test db: %v", err)
	}
	if err := db.AutoMigrate(&models.Organization{}, &models.VCSConnection{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	sfx := uuid.NewString()[:8]
	org := &models.Organization{ID: uuid.New(), Name: "vcsenc-" + sfx}
	// Pre-generate connection IDs so the row-scoped cleanup can be registered BEFORE any
	// seeding — it stays valid even if a Create below fails partway.
	encConnID := uuid.New()
	plainConnID := uuid.New()
	t.Cleanup(func() {
		db.Where("id IN ?", []uuid.UUID{encConnID, plainConnID}).Delete(&models.VCSConnection{})
		db.Where("id = ?", org.ID).Delete(&models.Organization{})
	})
	if err := db.Create(org).Error; err != nil {
		t.Fatalf("seed org: %v", err)
	}

	const plainAccess = "ado-access-plaintext-secret" //nolint:gosec // G101: test fixture, not a real credential
	const plainRefresh = "ado-refresh-plaintext-secret"

	cs, err := crypto.NewCryptoService([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("crypto: %v", err)
	}
	registry := vcs.NewProviderRegistry(nil, nil, nil, cs)
	repo := repository.NewVCSConnectionRepository(db)

	// --- Fixed path: the ADO callback now encrypts before persisting. ---
	enc := &models.VCSConnection{
		ID:             encConnID,
		OrganizationID: org.ID,
		Provider:       models.VCSProviderAzureDevOps,
		AccessToken:    plainAccess,
		RefreshToken:   plainRefresh,
		AccountName:    "enc-" + sfx,
		AccountType:    "organization",
	}
	if err := registry.EncryptTokens(enc); err != nil {
		t.Fatalf("EncryptTokens: %v", err)
	}
	if err := repo.Create(enc); err != nil {
		t.Fatalf("create encrypted conn: %v", err)
	}

	// Re-read from the DB. The model has no decrypt hook, so GetByID returns exactly what
	// is stored — which must be ciphertext, never the plaintext token.
	stored, err := repo.GetByID(encConnID)
	if err != nil {
		t.Fatalf("reload encrypted conn: %v", err)
	}
	if stored.AccessToken == plainAccess {
		t.Fatal("access token stored in cleartext at rest — AUD-005 regression")
	}
	if stored.RefreshToken == plainRefresh {
		t.Fatal("refresh token stored in cleartext at rest — AUD-005 regression")
	}
	// And the stored ciphertext must decrypt back to the originals, proving the connection
	// remains usable (providers call DecryptTokens transparently on read).
	registry.DecryptTokens(stored)
	if stored.AccessToken != plainAccess || stored.RefreshToken != plainRefresh {
		t.Fatalf("ciphertext did not roundtrip: access=%q refresh=%q", stored.AccessToken, stored.RefreshToken)
	}

	// --- Control: persisting without EncryptTokens (the pre-fix behavior) leaks the
	// plaintext, confirming the assertions above actually depend on the fix. ---
	leak := &models.VCSConnection{
		ID:             plainConnID,
		OrganizationID: org.ID,
		Provider:       models.VCSProviderAzureDevOps,
		AccessToken:    plainAccess,
		RefreshToken:   plainRefresh,
		AccountName:    "plain-" + sfx,
		AccountType:    "organization",
	}
	if err := repo.Create(leak); err != nil {
		t.Fatalf("create control conn: %v", err)
	}
	leaked, err := repo.GetByID(plainConnID)
	if err != nil {
		t.Fatalf("reload control conn: %v", err)
	}
	if leaked.AccessToken != plainAccess {
		t.Fatalf("control expectation broken: unencrypted persist should store plaintext, got %q", leaked.AccessToken)
	}
}
